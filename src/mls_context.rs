use crate::types::RemoveMembersResult;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::storage::StorageProvider;
use openmls_traits::OpenMlsProvider;
use rusqlite::ffi::ErrorCode;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::epoch_storage::EpochSecretManager;
use crate::error::MLSError;
use crate::message_limits::validate_inbound_mls_message_len;
use crate::metadata;
use crate::orchestrator::mls_provider::OwnEchoProof;
use openmls::component::ComponentData;
use uuid::Uuid;

/// Internal result from `MLSContext::create_group` carrying the group ID
/// plus optional metadata artifacts for the caller to upload.
pub(crate) struct CreateGroupInternalResult {
    pub group_id: Vec<u8>,
    /// Encrypted metadata v2 blob (nonce || ciphertext || tag).
    pub encrypted_metadata_blob: Option<Vec<u8>>,
    /// JSON-serialized `MetadataReference`.
    pub metadata_reference_json: Option<Vec<u8>>,
    /// UUIDv4 blob locator for the encrypted metadata blob.
    pub metadata_blob_locator: Option<String>,
}

/// Atomic result from `MLSContext::update_group_metadata_encrypted`. Caller:
///   1. Sends `commit_bytes` to the DS (server processes the commit, advancing the group epoch).
///   2. Uploads `metadata_blob_ciphertext` via `putGroupMetadataBlob` with `metadata_blob_locator`.
///   3. Calls `merge_pending_commit(group_id)` after server ACK to apply locally.
///   4. Stores `metadata_reference_json` (the FINAL reference, with real ciphertext hash) in
///      its local conversation cache.
///
/// The MetadataReference embedded in the commit itself carries a placeholder ciphertext hash
/// (the hash must be known at commit-staging time, but the ciphertext doesn't exist until after
/// staging — the staged commit's exporter is what derives the encryption key). AEAD provides
/// integrity on the blob; the reference's hash field is informational.
#[derive(Debug, Clone)]
pub struct UpdateGroupMetadataResult {
    /// TLS-serialized commit message to send to the DS.
    pub commit_bytes: Vec<u8>,
    /// Encrypted `GroupMetadataV1` blob (`nonce || ciphertext || tag`).
    pub metadata_blob_ciphertext: Vec<u8>,
    /// JSON-serialized `MetadataReference` (with real ciphertext hash) for the caller's local cache.
    pub metadata_reference_json: Vec<u8>,
    /// Monotonic counter (per conversation) for this metadata revision.
    pub metadata_version: u64,
    /// UUIDv4 locator the caller uses with `putGroupMetadataBlob`.
    pub metadata_blob_locator: String,
    pub next_confirmation_tag: Option<Vec<u8>>,
    pub next_group_context_hash: Option<Vec<u8>>,
}
use sha2::{Digest, Sha256};

// Capabilities split between leaf-advertised vs group-required.
//
// Post-cutover NEW groups must NOT require the retired plaintext 0xff00
// extension — the encrypted MetadataReference at AppDataDictionary 0x8001
// is the only metadata path. But LEGACY groups created before the cutover
// (or by a peer that hasn't updated yet) still list 0xff00 in their
// RequiredCapabilities. Per RFC 9420 §13.4 a new leaf joining a group
// must advertise support for every extension type the group requires;
// otherwise OpenMLS rejects it with `LeafNodeValidation(UnsupportedExtensions)`
// — which was blocking Android's External Commit recovery into legacy
// groups (see Android logs from Phase G).
//
// Resolution: new enrollment leaves advertise the server's clean profile:
// no extension or proposal capabilities. New groups likewise carry an empty
// RequiredCapabilities extension so these leaves can join successfully.

fn metadata_required_capabilities_extension() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(&[], &[], &[])
}

pub(crate) fn metadata_leaf_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[openmls::prelude::ProtocolVersion::Mls10]),
        Some(&[Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]),
        Some(&[
            openmls::prelude::ExtensionType::RatchetTree,
            openmls::prelude::ExtensionType::AppDataDictionary,
        ]),
        Some(&[openmls::prelude::ProposalType::AppDataUpdate]),
        Some(&[openmls::prelude::CredentialType::Basic]),
    )
}

fn map_sqlite_error(context: &str, error: &rusqlite::Error) -> MLSError {
    match error {
        rusqlite::Error::SqliteFailure(err, msg) => {
            let detail = msg.as_deref().unwrap_or("");
            match err.code {
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                    MLSError::ThreadSafety(format!("{context}: SQLITE_BUSY/LOCKED {detail}"))
                }
                ErrorCode::ApiMisuse => {
                    MLSError::Internal(format!("{context}: SQLITE_MISUSE {detail}"))
                }
                ErrorCode::OutOfMemory => {
                    MLSError::Internal(format!("{context}: SQLITE_NOMEM {detail}"))
                }
                _ => MLSError::invalid_input(format!("{context}: sqlite failure {:?}", err)),
            }
        }
        _ => MLSError::invalid_input(format!("{context}: sqlite error {:?}", error)),
    }
}

/// Derive a deterministic 16-byte salt from the encryption key.
/// Required when cipher_plaintext_header_size > 0 because SQLCipher
/// cannot store the salt in the (plaintext) header.
fn derive_cipher_salt_hex(encryption_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encryption_key.as_bytes());
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Budget-based TRUNCATE checkpoint configuration (Signal's pattern)
///
/// Signal checkpoints every ~32 writes with TRUNCATE mode to keep WAL perpetually small.
/// This prevents the 0xdead10cc crash by ensuring WAL never grows large enough to cause
/// long checkpoint operations during suspension.
const CHECKPOINT_BUDGET: u64 = 32;
const NORMAL_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DURABILITY_CHECKPOINT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

fn validate_durability_checkpoint(
    busy: i64,
    log_frames: i64,
    checkpointed_frames: i64,
) -> Result<(), MLSError> {
    if busy != 0 || log_frames < 0 || checkpointed_frames < 0 || checkpointed_frames != log_frames {
        crate::error_log!(
            "[MANIFEST-STORAGE] Incomplete durability checkpoint: busy={}, log={}, checkpointed={}",
            busy,
            log_frames,
            checkpointed_frames
        );
        return Err(MLSError::StorageFailed);
    }
    Ok(())
}

/// Maximum age for a stored key package bundle before it is pruned (90 days).
/// Matches the OpenMLS KeyPackage lifetime — older bundles are unusable by
/// joiners, so keeping them only bloats storage and slows writes.
const KEY_PACKAGE_BUNDLE_MAX_AGE_SECS: u64 = 90 * 24 * 60 * 60;

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Helper for storing application manifests in SQLite
/// This is separate from OpenMLS's storage and uses direct rusqlite access
pub(crate) struct ManifestStorage {
    conn: Connection,
    /// Write counter for budget-based TRUNCATE checkpoints (Signal's pattern)
    write_count: AtomicU64,
}

impl ManifestStorage {
    fn new(db_path: PathBuf, encryption_key: &str) -> Result<Self, MLSError> {
        let conn = Connection::open(&db_path)
            .map_err(|e| MLSError::invalid_input(format!("Failed to open DB: {}", e)))?;

        // Salt is required when using plaintext header
        let salt_hex = derive_cipher_salt_hex(encryption_key);

        // ═══════════════════════════════════════════════════════════════════════════
        // CRITICAL FIX: Disable SQLCipher memory security BEFORE setting the key
        // ═══════════════════════════════════════════════════════════════════════════
        // cipher_memory_security = ON causes SQLCipher to lock memory pages using
        // mlock() to prevent sensitive data from being swapped to disk. However,
        // on iOS this triggers:
        // - SQLITE_NOMEM (error 7) when the mlock quota is exhausted
        // - "out of memory" errors during rapid account switching
        // - Connection failures when multiple databases are open
        //
        // iOS already encrypts swap via Data Protection, so this is redundant.
        // This MUST be set BEFORE the key pragma or it has no effect!
        // ═══════════════════════════════════════════════════════════════════════════
        conn.pragma_update(None, "cipher_memory_security", "OFF")
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to disable cipher_memory_security: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;

        // CRITICAL: PRAGMA key MUST be the first cipher operation on the connection.
        // All other cipher_* pragmas (plaintext_header_size, salt, page_size, etc.)
        // are silently ignored if set before the key.
        conn.pragma_update(None, "key", encryption_key)
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to set encryption key: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Leave 32-byte SQLite header in plaintext so iOS recognizes it as SQLite.
        // MUST be after PRAGMA key or it has no effect!
        conn.pragma_update(None, "cipher_plaintext_header_size", 32)
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to set cipher_plaintext_header_size: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;

        // Explicit salt (required when header is plaintext)
        conn.pragma_update(None, "cipher_salt", format!("x'{}'", salt_hex))
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to set cipher_salt: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Match SQLCipher 4 settings used on the Swift side (CatbirdMLSCore)
        conn.pragma_update(None, "cipher_page_size", 4096)
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to set cipher_page_size: {:?}", e);
                MLSError::StorageFailed
            })?;
        conn.pragma_update(None, "kdf_iter", 256000).map_err(|e| {
            crate::error_log!("[MANIFEST-STORAGE] Failed to set kdf_iter: {:?}", e);
            MLSError::StorageFailed
        })?;
        conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to set cipher_hmac_algorithm: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;
        conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to set cipher_kdf_algorithm: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;

        // Require WAL rather than assuming the requested mode was accepted.
        let journal_mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to set WAL mode: {:?}", e);
                MLSError::StorageFailed
            })?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            crate::error_log!(
                "[MANIFEST-STORAGE] Database rejected WAL mode: {}",
                journal_mode
            );
            return Err(MLSError::StorageFailed);
        }

        // MLS epoch transitions and key material require power-loss durability.
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to set synchronous mode: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Enable hardware-level durability (Signal uses these for crash safety)
        // checkpoint_fullfsync ensures WAL checkpoints use F_FULLFSYNC
        // fullfsync ensures regular fsync operations use F_FULLFSYNC on macOS/iOS
        conn.pragma_update(None, "checkpoint_fullfsync", "ON")
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to set checkpoint_fullfsync: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;
        conn.pragma_update(None, "fullfsync", "ON").map_err(|e| {
            crate::error_log!("[MANIFEST-STORAGE] Failed to set fullfsync: {:?}", e);
            MLSError::StorageFailed
        })?;

        // Retry on contention (matches MLSContext connection settings)
        conn.busy_timeout(NORMAL_BUSY_TIMEOUT).map_err(|e| {
            crate::error_log!("[MANIFEST-STORAGE] Failed to set busy_timeout: {:?}", e);
            MLSError::StorageFailed
        })?;

        let storage = Self {
            conn,
            write_count: AtomicU64::new(0),
        };
        storage.init_tables()?;
        Ok(storage)
    }

    /// Initialize manifest tables if they don't exist
    fn init_tables(&self) -> Result<(), MLSError> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS mls_manifests (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
                [],
            )
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to create table: {:?}", e);
                map_sqlite_error("create_table(mls_manifests)", &e)
            })?;

        // Per-row key package bundle storage. Replaces the monolithic
        // "key_package_bundles" JSON blob in mls_manifests, whose full
        // read-modify-write on every create/delete grew with install age and
        // widened the 0xdead10cc suspension-kill window.
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS mls_key_package_bundles (
                hash_ref TEXT PRIMARY KEY,
                bundle_b64 TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
                [],
            )
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to create bundle table: {:?}", e);
                map_sqlite_error("create_table(mls_key_package_bundles)", &e)
            })?;

        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS mls_own_echo_proofs (
                canonical_entry_sha256 BLOB PRIMARY KEY CHECK(length(canonical_entry_sha256) = 32),
                accepted_request_sha256 BLOB NOT NULL CHECK(length(accepted_request_sha256) = 32),
                conversation_id TEXT NOT NULL,
                group_id BLOB NOT NULL,
                server_entry_id TEXT NOT NULL,
                mls_epoch INTEGER NOT NULL CHECK(mls_epoch >= 0),
                aad_sha256 BLOB NOT NULL CHECK(length(aad_sha256) = 32),
                ciphertext_sha256 BLOB NOT NULL CHECK(length(ciphertext_sha256) = 32)
            )",
                [],
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to create mls_own_echo_proofs table: {:?}",
                    e
                );
                map_sqlite_error("create_table(mls_own_echo_proofs)", &e)
            })?;

        self.migrate_key_package_bundles_blob()?;

        Ok(())
    }

    /// One-time migration: move the legacy "key_package_bundles" JSON blob
    /// from mls_manifests into per-row mls_key_package_bundles entries.
    ///
    /// Idempotent and safe across processes (main app + NSE): runs in a single
    /// IMMEDIATE transaction with INSERT OR IGNORE; whichever process commits
    /// first deletes the blob, and the other finds nothing to migrate.
    fn migrate_key_package_bundles_blob(&self) -> Result<(), MLSError> {
        let blob: Option<HashMap<String, String>> = self.read_manifest("key_package_bundles")?;
        let Some(bundles_map) = blob else {
            return Ok(());
        };

        let now = unix_now_secs();
        crate::info_log!(
            "[MANIFEST-STORAGE] Migrating {} key package bundles from blob to per-row storage",
            bundles_map.len()
        );

        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| map_sqlite_error("bundle_migration.begin", &e))?;

        let migrate = || -> Result<(), rusqlite::Error> {
            for (hex_ref, bundle_b64) in &bundles_map {
                self.conn.execute(
                    "INSERT OR IGNORE INTO mls_key_package_bundles (hash_ref, bundle_b64, created_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![hex_ref, bundle_b64, now],
                )?;
            }
            self.conn.execute(
                "DELETE FROM mls_manifests WHERE key = 'key_package_bundles'",
                [],
            )?;
            Ok(())
        };

        match migrate() {
            Ok(()) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| map_sqlite_error("bundle_migration.commit", &e))?;
                crate::info_log!("[MANIFEST-STORAGE] ✅ Bundle blob migration complete");
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                crate::error_log!(
                    "[MANIFEST-STORAGE] ❌ Bundle blob migration failed: {:?}",
                    e
                );
                Err(map_sqlite_error("bundle_migration", &e))
            }
        }
    }

    /// Get an interrupt handle for aborting in-flight SQLCipher operations.
    pub(crate) fn get_interrupt_handle(&self) -> rusqlite::InterruptHandle {
        self.conn.get_interrupt_handle()
    }

    /// Force database flush to ensure all pending writes are committed to disk
    ///
    /// This performs a bounded FULL checkpoint and validates SQLite's
    /// busy/log/checkpointed result. Partial checkpoints are failures: callers
    /// must not advance an ACK/cursor or prune recovery secrets afterward.
    pub(crate) fn flush_database(&self) -> Result<(), MLSError> {
        self.conn
            .busy_timeout(DURABILITY_CHECKPOINT_TIMEOUT)
            .map_err(|e| map_sqlite_error("durability_checkpoint.busy_timeout", &e))?;

        let checkpoint_result = self
            .conn
            .query_row("PRAGMA main.wal_checkpoint(FULL);", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to run FULL WAL checkpoint: {:?}",
                    e
                );
                map_sqlite_error("wal_checkpoint(FULL)", &e)
            })
            .and_then(|(busy, log, checkpointed)| {
                validate_durability_checkpoint(busy, log, checkpointed)
            });

        let restore_result = self
            .conn
            .busy_timeout(NORMAL_BUSY_TIMEOUT)
            .map_err(|e| map_sqlite_error("durability_checkpoint.restore_timeout", &e));

        checkpoint_result?;
        restore_result?;
        crate::debug_log!("[MANIFEST-STORAGE] ✅ Database durability checkpoint (FULL) completed");
        Ok(())
    }

    /// Budget-based checkpoint (Signal's pattern)
    ///
    /// Increments write counter and performs a checkpoint when budget is reached.
    ///
    /// CRITICAL (2026-03): In extension processes (NSE), use PASSIVE mode instead of
    /// TRUNCATE. TRUNCATE requires exclusive WAL access — if the main app also has the
    /// DB open, two concurrent TRUNCATE attempts corrupt the WAL. PASSIVE is non-blocking
    /// and safe for cross-process use.
    ///
    /// Uses a short busy timeout (50ms) - if we can't checkpoint quickly, abort and retry
    /// sooner on the next write. This prevents blocking the caller.
    fn maybe_truncate_checkpoint(&self) {
        let count = self.write_count.fetch_add(1, Ordering::Relaxed);

        // Checkpoint every CHECKPOINT_BUDGET writes (default 32, Signal's number)
        if count > 0 && count.is_multiple_of(CHECKPOINT_BUDGET) {
            let pid = std::process::id();

            // Set short busy timeout for this checkpoint - don't block writers for long
            // If another connection is holding the lock, we'll just retry sooner
            if let Err(e) = self.conn.busy_timeout(std::time::Duration::from_millis(50)) {
                crate::debug_log!(
                    "[MANIFEST-STORAGE/pid={}] ⚠️ Failed to set busy_timeout for checkpoint: {:?}",
                    pid,
                    e
                );
                return;
            }

            // Log WAL state before checkpoint for cross-process corruption diagnostics
            match self
                .conn
                .query_row("PRAGMA wal_checkpoint(PASSIVE);", [], |row| {
                    let busy: i32 = row.get(0)?;
                    let log: i32 = row.get(1)?;
                    let checkpointed: i32 = row.get(2)?;
                    Ok((busy, log, checkpointed))
                }) {
                Ok((busy, log, checkpointed)) => {
                    crate::info_log!(
                        "[MANIFEST-STORAGE/pid={}] 📊 PRE-checkpoint WAL: busy={} log={} checkpointed={} (write #{})",
                        pid, busy, log, checkpointed, count
                    );
                }
                Err(e) => {
                    crate::debug_log!(
                        "[MANIFEST-STORAGE/pid={}] ⚠️ WAL probe failed: {:?}",
                        pid,
                        e
                    );
                }
            }

            // Determine checkpoint mode based on process type
            // Extension processes (appex) must use PASSIVE to avoid WAL corruption
            let is_extension = std::env::current_exe()
                .map(|p| p.to_string_lossy().contains(".appex/"))
                .unwrap_or(false);

            let checkpoint_sql = if is_extension {
                "PRAGMA wal_checkpoint(PASSIVE);"
            } else {
                "PRAGMA wal_checkpoint(TRUNCATE);"
            };
            let mode_name = if is_extension { "PASSIVE" } else { "TRUNCATE" };

            match self.conn.execute_batch(checkpoint_sql) {
                Ok(_) => {
                    crate::info_log!(
                        "[MANIFEST-STORAGE/pid={}] ✅ Budget {} checkpoint at write {} (budget {})",
                        pid,
                        mode_name,
                        count,
                        CHECKPOINT_BUDGET
                    );
                }
                Err(e) => {
                    // Checkpoint failed (likely contention) - this is okay, we'll retry sooner
                    crate::info_log!(
                        "[MANIFEST-STORAGE/pid={}] ⚠️ Budget {} checkpoint deferred at write {}: {:?}",
                        pid,
                        mode_name,
                        count,
                        e
                    );
                }
            }

            // Restore normal busy timeout
            let _ = self.conn.busy_timeout(std::time::Duration::from_secs(5));
        }
    }

    /// Synchronous checkpoint for app/extension launch.
    /// Called once at startup to clear any WAL pages left from the previous session.
    /// Uses a 3s busy timeout (longer than normal) since this only runs once at launch.
    ///
    /// CRITICAL (2026-03): Extensions use PASSIVE mode to avoid WAL corruption from
    /// concurrent TRUNCATE with the main app.
    pub(crate) fn launch_truncate_checkpoint(&self) -> Result<(), MLSError> {
        let pid = std::process::id();
        let is_extension = std::env::current_exe()
            .map(|p| p.to_string_lossy().contains(".appex/"))
            .unwrap_or(false);

        // Set longer busy timeout for launch checkpoint
        self.conn
            .busy_timeout(std::time::Duration::from_secs(3))
            .map_err(|e| {
                crate::debug_log!(
                    "[MANIFEST-STORAGE/pid={}] ⚠️ Failed to set launch busy_timeout: {:?}",
                    pid,
                    e
                );
                map_sqlite_error("launch_checkpoint.busy_timeout", &e)
            })?;

        // Extensions must use PASSIVE to avoid WAL corruption
        let checkpoint_sql = if is_extension {
            "PRAGMA wal_checkpoint(PASSIVE);"
        } else {
            "PRAGMA wal_checkpoint(TRUNCATE);"
        };
        let mode_name = if is_extension { "PASSIVE" } else { "TRUNCATE" };

        match self.conn.execute_batch(checkpoint_sql) {
            Ok(_) => {
                crate::info_log!(
                    "[MANIFEST-STORAGE/pid={}] ✅ Launch {} checkpoint completed",
                    pid,
                    mode_name
                );
            }
            Err(e) => {
                // SQLITE_BUSY is tolerable at launch - WAL will be checkpointed during normal operation
                crate::info_log!(
                    "[MANIFEST-STORAGE/pid={}] ⚠️ Launch {} checkpoint deferred (busy): {:?}",
                    pid,
                    mode_name,
                    e
                );
            }
        }

        // Restore normal busy timeout
        let _ = self.conn.busy_timeout(std::time::Duration::from_secs(5));

        Ok(())
    }

    /// Write a manifest (JSON-serialized value)
    ///
    /// After every write, checks the budget counter and performs a TRUNCATE checkpoint
    /// if the budget is reached. This keeps the WAL file perpetually small.
    pub(crate) fn write_manifest<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), MLSError> {
        let json = serde_json::to_string(value).map_err(|_| MLSError::SerializationError)?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO mls_manifests (key, value) VALUES (?1, ?2)",
                [key, &json],
            )
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to write manifest: {:?}", e);
                map_sqlite_error("write_manifest", &e)
            })?;

        // Signal-style budget checkpoint: keep WAL perpetually small
        self.maybe_truncate_checkpoint();

        Ok(())
    }

    /// Read a manifest (deserialize from JSON)
    pub(crate) fn read_manifest<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, MLSError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM mls_manifests WHERE key = ?1")
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to prepare query: {:?}", e);
                map_sqlite_error("read_manifest.prepare", &e)
            })?;

        let result = stmt.query_row([key], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        });

        match result {
            Ok(json) => {
                let value: T =
                    serde_json::from_str(&json).map_err(|_| MLSError::SerializationError)?;
                Ok(Some(value))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(map_sqlite_error("read_manifest.query_row", &e)),
        }
    }

    // ─── Per-row key package bundle storage ────────────────────────────────

    /// Insert (or replace) key package bundle rows in a single transaction.
    /// Entries are (hex hash_ref, base64 bundle JSON) pairs.
    pub(crate) fn insert_bundles(&self, bundles: &[(String, String)]) -> Result<(), MLSError> {
        if bundles.is_empty() {
            return Ok(());
        }
        let now = unix_now_secs();
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| map_sqlite_error("insert_bundles.begin", &e))?;
        for (hex_ref, bundle_b64) in bundles {
            tx.execute(
                "INSERT OR REPLACE INTO mls_key_package_bundles (hash_ref, bundle_b64, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![hex_ref, bundle_b64, now],
            )
            .map_err(|e| map_sqlite_error("insert_bundles", &e))?;
        }
        tx.commit()
            .map_err(|e| map_sqlite_error("insert_bundles.commit", &e))?;
        self.maybe_truncate_checkpoint();
        Ok(())
    }

    /// Delete bundle rows by hex hash_ref. Returns the number of rows removed.
    pub(crate) fn delete_bundles(&self, hex_refs: &[String]) -> Result<usize, MLSError> {
        if hex_refs.is_empty() {
            return Ok(0);
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| map_sqlite_error("delete_bundles.begin", &e))?;
        let mut removed = 0usize;
        for hex_ref in hex_refs {
            removed += tx
                .execute(
                    "DELETE FROM mls_key_package_bundles WHERE hash_ref = ?1",
                    [hex_ref],
                )
                .map_err(|e| map_sqlite_error("delete_bundles", &e))?;
        }
        tx.commit()
            .map_err(|e| map_sqlite_error("delete_bundles.commit", &e))?;
        self.maybe_truncate_checkpoint();
        Ok(removed)
    }

    /// Load all bundle rows as (hex hash_ref, base64 bundle JSON) pairs.
    pub(crate) fn load_all_bundles(&self) -> Result<Vec<(String, String)>, MLSError> {
        let mut stmt = self
            .conn
            .prepare("SELECT hash_ref, bundle_b64 FROM mls_key_package_bundles")
            .map_err(|e| map_sqlite_error("load_all_bundles.prepare", &e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| map_sqlite_error("load_all_bundles.query", &e))?;
        let mut bundles = Vec::new();
        for row in rows {
            bundles.push(row.map_err(|e| map_sqlite_error("load_all_bundles.row", &e))?);
        }
        Ok(bundles)
    }

    /// Number of stored bundle rows.
    pub(crate) fn count_bundles(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM mls_key_package_bundles", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap_or(0)
    }

    /// First `limit` bundle hash_refs (hex), for diagnostics.
    pub(crate) fn list_bundle_refs(&self, limit: usize) -> Vec<String> {
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT hash_ref FROM mls_key_package_bundles LIMIT ?1")
        else {
            return Vec::new();
        };
        let refs = match stmt.query_map([limit], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        refs
    }

    /// Whether a bundle row exists for the given hex hash_ref.
    pub(crate) fn contains_bundle(&self, hex_ref: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM mls_key_package_bundles WHERE hash_ref = ?1",
                [hex_ref],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Remove bundle rows older than `max_age_secs`. Returns the pruned hex
    /// hash_refs so callers can evict matching in-memory cache entries.
    pub(crate) fn prune_bundles_older_than(
        &self,
        max_age_secs: u64,
    ) -> Result<Vec<String>, MLSError> {
        let cutoff = unix_now_secs().saturating_sub(max_age_secs as i64);
        let mut stmt = self
            .conn
            .prepare("SELECT hash_ref FROM mls_key_package_bundles WHERE created_at < ?1")
            .map_err(|e| map_sqlite_error("prune_bundles.prepare", &e))?;
        let expired: Vec<String> = stmt
            .query_map([cutoff], |row| row.get::<_, String>(0))
            .map_err(|e| map_sqlite_error("prune_bundles.query", &e))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        if expired.is_empty() {
            return Ok(expired);
        }
        self.conn
            .execute(
                "DELETE FROM mls_key_package_bundles WHERE created_at < ?1",
                [cutoff],
            )
            .map_err(|e| map_sqlite_error("prune_bundles.delete", &e))?;
        self.maybe_truncate_checkpoint();
        crate::info_log!(
            "[MANIFEST-STORAGE] 🧹 Pruned {} expired key package bundles (older than {}s)",
            expired.len(),
            max_age_secs
        );
        Ok(expired)
    }

    /// DEBUG: Count key packages in OpenMLS's internal storage table.
    /// Both ManifestStorage and OpenMLS use the same SQLite DB file,
    /// so we can query their table directly.
    pub(crate) fn debug_count_openmls_key_packages(&self) -> usize {
        match self
            .conn
            .query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
                row.get::<_, usize>(0)
            }) {
            Ok(count) => count,
            Err(e) => {
                crate::warn_log!(
                    "[MANIFEST-STORAGE] Could not count openmls_key_packages: {:?}",
                    e
                );
                0
            }
        }
    }

    /// DEBUG: List first N key package hash_refs from OpenMLS's internal storage table.
    pub(crate) fn debug_list_openmls_key_package_refs(&self, limit: usize) -> Vec<String> {
        match self
            .conn
            .prepare("SELECT hex(key_package_ref) FROM openmls_key_packages LIMIT ?1")
        {
            Ok(mut stmt) => match stmt.query_map([limit], |row| row.get::<_, String>(0)) {
                Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
                Err(e) => {
                    crate::warn_log!(
                        "[MANIFEST-STORAGE] Could not list openmls key_package_refs: {:?}",
                        e
                    );
                    Vec::new()
                }
            },
            Err(e) => {
                crate::warn_log!(
                    "[MANIFEST-STORAGE] Could not prepare openmls key_package_refs query: {:?}",
                    e
                );
                Vec::new()
            }
        }
    }

    pub(crate) fn store_own_echo_proof(&self, proof: &OwnEchoProof) -> Result<(), MLSError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO mls_own_echo_proofs (
                    canonical_entry_sha256,
                    accepted_request_sha256,
                    conversation_id,
                    group_id,
                    server_entry_id,
                    mls_epoch,
                    aad_sha256,
                    ciphertext_sha256
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    &proof.canonical_entry_sha256[..],
                    &proof.accepted_request_sha256[..],
                    &proof.conversation_id,
                    &proof.group_id[..],
                    &proof.server_entry_id,
                    proof.mls_epoch as i64,
                    &proof.aad_sha256[..],
                    &proof.ciphertext_sha256[..],
                ],
            )
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to store own echo proof: {:?}", e);
                map_sqlite_error("store_own_echo_proof", &e)
            })?;
        self.maybe_truncate_checkpoint();
        Ok(())
    }

    pub(crate) fn has_own_echo_proof(
        &self,
        conversation_id: &str,
        group_id: &[u8],
        server_entry_id: &str,
        mls_epoch: u64,
        aad_sha256: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
    ) -> Result<bool, MLSError> {
        let canonical_entry_sha256 = OwnEchoProof::compute_canonical_entry_sha256(
            conversation_id,
            group_id,
            server_entry_id,
            mls_epoch,
            aad_sha256,
            ciphertext_sha256,
        );
        let mut stmt = self
            .conn
            .prepare(
                "SELECT 1 FROM mls_own_echo_proofs WHERE
                    canonical_entry_sha256 = ?1 AND
                    conversation_id = ?2 AND
                    group_id = ?3 AND
                    server_entry_id = ?4 AND
                    mls_epoch = ?5 AND
                    aad_sha256 = ?6 AND
                    ciphertext_sha256 = ?7",
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MANIFEST-STORAGE] Failed to prepare has_own_echo_proof: {:?}",
                    e
                );
                map_sqlite_error("has_own_echo_proof.prepare", &e)
            })?;
        stmt.exists(rusqlite::params![
            &canonical_entry_sha256[..],
            conversation_id,
            group_id,
            server_entry_id,
            mls_epoch as i64,
            &aad_sha256[..],
            &ciphertext_sha256[..],
        ])
        .map_err(|e| {
            crate::error_log!(
                "[MANIFEST-STORAGE] Failed to check has_own_echo_proof: {:?}",
                e
            );
            map_sqlite_error("has_own_echo_proof.exists", &e)
        })
    }
}

/// JSON codec for SqliteStorageProvider
/// This implements the Codec trait required by openmls_sqlite_storage
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

use crate::hybrid_storage::HybridStorageProvider;
use crate::keychain::KeychainAccess;

/// Custom provider combining LibcruxCrypto with HybridStorageProvider
/// This uses persistent SQLite storage for group state and Keychain for keys.
/// LibcruxCrypto enables post-quantum X-Wing (MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519).
pub struct SqliteLibcruxProvider {
    crypto: LibcruxCrypto,
    storage: HybridStorageProvider<JsonCodec>,
}

impl SqliteLibcruxProvider {
    pub fn new(storage: HybridStorageProvider<JsonCodec>) -> Result<Self, MLSError> {
        Ok(Self {
            crypto: LibcruxCrypto::new()
                .map_err(|e| MLSError::Internal(format!("Crypto init failed: {:?}", e)))?,
            storage,
        })
    }
}

impl OpenMlsProvider for SqliteLibcruxProvider {
    type CryptoProvider = LibcruxCrypto;
    type RandProvider = LibcruxCrypto;
    type StorageProvider = HybridStorageProvider<JsonCodec>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// MlsProvider enum removed - use MLSContextVariant instead

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct PendingExternalJoin {
    signer_public_key: Vec<u8>,
    minted_signer_identity: Option<Vec<u8>>,
}

pub struct GroupState {
    pub group: MlsGroup,
    pub signer_public_key: Vec<u8>,
    /// Present until the locally finalized External Commit is accepted by the
    /// server. The nested identity exists only when this candidate minted its
    /// signer and therefore owns signer cleanup on rejection.
    pending_external_join: Option<PendingExternalJoin>,
}

pub struct MLSContext {
    pub(crate) provider: SqliteLibcruxProvider,
    pub(crate) groups: HashMap<Vec<u8>, GroupState>,
    signers_by_identity: HashMap<Vec<u8>, Vec<u8>>, // identity -> public key bytes
    pub(crate) key_package_bundles: HashMap<Vec<u8>, KeyPackageBundle>, // hash_ref -> bundle
    epoch_secret_manager: Arc<EpochSecretManager>,
    pub(crate) manifest_storage: ManifestStorage,
    // Per-context replay detection and sequencing
    pub(crate) processed_messages: HashMap<Vec<u8>, Vec<(u64, u32)>>,
    pub(crate) sequence_counters: HashMap<Vec<u8>, u64>,
    /// Ephemeral in-memory content root key used for field-level (envelope)
    /// encryption of message payloads (see `crate::field_encryption`). Set by
    /// the platform after MLS group sync exports the per-conversation secret;
    /// never persisted by this layer.
    content_root_key: std::sync::RwLock<Option<Vec<u8>>>,
}

use openmls::group::MlsGroupJoinConfig;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;

impl MLSContext {
    /// Create a new context with SQLite storage at the specified path (per-DID)
    /// Path should be a .db file, e.g., "/path/to/mls-state/{did_hash}.db"
    ///
    /// This creates a per-account SQLite database for MLS cryptographic state.
    /// For user content (transcripts), continue using SQLCipher separately.
    /// Returns `(context, interrupt_handles)`. The interrupt handles are extracted from
    /// the SQLCipher connections before they are consumed, so the caller can store them
    /// outside any Mutex and call `sqlite3_interrupt()` from any thread.
    pub fn new(
        storage_path: String,
        encryption_key: String,
        keychain: Box<dyn KeychainAccess>,
    ) -> Result<(Self, Vec<rusqlite::InterruptHandle>), MLSError> {
        crate::info_log!(
            "[MLS-CONTEXT] Initializing per-DID SQLite storage: {}",
            storage_path
        );

        let path = PathBuf::from(&storage_path);
        let salt_hex = derive_cipher_salt_hex(&encryption_key);

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            // Try to create directory, ignoring "already exists" error (error kind 17 / AlreadyExists)
            // This handles Mac Catalyst quirks with quarantine attributes
            match std::fs::create_dir_all(parent) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Directory already exists, this is fine
                    crate::debug_log!(
                        "[MLS-CONTEXT] Storage directory already exists: {:?}",
                        parent
                    );
                }
                Err(e) => {
                    crate::error_log!("[MLS-CONTEXT] Failed to create storage directory: {:?}", e);
                    return Err(MLSError::invalid_input(format!(
                        "Failed to create storage directory: {}",
                        e
                    )));
                }
            }
        }

        // Open SQLite connection via openmls_sqlite_storage (not rusqlite directly)
        let connection = Connection::open(&path).map_err(|e| {
            crate::error_log!("[MLS-CONTEXT] Failed to open SQLite database: {:?}", e);
            MLSError::invalid_input(format!("Failed to open SQLite database: {:?}", e))
        })?;

        // Capture interrupt handle BEFORE the connection is consumed by SqliteStorageProvider.
        // This allows aborting in-flight SQLCipher operations from another thread during
        // iOS app suspension (0xdead10cc prevention).
        let openmls_interrupt_handle = connection.get_interrupt_handle();

        // ═══════════════════════════════════════════════════════════════════════════
        // CRITICAL FIX: Disable SQLCipher memory security BEFORE setting the key
        // ═══════════════════════════════════════════════════════════════════════════
        // cipher_memory_security = ON causes SQLCipher to lock memory pages using
        // mlock() to prevent sensitive data from being swapped to disk. However,
        // on iOS this triggers:
        // - SQLITE_NOMEM (error 7) when the mlock quota is exhausted
        // - "out of memory" errors during rapid account switching
        // - Connection failures when multiple databases are open
        //
        // iOS already encrypts swap via Data Protection, so this is redundant.
        // This MUST be set BEFORE the key pragma or it has no effect!
        // ═══════════════════════════════════════════════════════════════════════════
        connection
            .pragma_update(None, "cipher_memory_security", "OFF")
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] Failed to disable cipher_memory_security: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;

        // CRITICAL: PRAGMA key MUST be the first cipher operation on the connection.
        // All other cipher_* pragmas (plaintext_header_size, salt, page_size, etc.)
        // are silently ignored if set before the key.
        connection
            .pragma_update(None, "key", &encryption_key)
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set encryption key: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Leave 32-byte SQLite header in plaintext so iOS recognizes it as SQLite.
        // MUST be after PRAGMA key or it has no effect!
        connection
            .pragma_update(None, "cipher_plaintext_header_size", 32)
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] Failed to set cipher_plaintext_header_size: {:?}",
                    e
                );
                MLSError::StorageFailed
            })?;

        // Explicit salt (required when header is plaintext)
        connection
            .pragma_update(None, "cipher_salt", format!("x'{}'", salt_hex))
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set cipher_salt: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Match SQLCipher 4 settings used on the Swift side (CatbirdMLSCore)
        connection
            .pragma_update(None, "cipher_page_size", 4096)
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set cipher_page_size: {:?}", e);
                MLSError::StorageFailed
            })?;
        connection
            .pragma_update(None, "kdf_iter", 256000)
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set kdf_iter: {:?}", e);
                MLSError::StorageFailed
            })?;
        connection
            .pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set cipher_hmac_algorithm: {:?}", e);
                MLSError::StorageFailed
            })?;
        connection
            .pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set cipher_kdf_algorithm: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Match manifest storage settings and require WAL to be active.
        let journal_mode: String = connection
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set WAL mode: {:?}", e);
                MLSError::StorageFailed
            })?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            crate::error_log!("[MLS-CONTEXT] Database rejected WAL mode: {}", journal_mode);
            return Err(MLSError::StorageFailed);
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set synchronous mode: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Enable hardware-level durability (Signal uses these for crash safety)
        // checkpoint_fullfsync ensures WAL checkpoints use F_FULLFSYNC
        // fullfsync ensures regular fsync operations use F_FULLFSYNC on macOS/iOS
        connection
            .pragma_update(None, "checkpoint_fullfsync", "ON")
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set checkpoint_fullfsync: {:?}", e);
                MLSError::StorageFailed
            })?;
        connection
            .pragma_update(None, "fullfsync", "ON")
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set fullfsync: {:?}", e);
                MLSError::StorageFailed
            })?;

        connection.busy_timeout(NORMAL_BUSY_TIMEOUT).map_err(|e| {
            crate::error_log!("[MLS-CONTEXT] Failed to set busy_timeout: {:?}", e);
            MLSError::StorageFailed
        })?;

        // Create storage provider with JsonCodec
        let mut sqlite_storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);

        // Run migrations to set up OpenMLS schema
        // NOTE: "Out of memory" errors here typically indicate WRONG ENCRYPTION KEY.
        // SQLCipher returns misleading "out of memory" when the key is incorrect.
        sqlite_storage.run_migrations().map_err(|e| {
            let error_str = format!("{:?}", e);
            crate::error_log!("[MLS-CONTEXT] Failed to run OpenMLS migrations: {:?}", e);

            // CRITICAL: Detect SQLCipher wrong-key errors (misleading "out of memory")
            // This happens when:
            // 1. Database was created with a different encryption key
            // 2. Keychain entry was lost/reset
            // 3. Device restore brought database but not keychain
            if error_str.contains("OutOfMemory") || error_str.contains("out of memory") {
                crate::error_log!(
                    "[MLS-CONTEXT] 🔑 LIKELY CAUSE: Wrong encryption key for existing database!"
                );
                crate::error_log!(
                    "[MLS-CONTEXT]    SQLCipher returns 'out of memory' when decryption fails"
                );
                crate::error_log!("[MLS-CONTEXT]    This typically means:");
                crate::error_log!("[MLS-CONTEXT]    1. Keychain entry was lost/reset");
                crate::error_log!("[MLS-CONTEXT]    2. Device restore brought DB but not keychain");
                crate::error_log!("[MLS-CONTEXT]    3. App reinstall without keychain backup");
                crate::error_log!(
                    "[MLS-CONTEXT] 🔧 FIX: Delete the database file and re-register device"
                );
                return MLSError::invalid_input(
                    "Database encryption key mismatch (SQLCipher 'out of memory'). \
                         Database file exists but cannot be decrypted with current key. \
                         Delete database and re-register device."
                        .to_string(),
                );
            }

            MLSError::invalid_input(format!("Failed to run migrations: {:?}", e))
        })?;

        crate::info_log!("[MLS-CONTEXT] ✅ SQLite storage initialized with migrations complete");

        // Wrap in our custom provider
        let hybrid_storage = HybridStorageProvider::new(sqlite_storage, keychain);
        let provider = SqliteLibcruxProvider::new(hybrid_storage)?;

        // Initialize manifest storage for application data
        let manifest_storage = ManifestStorage::new(path.clone(), &encryption_key)?;
        crate::info_log!("[MLS-CONTEXT] ✅ Manifest storage initialized");

        // 🔄 BUNDLE LOADING: Load all persisted key package bundles from storage
        // This populates the in-memory cache with bundles that survived app restarts
        crate::info_log!("[MLS-CONTEXT] 🔄 Loading persisted key package bundles...");

        let mut key_package_bundles = HashMap::new();

        // Load all bundle rows (per-row storage; legacy blob is migrated on open)
        let bundle_rows = manifest_storage.load_all_bundles()?;
        if bundle_rows.is_empty() {
            crate::info_log!("[MLS-CONTEXT] 📋 No bundles found, starting with empty bundle cache");
        } else {
            crate::info_log!(
                "[MLS-CONTEXT] 📋 Found {} bundle entries",
                bundle_rows.len()
            );

            let total = bundle_rows.len();
            let mut loaded_count = 0;
            for (hex_ref, bundle_b64) in bundle_rows {
                // Decode base64 first (bundles are stored as base64-encoded JSON)
                match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &bundle_b64,
                ) {
                    Ok(bundle_json_bytes) => {
                        // Then deserialize JSON
                        match serde_json::from_slice::<openmls::prelude::KeyPackageBundle>(
                            &bundle_json_bytes,
                        ) {
                            Ok(bundle) => {
                                if let Ok(hash_ref) = hex::decode(&hex_ref) {
                                    key_package_bundles.insert(hash_ref, bundle);
                                    loaded_count += 1;
                                } else {
                                    crate::error_log!(
                                        "[MLS-CONTEXT] ⚠️ Failed to decode hash ref: {}",
                                        hex_ref
                                    );
                                }
                            }
                            Err(e) => {
                                crate::error_log!(
                                    "[MLS-CONTEXT] ⚠️ Failed to deserialize bundle {}: {:?}",
                                    hex_ref,
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        crate::error_log!(
                            "[MLS-CONTEXT] ⚠️ Failed to decode base64 for bundle {}: {:?}",
                            hex_ref,
                            e
                        );
                    }
                }
            }

            crate::info_log!(
                "[MLS-CONTEXT] ✅ Loaded {} / {} bundles successfully",
                loaded_count,
                total
            );
        }

        // 🔄 SIGNER LOADING: Load all persisted signer identity mappings FIRST
        // (must be loaded before groups so we can restore signer_public_key)
        crate::info_log!("[MLS-CONTEXT] 🔄 Loading persisted signer mappings...");
        let mut signers_by_identity = HashMap::new();

        // Track stale signers that need to be cleaned up from manifest
        let mut stale_signers: Vec<String> = Vec::new();

        match manifest_storage.read_manifest::<HashMap<String, String>>("signers")? {
            Some(signers_map) => {
                crate::info_log!(
                    "[MLS-CONTEXT] 📋 Found {} signer entries in manifest",
                    signers_map.len()
                );

                for (hex_identity, hex_public_key) in &signers_map {
                    if let (Ok(identity), Ok(public_key)) =
                        (hex::decode(hex_identity), hex::decode(hex_public_key))
                    {
                        // 🔍 CRITICAL FIX: Verify the SignatureKeyPair actually exists in OpenMLS storage
                        // Stale manifest entries (where keypair was lost) will be detected and cleaned up
                        let signer_available = SignatureKeyPair::read(
                            provider.storage(),
                            &public_key,
                            SignatureScheme::ED25519,
                        )
                        .is_some()
                            || provider.storage().migrate_legacy_signature_key_pair(
                                &public_key,
                                SignatureScheme::ED25519,
                            )?;
                        match signer_available {
                            true => {
                                // Keypair exists in storage, this mapping is valid
                                signers_by_identity.insert(identity, public_key);
                            }
                            false => {
                                // Keypair NOT in storage - this is a stale mapping
                                let identity_str = String::from_utf8_lossy(&identity);
                                crate::error_log!("[MLS-CONTEXT] ⚠️ STALE SIGNER: {} -> {} (keypair not in storage, will be removed)", 
                                    identity_str, hex::encode(&public_key));
                                stale_signers.push(hex_identity.clone());
                            }
                        }
                    }
                }

                crate::info_log!(
                    "[MLS-CONTEXT] ✅ Loaded {} valid signer mappings ({} stale entries removed)",
                    signers_by_identity.len(),
                    stale_signers.len()
                );

                // Clean up stale entries from manifest if any were found
                if !stale_signers.is_empty() {
                    let mut cleaned_signers = signers_map.clone();
                    for stale_key in &stale_signers {
                        cleaned_signers.remove(stale_key);
                    }
                    if let Err(e) = manifest_storage.write_manifest("signers", &cleaned_signers) {
                        crate::error_log!(
                            "[MLS-CONTEXT] ⚠️ Failed to clean up stale signers from manifest: {:?}",
                            e
                        );
                    } else {
                        crate::info_log!(
                            "[MLS-CONTEXT] ✅ Cleaned up {} stale signer entries from manifest",
                            stale_signers.len()
                        );
                    }
                }
            }
            None => {
                crate::info_log!(
                    "[MLS-CONTEXT] 📋 No signers found, starting with empty signer cache"
                );
            }
        }

        // 🔄 GROUP LOADING: Load all persisted groups from storage
        crate::info_log!("[MLS-CONTEXT] 🔄 Loading persisted groups...");
        let mut groups = HashMap::new();
        let mut recovered_legacy_signers = false;
        let mut pending_external_joins: HashMap<String, PendingExternalJoin> = manifest_storage
            .read_manifest("pending_external_joins")?
            .unwrap_or_default();

        match manifest_storage.read_manifest::<Vec<String>>("group_ids")? {
            Some(group_id_list) => {
                crate::info_log!(
                    "[MLS-CONTEXT] 📋 Found {} group IDs in manifest",
                    group_id_list.len()
                );

                let mut loaded_count = 0;
                let mut orphaned_ids: Vec<String> = Vec::new();
                for hex_id in &group_id_list {
                    if let Ok(group_id_bytes) = hex::decode(hex_id) {
                        let group_id = openmls::prelude::GroupId::from_slice(&group_id_bytes);

                        crate::debug_log!("[MLS-CONTEXT] 🔍 Loading group: {}", hex_id);

                        match openmls::prelude::MlsGroup::load(provider.storage(), &group_id) {
                            Ok(Some(mut group)) => {
                                let join_config = openmls::group::MlsGroupJoinConfig::builder()
                                    .wire_format_policy(
                                        openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
                                    )
                                    .use_ratchet_tree_extension(true)
                                    .build();
                                let _ = group.set_configuration(provider.storage(), &join_config);
                                let loaded_epoch = group.epoch().as_u64();
                                let loaded_members = group.members().count();
                                crate::info_log!("[MLS-CONTEXT] ✅ Group loaded from storage:");
                                crate::info_log!("[MLS-CONTEXT]   Group ID: {}", hex_id);
                                crate::info_log!("[MLS-CONTEXT]   Epoch: {}", loaded_epoch);
                                crate::info_log!("[MLS-CONTEXT]   Members: {}", loaded_members);

                                // Restore the signer from an exact credential + leaf-key
                                // binding. Legacy databases can predate the signer manifest;
                                // recover those only when OpenMLS storage still proves possession
                                // of the precise private key authenticated by the own leaf.
                                let signer_public_key = if let Some(own_leaf) =
                                    group.own_leaf_node()
                                {
                                    let own_credential = own_leaf.credential().serialized_content();
                                    let leaf_signature_key =
                                        own_leaf.signature_key().as_slice().to_vec();

                                    if let Some(pk) = signers_by_identity.get(own_credential) {
                                        if pk != &leaf_signature_key {
                                            crate::error_log!(
                                                "[MLS-CONTEXT] Signer manifest does not match own leaf for group {}",
                                                hex_id
                                            );
                                            return Err(MLSError::StorageFailed);
                                        }
                                        crate::debug_log!(
                                            "[MLS-CONTEXT] ✅ Restored signer for group {}",
                                            hex_id
                                        );
                                        pk.clone()
                                    } else if SignatureKeyPair::read(
                                        provider.storage(),
                                        &leaf_signature_key,
                                        SignatureScheme::ED25519,
                                    )
                                    .is_some()
                                    {
                                        crate::info_log!(
                                            "[MLS-CONTEXT] Recovering legacy signer manifest entry for group {}",
                                            hex_id
                                        );
                                        signers_by_identity.insert(
                                            own_credential.to_vec(),
                                            leaf_signature_key.clone(),
                                        );
                                        recovered_legacy_signers = true;
                                        leaf_signature_key
                                    } else {
                                        crate::error_log!(
                                            "[MLS-CONTEXT] No durable leaf-bound signer found for group {} credential",
                                            hex_id
                                        );
                                        return Err(MLSError::StorageFailed);
                                    }
                                } else {
                                    crate::error_log!(
                                        "[MLS-CONTEXT] Group {} has no own leaf node",
                                        hex_id
                                    );
                                    return Err(MLSError::StorageFailed);
                                };

                                // Skip verification round-trip in production to speed up initialization
                                // The double-load was only useful for debugging storage consistency
                                let pending_external_join =
                                    pending_external_joins.get(hex_id).cloned();
                                if pending_external_join.as_ref().is_some_and(|pending| {
                                    pending.signer_public_key != signer_public_key
                                }) {
                                    crate::error_log!(
                                        "[MLS-CONTEXT] Pending external-join signer mismatch for group {}",
                                        hex_id
                                    );
                                    return Err(MLSError::StorageFailed);
                                }

                                groups.insert(
                                    group_id_bytes,
                                    GroupState {
                                        group,
                                        signer_public_key,
                                        pending_external_join,
                                    },
                                );
                                loaded_count += 1;
                            }
                            Ok(None) => {
                                crate::error_log!("[MLS-CONTEXT] ⚠️ Group {} exists in manifest but not in OpenMLS storage", hex_id);
                                crate::error_log!("[MLS-CONTEXT]   This indicates the manifest is out of sync with storage");
                                orphaned_ids.push(hex_id.clone());
                            }
                            Err(e) => {
                                crate::error_log!(
                                    "[MLS-CONTEXT] ⚠️ Failed to load group {}: {:?}",
                                    hex_id,
                                    e
                                );
                                orphaned_ids.push(hex_id.clone());
                            }
                        }
                    }
                }

                crate::info_log!(
                    "[MLS-CONTEXT] ✅ Loaded {} / {} groups successfully",
                    loaded_count,
                    group_id_list.len()
                );

                if !orphaned_ids.is_empty() {
                    crate::info_log!(
                        "[MLS-CONTEXT] Cleaning {} orphaned manifest entries",
                        orphaned_ids.len()
                    );
                    if let Ok(Some(mut group_ids)) =
                        manifest_storage.read_manifest::<Vec<String>>("group_ids")
                    {
                        group_ids.retain(|id| !orphaned_ids.contains(id));
                        let _ = manifest_storage.write_manifest("group_ids", &group_ids);
                    }
                }
            }
            None => {
                crate::info_log!(
                    "[MLS-CONTEXT] 📋 No groups found, starting with empty group cache"
                );
            }
        }

        if recovered_legacy_signers {
            let signer_manifest: HashMap<String, String> = signers_by_identity
                .iter()
                .map(|(identity, public_key)| (hex::encode(identity), hex::encode(public_key)))
                .collect();
            manifest_storage.write_manifest("signers", &signer_manifest)?;
            manifest_storage.flush_database()?;
        }

        let pending_count_before = pending_external_joins.len();
        pending_external_joins.retain(|hex_group_id, _| {
            hex::decode(hex_group_id)
                .ok()
                .is_some_and(|group_id| groups.contains_key(&group_id))
        });
        if pending_external_joins.len() != pending_count_before {
            manifest_storage.write_manifest("pending_external_joins", &pending_external_joins)?;
        }

        let manifest_interrupt_handle = manifest_storage.get_interrupt_handle();

        Ok((
            Self {
                provider,
                groups,              // Use the loaded groups
                signers_by_identity, // Use the loaded signers
                key_package_bundles, // Use the loaded bundles
                epoch_secret_manager: Arc::new(EpochSecretManager::new()),
                manifest_storage,
                processed_messages: HashMap::new(),
                sequence_counters: HashMap::new(),
                content_root_key: std::sync::RwLock::new(None),
            },
            vec![openmls_interrupt_handle, manifest_interrupt_handle],
        ))
    }

    /// Force database flush to ensure all pending writes are persisted to disk
    ///
    /// CRITICAL: Call this after state-changing operations like Welcome processing
    /// to ensure secret tree state survives app restarts.
    pub fn flush_database(&self) -> Result<(), MLSError> {
        self.manifest_storage.flush_database()
    }

    /// Budget-based TRUNCATE checkpoint (Signal's pattern)
    ///
    /// Call this after any MLS operation that writes to the database (e.g., creating groups,
    /// processing commits, encrypting/decrypting messages). The checkpoint keeps the WAL
    /// file perpetually small, preventing 0xdead10cc crashes during iOS suspension.
    ///
    /// Note: This uses the ManifestStorage connection to checkpoint, but since SQLite WAL
    /// is shared across all connections to the same database file, this also checkpoints
    /// writes from the OpenMLS SqliteStorageProvider.
    pub fn maybe_truncate_checkpoint(&self) {
        self.manifest_storage.maybe_truncate_checkpoint()
    }

    /// Perform a launch-time TRUNCATE checkpoint on the manifest storage.
    /// Call this once at app startup to clear leftover WAL from previous session.
    pub fn launch_checkpoint(&self) -> Result<(), MLSError> {
        self.manifest_storage.launch_truncate_checkpoint()
    }

    /// Get reference to epoch secret manager for setting storage backend
    pub fn epoch_secret_manager(&self) -> &Arc<EpochSecretManager> {
        &self.epoch_secret_manager
    }

    /// Get a reference to the provider's crypto
    pub fn provider_crypto(&self) -> &LibcruxCrypto {
        self.provider.crypto()
    }

    /// Store a proven own-message echo proof inside the encrypted MLS database.
    pub fn store_own_echo_proof(&self, proof: &OwnEchoProof) -> Result<(), MLSError> {
        self.manifest_storage.store_own_echo_proof(proof)
    }

    /// Query non-destructively for an exact own-message echo proof.
    pub fn has_own_echo_proof(
        &self,
        conversation_id: &str,
        group_id: &[u8],
        server_entry_id: &str,
        mls_epoch: u64,
        aad_sha256: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
    ) -> Result<bool, MLSError> {
        self.manifest_storage.has_own_echo_proof(
            conversation_id,
            group_id,
            server_entry_id,
            mls_epoch,
            aad_sha256,
            ciphertext_sha256,
        )
    }

    /// Get mutable access to key_package_bundles
    pub fn key_package_bundles_mut(&mut self) -> &mut HashMap<Vec<u8>, KeyPackageBundle> {
        &mut self.key_package_bundles
    }

    /// Get immutable access to key_package_bundles
    pub fn key_package_bundles(&self) -> &HashMap<Vec<u8>, KeyPackageBundle> {
        &self.key_package_bundles
    }

    /// Reconcile the in-memory + persisted KeyPackageBundle cache against
    /// OpenMLS's authoritative `openmls_key_packages` storage. Drops any
    /// cached bundles whose hash_ref OpenMLS no longer holds (typically
    /// because OpenMLS consumed it during a successful Welcome) and
    /// rewrites the manifest. Returns the count of stale entries removed.
    ///
    /// Without this, the manifest accumulates dead hashes which are
    /// re-advertised to the server via `publishKeyPackages action=sync`,
    /// causing the server to keep handing them out to inviters whose
    /// Welcomes then fail `NoMatchingKeyPackage` because OpenMLS storage
    /// no longer has the underlying init key.
    pub fn reconcile_key_package_bundles(&mut self) -> Result<usize, MLSError> {
        let stale: Vec<Vec<u8>> = {
            let crypto = self.provider.crypto();
            let storage = self.provider.storage();
            let mut stale = Vec::new();
            for (hash_ref_bytes, bundle) in &self.key_package_bundles {
                let typed_ref = match bundle.key_package().hash_ref(crypto) {
                    Ok(r) => r,
                    Err(e) => {
                        crate::warn_log!(
                            "[KP-RECONCILE] hash_ref recompute failed for {}: {:?}",
                            hex::encode(hash_ref_bytes),
                            e
                        );
                        continue;
                    }
                };
                let lookup: Result<Option<openmls::prelude::KeyPackageBundle>, _> =
                    storage.key_package(&typed_ref);
                match lookup {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        crate::info_log!(
                            "[KP-RECONCILE] Stale manifest entry (not in OpenMLS storage): {}",
                            hex::encode(hash_ref_bytes)
                        );
                        stale.push(hash_ref_bytes.clone());
                    }
                    Err(e) => {
                        crate::warn_log!(
                            "[KP-RECONCILE] Storage lookup failed for {}: {:?}",
                            hex::encode(hash_ref_bytes),
                            e
                        );
                    }
                }
            }
            stale
        };

        // Age-based pruning runs regardless of staleness: expired bundles are
        // unusable by joiners (KeyPackage lifetime) and only bloat storage.
        let pruned = self
            .manifest_storage
            .prune_bundles_older_than(KEY_PACKAGE_BUNDLE_MAX_AGE_SECS)?;
        for hex_ref in &pruned {
            if let Ok(hash_ref) = hex::decode(hex_ref) {
                self.key_package_bundles.remove(&hash_ref);
            }
        }

        if stale.is_empty() && pruned.is_empty() {
            return Ok(0);
        }

        let removed_count = stale.len() + pruned.len();
        crate::info_log!(
            "[KP-RECONCILE] Removing {} stale + {} expired entries (cache before: {})",
            stale.len(),
            pruned.len(),
            self.key_package_bundles.len()
        );

        for hash_ref in &stale {
            self.key_package_bundles.remove(hash_ref);
        }
        let stale_hex: Vec<String> = stale.iter().map(hex::encode).collect();
        self.manifest_storage.delete_bundles(&stale_hex)?;

        crate::info_log!(
            "[KP-RECONCILE] Reconcile complete: cache={} rows={}",
            self.key_package_bundles.len(),
            self.manifest_storage.count_bundles()
        );

        Ok(removed_count)
    }

    /// Persist group ID to manifest for reload on restart
    fn persist_group_id(&self, group_id: &[u8]) -> Result<(), MLSError> {
        let storage = &self.manifest_storage;

        let hex_id = hex::encode(group_id);

        // Read existing list or create new one
        let mut group_ids: Vec<String> =
            storage.read_manifest("group_ids")?.unwrap_or_else(Vec::new);

        // Add this group ID if not already present
        if !group_ids.contains(&hex_id) {
            group_ids.push(hex_id);
            storage.write_manifest("group_ids", &group_ids)?;
            crate::debug_log!(
                "[MLS-CONTEXT] 📋 Updated group manifest, now tracking {} groups",
                group_ids.len()
            );
        }

        Ok(())
    }

    fn remove_group_id_from_manifest(&self, group_id: &[u8]) -> Result<(), MLSError> {
        let hex_id = hex::encode(group_id);
        if let Some(mut group_ids) = self
            .manifest_storage
            .read_manifest::<Vec<String>>("group_ids")?
        {
            group_ids.retain(|id| id != &hex_id);
            self.manifest_storage
                .write_manifest("group_ids", &group_ids)?;
        }
        Ok(())
    }

    fn persist_pending_external_join(
        &self,
        group_id: &[u8],
        pending_join: &PendingExternalJoin,
    ) -> Result<(), MLSError> {
        let mut pending: HashMap<String, PendingExternalJoin> = self
            .manifest_storage
            .read_manifest("pending_external_joins")?
            .unwrap_or_default();
        pending.insert(hex::encode(group_id), pending_join.clone());
        self.manifest_storage
            .write_manifest("pending_external_joins", &pending)
    }

    fn remove_pending_external_join(&self, group_id: &[u8]) -> Result<(), MLSError> {
        if let Some(mut pending) = self
            .manifest_storage
            .read_manifest::<HashMap<String, PendingExternalJoin>>("pending_external_joins")?
        {
            pending.remove(&hex::encode(group_id));
            self.manifest_storage
                .write_manifest("pending_external_joins", &pending)?;
        }
        Ok(())
    }

    /// Compensate a group that OpenMLS persisted before it was published in
    /// the live map. Every cleanup component is attempted and the rollback is
    /// durability-checked before success is reported.
    pub(crate) fn rollback_unpublished_group(
        &self,
        group: &mut MlsGroup,
        group_id: &[u8],
        context: &str,
    ) -> Result<(), MLSError> {
        let mut failures = Vec::new();
        if let Err(error) = group.delete(self.provider.storage()) {
            failures.push(format!("OpenMLS delete: {error:?}"));
        }
        if let Err(error) = self.remove_group_id_from_manifest(group_id) {
            failures.push(format!("manifest delete: {error:?}"));
        }
        if let Err(error) = self.remove_pending_external_join(group_id) {
            failures.push(format!("pending external-join delete: {error:?}"));
        }
        if let Err(error) = self.flush_database() {
            failures.push(format!("rollback durability barrier: {error:?}"));
        }

        if failures.is_empty() {
            Ok(())
        } else {
            crate::error_log!(
                "[MLS-CONTEXT] {} rollback incomplete for group {}: {}",
                context,
                hex::encode(group_id),
                failures.join("; ")
            );
            Err(MLSError::Internal(failures.join("; ")))
        }
    }

    /// Persist signer identity mapping for reload on restart
    fn persist_signer_mapping(&self, identity: &[u8], public_key: &[u8]) -> Result<(), MLSError> {
        let storage = &self.manifest_storage;

        // Read existing map or create new one
        let mut signers: HashMap<String, String> = storage
            .read_manifest("signers")?
            .unwrap_or_else(HashMap::new);

        // Add or update this identity mapping
        signers.insert(hex::encode(identity), hex::encode(public_key));

        storage.write_manifest("signers", &signers)?;
        crate::debug_log!(
            "[MLS-CONTEXT] 📋 Updated signer manifest, now tracking {} identities",
            signers.len()
        );

        Ok(())
    }

    fn remove_signer_mapping_from_manifest(
        &self,
        identity: &[u8],
        expected_public_key: &[u8],
    ) -> Result<(), MLSError> {
        if let Some(mut signers) = self
            .manifest_storage
            .read_manifest::<HashMap<String, String>>("signers")?
        {
            let identity_hex = hex::encode(identity);
            let expected_key_hex = hex::encode(expected_public_key);
            if signers.get(&identity_hex) == Some(&expected_key_hex) {
                signers.remove(&identity_hex);
                self.manifest_storage.write_manifest("signers", &signers)?;
            }
        }
        Ok(())
    }

    fn rollback_external_join_candidate(
        &self,
        group: &mut MlsGroup,
        group_id: &[u8],
        identity: &[u8],
        signer_public_key: &[u8],
        signer_was_persisted: bool,
    ) -> Result<(), MLSError> {
        let mut failures = Vec::new();
        if let Err(error) = group.delete(self.provider.storage()) {
            failures.push(format!("OpenMLS delete: {error:?}"));
        }
        if let Err(error) = self.remove_group_id_from_manifest(group_id) {
            failures.push(format!("group manifest delete: {error:?}"));
        }
        if let Err(error) = self.remove_pending_external_join(group_id) {
            failures.push(format!("pending external-join delete: {error:?}"));
        }
        if signer_was_persisted {
            if let Err(error) =
                self.remove_signer_mapping_from_manifest(identity, signer_public_key)
            {
                failures.push(format!("signer manifest delete: {error:?}"));
            }
        }
        if let Err(error) = self.flush_database() {
            failures.push(format!("rollback durability barrier: {error:?}"));
        }
        // Signature key deletion is last: after it succeeds there is no later
        // fallible cleanup step that could require the key for retry.
        if signer_was_persisted {
            if let Err(error) = SignatureKeyPair::delete(
                self.provider.storage(),
                signer_public_key,
                SignatureScheme::ED25519,
            ) {
                failures.push(format!("signing key delete: {error:?}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            crate::error_log!(
                "[MLS-CONTEXT] External-join rollback incomplete for group {}: {}",
                hex::encode(group_id),
                failures.join("; ")
            );
            Err(MLSError::Internal(failures.join("; ")))
        }
    }

    pub fn export_group_info(
        &mut self,
        group_id: &[u8],
        signer_identity: &str,
    ) -> Result<Vec<u8>, MLSError> {
        let gid = GroupId::from_slice(group_id);

        // We need the signer to sign the GroupInfo
        let signer = self
            .get_signer_for_identity(signer_identity)
            .ok_or_else(|| MLSError::invalid_input("Signer not found for identity"))?;

        self.with_group(&gid, |group, provider, _group_signer| {
            // Use the provided signer (which should match the group member)
            let group_info = group
                .export_group_info(
                    provider.crypto(),
                    &signer,
                    true, // with_ratchet_tree
                )
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] ERROR: export_group_info failed: {:?}", e);
                    MLSError::OpenMLS(format!("export_group_info failed: {:?}", e))
                })?;

            let group_info_bytes = TlsSerialize::tls_serialize_detached(&group_info)
                .map_err(|_| MLSError::SerializationError)?;

            Ok(group_info_bytes)
        })
    }

    pub fn create_external_commit(
        &mut self,
        group_info_bytes: &[u8],
        identity: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>), MLSError> {
        validate_inbound_mls_message_len(group_info_bytes.len(), "group_info")?;
        if group_info_bytes.is_empty() {
            return Err(MLSError::invalid_input("GroupInfo is empty"));
        }
        if identity.is_empty() {
            return Err(MLSError::invalid_input("External-join identity is empty"));
        }

        let (mls_message, remaining) = MlsMessageIn::tls_deserialize_bytes(group_info_bytes)
            .map_err(|error| {
                crate::error_log!(
                    "[MLS-CONTEXT] Invalid GroupInfo envelope ({} bytes): {:?}",
                    group_info_bytes.len(),
                    error
                );
                MLSError::invalid_input("Invalid GroupInfo")
            })?;
        if !remaining.is_empty() {
            return Err(MLSError::invalid_input(
                "GroupInfo contains trailing unparsed bytes",
            ));
        }
        let verifiable_group_info = match mls_message.extract() {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            _ => {
                return Err(MLSError::invalid_input(
                    "Expected MlsMessage containing GroupInfo",
                ));
            }
        };

        let advertised_group_id = verifiable_group_info.group_id().as_slice().to_vec();
        if self.groups.contains_key(&advertised_group_id) {
            return Err(MLSError::InvalidState(format!(
                "Cannot stage an external join over live group {}",
                hex::encode(&advertised_group_id)
            )));
        }

        let credential = Credential::new(CredentialType::Basic, identity.as_bytes().to_vec());
        let (signature_keys, is_new_key) = match self.get_signer_for_identity(identity) {
            Some(existing_signer) => (existing_signer, false),
            None => {
                let new_keys =
                    SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|error| {
                        MLSError::OpenMLS(format!(
                            "create_external_commit: failed to create signing key: {error:?}"
                        ))
                    })?;
                (new_keys, true)
            }
        };

        let join_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();

        let build_result = (|| {
            let builder = MlsGroup::external_commit_builder()
                .with_config(join_config)
                .build_group(
                    &self.provider,
                    verifiable_group_info,
                    CredentialWithKey {
                        credential,
                        signature_key: signature_keys.public().into(),
                    },
                )
                .map_err(|error| {
                    MLSError::OpenMLS(format!(
                        "external_commit_builder build_group failed: {error:?}"
                    ))
                })?;
            let builder = builder
                .leaf_node_parameters(
                    LeafNodeParameters::builder()
                        .with_capabilities(metadata_leaf_capabilities())
                        .build(),
                )
                .load_psks(self.provider.storage())
                .map_err(|error| {
                    MLSError::OpenMLS(format!(
                        "external_commit_builder load_psks failed: {error:?}"
                    ))
                })?;
            let builder = builder
                .build(
                    self.provider.rand(),
                    self.provider.crypto(),
                    &signature_keys,
                    |_| true,
                )
                .map_err(|error| {
                    MLSError::OpenMLS(format!("external_commit_builder build failed: {error:?}"))
                })?;
            builder.finalize(&self.provider).map_err(|error| {
                MLSError::OpenMLS(format!(
                    "external_commit_builder finalize failed: {error:?}"
                ))
            })
        })();

        let (mut group, commit_message_bundle) = build_result?;

        let group_id = group.group_id().as_slice().to_vec();
        if group_id != advertised_group_id {
            let primary_error =
                MLSError::InvalidState("External-commit group ID changed during validation".into());
            let rollback_error = self
                .rollback_external_join_candidate(
                    &mut group,
                    &group_id,
                    identity.as_bytes(),
                    signature_keys.public(),
                    false,
                )
                .err();
            return match rollback_error {
                Some(error) => Err(MLSError::Internal(format!(
                    "{primary_error}; rollback failed ({error})"
                ))),
                None => Err(primary_error),
            };
        }

        // Produce every caller-visible artifact before publishing the group.
        let commit_bytes = match commit_message_bundle.commit().tls_serialize_detached() {
            Ok(bytes) => bytes,
            Err(_) => {
                let primary_error = MLSError::SerializationError;
                let rollback_error = self
                    .rollback_external_join_candidate(
                        &mut group,
                        &group_id,
                        identity.as_bytes(),
                        signature_keys.public(),
                        false,
                    )
                    .err();
                return match rollback_error {
                    Some(error) => Err(MLSError::Internal(format!(
                        "{primary_error}; rollback failed ({error})"
                    ))),
                    None => Err(primary_error),
                };
            }
        };
        let exported_group_info = group
            .export_group_info(self.provider.crypto(), &signature_keys, true)
            .ok()
            .and_then(|group_info| group_info.tls_serialize_detached().ok());

        let pending_external_join = PendingExternalJoin {
            signer_public_key: signature_keys.public().to_vec(),
            minted_signer_identity: is_new_key.then(|| identity.as_bytes().to_vec()),
        };
        let durable_preparation = (|| -> Result<(), MLSError> {
            if is_new_key {
                signature_keys
                    .store(self.provider.storage())
                    .map_err(|error| {
                        MLSError::OpenMLS(format!(
                            "create_external_commit: failed to store signing key: {error:?}"
                        ))
                    })?;
                self.persist_signer_mapping(identity.as_bytes(), signature_keys.public())?;
            }
            self.persist_group_id(&group_id)?;
            self.persist_pending_external_join(&group_id, &pending_external_join)?;
            self.flush_database()
        })();
        if let Err(primary_error) = durable_preparation {
            let rollback_error = self
                .rollback_external_join_candidate(
                    &mut group,
                    &group_id,
                    identity.as_bytes(),
                    signature_keys.public(),
                    is_new_key,
                )
                .err();
            return match rollback_error {
                Some(error) => Err(MLSError::Internal(format!(
                    "external-commit preparation failed ({primary_error}); rollback failed ({error})"
                ))),
                None => Err(primary_error),
            };
        }

        // Publication is the final, infallible step after serialization,
        // manifest persistence, and the checked durability barrier.
        if is_new_key {
            self.signers_by_identity.insert(
                identity.as_bytes().to_vec(),
                signature_keys.public().to_vec(),
            );
        }
        self.groups.insert(
            group_id.clone(),
            GroupState {
                group,
                signer_public_key: signature_keys.public().to_vec(),
                pending_external_join: Some(pending_external_join),
            },
        );

        Ok((commit_bytes, group_id, exported_group_info))
    }
    pub fn create_external_commit_with_psk(
        &mut self,
        group_info_bytes: &[u8],
        _identity: &str,
        _psk_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
        validate_inbound_mls_message_len(group_info_bytes.len(), "group_info")?;
        Err(MLSError::OperationNotSupported {
            reason: "PSK external commits are disabled: this implementation does not yet cryptographically bind the supplied PSK into the MLS commit".to_string(),
        })
    }
    /// Discard a locally staged external join after server rejection.
    ///
    /// Persistent group state and any signer minted solely for this candidate
    /// are durably removed before the live maps publish absence. Failures keep
    /// the maps and ownership marker so the caller can retry cleanup.
    pub fn discard_pending_external_join(&mut self, group_id: &[u8]) -> Result<(), MLSError> {
        let state = self
            .groups
            .get(group_id)
            .ok_or_else(|| MLSError::group_not_found(hex::encode(group_id)))?;
        let signer_public_key = state.signer_public_key.clone();
        let pending_join = state.pending_external_join.as_ref().ok_or_else(|| {
            MLSError::InvalidState("Group is not a pending external-join candidate".to_string())
        })?;
        if pending_join.signer_public_key != signer_public_key {
            return Err(MLSError::StorageFailed);
        }
        let pending_identity = pending_join.minted_signer_identity.clone();

        let signer_is_used_by_other_group = self.groups.iter().any(|(other_id, state)| {
            other_id.as_slice() != group_id && state.signer_public_key == signer_public_key
        });
        let signer_is_used_by_key_package = self.key_package_bundles.values().any(|bundle| {
            bundle.key_package().leaf_node().signature_key().as_slice()
                == signer_public_key.as_slice()
        });
        let delete_candidate_signer = pending_identity.is_some()
            && !signer_is_used_by_other_group
            && !signer_is_used_by_key_package;

        // OpenMLS's complete deletion routine includes proposal queues,
        // application export trees, and encryption epoch keypairs.
        {
            let (groups, provider) = (&mut self.groups, &self.provider);
            let state = groups
                .get_mut(group_id)
                .ok_or_else(|| MLSError::group_not_found(hex::encode(group_id)))?;
            state.group.delete(provider.storage())?;
        }

        if delete_candidate_signer {
            let identity = pending_identity
                .as_deref()
                .expect("delete_candidate_signer requires an identity");
            self.remove_signer_mapping_from_manifest(identity, &signer_public_key)?;
        }
        self.remove_group_id_from_manifest(group_id)?;
        self.remove_pending_external_join(group_id)?;

        self.flush_database()?;
        if delete_candidate_signer {
            // Last fallible step. With synchronous=FULL the SQLite deletion
            // commit is itself durable; no later checkpoint can strand a
            // consumed retry token after key deletion succeeds.
            SignatureKeyPair::delete(
                self.provider.storage(),
                &signer_public_key,
                SignatureScheme::ED25519,
            )?;
        }

        self.groups.remove(group_id);
        if delete_candidate_signer {
            let identity = pending_identity.expect("candidate identity checked above");
            if self.signers_by_identity.get(&identity) == Some(&signer_public_key) {
                self.signers_by_identity.remove(&identity);
            }
        }

        crate::info_log!(
            "[MLS-CONTEXT] Rejected external join durably removed for group {}",
            hex::encode(group_id)
        );
        Ok(())
    }

    pub fn create_group(
        &mut self,
        identity: &str,
        config: crate::types::GroupConfig,
    ) -> Result<CreateGroupInternalResult, MLSError> {
        self.create_group_internal(identity, None, config)
    }

    /// Create a group at a predetermined `group_id` (spec §8.5 first-responder
    /// bootstrap). All bootstrap candidates targeting the same `groupResetEvent.newGroupId`
    /// land on the same MLS GroupId — so Welcome recipients of the race winner
    /// can deserialize against the expected group identifier.
    ///
    /// `group_id` is the raw bytes (NOT hex-encoded).
    pub fn create_group_with_id(
        &mut self,
        identity: &str,
        group_id: Vec<u8>,
        config: crate::types::GroupConfig,
    ) -> Result<CreateGroupInternalResult, MLSError> {
        self.create_group_internal(identity, Some(group_id), config)
    }

    fn create_group_internal(
        &mut self,
        identity: &str,
        predetermined_group_id: Option<Vec<u8>>,
        config: crate::types::GroupConfig,
    ) -> Result<CreateGroupInternalResult, MLSError> {
        crate::debug_log!(
            "[MLS-CONTEXT] create_group: Starting for identity '{}'{}",
            identity,
            if predetermined_group_id.is_some() {
                " with predetermined group_id"
            } else {
                ""
            }
        );

        let credential = Credential::new(CredentialType::Basic, identity.as_bytes().to_vec());
        crate::debug_log!("[MLS-CONTEXT] Credential created");

        // Try to reuse existing signature keys for this identity (same pattern as create_key_package)
        crate::debug_log!("[MLS-CONTEXT] Getting or creating signature keys for identity...");
        let (signature_keys, is_new_key) = match self.get_signer_for_identity(identity) {
            Some(existing_signer) => {
                crate::info_log!(
                    "[MLS-CONTEXT] ✅ Reusing existing signature keypair for identity: {}",
                    identity
                );
                (existing_signer, false)
            }
            None => {
                crate::debug_log!(
                    "[MLS-CONTEXT] No existing signer found, generating new signature keys..."
                );
                let new_keys = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|e| {
                    crate::debug_log!(
                        "[MLS-CONTEXT] ERROR: Failed to create signature keys: {:?}",
                        e
                    );
                    MLSError::OpenMLSError
                })?;
                crate::debug_log!("[MLS-CONTEXT] Signature keys generated");

                crate::debug_log!("[MLS-CONTEXT] Storing new signature keys...");
                new_keys.store(self.provider.storage()).map_err(|e| {
                    crate::debug_log!(
                        "[MLS-CONTEXT] ERROR: Failed to store signature keys: {:?}",
                        e
                    );
                    MLSError::OpenMLSError
                })?;
                crate::debug_log!("[MLS-CONTEXT] Signature keys stored");

                (new_keys, true)
            }
        };

        // Build group config with forward secrecy settings
        crate::debug_log!("[MLS-CONTEXT] Building group config...");

        // Configure required capabilities to include ratchet tree and metadata extensions
        // This ensures Welcome messages include the ratchet tree for new members
        let capabilities = metadata_leaf_capabilities();

        // The creator's leaf lifetime must satisfy the delivery service's
        // MAX_KEY_PACKAGE_LIFETIME_SECONDS (30 days + 1 hour); OpenMLS would
        // otherwise default to 3 months and the genesis GroupInfo is rejected
        // with LifetimeTooLong. Keep this in lockstep with the KeyPackage
        // lifetime used when building key packages.
        let leaf_lifetime = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            openmls::prelude::Lifetime::init(now.saturating_sub(60), now + 29 * 24 * 60 * 60)
        };
        let group_config_builder = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .capabilities(capabilities) // Set required capabilities
            .lifetime(leaf_lifetime)
            .use_ratchet_tree_extension(true); // CRITICAL: Include ratchet tree in Welcome messages
        let _ = (&config.group_name, &config.group_description);

        let group_config = group_config_builder.build();
        crate::debug_log!(
            "[MLS-CONTEXT] Group config built with ratchet tree extension capability"
        );

        crate::debug_log!("[MLS-CONTEXT] Creating MLS group...");
        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        };
        let effective_id_bytes = match predetermined_group_id {
            Some(ref id_bytes) => id_bytes.clone(),
            None => {
                use openmls_traits::random::OpenMlsRand;
                self.provider.rand().random_vec(32).unwrap_or_else(|_| {
                    use rand::RngCore;
                    let mut b = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut b);
                    b.to_vec()
                })
            }
        };
        let openmls_group_id = openmls::prelude::GroupId::from_slice(&effective_id_bytes);
        let mut group = MlsGroup::new_with_group_id(
            &self.provider,
            &signature_keys,
            &group_config,
            openmls_group_id,
            credential_with_key,
        )
        .map_err(|e| {
            crate::debug_log!("[MLS-CONTEXT] ERROR: Failed to create MLS group: {:?}", e);
            MLSError::OpenMLSError
        })?;
        crate::debug_log!("[MLS-CONTEXT] MLS group created successfully");

        // 🔍 DEBUG: Check initial member count (should be 1 - just the creator)
        let initial_member_count = group.members().count();
        crate::debug_log!(
            "[MLS-CONTEXT] 🔍 Initial member count: {} (expected: 1)",
            initial_member_count
        );
        if initial_member_count != 1 {
            crate::debug_log!(
                "[MLS-CONTEXT] ⚠️ WARNING: Unexpected initial member count! Expected 1, got {}",
                initial_member_count
            );
        }

        let group_id = group.group_id().as_slice().to_vec();
        crate::debug_log!("[MLS-CONTEXT] Group ID: {}", hex::encode(&group_id));

        // CRITICAL: Export epoch 0 secret immediately after group creation
        // This ensures we can decrypt messages sent at epoch 0 even if the group advances
        let current_epoch = group.epoch().as_u64();
        crate::debug_log!(
            "[MLS-CONTEXT] Exporting epoch {} secret after group creation",
            current_epoch
        );

        // Fail-closed: if we can't export the epoch secret, we shouldn't create the group
        // because we won't be able to decrypt our own messages if the epoch advances.
        if let Err(export_error) = crate::async_runtime::block_on(
            self.epoch_secret_manager
                .export_current_epoch_secret(&mut group, &self.provider),
        ) {
            crate::error_log!(
                "[MLS-CONTEXT] Failed to durably export the initial epoch secret; rolling back group creation: {:?}",
                export_error
            );

            // OpenMLS persists a newly-created group before returning it from
            // `MlsGroup::new[_with_group_id]`. If the epoch-secret durability
            // boundary fails, remove that state before returning; otherwise a
            // deterministic-ID retry collides with an invisible, half-created
            // group that was never published in `self.groups`.
            let delete_result = group.delete(self.provider.storage());
            let flush_result = self.flush_database();

            match (delete_result, flush_result) {
                (Err(delete_error), Err(flush_error)) => {
                    crate::error_log!(
                        "[MLS-CONTEXT] Group-creation rollback failed to delete OpenMLS state ({:?}) and flush the database ({:?})",
                        delete_error,
                        flush_error
                    );
                    return Err(MLSError::Internal(format!(
                        "Failed to roll back group creation after epoch-secret persistence failure: OpenMLS delete failed: {:?}; database flush failed: {:?}",
                        delete_error, flush_error
                    )));
                }
                (Err(delete_error), Ok(())) => {
                    crate::error_log!(
                        "[MLS-CONTEXT] Failed to delete OpenMLS state while rolling back group creation: {:?}",
                        delete_error
                    );
                    return Err(MLSError::Internal(format!(
                        "Failed to roll back group creation after epoch-secret persistence failure: OpenMLS delete failed: {:?}",
                        delete_error
                    )));
                }
                (Ok(()), Err(flush_error)) => {
                    crate::error_log!(
                        "[MLS-CONTEXT] Failed to flush group-creation rollback: {:?}",
                        flush_error
                    );
                    return Err(MLSError::Internal(format!(
                        "Failed to roll back group creation after epoch-secret persistence failure: database flush failed: {:?}",
                        flush_error
                    )));
                }
                (Ok(()), Ok(())) => {}
            }

            return Err(export_error);
        }

        crate::debug_log!(
            "[MLS-CONTEXT] ✅ Exported epoch {} secret successfully",
            current_epoch
        );

        self.groups.insert(
            group_id.clone(),
            GroupState {
                group,
                signer_public_key: signature_keys.public().to_vec(),
                pending_external_join: None,
            },
        );
        crate::debug_log!("[MLS-CONTEXT] Group state stored");

        // Persist group ID to manifest
        self.persist_group_id(&group_id).map_err(|e| {
            crate::error_log!("[MLS-CONTEXT] ⚠️ Failed to persist group ID: {:?}", e);
            MLSError::Internal(format!("Failed to persist group ID: {:?}", e))
        })?;

        // MEK is NOT generated at group creation. Initial metadata is plaintext in the
        // extension (only the creator is in the group at this point). The first call to
        // update_group_metadata will derive the MEK from export_secret and encrypt.
        // All members who process that commit will derive and cache the same MEK.

        // ── Metadata: encrypt metadata using epoch-derived key ──────────
        // For initial group creation we derive the key from the group's current
        // epoch exporter (no StagedCommit involved — the group already exists).
        let metadata_result = if config.group_name.is_some() || config.group_description.is_some() {
            let group_state = self.groups.get_mut(&group_id).ok_or_else(|| {
                MLSError::Internal("Group just created but not found in groups map".to_string())
            })?;
            let epoch = group_state.group.epoch().as_u64();

            match metadata::derive_metadata_key_from_group(
                &mut group_state.group,
                self.provider.crypto(),
                self.provider.storage(),
                &group_id,
                epoch,
            ) {
                Ok(metadata_key) => {
                    let metadata_payload = metadata::GroupMetadataV1 {
                        version: 1,
                        title: config.group_name.clone().unwrap_or_default(),
                        description: config.group_description.clone().unwrap_or_default(),
                        avatar_blob_locator: None,
                        avatar_content_type: None,
                    };
                    let metadata_version: u64 = 1;

                    match metadata::encrypt_metadata_blob(
                        &metadata_key,
                        &group_id,
                        epoch,
                        metadata_version,
                        &metadata_payload,
                    ) {
                        Ok(encrypted_blob) => {
                            let blob_locator = Uuid::new_v4().to_string();
                            let ciphertext_hash = metadata::hash_ciphertext(&encrypted_blob);
                            let reference = metadata::build_metadata_reference(
                                metadata_version,
                                &blob_locator,
                                &ciphertext_hash,
                            );
                            let reference_json = serde_json::to_vec(&reference).map_err(|e| {
                                MLSError::Internal(format!(
                                    "Failed to serialize MetadataReference: {:?}",
                                    e
                                ))
                            })?;

                            crate::info_log!(
                                "[MLS-CONTEXT] ✅ Metadata encrypted for epoch {} (blob_locator={})",
                                epoch,
                                blob_locator,
                            );

                            Some((encrypted_blob, reference_json, blob_locator))
                        }
                        Err(e) => {
                            crate::error_log!(
                                "[MLS-CONTEXT] ⚠️ Failed to encrypt metadata: {:?} — group created without metadata blob",
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    crate::error_log!(
                        "[MLS-CONTEXT] ⚠️ Failed to derive metadata key: {:?} — group created without metadata blob",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Only register the signer if we created a new key (don't overwrite existing mappings)
        if is_new_key {
            self.signers_by_identity.insert(
                identity.as_bytes().to_vec(),
                signature_keys.public().to_vec(),
            );
            crate::debug_log!("[MLS-CONTEXT] Registered new signer for identity");

            // Persist signer mapping to manifest
            self.persist_signer_mapping(identity.as_bytes(), signature_keys.public())
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] ⚠️ Failed to persist signer mapping: {:?}", e);
                    MLSError::Internal(format!("Failed to persist signer mapping: {:?}", e))
                })?;
        } else {
            crate::debug_log!(
                "[MLS-CONTEXT] Signer already registered for identity, not overwriting"
            );
        }

        crate::debug_log!("[MLS-CONTEXT] create_group: Completed successfully");
        Ok(CreateGroupInternalResult {
            group_id,
            encrypted_metadata_blob: metadata_result.as_ref().map(|(blob, _, _)| blob.clone()),
            metadata_reference_json: metadata_result.as_ref().map(|(_, json, _)| json.clone()),
            metadata_blob_locator: metadata_result.map(|(_, _, loc)| loc),
        })
    }

    pub fn add_group(&mut self, mut group: MlsGroup, identity: &str) -> Result<(), MLSError> {
        crate::debug_log!("[ADD-GROUP] Adding group for identity: {}", identity);
        crate::debug_log!(
            "[ADD-GROUP]   Available signers: {} entries",
            self.signers_by_identity.len()
        );
        for (id_bytes, pk_bytes) in &self.signers_by_identity {
            if let Ok(id_str) = String::from_utf8(id_bytes.clone()) {
                crate::debug_log!(
                    "[ADD-GROUP]     - Identity: {} -> PK: {}",
                    id_str,
                    hex::encode(pk_bytes)
                );
            } else {
                crate::debug_log!(
                    "[ADD-GROUP]     - Identity (hex): {} -> PK: {}",
                    hex::encode(id_bytes),
                    hex::encode(pk_bytes)
                );
            }
        }

        let group_id = group.group_id().as_slice().to_vec();
        let preparation = (|| -> Result<Vec<u8>, MLSError> {
            let signer_pk = self
                .signers_by_identity
                .get(identity.as_bytes())
                .ok_or_else(|| {
                    crate::error_log!("[ADD-GROUP] No signer found for identity: {}", identity);
                    MLSError::group_not_found(format!("No signer for identity: {}", identity))
                })?
                .clone();

            if SignatureKeyPair::read(
                self.provider.storage(),
                &signer_pk,
                SignatureScheme::ED25519,
            )
            .is_none()
            {
                crate::error_log!(
                    "[ADD-GROUP] Signer keypair missing from storage for public key {}",
                    hex::encode(&signer_pk)
                );
                return Err(MLSError::StorageFailed);
            }

            self.persist_group_id(&group_id)?;
            self.flush_database()?;
            Ok(signer_pk)
        })();

        match preparation {
            Ok(signer_pk) => {
                crate::debug_log!(
                    "[ADD-GROUP] Publishing durable group {} with signer PK: {}",
                    hex::encode(&group_id),
                    hex::encode(&signer_pk)
                );
                self.groups.insert(
                    group_id,
                    GroupState {
                        group,
                        signer_public_key: signer_pk,
                        pending_external_join: None,
                    },
                );
                Ok(())
            }
            Err(primary_error) => {
                let rollback = self.rollback_unpublished_group(&mut group, &group_id, "add_group");
                if let Err(rollback_error) = rollback {
                    return Err(MLSError::Internal(format!(
                        "add_group failed ({primary_error}); rollback also failed ({rollback_error})"
                    )));
                }
                Err(primary_error)
            }
        }
    }

    /// Register a signer public key for an identity
    /// This must be called when creating key packages so the signer can be found when processing Welcome messages
    pub fn register_signer(
        &mut self,
        identity: &str,
        signer_public_key: Vec<u8>,
    ) -> Result<(), MLSError> {
        // Safeguard: Check if a signer already exists for this identity
        if let Some(existing_key) = self.signers_by_identity.get(identity.as_bytes()) {
            if existing_key == &signer_public_key {
                crate::debug_log!(
                    "[MLS-CONTEXT] Signer already registered for identity with same key: {}",
                    identity
                );
            } else {
                crate::error_log!(
                    "[MLS-CONTEXT] ⚠️ WARNING: Attempting to overwrite existing signer for identity '{}'. Existing: {}, New: {}",
                    identity,
                    hex::encode(existing_key),
                    hex::encode(&signer_public_key)
                );
                // Continue with registration but log the warning
            }
        }

        // Persist and pass the durability barrier before publishing the mapping
        // in memory. Re-registering the same key also repairs manifest drift.
        self.persist_signer_mapping(identity.as_bytes(), &signer_public_key)
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ⚠️ Failed to persist signer mapping in register_signer: {:?}",
                    e
                );
                MLSError::Internal(format!(
                    "Failed to persist signer mapping in register_signer: {:?}",
                    e
                ))
            })?;
        self.flush_database()?;

        self.signers_by_identity
            .insert(identity.as_bytes().to_vec(), signer_public_key);
        crate::debug_log!("[MLS-CONTEXT] Registered durable signer mapping");
        Ok(())
    }

    /// Get persistent signature keypair for an identity if it exists
    /// Returns None if no signer has been registered for this identity yet
    pub fn get_signer_for_identity(&self, identity: &str) -> Option<SignatureKeyPair> {
        tracing::info!(
            lookup_identity = %identity,
            available_signers = ?self.signers_by_identity.iter().map(|(k, v)| (String::from_utf8_lossy(k).to_string(), hex::encode(v))).collect::<Vec<_>>(),
            "get_signer_for_identity lookup"
        );
        // Look up public key bytes for this identity (exact match)
        if let Some(public_key_bytes) = self.signers_by_identity.get(identity.as_bytes()) {
            if let Some(keypair) = SignatureKeyPair::read(
                self.provider.storage(),
                public_key_bytes,
                SignatureScheme::ED25519,
            ) {
                return Some(keypair);
            }
        }

        // If identity is device-qualified (e.g. did:plc:...#uuid), try root DID
        if let Some((root, _)) = identity.split_once('#') {
            if let Some(public_key_bytes) = self.signers_by_identity.get(root.as_bytes()) {
                if let Some(keypair) = SignatureKeyPair::read(
                    self.provider.storage(),
                    public_key_bytes,
                    SignatureScheme::ED25519,
                ) {
                    return Some(keypair);
                }
            }
        }

        // Also check if any registered identity starts with identity#
        for (reg_id, pk_bytes) in &self.signers_by_identity {
            if let Ok(reg_str) = std::str::from_utf8(reg_id) {
                if reg_str.starts_with(identity)
                    && (reg_str.len() == identity.len()
                        || reg_str.as_bytes()[identity.len()] == b'#')
                {
                    if let Some(keypair) = SignatureKeyPair::read(
                        self.provider.storage(),
                        pk_bytes,
                        SignatureScheme::ED25519,
                    ) {
                        return Some(keypair);
                    }
                }
            }
        }

        None
    }

    pub fn with_group<T, F>(&mut self, group_id: &GroupId, f: F) -> Result<T, MLSError>
    where
        F: FnOnce(&mut MlsGroup, &SqliteLibcruxProvider, &SignatureKeyPair) -> Result<T, MLSError>,
    {
        // 🔍 DIAGNOSTIC: Thread and timing tracking
        let thread_id = std::thread::current().id();
        let entry_time = std::time::SystemTime::now();

        crate::debug_log!(
            "[WITH-GROUP] 🧵 Thread {:?} entering with_group for {}",
            thread_id,
            hex::encode(group_id.as_slice())
        );

        // Check if group exists first (before mutable borrow)
        if !self.groups.contains_key(group_id.as_slice()) {
            crate::error_log!(
                "[WITH-GROUP] ❌ Group not found: {}",
                hex::encode(group_id.as_slice())
            );
            let available: Vec<String> = self.groups.keys().map(hex::encode).collect();
            crate::debug_log!("[WITH-GROUP] Available groups: {:?}", available);
            return Err(MLSError::group_not_found(hex::encode(group_id.as_slice())));
        }

        // Now safe to get mutable reference
        let state = match self.groups.get_mut(group_id.as_slice()) {
            Some(s) => s,
            None => return Err(MLSError::group_not_found(hex::encode(group_id.as_slice()))),
        };

        // 🔍 DIAGNOSTIC: Log secret tree state at entry
        let epoch_at_entry = state.group.epoch().as_u64();
        let members_at_entry = state.group.members().count();

        crate::info_log!("[WITH-GROUP] 📊 ENTRY STATE:");
        crate::info_log!("[WITH-GROUP]   Group: {}", hex::encode(group_id.as_slice()));
        crate::info_log!("[WITH-GROUP]   Epoch: {}", epoch_at_entry);
        crate::info_log!("[WITH-GROUP]   Members: {}", members_at_entry);
        crate::info_log!("[WITH-GROUP]   Thread: {:?}", thread_id);
        crate::info_log!("[WITH-GROUP]   Timestamp: {:?}", entry_time);

        // Load signer from storage
        crate::debug_log!("[WITH-GROUP] Loading signer from storage...");
        crate::debug_log!(
            "[WITH-GROUP]   Signer public key (hex): {}",
            hex::encode(&state.signer_public_key)
        );
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            &state.signer_public_key,
            SignatureScheme::ED25519,
        )
        .ok_or_else(|| {
            crate::error_log!("[WITH-GROUP] Failed to load signer from storage!");
            crate::error_log!(
                "[WITH-GROUP]   Public key (hex): {}",
                hex::encode(&state.signer_public_key)
            );
            crate::error_log!(
                "[WITH-GROUP]   Group ID: {}",
                hex::encode(group_id.as_slice())
            );
            crate::error_log!("[WITH-GROUP]   Epoch: {}", epoch_at_entry);
            MLSError::OpenMLS(format!(
                "with_group: Failed to load signer (public_key={}, group={}, epoch={})",
                hex::encode(&state.signer_public_key),
                hex::encode(group_id.as_slice()),
                epoch_at_entry
            ))
        })?;
        crate::debug_log!("[WITH-GROUP] Signer loaded successfully");

        // Execute the closure
        let closure_start = std::time::SystemTime::now();
        let result = f(&mut state.group, &self.provider, &signer);
        let closure_duration = closure_start.elapsed().unwrap_or_default();

        // 🔍 DIAGNOSTIC: Log secret tree state at exit
        let epoch_at_exit = state.group.epoch().as_u64();
        let members_at_exit = state.group.members().count();
        let total_duration = entry_time.elapsed().unwrap_or_default();

        crate::info_log!("[WITH-GROUP] 📊 EXIT STATE:");
        crate::info_log!("[WITH-GROUP]   Epoch: {}", epoch_at_exit);
        crate::info_log!("[WITH-GROUP]   Members: {}", members_at_exit);
        crate::info_log!("[WITH-GROUP]   Closure duration: {:?}", closure_duration);
        crate::info_log!("[WITH-GROUP]   Total duration: {:?}", total_duration);

        if epoch_at_exit != epoch_at_entry {
            crate::warn_log!(
                "[WITH-GROUP] ⚠️ EPOCH CHANGED: {} -> {}",
                epoch_at_entry,
                epoch_at_exit
            );
        }

        if members_at_exit != members_at_entry {
            crate::warn_log!(
                "[WITH-GROUP] ⚠️ MEMBERS CHANGED: {} -> {}",
                members_at_entry,
                members_at_exit
            );
        }

        // 🔍 DIAGNOSTIC: Check for suspiciously fast concurrent operations
        if total_duration.as_millis() < 5 {
            crate::warn_log!(
                "[WITH-GROUP] ⚠️ SUSPICIOUSLY FAST: Operation completed in {:?}",
                total_duration
            );
            crate::warn_log!("[WITH-GROUP]   This might indicate concurrent access if multiple operations complete simultaneously");
        }

        result
    }

    pub fn with_group_ref<T, F>(&self, group_id: &GroupId, f: F) -> Result<T, MLSError>
    where
        F: FnOnce(&MlsGroup, &SqliteLibcruxProvider) -> Result<T, MLSError>,
    {
        let state = self
            .groups
            .get(group_id.as_slice())
            .ok_or_else(|| MLSError::group_not_found(hex::encode(group_id.as_slice())))?;
        f(&state.group, &self.provider)
    }

    /// Check if a group exists in the context
    pub fn has_group(&self, group_id: &[u8]) -> bool {
        self.groups.contains_key(group_id)
    }

    /// Clear rejection-cleanup ownership after the server-accepted external
    /// transition has passed the crypto durability barrier.
    pub(crate) fn mark_external_join_accepted(&mut self, group_id: &[u8]) -> Result<(), MLSError> {
        let is_pending = self
            .groups
            .get(group_id)
            .is_some_and(|state| state.pending_external_join.is_some());
        if !is_pending {
            return Ok(());
        }

        self.remove_pending_external_join(group_id)?;
        self.flush_database()?;
        if let Some(state) = self.groups.get_mut(group_id) {
            state.pending_external_join = None;
        }
        crate::debug_log!(
            "[MLS-CONTEXT] External join acceptance durably finalized for group {}",
            hex::encode(group_id)
        );
        Ok(())
    }

    pub(crate) fn local_group_ids(&self) -> Vec<Vec<u8>> {
        self.groups.keys().cloned().collect()
    }

    /// Delete a group from the context, cleaning up all persistent storage.
    /// Returns true if the group was found and durably removed, false when it
    /// was already absent. Persistence and flush failures are returned before
    /// the live in-memory group is removed so callers can retain a retryable
    /// pending-delete intent.
    pub fn delete_group(&mut self, group_id: &[u8]) -> Result<bool, MLSError> {
        if !self.groups.contains_key(group_id) {
            return Ok(false);
        }

        // Use OpenMLS's complete deletion routine (including proposal queues,
        // application export trees, and encryption epoch keypairs). Keep the
        // map entry until every persistent component and the barrier succeed.
        {
            let (groups, provider) = (&mut self.groups, &self.provider);
            let state = groups
                .get_mut(group_id)
                .ok_or_else(|| MLSError::group_not_found(hex::encode(group_id)))?;
            state.group.delete(provider.storage())?;
        }

        self.remove_group_id_from_manifest(group_id)?;
        self.remove_pending_external_join(group_id)?;

        // Flush to ensure cleanup is persisted
        self.flush_database()?;

        self.groups.remove(group_id);
        Ok(true)
    }

    /// Stage a metadata-update commit using the legacy `metadata_json` shape
    /// expected by `CommitKind::UpdateMetadata` (orchestrator stage_commit
    /// dispatch). The JSON is decoded for legacy compat but its contents are
    /// NOT written into the MLS group context — Phase A retired the 0xff00
    /// plaintext extension. This commit:
    ///
    ///   * advances the `MetadataReference` in AppDataDictionary 0x8001 with
    ///     a fresh placeholder (the platform layer re-encrypts the blob
    ///     post-merge using the new epoch's exporter — see iOS
    ///     `reWrapMetadataAfterMerge`),
    ///   * (defensively) filters any stale 0xff00 entry out of
    ///     `RequiredCapabilities` and replaces a leftover 0xff00 extension
    ///     payload with empty bytes for groups created by older builds.
    ///
    /// Returns the commit message bytes that must be sent to the server.
    /// Direct callers wanting the encrypted blob + locator + version + final
    /// MetadataReference in one shot should use
    /// [`Self::update_group_metadata_encrypted`] (Phase A.2 atomic FFI).
    pub fn update_group_metadata(
        &mut self,
        group_id: &[u8],
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        let gid = GroupId::from_slice(group_id);
        // The legacy `GroupMetadataPayload` JSON is parsed for forward
        // compat but its contents are intentionally unused — see fn doc.
        let _ = metadata_json;

        self.with_group(&gid, |group, provider, signer| {
            let commit_stage = group
                .commit_builder()
                .load_psks(provider.storage())
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] Failed to load PSKs: {:?}", e);
                    MLSError::OpenMLS(format!("load_psks: {:?}", e))
                })?;

            let commit_bundle = commit_stage
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] Failed to build metadata commit: {:?}", e);
                    MLSError::OpenMLS(format!("build metadata commit: {:?}", e))
                })?
                .stage_commit(provider)
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] Failed to stage metadata commit: {:?}", e);
                    MLSError::OpenMLS(format!("stage metadata commit: {:?}", e))
                })?;

            let (commit_msg, _welcome, _group_info) = commit_bundle.into_contents();

            let commit_bytes = TlsSerialize::tls_serialize_detached(&commit_msg).map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to serialize metadata commit: {:?}", e);
                MLSError::SerializationError
            })?;

            crate::info_log!(
                "[MLS-CONTEXT] Group metadata update committed, {} bytes",
                commit_bytes.len()
            );

            Ok(commit_bytes)
        })
    }

    /// Atomic encrypted metadata update (Phase A.2).
    ///
    /// Stages a GroupContextExtensions commit that updates the
    /// `MetadataReference` in AppDataDictionary 0x8001, derives the
    /// post-commit metadata key from the staged commit's exporter, and
    /// encrypts a fresh `GroupMetadataV1` payload. Returns everything
    /// the caller needs: the commit bytes, the encrypted blob, the
    /// blob locator, the new metadata version, and the final
    /// MetadataReference JSON (with the real ciphertext hash) for the
    /// caller's local cache.
    ///
    /// Caller orchestration:
    ///   1. Send `commit_bytes` to the DS.
    ///   2. Upload `metadata_blob_ciphertext` via `putGroupMetadataBlob`
    ///      with `metadata_blob_locator`.
    ///   3. After server ACK, call `merge_pending_commit(group_id)` to
    ///      apply the commit locally.
    ///   4. Store `metadata_reference_json` in the conversation cache.
    ///
    /// Empty `title` and `description` are encoded as empty strings in
    /// the encrypted payload (callers can treat empty as "unset").
    pub fn update_group_metadata_encrypted(
        &mut self,
        group_id: &[u8],
        title: Option<String>,
        description: Option<String>,
        avatar_blob_locator: Option<String>,
        avatar_content_type: Option<String>,
        aad: Option<Vec<u8>>,
    ) -> Result<UpdateGroupMetadataResult, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            // 1. Compute next metadata version + fresh blob locator.
            let current_ref = metadata::current_metadata_reference(group);
            let had_metadata = current_ref.is_some();
            let next_version = metadata::next_metadata_version(
                current_ref.as_ref(),
                had_metadata,
                true,
            )
            .unwrap_or(1);
            let new_locator = Uuid::new_v4().to_string().to_lowercase();

            // 2. Build placeholder MetadataReference (empty ciphertext_hash).
            //    The hash is filled in for the *caller's local* reference but
            //    NOT the one embedded in the commit — see fn doc above.
            let placeholder_ref = metadata::build_metadata_reference(
                next_version,
                &new_locator,
                &[],
            );
            let placeholder_ref_json = serde_json::to_vec(&placeholder_ref).map_err(|e| {
                MLSError::Internal(format!("serialize placeholder reference: {:?}", e))
            })?;

            if let Some(ref aad_bytes) = aad {
                group.set_aad(aad_bytes.clone());
            }
            let commit_bundle_res = (|| -> Result<_, MLSError> {
                let commit_stage = group
                    .commit_builder()
                    .force_self_update(true)
                    .load_psks(provider.storage())
                    .map_err(|e| MLSError::OpenMLS(format!("load_psks: {:?}", e)))?;
                let commit_bundle = commit_stage
                    .build(provider.rand(), provider.crypto(), signer, |_| true)
                    .map_err(|e| MLSError::OpenMLS(format!("build commit: {:?}", e)))?
                    .stage_commit(provider)
                    .map_err(|e| MLSError::OpenMLS(format!("stage commit: {:?}", e)))?;
                Ok(commit_bundle)
            })();
            if aad.is_some() {
                group.set_aad(vec![]);
            }
            let commit_bundle = commit_bundle_res?;
            let (commit_msg, _welcome, _group_info) = commit_bundle.into_contents();
            let commit_bytes = TlsSerialize::tls_serialize_detached(&commit_msg)
                .map_err(|_| MLSError::SerializationError)?;

            // 5. Derive the post-commit metadata key from the now-pending staged commit.
            let next_epoch = group.epoch().as_u64() + 1;
            let pending = group.pending_commit().ok_or_else(|| {
                MLSError::Internal(
                    "no pending commit after stage_commit — internal invariant violated".into(),
                )
            })?;
            let metadata_key = metadata::derive_metadata_key(
                pending,
                provider.crypto(),
                group_id,
                next_epoch,
            )
            .map_err(|e| MLSError::Internal(format!("derive metadata key: {:?}", e)))?;

            // 6. Build payload + encrypt.
            let payload = metadata::GroupMetadataV1 {
                version: 1,
                title: title.unwrap_or_default(),
                description: description.unwrap_or_default(),
                avatar_blob_locator,
                avatar_content_type,
            };
            let ciphertext = metadata::encrypt_metadata_blob(
                &metadata_key,
                group_id,
                next_epoch,
                next_version,
                &payload,
            )
            .map_err(|e| MLSError::Internal(format!("encrypt metadata: {:?}", e)))?;

            // 7. Build the FINAL reference (with real ciphertext hash) for the
            //    caller's local cache. The reference embedded in the commit
            //    keeps the placeholder hash; the ciphertext hash is
            //    informational on the wire (AEAD authenticates the payload).
            let real_hash = metadata::hash_ciphertext(&ciphertext);
            let final_ref = metadata::build_metadata_reference(
                next_version,
                &new_locator,
                &real_hash,
            );
            let final_ref_json = serde_json::to_vec(&final_ref).map_err(|e| {
                MLSError::Internal(format!("serialize final reference: {:?}", e))
            })?;

            crate::info_log!(
                "[MLS-CONTEXT] update_group_metadata_encrypted committed (epoch→{}, version={}, locator={})",
                next_epoch,
                next_version,
                new_locator
            );

            use openmls::prelude::tls_codec::DeserializeBytes as _;
            let next_tag = MlsMessageIn::tls_deserialize_exact_bytes(&commit_bytes)
                .ok()
                .and_then(|msg_in| match msg_in.extract() {
                    MlsMessageBodyIn::PublicMessage(pm) => pm.confirmation_tag().cloned(),
                    _ => None,
                })
                .and_then(|t| t.tls_serialize_detached().ok())
                .map(|tag_bytes| if tag_bytes.len() > 32 { tag_bytes[tag_bytes.len() - 32..].to_vec() } else { tag_bytes });
            let next_gch = pending
                .group_context()
                .tls_serialize_detached()
                .ok()
                .map(|gc_bytes| sha2::Sha256::digest(&gc_bytes).to_vec());

            Ok(UpdateGroupMetadataResult {
                commit_bytes,
                metadata_blob_ciphertext: ciphertext,
                metadata_reference_json: final_ref_json,
                metadata_version: next_version,
                metadata_blob_locator: new_locator,
                next_confirmation_tag: next_tag,
                next_group_context_hash: next_gch,
            })
        })
    }

    /// Export a group's state for persistent storage
    ///
    /// Uses OpenMLS's built-in load/save mechanism.
    /// Returns just the group ID and signer key - the group state
    /// is persisted in OpenMLS's internal storage which is memory-based.
    ///
    /// NOTE: This is a simplified implementation. For true persistence,
    /// we'd need to implement a custom StorageProvider that writes to disk.
    pub fn export_group_state(&self, group_id: &[u8]) -> Result<Vec<u8>, MLSError> {
        crate::debug_log!(
            "[MLS-CONTEXT] export_group_state: Starting for group {}",
            hex::encode(group_id)
        );

        let state = self.groups.get(group_id).ok_or_else(|| {
            crate::debug_log!("[MLS-CONTEXT] ERROR: Group not found for export");
            MLSError::group_not_found(hex::encode(group_id))
        })?;

        // For now, just return the signer public key and group ID
        // The actual group state is in OpenMLS's provider storage (memory)
        // This is sufficient for the singleton approach

        // Format: [group_id_len: u32][group_id][signer_key_len: u32][signer_key]
        let mut result = Vec::new();
        let gid_len = group_id.len() as u32;
        let key_len = state.signer_public_key.len() as u32;

        result.extend_from_slice(&gid_len.to_le_bytes());
        result.extend_from_slice(group_id);
        result.extend_from_slice(&key_len.to_le_bytes());
        result.extend_from_slice(&state.signer_public_key);

        crate::debug_log!(
            "[MLS-CONTEXT] export_group_state: Complete, total {} bytes",
            result.len()
        );
        Ok(result)
    }

    /// Import a group's state from persistent storage
    ///
    /// NOTE: This is a placeholder for the singleton approach.
    /// Groups are already in memory, so this just validates the group exists.
    pub fn import_group_state(&mut self, state_bytes: &[u8]) -> Result<Vec<u8>, MLSError> {
        crate::debug_log!(
            "[MLS-CONTEXT] import_group_state: Starting with {} bytes",
            state_bytes.len()
        );

        if state_bytes.len() < 8 {
            crate::debug_log!("[MLS-CONTEXT] ERROR: State bytes too short");
            return Err(MLSError::invalid_input("State bytes too short"));
        }

        // Parse: [group_id_len: u32][group_id][signer_key_len: u32][signer_key]
        let gid_len = u32::from_le_bytes([
            state_bytes[0],
            state_bytes[1],
            state_bytes[2],
            state_bytes[3],
        ]) as usize;

        if state_bytes.len() < 4 + gid_len + 4 {
            crate::debug_log!("[MLS-CONTEXT] ERROR: Invalid state format");
            return Err(MLSError::invalid_input("Invalid state format"));
        }

        let group_id = state_bytes[4..4 + gid_len].to_vec();
        crate::debug_log!(
            "[MLS-CONTEXT] Group ID from state: {}",
            hex::encode(&group_id)
        );

        // Check if group exists (singleton keeps it in memory)
        if self.has_group(&group_id) {
            crate::debug_log!("[MLS-CONTEXT] Group already loaded in memory");
            Ok(group_id)
        } else {
            crate::debug_log!("[MLS-CONTEXT] Group not found - needs reconstruction from Welcome");
            Err(MLSError::group_not_found(hex::encode(&group_id)))
        }
    }

    /// Find every leaf selected by a removal identity.
    ///
    /// A fragment-qualified identity names one exact device. A bare DID names
    /// the root credential and every device credential below that root. The
    /// explicit `#` boundary prevents prefix lookalikes from matching.
    pub(crate) fn find_member_indices(group: &MlsGroup, identity: &[u8]) -> Vec<LeafNodeIndex> {
        let is_bare_did = !identity.contains(&b'#');

        group
            .members()
            .filter_map(|member| {
                let credential = member.credential.serialized_content();
                let root_match = is_bare_did
                    && credential
                        .strip_prefix(identity)
                        .is_some_and(|suffix| suffix.first() == Some(&b'#'));

                (credential == identity || root_match).then_some(member.index)
            })
            .collect()
    }

    /// Remove members from the group (internal implementation)
    ///
    /// Creates a commit with Remove proposals. Follows send-then-merge pattern:
    /// caller must send commit to server and call merge_pending_commit() after ACK.
    pub fn remove_members_internal(
        &mut self,
        group_id: &[u8],
        member_identities: &[Vec<u8>],
        aad: Option<Vec<u8>>,
    ) -> Result<RemoveMembersResult, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            // 1. Convert identities to leaf indices
            let mut indices_to_remove = Vec::new();
            for identity in member_identities {
                let matching_indices = Self::find_member_indices(group, identity);
                if matching_indices.is_empty() {
                    crate::warn_log!(
                        "[MLS-CONTEXT] Member not found (may already be removed): {}",
                        hex::encode(identity)
                    );
                } else {
                    for index in matching_indices {
                        crate::debug_log!(
                            "[MLS-CONTEXT] Found member to remove: {} at index {}",
                            hex::encode(identity),
                            index.u32()
                        );
                        if !indices_to_remove.contains(&index) {
                            indices_to_remove.push(index);
                        }
                    }
                }
            }

            if indices_to_remove.is_empty() {
                crate::warn_log!("[MLS-CONTEXT] No valid members found to remove");
                return Err(MLSError::invalid_input("No members found to remove"));
            }

            crate::info_log!(
                "[MLS-CONTEXT] Removing {} members from group",
                indices_to_remove.len()
            );

            let join_config = openmls::group::MlsGroupJoinConfig::builder()
                .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build();
            let _ = group.set_configuration(provider.storage(), &join_config);

            if let Some(aad_bytes) = &aad {
                group.set_aad(aad_bytes.clone());
            }
            let commit_bundle_res = (|| -> Result<_, MLSError> {
                let commit_builder = group
                    .commit_builder()
                    .propose_removals(indices_to_remove)
                    .force_self_update(true);

                let commit_stage = commit_builder.load_psks(provider.storage()).map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] remove_members load_psks failed: {:?}", e);
                    MLSError::OpenMLS(format!("remove_members load_psks failed: {:?}", e))
                })?;

                let commit_bundle = commit_stage
                    .build(provider.rand(), provider.crypto(), signer, |_| true)
                    .map_err(|e| {
                        crate::error_log!("[MLS-CONTEXT] remove_members build failed: {:?}", e);
                        MLSError::OpenMLS(format!("remove_members build failed: {:?}", e))
                    })?
                    .stage_commit(provider)
                    .map_err(|e| {
                        crate::error_log!("[MLS-CONTEXT] remove_members stage failed: {:?}", e);
                        MLSError::OpenMLS(format!("remove_members stage failed: {:?}", e))
                    })?;
                Ok(commit_bundle)
            })();
            if aad.is_some() {
                group.set_aad(vec![]);
            }
            let commit_bundle = commit_bundle_res?;
            let (commit, welcome_option, group_info) = commit_bundle.into_contents();

            // 3. DO NOT merge - send-then-merge pattern
            crate::debug_log!("[MLS-CONTEXT] Remove commit staged (NOT merged)");
            crate::debug_log!("[MLS-CONTEXT]   Caller MUST merge after server ACK");

            // 4. Serialize commit
            let commit_bytes = commit.tls_serialize_detached().map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to serialize remove commit: {:?}", e);
                MLSError::SerializationError
            })?;

            // Remove operations never produce Welcome messages
            if welcome_option.is_some() {
                crate::error_log!("[MLS-CONTEXT] ⚠️ Unexpected Welcome from remove_members!");
            }

            let next_gch = group
                .pending_commit()
                .and_then(|pending| {
                    pending
                        .group_context()
                        .tls_serialize_detached()
                        .ok()
                        .map(|gc_bytes| sha2::Sha256::digest(&gc_bytes).to_vec())
                })
                .or_else(|| {
                    group_info.as_ref().and_then(|gi| {
                        gi.group_context()
                            .tls_serialize_detached()
                            .ok()
                            .map(|gc_bytes| sha2::Sha256::digest(&gc_bytes).to_vec())
                    })
                });

            use openmls::prelude::tls_codec::DeserializeBytes as _;
            let next_tag = MlsMessageIn::tls_deserialize_exact_bytes(&commit_bytes)
                .ok()
                .and_then(|msg_in| match msg_in.extract() {
                    MlsMessageBodyIn::PublicMessage(pm) => pm.confirmation_tag().cloned(),
                    _ => None,
                })
                .and_then(|t| t.tls_serialize_detached().ok())
                .map(|tag_bytes| {
                    if tag_bytes.len() > 32 {
                        tag_bytes[tag_bytes.len() - 32..].to_vec()
                    } else {
                        tag_bytes
                    }
                });

            crate::info_log!(
                "[MLS-CONTEXT] ✅ Remove commit created, size: {} bytes",
                commit_bytes.len()
            );

            Ok(RemoveMembersResult {
                commit_data: commit_bytes,
                next_confirmation_tag: next_tag,
                next_group_context_hash: next_gch,
            })
        })
    }

    /// Create an Add proposal (does not commit)
    ///
    /// Returns tuple of (proposal_message, proposal_ref) for tracking
    pub fn propose_add_internal(
        &mut self,
        group_id: &[u8],
        key_package_data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            // Deserialize and validate key package
            let kp_in =
                if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(key_package_data) {
                    match mls_msg.extract() {
                        MlsMessageBodyIn::KeyPackage(kp_in) => kp_in,
                        _ => {
                            let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(key_package_data)
                                .map_err(|e| {
                                    crate::error_log!(
                                        "[MLS-CONTEXT] Failed to deserialize key package: {:?}",
                                        e
                                    );
                                    MLSError::SerializationError
                                })?;
                            kp_in
                        }
                    }
                } else {
                    let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(key_package_data)
                        .map_err(|e| {
                            crate::error_log!(
                                "[MLS-CONTEXT] Failed to deserialize key package: {:?}",
                                e
                            );
                            MLSError::SerializationError
                        })?;
                    kp_in
                };

            let key_package = kp_in
                .validate(provider.crypto(), ProtocolVersion::default())
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] Key package validation failed: {:?}", e);
                    MLSError::InvalidKeyPackage
                })?;

            // Create proposal via OpenMLS
            let (msg_out, proposal_ref) = group
                .propose_add_member(provider, signer, &key_package)
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] propose_add_member failed: {:?}", e);
                    MLSError::OpenMLS(format!("propose_add_member failed: {:?}", e))
                })?;

            // Serialize both message and reference
            let msg_bytes = msg_out.tls_serialize_detached().map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] Failed to serialize proposal message: {:?}",
                    e
                );
                MLSError::SerializationError
            })?;

            let ref_bytes = proposal_ref.tls_serialize_detached().map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to serialize proposal ref: {:?}", e);
                MLSError::SerializationError
            })?;

            crate::info_log!(
                "[MLS-CONTEXT] ✅ Add proposal created, message: {} bytes, ref: {} bytes",
                msg_bytes.len(),
                ref_bytes.len()
            );

            Ok((msg_bytes, ref_bytes))
        })
    }

    /// Create a Remove proposal (does not commit)
    ///
    /// Returns tuple of (proposal_message, proposal_ref) for tracking
    pub fn propose_remove_internal(
        &mut self,
        group_id: &[u8],
        member_identity: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            // A proposal carries exactly one Remove. Expand a bare DID through
            // the same selector as direct removal, but fail closed when it is
            // ambiguous instead of silently leaving additional devices active.
            let member_indices = Self::find_member_indices(group, member_identity);
            let member_index = match member_indices.as_slice() {
                [] => {
                    crate::error_log!(
                        "[MLS-CONTEXT] Member not found: {}",
                        hex::encode(member_identity)
                    );
                    return Err(MLSError::member_not_found(
                        String::from_utf8_lossy(member_identity).to_string(),
                    ));
                }
                [member_index] => *member_index,
                _ => {
                    crate::error_log!(
                        "[MLS-CONTEXT] Remove proposal identity matched multiple leaves: {}",
                        hex::encode(member_identity)
                    );
                    return Err(MLSError::invalid_input(
                        "Remove proposal identity matches multiple device leaves; use fragment-qualified identities or the multi-member removal API",
                    ));
                }
            };

            crate::debug_log!(
                "[MLS-CONTEXT] Creating remove proposal for member at index {}",
                member_index.u32()
            );

            // Create proposal via OpenMLS
            let (msg_out, proposal_ref) = group
                .propose_remove_member(provider, signer, member_index)
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] propose_remove_member failed: {:?}", e);
                    MLSError::OpenMLSError
                })?;

            // Serialize
            let msg_bytes = msg_out.tls_serialize_detached().map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] Failed to serialize proposal message: {:?}",
                    e
                );
                MLSError::SerializationError
            })?;

            let ref_bytes = proposal_ref.tls_serialize_detached().map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to serialize proposal ref: {:?}", e);
                MLSError::SerializationError
            })?;

            crate::info_log!(
                "[MLS-CONTEXT] ✅ Remove proposal created, message: {} bytes, ref: {} bytes",
                msg_bytes.len(),
                ref_bytes.len()
            );

            Ok((msg_bytes, ref_bytes))
        })
    }

    /// Get detailed information about pending proposals
    pub fn get_pending_proposal_details(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<crate::types::PendingProposalDetail>, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group_ref(&gid, |group, _provider| {
            let details: Vec<crate::types::PendingProposalDetail> = group
                .pending_proposals()
                .filter_map(|queued_proposal| {
                    let proposal = queued_proposal.proposal();

                    // Use OpenMLS's authenticated-content reference exactly.
                    // Hashing only the proposal body produces a different key
                    // that cannot address the durable proposal store.
                    let proposal_ref = queued_proposal
                        .proposal_reference_ref()
                        .tls_serialize_detached()
                        .ok()?;

                    let sender_identity = match queued_proposal.sender() {
                        Sender::Member(leaf_index) => group
                            .members()
                            .find(|m| m.index == *leaf_index)
                            .map(|m| m.credential.serialized_content().to_vec()),
                        _ => None,
                    };

                    let sender_leaf_index = match queued_proposal.sender() {
                        Sender::Member(leaf_index) => Some(leaf_index.u32()),
                        _ => None,
                    };

                    match proposal {
                        Proposal::Add(add) => Some(crate::types::PendingProposalDetail {
                            proposal_ref,
                            proposal_type: "add".to_string(),
                            add_identity: Some(
                                add.key_package()
                                    .leaf_node()
                                    .credential()
                                    .serialized_content()
                                    .to_vec(),
                            ),
                            remove_leaf_index: None,
                            update_identity: None,
                            sender_identity,
                            sender_leaf_index,
                        }),
                        Proposal::Remove(remove) => Some(crate::types::PendingProposalDetail {
                            proposal_ref,
                            proposal_type: "remove".to_string(),
                            add_identity: None,
                            remove_leaf_index: Some(remove.removed().u32()),
                            update_identity: None,
                            sender_identity,
                            sender_leaf_index,
                        }),
                        Proposal::Update(update) => Some(crate::types::PendingProposalDetail {
                            proposal_ref,
                            proposal_type: "update".to_string(),
                            add_identity: None,
                            remove_leaf_index: None,
                            update_identity: Some(
                                update
                                    .leaf_node()
                                    .credential()
                                    .serialized_content()
                                    .to_vec(),
                            ),
                            sender_identity,
                            sender_leaf_index,
                        }),
                        Proposal::PreSharedKey(_) => Some(crate::types::PendingProposalDetail {
                            proposal_ref,
                            proposal_type: "psk".to_string(),
                            add_identity: None,
                            remove_leaf_index: None,
                            update_identity: None,
                            sender_identity,
                            sender_leaf_index,
                        }),
                        Proposal::ReInit(_) => Some(crate::types::PendingProposalDetail {
                            proposal_ref,
                            proposal_type: "reinit".to_string(),
                            add_identity: None,
                            remove_leaf_index: None,
                            update_identity: None,
                            sender_identity,
                            sender_leaf_index,
                        }),
                        Proposal::ExternalInit(_) => Some(crate::types::PendingProposalDetail {
                            proposal_ref,
                            proposal_type: "external_init".to_string(),
                            add_identity: None,
                            remove_leaf_index: None,
                            update_identity: None,
                            sender_identity,
                            sender_leaf_index,
                        }),
                        Proposal::GroupContextExtensions(_) => {
                            Some(crate::types::PendingProposalDetail {
                                proposal_ref,
                                proposal_type: "group_context_extensions".to_string(),
                                add_identity: None,
                                remove_leaf_index: None,
                                update_identity: None,
                                sender_identity,
                                sender_leaf_index,
                            })
                        }
                        _ => None,
                    }
                })
                .collect();

            Ok(details)
        })
    }

    /// Create a self-update proposal (does not commit)
    ///
    /// Returns tuple of (proposal_message, proposal_ref) for tracking
    pub fn propose_self_update_internal(
        &mut self,
        group_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            crate::debug_log!("[MLS-CONTEXT] Creating self-update proposal");

            // Create proposal via OpenMLS using default leaf node parameters
            let (msg_out, proposal_ref) = group
                .propose_self_update(provider, signer, LeafNodeParameters::builder().build())
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] propose_self_update failed: {:?}", e);
                    MLSError::OpenMLSError
                })?;

            // Serialize
            let msg_bytes = msg_out.tls_serialize_detached().map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] Failed to serialize proposal message: {:?}",
                    e
                );
                MLSError::SerializationError
            })?;

            let ref_bytes = proposal_ref.tls_serialize_detached().map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to serialize proposal ref: {:?}", e);
                MLSError::SerializationError
            })?;

            crate::info_log!(
                "[MLS-CONTEXT] ✅ Self-update proposal created, message: {} bytes, ref: {} bytes",
                msg_bytes.len(),
                ref_bytes.len()
            );

            Ok((msg_bytes, ref_bytes))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Field-level (envelope) encryption: content root key plumbing
// ─────────────────────────────────────────────────────────────────────────────
//
// These methods manage an ephemeral, in-memory content root key used by
// `crate::field_encryption` to encrypt/decrypt message payloads and chain
// HMACs. The key is platform-supplied (typically exported from MLS group
// state on the platform layer) and never persisted by this layer.
impl MLSContext {
    /// Install the content root key. Must be exactly
    /// [`crate::field_encryption::KEY_LEN`] bytes (32).
    pub fn set_content_root_key(&self, key: Vec<u8>) -> Result<(), MLSError> {
        if key.len() != crate::field_encryption::KEY_LEN {
            return Err(MLSError::InvalidArgument(format!(
                "content root key must be {} bytes, got {}",
                crate::field_encryption::KEY_LEN,
                key.len(),
            )));
        }
        let mut guard = self
            .content_root_key
            .write()
            .map_err(|e| MLSError::lock_poisoned(format!("content_root_key write: {}", e)))?;
        *guard = Some(key);
        Ok(())
    }

    /// Drop the in-memory content root key. Subsequent calls to
    /// `with_content_root_key` will return `MLSError::InvalidState` until
    /// `set_content_root_key` is called again.
    pub fn clear_content_root_key(&self) {
        if let Ok(mut guard) = self.content_root_key.write() {
            *guard = None;
        }
    }

    /// Run `f` with a borrowed reference to the current content root key,
    /// returning `MLSError::InvalidState` if no key has been installed.
    pub(crate) fn with_content_root_key<F, T>(&self, f: F) -> Result<T, MLSError>
    where
        F: FnOnce(&[u8]) -> Result<T, MLSError>,
    {
        let guard = self
            .content_root_key
            .read()
            .map_err(|e| MLSError::lock_poisoned(format!("content_root_key read: {}", e)))?;
        let key = guard
            .as_ref()
            .ok_or_else(|| MLSError::InvalidState("content root key not set".to_string()))?;
        f(key)
    }
}

#[cfg(test)]
mod manifest_bundle_storage_tests {
    use super::*;

    struct NoopKeychain;

    #[async_trait::async_trait]
    impl KeychainAccess for NoopKeychain {
        async fn read(&self, _key: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }

        async fn write(&self, _key: String, _value: Vec<u8>) -> Result<(), MLSError> {
            Ok(())
        }

        async fn delete(&self, _key: String) -> Result<(), MLSError> {
            Ok(())
        }
    }

    fn make_storage() -> (ManifestStorage, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "catbird_mls_manifest_bundle_tests_{}_{}_{}",
            std::process::id(),
            id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let storage =
            ManifestStorage::new(dir.join("manifest.db"), "test-key-1234567890123456").unwrap();
        (storage, dir)
    }

    #[test]
    fn durability_checkpoint_requires_complete_non_busy_wal_result() {
        assert!(validate_durability_checkpoint(0, 7, 7).is_ok());
        assert!(validate_durability_checkpoint(1, 7, 7).is_err());
        assert!(validate_durability_checkpoint(0, 7, 6).is_err());
        assert!(validate_durability_checkpoint(0, -1, -1).is_err());
    }

    #[test]
    fn psk_external_commit_fails_closed_without_materializing_state() {
        let (storage, dir) = make_storage();
        drop(storage);
        let db_path = dir.join("manifest.db").to_string_lossy().to_string();
        let (mut context, _interrupt_handles) = MLSContext::new(
            db_path,
            "test-key-1234567890123456".to_string(),
            Box::new(NoopKeychain),
        )
        .unwrap();

        let error = context
            .create_external_commit_with_psk(
                &[0x01, 0x02, 0x03],
                "did:plc:alice#device-1",
                &[0x42; 32],
            )
            .unwrap_err();
        assert!(matches!(error, MLSError::OperationNotSupported { .. }));
        assert!(context.groups.is_empty());
        assert!(context.signers_by_identity.is_empty());
        assert!(context
            .manifest_storage
            .read_manifest::<Vec<String>>("group_ids")
            .unwrap()
            .unwrap_or_default()
            .is_empty());
        assert!(context
            .manifest_storage
            .read_manifest::<HashMap<String, PendingExternalJoin>>("pending_external_joins")
            .unwrap()
            .unwrap_or_default()
            .is_empty());
    }

    #[test]
    fn bundle_rows_round_trip() {
        let (storage, _dir) = make_storage();

        let rows = vec![
            ("aa11".to_string(), "YnVuZGxlMQ==".to_string()),
            ("bb22".to_string(), "YnVuZGxlMg==".to_string()),
        ];
        storage.insert_bundles(&rows).unwrap();

        assert_eq!(storage.count_bundles(), 2);
        assert!(storage.contains_bundle("aa11"));
        assert!(!storage.contains_bundle("cc33"));

        let mut loaded = storage.load_all_bundles().unwrap();
        loaded.sort();
        assert_eq!(loaded, rows);

        let removed = storage.delete_bundles(&["aa11".to_string()]).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(storage.count_bundles(), 1);
        assert!(!storage.contains_bundle("aa11"));

        // Deleting an absent ref is a no-op, not an error.
        let removed = storage.delete_bundles(&["zz99".to_string()]).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn legacy_blob_migrates_to_rows_on_open() {
        let (storage, dir) = make_storage();

        // Seed the legacy monolithic blob format.
        let mut blob: HashMap<String, String> = HashMap::new();
        blob.insert("aa11".to_string(), "YnVuZGxlMQ==".to_string());
        blob.insert("bb22".to_string(), "YnVuZGxlMg==".to_string());
        storage
            .write_manifest("key_package_bundles", &blob)
            .unwrap();
        drop(storage);

        // Reopen: migration must move blob entries into per-row storage.
        let reopened =
            ManifestStorage::new(dir.join("manifest.db"), "test-key-1234567890123456").unwrap();

        let mut rows = reopened.load_all_bundles().unwrap();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                ("aa11".to_string(), "YnVuZGxlMQ==".to_string()),
                ("bb22".to_string(), "YnVuZGxlMg==".to_string()),
            ],
            "blob entries must be migrated into per-row storage"
        );

        let blob_after: Option<HashMap<String, String>> =
            reopened.read_manifest("key_package_bundles").unwrap();
        assert!(
            blob_after.is_none(),
            "legacy blob must be deleted after migration"
        );

        // Migration is idempotent across reopens.
        drop(reopened);
        let reopened_again =
            ManifestStorage::new(dir.join("manifest.db"), "test-key-1234567890123456").unwrap();
        assert_eq!(reopened_again.count_bundles(), 2);
    }

    #[test]
    fn migration_does_not_clobber_existing_rows() {
        let (storage, dir) = make_storage();

        // A row already exists (e.g. written by the migrated process)...
        storage
            .insert_bundles(&[("aa11".to_string(), "bmV3LXJvdw==".to_string())])
            .unwrap();
        // ...while a stale blob with the same hash_ref reappears (e.g. written
        // by a not-yet-updated NSE process).
        let mut blob: HashMap<String, String> = HashMap::new();
        blob.insert("aa11".to_string(), "b2xkLWJsb2I=".to_string());
        storage
            .write_manifest("key_package_bundles", &blob)
            .unwrap();
        drop(storage);

        let reopened =
            ManifestStorage::new(dir.join("manifest.db"), "test-key-1234567890123456").unwrap();
        let rows = reopened.load_all_bundles().unwrap();
        assert_eq!(
            rows,
            vec![("aa11".to_string(), "bmV3LXJvdw==".to_string())],
            "INSERT OR IGNORE migration must keep the newer row over the stale blob entry"
        );
    }

    #[test]
    fn prune_removes_only_expired_bundles() {
        let (storage, _dir) = make_storage();

        storage
            .insert_bundles(&[
                ("old1".to_string(), "YQ==".to_string()),
                ("new1".to_string(), "Yg==".to_string()),
            ])
            .unwrap();

        // Backdate one row past the 90-day lifetime.
        let backdated = unix_now_secs() - (KEY_PACKAGE_BUNDLE_MAX_AGE_SECS as i64) - 60;
        storage
            .conn
            .execute(
                "UPDATE mls_key_package_bundles SET created_at = ?1 WHERE hash_ref = 'old1'",
                [backdated],
            )
            .unwrap();

        let pruned = storage
            .prune_bundles_older_than(KEY_PACKAGE_BUNDLE_MAX_AGE_SECS)
            .unwrap();
        assert_eq!(pruned, vec!["old1".to_string()]);
        assert_eq!(storage.count_bundles(), 1);
        assert!(storage.contains_bundle("new1"));

        // Fresh rows survive a second prune.
        let pruned = storage
            .prune_bundles_older_than(KEY_PACKAGE_BUNDLE_MAX_AGE_SECS)
            .unwrap();
        assert!(pruned.is_empty());
    }
}
