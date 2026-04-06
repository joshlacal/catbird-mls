use openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;
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
use crate::group_metadata::{GroupMetadata, CATBIRD_METADATA_EXTENSION_TYPE};
use crate::metadata;
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
use sha2::{Digest, Sha256};

fn metadata_extension_capabilities() -> [ExtensionType; 3] {
    [
        ExtensionType::RatchetTree,
        ExtensionType::AppDataDictionary,
        ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE),
    ]
}

fn metadata_proposal_capabilities() -> [ProposalType; 1] {
    [ProposalType::AppDataUpdate]
}

fn metadata_leaf_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&metadata_extension_capabilities()),
        Some(&metadata_proposal_capabilities()),
        None,
    )
}

fn metadata_required_capabilities_extension() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(
        &metadata_extension_capabilities(),
        &metadata_proposal_capabilities(),
        &[],
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

        // Enable WAL mode for better concurrent performance
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to set WAL mode: {:?}", e);
                MLSError::StorageFailed
            })?;

        // Use NORMAL synchronous mode for faster writes (still safe with WAL)
        // NORMAL is faster than FULL and provides adequate durability
        conn.pragma_update(None, "synchronous", "NORMAL")
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
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| {
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

        Ok(())
    }

    /// Get an interrupt handle for aborting in-flight SQLCipher operations.
    pub(crate) fn get_interrupt_handle(&self) -> rusqlite::InterruptHandle {
        self.conn.get_interrupt_handle()
    }

    /// Force database flush to ensure all pending writes are committed to disk
    ///
    /// This executes a WAL checkpoint (if in WAL mode) and ensures durability.
    /// Uses PASSIVE mode to avoid blocking - SQLite will checkpoint what it can without waiting.
    /// This is faster than FULL mode while still providing reasonable durability guarantees.
    pub(crate) fn flush_database(&self) -> Result<(), MLSError> {
        // Use PASSIVE checkpoint which is non-blocking
        // It checkpoints as many frames as possible without waiting for readers/writers
        // This avoids the main thread stalls caused by FULL checkpoints
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
            .map_err(|e| {
                crate::error_log!("[MANIFEST-STORAGE] Failed to WAL checkpoint: {:?}", e);
                map_sqlite_error("wal_checkpoint(PASSIVE)", &e)
            })?;

        crate::debug_log!("[MANIFEST-STORAGE] ✅ Database checkpoint (PASSIVE) completed");
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

    pub fn storage_mut(&mut self) -> &mut HybridStorageProvider<JsonCodec> {
        &mut self.storage
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

pub struct GroupState {
    pub group: MlsGroup,
    pub signer_public_key: Vec<u8>,
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

        // Match manifest storage settings: WAL + fast sync + retry on contention
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to set WAL mode: {:?}", e);
                MLSError::StorageFailed
            })?;
        connection
            .pragma_update(None, "synchronous", "NORMAL")
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

        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| {
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

        // Read the manifest to get list of all bundle refs and their data
        match manifest_storage.read_manifest::<HashMap<String, String>>("key_package_bundles")? {
            Some(bundles_map) => {
                crate::info_log!(
                    "[MLS-CONTEXT] 📋 Found {} bundle entries",
                    bundles_map.len()
                );

                let mut loaded_count = 0;
                for (hex_ref, bundle_b64) in &bundles_map {
                    // Decode base64 first (bundles are stored as base64-encoded JSON)
                    match base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        bundle_b64,
                    ) {
                        Ok(bundle_json_bytes) => {
                            // Then deserialize JSON
                            match serde_json::from_slice::<openmls::prelude::KeyPackageBundle>(
                                &bundle_json_bytes,
                            ) {
                                Ok(bundle) => {
                                    if let Ok(hash_ref) = hex::decode(hex_ref) {
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
                    bundles_map.len()
                );
            }
            None => {
                crate::info_log!(
                    "[MLS-CONTEXT] 📋 No bundles found, starting with empty bundle cache"
                );
            }
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
                        match SignatureKeyPair::read(
                            provider.storage(),
                            &public_key,
                            SignatureScheme::ED25519,
                        ) {
                            Some(_) => {
                                // Keypair exists in storage, this mapping is valid
                                signers_by_identity.insert(identity, public_key);
                            }
                            None => {
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
                            Ok(Some(group)) => {
                                let loaded_epoch = group.epoch().as_u64();
                                let loaded_members = group.members().count();

                                crate::info_log!("[MLS-CONTEXT] ✅ Group loaded from storage:");
                                crate::info_log!("[MLS-CONTEXT]   Group ID: {}", hex_id);
                                crate::info_log!("[MLS-CONTEXT]   Epoch: {}", loaded_epoch);
                                crate::info_log!("[MLS-CONTEXT]   Members: {}", loaded_members);

                                // 🔑 CRITICAL FIX: Restore signer_public_key from signers_by_identity
                                // Extract own credential from the group to find the correct signer
                                let signer_public_key = if let Some(own_leaf) =
                                    group.own_leaf_node()
                                {
                                    let own_credential = own_leaf.credential().serialized_content();

                                    // Look up signer public key by identity
                                    if let Some(pk) = signers_by_identity.get(own_credential) {
                                        crate::debug_log!(
                                            "[MLS-CONTEXT] ✅ Restored signer for group {}",
                                            hex_id
                                        );
                                        pk.clone()
                                    } else {
                                        crate::error_log!("[MLS-CONTEXT] ⚠️ No signer found for group {} credential", hex_id);
                                        Vec::new()
                                    }
                                } else {
                                    crate::error_log!(
                                        "[MLS-CONTEXT] ⚠️ Group {} has no own leaf node",
                                        hex_id
                                    );
                                    Vec::new()
                                };

                                // Skip verification round-trip in production to speed up initialization
                                // The double-load was only useful for debugging storage consistency

                                groups.insert(
                                    group_id_bytes,
                                    GroupState {
                                        group,
                                        signer_public_key,
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

    /// Get mutable access to key_package_bundles
    pub fn key_package_bundles_mut(&mut self) -> &mut HashMap<Vec<u8>, KeyPackageBundle> {
        &mut self.key_package_bundles
    }

    /// Get immutable access to key_package_bundles
    pub fn key_package_bundles(&self) -> &HashMap<Vec<u8>, KeyPackageBundle> {
        &self.key_package_bundles
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
        crate::debug_log!(
            "[MLS-CONTEXT] create_external_commit: Starting for identity '{}'",
            identity
        );

        // 🔍 DIAGNOSTIC: Log GroupInfo details to debug InvalidVectorLength errors
        crate::info_log!("[MLS-CONTEXT] create_external_commit: GroupInfo diagnostics:");
        crate::info_log!("   - Total bytes: {}", group_info_bytes.len());
        if group_info_bytes.len() >= 16 {
            crate::info_log!("   - First 16 bytes: {:02x?}", &group_info_bytes[..16]);
        } else {
            crate::info_log!("   - All bytes (truncated): {:02x?}", group_info_bytes);
        }
        if group_info_bytes.is_empty() {
            crate::error_log!("[MLS-CONTEXT] ❌ ERROR: GroupInfo is empty!");
            return Err(MLSError::invalid_input("GroupInfo is empty"));
        }

        // 🔍 DIAGNOSTIC: Check for suspiciously small GroupInfo
        // A valid MLS GroupInfo should be at least ~100 bytes (group_id, epoch, tree, etc.)
        if group_info_bytes.len() < 100 {
            crate::error_log!(
                "[MLS-CONTEXT] ⚠️ WARNING: GroupInfo suspiciously small: {} bytes",
                group_info_bytes.len()
            );
            crate::error_log!("[MLS-CONTEXT]    Valid GroupInfo typically >= 100 bytes");
            crate::error_log!("[MLS-CONTEXT]    Raw bytes: {:02x?}", group_info_bytes);
            // Don't fail yet - let deserialization provide the specific error
        }

        // 🔍 DIAGNOSTIC: Check for base64 encoding issues
        // MLS GroupInfo is binary TLS-serialized data, NOT base64 ASCII text
        // If all bytes are printable ASCII, it was likely not decoded from base64
        let is_ascii_only = group_info_bytes.iter().all(|&b| {
            (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D // printable ASCII + newlines
        });
        if is_ascii_only && group_info_bytes.len() > 50 {
            crate::error_log!(
                "[MLS-CONTEXT] ❌ ERROR: GroupInfo appears to be base64-encoded text!"
            );
            crate::error_log!(
                "[MLS-CONTEXT]    All {} bytes are printable ASCII characters",
                group_info_bytes.len()
            );
            crate::error_log!(
                "[MLS-CONTEXT]    This suggests base64 decoding was skipped somewhere"
            );
            if let Ok(text_preview) =
                std::str::from_utf8(&group_info_bytes[..std::cmp::min(100, group_info_bytes.len())])
            {
                crate::error_log!("[MLS-CONTEXT]    First 100 chars: {}", text_preview);
            }
            return Err(MLSError::invalid_input(
                "GroupInfo appears to be base64-encoded - decoding may have been skipped",
            ));
        }

        // 1. Deserialize MlsMessageIn first (GroupInfo is wrapped in MLS message envelope)
        // The export_group_info() function returns MlsMessageOut which serializes with:
        //   - 2 bytes: protocol version (0x0001)
        //   - 2 bytes: message type discriminant (0x0004 for GroupInfo)
        //   - N bytes: the actual GroupInfo/VerifiableGroupInfo data
        let (mls_message, _) =
            MlsMessageIn::tls_deserialize_bytes(group_info_bytes).map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] ❌ ERROR: MlsMessageIn deserialization failed!");
                crate::error_log!("[MLS-CONTEXT]    Error type: {:?}", e);
                crate::error_log!(
                    "[MLS-CONTEXT]    GroupInfo length: {} bytes",
                    group_info_bytes.len()
                );
                crate::error_log!("[MLS-CONTEXT]    This typically indicates:");
                crate::error_log!("[MLS-CONTEXT]    1. GroupInfo was corrupted during transport");
                crate::error_log!("[MLS-CONTEXT]    2. GroupInfo format version mismatch");
                crate::error_log!(
                    "[MLS-CONTEXT]    3. Server stored/returned stale or invalid GroupInfo"
                );
                MLSError::invalid_input(format!(
                    "Invalid GroupInfo ({} bytes): {:?}",
                    group_info_bytes.len(),
                    e
                ))
            })?;

        // Extract the VerifiableGroupInfo from the MLS message body
        let verifiable_group_info = match mls_message.extract() {
            MlsMessageBodyIn::GroupInfo(vgi) => {
                crate::debug_log!(
                    "[MLS-CONTEXT] ✅ Successfully extracted VerifiableGroupInfo from MlsMessage"
                );
                vgi
            }
            _other => {
                crate::error_log!("[MLS-CONTEXT] ❌ ERROR: MlsMessage is not a GroupInfo!");
                crate::error_log!(
                    "[MLS-CONTEXT]    Expected GroupInfo variant, got different message type"
                );
                return Err(MLSError::invalid_input(
                    "Expected MlsMessage containing GroupInfo, got different message type"
                        .to_string(),
                ));
            }
        };

        // 2. Create credential
        let credential = Credential::new(CredentialType::Basic, identity.as_bytes().to_vec());

        // 3. Get or create signature keys (reuse existing keys for this identity)
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
                    crate::error_log!(
                        "[MLS-CONTEXT] ERROR: Failed to create signature keys: {:?}",
                        e
                    );
                    MLSError::OpenMLS(format!(
                        "create_external_commit: Failed to create signature keys: {:?}",
                        e
                    ))
                })?;

                new_keys.store(self.provider.storage()).map_err(|e| {
                    crate::error_log!(
                        "[MLS-CONTEXT] ERROR: Failed to store signature keys: {:?}",
                        e
                    );
                    MLSError::OpenMLS(format!(
                        "create_external_commit: Failed to store signature keys: {:?}",
                        e
                    ))
                })?;
                crate::debug_log!("[MLS-CONTEXT] Signature keys generated and stored");

                (new_keys, true)
            }
        };

        // 4. Create join config
        let join_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();

        // 5. Create external commit using builder pattern (replaces deprecated join_by_external_commit)
        let (group, commit_message_bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config)
            .build_group(
                &self.provider,
                verifiable_group_info,
                CredentialWithKey {
                    credential,
                    signature_key: signature_keys.public().into(),
                },
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder build_group failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!(
                    "external_commit_builder build_group failed: {:?}",
                    e
                ))
            })?
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(metadata_leaf_capabilities())
                    .build(),
            )
            .load_psks(self.provider.storage())
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder load_psks failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!("external_commit_builder load_psks failed: {:?}", e))
            })?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &signature_keys,
                |_| true, // accept all proposals
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder build failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!("external_commit_builder build failed: {:?}", e))
            })?
            .finalize(&self.provider)
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder finalize failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!("external_commit_builder finalize failed: {:?}", e))
            })?;

        let commit = commit_message_bundle.commit();

        // 6. Store group state
        let group_id = group.group_id().as_slice().to_vec();
        self.groups.insert(
            group_id.clone(),
            GroupState {
                group,
                signer_public_key: signature_keys.public().to_vec(),
            },
        );

        // Persist
        self.persist_group_id(&group_id).map_err(|e| {
            crate::error_log!("[MLS-CONTEXT] ⚠️ Failed to persist group ID: {:?}", e);
            MLSError::Internal(format!("Failed to persist group ID: {:?}", e))
        })?;

        // Only persist signer mapping if we created a new key
        if is_new_key {
            self.persist_signer_mapping(identity.as_bytes(), signature_keys.public())
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] ⚠️ Failed to persist signer mapping: {:?}", e);
                    MLSError::Internal(format!("Failed to persist signer mapping: {:?}", e))
                })?;
            crate::debug_log!("[MLS-CONTEXT] Persisted new signer mapping for identity");
        } else {
            crate::debug_log!(
                "[MLS-CONTEXT] Signer already registered for identity, not persisting"
            );
        }

        // Return commit bytes (to send to server) and group ID
        let commit_bytes = TlsSerialize::tls_serialize_detached(&commit)
            .map_err(|_| MLSError::SerializationError)?;

        // Export GroupInfo from the newly created group so it can be sent to the server
        let exported_group_info = {
            let gs = self.groups.get(&group_id);
            match gs {
                Some(gs) => {
                    match gs.group.export_group_info(
                        self.provider.crypto(),
                        &signature_keys,
                        true, // with ratchet tree
                    ) {
                        Ok(gi_out) => {
                            match TlsSerialize::tls_serialize_detached(&gi_out) {
                                Ok(bytes) => {
                                    crate::debug_log!(
                                        "[MLS-CONTEXT] Exported GroupInfo after external commit: {} bytes",
                                        bytes.len()
                                    );
                                    Some(bytes)
                                }
                                Err(e) => {
                                    crate::warn_log!(
                                        "[MLS-CONTEXT] Failed to serialize exported GroupInfo: {:?}", e
                                    );
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            crate::warn_log!(
                                "[MLS-CONTEXT] Failed to export GroupInfo after external commit: {:?}", e
                            );
                            None
                        }
                    }
                }
                None => None,
            }
        };

        crate::debug_log!("[MLS-CONTEXT] create_external_commit: Complete");
        Ok((commit_bytes, group_id, exported_group_info))
    }

    pub fn create_external_commit_with_psk(
        &mut self,
        group_info_bytes: &[u8],
        identity: &str,
        psk_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
        crate::debug_log!(
            "[MLS-CONTEXT] create_external_commit_with_psk: Starting for identity '{}'",
            identity
        );
        crate::debug_log!("[MLS-CONTEXT] PSK length: {} bytes", psk_bytes.len());

        // Note: OpenMLS 0.7.1's external commit mechanism with PSK requires using the new builder API
        // or manually creating PSK proposals. The deprecated join_by_external_commit doesn't support
        // PSK directly. For now, we'll create the PSK ID and store it for potential future use.
        //
        // A full implementation would require:
        // 1. Using MlsGroup::external_commit_builder() (the non-deprecated API)
        // 2. Adding a PSK proposal to the external commit
        // 3. Ensuring both joiner and existing members have the PSK stored
        //
        // For this initial implementation, we'll create the external commit normally
        // and document that PSK support requires the builder API (OpenMLS 0.7.1+).

        // 🔍 DIAGNOSTIC: Log GroupInfo details to debug InvalidVectorLength errors
        crate::info_log!("[MLS-CONTEXT] create_external_commit_with_psk: GroupInfo diagnostics:");
        crate::info_log!("   - Total bytes: {}", group_info_bytes.len());
        if group_info_bytes.len() >= 16 {
            crate::info_log!("   - First 16 bytes: {:02x?}", &group_info_bytes[..16]);
        } else {
            crate::info_log!("   - All bytes (truncated): {:02x?}", group_info_bytes);
        }
        if group_info_bytes.is_empty() {
            crate::error_log!("[MLS-CONTEXT] ❌ ERROR: GroupInfo is empty!");
            return Err(MLSError::invalid_input("GroupInfo is empty"));
        }

        // 🔍 DIAGNOSTIC: Check for suspiciously small GroupInfo
        if group_info_bytes.len() < 100 {
            crate::error_log!(
                "[MLS-CONTEXT] ⚠️ WARNING: GroupInfo suspiciously small: {} bytes",
                group_info_bytes.len()
            );
            crate::error_log!("[MLS-CONTEXT]    Valid GroupInfo typically >= 100 bytes");
            crate::error_log!("[MLS-CONTEXT]    Raw bytes: {:02x?}", group_info_bytes);
        }

        // 🔍 DIAGNOSTIC: Check for base64 encoding issues
        let is_ascii_only = group_info_bytes
            .iter()
            .all(|&b| (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D);
        if is_ascii_only && group_info_bytes.len() > 50 {
            crate::error_log!(
                "[MLS-CONTEXT] ❌ ERROR: GroupInfo appears to be base64-encoded text!"
            );
            crate::error_log!(
                "[MLS-CONTEXT]    All {} bytes are printable ASCII characters",
                group_info_bytes.len()
            );
            crate::error_log!(
                "[MLS-CONTEXT]    This suggests base64 decoding was skipped somewhere"
            );
            if let Ok(text_preview) =
                std::str::from_utf8(&group_info_bytes[..std::cmp::min(100, group_info_bytes.len())])
            {
                crate::error_log!("[MLS-CONTEXT]    First 100 chars: {}", text_preview);
            }
            return Err(MLSError::invalid_input(
                "GroupInfo appears to be base64-encoded - decoding may have been skipped",
            ));
        }

        // 1. Deserialize MlsMessageIn first (GroupInfo is wrapped in MLS message envelope)
        let (mls_message, _) =
            MlsMessageIn::tls_deserialize_bytes(group_info_bytes).map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] ❌ ERROR: MlsMessageIn deserialization failed!");
                crate::error_log!("[MLS-CONTEXT]    Error type: {:?}", e);
                crate::error_log!(
                    "[MLS-CONTEXT]    GroupInfo length: {} bytes",
                    group_info_bytes.len()
                );
                MLSError::invalid_input(format!(
                    "Invalid GroupInfo ({} bytes): {:?}",
                    group_info_bytes.len(),
                    e
                ))
            })?;

        // Extract the VerifiableGroupInfo from the MLS message body
        let verifiable_group_info = match mls_message.extract() {
            MlsMessageBodyIn::GroupInfo(vgi) => {
                crate::debug_log!(
                    "[MLS-CONTEXT] ✅ Successfully extracted VerifiableGroupInfo from MlsMessage"
                );
                vgi
            }
            _ => {
                crate::error_log!("[MLS-CONTEXT] ❌ ERROR: MlsMessage is not a GroupInfo!");
                return Err(MLSError::invalid_input(
                    "Expected MlsMessage containing GroupInfo",
                ));
            }
        };

        // 2. Create credential
        let credential = Credential::new(CredentialType::Basic, identity.as_bytes().to_vec());

        // 3. Get or create signature keys (reuse existing keys for this identity)
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
                    crate::error_log!(
                        "[MLS-CONTEXT] ERROR: Failed to create signature keys: {:?}",
                        e
                    );
                    MLSError::OpenMLS(format!(
                        "create_external_commit_with_psk: Failed to create signature keys: {:?}",
                        e
                    ))
                })?;

                new_keys.store(self.provider.storage()).map_err(|e| {
                    crate::error_log!(
                        "[MLS-CONTEXT] ERROR: Failed to store signature keys: {:?}",
                        e
                    );
                    MLSError::OpenMLS(format!(
                        "create_external_commit_with_psk: Failed to store signature keys: {:?}",
                        e
                    ))
                })?;
                crate::debug_log!("[MLS-CONTEXT] Signature keys generated and stored");

                (new_keys, true)
            }
        };

        // 4. Store PSK for later retrieval
        // Create a deterministic PSK ID based on the PSK bytes
        let psk_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(psk_bytes);
            hex::encode(hasher.finalize())
        };

        crate::debug_log!("[MLS-CONTEXT] PSK ID (hash): {}", psk_hash);

        // Store the PSK in manifest storage for later use
        // This allows the application to retrieve it when needed
        let mut psk_map: HashMap<String, Vec<u8>> = self
            .manifest_storage
            .read_manifest("psks")?
            .unwrap_or_else(HashMap::new);

        psk_map.insert(psk_hash.clone(), psk_bytes.to_vec());
        self.manifest_storage.write_manifest("psks", &psk_map)?;

        crate::debug_log!("[MLS-CONTEXT] PSK stored in manifest");

        // 5. Create join config
        let join_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();

        // 6. Create external commit with PSK using builder pattern
        let (group, commit_message_bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config)
            .build_group(
                &self.provider,
                verifiable_group_info,
                CredentialWithKey {
                    credential,
                    signature_key: signature_keys.public().into(),
                },
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder build_group failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!(
                    "external_commit_builder (with PSK) build_group failed: {:?}",
                    e
                ))
            })?
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(metadata_leaf_capabilities())
                    .build(),
            )
            .load_psks(self.provider.storage())
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder load_psks failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!(
                    "external_commit_builder (with PSK) load_psks failed: {:?}",
                    e
                ))
            })?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &signature_keys,
                |_| true, // accept all proposals
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder build failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!(
                    "external_commit_builder (with PSK) build failed: {:?}",
                    e
                ))
            })?
            .finalize(&self.provider)
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] ERROR: external_commit_builder finalize failed: {:?}",
                    e
                );
                MLSError::OpenMLS(format!(
                    "external_commit_builder (with PSK) finalize failed: {:?}",
                    e
                ))
            })?;

        let commit = commit_message_bundle.commit();

        // 7. Store group state
        let group_id = group.group_id().as_slice().to_vec();
        self.groups.insert(
            group_id.clone(),
            GroupState {
                group,
                signer_public_key: signature_keys.public().to_vec(),
            },
        );

        // Persist
        self.persist_group_id(&group_id).map_err(|e| {
            crate::error_log!("[MLS-CONTEXT] ⚠️ Failed to persist group ID: {:?}", e);
            MLSError::Internal(format!("Failed to persist group ID: {:?}", e))
        })?;

        // Only persist signer mapping if we created a new key
        if is_new_key {
            self.persist_signer_mapping(identity.as_bytes(), signature_keys.public())
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] ⚠️ Failed to persist signer mapping: {:?}", e);
                    MLSError::Internal(format!("Failed to persist signer mapping: {:?}", e))
                })?;
            crate::debug_log!("[MLS-CONTEXT] Persisted new signer mapping for identity");
        } else {
            crate::debug_log!(
                "[MLS-CONTEXT] Signer already registered for identity, not persisting"
            );
        }

        // Return commit bytes (to send to server) and group ID
        let commit_bytes = TlsSerialize::tls_serialize_detached(&commit)
            .map_err(|_| MLSError::SerializationError)?;

        crate::debug_log!("[MLS-CONTEXT] create_external_commit_with_psk: Complete");
        Ok((commit_bytes, group_id))
    }

    /// Discard a pending external join after server rejection.
    ///
    /// CRITICAL: Call this when the delivery service rejects an external commit.
    /// This cleans up:
    /// - The MlsGroup instance
    /// - Signature keypairs generated for the join
    /// - Manifest entries
    /// - Epoch secret storage
    ///
    /// # Arguments
    /// * `group_id` - Group identifier from the rejected external commit
    ///
    /// # Returns
    /// Ok(()) if cleanup succeeded, Err if group not found or cleanup failed
    pub fn discard_pending_external_join(&mut self, group_id: &[u8]) -> Result<(), MLSError> {
        crate::info_log!(
            "[MLS-CONTEXT] discard_pending_external_join: Cleaning up rejected join for group {}",
            hex::encode(group_id)
        );

        let gid = GroupId::from_slice(group_id);

        // 1. Get the group state to find associated signer
        let signer_public_key = self
            .groups
            .get(group_id)
            .map(|state| state.signer_public_key.clone());

        // 2. Remove from groups HashMap
        if self.groups.remove(group_id).is_none() {
            crate::warn_log!(
                "[MLS-CONTEXT] Group not found for discard: {}",
                hex::encode(group_id)
            );
            return Err(MLSError::group_not_found(hex::encode(group_id)));
        }

        // 3. Delete from OpenMLS storage
        // Manually delete group data since MlsGroup::delete is an instance method
        let storage = self.provider.storage_mut();

        // Best-effort deletion of all group components
        let _ = storage.delete_group_state(&gid);
        let _ = storage.delete_tree(&gid);
        let _ = storage.delete_confirmation_tag(&gid);
        let _ = storage.delete_interim_transcript_hash(&gid);
        let _ = storage.delete_context(&gid);
        let _ = storage.delete_message_secrets(&gid);
        let _ = storage.delete_all_resumption_psk_secrets(&gid);
        let _ = storage.delete_own_leaf_index(&gid);
        let _ = storage.delete_group_epoch_secrets(&gid);
        let _ = storage.delete_own_leaf_nodes(&gid);
        let _ = storage.delete_group_config(&gid);

        // 4. Remove from manifest
        let storage = &self.manifest_storage;
        if let Ok(Some(mut group_ids)) = storage.read_manifest::<Vec<String>>("group_ids") {
            let hex_id = hex::encode(group_id);
            group_ids.retain(|id| id != &hex_id);
            let _ = storage.write_manifest("group_ids", &group_ids);
        }

        // 5. Clean up signature keypair if it was newly created for this join
        // Note: Only delete if no other groups use this signer
        if let Some(pk) = signer_public_key {
            let other_groups_use_signer = self
                .groups
                .values()
                .any(|state| state.signer_public_key == pk);

            if !other_groups_use_signer {
                // Delete from storage
                if let Some(identity) = self
                    .signers_by_identity
                    .iter()
                    .find(|(_, v)| **v == pk)
                    .map(|(k, _)| k.clone())
                {
                    self.signers_by_identity.remove(&identity);
                    // Remove from manifest
                    if let Ok(Some(mut signers)) =
                        storage.read_manifest::<HashMap<String, String>>("signers")
                    {
                        signers.remove(&hex::encode(&identity));
                        let _ = storage.write_manifest("signers", &signers);
                    }
                }
            }
        }

        // 6. Flush to ensure cleanup is persisted
        self.flush_database()?;

        crate::info_log!("[MLS-CONTEXT] ✅ Successfully cleaned up rejected external join");
        Ok(())
    }

    pub fn create_group(
        &mut self,
        identity: &str,
        config: crate::types::GroupConfig,
    ) -> Result<CreateGroupInternalResult, MLSError> {
        crate::debug_log!(
            "[MLS-CONTEXT] create_group: Starting for identity '{}'",
            identity
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

        let mut group_config_builder = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .capabilities(capabilities) // Set required capabilities
            .use_ratchet_tree_extension(true); // CRITICAL: Include ratchet tree in Welcome messages

        let mut group_context_extensions = Extensions::<GroupContext>::empty();
        group_context_extensions
            .add(Extension::RequiredCapabilities(
                metadata_required_capabilities_extension(),
            ))
            .map_err(|e| {
                MLSError::Internal(format!(
                    "Failed to add required capabilities extension: {:?}",
                    e
                ))
            })?;
        group_context_extensions
            .add(Extension::AppDataDictionary(
                AppDataDictionaryExtension::default(),
            ))
            .map_err(|e| {
                MLSError::Internal(format!(
                    "Failed to add app data dictionary extension: {:?}",
                    e
                ))
            })?;

        if config.group_name.is_some() || config.group_description.is_some() {
            let metadata =
                GroupMetadata::new(config.group_name.clone(), config.group_description.clone());
            let metadata_bytes = metadata.to_extension_bytes().map_err(|e| {
                crate::error_log!(
                    "[MLS-CONTEXT] Failed to build group metadata extension: {:?}",
                    e
                );
                MLSError::Internal(format!("serialize metadata: {:?}", e))
            })?;
            group_context_extensions
                .add(Extension::Unknown(
                    CATBIRD_METADATA_EXTENSION_TYPE,
                    UnknownExtension(metadata_bytes),
                ))
                .map_err(|e| {
                    MLSError::Internal(format!("Failed to add metadata extension: {:?}", e))
                })?;
            crate::info_log!(
                "[MLS-CONTEXT] Group metadata set: name={:?}",
                config.group_name
            );
        }

        group_config_builder =
            group_config_builder.with_group_context_extensions(group_context_extensions);

        let group_config = group_config_builder.build();
        crate::debug_log!(
            "[MLS-CONTEXT] Group config built with ratchet tree extension capability"
        );

        crate::debug_log!("[MLS-CONTEXT] Creating MLS group...");
        let group = MlsGroup::new(
            &self.provider,
            &signature_keys,
            &group_config,
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
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
        crate::async_runtime::block_on(
            self.epoch_secret_manager
                .export_current_epoch_secret(&group, &self.provider),
        )
        .map_err(|e| {
            crate::error_log!("[MLS-CONTEXT] ❌ Failed to export epoch secret: {:?}", e);
            MLSError::StorageFailed
        })?;

        crate::debug_log!(
            "[MLS-CONTEXT] ✅ Exported epoch {} secret successfully",
            current_epoch
        );

        self.groups.insert(
            group_id.clone(),
            GroupState {
                group,
                signer_public_key: signature_keys.public().to_vec(),
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
            let group_state = self.groups.get(&group_id).ok_or_else(|| {
                MLSError::Internal("Group just created but not found in groups map".to_string())
            })?;
            let group_ref = &group_state.group;
            let epoch = group_ref.epoch().as_u64();

            match metadata::derive_metadata_key_from_group(
                group_ref,
                self.provider.crypto(),
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

    pub fn add_group(&mut self, group: MlsGroup, identity: &str) -> Result<(), MLSError> {
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

        let signer_pk = self
            .signers_by_identity
            .get(identity.as_bytes())
            .ok_or_else(|| {
                crate::error_log!("[ADD-GROUP] No signer found for identity: {}", identity);
                crate::error_log!(
                    "[ADD-GROUP]   Identity bytes (hex): {}",
                    hex::encode(identity.as_bytes())
                );
                MLSError::group_not_found(format!("No signer for identity: {}", identity))
            })?
            .clone();

        crate::debug_log!(
            "[ADD-GROUP] Found signer with public key: {}",
            hex::encode(&signer_pk)
        );

        // Verify the signer can be loaded from storage
        match SignatureKeyPair::read(
            self.provider.storage(),
            &signer_pk,
            SignatureScheme::ED25519,
        ) {
            Some(_) => {
                crate::debug_log!("[ADD-GROUP] Signer verified in storage");
            }
            None => {
                crate::error_log!(
                    "[ADD-GROUP] CRITICAL: Signer NOT found in storage! PK: {}",
                    hex::encode(&signer_pk)
                );
            }
        }

        let group_id = group.group_id().as_slice().to_vec();
        crate::debug_log!(
            "[ADD-GROUP] Storing group {} with signer PK: {}",
            hex::encode(&group_id),
            hex::encode(&signer_pk)
        );
        self.groups.insert(
            group_id.clone(),
            GroupState {
                group,
                signer_public_key: signer_pk,
            },
        );

        // Persist group ID to manifest
        self.persist_group_id(&group_id).map_err(|e| {
            crate::error_log!(
                "[MLS-CONTEXT] ⚠️ Failed to persist group ID in add_group: {:?}",
                e
            );
            MLSError::Internal(format!("Failed to persist group ID in add_group: {:?}", e))
        })?;

        Ok(())
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
                return Ok(()); // No need to re-register the same key
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

        self.signers_by_identity
            .insert(identity.as_bytes().to_vec(), signer_public_key.clone());
        crate::debug_log!("[MLS-CONTEXT] Registered signer for identity: {}", identity);

        // Persist signer mapping to manifest
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

        Ok(())
    }

    /// Get persistent signature keypair for an identity if it exists
    /// Returns None if no signer has been registered for this identity yet
    pub fn get_signer_for_identity(&self, identity: &str) -> Option<SignatureKeyPair> {
        // Look up public key bytes for this identity
        let public_key_bytes = self.signers_by_identity.get(identity.as_bytes())?;

        // Load the full keypair from storage using the public key
        SignatureKeyPair::read(
            self.provider.storage(),
            public_key_bytes,
            SignatureScheme::ED25519,
        )
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

    /// Delete a group from the context, cleaning up all persistent storage.
    /// Returns true if the group was found and removed, false otherwise.
    pub fn delete_group(&mut self, group_id: &[u8]) -> bool {
        let existed = self.groups.remove(group_id).is_some();
        if !existed {
            return false;
        }

        // Remove from OpenMLS storage (best-effort, matching discard_pending_external_join)
        let gid = GroupId::from_slice(group_id);
        let storage = self.provider.storage_mut();
        let _ = storage.delete_group_state(&gid);
        let _ = storage.delete_tree(&gid);
        let _ = storage.delete_confirmation_tag(&gid);
        let _ = storage.delete_interim_transcript_hash(&gid);
        let _ = storage.delete_context(&gid);
        let _ = storage.delete_message_secrets(&gid);
        let _ = storage.delete_all_resumption_psk_secrets(&gid);
        let _ = storage.delete_own_leaf_index(&gid);
        let _ = storage.delete_group_epoch_secrets(&gid);
        let _ = storage.delete_own_leaf_nodes(&gid);
        let _ = storage.delete_group_config(&gid);

        // Remove from manifest
        let hex_id = hex::encode(group_id);
        if let Ok(Some(mut group_ids)) = self
            .manifest_storage
            .read_manifest::<Vec<String>>("group_ids")
        {
            group_ids.retain(|id| id != &hex_id);
            let _ = self
                .manifest_storage
                .write_manifest("group_ids", &group_ids);
        }

        // Flush to ensure cleanup is persisted
        let _ = self.flush_database();

        true
    }

    /// Read group metadata from the MLS group context extensions (plaintext).
    /// Encrypted metadata is now handled by the metadata module via server-side blobs.
    pub fn get_group_metadata(&self, group_id: &[u8]) -> Result<Option<GroupMetadata>, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group_ref(&gid, |group, _provider| {
            Ok(crate::group_metadata::GroupMetadata::from_group(group))
        })
    }

    /// Update group metadata by proposing + committing a GroupContextExtensions change.
    /// Stores plaintext metadata in the 0xff00 extension. Encrypted metadata is now
    /// handled separately by the metadata module via server-side blobs.
    /// Returns the commit message bytes that must be sent to the server.
    pub fn update_group_metadata(
        &mut self,
        group_id: &[u8],
        metadata: GroupMetadata,
    ) -> Result<Vec<u8>, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            let metadata_bytes = metadata
                .to_extension_bytes()
                .map_err(|e| MLSError::Internal(format!("serialize metadata: {}", e)))?;

            // Clone existing extensions and add/replace the metadata extension.
            // update_group_context_extensions replaces ALL extensions, so we must
            // preserve any existing ones (e.g. RequiredCapabilities).
            let mut extensions = group.extensions().clone();

            // Read existing RequiredCapabilities and merge our extension type
            let existing_rc = extensions.required_capabilities().cloned();
            let mut ext_types: Vec<ExtensionType> = existing_rc
                .as_ref()
                .map(|rc| rc.extension_types().to_vec())
                .unwrap_or_default();
            if !ext_types.contains(&ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE)) {
                ext_types.push(ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE));
            }
            if !ext_types.contains(&ExtensionType::AppDataDictionary) {
                ext_types.push(ExtensionType::AppDataDictionary);
            }
            // Ensure RatchetTree is always present
            if !ext_types.contains(&ExtensionType::RatchetTree) {
                ext_types.push(ExtensionType::RatchetTree);
            }

            let mut proposal_types = existing_rc
                .as_ref()
                .map(|rc| rc.proposal_types().to_vec())
                .unwrap_or_default();
            if !proposal_types.contains(&ProposalType::AppDataUpdate) {
                proposal_types.push(ProposalType::AppDataUpdate);
            }
            let credential_types = existing_rc
                .as_ref()
                .map(|rc| rc.credential_types().to_vec())
                .unwrap_or_default();

            extensions
                .add_or_replace(Extension::RequiredCapabilities(
                    RequiredCapabilitiesExtension::new(
                        &ext_types,
                        &proposal_types,
                        &credential_types,
                    ),
                ))
                .map_err(|e| {
                    MLSError::Internal(format!(
                        "Failed to add required capabilities extension: {:?}",
                        e
                    ))
                })?;

            extensions
                .add_or_replace(Extension::Unknown(
                    CATBIRD_METADATA_EXTENSION_TYPE,
                    UnknownExtension(metadata_bytes),
                ))
                .map_err(|e| {
                    MLSError::Internal(format!("Failed to add metadata extension: {:?}", e))
                })?;

            let planned_reference_json = metadata::planned_metadata_reference_json(
                metadata::current_metadata_reference(group).as_ref(),
                crate::group_metadata::GroupMetadata::from_group(group).is_some(),
                true,
            )
            .map_err(|e| MLSError::Internal(format!("plan metadata reference: {:?}", e)))?;

            let mut commit_builder = group
                .commit_builder()
                .propose_group_context_extensions(extensions)
                .map_err(|e| {
                    crate::error_log!(
                        "[MLS-CONTEXT] Failed to propose group context extensions: {:?}",
                        e
                    );
                    MLSError::OpenMLS(format!("propose_group_context_extensions: {:?}", e))
                })?;

            if let Some(ref_json) = planned_reference_json.clone() {
                commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        metadata::METADATA_REFERENCE_COMPONENT_ID,
                        ref_json,
                    ),
                )));
            }

            let mut commit_stage = commit_builder.load_psks(provider.storage()).map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] Failed to load PSKs: {:?}", e);
                MLSError::OpenMLS(format!("load_psks: {:?}", e))
            })?;

            if let Some(ref_json) = planned_reference_json {
                let mut updater = commit_stage.app_data_dictionary_updater();
                updater.set(ComponentData::from_parts(
                    metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.into(),
                ));
                commit_stage.with_app_data_dictionary_updates(updater.changes());
            }

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

    /// Find leaf index for a member by credential identity (DID bytes)
    /// Returns None if member not found in group
    fn find_member_index(group: &MlsGroup, identity: &[u8]) -> Option<LeafNodeIndex> {
        for member in group.members() {
            let credential = member.credential.serialized_content();
            if credential == identity {
                return Some(member.index);
            }
        }
        None
    }

    /// Remove members from the group (internal implementation)
    ///
    /// Creates a commit with Remove proposals. Follows send-then-merge pattern:
    /// caller must send commit to server and call merge_pending_commit() after ACK.
    pub fn remove_members_internal(
        &mut self,
        group_id: &[u8],
        member_identities: &[Vec<u8>],
    ) -> Result<Vec<u8>, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            // 1. Convert identities to leaf indices
            let mut indices_to_remove = Vec::new();
            for identity in member_identities {
                match Self::find_member_index(group, identity) {
                    Some(index) => {
                        crate::debug_log!(
                            "[MLS-CONTEXT] Found member to remove: {} at index {}",
                            hex::encode(identity),
                            index.u32()
                        );
                        indices_to_remove.push(index);
                    }
                    None => {
                        crate::warn_log!(
                            "[MLS-CONTEXT] Member not found (may already be removed): {}",
                            hex::encode(identity)
                        );
                        // Continue - ignore not found (already removed)
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

            let planned_reference_json = metadata::planned_metadata_reference_json(
                metadata::current_metadata_reference(group).as_ref(),
                metadata::metadata_payload_from_group(group).is_some(),
                false,
            )
            .map_err(|e| MLSError::Internal(format!("plan metadata reference: {:?}", e)))?;

            let mut commit_builder = group.commit_builder().propose_removals(indices_to_remove);
            if let Some(ref_json) = planned_reference_json.clone() {
                commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        metadata::METADATA_REFERENCE_COMPONENT_ID,
                        ref_json,
                    ),
                )));
            }

            let mut commit_stage = commit_builder.load_psks(provider.storage()).map_err(|e| {
                crate::error_log!("[MLS-CONTEXT] remove_members load_psks failed: {:?}", e);
                MLSError::OpenMLS(format!("remove_members load_psks failed: {:?}", e))
            })?;

            if let Some(ref_json) = planned_reference_json {
                let mut updater = commit_stage.app_data_dictionary_updater();
                updater.set(ComponentData::from_parts(
                    metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.into(),
                ));
                commit_stage.with_app_data_dictionary_updates(updater.changes());
            }

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

            let (commit, welcome_option, _group_info) = commit_bundle.into_contents();

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

            crate::info_log!(
                "[MLS-CONTEXT] ✅ Remove commit created, size: {} bytes",
                commit_bytes.len()
            );

            Ok(commit_bytes)
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
            let (kp_in, _) =
                KeyPackageIn::tls_deserialize_bytes(key_package_data).map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] Failed to deserialize key package: {:?}", e);
                    MLSError::SerializationError
                })?;

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
            // Find member index
            let member_index =
                Self::find_member_index(group, member_identity).ok_or_else(|| {
                    crate::error_log!(
                        "[MLS-CONTEXT] Member not found: {}",
                        hex::encode(member_identity)
                    );
                    MLSError::member_not_found(String::from_utf8_lossy(member_identity).to_string())
                })?;

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

        self.with_group_ref(&gid, |group, provider| {
            let details: Vec<crate::types::PendingProposalDetail> = group
                .pending_proposals()
                .filter_map(|queued_proposal| {
                    let proposal = queued_proposal.proposal();

                    // Compute proposal reference
                    let proposal_bytes = proposal.tls_serialize_detached().ok()?;
                    let proposal_ref = provider
                        .crypto()
                        .hash(group.ciphersuite().hash_algorithm(), &proposal_bytes)
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
