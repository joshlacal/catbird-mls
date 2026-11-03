//! Native `rusqlite` + SQLCipher 4 storage driver (`Spec §6.1`, `I7`, `I8`, `I9`).
//!
//! Enforces:
//! - `I8`: 96-hex raw key+HKDF salt (`PRAGMA key = "x'<64-hex><32-hex>'";`)
//!   followed by `PRAGMA cipher_plaintext_header_size = 32;` and
//!   `PRAGMA journal_mode = WAL;` in exact order.
//! - `I7`: `last_reconciled_data_version` checked ONLY inside `BEGIN IMMEDIATE`
//!   (never mutated by `read_tx` paged `SELECT`s) so cross-process NSE commits
//!   always evict stale in-memory `MlsGroup` caches.
//! - `I9`: `prepare_for_background()` stops admissions, sets `busy_timeout = 0`,
//!   runs `PRAGMA wal_checkpoint(PASSIVE)`, and closes the SQLite connection
//!   synchronously (`< 50 ms`, zero open file descriptors).

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hkdf::Hkdf;
use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::MLSError;
use crate::keychain::KeychainAccess;
use crate::types::EpochSecretStorage;

use super::openmls_kv::{KvBackend, OpenMlsKvError, OpenMlsKvProvider, OpenMlsKvStorage};
use super::queries::{
    ConversationRow, GroupMetadataRow, LabyrinthQueueRow, MessageRow, MutationJournalRow,
    RequestRow, RoutingCacheRow,
};
use super::schema::{UNIFIED_SCHEMA_DDL, UNIFIED_SCHEMA_TABLES};

const SQLCIPHER_SALT_HKDF_INFO: &[u8] = b"catbird-mls-sqlcipher-salt-v1";
const APP_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const EXTENSION_BUSY_TIMEOUT: Duration = Duration::from_millis(1500);

/// Execution profile for opening a per-account SQLCipher database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Foreground / desktop / CLI mode (`WAL`, normal page cache, 5s busy timeout).
    App,
    /// iOS NSE / push-extension mode (`cache_size = -512`, `mmap_size = 0`, 1.5s busy timeout).
    PushExtension,
}

/// Telemetry returned by [`MlsAccountDb::prepare_for_background`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct BackgroundCheckpointReport {
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
    pub handle_closed: bool,
}

/// Derive the canonical 96-hex SQLCipher raw key + HKDF salt literal (`I8`):
/// `x'<64-hex key><32-hex HKDF salt>'` (99 ASCII bytes total).
pub fn derive_sqlcipher_96hex_key_spec(db_key_32: &[u8; 32]) -> String {
    let hk = Hkdf::<Sha256>::new(Some(b""), db_key_32);
    let mut salt_16 = [0u8; 16];
    hk.expand(SQLCIPHER_SALT_HKDF_INFO, &mut salt_16)
        .expect("16-byte HKDF-SHA256 output is valid");
    format!("x'{}{}'", hex::encode(db_key_32), hex::encode(salt_16))
}

/// Normalize a caller-provided key string into a 32-byte key (`[u8; 32]`):
/// - If `raw` is 64 ASCII hex characters, decodes the 32 bytes directly.
/// - Otherwise derives `SHA-256(raw.as_bytes())`.
pub fn derive_db_key_32_from_str(raw: &str) -> [u8; 32] {
    if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(decoded) = hex::decode(raw) {
            if let Ok(arr) = <[u8; 32]>::try_from(decoded.as_slice()) {
                return arr;
            }
        }
    }
    Sha256::digest(raw.as_bytes()).into()
}

pub(crate) fn map_rusqlite_err(context: &str, err: &rusqlite::Error) -> MLSError {
    match err {
        rusqlite::Error::SqliteFailure(ffi_err, detail) => {
            let msg = detail.as_deref().unwrap_or("");
            match ffi_err.code {
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                    MLSError::ThreadSafety(format!("{context}: SQLITE_BUSY/LOCKED {msg}"))
                }
                ErrorCode::NotADatabase => MLSError::invalid_input(format!(
                    "{context}: SQLITE_NOTADB (wrong key or corrupt header) {msg}"
                )),
                ErrorCode::ApiMisuse => {
                    MLSError::Internal(format!("{context}: SQLITE_MISUSE {msg}"))
                }
                ErrorCode::OutOfMemory => {
                    MLSError::Internal(format!("{context}: SQLITE_NOMEM {msg}"))
                }
                _ => {
                    MLSError::invalid_input(format!("{context}: sqlite failure {ffi_err:?} {msg}"))
                }
            }
        }
        _ => MLSError::invalid_input(format!("{context}: sqlite error {err}")),
    }
}

fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn open_sqlite_connection(path: &Path) -> Result<Connection, rusqlite::Error> {
    #[cfg(feature = "sim")]
    if let Some(vfs_name) = crate::sim_hooks::sim_sqlite_vfs_name() {
        return Connection::open_with_flags_and_vfs(path, rusqlite::OpenFlags::default(), vfs_name);
    }
    Connection::open(path)
}

fn open_configured_connection(
    path: &Path,
    db_key_32: &[u8; 32],
    mode: OpenMode,
) -> Result<(Connection, i64), MLSError> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    MLSError::invalid_input(format!(
                        "failed to create DB parent dir {parent:?}: {e}"
                    ))
                })?;
            }
        }
    }

    let conn =
        open_sqlite_connection(path).map_err(|e| map_rusqlite_err("Connection::open", &e))?;

    let key_spec = Zeroizing::new(derive_sqlcipher_96hex_key_spec(db_key_32));

    // Exact pragma order mandated by Spec §6.1 / I8:
    // 1. PRAGMA key = "x'<64-hex><32-hex>'";
    // 2. PRAGMA cipher_plaintext_header_size = 32;
    // 3. PRAGMA journal_mode = WAL;
    conn.execute_batch(&format!(
        "PRAGMA cipher_memory_security = OFF;\n\
         PRAGMA key = \"{}\";\n\
         PRAGMA cipher_plaintext_header_size = 32;\n\
         PRAGMA journal_mode = WAL;",
        key_spec.as_str()
    ))
    .map_err(|e| map_rusqlite_err("SQLCipher key+WAL init", &e))?;

    match mode {
        OpenMode::App => {
            conn.execute_batch("PRAGMA synchronous = NORMAL;")
                .map_err(|e| map_rusqlite_err("App pragmas", &e))?;
            conn.busy_timeout(APP_BUSY_TIMEOUT)
                .map_err(|e| map_rusqlite_err("App busy_timeout", &e))?;
        }
        OpenMode::PushExtension => {
            conn.execute_batch(
                "PRAGMA cache_size = -512;\n\
                 PRAGMA mmap_size = 0;\n\
                 PRAGMA synchronous = NORMAL;",
            )
            .map_err(|e| map_rusqlite_err("PushExtension pragmas", &e))?;
            conn.busy_timeout(EXTENSION_BUSY_TIMEOUT)
                .map_err(|e| map_rusqlite_err("PushExtension busy_timeout", &e))?;
        }
    }

    // Read-only key verification & schema presence check:
    // Fails immediately with SQLITE_NOTADB on wrong key without issuing writes on already-initialized DBs.
    let existing_unified_tables: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (\
                'openmls_kv','account_meta','conversations','messages','requests',\
                'participant_profiles','group_metadata_cache','epoch_secrets',\
                'sequencer_receipts','recovery_state','pending_ops','mutation_journal',\
                'routing_cache','labyrinth_state','labyrinth_queue'\
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|e| map_rusqlite_err("sqlite_master schema check", &e))?;

    if existing_unified_tables < UNIFIED_SCHEMA_TABLES.len() {
        conn.execute_batch(UNIFIED_SCHEMA_DDL)
            .map_err(|e| map_rusqlite_err("UNIFIED_SCHEMA_DDL", &e))?;
    }

    let initial_dv: i64 = conn
        .query_row("PRAGMA data_version;", [], |row| row.get(0))
        .map_err(|e| map_rusqlite_err("initial PRAGMA data_version", &e))?;

    Ok((conn, initial_dv))
}

struct AccountDbConnState {
    conn: Option<Connection>,
    last_reconciled_data_version: i64,
}

/// Single-connection per-account encrypted SQLite database (`Spec §6.1`).
pub struct MlsAccountDb {
    path: PathBuf,
    db_key_32: Zeroizing<[u8; 32]>,
    mode: OpenMode,
    suspended: AtomicBool,
    conn_open: AtomicBool,
    conn_in_tx: AtomicBool,
    write_tx_active: AtomicBool,
    state: Mutex<AccountDbConnState>,
    eviction_hooks: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
    keychain: Mutex<Option<Arc<dyn KeychainAccess>>>,
}

/// Alias used by deterministic simulation (`catbird-sim`) and `I6` autocommit probes.
pub type SqlDriver = MlsAccountDb;

impl MlsAccountDb {
    /// Open or create `<did_hash>.db` using SQLCipher 4 96-hex raw key+HKDF salt (`I8`).
    pub fn open_native(
        path: impl AsRef<Path>,
        db_key_32: &[u8; 32],
        mode: OpenMode,
    ) -> Result<Self, MLSError> {
        let path_buf = path.as_ref().to_path_buf();
        let (conn, initial_dv) = open_configured_connection(&path_buf, db_key_32, mode)?;
        Ok(Self {
            path: path_buf,
            db_key_32: Zeroizing::new(*db_key_32),
            mode,
            suspended: AtomicBool::new(false),
            conn_open: AtomicBool::new(true),
            conn_in_tx: AtomicBool::new(false),
            write_tx_active: AtomicBool::new(false),
            state: Mutex::new(AccountDbConnState {
                conn: Some(conn),
                last_reconciled_data_version: initial_dv,
            }),
            eviction_hooks: Mutex::new(Vec::new()),
            keychain: Mutex::new(None),
        })
    }

    /// Open an isolated in-memory SQLCipher database with the unified schema initialized.
    ///
    /// Intended for fast, deterministic unit and pressure-tank (`I6`) tests without
    /// filesystem setup.
    pub fn open_in_memory_for_test() -> Result<Self, MLSError> {
        let db_key_32 = [0x42u8; 32];
        let conn = Connection::open_in_memory()
            .map_err(|e| map_rusqlite_err("Connection::open_in_memory", &e))?;
        let key_spec = Zeroizing::new(derive_sqlcipher_96hex_key_spec(&db_key_32));
        conn.execute_batch(&format!(
            "PRAGMA cipher_memory_security = OFF;\n\
             PRAGMA key = \"{}\";\n\
             PRAGMA synchronous = NORMAL;",
            key_spec.as_str()
        ))
        .map_err(|e| map_rusqlite_err("open_in_memory_for_test SQLCipher init", &e))?;
        conn.execute_batch(UNIFIED_SCHEMA_DDL)
            .map_err(|e| map_rusqlite_err("open_in_memory_for_test UNIFIED_SCHEMA_DDL", &e))?;
        let initial_dv: i64 = conn
            .query_row("PRAGMA data_version;", [], |row| row.get(0))
            .map_err(|e| map_rusqlite_err("open_in_memory_for_test data_version", &e))?;
        Ok(Self {
            path: PathBuf::from(":memory:"),
            db_key_32: Zeroizing::new(db_key_32),
            mode: OpenMode::App,
            suspended: AtomicBool::new(false),
            conn_open: AtomicBool::new(true),
            conn_in_tx: AtomicBool::new(false),
            write_tx_active: AtomicBool::new(false),
            state: Mutex::new(AccountDbConnState {
                conn: Some(conn),
                last_reconciled_data_version: initial_dv,
            }),
            eviction_hooks: Mutex::new(Vec::new()),
            keychain: Mutex::new(None),
        })
    }

    /// Attach a platform `KeychainAccess` so `SignatureKeyPair` reads/writes route through Keychain.
    pub fn set_keychain(&self, keychain: Arc<dyn KeychainAccess>) {
        if let Ok(mut guard) = self.keychain.lock() {
            *guard = Some(keychain);
        }
    }

    pub fn keychain(&self) -> Option<Arc<dyn KeychainAccess>> {
        self.keychain.lock().ok().and_then(|g| g.clone())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    /// Register a callback invoked inside `BEGIN IMMEDIATE` whenever `PRAGMA data_version`
    /// has advanced relative to `last_reconciled_data_version` (`I7`).
    pub fn register_cache_eviction_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        if let Ok(mut hooks) = self.eviction_hooks.lock() {
            hooks.push(hook);
        }
    }

    fn fire_eviction_hooks(&self) {
        let hooks: Vec<Arc<dyn Fn() + Send + Sync>> = self
            .eviction_hooks
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        for hook in hooks {
            hook();
        }
    }

    /// Returns `true` when the database handle is open and accepting admissions.
    /// Lock-free (`AtomicBool`) so `@MainActor` handle checks never contend on `self.state`.
    pub fn is_open(&self) -> bool {
        !self.suspended.load(Ordering::SeqCst) && self.conn_open.load(Ordering::SeqCst)
    }

    /// Returns `true` when the underlying SQLite connection is currently inside an active
    /// transaction (`!conn.is_autocommit()`), using safe `rusqlite::Connection::is_autocommit()`
    /// exclusively (zero `unsafe`).
    ///
    /// Safe to call both from outside a transaction (e.g. inside `PlatformTransport::execute_http`
    /// to assert `I6`) and re-entrantly from inside `read_tx` / `write_tx` on the same thread.
    pub fn is_in_transaction(&self) -> bool {
        if !self.is_open() {
            return false;
        }
        match self.state.try_lock() {
            Ok(guard) => guard
                .conn
                .as_ref()
                .is_some_and(|conn| !conn.is_autocommit()),
            Err(std::sync::TryLockError::WouldBlock) => self.conn_in_tx.load(Ordering::SeqCst),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned
                .into_inner()
                .conn
                .as_ref()
                .is_some_and(|conn| !conn.is_autocommit()),
        }
    }

    /// Returns `true` when the database is currently inside an active `BEGIN IMMEDIATE`
    /// write transaction (`write_tx`).
    pub fn is_in_write_transaction(&self) -> bool {
        self.is_open() && self.write_tx_active.load(Ordering::SeqCst) && self.is_in_transaction()
    }

    /// Build a cloneable [`crate::sim_hooks::TxAutocommitProbe`] bound to this database handle
    /// so `PlatformTransport::execute_http` implementations can assert `I6` (`!probe.is_in_transaction()`).
    pub fn autocommit_probe(self: &Arc<Self>) -> crate::sim_hooks::TxAutocommitProbe {
        let weak = Arc::downgrade(self);
        crate::sim_hooks::TxAutocommitProbe::new(Arc::new(move || {
            weak.upgrade().is_some_and(|db| db.is_in_transaction())
        }))
    }

    /// Obtain a SQLite interrupt handle if the connection is currently open.
    pub fn get_interrupt_handle(&self) -> Option<rusqlite::InterruptHandle> {
        self.state
            .lock()
            .ok()
            .and_then(|g| g.conn.as_ref().map(Connection::get_interrupt_handle))
    }

    /// Execute a read-only snapshot without updating `last_reconciled_data_version` (`I7`).
    pub fn read_tx<T>(
        &self,
        f: impl FnOnce(&SqlReadTx<'_>) -> Result<T, MLSError>,
    ) -> Result<T, MLSError> {
        if self.suspended.load(Ordering::SeqCst) {
            return Err(MLSError::ContextClosed);
        }
        let keychain = self.keychain();
        let guard = self
            .state
            .lock()
            .map_err(|_| MLSError::lock_poisoned("MlsAccountDb.state"))?;
        let conn = guard.conn.as_ref().ok_or(MLSError::ContextClosed)?;

        conn.execute_batch("BEGIN DEFERRED;")
            .map_err(|e| map_rusqlite_err("read_tx BEGIN DEFERRED", &e))?;
        self.conn_in_tx
            .store(!conn.is_autocommit(), Ordering::SeqCst);
        struct EndRead<'a> {
            conn: &'a Connection,
            conn_in_tx: &'a AtomicBool,
        }
        impl Drop for EndRead<'_> {
            fn drop(&mut self) {
                if !self.conn.is_autocommit() {
                    let _ = self.conn.execute_batch("ROLLBACK;");
                }
                self.conn_in_tx
                    .store(!self.conn.is_autocommit(), Ordering::SeqCst);
            }
        }
        let end_guard = EndRead {
            conn,
            conn_in_tx: &self.conn_in_tx,
        };
        let rx = SqlReadTx { conn, keychain };
        let out = f(&rx)?;
        conn.execute_batch("COMMIT;")
            .map_err(|e| map_rusqlite_err("read_tx COMMIT", &e))?;
        self.conn_in_tx
            .store(!conn.is_autocommit(), Ordering::SeqCst);
        std::mem::forget(end_guard);
        Ok(out)
    }

    /// Execute an atomic `BEGIN IMMEDIATE` write transaction enforcing `I7`
    /// (`last_reconciled_data_version` check + cache eviction BEFORE running `f`).
    pub fn write_tx<T>(
        &self,
        f: impl FnOnce(&SqlTx<'_>) -> Result<T, MLSError>,
    ) -> Result<T, MLSError> {
        if self.suspended.load(Ordering::SeqCst) {
            return Err(MLSError::ContextClosed);
        }
        let keychain = self.keychain();
        let mut guard = self
            .state
            .lock()
            .map_err(|_| MLSError::lock_poisoned("MlsAccountDb.state"))?;
        if self.suspended.load(Ordering::SeqCst) || guard.conn.is_none() {
            return Err(MLSError::ContextClosed);
        }

        let current_dv = {
            let conn = guard.conn.as_ref().ok_or(MLSError::ContextClosed)?;
            conn.execute_batch("BEGIN IMMEDIATE;")
                .map_err(|e| map_rusqlite_err("write_tx BEGIN IMMEDIATE", &e))?;
            self.conn_in_tx
                .store(!conn.is_autocommit(), Ordering::SeqCst);
            self.write_tx_active.store(true, Ordering::SeqCst);
            match conn.query_row("PRAGMA data_version;", [], |r| r.get::<_, i64>(0)) {
                Ok(dv) => dv,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    self.conn_in_tx
                        .store(!conn.is_autocommit(), Ordering::SeqCst);
                    self.write_tx_active.store(false, Ordering::SeqCst);
                    return Err(map_rusqlite_err("write_tx PRAGMA data_version", &e));
                }
            }
        };

        if current_dv != guard.last_reconciled_data_version
            && !crate::planted::is_planted_bug_active(
                crate::planted::PlantedBug::P10SkipDataVersionCheckAfterNseAdvance,
            )
        {
            self.fire_eviction_hooks();
        }

        let result = {
            let conn = guard.conn.as_ref().ok_or(MLSError::ContextClosed)?;
            struct UnwindWrite<'a> {
                conn: &'a Connection,
                conn_in_tx: &'a AtomicBool,
                write_tx_active: &'a AtomicBool,
                disarmed: bool,
            }
            impl Drop for UnwindWrite<'_> {
                fn drop(&mut self) {
                    if !self.disarmed {
                        if !self.conn.is_autocommit() {
                            let _ = self.conn.execute_batch("ROLLBACK;");
                        }
                        self.conn_in_tx
                            .store(!self.conn.is_autocommit(), Ordering::SeqCst);
                        self.write_tx_active.store(false, Ordering::SeqCst);
                    }
                }
            }
            let mut unwind_guard = UnwindWrite {
                conn,
                conn_in_tx: &self.conn_in_tx,
                write_tx_active: &self.write_tx_active,
                disarmed: false,
            };
            let tx = SqlTx {
                read: SqlReadTx { conn, keychain },
            };
            let res = f(&tx);
            unwind_guard.disarmed = true;
            res
        };

        match result {
            Ok(val) => {
                let post_dv = {
                    let conn = guard.conn.as_ref().ok_or(MLSError::ContextClosed)?;
                    if let Err(e) = conn.execute_batch("COMMIT;") {
                        let _ = conn.execute_batch("ROLLBACK;");
                        self.conn_in_tx
                            .store(!conn.is_autocommit(), Ordering::SeqCst);
                        self.write_tx_active.store(false, Ordering::SeqCst);
                        guard.last_reconciled_data_version = 0;
                        self.fire_eviction_hooks();
                        return Err(map_rusqlite_err("write_tx COMMIT", &e));
                    }
                    self.conn_in_tx
                        .store(!conn.is_autocommit(), Ordering::SeqCst);
                    self.write_tx_active.store(false, Ordering::SeqCst);
                    conn.query_row("PRAGMA data_version;", [], |r| r.get::<_, i64>(0))
                        .unwrap_or(current_dv)
                };
                guard.last_reconciled_data_version = post_dv;
                Ok(val)
            }
            Err(err) => {
                if let Some(conn) = guard.conn.as_ref() {
                    let _ = conn.execute_batch("ROLLBACK;");
                    self.conn_in_tx
                        .store(!conn.is_autocommit(), Ordering::SeqCst);
                } else {
                    self.conn_in_tx.store(false, Ordering::SeqCst);
                }
                self.write_tx_active.store(false, Ordering::SeqCst);
                guard.last_reconciled_data_version = 0;
                self.fire_eviction_hooks();
                Err(err)
            }
        }
    }

    /// Low-level direct connection access used internally by `MLSContext` / `ManifestStorage`.
    /// Rejects calls when backgrounded (`I9`) and never mutates `last_reconciled_data_version`
    /// outside `BEGIN IMMEDIATE` (`I7`).
    pub(crate) fn with_raw_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, MLSError>,
    ) -> Result<T, MLSError> {
        if self.suspended.load(Ordering::SeqCst) {
            return Err(MLSError::ContextClosed);
        }
        let guard = self
            .state
            .lock()
            .map_err(|_| MLSError::lock_poisoned("MlsAccountDb.state"))?;
        let conn = guard.conn.as_ref().ok_or(MLSError::ContextClosed)?;
        f(conn)
    }

    /// Reconcile `PRAGMA data_version` under `BEGIN IMMEDIATE` (`I7`) before `MLSContext`
    /// touches its in-memory `MlsGroup` cache. Returns `true` if external commits occurred.
    pub(crate) fn reconcile_before_group_op(&self) -> Result<bool, MLSError> {
        let mut evicted = false;
        self.write_tx(|_tx| {
            let _ = &mut evicted;
            Ok(())
        })?;
        Ok(evicted)
    }

    /// Non-blocking suspend path (`I9` — eliminates iOS `0xdead10cc` kills):
    /// 1. Stop new admissions (`suspended = true`).
    /// 2. Set `busy_timeout = 0`.
    /// 3. Run `PRAGMA wal_checkpoint(PASSIVE)` (never `TRUNCATE` or `RESTART`).
    /// 4. Flush statement cache and close the SQLite handle synchronously so zero FDs remain.
    pub fn prepare_for_background(&self) -> Result<BackgroundCheckpointReport, MLSError> {
        self.suspended.store(true, Ordering::SeqCst);
        let mut guard = self
            .state
            .lock()
            .map_err(|_| MLSError::lock_poisoned("MlsAccountDb.state"))?;
        guard.last_reconciled_data_version = 0;

        let Some(conn) = guard.conn.take() else {
            self.conn_in_tx.store(false, Ordering::SeqCst);
            self.write_tx_active.store(false, Ordering::SeqCst);
            self.conn_open.store(false, Ordering::SeqCst);
            drop(guard);
            self.fire_eviction_hooks();
            return Ok(BackgroundCheckpointReport {
                busy: 0,
                log_frames: 0,
                checkpointed_frames: 0,
                handle_closed: true,
            });
        };

        let _ = conn.busy_timeout(Duration::ZERO);
        let (busy, log_frames, checkpointed_frames) =
            if crate::buggify!("before_wal_passive_checkpoint") {
                (1, 0, 0)
            } else {
                conn.query_row("PRAGMA main.wal_checkpoint(PASSIVE);", [], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap_or((1, 0, 0))
            };

        conn.flush_prepared_statement_cache();
        match conn.close() {
            Ok(()) => {}
            Err((leaked_conn, _)) => drop(leaked_conn),
        }
        self.conn_in_tx.store(false, Ordering::SeqCst);
        self.write_tx_active.store(false, Ordering::SeqCst);
        self.conn_open.store(false, Ordering::SeqCst);

        drop(guard);
        self.fire_eviction_hooks();

        Ok(BackgroundCheckpointReport {
            busy,
            log_frames,
            checkpointed_frames,
            handle_closed: true,
        })
    }

    /// Reopen `<did_hash>.db` on foreground resume after [`Self::prepare_for_background`].
    pub fn resume_from_background(&self) -> Result<(), MLSError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| MLSError::lock_poisoned("MlsAccountDb.state"))?;
        if guard.conn.is_none() {
            let (conn, _dv) = open_configured_connection(&self.path, &self.db_key_32, self.mode)?;
            guard.conn = Some(conn);
            // Force first post-resume write_tx to reconcile against any NSE writes made while closed.
            guard.last_reconciled_data_version = 0;
        }
        self.conn_open.store(true, Ordering::SeqCst);
        self.suspended.store(false, Ordering::SeqCst);
        drop(guard);
        self.fire_eviction_hooks();
        Ok(())
    }

    /// Non-blocking passive checkpoint for foreground durability checks.
    pub fn passive_checkpoint(&self) -> Result<(), MLSError> {
        if crate::buggify!("before_wal_passive_checkpoint") {
            return Err(MLSError::Internal(
                "sim buggify: before_wal_passive_checkpoint".to_string(),
            ));
        }
        self.with_raw_conn(|conn| {
            let _ = conn.query_row("PRAGMA main.wal_checkpoint(PASSIVE);", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            });
            Ok(())
        })
    }

    /// Test helper pinning an active WAL read snapshot while `f` executes (`I9` verification).
    pub fn hold_read_snapshot_for_test(&self, f: impl FnOnce()) -> Result<(), MLSError> {
        self.read_tx(|rx| {
            let _: i64 = rx
                .conn
                .query_row("SELECT COUNT(*) FROM messages;", [], |r| r.get(0))
                .map_err(|e| map_rusqlite_err("hold_read_snapshot_for_test", &e))?;
            f();
            Ok(())
        })
    }
}

/// `KvBackend` over a borrowed `rusqlite::Connection` (inside an active transaction or raw call).
#[derive(Clone, Copy)]
pub struct RusqliteKvBackend<'a>(pub &'a Connection);

impl KvBackend for RusqliteKvBackend<'_> {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError> {
        self.0
            .query_row(
                "SELECT value_bytes FROM openmls_kv WHERE version = ?1 AND scope = ?2 AND key_bytes = ?3",
                rusqlite::params![i64::from(version), scope, key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        self.0
            .execute(
                "INSERT OR REPLACE INTO openmls_kv (version, scope, key_bytes, value_bytes) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![i64::from(version), scope, key, value],
            )
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        Ok(())
    }

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        self.0
            .execute(
                "DELETE FROM openmls_kv WHERE version = ?1 AND scope = ?2 AND key_bytes = ?3",
                rusqlite::params![i64::from(version), scope, key],
            )
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        Ok(())
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError> {
        let mut stmt = self
            .0
            .prepare("SELECT key_bytes FROM openmls_kv WHERE version = ?1 AND scope = ?2")
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![i64::from(version), scope], |row| {
                row.get(0)
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError> {
        let mut stmt = self
            .0
            .prepare(
                "SELECT key_bytes, value_bytes FROM openmls_kv WHERE version = ?1 AND scope = ?2",
            )
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![i64::from(version), scope], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))
    }

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError> {
        self.0
            .query_row("SELECT COUNT(*) FROM openmls_kv", [], |row| row.get(0))
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))
    }
}

/// `KvBackend` delegating through a shared `Arc<MlsAccountDb>`.
#[derive(Clone)]
pub struct SharedAccountDbKvBackend(pub Arc<MlsAccountDb>);

impl KvBackend for SharedAccountDbKvBackend {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, OpenMlsKvError> {
        let mut result = None;
        self.0
            .with_raw_conn(|conn| {
                result = RusqliteKvBackend(conn)
                    .kv_get(version, scope, key)
                    .map_err(|e| MLSError::invalid_input(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        Ok(result)
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), OpenMlsKvError> {
        self.0
            .with_raw_conn(|conn| {
                RusqliteKvBackend(conn)
                    .kv_put(version, scope, key, value)
                    .map_err(|e| MLSError::invalid_input(e.to_string()))
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))
    }

    fn kv_delete(&self, version: u16, scope: &str, key: &[u8]) -> Result<(), OpenMlsKvError> {
        self.0
            .with_raw_conn(|conn| {
                RusqliteKvBackend(conn)
                    .kv_delete(version, scope, key)
                    .map_err(|e| MLSError::invalid_input(e.to_string()))
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, OpenMlsKvError> {
        let mut out = Vec::new();
        self.0
            .with_raw_conn(|conn| {
                out = RusqliteKvBackend(conn)
                    .kv_list_keys_in_scope(version, scope)
                    .map_err(|e| MLSError::invalid_input(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        Ok(out)
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, OpenMlsKvError> {
        let mut out = Vec::new();
        self.0
            .with_raw_conn(|conn| {
                out = RusqliteKvBackend(conn)
                    .kv_list_entries_in_scope(version, scope)
                    .map_err(|e| MLSError::invalid_input(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        Ok(out)
    }

    fn kv_count_all(&self) -> Result<usize, OpenMlsKvError> {
        let mut count = 0;
        self.0
            .with_raw_conn(|conn| {
                count = RusqliteKvBackend(conn)
                    .kv_count_all()
                    .map_err(|e| MLSError::invalid_input(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| OpenMlsKvError::Sql(e.to_string()))?;
        Ok(count)
    }
}

/// Read-only transaction handle over [`MlsAccountDb`].
pub struct SqlReadTx<'a> {
    conn: &'a Connection,
    keychain: Option<Arc<dyn KeychainAccess>>,
}

impl<'a> SqlReadTx<'a> {
    pub fn conn(&self) -> &'a Connection {
        self.conn
    }

    pub fn list_table_names(&self) -> Result<Vec<String>, MLSError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name ASC",
            )
            .map_err(|e| map_rusqlite_err("list_table_names.prepare", &e))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| map_rusqlite_err("list_table_names.query", &e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_rusqlite_err("list_table_names.collect", &e))
    }

    pub fn count_openmls_kv_rows(&self) -> Result<usize, MLSError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM openmls_kv", [], |row| row.get(0))
            .map_err(|e| map_rusqlite_err("count_openmls_kv_rows", &e))
    }

    pub fn get_account_meta(&self, key: &str) -> Result<Option<String>, MLSError> {
        self.conn
            .query_row(
                "SELECT value_json FROM account_meta WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_account_meta", &e))
    }

    pub fn list_account_meta_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, MLSError> {
        let pattern = format!("{prefix}%");
        let mut stmt = self
            .conn
            .prepare("SELECT key, value_json FROM account_meta WHERE key LIKE ?1 ORDER BY key ASC")
            .map_err(|e| map_rusqlite_err("list_account_meta_prefix.prepare", &e))?;
        let rows = stmt
            .query_map([pattern], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| map_rusqlite_err("list_account_meta_prefix.query", &e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_rusqlite_err("list_account_meta_prefix.collect", &e))
    }

    pub fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationRow>, MLSError> {
        self.conn
            .query_row(
                "SELECT conversation_id, group_id, generation, epoch, last_seq, sequencer_did, \
                        space_uri, title, unread_count, updated_at_ms \
                 FROM conversations WHERE conversation_id = ?1",
                [conversation_id],
                |row| {
                    Ok(ConversationRow {
                        conversation_id: row.get(0)?,
                        group_id: row.get(1)?,
                        generation: row.get(2)?,
                        epoch: row.get(3)?,
                        last_seq: row.get(4)?,
                        sequencer_did: row.get(5)?,
                        space_uri: row.get(6)?,
                        title: row.get(7)?,
                        unread_count: row.get(8)?,
                        updated_at_ms: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_conversation", &e))
    }

    pub fn get_conversation_by_group_id(
        &self,
        group_id: &[u8],
    ) -> Result<Option<ConversationRow>, MLSError> {
        self.conn
            .query_row(
                "SELECT conversation_id, group_id, generation, epoch, last_seq, sequencer_did, \
                        space_uri, title, unread_count, updated_at_ms \
                 FROM conversations WHERE group_id = ?1 LIMIT 1",
                [group_id],
                |row| {
                    Ok(ConversationRow {
                        conversation_id: row.get(0)?,
                        group_id: row.get(1)?,
                        generation: row.get(2)?,
                        epoch: row.get(3)?,
                        last_seq: row.get(4)?,
                        sequencer_did: row.get(5)?,
                        space_uri: row.get(6)?,
                        title: row.get(7)?,
                        unread_count: row.get(8)?,
                        updated_at_ms: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_conversation_by_group_id", &e))
    }

    pub fn list_conversations(
        &self,
        before_updated_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ConversationRow>, MLSError> {
        let cap = limit.min(500) as i64;
        let sql = if before_updated_ms.is_some() {
            "SELECT conversation_id, group_id, generation, epoch, last_seq, sequencer_did, \
                    space_uri, title, unread_count, updated_at_ms \
             FROM conversations WHERE updated_at_ms < ?1 \
             ORDER BY updated_at_ms DESC, conversation_id ASC LIMIT ?2"
        } else {
            "SELECT conversation_id, group_id, generation, epoch, last_seq, sequencer_did, \
                    space_uri, title, unread_count, updated_at_ms \
             FROM conversations \
             ORDER BY updated_at_ms DESC, conversation_id ASC LIMIT ?1"
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| map_rusqlite_err("list_conversations.prepare", &e))?;
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(ConversationRow {
                conversation_id: row.get(0)?,
                group_id: row.get(1)?,
                generation: row.get(2)?,
                epoch: row.get(3)?,
                last_seq: row.get(4)?,
                sequencer_did: row.get(5)?,
                space_uri: row.get(6)?,
                title: row.get(7)?,
                unread_count: row.get(8)?,
                updated_at_ms: row.get(9)?,
            })
        };
        let rows = if let Some(cursor) = before_updated_ms {
            stmt.query_map(rusqlite::params![cursor, cap], map_row)
        } else {
            stmt.query_map(rusqlite::params![cap], map_row)
        }
        .map_err(|e| map_rusqlite_err("list_conversations.query", &e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_rusqlite_err("list_conversations.collect", &e))
    }

    pub fn list_messages(
        &self,
        conversation_id: &str,
        before_seq: Option<i64>,
        limit: usize,
    ) -> Result<Vec<MessageRow>, MLSError> {
        let cap = limit.min(500) as i64;
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(MessageRow {
                message_id: row.get(0)?,
                conversation_id: row.get(1)?,
                group_id: row.get(2)?,
                epoch: row.get(3)?,
                seq: row.get(4)?,
                sender_did: row.get(5)?,
                sender_device_id: row.get(6)?,
                plaintext_json: row.get(7)?,
                created_at_ms: row.get(8)?,
                is_own: row.get::<_, i64>(9)? != 0,
            })
        };
        let order_clause = if crate::planted::is_planted_bug_active(
            crate::planted::PlantedBug::P6OrderTimelineByEpochSeq,
        ) {
            "epoch DESC, seq DESC"
        } else {
            "seq DESC"
        };
        if let Some(before) = before_seq {
            let sql = format!(
                "SELECT message_id, conversation_id, group_id, epoch, seq, sender_did, \
                        sender_device_id, plaintext_json, created_at_ms, is_own \
                 FROM messages WHERE conversation_id = ?1 AND seq < ?2 \
                 ORDER BY {order_clause} LIMIT ?3"
            );
            let mut stmt = self
                .conn
                .prepare(&sql)
                .map_err(|e| map_rusqlite_err("list_messages.prepare", &e))?;
            let rows = stmt
                .query_map(rusqlite::params![conversation_id, before, cap], map_row)
                .map_err(|e| map_rusqlite_err("list_messages.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("list_messages.collect", &e))
        } else {
            let sql = format!(
                "SELECT message_id, conversation_id, group_id, epoch, seq, sender_did, \
                        sender_device_id, plaintext_json, created_at_ms, is_own \
                 FROM messages WHERE conversation_id = ?1 \
                 ORDER BY {order_clause} LIMIT ?2"
            );
            let mut stmt = self
                .conn
                .prepare(&sql)
                .map_err(|e| map_rusqlite_err("list_messages.prepare", &e))?;
            let rows = stmt
                .query_map(rusqlite::params![conversation_id, cap], map_row)
                .map_err(|e| map_rusqlite_err("list_messages.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("list_messages.collect", &e))
        }
    }

    pub fn get_message(&self, message_id: &str) -> Result<Option<MessageRow>, MLSError> {
        self.conn
            .query_row(
                "SELECT message_id, conversation_id, group_id, epoch, seq, sender_did, \
                        sender_device_id, plaintext_json, created_at_ms, is_own \
                 FROM messages WHERE message_id = ?1",
                [message_id],
                |row| {
                    Ok(MessageRow {
                        message_id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        group_id: row.get(2)?,
                        epoch: row.get(3)?,
                        seq: row.get(4)?,
                        sender_did: row.get(5)?,
                        sender_device_id: row.get(6)?,
                        plaintext_json: row.get(7)?,
                        created_at_ms: row.get(8)?,
                        is_own: row.get::<_, i64>(9)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_message", &e))
    }

    pub fn get_request(&self, request_id: &str) -> Result<Option<RequestRow>, MLSError> {
        self.conn
            .query_row(
                "SELECT request_id, conversation_id, sender_did, recipient_did, consent, \
                        first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                 FROM requests WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok(RequestRow {
                        request_id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        sender_did: row.get(2)?,
                        recipient_did: row.get(3)?,
                        consent: row.get(4)?,
                        first_message_id: row.get(5)?,
                        first_message_archived: row.get::<_, i64>(6)? != 0,
                        payload_json: row.get(7)?,
                        expires_at_ms: row.get(8)?,
                        updated_at_ms: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_request", &e))
    }

    pub fn list_requests(&self, consent_filter: Option<&str>) -> Result<Vec<RequestRow>, MLSError> {
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(RequestRow {
                request_id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_did: row.get(2)?,
                recipient_did: row.get(3)?,
                consent: row.get(4)?,
                first_message_id: row.get(5)?,
                first_message_archived: row.get::<_, i64>(6)? != 0,
                payload_json: row.get(7)?,
                expires_at_ms: row.get(8)?,
                updated_at_ms: row.get(9)?,
            })
        };
        if let Some(consent) = consent_filter {
            let matching_states: Option<&[&str]> = match consent {
                "pending" => Some(&[
                    "pending",
                    "incomingPending",
                    "outgoingPending",
                    "incoming_pending",
                    "outgoing_pending",
                ]),
                "incomingPending" | "incoming_pending" => {
                    Some(&["incomingPending", "incoming_pending"])
                }
                "outgoingPending" | "outgoing_pending" => {
                    Some(&["outgoingPending", "outgoing_pending"])
                }
                "declined" | "closed" => Some(&["declined", "closed"]),
                _ => None,
            };
            if let Some(states) = matching_states {
                let placeholders: Vec<String> =
                    (1..=states.len()).map(|i| format!("?{i}")).collect();
                let sql = format!(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, \
                            first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests WHERE consent IN ({}) ORDER BY updated_at_ms DESC",
                    placeholders.join(", ")
                );
                let mut stmt = self
                    .conn
                    .prepare(&sql)
                    .map_err(|e| map_rusqlite_err("list_requests.prepare", &e))?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(states.iter()), map_row)
                    .map_err(|e| map_rusqlite_err("list_requests.query", &e))?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| map_rusqlite_err("list_requests.collect", &e))
            } else {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT request_id, conversation_id, sender_did, recipient_did, consent, \
                                first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                         FROM requests WHERE consent = ?1 ORDER BY updated_at_ms DESC",
                    )
                    .map_err(|e| map_rusqlite_err("list_requests.prepare", &e))?;
                let rows = stmt
                    .query_map([consent], map_row)
                    .map_err(|e| map_rusqlite_err("list_requests.query", &e))?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| map_rusqlite_err("list_requests.collect", &e))
            }
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, \
                            first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests ORDER BY updated_at_ms DESC",
                )
                .map_err(|e| map_rusqlite_err("list_requests.prepare", &e))?;
            let rows = stmt
                .query_map([], map_row)
                .map_err(|e| map_rusqlite_err("list_requests.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("list_requests.collect", &e))
        }
    }

    pub fn get_group_metadata(
        &self,
        conversation_id: &str,
    ) -> Result<Option<GroupMetadataRow>, MLSError> {
        self.conn
            .query_row(
                "SELECT conversation_id, metadata_version, epoch, title, description, \
                        avatar_setter_did, avatar_blob_cid, avatar_sym_key, avatar_sha256, \
                        avatar_mime_type, metadata_json, updated_at_ms \
                 FROM group_metadata_cache WHERE conversation_id = ?1",
                [conversation_id],
                |row| {
                    Ok(GroupMetadataRow {
                        conversation_id: row.get(0)?,
                        metadata_version: row.get(1)?,
                        epoch: row.get(2)?,
                        title: row.get(3)?,
                        description: row.get(4)?,
                        avatar_setter_did: row.get(5)?,
                        avatar_blob_cid: row.get(6)?,
                        avatar_sym_key: row.get(7)?,
                        avatar_sha256: row.get(8)?,
                        avatar_mime_type: row.get(9)?,
                        metadata_json: row.get(10)?,
                        updated_at_ms: row.get(11)?,
                    })
                },
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_group_metadata", &e))
    }

    pub fn get_epoch_secret(
        &self,
        group_id_hex: &str,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        self.conn
            .query_row(
                "SELECT secret_bytes FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch = ?2",
                rusqlite::params![group_id_hex, epoch as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_epoch_secret", &e))
    }

    pub fn get_pending_op(&self, op_kind: &str, op_key: &str) -> Result<Option<String>, MLSError> {
        self.conn
            .query_row(
                "SELECT payload_json FROM pending_ops WHERE op_kind = ?1 AND op_key = ?2",
                rusqlite::params![op_kind, op_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_pending_op", &e))
    }

    pub fn list_mutation_journal_pending(&self) -> Result<Vec<MutationJournalRow>, MLSError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT journal_id, op_type, epoch_seq, state_json, status, created_at_ms, updated_at_ms \
                 FROM mutation_journal WHERE status != 'completed' ORDER BY created_at_ms ASC",
            )
            .map_err(|e| map_rusqlite_err("list_mutation_journal_pending.prepare", &e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(MutationJournalRow {
                    journal_id: row.get(0)?,
                    op_type: row.get(1)?,
                    epoch_seq: row.get::<_, i64>(2)? as u64,
                    state_json: row.get(3)?,
                    status: row.get(4)?,
                    created_at_ms: row.get(5)?,
                    updated_at_ms: row.get(6)?,
                })
            })
            .map_err(|e| map_rusqlite_err("list_mutation_journal_pending.query", &e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_rusqlite_err("list_mutation_journal_pending.collect", &e))
    }

    pub fn get_routing_cache(&self, did: &str) -> Result<Option<RoutingCacheRow>, MLSError> {
        self.conn
            .query_row(
                "SELECT did, home_ds_did, home_ds_endpoint, pds_endpoint, resolved_at_ms \
                 FROM routing_cache WHERE did = ?1",
                [did],
                |row| {
                    Ok(RoutingCacheRow {
                        did: row.get(0)?,
                        home_ds_did: row.get(1)?,
                        home_ds_endpoint: row.get(2)?,
                        pds_endpoint: row.get(3)?,
                        resolved_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_routing_cache", &e))
    }

    pub fn get_labyrinth_state(&self, state_key: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.conn
            .query_row(
                "SELECT value_bytes FROM labyrinth_state WHERE state_key = ?1",
                [state_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| map_rusqlite_err("get_labyrinth_state", &e))
    }

    pub fn list_labyrinth_queue(
        &self,
        conversation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<LabyrinthQueueRow>, MLSError> {
        let cap = limit.min(500) as i64;
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(LabyrinthQueueRow {
                item_id: row.get(0)?,
                conversation_id: row.get(1)?,
                group_id_hex: row.get(2)?,
                seq: row.get(3)?,
                payload_bytes: row.get(4)?,
                created_at_ms: row.get(5)?,
            })
        };
        if let Some(cid) = conversation_id {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms \
                     FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY seq ASC, item_id ASC LIMIT ?2",
                )
                .map_err(|e| map_rusqlite_err("list_labyrinth_queue.prepare", &e))?;
            let rows = stmt
                .query_map(rusqlite::params![cid, cap], map_row)
                .map_err(|e| map_rusqlite_err("list_labyrinth_queue.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("list_labyrinth_queue.collect", &e))
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms \
                     FROM labyrinth_queue ORDER BY created_at_ms ASC, seq ASC, item_id ASC LIMIT ?1",
                )
                .map_err(|e| map_rusqlite_err("list_labyrinth_queue.prepare", &e))?;
            let rows = stmt
                .query_map([cap], map_row)
                .map_err(|e| map_rusqlite_err("list_labyrinth_queue.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("list_labyrinth_queue.collect", &e))
        }
    }

    /// Return distinct pending `conversation_id`s in oldest-first order so transient
    /// errors on one conversation Space never head-of-line block healthy conversations.
    pub fn list_labyrinth_queue_conversations(&self) -> Result<Vec<String>, MLSError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT conversation_id FROM labyrinth_queue \
                 GROUP BY conversation_id \
                 ORDER BY MIN(created_at_ms) ASC, conversation_id ASC",
            )
            .map_err(|e| map_rusqlite_err("list_labyrinth_queue_conversations.prepare", &e))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| map_rusqlite_err("list_labyrinth_queue_conversations.query", &e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_rusqlite_err("list_labyrinth_queue_conversations.collect", &e))
    }
}

/// Read-write atomic SQLite transaction over [`MlsAccountDb`].
pub struct SqlTx<'a> {
    read: SqlReadTx<'a>,
}

impl<'a> Deref for SqlTx<'a> {
    type Target = SqlReadTx<'a>;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}

impl<'a> SqlTx<'a> {
    /// Construct an `OpenMlsProvider` backed by `openmls_kv` inside this active transaction.
    pub fn openmls_provider(&self) -> OpenMlsKvProvider<RusqliteKvBackend<'a>> {
        OpenMlsKvProvider::new(self.openmls_storage()).expect("LibcruxCrypto initialization")
    }

    pub fn openmls_storage(&self) -> OpenMlsKvStorage<RusqliteKvBackend<'a>> {
        let backend = RusqliteKvBackend(self.read.conn);
        match &self.read.keychain {
            Some(kc) => OpenMlsKvStorage::with_keychain(backend, Arc::clone(kc)),
            None => OpenMlsKvStorage::new(backend),
        }
    }

    pub fn put_account_meta(
        &self,
        key: &str,
        value_json: &str,
        updated_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO account_meta (key, value_json, updated_at_ms) VALUES (?1, ?2, ?3)",
                rusqlite::params![key, value_json, updated_at_ms],
            )
            .map_err(|e| map_rusqlite_err("put_account_meta", &e))?;
        Ok(())
    }

    pub fn delete_account_meta(&self, key: &str) -> Result<(), MLSError> {
        self.read
            .conn
            .execute("DELETE FROM account_meta WHERE key = ?1", [key])
            .map_err(|e| map_rusqlite_err("delete_account_meta", &e))?;
        Ok(())
    }

    pub fn upsert_conversation(&self, row: &ConversationRow) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT INTO conversations (\
                    conversation_id, group_id, generation, epoch, last_seq, \
                    sequencer_did, space_uri, title, unread_count, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(conversation_id) DO UPDATE SET \
                    group_id = excluded.group_id, \
                    generation = excluded.generation, \
                    epoch = excluded.epoch, \
                    last_seq = MAX(conversations.last_seq, excluded.last_seq), \
                    sequencer_did = excluded.sequencer_did, \
                    space_uri = COALESCE(excluded.space_uri, conversations.space_uri), \
                    title = COALESCE(excluded.title, conversations.title), \
                    unread_count = excluded.unread_count, \
                    updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    row.conversation_id,
                    row.group_id,
                    row.generation,
                    row.epoch,
                    row.last_seq,
                    row.sequencer_did,
                    row.space_uri,
                    row.title,
                    row.unread_count,
                    row.updated_at_ms,
                ],
            )
            .map_err(|e| map_rusqlite_err("upsert_conversation", &e))?;
        Ok(())
    }

    pub fn delete_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "DELETE FROM conversations WHERE conversation_id = ?1",
                [conversation_id],
            )
            .map_err(|e| map_rusqlite_err("delete_conversation", &e))?;
        Ok(())
    }

    pub fn insert_message(&self, row: &MessageRow) -> Result<(), MLSError> {
        self.insert_message_with_commitment(row, None, None)
    }

    pub fn insert_message_with_commitment(
        &self,
        row: &MessageRow,
        archive_commitment: Option<&[u8]>,
        receipt_json: Option<&str>,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO messages (\
                    message_id, conversation_id, group_id, epoch, seq, \
                    sender_did, sender_device_id, plaintext_json, \
                    archive_commitment, receipt_json, created_at_ms, is_own\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    row.message_id,
                    row.conversation_id,
                    row.group_id,
                    row.epoch,
                    row.seq,
                    row.sender_did,
                    row.sender_device_id,
                    row.plaintext_json,
                    archive_commitment,
                    receipt_json,
                    row.created_at_ms,
                    i64::from(row.is_own),
                ],
            )
            .map_err(|e| map_rusqlite_err("insert_message", &e))?;
        Ok(())
    }

    /// Purge all locally stored messages from `sender_did` (`I13` `accountDeleted` compliance).
    pub fn purge_messages_from_sender(
        &self,
        conversation_id: Option<&str>,
        sender_did: &str,
    ) -> Result<usize, MLSError> {
        if let Some(cid) = conversation_id {
            self.read
                .conn
                .execute(
                    "DELETE FROM messages WHERE conversation_id = ?1 AND sender_did = ?2",
                    rusqlite::params![cid, sender_did],
                )
                .map_err(|e| map_rusqlite_err("purge_messages_from_sender(convo)", &e))
        } else {
            self.read
                .conn
                .execute("DELETE FROM messages WHERE sender_did = ?1", [sender_did])
                .map_err(|e| map_rusqlite_err("purge_messages_from_sender(all)", &e))
        }
    }

    pub fn upsert_request(&self, row: &RequestRow) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO requests (\
                    request_id, conversation_id, sender_did, recipient_did, consent, \
                    first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    row.request_id,
                    row.conversation_id,
                    row.sender_did,
                    row.recipient_did,
                    row.consent,
                    row.first_message_id,
                    i64::from(row.first_message_archived),
                    row.payload_json,
                    row.expires_at_ms,
                    row.updated_at_ms,
                ],
            )
            .map_err(|e| map_rusqlite_err("upsert_request", &e))?;
        Ok(())
    }

    pub fn mark_request_first_message_archived(
        &self,
        request_id: &str,
        updated_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "UPDATE requests SET first_message_archived = 1, updated_at_ms = ?2 WHERE request_id = ?1",
                rusqlite::params![request_id, updated_at_ms],
            )
            .map_err(|e| map_rusqlite_err("mark_request_first_message_archived", &e))?;
        Ok(())
    }

    pub fn upsert_group_metadata(&self, row: &GroupMetadataRow) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO group_metadata_cache (\
                    conversation_id, metadata_version, epoch, title, description, \
                    avatar_setter_did, avatar_blob_cid, avatar_sym_key, avatar_sha256, \
                    avatar_mime_type, metadata_json, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    row.conversation_id,
                    row.metadata_version,
                    row.epoch,
                    row.title,
                    row.description,
                    row.avatar_setter_did,
                    row.avatar_blob_cid,
                    row.avatar_sym_key,
                    row.avatar_sha256,
                    row.avatar_mime_type,
                    row.metadata_json,
                    row.updated_at_ms,
                ],
            )
            .map_err(|e| map_rusqlite_err("upsert_group_metadata", &e))?;
        Ok(())
    }

    pub fn put_epoch_secret(
        &self,
        group_id_hex: &str,
        epoch: u64,
        secret_bytes: &[u8],
        created_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO epoch_secrets (group_id_hex, epoch, secret_bytes, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![group_id_hex, epoch as i64, secret_bytes, created_at_ms],
            )
            .map_err(|e| map_rusqlite_err("put_epoch_secret", &e))?;
        Ok(())
    }

    pub fn delete_epoch_secret(&self, group_id_hex: &str, epoch: u64) -> Result<bool, MLSError> {
        let changed = self
            .read
            .conn
            .execute(
                "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch = ?2",
                rusqlite::params![group_id_hex, epoch as i64],
            )
            .map_err(|e| map_rusqlite_err("delete_epoch_secret", &e))?;
        Ok(changed > 0)
    }

    pub fn delete_epoch_secrets_before(
        &self,
        group_id_hex: &str,
        cutoff_epoch: u64,
    ) -> Result<u32, MLSError> {
        let deleted = self
            .read
            .conn
            .execute(
                "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch < ?2",
                rusqlite::params![group_id_hex, cutoff_epoch as i64],
            )
            .map_err(|e| map_rusqlite_err("delete_epoch_secrets_before", &e))?;
        Ok(deleted as u32)
    }

    pub fn put_sequencer_receipt(
        &self,
        conversation_id: &str,
        epoch: i64,
        seq: i64,
        entry_id: &str,
        receipt_json: &str,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO sequencer_receipts \
                 (conversation_id, epoch, seq, entry_id, receipt_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![conversation_id, epoch, seq, entry_id, receipt_json],
            )
            .map_err(|e| map_rusqlite_err("put_sequencer_receipt", &e))?;
        Ok(())
    }

    pub fn clear_sequencer_receipts(&self, conversation_id: &str) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "DELETE FROM sequencer_receipts WHERE conversation_id = ?1",
                [conversation_id],
            )
            .map_err(|e| map_rusqlite_err("clear_sequencer_receipts", &e))?;
        Ok(())
    }

    pub fn put_pending_op(
        &self,
        op_kind: &str,
        op_key: &str,
        payload_json: &str,
        created_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO pending_ops (op_kind, op_key, payload_json, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![op_kind, op_key, payload_json, created_at_ms],
            )
            .map_err(|e| map_rusqlite_err("put_pending_op", &e))?;
        Ok(())
    }

    pub fn delete_pending_op(&self, op_kind: &str, op_key: &str) -> Result<usize, MLSError> {
        self.read
            .conn
            .execute(
                "DELETE FROM pending_ops WHERE op_kind = ?1 AND op_key = ?2",
                rusqlite::params![op_kind, op_key],
            )
            .map_err(|e| map_rusqlite_err("delete_pending_op", &e))
    }

    pub fn upsert_mutation_journal(&self, row: &MutationJournalRow) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO mutation_journal \
                 (journal_id, op_type, epoch_seq, state_json, status, created_at_ms, updated_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    row.journal_id,
                    row.op_type,
                    row.epoch_seq as i64,
                    row.state_json,
                    row.status,
                    row.created_at_ms,
                    row.updated_at_ms,
                ],
            )
            .map_err(|e| map_rusqlite_err("upsert_mutation_journal", &e))?;
        Ok(())
    }

    pub fn delete_mutation_journal(&self, journal_id: &str) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "DELETE FROM mutation_journal WHERE journal_id = ?1",
                [journal_id],
            )
            .map_err(|e| map_rusqlite_err("delete_mutation_journal", &e))?;
        Ok(())
    }

    pub fn upsert_routing_cache(&self, row: &RoutingCacheRow) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO routing_cache \
                 (did, home_ds_did, home_ds_endpoint, pds_endpoint, resolved_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    row.did,
                    row.home_ds_did,
                    row.home_ds_endpoint,
                    row.pds_endpoint,
                    row.resolved_at_ms,
                ],
            )
            .map_err(|e| map_rusqlite_err("upsert_routing_cache", &e))?;
        Ok(())
    }

    pub fn put_labyrinth_state(
        &self,
        state_key: &str,
        value_bytes: &[u8],
        updated_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO labyrinth_state (state_key, value_bytes, updated_at_ms) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![state_key, value_bytes, updated_at_ms],
            )
            .map_err(|e| map_rusqlite_err("put_labyrinth_state", &e))?;
        Ok(())
    }

    pub fn enqueue_labyrinth_item(&self, row: &LabyrinthQueueRow) -> Result<(), MLSError> {
        self.read
            .conn
            .execute(
                "INSERT OR REPLACE INTO labyrinth_queue \
                 (item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    row.item_id,
                    row.conversation_id,
                    row.group_id_hex,
                    row.seq,
                    row.payload_bytes,
                    row.created_at_ms,
                ],
            )
            .map_err(|e| map_rusqlite_err("enqueue_labyrinth_item", &e))?;
        Ok(())
    }

    pub fn dequeue_labyrinth_item(&self, item_id: &str) -> Result<(), MLSError> {
        self.read
            .conn
            .execute("DELETE FROM labyrinth_queue WHERE item_id = ?1", [item_id])
            .map_err(|e| map_rusqlite_err("dequeue_labyrinth_item", &e))?;
        Ok(())
    }
}

/// Rust-internal [`EpochSecretStorage`] backed directly by the `epoch_secrets` table in [`MlsAccountDb`].
#[async_trait::async_trait]
impl EpochSecretStorage for MlsAccountDb {
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool {
        let now = unix_now_ms();
        self.with_raw_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO epoch_secrets (group_id_hex, epoch, secret_bytes, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![conversation_id, epoch as i64, secret_data, now],
            )
            .map_err(|e| map_rusqlite_err("EpochSecretStorage::store", &e))?;
            Ok(())
        })
        .is_ok()
    }

    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>> {
        let mut out = None;
        let _ = self.with_raw_conn(|conn| {
            out = conn
                .query_row(
                    "SELECT secret_bytes FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch = ?2",
                    rusqlite::params![conversation_id, epoch as i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| map_rusqlite_err("EpochSecretStorage::get", &e))?;
            Ok(())
        });
        out
    }

    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool {
        self.with_raw_conn(|conn| {
            conn.execute(
                "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch = ?2",
                rusqlite::params![conversation_id, epoch as i64],
            )
            .map_err(|e| map_rusqlite_err("EpochSecretStorage::delete", &e))?;
            Ok(())
        })
        .is_ok()
    }

    async fn delete_epochs_before(&self, conversation_id: String, cutoff_epoch: u64) -> u32 {
        let mut deleted = 0u32;
        let _ = self.with_raw_conn(|conn| {
            let count = conn
                .execute(
                    "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch < ?2",
                    rusqlite::params![conversation_id, cutoff_epoch as i64],
                )
                .map_err(|e| map_rusqlite_err("EpochSecretStorage::delete_before", &e))?;
            deleted = count as u32;
            Ok(())
        });
        deleted
    }
}
