//! Unified per-account encrypted SQLite storage (`Spec §6.1`).
//!
//! - Native (`rusqlite` + SQLCipher 4): [`MlsAccountDb`] (`driver_native`)
//! - Browser WASM (`sqlite-wasm-rs` + `sqlite3mc` ChaCha20): [`WasmAccountDb`] (`driver_wasm`)
//! - Shared 15-table DDL (`schema`), single-table `openmls_kv` `StorageProvider<1>` (`openmls_kv`),
//!   and strongly typed row models (`queries`).

#[cfg(not(target_arch = "wasm32"))]
pub mod driver_native;
pub mod driver_wasm;
pub mod openmls_kv;
#[cfg(not(target_arch = "wasm32"))]
pub mod orchestrator_backend;
pub mod queries;
pub mod schema;

#[cfg(not(target_arch = "wasm32"))]
pub use driver_native::{
    derive_db_key_32_from_str, derive_sqlcipher_96hex_key_spec, BackgroundCheckpointReport,
    MlsAccountDb, OpenMode, RusqliteKvBackend, SharedAccountDbKvBackend, SqlDriver, SqlReadTx,
    SqlTx,
};
pub use driver_wasm::{wasm_sqlite3mc_init_pragmas, WasmAccountDb, WasmSqlBackend};
pub use openmls_kv::{
    KvBackend, KvWriteBatch, KvWriteOverlay, OpenMlsKvError, OpenMlsKvProvider, OpenMlsKvStorage,
    DIRECT_GROUP_SCOPES, SCOPE_APPLICATION_EXPORT_TREE, SCOPE_CONFIRMATION_TAG,
    SCOPE_ENCRYPTION_KEY_PAIR, SCOPE_EPOCH_KEY_PAIRS, SCOPE_EPOCH_SECRETS, SCOPE_GROUP_CONTEXT,
    SCOPE_GROUP_STATE, SCOPE_INTERIM_TRANSCRIPT_HASH, SCOPE_JOIN_CONFIG, SCOPE_KEY_PACKAGE,
    SCOPE_MESSAGE_SECRETS, SCOPE_OWN_LEAF_NODES, SCOPE_OWN_LEAF_NODE_INDEX,
    SCOPE_PROPOSAL_QUEUE_REFS, SCOPE_PSK, SCOPE_QUEUED_PROPOSAL, SCOPE_RESUMPTION_PSK_STORE,
    SCOPE_SIGNATURE_KEY_PAIR, SCOPE_TREE,
};
pub use queries::{
    ConversationRow, GroupMetadataRow, LabyrinthQueueRow, MessageRow, MutationJournalRow,
    RequestRow, RoutingCacheRow,
};
pub use schema::{
    LOCAL_STATE_FORMAT_KEY, LOCAL_STATE_FORMAT_VERSION, UNIFIED_SCHEMA_DDL, UNIFIED_SCHEMA_TABLES,
};
