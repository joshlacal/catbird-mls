//! Unified 15-table per-account SQLite schema (`Spec §6.1`).
//!
//! Shared identically across native SQLCipher 4 (`rusqlite`) and browser WASM
//! `sqlite3mc` (`sqlite-wasm-rs`). Consolidates all OpenMLS state into `openmls_kv`
//! alongside app-facing tables in one Rust-owned database per account.

/// `account_meta` key gating the encrypted client database as one indivisible format.
pub const LOCAL_STATE_FORMAT_KEY: &str = "local_state_format_version";
/// First storage format carrying every Round 4 invariant. Version 0 means the pre-gate schema.
pub const LOCAL_STATE_FORMAT_VERSION: u32 = 1;

/// Canonical 15 tables in every per-account Catbird MLS database (`Spec §6.1`).
pub const UNIFIED_SCHEMA_TABLES: &[&str; 15] = &[
    "openmls_kv",
    "account_meta",
    "conversations",
    "messages",
    "requests",
    "participant_profiles",
    "group_metadata_cache",
    "epoch_secrets",
    "sequencer_receipts",
    "recovery_state",
    "pending_ops",
    "mutation_journal",
    "routing_cache",
    "labyrinth_state",
    "labyrinth_queue",
];

/// Idempotent schema DDL executed when initializing a per-account database.
pub const UNIFIED_SCHEMA_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS openmls_kv (
    version INTEGER NOT NULL,
    scope TEXT NOT NULL,
    key_bytes BLOB NOT NULL,
    value_bytes BLOB NOT NULL,
    storage_key BLOB GENERATED ALWAYS AS (CAST(scope AS BLOB) || key_bytes) VIRTUAL,
    value BLOB GENERATED ALWAYS AS (value_bytes) VIRTUAL,
    PRIMARY KEY (version, scope, key_bytes)
);

CREATE TABLE IF NOT EXISTS account_meta (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS conversations (
    conversation_id TEXT PRIMARY KEY,
    group_id BLOB NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0,
    epoch INTEGER NOT NULL DEFAULT 0,
    join_method TEXT NOT NULL DEFAULT 'created',
    join_epoch INTEGER NOT NULL DEFAULT 0,
    last_seq INTEGER NOT NULL DEFAULT 0,
    acked_seq INTEGER NOT NULL DEFAULT 0,
    state_tag TEXT NOT NULL DEFAULT 'active',
    state_json TEXT,
    needs_rejoin INTEGER NOT NULL DEFAULT 0,
    sequencer_did TEXT NOT NULL DEFAULT '',
    space_uri TEXT,
    title TEXT,
    description TEXT,
    avatar_json TEXT,
    unread_count INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    group_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    sender_did TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    plaintext_json TEXT NOT NULL,
    archive_commitment BLOB,
    receipt_json TEXT,
    created_at_ms INTEGER NOT NULL,
    is_own INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
    ON messages (conversation_id, seq DESC);

CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    consent TEXT NOT NULL,
    first_message_id TEXT,
    first_message_archived INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_requests_convo
    ON requests (conversation_id);

CREATE TABLE IF NOT EXISTS participant_profiles (
    did TEXT PRIMARY KEY,
    handle TEXT,
    display_name TEXT,
    avatar_url TEXT,
    home_ds_did TEXT,
    updated_at_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS group_metadata_cache (
    conversation_id TEXT PRIMARY KEY,
    metadata_version INTEGER NOT NULL DEFAULT 0,
    epoch INTEGER NOT NULL DEFAULT 0,
    title TEXT,
    description TEXT,
    avatar_setter_did TEXT,
    avatar_blob_cid TEXT,
    avatar_sym_key BLOB,
    avatar_sha256 BLOB,
    avatar_mime_type TEXT,
    metadata_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS epoch_secrets (
    group_id_hex TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    secret_bytes BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id_hex, epoch)
);

CREATE TABLE IF NOT EXISTS sequencer_receipts (
    conversation_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    entry_id TEXT NOT NULL DEFAULT '',
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (conversation_id, epoch, entry_id)
);

CREATE TABLE IF NOT EXISTS recovery_state (
    scope_key TEXT PRIMARY KEY,
    failed_rejoin_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at_ms INTEGER NOT NULL DEFAULT 0,
    quarantined_until_ms INTEGER,
    extra_json TEXT
);

CREATE TABLE IF NOT EXISTS pending_ops (
    op_kind TEXT NOT NULL,
    op_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (op_kind, op_key)
);

CREATE INDEX IF NOT EXISTS idx_pending_ops_kind
    ON pending_ops (op_kind, created_at_ms ASC);

CREATE TABLE IF NOT EXISTS mutation_journal (
    journal_id TEXT PRIMARY KEY,
    op_type TEXT NOT NULL,
    epoch_seq INTEGER NOT NULL DEFAULT 0,
    state_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_cache (
    did TEXT PRIMARY KEY,
    home_ds_did TEXT NOT NULL,
    home_ds_endpoint TEXT,
    pds_endpoint TEXT,
    resolved_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS labyrinth_state (
    state_key TEXT PRIMARY KEY,
    value_bytes BLOB NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS labyrinth_queue (
    item_id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    group_id_hex TEXT NOT NULL,
    seq INTEGER NOT NULL,
    payload_bytes BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_labyrinth_queue_convo_seq
    ON labyrinth_queue (conversation_id, seq ASC);
"#;
