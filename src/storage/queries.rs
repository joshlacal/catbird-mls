//! Strongly-typed row projections for the unified per-account SQLite schema (`Spec §6.1`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationRow {
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub generation: i64,
    pub epoch: i64,
    pub last_seq: i64,
    pub sequencer_did: String,
    pub space_uri: Option<String>,
    pub title: Option<String>,
    pub unread_count: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRow {
    pub message_id: String,
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub epoch: i64,
    pub seq: i64,
    pub sender_did: String,
    pub sender_device_id: String,
    pub plaintext_json: String,
    pub created_at_ms: i64,
    pub is_own: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRow {
    pub request_id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    pub consent: String,
    pub first_message_id: Option<String>,
    pub first_message_archived: bool,
    pub payload_json: String,
    pub expires_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMetadataRow {
    pub conversation_id: String,
    pub metadata_version: i64,
    pub epoch: i64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub avatar_setter_did: Option<String>,
    pub avatar_blob_cid: Option<String>,
    pub avatar_sym_key: Option<Vec<u8>>,
    pub avatar_sha256: Option<Vec<u8>>,
    pub avatar_mime_type: Option<String>,
    pub metadata_json: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationJournalRow {
    pub journal_id: String,
    pub op_type: String,
    pub epoch_seq: u64,
    pub state_json: String,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingCacheRow {
    pub did: String,
    pub home_ds_did: String,
    pub home_ds_endpoint: Option<String>,
    pub pds_endpoint: Option<String>,
    pub resolved_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabyrinthQueueRow {
    pub item_id: String,
    pub conversation_id: String,
    pub group_id_hex: String,
    pub seq: i64,
    pub payload_bytes: Vec<u8>,
    pub created_at_ms: i64,
}
