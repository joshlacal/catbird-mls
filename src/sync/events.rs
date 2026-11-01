//! Realtime `mls-ds` event classification (`Spec §6.5`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RealtimeSyncEvent {
    SequencedEntry {
        conversation_id: String,
        seq: i64,
        epoch: i64,
    },
    AccountDeleted {
        deleted_did: String,
    },
    LabyrinthEpochHead {
        owner_did: String,
        epoch_seq: u64,
        epoch_head_hex: String,
    },
    ConversationSpaceAssigned {
        conversation_id: String,
        space_uri: String,
        generation: u64,
    },
}
