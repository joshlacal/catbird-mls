//! Outbound MLS `PrivateMessage` AAD envelope helper (`I13`) and post-commit acknowledgment re-exports.

use serde::{Deserialize, Serialize};

use super::receive::compute_archive_commitment;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::sync::reconcile::persist_entries_then_acknowledge;
pub use crate::sync::reconcile::persist_entries_then_acknowledge_wasm;

/// Canonical JSON AAD payload embedded in OpenMLS `PrivateMessage` framing (`Spec §5 I13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateMessageAadEnvelope {
    pub version: u8,
    pub conversation_id: String,
    pub message_id: String,
    /// Hex-encoded 32-byte `archive_commitment` (`I13`).
    pub archive_commitment_hex: String,
}

impl PrivateMessageAadEnvelope {
    pub fn build(
        conversation_id: &str,
        group_id: &[u8],
        message_id: &str,
        plaintext_bytes: &[u8],
        created_at_ms: i64,
    ) -> Self {
        let commitment = compute_archive_commitment(
            conversation_id,
            group_id,
            message_id,
            plaintext_bytes,
            created_at_ms,
        );
        Self {
            version: 1,
            conversation_id: conversation_id.to_owned(),
            message_id: message_id.to_owned(),
            archive_commitment_hex: hex::encode(commitment),
        }
    }

    pub fn to_aad_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}
