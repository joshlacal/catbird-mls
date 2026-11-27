//! Local erase of one message's content: delete-for-me (F1) and scrub-on-unsend (F2).
//!
//! A durable `labyrinth_state` marker records that the message is gone from this device and
//! must never come back, from sync, a push extension store, a restore or a reindex. The marker
//! is written in the same transaction that removes the display row, the retained archive
//! evidence (`native.message:`), queued archive copies and pending receipt work, so a crash
//! leaves either everything or nothing. The marker is never deleted.
//!
//! The marker, not the evidence, now recognises this device's own echo: sync skips an entry
//! whose message id carries a marker for the same sender (see `live_sync`).
//!
//! Engine (`field_encryption`) rows and `sequencer_receipts` are not touched: the native
//! message path stores no content there, and the hmac chain must keep verifying.

use serde::{Deserialize, Serialize};

use crate::error::MLSError;
use crate::storage::{SqlReadTx, SqlTx};

/// `pending_ops` kind: a delete-for-me owner tombstone not yet published to the mailbox.
pub(crate) const NATIVE_DELETE_FOR_ME_OP: &str = "native_delete_for_me";

/// The author unsent `message_id`. Values: `unsent` (redaction published), `unsent-local`
/// (never archived), `unsent-peer` (a verified author redaction applied from history).
pub(crate) fn unsent_message_key(conversation_id: &str, message_id: &str) -> String {
    format!("native.unsent:{conversation_id}:{message_id}")
}

/// This account deleted `message_id` for itself. Value: [`DeletedForMeMarker`] JSON.
pub(crate) fn deleted_for_me_key(conversation_id: &str, message_id: &str) -> String {
    format!("native.deleted:{conversation_id}:{message_id}")
}

/// Durable delete-for-me marker. `published` is true once the owner tombstone is in the
/// personal mailbox (or the tombstone came from there).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeletedForMeMarker {
    pub v: u32,
    pub at_ms: i64,
    pub sender_did: String,
    pub published: bool,
}

impl DeletedForMeMarker {
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, MLSError> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// Payload of a [`NATIVE_DELETE_FOR_ME_OP`] pending op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingDeleteForMe {
    pub conversation_id: String,
    pub message_id: String,
    pub timestamp_ms: u64,
    pub sender_did: String,
}

/// True when this device erased `message_id` (unsent or deleted for me).
pub(crate) fn is_locally_erased(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    message_id: &str,
) -> Result<bool, MLSError> {
    Ok(tx
        .get_labyrinth_state(&unsent_message_key(conversation_id, message_id))?
        .is_some()
        || tx
            .get_labyrinth_state(&deleted_for_me_key(conversation_id, message_id))?
            .is_some())
}

/// The sender a marker binds, when the marker names one. `unsent` markers bind this account
/// (own unsend) or the redaction's verified author (`unsent-peer`), which the caller already
/// checked; they return `None`, meaning "any sender".
pub(crate) fn erased_marker_sender(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    message_id: &str,
) -> Result<Option<Option<String>>, MLSError> {
    if tx
        .get_labyrinth_state(&unsent_message_key(conversation_id, message_id))?
        .is_some()
    {
        return Ok(Some(None));
    }
    match tx.get_labyrinth_state(&deleted_for_me_key(conversation_id, message_id))? {
        None => Ok(None),
        Some(raw) => Ok(Some(
            serde_json::from_slice::<DeletedForMeMarker>(&raw)
                .ok()
                .map(|marker| marker.sender_did),
        )),
    }
}

/// What [`erase_message_content`] removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ErasedMessage {
    /// A display row existed and was deleted.
    pub existed: bool,
    /// Attachment blob ids named by the deleted row's embed, for platform cache drops.
    pub blob_ids: Vec<String>,
    pub sender_did: Option<String>,
}

fn delete_state(tx: &SqlTx<'_>, key: &str) -> Result<(), MLSError> {
    tx.conn()
        .execute("DELETE FROM labyrinth_state WHERE state_key = ?1", [key])
        .map_err(|e| MLSError::Internal(format!("erase labyrinth state: {e}")))?;
    Ok(())
}

/// Blob ids anywhere under an `embed` of the plaintext JSON (`blobId` / `blob_id` strings).
fn collect_blob_ids(plaintext_json: &str) -> Vec<String> {
    fn walk(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if matches!(key.as_str(), "blobId" | "blob_id") {
                        if let Some(id) = child.as_str() {
                            out.push(id.to_owned());
                        }
                    }
                    walk(child, out);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(plaintext_json) {
        if let Some(embed) = value.get("embed") {
            walk(embed, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Erase `message_id`'s local content and write `marker_key = marker_val`, inside the
/// caller's write transaction. Idempotent: a rerun with the row gone only rewrites the marker
/// and returns `existed: false`.
pub(crate) fn erase_message_content(
    tx: &SqlTx<'_>,
    conversation_id: &str,
    message_id: &str,
    marker_key: &str,
    marker_val: &[u8],
    now_ms: i64,
) -> Result<ErasedMessage, MLSError> {
    // The never-resurrect marker first; the transaction makes the order cosmetic.
    tx.put_labyrinth_state(marker_key, marker_val, now_ms)?;
    let row = tx
        .get_message(message_id)?
        .filter(|row| row.conversation_id == conversation_id);
    let erased = ErasedMessage {
        existed: row.is_some(),
        blob_ids: row
            .as_ref()
            .map(|row| collect_blob_ids(&row.plaintext_json))
            .unwrap_or_default(),
        sender_did: row.as_ref().map(|row| row.sender_did.clone()),
    };
    tx.conn()
        .execute(
            "DELETE FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
            rusqlite::params![conversation_id, message_id],
        )
        .map_err(|e| MLSError::Internal(format!("erase message row: {e}")))?;
    for key in [
        format!("native.message:{conversation_id}:{message_id}"),
        format!("push.verified_receipt:{conversation_id}:{message_id}"),
        super::chat_wire::unavailable_message_key(conversation_id, message_id),
        super::chat_wire::undecryptable_evidence_key(conversation_id, message_id),
    ] {
        delete_state(tx, &key)?;
    }
    // Scoped to this conversation: an erase never reaches another conversation's work.
    tx.conn()
        .execute(
            "DELETE FROM labyrinth_queue WHERE item_id = ?1 AND conversation_id = ?2",
            rusqlite::params![message_id, conversation_id],
        )
        .map_err(|e| MLSError::Internal(format!("erase queued archive copy: {e}")))?;
    tx.conn()
        .execute(
            "DELETE FROM pending_ops WHERE op_kind = ?1 AND op_key = ?2 \
             AND coalesce(json_extract(payload_json, '$.conversation_id'), ?3) = ?3",
            rusqlite::params![
                crate::push::processor::NATIVE_ARCHIVE_RECEIPT_OP,
                message_id,
                conversation_id
            ],
        )
        .map_err(|e| MLSError::Internal(format!("erase pending archive receipt: {e}")))?;
    Ok(erased)
}

#[cfg(test)]
#[path = "message_erase_unit_tests.rs"]
mod tests;
