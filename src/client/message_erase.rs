//! Local erase of one message's content: delete-for-me (F1) and scrub-on-unsend (F2).
//!
//! A durable `labyrinth_state` marker records that the message is gone from this device and
//! must never come back, from sync, a push extension store, a restore or a reindex. The marker
//! is written in the same transaction that removes the display row, the retained archive
//! evidence (`native.message:`), queued archive copies, pending receipt work, the message's
//! edits and a direct-request opening preview, so a crash leaves either everything or
//! nothing. The marker is never deleted.
//!
//! Every marker is bound to a sender. A message id is chosen by its sender, so a marker only
//! covers copies, entries and edits from the sender it names: a redaction by one member that
//! names another member's message id never suppresses that other member's message. The
//! marker, not the evidence, now recognises this device's own echo: sync skips an entry whose
//! message id carries a marker covering the entry's verified sender (see `live_sync`).
//!
//! Engine (`field_encryption`) rows and `sequencer_receipts` are not touched: the native
//! message path stores no content there, and the hmac chain must keep verifying.

use serde::{Deserialize, Serialize};

use crate::error::MLSError;
use crate::storage::{SqlReadTx, SqlTx};

/// `pending_ops` kind: a delete-for-me owner tombstone not yet published to the mailbox.
pub(crate) const NATIVE_DELETE_FOR_ME_OP: &str = "native_delete_for_me";

/// The author unsent `message_id`. Value: [`UnsentMarker`] JSON. A value that is not JSON
/// (written before markers named their sender) covers every sender.
pub(crate) fn unsent_message_key(conversation_id: &str, message_id: &str) -> String {
    format!("native.unsent:{conversation_id}:{message_id}")
}

/// This account deleted `message_id` for itself. Value: [`DeletedForMeMarker`] JSON.
pub(crate) fn deleted_for_me_key(conversation_id: &str, message_id: &str) -> String {
    format!("native.deleted:{conversation_id}:{message_id}")
}

/// Durable unsend marker. `kind` records the first writer: `unsent` (own redaction
/// published), `unsent-local` (own, never archived) or `unsent-peer` (a verified author
/// redaction applied from history). `senders` lists the verified authors whose copies of the
/// id are gone; an empty list covers every sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UnsentMarker {
    pub v: u32,
    pub kind: String,
    pub senders: Vec<String>,
}

/// Durable delete-for-me marker. `published` is true once the owner tombstone is in the
/// personal mailbox (or the tombstone came from there). An empty `sender_did` (a tombstone
/// loaded from history with no local row) covers every sender.
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

/// Which marker an erase writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EraseKind<'a> {
    /// `native.unsent`, with the [`UnsentMarker::kind`] to record.
    Unsent(&'a str),
    /// `native.deleted`.
    DeletedForMe { published: bool },
}

/// True when any marker exists for `message_id`, whatever sender it names.
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

fn unsent_covers(raw: &[u8], sender: &str) -> bool {
    match serde_json::from_slice::<UnsentMarker>(raw) {
        Ok(marker) => marker.senders.is_empty() || marker.senders.iter().any(|s| s == sender),
        // Legacy (pre sender binding) or unreadable: fail toward keeping it erased.
        Err(_) => true,
    }
}

fn deleted_covers(raw: &[u8], sender: &str) -> bool {
    match serde_json::from_slice::<DeletedForMeMarker>(raw) {
        Ok(marker) => marker.sender_did.is_empty() || marker.sender_did == sender,
        Err(_) => true,
    }
}

/// True when a marker for `message_id` covers copies sent by `sender`.
pub(crate) fn is_erased_for(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    message_id: &str,
    sender: &str,
) -> Result<bool, MLSError> {
    if let Some(raw) = tx.get_labyrinth_state(&unsent_message_key(conversation_id, message_id))? {
        if unsent_covers(&raw, sender) {
            return Ok(true);
        }
    }
    if let Some(raw) = tx.get_labyrinth_state(&deleted_for_me_key(conversation_id, message_id))? {
        if deleted_covers(&raw, sender) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The message id an edit frame targets, at any path `archive_policy` also reads. A stored
/// row keeps a frame without a top-level `text` string wrapped as `{"text": "<frame>"}`
/// (`parse_canonical_message_body`), so the wrapped frame is read too.
pub(crate) fn edit_target_id(plaintext_json: &str) -> Option<String> {
    fn target(value: &serde_json::Value) -> Option<String> {
        [
            "/edit/targetMessageId",
            "/edit/messageId",
            "/editedMessageId",
        ]
        .into_iter()
        .find_map(|path| value.pointer(path).and_then(serde_json::Value::as_str))
        .map(str::to_owned)
    }
    let value = serde_json::from_str::<serde_json::Value>(plaintext_json).ok()?;
    target(&value).or_else(|| {
        let inner = value.get("text")?.as_str()?;
        target(&serde_json::from_str::<serde_json::Value>(inner).ok()?)
    })
}

/// True when this frame must not be stored or archived here: its own id is erased for its
/// sender, or it edits a message that is erased for the same sender.
pub(crate) fn is_frame_erased(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    message_id: &str,
    sender: &str,
    plaintext_json: &str,
) -> Result<bool, MLSError> {
    if is_erased_for(tx, conversation_id, message_id, sender)? {
        return Ok(true);
    }
    match edit_target_id(plaintext_json) {
        Some(target) if target != message_id => is_erased_for(tx, conversation_id, &target, sender),
        _ => Ok(false),
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

/// The `sender_did` a stored JSON payload names, if any.
fn payload_sender(raw: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(raw)
        .ok()?
        .get("sender_did")?
        .as_str()
        .map(str::to_owned)
}

/// Write (or widen) the marker for `message_id` so it covers `sender` (`None`: any sender).
fn write_marker(
    tx: &SqlTx<'_>,
    conversation_id: &str,
    message_id: &str,
    sender: Option<&str>,
    kind: EraseKind<'_>,
    now_ms: i64,
) -> Result<(), MLSError> {
    match kind {
        EraseKind::Unsent(kind) => {
            let key = unsent_message_key(conversation_id, message_id);
            let marker = match tx.get_labyrinth_state(&key)? {
                None => UnsentMarker {
                    v: 1,
                    kind: kind.to_owned(),
                    senders: sender.map(str::to_owned).into_iter().collect(),
                },
                Some(raw) => match serde_json::from_slice::<UnsentMarker>(&raw) {
                    // A legacy marker already covers every sender.
                    Err(_) => return Ok(()),
                    Ok(mut marker) => {
                        match sender {
                            // Already covers every sender, or already names this one.
                            _ if marker.senders.is_empty() => return Ok(()),
                            Some(s) if marker.senders.iter().any(|known| known == s) => {
                                return Ok(())
                            }
                            Some(s) => marker.senders.push(s.to_owned()),
                            None => marker.senders.clear(),
                        }
                        marker.senders.sort();
                        marker
                    }
                },
            };
            tx.put_labyrinth_state(&key, &serde_json::to_vec(&marker)?, now_ms)
        }
        EraseKind::DeletedForMe { published } => {
            let key = deleted_for_me_key(conversation_id, message_id);
            let existing = tx
                .get_labyrinth_state(&key)?
                .and_then(|raw| serde_json::from_slice::<DeletedForMeMarker>(&raw).ok());
            let marker = match existing {
                Some(mut marker) => {
                    // This account's own choice: a second sender for the same id widens the
                    // marker to every sender rather than leaving one uncovered.
                    let widen = !marker.sender_did.is_empty()
                        && sender.is_none_or(|s| s != marker.sender_did);
                    let publish = published && !marker.published;
                    if !widen && !publish {
                        return Ok(());
                    }
                    if widen {
                        marker.sender_did.clear();
                    }
                    marker.published |= published;
                    marker
                }
                None => DeletedForMeMarker {
                    v: 1,
                    at_ms: now_ms,
                    sender_did: sender.unwrap_or_default().to_owned(),
                    published,
                },
            };
            tx.put_labyrinth_state(&key, &marker.to_bytes()?, now_ms)
        }
    }
}

/// Erase `message_id`'s local content and write its marker, inside the caller's write
/// transaction.
///
/// `sender` is the verified author the erase is for. A local row (or retained evidence, or a
/// queued copy) from any other sender is kept; only the marker is written, bound to `sender`.
/// `None` (a delete-for-me tombstone from history) takes the sender from the local row, or
/// covers every sender when there is none.
///
/// Edits of the message by the same sender are erased under the same kind of marker, and a
/// direct-request opening preview or staged opening for it is cleared.
///
/// Idempotent: a rerun with the row gone only keeps the marker and returns `existed: false`.
pub(crate) fn erase_message_content(
    tx: &SqlTx<'_>,
    conversation_id: &str,
    message_id: &str,
    sender: Option<&str>,
    kind: EraseKind<'_>,
    now_ms: i64,
) -> Result<ErasedMessage, MLSError> {
    let row = tx
        .get_message(message_id)?
        .filter(|row| row.conversation_id == conversation_id);
    let covered: Option<String> = sender
        .map(str::to_owned)
        .or_else(|| row.as_ref().map(|row| row.sender_did.clone()));
    // The never-resurrect marker first; the transaction makes the order cosmetic.
    write_marker(
        tx,
        conversation_id,
        message_id,
        covered.as_deref(),
        kind,
        now_ms,
    )?;
    let foreign_row = row
        .as_ref()
        .is_some_and(|row| covered.as_deref().is_some_and(|s| row.sender_did != s));
    let row = row.filter(|_| !foreign_row);
    let erased = ErasedMessage {
        existed: row.is_some(),
        blob_ids: row
            .as_ref()
            .map(|row| collect_blob_ids(&row.plaintext_json))
            .unwrap_or_default(),
        sender_did: row.as_ref().map(|row| row.sender_did.clone()),
    };
    let ours = |raw: &[u8]| match (covered.as_deref(), payload_sender(raw)) {
        (Some(s), Some(named)) => named == s,
        _ => true,
    };
    if !foreign_row {
        tx.conn()
            .execute(
                "DELETE FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
                rusqlite::params![conversation_id, message_id],
            )
            .map_err(|e| MLSError::Internal(format!("erase message row: {e}")))?;
        let evidence_key = format!("native.message:{conversation_id}:{message_id}");
        let evidence_ours = tx
            .get_labyrinth_state(&evidence_key)?
            .is_none_or(|raw| ours(&raw));
        if evidence_ours {
            for key in [
                evidence_key,
                format!("push.verified_receipt:{conversation_id}:{message_id}"),
                super::chat_wire::unavailable_message_key(conversation_id, message_id),
                super::chat_wire::undecryptable_evidence_key(conversation_id, message_id),
            ] {
                delete_state(tx, &key)?;
            }
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
        }
        // Scoped to this conversation: an erase never reaches another conversation's work.
        let queued: Option<Vec<u8>> = tx
            .conn()
            .query_row(
                "SELECT payload_bytes FROM labyrinth_queue WHERE item_id = ?1 AND conversation_id = ?2",
                rusqlite::params![message_id, conversation_id],
                |row| row.get(0),
            )
            .ok();
        if queued.as_deref().is_none_or(ours) {
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_queue WHERE item_id = ?1 AND conversation_id = ?2",
                    rusqlite::params![message_id, conversation_id],
                )
                .map_err(|e| MLSError::Internal(format!("erase queued archive copy: {e}")))?;
        }
        scrub_request_opening(tx, conversation_id, message_id, covered.as_deref(), now_ms)?;
    }
    // Edits carry the message's current text in their own rows: erase the sender's edits too.
    let edits: Vec<(String, String)> = {
        let mut statement = tx
            .conn()
            .prepare(
                "SELECT message_id, sender_did FROM messages
                 WHERE conversation_id = ?1 AND message_id <> ?2
                 AND (?3 IS NULL OR sender_did = ?3)
                 AND CASE WHEN json_valid(plaintext_json) THEN coalesce(
                     json_extract(plaintext_json, '$.edit.targetMessageId'),
                     json_extract(plaintext_json, '$.edit.messageId'),
                     json_extract(plaintext_json, '$.editedMessageId'),
                     CASE WHEN json_valid(json_extract(plaintext_json, '$.text')) THEN coalesce(
                         json_extract(json_extract(plaintext_json, '$.text'), '$.edit.targetMessageId'),
                         json_extract(json_extract(plaintext_json, '$.text'), '$.edit.messageId'),
                         json_extract(json_extract(plaintext_json, '$.text'), '$.editedMessageId'))
                     END) END = ?2",
            )
            .map_err(|e| MLSError::Internal(format!("select edits: {e}")))?;
        let rows = statement
            .query_map(
                rusqlite::params![conversation_id, message_id, covered],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| MLSError::Internal(format!("select edits: {e}")))?;
        rows.collect::<Result<_, _>>()
            .map_err(|e| MLSError::Internal(format!("read edits: {e}")))?
    };
    for (edit_id, edit_sender) in edits {
        // Each edit row is deleted before its own edits are looked up, so this terminates.
        erase_message_content(
            tx,
            conversation_id,
            &edit_id,
            Some(&edit_sender),
            kind,
            now_ms,
        )?;
    }
    Ok(erased)
}

/// A direct-request opening keeps its text beside the message row: the request preview
/// (`requests.payload_json`) and, before acceptance, the staged archive frame
/// (`c33_pending_opening:{cid}`). Clear both, as an account-deletion scrub does.
fn scrub_request_opening(
    tx: &SqlTx<'_>,
    conversation_id: &str,
    message_id: &str,
    sender: Option<&str>,
    now_ms: i64,
) -> Result<(), MLSError> {
    tx.conn()
        .execute(
            "UPDATE requests SET payload_json = '{}' WHERE conversation_id = ?1
             AND first_message_id = ?2 AND (?3 IS NULL OR sender_did = ?3)",
            rusqlite::params![conversation_id, message_id, sender],
        )
        .map_err(|e| MLSError::Internal(format!("erase request opening preview: {e}")))?;
    let key = format!("c33_pending_opening:{conversation_id}");
    let staged = tx
        .get_account_meta(&key)?
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    if let Some(staged) = staged {
        let same_id = staged["message_id"].as_str() == Some(message_id);
        let same_sender = sender.is_none_or(|s| staged["sender_did"].as_str() == Some(s));
        if same_id && same_sender {
            // The value a decline leaves: acceptance then archives nothing.
            tx.put_account_meta(&key, "", now_ms)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "message_erase_unit_tests.rs"]
mod tests;
