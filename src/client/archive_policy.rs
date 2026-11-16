//! Conversation history-backup policy. Every archive enqueue passes through this module.
//!
//! `historyBackup` lives in the encrypted group metadata. The per-sequence flip log keeps an
//! already accepted message's decision stable even when a later signed transition turns backup
//! back on. A sender's authenticated `noBackup` frame is an independent, permanent veto.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::MLSError;
use crate::metadata::GroupMetadataV1;
use crate::storage::{GroupMetadataRow, LabyrinthQueueRow, SqlReadTx, SqlTx};

use super::QueuedLabyrinthArchivePayload;

const HISTORY_BACKUP: &str = "historyBackup";
const FLIPS_PREFIX: &str = "archive.policy.flips:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Flip {
    seq: i64,
    enabled: bool,
}

fn flip_key(conversation_id: &str) -> String {
    format!("{FLIPS_PREFIX}{conversation_id}")
}

fn flips(tx: &SqlReadTx<'_>, conversation_id: &str) -> Result<Vec<Flip>, MLSError> {
    tx.get_account_meta(&flip_key(conversation_id))?
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|e| {
                MLSError::Cryptography(format!("invalid archive policy flip log: {e}"))
            })
        })
        .transpose()
        .map(|flips| flips.unwrap_or_default())
}

/// An absent field is the pre-policy default (backup on). A malformed present field is off.
pub(crate) fn metadata_enabled(metadata: &GroupMetadataV1) -> bool {
    match metadata.extra.get(HISTORY_BACKUP) {
        None => true,
        Some(value) => value.as_bool().unwrap_or(false),
    }
}

pub(crate) fn set_metadata_enabled(metadata: &mut GroupMetadataV1, enabled: bool) {
    metadata.extra.insert(HISTORY_BACKUP.into(), json!(enabled));
}

fn row_enabled(row: &GroupMetadataRow) -> bool {
    serde_json::from_str::<GroupMetadataV1>(&row.metadata_json)
        .map(|metadata| metadata_enabled(&metadata))
        .unwrap_or(false)
}

pub(crate) fn current_enabled(tx: &SqlReadTx<'_>, conversation_id: &str) -> Result<bool, MLSError> {
    if let Some(last) = flips(tx, conversation_id)?.last() {
        return Ok(last.enabled);
    }
    Ok(tx
        .get_group_metadata(conversation_id)?
        .as_ref()
        .is_none_or(row_enabled))
}

fn enabled_at_seq(tx: &SqlReadTx<'_>, conversation_id: &str, seq: i64) -> Result<bool, MLSError> {
    let flips = flips(tx, conversation_id)?;
    if !flips.is_empty() && seq > 0 {
        return Ok(flips
            .iter()
            .rev()
            .find(|flip| flip.seq <= seq)
            .is_none_or(|flip| flip.enabled));
    }
    current_enabled(tx, conversation_id)
}

fn record_flip(
    tx: &SqlTx<'_>,
    conversation_id: &str,
    seq: i64,
    enabled: bool,
    now_ms: i64,
) -> Result<bool, MLSError> {
    // Sequence zero is the baseline for a restored metadata snapshot whose
    // sequencer position is unavailable. It must survive a later verbatim row
    // overwrite, or an unauthorized ON snapshot would silently re-enable backup.
    if seq < 0 {
        return Ok(false);
    }
    let mut log = flips(tx, conversation_id)?;
    let was_latest = log.last().is_none_or(|last| seq >= last.seq);
    match log.binary_search_by_key(&seq, |flip| flip.seq) {
        Ok(index) => {
            // An authenticated coordinate must never describe two different settings.
            if log[index].enabled != enabled {
                return Err(MLSError::Cryptography(
                    "conflicting archive policy at one sequence".into(),
                ));
            }
        }
        Err(index) => log.insert(index, Flip { seq, enabled }),
    }
    tx.put_account_meta(
        &flip_key(conversation_id),
        &serde_json::to_string(&log)?,
        now_ms,
    )?;
    Ok(was_latest)
}

/// Apply a decrypted snapshot without letting a Commit, reset, or recovery silently re-enable
/// backup. Only a separately signed metadata transition may do that.
pub(crate) fn accept_snapshot(
    tx: &SqlTx<'_>,
    conversation_id: &str,
    seq: i64,
    metadata: &GroupMetadataV1,
    signed_metadata_transition: bool,
    now_ms: i64,
) -> Result<(), MLSError> {
    let before = current_enabled(tx, conversation_id)?;
    let requested = metadata_enabled(metadata);
    let explicit_on = metadata.extra.get(HISTORY_BACKUP) == Some(&json!(true));
    if !before && requested && !(signed_metadata_transition && explicit_on) {
        // The caller still stores the authenticated snapshot verbatim. Preserve
        // the stricter effective policy in the sequenced log even if this is
        // the first flip this device has ever observed.
        record_flip(tx, conversation_id, seq, false, now_ms)?;
        return Ok(());
    }
    if before != requested {
        record_flip(tx, conversation_id, seq, requested, now_ms)?;
    }
    Ok(())
}

fn frame_value(frame_json: &str) -> Option<Value> {
    serde_json::from_str::<Value>(frame_json).ok()
}

/// Invalid frame policy values are treated as an opt-out. The MLS payload's JSON object itself
/// is authenticated by the sender and must never be round-tripped through `MLSMessagePayload`.
pub(crate) fn frame_no_backup(frame_json: &str) -> bool {
    let Some(value) = frame_value(frame_json) else {
        return true;
    };
    match value.get("noBackup") {
        None => false,
        Some(value) => value.as_bool().unwrap_or(true),
    }
}

fn referenced_message_id(value: &Value) -> Option<&str> {
    [
        "/reaction/messageId",
        "/edit/messageId",
        "/edit/targetMessageId",
        "/unsend/messageId",
        "/editedMessageId",
    ]
    .into_iter()
    .find_map(|path| value.pointer(path).and_then(Value::as_str))
}

fn target_no_backup(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    frame_json: &str,
) -> Result<bool, MLSError> {
    let Some(value) = frame_value(frame_json) else {
        return Ok(true);
    };
    let Some(target_id) = referenced_message_id(&value) else {
        return Ok(false);
    };
    if let Some(raw) =
        tx.get_labyrinth_state(&format!("native.message:{conversation_id}:{target_id}"))?
    {
        if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
            if let Some(frame) = value.get("labyrinth_frame_json").and_then(Value::as_str) {
                return Ok(frame_no_backup(frame));
            }
        }
    }
    if let Some(row) = tx.get_message(target_id)? {
        if row.conversation_id == conversation_id {
            return Ok(frame_no_backup(&row.plaintext_json));
        }
    }
    // A reaction or edit whose target is unavailable cannot prove backup is permitted.
    Ok(true)
}

/// Stamp a normal outgoing application frame. C33's introduction uses a closed frame and never
/// calls this function; it can still be excluded by the enqueue wrapper after acceptance.
pub(crate) fn stamp_outgoing(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    frame_json: &str,
) -> Result<String, MLSError> {
    let mut value = frame_value(frame_json)
        .ok_or_else(|| MLSError::Cryptography("outgoing archive frame is not JSON".into()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        MLSError::Cryptography("outgoing archive frame is not a JSON object".into())
    })?;
    let already_off = object
        .get("noBackup")
        .is_some_and(|flag| flag != &json!(false));
    let inherited_off = target_no_backup(tx, conversation_id, frame_json)?;
    let group_off = !current_enabled(tx, conversation_id)?;
    object.insert("backupPolicy".into(), json!(1));
    if already_off || inherited_off || group_off {
        object.insert("noBackup".into(), json!(true));
    }
    Ok(value.to_string())
}

/// An authenticated flagged frame tightens the local group policy even before a metadata
/// transition arrives. A later, higher-sequence signed re-enable still wins.
pub(crate) fn observe_frame(
    tx: &SqlTx<'_>,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<(), MLSError> {
    let frame = frame_value(&payload.labyrinth_frame_json);
    let change = frame.as_ref().and_then(|frame| {
        (frame["messageType"] == "system"
            && frame["backupPolicy"] == 1
            && frame["noBackup"] == true)
            .then(|| frame.get("historyBackupChange").and_then(Value::as_bool))
            .flatten()
    });
    let requested = match change {
        Some(enabled) => enabled,
        None if frame_no_backup(&payload.labyrinth_frame_json) => false,
        None => return Ok(()),
    };
    if requested == enabled_at_seq(tx, &payload.conversation_id, payload.seq)? {
        return Ok(());
    }
    record_flip(
        tx,
        &payload.conversation_id,
        payload.seq,
        requested,
        payload.created_at_ms,
    )?;
    Ok(())
}

/// The notification extension may immediately adopt an opt-out, while an opt-in waits for the
/// foreground's canonical entry replay before it can loosen the setting.
pub(crate) fn observe_frame_tighten_only(
    tx: &SqlTx<'_>,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<(), MLSError> {
    if frame_value(&payload.labyrinth_frame_json)
        .as_ref()
        .is_some_and(|frame| frame["historyBackupChange"] == true)
    {
        return Ok(());
    }
    observe_frame(tx, payload)
}

pub(crate) fn should_enqueue(
    tx: &SqlReadTx<'_>,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<bool, MLSError> {
    should_archive_frame(
        tx,
        &payload.conversation_id,
        payload.seq,
        &payload.labyrinth_frame_json,
    )
}

pub(crate) fn should_archive_frame(
    tx: &SqlReadTx<'_>,
    conversation_id: &str,
    seq: i64,
    frame_json: &str,
) -> Result<bool, MLSError> {
    Ok(!frame_no_backup(frame_json)
        && !target_no_backup(tx, conversation_id, frame_json)?
        && enabled_at_seq(tx, conversation_id, seq)?)
}

/// Single write path for sender, witness, C33 acceptance, NSE completion and offline harness.
pub(crate) fn enqueue(
    tx: &SqlTx<'_>,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<bool, MLSError> {
    observe_frame(tx, payload)?;
    if !should_enqueue(tx, payload)? {
        return Ok(false);
    }
    tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
        item_id: payload.message_id.clone(),
        conversation_id: payload.conversation_id.clone(),
        group_id_hex: payload.group_id_hex.clone(),
        seq: payload.seq,
        payload_bytes: serde_json::to_vec(payload)?,
        created_at_ms: payload.created_at_ms,
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{MlsAccountDb, OpenMode};

    const CID: &str = "00000000-0000-4000-8000-000000000001";

    fn payload(id: &str, seq: i64, frame: &str) -> QueuedLabyrinthArchivePayload {
        QueuedLabyrinthArchivePayload {
            version: 1,
            message_id: id.into(),
            conversation_id: CID.into(),
            group_id_hex: "01".into(),
            epoch: 0,
            expected_member_dids: vec!["did:plc:alice".into()],
            seq,
            sender_did: "did:plc:alice".into(),
            sender_device_id: "device".into(),
            sequencer_did: "did:web:chat.catbird.blue".into(),
            space_uri: None,
            plaintext_json: frame.into(),
            labyrinth_frame_json: frame.into(),
            mls_ciphertext_b64: String::new(),
            frame_nonce_b64: None,
            sequencer_receipt_json: None,
            original_sender_attestation_json: None,
            created_at_ms: seq,
        }
    }

    fn db() -> (tempfile::TempDir, MlsAccountDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = MlsAccountDb::open_native(dir.path().join("policy.db"), &[7; 32], OpenMode::App)
            .unwrap();
        db.write_tx(|tx| {
            let row = super::super::chat_wire::group_metadata_row_from_v1(
                CID,
                1,
                0,
                &GroupMetadataV1::new("Chat", ""),
                1,
            )?;
            tx.upsert_group_metadata(&row)
        })
        .unwrap();
        (dir, db)
    }

    #[test]
    fn opt_out_sticks_to_frame_and_old_sequence_after_explicit_reenable() {
        let (_dir, db) = db();
        let ordinary = r#"{"version":1,"messageType":"text","text":"hello"}"#;
        db.write_tx(|tx| {
            assert!(enqueue(tx, &payload("before", 1, ordinary))?);
            let stamped = stamp_outgoing(tx, CID, ordinary)?;
            assert_eq!(frame_value(&stamped).unwrap()["backupPolicy"], 1);
            assert!(!frame_no_backup(&stamped));

            let off = r#"{"version":1,"messageType":"system","historyBackupChange":false,"backupPolicy":1,"noBackup":true}"#;
            assert!(!enqueue(tx, &payload("off", 2, off))?);
            assert!(!current_enabled(tx, CID)?);
            assert!(frame_no_backup(&stamp_outgoing(tx, CID, ordinary)?));
            assert!(!should_enqueue(tx, &payload("during", 3, ordinary))?);

            let on = r#"{"version":1,"messageType":"system","historyBackupChange":true,"backupPolicy":1,"noBackup":true}"#;
            assert!(!enqueue(tx, &payload("on", 4, on))?);
            assert!(current_enabled(tx, CID)?);
            assert!(!should_enqueue(tx, &payload("during", 3, ordinary))?);
            assert!(!should_enqueue(tx, &payload("off", 2, off))?);
            assert!(enqueue(tx, &payload("after", 5, ordinary))?);
            Ok(())
        })
        .unwrap();
        db.read_tx(|tx| {
            let ids: Vec<_> = tx
                .list_labyrinth_queue(Some(CID), 10)?
                .into_iter()
                .map(|row| row.item_id)
                .collect();
            assert_eq!(ids, ["before", "after"]);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn commit_snapshot_cannot_reenable_and_unknown_settings_survive() {
        let (_dir, db) = db();
        db.write_tx(|tx| {
            let mut off = GroupMetadataV1::new("Chat", "");
            off.extra
                .insert("futureSetting".into(), json!({"nested": [1, 2]}));
            set_metadata_enabled(&mut off, false);
            accept_snapshot(tx, CID, 2, &mut off, false, 2)?;
            tx.upsert_group_metadata(&super::super::chat_wire::group_metadata_row_from_v1(
                CID, 2, 0, &off, 2,
            )?)?;

            let mut carried = off.clone();
            carried.title = "Retitled".into();
            set_metadata_enabled(&mut carried, true);
            accept_snapshot(tx, CID, 3, &mut carried, false, 3)?;
            assert!(
                metadata_enabled(&carried),
                "the decrypted JSON stays verbatim"
            );
            assert!(!current_enabled(tx, CID)?, "the effective policy stays off");
            assert_eq!(carried.extra["futureSetting"], json!({"nested": [1, 2]}));

            // A separately signed metadata transition can opt back in.
            set_metadata_enabled(&mut carried, true);
            accept_snapshot(tx, CID, 4, &mut carried, true, 4)?;
            assert!(current_enabled(tx, CID)?);
            assert!(!enabled_at_seq(tx, CID, 3)?);
            assert!(enabled_at_seq(tx, CID, 4)?);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn restored_off_metadata_without_flip_log_cannot_be_loosened_by_snapshot() {
        let (_dir, db) = db();
        db.write_tx(|tx| {
            let mut off = GroupMetadataV1::new("Chat", "");
            set_metadata_enabled(&mut off, false);
            tx.upsert_group_metadata(&super::super::chat_wire::group_metadata_row_from_v1(
                CID, 1, 0, &off, 1,
            )?)?;
            assert!(flips(tx, CID)?.is_empty());

            let mut carried = off.clone();
            set_metadata_enabled(&mut carried, true);
            accept_snapshot(tx, CID, 0, &carried, false, 2)?;
            tx.upsert_group_metadata(&super::super::chat_wire::group_metadata_row_from_v1(
                CID, 2, 0, &carried, 2,
            )?)?;
            assert_eq!(
                flips(tx, CID)?,
                vec![Flip {
                    seq: 0,
                    enabled: false
                }]
            );
            assert!(!current_enabled(tx, CID)?);
            assert!(!enabled_at_seq(tx, CID, 1)?);
            assert!(frame_no_backup(&stamp_outgoing(
                tx,
                CID,
                r#"{"version":1,"messageType":"text"}"#,
            )?));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reaction_inherits_a_flagged_target() {
        let (_dir, db) = db();
        db.write_tx(|tx| {
            let target = payload(
                "target",
                1,
                r#"{"version":1,"messageType":"text","noBackup":true}"#,
            );
            tx.put_labyrinth_state(
                &format!("native.message:{CID}:target"),
                &serde_json::to_vec(&target)?,
                1,
            )?;
            let reaction = r#"{"version":1,"messageType":"reaction","reaction":{"messageId":"target","emoji":"👍","action":"add"}}"#;
            assert!(frame_no_backup(&stamp_outgoing(tx, CID, reaction)?));
            assert!(!should_enqueue(tx, &payload("reaction", 2, reaction))?);
            Ok(())
        })
        .unwrap();
    }
}
