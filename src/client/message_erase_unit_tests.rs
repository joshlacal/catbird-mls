use super::*;
use crate::storage::{LabyrinthQueueRow, MessageRow, MlsAccountDb};

const CID: &str = "c-1";
const MID: &str = "m-1";
const BOB: &str = "did:plc:bob";
const EVE: &str = "did:plc:eve";
const DFM: EraseKind<'static> = EraseKind::DeletedForMe { published: false };

fn row(message_id: &str) -> MessageRow {
    MessageRow {
        message_id: message_id.into(),
        conversation_id: CID.into(),
        group_id: vec![1, 2, 3],
        epoch: 1,
        seq: 7,
        sender_did: "did:plc:bob".into(),
        sender_device_id: "dev".into(),
        plaintext_json: r#"{"version":1,"messageType":"text","text":"secret","embed":{"images":[{"blobId":"b-2"},{"blobId":"b-1"}]}}"#.into(),
        created_at_ms: 1_000,
        is_own: false,
    }
}

fn seed(db: &MlsAccountDb, message_id: &str) {
    db.write_tx(|tx| {
        tx.insert_message(&row(message_id))?;
        tx.put_labyrinth_state(&format!("native.message:{CID}:{message_id}"), b"{}", 1)?;
        tx.put_labyrinth_state(
            &format!("push.verified_receipt:{CID}:{message_id}"),
            b"1",
            1,
        )?;
        tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
            item_id: message_id.into(),
            conversation_id: CID.into(),
            group_id_hex: "010203".into(),
            seq: 7,
            payload_bytes: b"{}".to_vec(),
            created_at_ms: 1,
        })?;
        tx.put_pending_op(
            crate::push::processor::NATIVE_ARCHIVE_RECEIPT_OP,
            message_id,
            "{}",
            1,
        )
    })
    .unwrap();
}

fn state(db: &MlsAccountDb, key: &str) -> Option<Vec<u8>> {
    db.read_tx(|tx| tx.get_labyrinth_state(key)).unwrap()
}

fn unsent(db: &MlsAccountDb, message_id: &str) -> UnsentMarker {
    serde_json::from_slice(&state(db, &unsent_message_key(CID, message_id)).unwrap()).unwrap()
}

fn listed(db: &MlsAccountDb) -> Vec<String> {
    db.read_tx(|tx| tx.list_messages(CID, None, 10))
        .unwrap()
        .into_iter()
        .map(|row| row.message_id)
        .collect()
}

fn insert_row(db: &MlsAccountDb, message_id: &str, sender: &str, plaintext_json: &str) {
    db.write_tx(|tx| {
        tx.insert_message(&MessageRow {
            sender_did: sender.into(),
            plaintext_json: plaintext_json.into(),
            ..row(message_id)
        })
    })
    .unwrap();
}

fn marker() -> Vec<u8> {
    DeletedForMeMarker {
        v: 1,
        at_ms: 5,
        sender_did: "did:plc:bob".into(),
        published: false,
    }
    .to_bytes()
    .unwrap()
}

#[test]
fn erase_removes_row_evidence_queue_and_pending_op_and_writes_marker() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let key = deleted_for_me_key(CID, MID);
    let erased = db
        .write_tx(|tx| erase_message_content(tx, CID, MID, Some(BOB), DFM, 5))
        .unwrap();
    assert!(erased.existed);
    assert_eq!(erased.blob_ids, vec!["b-1".to_owned(), "b-2".to_owned()]);
    assert_eq!(erased.sender_did.as_deref(), Some("did:plc:bob"));
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_none());
    assert!(state(&db, &format!("native.message:{CID}:{MID}")).is_none());
    assert!(state(&db, &format!("push.verified_receipt:{CID}:{MID}")).is_none());
    assert!(db
        .read_tx(|tx| tx.list_labyrinth_queue(Some(CID), 10))
        .unwrap()
        .is_empty());
    assert!(db
        .read_tx(|tx| tx.get_pending_op(crate::push::processor::NATIVE_ARCHIVE_RECEIPT_OP, MID))
        .unwrap()
        .is_none());
    assert_eq!(state(&db, &key), Some(marker()));
    assert!(db.read_tx(|tx| is_locally_erased(tx, CID, MID)).unwrap());
    assert!(db.read_tx(|tx| is_erased_for(tx, CID, MID, BOB)).unwrap());
    assert!(!db.read_tx(|tx| is_erased_for(tx, CID, MID, EVE)).unwrap());
}

#[test]
fn erase_is_idempotent() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let first = db
        .write_tx(|tx| {
            erase_message_content(tx, CID, MID, Some(BOB), EraseKind::Unsent("unsent"), 5)
        })
        .unwrap();
    let second = db
        .write_tx(|tx| {
            erase_message_content(tx, CID, MID, Some(BOB), EraseKind::Unsent("unsent"), 6)
        })
        .unwrap();
    assert!(first.existed);
    assert_eq!(second, ErasedMessage::default());
    assert_eq!(unsent(&db, MID).senders, vec![BOB.to_owned()]);
    assert!(db.read_tx(|tx| is_erased_for(tx, CID, MID, BOB)).unwrap());
    assert!(!db.read_tx(|tx| is_erased_for(tx, CID, MID, EVE)).unwrap());
}

#[test]
fn erase_rolls_back_with_its_transaction() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let key = deleted_for_me_key(CID, MID);
    let crashed: Result<(), MLSError> = db.write_tx(|tx| {
        erase_message_content(tx, CID, MID, Some(BOB), DFM, 5)?;
        Err(MLSError::Internal("crash before commit".into()))
    });
    assert!(crashed.is_err());
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_some());
    assert!(
        state(&db, &key).is_none(),
        "marker and erase roll back together"
    );
    assert!(state(&db, &format!("native.message:{CID}:{MID}")).is_some());
    let erased = db
        .write_tx(|tx| erase_message_content(tx, CID, MID, Some(BOB), DFM, 6))
        .unwrap();
    assert!(erased.existed);
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_none());
}

#[test]
fn list_messages_hides_a_row_under_either_marker() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    seed(&db, "m-2");
    seed(&db, "m-3");
    db.write_tx(|tx| {
        erase_message_content(tx, CID, MID, Some(BOB), DFM, 5)?;
        erase_message_content(tx, CID, "m-2", Some(BOB), EraseKind::Unsent("unsent"), 5)?;
        // A row put back by any later path stays hidden by its marker.
        tx.insert_message(&row(MID))?;
        tx.insert_message(&row("m-2"))
    })
    .unwrap();
    let listed: Vec<String> = db
        .read_tx(|tx| tx.list_messages(CID, None, 10))
        .unwrap()
        .into_iter()
        .map(|row| row.message_id)
        .collect();
    assert_eq!(listed, vec!["m-3".to_owned()]);
}

#[test]
fn erase_leaves_other_conversations_rows() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let erased = db
        .write_tx(|tx| erase_message_content(tx, "other", MID, Some(BOB), DFM, 5))
        .unwrap();
    assert!(!erased.existed);
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_some());
}

/// Finding 1: a verified redaction by eve that names bob's message id erases nothing of bob's.
/// The marker it leaves covers eve only.
#[test]
fn a_redaction_naming_another_senders_id_keeps_that_message() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let erased = db
        .write_tx(|tx| {
            erase_message_content(tx, CID, MID, Some(EVE), EraseKind::Unsent("unsent-peer"), 5)
        })
        .unwrap();
    assert!(!erased.existed);
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_some());
    assert!(state(&db, &format!("native.message:{CID}:{MID}")).is_some());
    assert_eq!(
        db.read_tx(|tx| tx.list_labyrinth_queue(Some(CID), 10))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(unsent(&db, MID).senders, vec![EVE.to_owned()]);
    assert!(db.read_tx(|tx| is_erased_for(tx, CID, MID, EVE)).unwrap());
    assert!(!db.read_tx(|tx| is_erased_for(tx, CID, MID, BOB)).unwrap());
    assert_eq!(listed(&db), vec![MID.to_owned()], "bob's row stays listed");
}

/// Finding 1, fresh restore: with no local row the marker is still bound to the redaction's
/// author, so bob's copy restored afterwards is kept and listed.
#[test]
fn a_redaction_marker_without_a_local_row_is_bound_to_its_author() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    db.write_tx(|tx| {
        erase_message_content(tx, CID, MID, Some(EVE), EraseKind::Unsent("unsent-peer"), 5)
    })
    .unwrap();
    assert!(db.read_tx(|tx| is_locally_erased(tx, CID, MID)).unwrap());
    assert!(!db.read_tx(|tx| is_erased_for(tx, CID, MID, BOB)).unwrap());
    let text = r#"{"version":1,"messageType":"text","text":"bob"}"#;
    assert!(!db
        .read_tx(|tx| is_frame_erased(tx, CID, MID, BOB, text))
        .unwrap());
    insert_row(&db, MID, BOB, text);
    assert_eq!(listed(&db), vec![MID.to_owned()]);

    // Bob's own later unsend still erases his copy: the marker widens to both senders.
    db.write_tx(|tx| {
        erase_message_content(tx, CID, MID, Some(BOB), EraseKind::Unsent("unsent"), 6)
    })
    .unwrap();
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_none());
    assert_eq!(
        unsent(&db, MID).senders,
        vec![BOB.to_owned(), EVE.to_owned()]
    );
}

/// A marker written before markers named their sender covers every sender.
#[test]
fn a_legacy_unsent_marker_covers_every_sender() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    db.write_tx(|tx| tx.put_labyrinth_state(&unsent_message_key(CID, MID), b"unsent", 1))
        .unwrap();
    assert!(db.read_tx(|tx| is_erased_for(tx, CID, MID, BOB)).unwrap());
    assert!(db.read_tx(|tx| is_erased_for(tx, CID, MID, EVE)).unwrap());
    insert_row(&db, MID, BOB, "{}");
    assert!(listed(&db).is_empty());
}

/// Finding 2: an edit row holds the message's current text. Erasing the message erases the
/// sender's edits (with their evidence) under their own markers; another sender's edit of the
/// same id is not the author's and is kept. A later edit of the erased message is refused.
#[test]
fn erase_removes_the_senders_edits_of_the_message() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let edit = |target: &str, text: &str| {
        format!(
            r#"{{"version":1,"messageType":"edit","edit":{{"targetMessageId":"{target}","newText":"{text}"}}}}"#
        )
    };
    insert_row(&db, "e-1", BOB, &edit(MID, "edited secret"));
    db.write_tx(|tx| tx.put_labyrinth_state(&format!("native.message:{CID}:e-1"), b"{}", 1))
        .unwrap();
    insert_row(&db, "e-2", EVE, &edit(MID, "not the author"));
    // As stored on receive: a frame without a top-level text string is wrapped in one.
    let wrapped = |frame: String| serde_json::json!({ "text": frame }).to_string();
    insert_row(&db, "e-5", BOB, &wrapped(edit(MID, "wrapped secret")));
    insert_row(&db, "x", BOB, "not json");
    db.write_tx(|tx| erase_message_content(tx, CID, MID, Some(BOB), DFM, 5))
        .unwrap();
    assert!(db.read_tx(|tx| tx.get_message("e-1")).unwrap().is_none());
    assert!(state(&db, &format!("native.message:{CID}:e-1")).is_none());
    assert!(db.read_tx(|tx| is_erased_for(tx, CID, "e-1", BOB)).unwrap());
    assert!(db.read_tx(|tx| tx.get_message("e-5")).unwrap().is_none());
    assert!(db.read_tx(|tx| tx.get_message("e-2")).unwrap().is_some());
    assert!(db.read_tx(|tx| tx.get_message("x")).unwrap().is_some());
    let no_row_has_text = db
        .read_tx(|tx| tx.list_messages(CID, None, 10))
        .unwrap()
        .iter()
        .all(|row| {
            !row.plaintext_json.contains("edited secret")
                && !row.plaintext_json.contains("wrapped secret")
        });
    assert!(no_row_has_text);

    let late = edit(MID, "edited again");
    assert!(db
        .read_tx(|tx| is_frame_erased(tx, CID, "e-3", BOB, &late))
        .unwrap());
    assert!(!db
        .read_tx(|tx| is_frame_erased(tx, CID, "e-4", EVE, &late))
        .unwrap());
    assert!(db
        .read_tx(|tx| is_frame_erased(tx, CID, "e-6", BOB, &wrapped(late.clone())))
        .unwrap());
}

/// Finding 3: a direct-request opening keeps its text in the request preview and the staged
/// opening. Erasing the opening clears both.
#[test]
fn erase_clears_a_request_opening_preview_and_staged_opening() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let stage_key = format!("c33_pending_opening:{CID}");
    db.write_tx(|tx| {
        tx.upsert_request(&crate::storage::RequestRow {
            request_id: "r-1".into(),
            conversation_id: CID.into(),
            sender_did: BOB.into(),
            recipient_did: EVE.into(),
            consent: "incomingPending".into(),
            first_message_id: Some(MID.into()),
            first_message_archived: false,
            payload_json: r#"{"text":"secret opening"}"#.into(),
            expires_at_ms: 9,
            updated_at_ms: 1,
        })?;
        tx.put_account_meta(
            &stage_key,
            &serde_json::json!({
                "message_id": MID,
                "sender_did": BOB,
                "plaintext_json": "secret opening",
            })
            .to_string(),
            1,
        )
    })
    .unwrap();
    db.write_tx(|tx| erase_message_content(tx, CID, MID, Some(BOB), DFM, 5))
        .unwrap();
    let request = db
        .read_tx(|tx| tx.list_requests(None))
        .unwrap()
        .into_iter()
        .find(|row| row.request_id == "r-1")
        .unwrap();
    assert_eq!(request.payload_json, "{}");
    assert_eq!(request.consent, "incomingPending", "consent is untouched");
    assert_eq!(
        db.read_tx(|tx| tx.get_account_meta(&stage_key))
            .unwrap()
            .as_deref(),
        Some("")
    );
}
