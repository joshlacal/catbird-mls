use super::*;
use crate::storage::{LabyrinthQueueRow, MessageRow, MlsAccountDb};

const CID: &str = "c-1";
const MID: &str = "m-1";

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
        .write_tx(|tx| erase_message_content(tx, CID, MID, &key, &marker(), 5))
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
    assert_eq!(
        db.read_tx(|tx| erased_marker_sender(tx, CID, MID)).unwrap(),
        Some(Some("did:plc:bob".to_owned()))
    );
}

#[test]
fn erase_is_idempotent() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let key = unsent_message_key(CID, MID);
    let first = db
        .write_tx(|tx| erase_message_content(tx, CID, MID, &key, b"unsent", 5))
        .unwrap();
    let second = db
        .write_tx(|tx| erase_message_content(tx, CID, MID, &key, b"unsent", 6))
        .unwrap();
    assert!(first.existed);
    assert_eq!(second, ErasedMessage::default());
    assert_eq!(state(&db, &key).as_deref(), Some(&b"unsent"[..]));
    assert_eq!(
        db.read_tx(|tx| erased_marker_sender(tx, CID, MID)).unwrap(),
        Some(None)
    );
}

#[test]
fn erase_rolls_back_with_its_transaction() {
    let db = MlsAccountDb::open_in_memory_for_test().unwrap();
    seed(&db, MID);
    let key = deleted_for_me_key(CID, MID);
    let crashed: Result<(), MLSError> = db.write_tx(|tx| {
        erase_message_content(tx, CID, MID, &key, &marker(), 5)?;
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
        .write_tx(|tx| erase_message_content(tx, CID, MID, &key, &marker(), 6))
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
        erase_message_content(tx, CID, MID, &deleted_for_me_key(CID, MID), &marker(), 5)?;
        erase_message_content(
            tx,
            CID,
            "m-2",
            &unsent_message_key(CID, "m-2"),
            b"unsent",
            5,
        )?;
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
        .write_tx(|tx| {
            erase_message_content(
                tx,
                "other",
                MID,
                &deleted_for_me_key("other", MID),
                &marker(),
                5,
            )
        })
        .unwrap();
    assert!(!erased.existed);
    assert!(db.read_tx(|tx| tx.get_message(MID)).unwrap().is_some());
}
