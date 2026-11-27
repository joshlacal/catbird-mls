//! Delete for me (F1) and scrub-on-unsend (F2): an erased message leaves no local content
//! (row, archive evidence, queued copy), a durable marker keeps every later path (own echo,
//! restore, reindex) from bringing it back, and delete for me writes only an owner tombstone
//! to this account's mailbox, never anything to the conversation Space.

use super::*;

fn visible(client: &CatbirdMlsClient, cid: &str, id: &str) -> bool {
    client
        .list_messages(cid, None, 100)
        .unwrap()
        .iter()
        .any(|row| row.message_id == id)
}

fn has_row(client: &CatbirdMlsClient, id: &str) -> bool {
    client
        .db()
        .read_tx(|tx| tx.get_message(id))
        .unwrap()
        .is_some()
}

fn deleted_marker(client: &CatbirdMlsClient, cid: &str, id: &str) -> Option<Value> {
    labyrinth_state(client, &format!("native.deleted:{cid}:{id}"))
        .map(|raw| serde_json::from_slice(&raw).unwrap())
}

fn last_seq(client: &CatbirdMlsClient, cid: &str) -> i64 {
    client
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap()
        .last_seq
}

/// F2 own device: unsend erases the row and its retained evidence, not just hides them. The
/// own echo that arrives afterwards verifies, advances the cursor and stores nothing; a
/// restore and a reindex keep it gone.
#[test]
fn own_unsend_erases_content_and_the_later_echo_is_skipped() {
    let f = send_order_fixture(false);
    let (cid, alice) = (f.cid.as_str(), &f.alice);
    let id = new_id();
    alice.send_message(cid, &id, "take this back").unwrap();
    assert!(labyrinth_state(alice, &format!("native.message:{cid}:{id}")).is_some());
    let before = last_seq(alice, cid);

    alice.unsend_message(cid, &id).expect("unsend");
    assert!(!has_row(alice, &id), "the plaintext row is erased");
    assert!(
        labyrinth_state(alice, &format!("native.message:{cid}:{id}")).is_none(),
        "retained archive evidence is erased"
    );
    assert!(labyrinth_state(alice, &format!("native.unsent:{cid}:{id}")).is_some());
    assert_eq!(alice.unsend_message(cid, &id).unwrap(), 0, "idempotent");

    alice
        .sync()
        .expect("the own echo of an erased message verifies and is skipped");
    assert!(!has_row(alice, &id), "the echo stores nothing");
    assert!(last_seq(alice, cid) >= before, "the cursor never regresses");

    alice
        .restore_conversation_from_owner_mailbox(cid)
        .expect("restore");
    alice.verify_and_reindex_history(cid).expect("reindex");
    assert!(
        !has_row(alice, &id),
        "restore and reindex never resurrect it"
    );
    assert!(!visible(alice, cid, &id));
}

/// The echo of an erased own message is still verified before the cursor moves: sync after
/// the erase reaches the same head as a peer that kept the message.
#[test]
fn erased_own_echo_advances_the_cursor_to_the_peer_head() {
    let f = send_order_fixture(false);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    let id = new_id();
    alice.send_message(cid, &id, "soon gone").unwrap();
    alice.unsend_message(cid, &id).unwrap();
    let after = new_id();
    bob.sync().unwrap();
    bob.send_message(cid, &after, "after").unwrap();
    alice.sync().expect("alice syncs past her erased message");
    assert!(visible(alice, cid, &after), "later messages still arrive");
    assert!(!has_row(alice, &id));
    assert_eq!(last_seq(alice, cid), last_seq(bob, cid));
}

/// F2 peer device: a verified author redaction loaded from history erases the peer's local
/// copy under an `unsent` marker.
#[test]
fn peer_restore_erases_a_message_its_author_unsent() {
    let f = send_order_fixture(false);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code().expect("bob enrolls his archive");
    let id = new_id();
    alice
        .send_message(cid, &id, "archived then unsent")
        .unwrap();
    alice
        .flush_labyrinth_queue()
        .expect("alice archives her copy");
    bob.sync().unwrap();
    assert!(has_row(bob, &id));

    alice
        .unsend_message(cid, &id)
        .expect("alice publishes the redaction");
    bob.restore_conversation_from_owner_mailbox(cid)
        .expect("bob loads history");
    assert!(!has_row(bob, &id), "the redaction erases bob's copy");
    assert!(labyrinth_state(bob, &format!("native.message:{cid}:{id}")).is_none());
    assert!(labyrinth_state(bob, &format!("native.unsent:{cid}:{id}")).is_some());
}

/// F1: delete for me on a peer's message erases it here and writes an owner tombstone to the
/// mailbox. A second call is a no-op. A restore never brings it back, and a device that loads
/// the tombstone from history (the marker missing locally) erases its copy.
#[test]
fn delete_for_me_erases_locally_publishes_a_tombstone_and_is_not_restored() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code().expect("bob enrolls his archive");
    let id = new_id();
    alice
        .send_message(cid, &id, "bob deletes this for himself")
        .unwrap();
    alice.flush_labyrinth_queue().unwrap();
    bob.sync().unwrap();
    bob.flush_labyrinth_queue().unwrap();
    assert!(has_row(bob, &id));

    let writes = ds.archive_auth.committed_space_write_count();
    bob.delete_message_for_me(cid, &id).expect("delete for me");
    assert!(!has_row(bob, &id));
    assert!(labyrinth_state(bob, &format!("native.message:{cid}:{id}")).is_none());
    let marker = deleted_marker(bob, cid, &id).expect("durable marker");
    assert_eq!(marker["published"], json!(true), "{marker}");
    assert_eq!(marker["sender_did"], json!(ALICE_DID));
    let after_tombstone = ds.archive_auth.committed_space_write_count();
    assert!(after_tombstone > writes, "the owner tombstone is written");
    assert!(has_row(alice, &id), "the author keeps her copy");

    bob.delete_message_for_me(cid, &id).expect("idempotent");
    assert_eq!(
        ds.archive_auth.committed_space_write_count(),
        after_tombstone,
        "no second tombstone"
    );

    bob.restore_conversation_from_owner_mailbox(cid).unwrap();
    assert!(!has_row(bob, &id), "restore does not resurrect it");

    // As on another device of bob's: no local marker, the tombstone arrives with history.
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_state WHERE state_key = ?1",
                    [format!("native.deleted:{cid}:{id}")],
                )
                .unwrap();
            Ok(())
        })
        .unwrap();
    bob.restore_conversation_from_owner_mailbox(cid).unwrap();
    assert!(!has_row(bob, &id));
    let marker = deleted_marker(bob, cid, &id).expect("history writes the marker");
    assert_eq!(marker["published"], json!(true));
    assert!(!visible(bob, cid, &id));
}

/// F1 with history backup off for the conversation: a local erase only, no tombstone and no
/// pending publish.
#[test]
fn delete_for_me_of_an_unarchived_message_is_local_only() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    bob.set_history_backup_enabled(cid, false).unwrap();
    alice.sync().unwrap();
    let id = new_id();
    alice.send_message(cid, &id, "never archived").unwrap();
    let writes = ds.archive_auth.committed_space_write_count();
    alice
        .delete_message_for_me(cid, &id)
        .expect("delete for me");
    assert!(!has_row(alice, &id));
    let marker = deleted_marker(alice, cid, &id).expect("marker");
    assert_eq!(marker["published"], json!(false));
    assert!(alice
        .db()
        .read_tx(|tx| tx.get_pending_op("native_delete_for_me", &id))
        .unwrap()
        .is_none());
    assert_eq!(ds.archive_auth.committed_space_write_count(), writes);
    alice
        .sync()
        .expect("own echo of a deleted-for-me message is skipped");
    assert!(!has_row(alice, &id));
}

/// Unknown ids are refused; system rows cannot be deleted for me.
#[test]
fn delete_for_me_rejects_unknown_and_system_messages() {
    let f = send_order_fixture(true);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    assert!(alice.delete_message_for_me(cid, &new_id()).is_err());
    let off = bob.set_history_backup_enabled(cid, false).unwrap();
    alice.sync().unwrap();
    let error = alice
        .delete_message_for_me(cid, &off.message_id)
        .expect_err("system row");
    assert!(error.to_string().contains("system"), "{error}");
    assert!(has_row(alice, &off.message_id));
}

fn put_deleted_marker(client: &CatbirdMlsClient, cid: &str, id: &str, sender: &str) {
    let marker = json!({"v": 1, "at_ms": 1, "sender_did": sender, "published": true});
    client
        .db()
        .write_tx(|tx| {
            tx.put_labyrinth_state(
                &format!("native.deleted:{cid}:{id}"),
                &serde_json::to_vec(&marker).unwrap(),
                1,
            )
        })
        .unwrap();
}

/// A tombstone can reach a device before the live entry does (another device of the account
/// deleted it and this one loaded history first). Sync then verifies the entry's receipt,
/// moves the cursor and stores nothing; later messages still arrive.
#[test]
fn live_entry_of_a_message_already_deleted_for_me_is_verified_and_not_stored() {
    let f = send_order_fixture(false);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    let id = new_id();
    alice
        .send_message(cid, &id, "deleted on bob's other device")
        .unwrap();
    put_deleted_marker(bob, cid, &id, ALICE_DID);
    bob.sync().expect("bob syncs past the deleted entry");
    assert!(
        !has_row(bob, &id),
        "nothing is stored for an erased message"
    );
    assert!(labyrinth_state(bob, &format!("native.message:{cid}:{id}")).is_none());
    let after = new_id();
    alice.send_message(cid, &after, "later").unwrap();
    bob.sync().unwrap();
    assert!(visible(bob, cid, &after));
    assert_eq!(last_seq(bob, cid), last_seq(alice, cid));
}

/// A marker naming a different sender does not cover the entry: it is applied and listed.
#[test]
fn deleted_marker_for_another_sender_does_not_skip_the_entry() {
    let f = send_order_fixture(false);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    let id = new_id();
    alice.send_message(cid, &id, "real message").unwrap();
    put_deleted_marker(bob, cid, &id, EVE_DID);
    bob.sync().unwrap();
    assert!(has_row(bob, &id), "the entry is applied");
    assert!(
        visible(bob, cid, &id),
        "a marker bound to eve does not hide alice's row"
    );
}

fn put_unsent_marker(client: &CatbirdMlsClient, cid: &str, id: &str, sender: &str) {
    let marker = json!({"v": 1, "kind": "unsent-peer", "senders": [sender]});
    client
        .db()
        .write_tx(|tx| {
            tx.put_labyrinth_state(
                &format!("native.unsent:{cid}:{id}"),
                &serde_json::to_vec(&marker).unwrap(),
                1,
            )
        })
        .unwrap();
}

/// Rows, archive state and queued copies whose text contains `needle`.
fn rows_containing(client: &CatbirdMlsClient, needle: &str) -> i64 {
    client
        .db()
        .read_tx(|tx| {
            Ok(tx
                .conn()
                .query_row(
                    "SELECT (SELECT count(*) FROM messages WHERE instr(plaintext_json, ?1) > 0)
                     + (SELECT count(*) FROM labyrinth_state
                        WHERE instr(CAST(value_bytes AS TEXT), ?1) > 0)
                     + (SELECT count(*) FROM labyrinth_queue
                        WHERE instr(CAST(payload_bytes AS TEXT), ?1) > 0)",
                    [needle],
                    |row| row.get(0),
                )
                .unwrap())
        })
        .unwrap()
}

/// Finding 1: Labyrinth verifies who signed a redaction, not that the signer wrote the id.
/// Eve's verified redaction naming alice's message id leaves a marker bound to eve. It must
/// not suppress alice's live entry, her restored copy on a fresh device, or a reindex.
#[test]
fn a_redaction_naming_another_senders_id_suppresses_nothing_of_theirs() {
    let f = send_order_fixture(false);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code().expect("bob enrolls his archive");
    let id = new_id();
    alice.send_message(cid, &id, "alice wrote this").unwrap();
    alice.flush_labyrinth_queue().unwrap();
    put_unsent_marker(bob, cid, &id, EVE_DID);

    bob.sync().unwrap();
    assert!(has_row(bob, &id), "alice's live entry is stored");
    assert!(visible(bob, cid, &id));

    // As on a fresh device: no local row or evidence, only eve's marker.
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute("DELETE FROM messages WHERE message_id = ?1", [&id])
                .unwrap();
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_state WHERE state_key = ?1",
                    [format!("native.message:{cid}:{id}")],
                )
                .unwrap();
            Ok(())
        })
        .unwrap();
    bob.restore_conversation_from_owner_mailbox(cid)
        .expect("restore");
    assert!(has_row(bob, &id), "alice's restored copy is kept");
    assert!(visible(bob, cid, &id));
    bob.verify_and_reindex_history(cid).expect("reindex");
    assert!(has_row(bob, &id), "reindex keeps it");
}

fn edit_frame(target: &str, text: &str) -> String {
    json!({
        "version": 1,
        "messageType": "edit",
        "edit": {"targetMessageId": target, "newText": text},
    })
    .to_string()
}

/// Finding 2: an edit row carries the message's current text. Delete for me erases the
/// author's edits with the message; a later edit of it is verified and stored nowhere; a
/// restore and a reindex bring neither back.
#[test]
fn delete_for_me_erases_the_messages_edits_and_later_edits_are_not_stored() {
    let f = send_order_fixture(false);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code().expect("bob enrolls his archive");
    let id = new_id();
    alice.send_message(cid, &id, "original text").unwrap();
    let edit = new_id();
    alice
        .send_message(cid, &edit, &edit_frame(&id, "EDITED-SECRET"))
        .unwrap();
    alice.flush_labyrinth_queue().unwrap();
    bob.sync().unwrap();
    bob.flush_labyrinth_queue().unwrap();
    assert!(has_row(bob, &edit));
    assert!(rows_containing(bob, "EDITED-SECRET") > 0);

    bob.delete_message_for_me(cid, &id).expect("delete for me");
    assert!(!has_row(bob, &id));
    assert!(!has_row(bob, &edit), "the edit row goes with the message");
    assert_eq!(
        rows_containing(bob, "EDITED-SECRET"),
        0,
        "no row, evidence or queued copy keeps the edited text"
    );

    let later = new_id();
    alice
        .send_message(cid, &later, &edit_frame(&id, "LATER-SECRET"))
        .unwrap();
    bob.sync().expect("bob syncs past the later edit");
    assert!(!has_row(bob, &later));
    assert_eq!(rows_containing(bob, "LATER-SECRET"), 0);
    assert_eq!(last_seq(bob, cid), last_seq(alice, cid));

    alice.flush_labyrinth_queue().unwrap();
    bob.restore_conversation_from_owner_mailbox(cid).unwrap();
    bob.verify_and_reindex_history(cid).unwrap();
    assert!(!has_row(bob, &id) && !has_row(bob, &edit) && !has_row(bob, &later));
    assert_eq!(rows_containing(bob, "EDITED-SECRET"), 0);
    assert_eq!(rows_containing(bob, "LATER-SECRET"), 0);
}
