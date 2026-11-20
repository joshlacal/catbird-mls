//! `LabyrinthBackupStatus::archive_established`: false until a session of this device has
//! opened or created the account's archive on the server, true from then on.

use super::*;
use catbird_mls::client::LabyrinthBackupStatus;

struct Fixture {
    tmp: tempfile::TempDir,
    ds: Arc<SharedMockDs>,
    keys: Arc<MemKeyStore>,
    device_id: String,
    alice: Arc<CatbirdMlsClient>,
    _bob: Arc<CatbirdMlsClient>,
}

const ALICE_STORE: &str = "established-alice";

/// Alice and Bob share a live group and Alice has one message queued for her archive. No
/// request has reached her mailbox Space yet.
fn enrolled_with_a_queued_message() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let keys = Arc::new(MemKeyStore::new());
    let device_id = new_id();
    let alice = live_client(tmp.path(), &ds, ALICE_STORE, ALICE_DID, &device_id, &keys);
    alice.enroll_device(&oauth_scopes()).expect("enroll alice");
    let bob = enrolled(&tmp, &ds, "established-bob", BOB_DID, &new_id());
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Archive established".into()),
            None,
        )
        .expect("create group");
    bob.sync().expect("bob accepts the invite");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");
    alice
        .send_message(&cid, &new_id(), "first archived message")
        .expect("send");
    Fixture {
        tmp,
        ds,
        keys,
        device_id,
        alice,
        _bob: bob,
    }
}

fn status(client: &CatbirdMlsClient) -> LabyrinthBackupStatus {
    client.labyrinth_status().expect("status")
}

#[test]
fn archive_is_established_by_the_first_successful_flush_and_stays_so_across_reopen() {
    let f = enrolled_with_a_queued_message();
    let before = status(&f.alice);
    assert!(
        !before.archive_established,
        "an enrolled device that never reached its archive has not established it"
    );
    // The intent flag and the placeholders other code reads keep their first-open values.
    assert!(before.backup_enabled);
    assert_eq!(before.epoch_seq, 1);
    assert_eq!(before.active_device_ids, vec![f.device_id.clone()]);

    assert_eq!(f.alice.flush_labyrinth_queue().expect("first flush"), 1);
    assert!(
        status(&f.alice).archive_established,
        "the first flush created the mailbox Space, this device and its epoch"
    );
    assert_eq!(f.alice.flush_labyrinth_queue().expect("idle flush"), 0);
    assert!(status(&f.alice).archive_established);

    let Fixture {
        tmp,
        ds,
        keys,
        device_id,
        alice,
        _bob,
    } = f;
    drop(alice);
    let reopened = live_client(tmp.path(), &ds, ALICE_STORE, ALICE_DID, &device_id, &keys);
    assert!(
        status(&reopened).archive_established,
        "reopening the client keeps the archive established"
    );
}

#[test]
fn a_failed_first_enable_leaves_the_archive_not_established() {
    let f = enrolled_with_a_queued_message();
    f.ds.archive_auth.set_write_outage(true);
    assert!(
        f.alice.flush_labyrinth_queue().is_err(),
        "the Space refuses every write, so the archive cannot be created"
    );
    assert!(
        !status(&f.alice).archive_established,
        "a session that never opened leaves nothing established"
    );

    f.ds.archive_auth.set_write_outage(false);
    assert_eq!(f.alice.flush_labyrinth_queue().expect("retry"), 1);
    assert!(status(&f.alice).archive_established);
}

#[test]
fn a_status_saved_before_the_field_existed_reads_as_not_established() {
    let f = enrolled_with_a_queued_message();
    f.alice
        .db()
        .write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.expect("status");
            let mut stored: Value = serde_json::from_slice(&raw).unwrap();
            stored
                .as_object_mut()
                .unwrap()
                .remove("archive_established")
                .expect("the status is stored with the field");
            tx.put_labyrinth_state("status_json", &serde_json::to_vec(&stored).unwrap(), 0)
        })
        .unwrap();
    assert!(!status(&f.alice).archive_established);
}
