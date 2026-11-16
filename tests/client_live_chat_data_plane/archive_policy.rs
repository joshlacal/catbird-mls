//! History-backup policy end to end: unknown group settings survive every snapshot rebuild,
//! flagged frames are never archived by sender or witness, the policy follows its signed
//! transitions and never loosens from a carried snapshot, and the acknowledgement advances once
//! a flush archived what it was waiting for.

use super::*;

fn stored_metadata(client: &CatbirdMlsClient, cid: &str) -> Value {
    let row = client
        .get_group_metadata(cid)
        .unwrap()
        .expect("stored group metadata");
    serde_json::from_str(&row.metadata_json).unwrap()
}

/// Eve accepts, Alice adds her with a Commit, Bob applies it and Eve joins.
fn admit_eve(f: &SendOrderFixture) {
    f.eve.sync().expect("eve accepts the invite");
    f.alice.sync().expect("alice adds eve");
    f.bob.sync().expect("bob applies the add commit");
    f.eve.sync().expect("eve joins");
    f.alice.sync().expect("alice reaches the head");
}

/// A group setting this build does not know (a reserved name and a future one) rides every
/// snapshot rebuild: Alice's re-title, Bob's re-title, and the add Commit that carries the
/// snapshot to Bob and to the joining Eve.
///
/// Fail-before: a re-title rebuilt the snapshot from title, description and avatar only, so the
/// unknown setting was gone from every member after the first rebuild.
#[test]
fn unknown_group_settings_survive_retitle_and_membership_commits() {
    let f = send_order_fixture(true);
    let (cid, alice, bob) = (f.cid.as_str(), &f.alice, &f.bob);
    let mut row = alice.get_group_metadata(cid).unwrap().expect("metadata");
    let mut meta: Value = serde_json::from_str(&row.metadata_json).unwrap();
    meta["disappearingTtlSecs"] = json!(3600);
    meta["futureSetting"] = json!({ "nested": [1, 2] });
    row.metadata_json = meta.to_string();
    alice
        .db()
        .write_tx(|tx| tx.upsert_group_metadata(&row))
        .unwrap();

    alice
        .update_group_metadata(cid, "Renamed".into(), String::new(), None)
        .expect("alice re-titles");
    bob.sync().expect("bob applies the re-title");
    let unknown = |client: &CatbirdMlsClient, step: &str| {
        let meta = stored_metadata(client, cid);
        assert_eq!(meta["disappearingTtlSecs"], json!(3600), "{step}");
        assert_eq!(meta["futureSetting"], json!({ "nested": [1, 2] }), "{step}");
    };
    unknown(bob, "bob after alice's re-title");

    bob.update_group_metadata(cid, "Bob's title".into(), String::new(), None)
        .expect("bob re-titles");
    alice.sync().expect("alice applies bob's re-title");
    unknown(alice, "alice after bob's re-title");

    admit_eve(&f);
    unknown(bob, "bob after the add commit");
    unknown(&f.eve, "eve after joining");
    assert_eq!(stored_metadata(&f.eve, cid)["title"], json!("Bob's title"));
}

/// Bob is a non-admin participant in this direct conversation. His authenticated policy
/// messages must be accepted by the normal send path, observed by Alice, and never enter either
/// archive queue. After a second explicit change, only later unflagged messages are archivable.
#[test]
fn either_direct_peer_can_turn_backup_off_and_explicitly_back_on() {
    let f = send_order_fixture(false);
    let cid = f.cid.as_str();
    let queued = |client: &CatbirdMlsClient, id: &str| {
        client
            .db()
            .read_tx(|tx| {
                Ok(tx
                    .list_labyrinth_queue(Some(cid), 100)?
                    .iter()
                    .any(|r| r.item_id == id))
            })
            .unwrap()
    };

    let off = f.bob.set_history_backup_enabled(cid, false).unwrap();
    f.alice.sync().unwrap();
    assert!(!f.alice.history_backup_enabled(cid).unwrap());
    assert!(!f.bob.history_backup_enabled(cid).unwrap());
    assert!(!queued(&f.bob, &off.message_id));
    assert!(!queued(&f.alice, &off.message_id));
    assert_eq!(
        serde_json::from_str::<Value>(&off.plaintext_json).unwrap()["messageType"],
        "system"
    );

    let hidden = new_id();
    f.alice
        .send_message(cid, &hidden, "during opt-out")
        .unwrap();
    f.bob.sync().unwrap();
    assert!(!queued(&f.alice, &hidden));
    assert!(!queued(&f.bob, &hidden));
    assert_eq!(f.alice.unsend_message(cid, &hidden).unwrap(), 0);
    assert!(
        f.alice
            .db()
            .read_tx(|tx| tx.get_labyrinth_state(&format!("native.unsent:{cid}:{hidden}")))
            .unwrap()
            .is_some(),
        "opted-out unsend leaves a local marker without a remote redaction"
    );

    let on = f.bob.set_history_backup_enabled(cid, true).unwrap();
    f.alice.sync().unwrap();
    assert!(f.alice.history_backup_enabled(cid).unwrap());
    assert!(f.bob.history_backup_enabled(cid).unwrap());
    assert!(!queued(&f.bob, &on.message_id));
    assert!(!queued(&f.alice, &on.message_id));

    let visible = new_id();
    f.alice.send_message(cid, &visible, "after opt-in").unwrap();
    f.bob.sync().unwrap();
    assert!(queued(&f.alice, &visible));
    assert!(queued(&f.bob, &visible));
    assert!(!queued(&f.alice, &hidden));
}
