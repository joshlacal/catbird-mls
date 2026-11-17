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
            .list_messages(cid, None, 100)
            .unwrap()
            .iter()
            .all(|row| row.message_id != hidden),
        "the unsent message leaves the visible timeline"
    );
    assert!(
        f.alice
            .db()
            .read_tx(|tx| tx.get_labyrinth_state(&format!("native.unsent:{cid}:{hidden}")))
            .unwrap()
            .is_some(),
        "opted-out unsend leaves a local marker without a remote redaction"
    );
    f.alice.sync().unwrap();
    assert!(f
        .alice
        .list_messages(cid, None, 100)
        .unwrap()
        .iter()
        .all(|row| row.message_id != hidden));

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

#[test]
fn joining_member_inherits_effective_backup_off_from_verified_welcome() {
    let f = send_order_fixture(true);
    let cid = f.cid.as_str();
    assert!(
        stored_metadata(&f.alice, cid)
            .get("historyBackup")
            .is_none(),
        "genesis uses the missing-field default"
    );
    f.bob.set_history_backup_enabled(cid, false).unwrap();
    f.alice.sync().unwrap();
    assert!(!f.alice.history_backup_enabled(cid).unwrap());

    admit_eve(&f);
    assert!(!f.eve.history_backup_enabled(cid).unwrap());
    assert!(
        stored_metadata(&f.eve, cid)
            .get("historyBackup")
            .is_none(),
        "the Commit carries exact prior metadata; OFF arrives in the verified Welcome"
    );
}

#[test]
fn missing_backup_field_survives_first_membership_commit_without_normalization() {
    let f = send_order_fixture(true);
    let cid = f.cid.as_str();
    assert!(stored_metadata(&f.alice, cid)
        .get("historyBackup")
        .is_none());

    admit_eve(&f);

    assert!(f.eve.history_backup_enabled(cid).unwrap());
    assert!(stored_metadata(&f.eve, cid)
        .get("historyBackup")
        .is_none());
}

#[test]
fn explicit_backup_policy_survives_generic_commit_and_leave_carry_forward() {
    let f = send_order_fixture(true);
    let cid = f.cid.as_str();

    // Model an authenticated snapshot written by a policy-aware older client: place its explicit
    // field in Alice's complete local metadata, then publish it through the normal signed admin
    // metadata transition. Subsequent Commit forms must carry that plaintext exactly.
    let mut row = f.alice.get_group_metadata(cid).unwrap().expect("metadata");
    let mut metadata: Value = serde_json::from_str(&row.metadata_json).unwrap();
    metadata["historyBackup"] = json!(false);
    row.metadata_json = metadata.to_string();
    f.alice
        .db()
        .write_tx(|tx| tx.upsert_group_metadata(&row))
        .unwrap();
    f.alice
        .update_group_metadata(cid, "Explicit policy".into(), String::new(), None)
        .expect("publish explicit policy metadata");
    f.bob.sync().expect("bob applies metadata transition");
    assert_eq!(
        stored_metadata(&f.bob, cid)["historyBackup"],
        json!(false)
    );

    admit_eve(&f);
    f.alice
        .remove_group_member(MemberRole::Admin, cid, EVE_DID)
        .expect("generic Commit removes Eve");
    f.bob.sync().expect("bob applies Eve removal");
    assert_eq!(
        stored_metadata(&f.bob, cid)["historyBackup"],
        json!(false)
    );

    let leave = f
        .bob
        .leave_conversation(cid)
        .expect("bob requests durable leave");
    assert!(!leave.left_immediately);
    assert_eq!(
        f.alice
            .fulfill_pending_group_leaves()
            .expect("alice fulfills Bob's leave"),
        1
    );
    assert_eq!(
        stored_metadata(&f.alice, cid)["historyBackup"],
        json!(false)
    );
}

/// A completed OFF control is newer than the stored metadata row. A later title edit must author
/// the current OFF value rather than republish the row's missing-field ON default.
#[test]
fn authored_retitle_stamps_completed_off_over_stale_metadata() {
    let f = send_order_fixture(false);
    let cid = f.cid.as_str();
    assert!(stored_metadata(&f.alice, cid)
        .get("historyBackup")
        .is_none());

    f.alice
        .set_history_backup_enabled(cid, false)
        .expect("turn backup off");
    f.bob.sync().expect("bob observes OFF");
    f.alice
        .update_group_metadata(cid, "Renamed while off".into(), String::new(), None)
        .expect("author metadata after OFF");
    f.bob.sync().expect("bob applies authored metadata");

    assert_eq!(
        stored_metadata(&f.bob, cid)["historyBackup"],
        json!(false)
    );
    assert!(!f.alice.history_backup_enabled(cid).unwrap());
    assert!(!f.bob.history_backup_enabled(cid).unwrap());
}

/// An epoch Commit carries the last metadata plaintext exactly, but that old field is not a new
/// policy action. OFF metadata followed by an explicit ON remains ON after a peer applies the
/// carried snapshot.
#[test]
fn stale_off_epoch_carry_does_not_override_later_explicit_on() {
    let f = send_order_fixture(true);
    let cid = f.cid.as_str();

    f.alice
        .set_history_backup_enabled(cid, false)
        .expect("turn backup off");
    f.bob.sync().expect("bob observes OFF");
    f.alice
        .update_group_metadata(cid, "Metadata authored off".into(), String::new(), None)
        .expect("author OFF metadata");
    f.bob.sync().expect("bob applies OFF metadata");
    assert_eq!(
        stored_metadata(&f.bob, cid)["historyBackup"],
        json!(false)
    );

    f.alice
        .set_history_backup_enabled(cid, true)
        .expect("explicitly turn backup on");
    f.bob.sync().expect("bob observes ON");
    assert!(f.bob.history_backup_enabled(cid).unwrap());

    // A legacy install persisted this one schema byte field with the old `$bytes` wrapper.
    // Semantic byte equality must accept it without relaxing any opaque envelope field.
    f.bob
        .db()
        .write_tx(|tx| {
            let key = format!("metadata_snapshot_json:{cid}");
            let raw = tx
                .get_account_meta(&key)?
                .expect("bob cached authenticated metadata");
            let mut snapshot: Value = serde_json::from_str(&raw)?;
            let public_key = snapshot
                .pointer("/authorProof/signaturePublicKey")
                .and_then(Value::as_str)
                .expect("canonical author key")
                .to_string();
            snapshot["authorProof"]["signaturePublicKey"] =
                json!({ "$bytes": public_key });
            tx.put_account_meta(&key, &snapshot.to_string(), 0)
        })
        .unwrap();

    f.eve.sync().expect("eve accepts the invite");
    f.alice.sync().expect("alice adds eve with an epoch Commit");
    f.bob.sync().expect("bob applies the epoch Commit");

    assert_eq!(
        stored_metadata(&f.bob, cid)["historyBackup"],
        json!(false),
        "the old metadata plaintext is still carried exactly"
    );
    assert!(
        f.bob.history_backup_enabled(cid).unwrap(),
        "the carried OFF field has no authority to override the later explicit ON"
    );
}
