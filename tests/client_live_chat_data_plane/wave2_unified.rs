//! Live multi-device, archive-auth, CARv1 repo-proof, device lifecycle, and leave-fulfillment
//! integration tests for `CatbirdMlsClient`.

use super::*;

fn join_invited_group(creator: &CatbirdMlsClient, invitees: &[&CatbirdMlsClient]) {
    for _ in 0..invitees.len().max(1) {
        for invitee in invitees {
            invitee
                .sync()
                .expect("invitee accepts group invitation or requests leaf");
        }
        creator
            .sync()
            .expect("creator fulfills invitee leaf recoveries");
        for invitee in invitees {
            invitee.sync().expect("invitee joins pending group Welcome");
        }
    }
    creator.sync().expect("creator reaches group head");
}

#[test]
fn carv1_repo_proof_blocks_tampered_peer_keys_with_zero_mek_wraps_and_leaf_attester_check() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_dev = new_id();
    let bob_dev = new_id();
    let carol_dev = new_id();

    let alice = enrolled(&tmp, &ds, "w2-car-alice", ALICE_DID, &alice_dev);
    let bob = enrolled(&tmp, &ds, "w2-car-bob", BOB_DID, &bob_dev);
    let carol = enrolled(&tmp, &ds, "w2-car-carol", CAROL_DID, &carol_dev);

    alice.setup_recovery_code().expect("alice mailbox");
    bob.setup_recovery_code().expect("bob mailbox");
    carol.setup_recovery_code().expect("carol mailbox");

    // 1. Positive C33 DM + archive roundtrip with valid signed CARv1 proofs.
    let dm_cid = new_id();
    alice
        .create_group(
            &dm_cid,
            DS_DID,
            vec![BOB_DID.into()],
            None,
            Some("Hello Bob with CARv1 verification".into()),
        )
        .expect("create C33 DM");
    bob.sync().expect("bob sync C33");
    let reqs = bob
        .list_requests(Some("incomingPending"))
        .expect("bob pending reqs");
    assert_eq!(reqs.len(), 1);
    bob.accept_direct_request(&reqs[0].request_id)
        .expect("bob accept DM");
    alice.sync().expect("alice sync DM acceptance");

    let dm_msg_id = new_id();
    alice
        .send_message(&dm_cid, &dm_msg_id, "DM follow-up archived")
        .expect("alice send DM message");
    assert!(alice.flush_labyrinth_queue().expect("alice flush DM") >= 1);
    bob.sync().expect("bob sync DM message");

    // 2. Tampered CARv1 repo proof on peer `blue.catbird.chat.device` fails closed.
    ds.archive_auth.set_repo_proof_fault(Some((
        CAROL_DID,
        "blue.catbird.chat.device",
        "wrong_signer",
    )));
    let bad_grp_cid = new_id();
    let dev_proof_err = alice
        .create_group(
            &bad_grp_cid,
            DS_DID,
            vec![CAROL_DID.into()],
            Some("Blocked Group".into()),
            Some("group".into()),
        )
        .expect_err("wrong_signer CARv1 proof on peer chat.device must fail closed");
    assert!(
        dev_proof_err.to_string().contains("CARv1")
            || dev_proof_err.to_string().contains("proof")
            || dev_proof_err.to_string().contains("I4"),
        "unexpected chat.device CARv1 error: {dev_proof_err:?}"
    );
    ds.archive_auth.set_repo_proof_fault(None);

    // 3. Tampered CARv1 repo proof on peer `blue.catbird.labyrinth.mailboxKeys` wraps zero MEKs to Carol.
    let grp_cid = new_id();
    alice
        .create_group(
            &grp_cid,
            DS_DID,
            vec![CAROL_DID.into()],
            Some("Verified Group".into()),
            Some("group".into()),
        )
        .expect("create verified group with carol");
    join_invited_group(&alice, &[&carol]);

    let msg_id = new_id();
    alice
        .send_message(
            &grp_cid,
            &msg_id,
            "Group secret protected against key substitution",
        )
        .expect("alice sends group message");
    carol.sync().expect("carol syncs live MLS message");
    ds.archive_auth.set_repo_proof_fault(Some((
        CAROL_DID,
        "blue.catbird.labyrinth.mailboxKeys",
        "tampered_value",
    )));
    assert_eq!(
        alice
            .flush_labyrinth_queue()
            .expect("alice archives own copy while excluding unverified peer mailboxKeys"),
        1
    );
    ds.archive_auth.set_repo_proof_fault(None);

    // Delete `msg_id` locally on Carol and verify Space restore recovers ZERO messages for Carol
    // because Alice wrapped zero MEKs to Carol while Carol's mailboxKeys CARv1 proof failed.
    carol
        .db()
        .write_tx(|tx| {
            tx.conn()
                .execute("DELETE FROM messages WHERE message_id = ?1", [&msg_id])
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .expect("delete carol local copy of msg_id");
    assert_eq!(
        carol
            .restore_conversation_from_owner_mailbox(&grp_cid)
            .expect("carol restore after zero-MEK-wrap flush"),
        0,
        "Carol must receive zero MEK wraps from a batch flushed while her mailboxKeys CARv1 proof was invalid"
    );

    // Positive control once Carol's valid CARv1 proof is restored: Alice's next flush wraps MEK to Carol.
    let msg_valid_id = new_id();
    alice
        .send_message(
            &grp_cid,
            &msg_valid_id,
            "Group message with verified Carol mailboxKeys",
        )
        .expect("alice sends msg_valid_id");
    assert_eq!(
        alice
            .flush_labyrinth_queue()
            .expect("alice flushes valid batch"),
        1
    );
    carol.sync().expect("carol syncs msg_valid_id");
    carol
        .db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM messages WHERE message_id = ?1",
                    [&msg_valid_id],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .expect("delete carol local copy of msg_valid_id");
    assert_eq!(
        carol
            .restore_conversation_from_owner_mailbox(&grp_cid)
            .expect("carol restores valid batch"),
        1,
        "Carol must restore messages once her mailboxKeys CARv1 proof verifies"
    );

    // 4. Leaf-attester cross-check refuses DS-reported device keys outside OpenMLS group leaves.
    ds.inner.lock().unwrap().member_devices_override =
        Some((ALICE_DID.to_owned(), vec![[0xEE; 32]]));
    let leaf_err = carol
        .restore_conversation_from_owner_mailbox(&grp_cid)
        .expect_err("rogue DS-reported device key outside MLS leaves must fail closed");
    assert!(
        leaf_err
            .to_string()
            .contains("disagree with the local MLS group"),
        "unexpected leaf-attester error: {leaf_err:?}"
    );
    ds.inner.lock().unwrap().member_devices_override = None;
}

#[test]
fn pending_approval_blocks_leaf_fulfillment_verifies_pds_key_on_approve_and_supports_recovery_promotion(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    ds.inner.lock().unwrap().enroll_second_device_pending = true;

    let scopes = oauth_scopes();
    let alice_d1_dev = new_id();
    let alice_d2_dev = new_id();
    let alice_d3_dev = new_id();

    let alice_d1 = enrolled(&tmp, &ds, "w2-pend-a1", ALICE_DID, &alice_d1_dev);
    assert!(
        !alice_d1.is_device_pending_approval().expect("d1 status"),
        "first device should enroll active"
    );
    let recovery_code = alice_d1
        .setup_recovery_code()
        .expect("alice_d1 setup recovery code");

    let alice_d2_keys = Arc::new(MemKeyStore::new());
    let alice_d2 = live_client(
        tmp.path(),
        &ds,
        "w2-pend-a2",
        ALICE_DID,
        &alice_d2_dev,
        &alice_d2_keys,
    );
    alice_d2.enroll_device(&scopes).expect("enroll alice_d2");
    assert!(
        alice_d2.is_device_pending_approval().expect("d2 pending"),
        "second device should enter pending_approval before existing-device approval"
    );
    assert!(
        !ds.inner
            .lock()
            .unwrap()
            .dr_revisions
            .contains_key(&(ALICE_DID.to_owned(), alice_d2_dev.clone())),
        "pending_approval enrollment must defer publishDirectRequestKeys until promotion"
    );

    let kp_err = alice_d2
        .replenish_key_packages(2)
        .expect_err("pending_approval device must not publish active key packages");
    assert!(
        matches!(kp_err, MLSError::PendingDeviceAccess { .. }),
        "unexpected pending key package error: {kp_err:?}"
    );

    // Tampered PDS chat.device CARv1 proof on target sibling must fail approve_device closed.
    ds.archive_auth.set_repo_proof_fault(Some((
        ALICE_DID,
        "blue.catbird.chat.device",
        "tampered_value",
    )));
    let approve_err = alice_d1
        .approve_device(&alice_d2_dev)
        .expect_err("approve_device must verify target sibling PDS chat.device CARv1 proof");
    assert!(
        approve_err.to_string().contains("CARv1")
            || approve_err.to_string().contains("proof")
            || approve_err.to_string().contains("I4"),
        "unexpected approve_device error: {approve_err:?}"
    );
    ds.archive_auth.set_repo_proof_fault(None);

    // Valid approval promotes d2 to active and clears local pending_approval state on re-enroll.
    alice_d1
        .approve_device(&alice_d2_dev)
        .expect("approve alice_d2");
    alice_d2
        .enroll_device(&scopes)
        .expect("re-enroll approved alice_d2");
    assert!(!alice_d2
        .is_device_pending_approval()
        .expect("d2 approved status"));
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .dr_revisions
            .get(&(ALICE_DID.to_owned(), alice_d2_dev.clone())),
        Some(&1),
        "post-approval re-enroll must publish direct-request keys revision 1"
    );
    assert!(alice_d2.replenish_key_packages(2).expect("d2 replenish") >= 2);

    // Lost-device recovery promotion: d3 enrolls pending_approval, then restore_with_recovery_code
    // publishes epoch E+1 via publishEpochHead and promotes d3 to active without sibling approval.
    let alice_d3_keys = Arc::new(MemKeyStore::new());
    let alice_d3 = live_client(
        tmp.path(),
        &ds,
        "w2-pend-a3",
        ALICE_DID,
        &alice_d3_dev,
        &alice_d3_keys,
    );
    alice_d3.enroll_device(&scopes).expect("enroll alice_d3");
    assert!(alice_d3.is_device_pending_approval().expect("d3 pending"));
    alice_d3
        .restore_with_recovery_code(&recovery_code)
        .expect("d3 restore_with_recovery_code promotes pending device");
    assert!(!alice_d3
        .is_device_pending_approval()
        .expect("d3 promoted active"));
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .dr_revisions
            .get(&(ALICE_DID.to_owned(), alice_d3_dev)),
        Some(&1),
        "recovery self-promotion must also complete deferred direct-request key publication"
    );
}

#[test]
fn multidevice_direct_onboarding_auto_history_restore_auto_ack_and_sibling_push_flag() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes = oauth_scopes();

    let alice_d1_dev = new_id();
    let alice_d2_dev = new_id();
    let bob_dev = new_id();

    let alice_d1 = enrolled(&tmp, &ds, "w2-md-a1", ALICE_DID, &alice_d1_dev);
    let bob = enrolled(&tmp, &ds, "w2-md-bob", BOB_DID, &bob_dev);

    let code = alice_d1
        .setup_recovery_code()
        .expect("alice_d1 setup recovery code");
    bob.setup_recovery_code().expect("bob setup recovery code");

    // 1. Alice d1 opens a C33 1:1 direct conversation with Bob; Bob accepts; messages are archived.
    let dm_cid = new_id();
    alice_d1
        .create_group(
            &dm_cid,
            DS_DID,
            vec![BOB_DID.into()],
            None,
            Some("Opening DM message before d2 exists".into()),
        )
        .expect("alice_d1 create DM");
    bob.sync().expect("bob syncs DM opening");
    let pending = bob
        .list_requests(Some("incomingPending"))
        .expect("bob pending");
    bob.accept_direct_request(&pending[0].request_id)
        .expect("bob accepts DM");
    alice_d1.sync().expect("alice_d1 syncs acceptance");
    let hist_msg_id = new_id();
    alice_d1
        .send_message(&dm_cid, &hist_msg_id, "Historical DM message for d2")
        .expect("alice_d1 sends historical DM");
    assert!(alice_d1.flush_labyrinth_queue().expect("flush DM history") >= 1);
    bob.sync().expect("bob syncs historical DM");

    // 2. Alice d2 enrolls, restores OwnerMailbox via recovery code, and syncs:
    //    - pass 1: d2 requests "add" leaf recovery on the direct conversation;
    //    - pass 2: d1 fulfills d2's leaf recovery (transitionSeq > 1) and Bob advances epoch;
    //    - pass 3: d2 joins Welcome AND auto-restores historical messages from OwnerMailbox!
    let alice_d2_keys = Arc::new(MemKeyStore::new());
    let alice_d2 = live_client(
        tmp.path(),
        &ds,
        "w2-md-a2",
        ALICE_DID,
        &alice_d2_dev,
        &alice_d2_keys,
    );
    alice_d2.enroll_device(&scopes).expect("enroll alice_d2");
    alice_d2
        .restore_with_recovery_code(&code)
        .expect("alice_d2 restore mailbox");

    alice_d2
        .sync()
        .expect("alice_d2 submits add leaf recovery on direct conversation");
    alice_d1
        .sync()
        .expect("alice_d1 fulfills alice_d2 leaf recovery");
    bob.sync().expect("bob applies add-sibling commit");
    alice_d2
        .sync()
        .expect("alice_d2 joins Welcome and auto-restores history");

    let d2_msgs = alice_d2
        .list_messages(&dm_cid, None, 20)
        .expect("d2 messages after auto-restore");
    assert!(
        d2_msgs
            .iter()
            .any(|m| m.plaintext_json.contains("Historical DM message for d2")),
        "alice_d2 must auto-restore historical DM messages on Welcome join: {d2_msgs:?}"
    );

    // 3. Push wake on sibling device (alice_d2) vs peer device (bob):
    //    - sets `is_own_sibling_sender = true` on alice_d2 and `false` on bob;
    //    - auto-acknowledges `acked_watermarks` for both devices after SQLite commit!
    let push_msg_id = new_id();
    alice_d1
        .send_message(&dm_cid, &push_msg_id, "Live push wake from d1")
        .expect("alice_d1 sends push target message");
    let push_seq = ds.inner.lock().unwrap().entries[&dm_cid]
        .last()
        .and_then(|e| e["seq"].as_i64())
        .expect("push entry seq");

    let wake_d2 = PushWakePayload {
        kind: "application_message".into(),
        conversation_id: dm_cid.clone(),
        generation: 0,
        entry_seq: push_seq,
        message_id: push_msg_id.clone(),
        recipient_account_hash: account_did_hash_hex(ALICE_DID).unwrap(),
        fetch_required: true,
        sender_did: Some(ALICE_DID.into()),
        inline_ciphertext: None,
    };
    let preview_d2 = alice_d2
        .process_push_wake(wake_d2)
        .expect("alice_d2 process_push_wake");
    assert!(!preview_d2.fallback_generic, "{preview_d2:?}");
    assert!(preview_d2.receipt_verified, "{preview_d2:?}");
    assert!(
        preview_d2.is_own_sibling_sender,
        "sibling device sender must set is_own_sibling_sender = true: {preview_d2:?}"
    );
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(dm_cid.clone(), alice_d2_dev.clone())),
        Some(&push_seq),
        "process_push_wake must auto-acknowledge watermark for alice_d2"
    );

    let wake_bob = PushWakePayload {
        kind: "application_message".into(),
        conversation_id: dm_cid.clone(),
        generation: 0,
        entry_seq: push_seq,
        message_id: push_msg_id.clone(),
        recipient_account_hash: account_did_hash_hex(BOB_DID).unwrap(),
        fetch_required: true,
        sender_did: Some(ALICE_DID.into()),
        inline_ciphertext: None,
    };
    let preview_bob = bob
        .process_push_wake(wake_bob)
        .expect("bob process_push_wake");
    assert!(!preview_bob.fallback_generic, "{preview_bob:?}");
    assert!(preview_bob.receipt_verified, "{preview_bob:?}");
    assert!(
        !preview_bob.is_own_sibling_sender,
        "peer sender must set is_own_sibling_sender = false: {preview_bob:?}"
    );
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(dm_cid.clone(), bob_dev.clone())),
        Some(&push_seq),
        "process_push_wake must auto-acknowledge watermark for bob"
    );

    // 4. `verify_and_reindex_history` purges unverified forged SQLite message rows while keeping verified rows.
    let forged_id = new_id();
    alice_d2
        .db()
        .write_tx(|tx| {
            let convo = tx.get_conversation(&dm_cid)?.unwrap();
            tx.conn()
                .execute(
                    "INSERT INTO messages (message_id, conversation_id, group_id, epoch, seq, \
                     sender_did, sender_device_id, plaintext_json, created_at_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        &forged_id,
                        &dm_cid,
                        &convo.group_id,
                        convo.epoch,
                        9999i64,
                        BOB_DID,
                        &bob_dev,
                        r#"{"$type":"blue.catbird.mlsChat.messagePayload","version":1,"text":"forged local row"}"#,
                        1_700_000_000_000i64,
                    ],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .expect("insert forged unverified message row");

    let verified_kept = alice_d2
        .verify_and_reindex_history(&dm_cid)
        .expect("verify_and_reindex_history");
    assert!(verified_kept >= 2);
    let post_verify_msgs = alice_d2
        .list_messages(&dm_cid, None, 50)
        .expect("messages after verify_and_reindex_history");
    assert!(
        !post_verify_msgs.iter().any(|m| m.message_id == forged_id),
        "unverified forged SQLite row must be purged by verify_and_reindex_history"
    );
    assert!(
        post_verify_msgs.iter().any(|m| m.message_id == push_msg_id),
        "cryptographically verified message rows must remain intact"
    );
}

#[test]
fn unified_revoke_device_retire_current_device_and_fail_closed_delete_account_data() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes = oauth_scopes();

    let alice_d1_dev = new_id();
    let alice_d2_dev = new_id();
    let alice_d3_dev = new_id();
    let bob_d1_dev = new_id();
    let bob_d2_dev = new_id();
    let carol_dev = new_id();

    let alice_d1 = enrolled(&tmp, &ds, "w2-rev-a1", ALICE_DID, &alice_d1_dev);
    let bob_d1 = enrolled(&tmp, &ds, "w2-rev-b1", BOB_DID, &bob_d1_dev);
    let carol = enrolled(&tmp, &ds, "w2-rev-carol", CAROL_DID, &carol_dev);

    let old_alice_code = alice_d1.setup_recovery_code().expect("alice_d1 recovery");
    let bob_code = bob_d1.setup_recovery_code().expect("bob_d1 recovery");
    carol.setup_recovery_code().expect("carol recovery");

    let alice_d2 = live_client(
        tmp.path(),
        &ds,
        "w2-rev-a2",
        ALICE_DID,
        &alice_d2_dev,
        &Arc::new(MemKeyStore::new()),
    );
    alice_d2.enroll_device(&scopes).expect("enroll alice_d2");
    alice_d2
        .restore_with_recovery_code(&old_alice_code)
        .expect("alice_d2 join mailbox");

    let bob_d2 = live_client(
        tmp.path(),
        &ds,
        "w2-rev-b2",
        BOB_DID,
        &bob_d2_dev,
        &Arc::new(MemKeyStore::new()),
    );
    bob_d2.enroll_device(&scopes).expect("enroll bob_d2");
    bob_d2
        .restore_with_recovery_code(&bob_code)
        .expect("bob_d2 join mailbox");

    let grp_cid = new_id();
    alice_d1
        .create_group(
            &grp_cid,
            DS_DID,
            vec![BOB_DID.into(), CAROL_DID.into()],
            Some("Device Lifecycle Group".into()),
            Some("group".into()),
        )
        .expect("create lifecycle group");
    // Invitees + sibling leaves accept / request leaf recovery, creator fulfills, then all join Welcomes.
    join_invited_group(&alice_d1, &[&alice_d2, &bob_d1, &bob_d2, &carol]);
    bob_d1.sync().expect("bob_d1 catches up roster commits");
    bob_d2.sync().expect("bob_d2 catches up roster commits");
    carol.sync().expect("carol catches up roster commits");
    alice_d2.sync().expect("alice_d2 catches up roster commits");

    let carol_msg_id = new_id();
    carol
        .send_message(
            &grp_cid,
            &carol_msg_id,
            "Carol message before account deletion",
        )
        .expect("carol sends message");
    carol.flush_labyrinth_queue().expect("carol flushes");
    alice_d1.sync().expect("alice_d1 receives carol message");
    bob_d1.sync().expect("bob_d1 receives carol message");
    bob_d2.sync().expect("bob_d2 receives carol message");
    assert!(alice_d1
        .list_messages(&grp_cid, None, 20)
        .expect("alice messages")
        .iter()
        .any(|m| m.message_id == carol_msg_id));

    // 1. `list_devices` merges mls-ds inventory + OwnerMailbox Labyrinth key metadata.
    let devices = alice_d1.list_devices().expect("alice_d1 list_devices");
    assert_eq!(devices.len(), 2);
    assert!(devices
        .iter()
        .any(|d| d.device_id == alice_d1_dev && d.is_current_device));
    assert!(devices.iter().any(|d| {
        d.device_id == alice_d2_dev && !d.is_current_device && d.labyrinth_device_key_hex.is_some()
    }));

    // 2. `revoke_device` revokes d2 on mls-ds, removes d2's MLS leaf, rotates Labyrinth epoch +
    //    re-keys recovery code, and deletes d2's PDS `chat.device` record.
    let report = alice_d1
        .revoke_device(&alice_d2_dev)
        .expect("alice_d1 revoke_device(d2)");
    assert!(report.ds_revoked);
    assert!(report.groups_updated >= 1);
    assert!(report.labyrinth_rotated);
    assert!(report.pds_record_deleted);
    let new_alice_code = report
        .rekeyed_recovery_code
        .expect("revocation must re-key recovery code");
    assert_ne!(new_alice_code, old_alice_code);

    let alice_d3 = live_client(
        tmp.path(),
        &ds,
        "w2-rev-a3",
        ALICE_DID,
        &alice_d3_dev,
        &Arc::new(MemKeyStore::new()),
    );
    alice_d3.enroll_device(&scopes).expect("enroll alice_d3");
    assert!(
        alice_d3
            .restore_with_recovery_code(&old_alice_code)
            .is_err(),
        "pre-revocation recovery code must be invalidated after device revocation"
    );
    alice_d3
        .restore_with_recovery_code(&new_alice_code)
        .expect("re-keyed recovery code must succeed on fresh device");

    bob_d1.sync().expect("bob_d1 syncs alice d2 removal");
    bob_d2.sync().expect("bob_d2 syncs alice d2 removal");
    carol.sync().expect("carol syncs alice d2 removal");

    // 3. `retire_current_device` cleanly retires bob_d2 without wiping Bob's account mailbox or bob_d1.
    bob_d2
        .retire_current_device()
        .expect("bob_d2 retire_current_device");
    assert!(bob_d2.is_handle_closed());
    alice_d1.sync().expect("alice_d1 syncs after bob_d2 retire");
    bob_d1
        .sync()
        .expect("bob_d1 remains active after bob_d2 retire");
    carol.sync().expect("carol syncs after bob_d2 retire");
    assert!(bob_d1
        .list_members(&grp_cid)
        .expect("bob_d1 group members")
        .contains(&BOB_DID.to_string()));

    // 4. `delete_account_data` fails closed on remote 500 (keeping local DB open), then purges on retry
    //    and sequences signed `accountDeletedEntry` so survivors purge Carol's messages.
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.labyrinth.deleteAccountData",
        500,
        "InternalServerError",
        None,
    ));
    assert!(
        carol.delete_account_data().is_err(),
        "remote 500 during deleteAccountData must fail closed before wiping local DB"
    );
    assert!(
        !carol.is_handle_closed(),
        "local SQLCipher handle must stay intact when remote deleteAccountData fails"
    );

    carol
        .delete_account_data()
        .expect("carol delete_account_data succeeds on retry");
    assert!(carol.is_handle_closed());

    alice_d1
        .sync()
        .expect("alice_d1 syncs carol accountDeletedEntry");
    assert!(
        !alice_d1
            .list_messages(&grp_cid, None, 50)
            .expect("alice_d1 messages after carol account deletion")
            .iter()
            .any(|m| m.sender_did == CAROL_DID),
        "verified accountDeletedEntry must purge Carol's messages on surviving peers"
    );
}

#[test]
fn d5_flush_requires_signed_space_denial_jwt_fc07_group_leaves_and_attachment_persistence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();

    let alice_dev = new_id();
    let bob_dev = new_id();
    let carol_dev = new_id();

    let alice = enrolled(&tmp, &ds, "w2-leave-alice", ALICE_DID, &alice_dev);
    let bob = enrolled(&tmp, &ds, "w2-leave-bob", BOB_DID, &bob_dev);
    let carol = enrolled(&tmp, &ds, "w2-leave-carol", CAROL_DID, &carol_dev);

    alice.setup_recovery_code().expect("alice mailbox");
    bob.setup_recovery_code().expect("bob mailbox");
    carol.setup_recovery_code().expect("carol mailbox");

    let grp_cid = new_id();
    let grp_row = alice
        .create_group(
            &grp_cid,
            DS_DID,
            vec![BOB_DID.into(), CAROL_DID.into()],
            Some("Attachments & Leaves".into()),
            Some("group".into()),
        )
        .expect("create 3-member group");
    join_invited_group(&alice, &[&bob, &carol]);
    bob.sync().expect("bob reaches head");
    carol.sync().expect("carol reaches head");

    // 1. Conversation attachment upload returns canonical "{spaceURI}|{repoDID}|{cid}" locator,
    //    and Space writer revision floors (`listWriters` / `listSpaces`) persist durably.
    let att = alice
        .upload_conversation_attachment(
            &grp_cid,
            b"encrypted-attachment-bytes-wave2".to_vec(),
            "application/octet-stream".into(),
        )
        .expect("upload_conversation_attachment");
    assert_eq!(
        att.locator,
        format!("{}|{}|{}", att.space_uri, ALICE_DID, att.cid)
    );
    let seeded_msg = new_id();
    alice
        .send_message(
            &grp_cid,
            &seeded_msg,
            "Message establishing writer rev floor",
        )
        .expect("alice send seeded_msg");
    alice
        .flush_labyrinth_queue()
        .expect("alice flush seeded_msg");
    bob.sync().expect("bob sync seeded_msg");
    let _ = bob
        .restore_conversation_from_owner_mailbox(&grp_cid)
        .expect("bob inspects Space listWriters");
    let persisted_floors = bob
        .db()
        .read_tx(|tx| {
            tx.get_labyrinth_state(&format!("native.placements:writer_rev_floors:{BOB_DID}"))
        })
        .expect("read writer_rev_floors");
    assert!(
        persisted_floors.is_some(),
        "Space listWriters observation must persist writer_rev_floors in labyrinth_state"
    );

    // 2. Unsigned 403 on conversation state during `flush_labyrinth_queue` fails closed with
    //    `InvalidState("ArchiveFlushDenialUnverified")`; signed `catbird-space-denial+jwt`
    //    verifies removal and rescues queued messages to Bob's OwnerMailbox.
    let bob_msg_id = new_id();
    bob.send_message(&grp_cid, &bob_msg_id, "Bob message before Space 403")
        .expect("bob sends message");
    ds.inner.lock().unwrap().conversation_state_errors.insert(
        (BOB_DID.into(), grp_cid.clone()),
        (403, "NotEntitled".into()),
    );
    ds.archive_auth
        .set_unsigned_space_not_found(Some("authorizeSpaceSync"), 403);
    let unverified_err = bob
        .flush_labyrinth_queue()
        .expect_err("unsigned 403 without catbird-space-denial+jwt must fail closed");
    assert!(
        matches!(&unverified_err, MLSError::InvalidState(code) if code == "ArchiveFlushDenialUnverified"),
        "expected ArchiveFlushDenialUnverified, got {unverified_err:?}"
    );
    ds.archive_auth.set_unsigned_space_not_found(None, 403);

    ds.archive_auth
        .set_space_denied(BOB_DID, &att.space_uri, Some(&grp_row.group_id));
    assert!(
        bob.flush_labyrinth_queue()
            .expect("signed catbird-space-denial+jwt allows OwnerMailbox rescue")
            >= 1
    );
    ds.archive_auth
        .set_space_denied(BOB_DID, &att.space_uri, None);
    ds.inner
        .lock()
        .unwrap()
        .conversation_state_errors
        .remove(&(BOB_DID.into(), grp_cid.clone()));

    // 3. `leave_conversation` + `fulfill_pending_group_leaves`:
    //    - Sole admin Alice cannot leave a multi-member group (`LastAdminCannotLeave`);
    //    - Member Carol submits durable leave request (`!left_immediately`);
    //    - Admin Alice fulfills pending leave, removing Carol from MLS group leaves & roster.
    let last_admin_err = alice
        .leave_conversation(&grp_cid)
        .expect_err("sole admin must not abandon multi-member group");
    assert!(
        matches!(&last_admin_err, MLSError::InvalidState(code) if code == "LastAdminCannotLeave"),
        "expected LastAdminCannotLeave, got {last_admin_err:?}"
    );

    let carol_leave = carol
        .leave_conversation(&grp_cid)
        .expect("carol requests durable group leave");
    assert!(!carol_leave.left_immediately);
    assert!(carol_leave.leave_request_id.is_some());

    let fulfilled = alice
        .fulfill_pending_group_leaves()
        .expect("alice fulfills carol pending leave");
    assert_eq!(fulfilled, 1);
    assert!(
        !alice
            .list_members(&grp_cid)
            .expect("members after leave fulfillment")
            .contains(&CAROL_DID.to_string()),
        "Carol must be removed from group roster after leaveCommitFulfillment"
    );

    // 4. Direct 1:1 `leave_conversation` closes immediately (`left_immediately == true`).
    let dm_cid = new_id();
    alice
        .create_group(
            &dm_cid,
            DS_DID,
            vec![BOB_DID.into()],
            None,
            Some("1:1 leave test".into()),
        )
        .expect("create DM for leave");
    bob.sync().expect("bob syncs DM");
    let reqs = bob.list_requests(Some("incomingPending")).expect("reqs");
    bob.accept_direct_request(&reqs[0].request_id)
        .expect("accept DM");
    alice.sync().expect("alice syncs DM acceptance");

    let dm_leave = bob
        .leave_conversation(&dm_cid)
        .expect("bob leaves 1:1 DM immediately");
    assert!(dm_leave.left_immediately);
}
