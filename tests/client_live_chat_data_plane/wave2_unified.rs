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
fn pending_approval_blocks_leaf_fulfillment_verifies_pds_key_on_approve_and_holds_recovery_promotion(
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
    {
        let state = ds.inner.lock().unwrap();
        let anchored = state
            .labyrinth_epochs
            .get(ALICE_DID)
            .expect("active device must publish authenticated genesis to mls-ds");
        assert_eq!(anchored.len(), 1);
        assert_eq!(anchored[0]["epochNumber"], 0);
    }

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

    // A recovery code authenticates archive access, not immediate chat-device activation.
    // While an active sibling can approve this device, the authenticated epoch publication is
    // held for the server's durable recovery notice + sibling-dormancy gate.
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
    let recovery_status = alice_d3
        .restore_with_recovery_code(&recovery_code)
        .expect("d3 restores archive state while directory publication is held");
    assert!(
        recovery_status.pending_directory_epoch.is_some(),
        "held directory publication must remain pending"
    );
    assert_eq!(
        recovery_status.directory_publication_error.as_deref(),
        Some("store refused access"),
        "held publication must retain the mapped authorization rejection"
    );
    {
        let state = ds.inner.lock().unwrap();
        assert_eq!(
            state.pending_epoch_publication_rejections, 1,
            "authenticated pending publication must reach the NotAuthorized admission gate"
        );
        assert_eq!(
            state.labyrinth_epochs.get(ALICE_DID).map(Vec::len),
            Some(1),
            "NotAuthorized pending publication must not advance the mls-ds head"
        );
    }
    assert!(
        alice_d3
            .is_device_pending_approval()
            .expect("d3 remains pending"),
        "recovery code alone must not bypass an awake sibling's approval"
    );
    assert!(
        !ds.inner
            .lock()
            .unwrap()
            .dr_revisions
            .contains_key(&(ALICE_DID.to_owned(), alice_d3_dev.clone())),
        "held recovery must not publish active-only direct-request keys"
    );

    // Once the server-authoritative notice is old enough and every active sibling is dormant,
    // opening the archive retries the exact held head. The DS atomically admits that head and
    // activates d3; the native completion path then refreshes enrollment and deferred keys.
    {
        let mut state = ds.inner.lock().unwrap();
        state
            .aged_pending_notices
            .insert((ALICE_DID.to_owned(), alice_d3_dev.clone()));
        state
            .dormant_devices
            .insert((ALICE_DID.to_owned(), alice_d1_dev));
        state
            .dormant_devices
            .insert((ALICE_DID.to_owned(), alice_d2_dev));
        state.xrpc_failures.push((
            "/xrpc/blue.catbird.chat.getOwnDevices",
            503,
            "Unavailable",
            None,
        ));
    }
    assert_eq!(
        alice_d3
            .flush_labyrinth_queue()
            .expect("eligible held publication retry"),
        0
    );
    assert!(
        alice_d3
            .is_device_pending_approval()
            .expect("d3 remains locally pending after refresh failure"),
        "a transient enrollment refresh failure must retain local pending state"
    );
    {
        let state = ds.inner.lock().unwrap();
        assert_eq!(
            state
                .device_statuses
                .get(&(ALICE_DID.to_owned(), alice_d3_dev.clone()))
                .map(String::as_str),
            Some("active"),
            "eligible held publication must atomically activate d3 on the DS"
        );
        assert!(
            !state
                .dr_revisions
                .contains_key(&(ALICE_DID.to_owned(), alice_d3_dev.clone())),
            "failed activation refresh must not fake deferred key publication"
        );
    }
    assert_eq!(
        alice_d3
            .flush_labyrinth_queue()
            .expect("ordinary reopen retries durable activation refresh"),
        0
    );
    assert!(
        !alice_d3
            .is_device_pending_approval()
            .expect("d3 activation refresh retry"),
        "later ordinary archive open must retry and complete verified DS activation"
    );
    let activated_status = alice_d3
        .labyrinth_status()
        .expect("activated archive status");
    assert_eq!(activated_status.pending_directory_epoch, None);
    assert_eq!(activated_status.directory_publication_error, None);
    {
        let state = ds.inner.lock().unwrap();
        assert_eq!(
            state
                .device_statuses
                .get(&(ALICE_DID.to_owned(), alice_d3_dev.clone()))
                .map(String::as_str),
            Some("active")
        );
        assert_eq!(state.labyrinth_epochs.get(ALICE_DID).map(Vec::len), Some(2));
        assert_eq!(
            state
                .dr_revisions
                .get(&(ALICE_DID.to_owned(), alice_d3_dev.clone())),
            Some(&1),
            "activation refresh must publish deferred direct-request keys"
        );
    }
    assert!(
        alice_d3
            .replenish_key_packages(2)
            .expect("activated d3 replenishes key packages")
            >= 2
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
    //    - does NOT prematurely acknowledge `acked_watermarks` before foreground sync + archive flush!
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
    assert_ne!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(dm_cid.clone(), alice_d2_dev.clone())),
        Some(&push_seq),
        "process_push_wake must not advance acked_watermarks before foreground sync and archive flush"
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
    assert_ne!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(dm_cid.clone(), bob_dev.clone())),
        Some(&push_seq),
        "process_push_wake must not advance acked_watermarks before foreground sync and archive flush"
    );

    alice_d2
        .sync()
        .expect("alice_d2 foreground sync completes receipt");
    alice_d2
        .flush_labyrinth_queue()
        .expect("alice_d2 flushes archive queue");
    alice_d2
        .acknowledge_entries_up_to(&dm_cid, push_seq)
        .expect("alice_d2 acknowledges after sync + archive flush");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(dm_cid.clone(), alice_d2_dev.clone())),
        Some(&push_seq),
        "acked_watermarks advances once foreground sync and archive flush commit"
    );

    bob.sync().expect("bob foreground sync completes receipt");
    bob.flush_labyrinth_queue()
        .expect("bob flushes archive queue");
    bob.acknowledge_entries_up_to(&dm_cid, push_seq)
        .expect("bob acknowledges after sync + archive flush");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(dm_cid.clone(), bob_dev.clone())),
        Some(&push_seq),
        "acked_watermarks advances for bob once foreground sync and archive flush commit"
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

    // 4. `delete_account_data` fails closed on remote 500. Its later sequenced
    // deletion remains quarantined until historical non-revocation can be proved:
    // survivors retain the cursor, plaintext and exact unverified evidence.
    let deletion_cursor = last_seq(&alice_d1, &grp_cid);
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
    {
        let g = ds.inner.lock().unwrap();
        assert!(
            g.pds_records.contains_key(&(
                CAROL_DID.to_string(),
                "blue.catbird.chat.deviceRevocation".to_string(),
                carol_dev.clone(),
            )),
            "deleteAccountData must publish self-deletion deviceRevocation record on PDS"
        );
        let has_rev_proof = g
            .entries
            .get(&grp_cid)
            .and_then(|entries| entries.last())
            .and_then(|e| e.get("revocationProof"))
            .is_some();
        assert!(
            has_rev_proof,
            "deleteAccountData entry must carry revocationProof CARv1 bytes"
        );
    }

    alice_d1
        .sync()
        .expect("verified keyProof + revocationProof must apply Carol's account deletion");
    assert!(
        last_seq(&alice_d1, &grp_cid) > deletion_cursor,
        "verified deletion must advance the live cursor"
    );
    assert!(
        !alice_d1
            .list_messages(&grp_cid, None, 50)
            .expect("alice_d1 messages after deletion")
            .iter()
            .any(|message| message.message_id == carol_msg_id),
        "verified deletion must purge Carol's pre-deletion live plaintext"
    );
    assert!(
        alice_d1
            .db()
            .read_tx(|tx| tx
                .get_labyrinth_state(&format!("native.account_deleted:{grp_cid}:{CAROL_DID}")))
            .unwrap()
            .is_some(),
        "verified deletion must install the applied deletion marker"
    );
    let evidence: Value = serde_json::from_str(
        &alice_d1
            .export_conversation_integrity_evidence_json(&grp_cid)
            .expect("export post-deletion evidence"),
    )
    .unwrap();
    assert!(
        evidence["unverifiedAccountDeletions"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "verified deletion must leave zero unverified account deletion entries: {evidence}"
    );
}

#[test]
fn pds_revocation_proof_blocks_sibling_revoked_quarantines_unproven_and_hides_on_restore() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes = oauth_scopes();

    let alice_d1_dev = new_id();
    let alice_d2_dev = new_id();
    let bob_dev = new_id();
    let carol_d1_dev = new_id();
    let carol_d2_dev = new_id();

    let alice_d1 = enrolled(&tmp, &ds, "w2-revp-a1", ALICE_DID, &alice_d1_dev);
    let bob = enrolled(&tmp, &ds, "w2-revp-b1", BOB_DID, &bob_dev);
    let carol_d1 = enrolled(&tmp, &ds, "w2-revp-c1", CAROL_DID, &carol_d1_dev);

    let alice_code = alice_d1.setup_recovery_code().expect("alice recovery");
    bob.setup_recovery_code().expect("bob recovery");
    let carol_code = carol_d1.setup_recovery_code().expect("carol recovery");

    let carol_d2 = live_client(
        tmp.path(),
        &ds,
        "w2-revp-c2",
        CAROL_DID,
        &carol_d2_dev,
        &Arc::new(MemKeyStore::new()),
    );
    carol_d2.enroll_device(&scopes).expect("enroll carol_d2");
    carol_d2
        .restore_with_recovery_code(&carol_code)
        .expect("carol_d2 join mailbox");

    let grp_cid = new_id();
    alice_d1
        .create_group(
            &grp_cid,
            DS_DID,
            vec![BOB_DID.into(), CAROL_DID.into()],
            Some("Revocation Proof Group".into()),
            Some("group".into()),
        )
        .expect("create group");
    join_invited_group(&alice_d1, &[&bob, &carol_d1, &carol_d2]);
    bob.sync().expect("bob sync");
    carol_d1.sync().expect("carol_d1 sync");
    carol_d2.sync().expect("carol_d2 sync");

    let carol_msg_id = new_id();
    carol_d1
        .send_message(&grp_cid, &carol_msg_id, "Carol secret pre-deletion")
        .expect("carol send");
    carol_d1.flush_labyrinth_queue().expect("carol flush");
    let bob_msg_id = new_id();
    bob.send_message(&grp_cid, &bob_msg_id, "Bob message stays visible")
        .expect("bob send");
    bob.flush_labyrinth_queue().expect("bob flush");
    alice_d1.sync().expect("alice receives messages");
    bob.sync().expect("bob catches up");
    // Ensure Alice's OwnerMailbox has rescued owner history for fresh restore check below.
    alice_d1.flush_labyrinth_queue().expect("alice flush");
    alice_d1
        .rescue_conversation_on_kick(&grp_cid)
        .expect("alice rescues conversation history");

    // 1. Sibling device revokes carol_d2; carol_d2.delete_account_data() must fail closed
    //    BEFORE calling deleteAccountData on DS or wiping its local SQLCipher DB.
    carol_d1
        .revoke_device(&carol_d2_dev)
        .expect("carol_d1 revokes carol_d2");
    alice_d1.sync().expect("alice_d1 syncs carol_d2 revocation");
    bob.sync().expect("bob syncs carol_d2 revocation");
    let pre_ds_call_count = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.labyrinth.deleteAccountData"))
        .count();
    assert!(
        carol_d2.delete_account_data().is_err(),
        "sibling-revoked device must refuse delete_account_data"
    );
    assert!(
        !carol_d2.is_handle_closed(),
        "sibling-revoked device must keep local DB intact on refusal"
    );
    let post_ds_call_count = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.labyrinth.deleteAccountData"))
        .count();
    assert_eq!(
        pre_ds_call_count, post_ds_call_count,
        "sibling-revoked device must abort BEFORE calling deleteAccountData on DS"
    );

    // 2. Unrevoked carol_d1 deletes her account. Strip revocationProof before Bob syncs:
    //    live sync must quarantine as AccountDeletionUnverified (`revocation-status-unproven`).
    let bob_cursor = last_seq(&bob, &grp_cid);
    carol_d1
        .delete_account_data()
        .expect("unrevoked carol_d1 delete_account_data succeeds");
    assert!(carol_d1.is_handle_closed());
    {
        let mut g = ds.inner.lock().unwrap();
        if let Some(entries) = g.entries.get_mut(&grp_cid) {
            for e in entries.iter_mut() {
                if e.get("deletedDid").and_then(Value::as_str) == Some(CAROL_DID) {
                    if let Some(obj) = e.as_object_mut() {
                        obj.remove("revocationProof");
                    }
                }
            }
        }
    }
    let sync_err = bob
        .sync()
        .expect_err("entry omitting revocationProof must quarantine");
    assert!(
        matches!(&sync_err, MLSError::SyncIncomplete { applied: 0, failures }
            if failures.len() == 1
                && failures[0].conversation_id == grp_cid
                && matches!(failures[0].error.as_ref(),
                    MLSError::InvalidState(code) if code == "AccountDeletionUnverified")),
        "{sync_err:?}"
    );
    assert_eq!(last_seq(&bob, &grp_cid), bob_cursor);
    assert!(bob
        .list_messages(&grp_cid, None, 50)
        .unwrap()
        .iter()
        .any(|m| m.message_id == carol_msg_id));

    // 3a. Fresh restore fail-closed when mls-ds omits Carol from getConversationState
    //     ["accountDeletions"] while Carol's PDS still carries her live deleteAccountData record.
    let saved_deletions = ds
        .inner
        .lock()
        .unwrap()
        .account_deletions
        .remove(&grp_cid)
        .expect("saved carol deletion entry");
    let alice_d2 = live_client(
        tmp.path(),
        &ds,
        "w2-revp-a2",
        ALICE_DID,
        &alice_d2_dev,
        &Arc::new(MemKeyStore::new()),
    );
    alice_d2.enroll_device(&scopes).expect("enroll alice_d2");
    alice_d2
        .restore_with_recovery_code(&alice_code)
        .expect("alice_d2 recover archive keys");
    let omitted_live_err = alice_d2
        .restore_conversation_from_owner_mailbox(&grp_cid)
        .expect_err("live PDS self-deletion omitted from accountDeletions must fail closed");
    assert!(
        matches!(&omitted_live_err, MLSError::InvalidState(code) if code == "ArchiveDeletionUnverified"),
        "expected ArchiveDeletionUnverified, got {omitted_live_err:?}"
    );

    // 3b. When mls-ds serves Carol's verified accountDeletedEntry and Carol's PDS repo is
    //     tombstoned (400 RepoNotFound), fresh restore succeeds, hides Carol's message, and
    //     keeps Bob's visible.
    ds.inner
        .lock()
        .unwrap()
        .account_deletions
        .insert(grp_cid.clone(), saved_deletions);
    ds.inner
        .lock()
        .unwrap()
        .pds_repo_status_for
        .insert(CAROL_DID.into(), (400, "RepoNotFound".into()));
    let restored = alice_d2
        .restore_conversation_from_owner_mailbox(&grp_cid)
        .expect("fresh restore succeeds with verified deletion + tombstoned PDS");
    let restored_msgs = alice_d2
        .list_messages(&grp_cid, None, 50)
        .expect("list restored messages");
    assert_eq!(restored, 1);
    assert!(!restored_msgs.iter().any(|m| m.message_id == carol_msg_id));
    assert!(restored_msgs.iter().any(|m| m.message_id == bob_msg_id));

    // 3c. When DS omits accountDeletions: transient `RepoDeactivated` fails closed as
    //     `ArchiveDeletionInventoryUnavailable`, whereas terminal `RepoNotFound` ephemerally
    //     hides the tombstoned sender's messages without writing a permanent DB tombstone marker.
    ds.inner.lock().unwrap().account_deletions.remove(&grp_cid);
    ds.inner
        .lock()
        .unwrap()
        .pds_repo_status_for
        .insert(CAROL_DID.into(), (400, "RepoDeactivated".into()));
    let alice_d3 = live_client(
        tmp.path(),
        &ds,
        "w2-revp-a3",
        ALICE_DID,
        &new_id(),
        &Arc::new(MemKeyStore::new()),
    );
    alice_d3.enroll_device(&scopes).expect("enroll alice_d3");
    alice_d3
        .restore_with_recovery_code(&alice_code)
        .expect("alice_d3 recover archive keys");
    let deactivated_err = alice_d3
        .restore_conversation_from_owner_mailbox(&grp_cid)
        .expect_err(
            "RepoDeactivated must fail closed rather than treating deactivation as tombstone",
        );
    assert!(
        matches!(&deactivated_err, MLSError::InvalidState(code) if code == "ArchiveDeletionInventoryUnavailable")
            || matches!(&deactivated_err, MLSError::Cryptography(msg) if msg.contains("corrupt or unverified")),
        "expected fail-closed RepoDeactivated refusal, got {deactivated_err:?}"
    );
    assert!(
        alice_d3
            .list_messages(&grp_cid, None, 50)
            .expect("list messages after failed RepoDeactivated restore")
            .is_empty(),
        "failed RepoDeactivated restore must expose zero messages"
    );
    ds.inner
        .lock()
        .unwrap()
        .pds_repo_status_for
        .insert(CAROL_DID.into(), (400, "RepoNotFound".into()));
    let restored_tombstone = alice_d3
        .restore_conversation_from_owner_mailbox(&grp_cid)
        .expect("RepoNotFound hides tombstoned foreign sender");
    let d3_msgs = alice_d3
        .list_messages(&grp_cid, None, 50)
        .expect("list alice_d3 restored messages");
    assert_eq!(restored_tombstone, 1);
    assert!(!d3_msgs.iter().any(|m| m.message_id == carol_msg_id));
    assert!(d3_msgs.iter().any(|m| m.message_id == bob_msg_id));
    let permanent_marker = alice_d3
        .db()
        .read_tx(|tx| {
            tx.get_labyrinth_state(
                &catbird_mls::client::deletion_authority::pds_deletion_marker_key(
                    &grp_cid, CAROL_DID,
                ),
            )
        })
        .unwrap();
    assert!(
        permanent_marker.is_none(),
        "ephemeral RepoNotFound tombstone must not write permanent i64::MAX marker to SQLite"
    );
}

#[test]
fn pds_revocation_proof_delete_retry_past_300s_refreshes_signed_at_and_keeps_pds_created_at() {
    use catbird_mls::sim_hooks::{FixedStepClock, OsSimEntropy, SimClientHooks, SimClock as _};

    let tmp = tempfile::tempdir().expect("tempdir");
    let start_ms = chrono::Utc::now().timestamp_millis();
    let clock = Arc::new(FixedStepClock::new(start_ms, 0));
    let ds = SharedMockDs::new_with_now_fn(Arc::new({
        let clock = clock.clone();
        move || clock.now_ms()
    }));
    let scopes = oauth_scopes();
    let carol_dev = new_id();
    let alice_dev = new_id();
    let carol = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("w2-revp-retry-c").to_string_lossy().into(),
            account_did: CAROL_DID.into(),
            device_id: carol_dev.clone(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(CAROL_DID),
        None,
        SimClientHooks::new(clock.clone(), Arc::new(OsSimEntropy)),
    )
    .expect("open clocked carol");
    let alice = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("w2-revp-retry-a").to_string_lossy().into(),
            account_did: ALICE_DID.into(),
            device_id: alice_dev,
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(ALICE_DID),
        None,
        SimClientHooks::new(clock.clone(), Arc::new(OsSimEntropy)),
    )
    .expect("open clocked alice");
    alice.enroll_device(&scopes).expect("enroll alice");
    carol.enroll_device(&scopes).expect("enroll carol");
    carol.setup_recovery_code().expect("carol recovery");
    alice.setup_recovery_code().expect("alice recovery");

    let dm_cid = new_id();
    carol
        .create_group(
            &dm_cid,
            DS_DID,
            vec![ALICE_DID.into()],
            None,
            Some("Clocked deletion retry".into()),
        )
        .expect("create DM");
    alice.sync().expect("alice sync DM");
    let reqs = alice.list_requests(Some("incomingPending")).expect("reqs");
    alice
        .accept_direct_request(&reqs[0].request_id)
        .expect("alice accept DM");
    carol.sync().expect("carol sync DM acceptance");

    // First delete_account_data attempt fails at DS with 500 after persisting PDS deviceRevocation.
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.labyrinth.deleteAccountData",
        500,
        "InternalServerError",
        None,
    ));
    assert!(carol.delete_account_data().is_err());
    assert!(!carol.is_handle_closed());
    let first_created_at = ds.inner.lock().unwrap().pds_records[&(
        CAROL_DID.to_string(),
        "blue.catbird.chat.deviceRevocation".to_string(),
        carol_dev.clone(),
    )]["createdAt"]
        .as_str()
        .expect("first PDS createdAt")
        .to_string();

    // Advance clock +360s past the 300s skew window and enable DS clock enforcement.
    clock.advance_ms(360_000);
    ds.inner.lock().unwrap().mock_clock_ms = Some(clock.now_ms());
    carol
        .delete_account_data()
        .expect("retry past 300s must refresh actorWrite signedAt while keeping PDS createdAt");
    assert!(carol.is_handle_closed());
    let after_created_at = ds.inner.lock().unwrap().pds_records[&(
        CAROL_DID.to_string(),
        "blue.catbird.chat.deviceRevocation".to_string(),
        carol_dev,
    )]["createdAt"]
        .as_str()
        .expect("retained PDS createdAt")
        .to_string();
    assert_eq!(after_created_at, first_created_at);
    alice
        .sync()
        .expect("alice accepts retried deletion whose PDS createdAt precedes refreshed signedAt");
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

#[test]
fn acknowledge_entries_clamps_to_durable_contiguous_and_archived_watermarks() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_dev = new_id();
    let bob_dev = new_id();

    let alice = enrolled(&tmp, &ds, "ack-clamp-alice", ALICE_DID, &alice_dev);
    let bob = enrolled(&tmp, &ds, "ack-clamp-bob", BOB_DID, &bob_dev);
    alice.setup_recovery_code().expect("alice mailbox");
    bob.setup_recovery_code().expect("bob mailbox");

    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Ack Clamp Group".into()),
            Some("init".into()),
        )
        .expect("create group");
    join_invited_group(&alice, &[&bob]);
    bob.flush_labyrinth_queue().expect("bob initial flush");

    let base_seq = bob
        .db()
        .read_tx(|tx| Ok(tx.get_conversation(&cid)?.unwrap().last_seq))
        .unwrap();
    bob.acknowledge_entries_up_to(&cid, base_seq + 500)
        .expect("over-watermark ack request clamps to last_seq");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.clone(), bob_dev.clone())),
        Some(&base_seq),
        "acknowledge_entries_up_to must clamp to durable conversations.last_seq"
    );

    // Unflushed Labyrinth queue item clamps `acknowledge_entries_up_to` strictly below `msg1_seq`.
    let msg1_id = new_id();
    alice
        .send_message(&cid, &msg1_id, "must be archived before DS pruning")
        .expect("alice send msg1");
    bob.sync().expect("bob syncs msg1");
    let msg1_seq = bob
        .db()
        .read_tx(|tx| Ok(tx.get_conversation(&cid)?.unwrap().last_seq))
        .unwrap();
    assert!(msg1_seq > base_seq);
    bob.acknowledge_entries_up_to(&cid, msg1_seq)
        .expect("ack clamped below unflushed queue item");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.clone(), bob_dev.clone())),
        Some(&base_seq),
        "unflushed labyrinth_queue item must hold acked_seq strictly below msg1_seq"
    );

    // Pending `native_archive_receipt` marker also clamps strictly below `msg1_seq` even after flush.
    bob.flush_labyrinth_queue().expect("bob flushes msg1");
    bob.db()
        .write_tx(|tx| {
            tx.put_pending_op(
                "native_archive_receipt",
                &msg1_id,
                &serde_json::to_string(&json!({
                    "conversation_id": cid,
                    "seq": msg1_seq,
                }))
                .unwrap(),
                1_700_000_000_000,
            )
        })
        .unwrap();
    bob.acknowledge_entries_up_to(&cid, msg1_seq)
        .expect("ack clamped below pending receipt op");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.clone(), bob_dev.clone())),
        Some(&base_seq),
        "pending native_archive_receipt op must hold acked_seq strictly below msg1_seq"
    );
    bob.db()
        .write_tx(|tx| tx.delete_pending_op("native_archive_receipt", &msg1_id))
        .unwrap();

    // Un-archived undecryptable gap (`native.undecryptable:{cid}:...`) also clamps strictly below `msg1_seq`.
    let gap_key = format!("native.undecryptable:{cid}:gap-test");
    bob.db()
        .write_tx(|tx| {
            tx.put_labyrinth_state(
                &gap_key,
                serde_json::to_vec(&json!({ "seq": msg1_seq }))
                    .unwrap()
                    .as_slice(),
                1_700_000_000_000,
            )
        })
        .unwrap();
    bob.acknowledge_entries_up_to(&cid, msg1_seq)
        .expect("ack clamped below un-archived undecryptable gap");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.clone(), bob_dev.clone())),
        Some(&base_seq),
        "un-archived undecryptable gap must hold acked_seq strictly below gap seq"
    );
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_state WHERE state_key = ?1;",
                    rusqlite::params![gap_key],
                )
                .map(|_| ())
                .map_err(|e| MLSError::Internal(e.to_string()))
        })
        .unwrap();

    // Once receipt, archive queue, and undecryptable gaps are all clear, watermark advances to `msg1_seq`.
    bob.acknowledge_entries_up_to(&cid, msg1_seq)
        .expect("ack advances once all blockers clear");
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.clone(), bob_dev.clone())),
        Some(&msg1_seq)
    );
}

#[test]
fn pending_receipt_cursor_rewind_skips_already_applied_mls_ratchet_entries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_dev = new_id();
    let bob_dev = new_id();
    let carol_dev = new_id();

    let alice = enrolled(&tmp, &ds, "rewind-alice", ALICE_DID, &alice_dev);
    let bob = enrolled(&tmp, &ds, "rewind-bob", BOB_DID, &bob_dev);
    let carol = enrolled(&tmp, &ds, "rewind-carol", CAROL_DID, &carol_dev);

    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into(), CAROL_DID.into()],
            Some("Rewind Safety".into()),
            None,
        )
        .expect("create group");
    join_invited_group(&alice, &[&bob, &carol]);
    bob.sync().expect("bob catches up roster commits");
    carol.sync().expect("carol catches up roster commits");

    let (msg1_id, msg2_id) = (new_id(), new_id());
    let sent1 = alice
        .send_message(&cid, &msg1_id, "first message from alice")
        .expect("alice send msg1");
    let sent2 = carol
        .send_message(
            &cid,
            &msg2_id,
            "second message whose ratchet is already consumed",
        )
        .expect("carol send msg2");
    bob.sync().expect("bob decrypts msg1 and msg2");
    assert_eq!(
        bob.db()
            .read_tx(|tx| Ok(tx.get_conversation(&cid)?.unwrap().last_seq))
            .unwrap(),
        sent2.seq
    );

    // Simulate NSE having decrypted Alice's `msg1` at `sent1.seq` without a foreground receipt yet
    // (`peer_send_counter` for Alice not yet recorded, `native_archive_receipt` pending at `sent1.seq`)
    // while `convo.last_seq` already advanced to `sent2.seq` (Carol's `msg2` already consumed in MLS):
    // rewinding `fetch_after` below `sent1.seq` re-fetches `sent2.seq`, which MUST NOT be re-fed
    // into `group.process_message` (`SecretReuseError`) or downgraded to undecryptable.
    let alice_counter_key = {
        let state = ds.inner.lock().unwrap();
        let body = &state
            .entries
            .get(&cid)
            .unwrap()
            .iter()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == msg1_id)
            .unwrap()["signedRequest"]["body"];
        chat_wire::peer_send_counter_key(
            &cid,
            body["prior"]["generation"].as_i64().unwrap(),
            body["prior"]["epoch"].as_i64().unwrap(),
            body["actorDid"].as_str().unwrap(),
            body["actorDeviceId"].as_str().unwrap(),
        )
    };
    let archive_key_1 = format!("native.message:{cid}:{msg1_id}");
    bob.db()
        .write_tx(|tx| {
            let mut ev: Value =
                serde_json::from_slice(&tx.get_labyrinth_state(&archive_key_1)?.unwrap()).unwrap();
            ev["sequencer_receipt_json"] = Value::Null;
            tx.put_labyrinth_state(
                &archive_key_1,
                &serde_json::to_vec(&ev).unwrap(),
                1_700_000_000_000,
            )?;
            tx.delete_account_meta(&alice_counter_key)?;
            tx.put_pending_op(
                "native_archive_receipt",
                &msg1_id,
                &serde_json::to_string(&json!({
                    "conversation_id": cid,
                    "seq": sent1.seq,
                }))
                .unwrap(),
                1_700_000_000_000,
            )
        })
        .unwrap();

    bob.sync()
        .expect("cursor rewind completes pending receipt without SecretReuse failure on msg2");
    assert!(
        bob.db()
            .read_tx(|tx| tx.get_pending_op("native_archive_receipt", &msg1_id))
            .unwrap()
            .is_none(),
        "pending receipt at sent1.seq must be completed"
    );
    let msgs = bob.list_messages(&cid, None, 20).expect("bob messages");
    let m2 = msgs
        .iter()
        .find(|m| m.message_id == msg2_id)
        .expect("msg2 present");
    assert!(
        m2.plaintext_json
            .contains("second message whose ratchet is already consumed"),
        "msg2 plaintext must remain intact and never be overwritten by undecryptable notice: {}",
        m2.plaintext_json
    );
    let gap_key_2 = format!("native.undecryptable:{cid}:{msg2_id}");
    assert!(
        bob.db()
            .read_tx(|tx| tx.get_labyrinth_state(&gap_key_2))
            .unwrap()
            .is_none(),
        "already-applied entry must never record native.undecryptable evidence on cursor rewind"
    );
}

#[test]
fn enrollment_revocation_pagination_and_car_proof_fail_closed_boundaries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert!(
        scopes.contains(&"repo:blue.catbird.chat.deviceRevocation?action=create".to_string()),
        "REQUIRED_LABYRINTH_OAUTH_SCOPES must declare deviceRevocation create scope"
    );

    let alice_d1_dev = new_id();
    let alice_d2_dev = new_id();
    let bob_dev = new_id();

    let alice_d1_keys = Arc::new(MemKeyStore::new());
    let alice_d1 = live_client(
        tmp.path(),
        &ds,
        "dir-alice-1",
        ALICE_DID,
        &alice_d1_dev,
        &alice_d1_keys,
    );
    alice_d1.enroll_device(&scopes).expect("enroll alice_d1");
    // Idempotent re-enrollment when `createRecord` returns 400 and `getRecord` matches our key.
    alice_d1
        .enroll_device(&scopes)
        .expect("idempotent re-enrollment on matching existing PDS device record");

    // Conflicting PDS `blue.catbird.chat.device/{rkey}` key fails closed on duplicate `createRecord`.
    let conflict_dev = new_id();
    ds.inner.lock().unwrap().pds_records.insert(
        (
            ALICE_DID.to_string(),
            "blue.catbird.chat.device".to_string(),
            conflict_dev.clone(),
        ),
        json!({
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode([0xAAu8; 32]) },
            "homeDeliveryServiceDid": DS_DID,
            "algorithm": "ed25519",
            "createdAt": "2026-11-15T00:00:00.000Z",
        }),
    );
    let conflict_client = live_client(
        tmp.path(),
        &ds,
        "dir-alice-conflict",
        ALICE_DID,
        &conflict_dev,
        &Arc::new(MemKeyStore::new()),
    );
    let conflict_err = conflict_client
        .enroll_device(&scopes)
        .expect_err("mismatched existing PDS device record must fail closed");
    assert!(
        format!("{conflict_err:?}").contains("EnrollmentPdsRecordConflict"),
        "expected EnrollmentPdsRecordConflict, got {conflict_err:?}"
    );
    ds.inner.lock().unwrap().pds_records.remove(&(
        ALICE_DID.to_string(),
        "blue.catbird.chat.device".to_string(),
        conflict_dev,
    ));

    let alice_d2 = enrolled(&tmp, &ds, "dir-alice-2", ALICE_DID, &alice_d2_dev);
    let bob = enrolled(&tmp, &ds, "dir-bob", BOB_DID, &bob_dev);

    let code = alice_d1.setup_recovery_code().expect("alice setup mailbox");
    alice_d2
        .restore_with_recovery_code(&code)
        .expect("alice_d2 join mailbox");
    bob.setup_recovery_code().expect("bob setup mailbox");

    // Revoking `alice_d2` publishes `blue.catbird.chat.deviceRevocation/{alice_d2_dev}` via `createRecord`,
    // with zero `putRecord` or `deleteRecord` calls on `blue.catbird.chat.device*`!
    let rev_report = alice_d1
        .revoke_device(&alice_d2_dev)
        .expect("revoke alice_d2");
    assert!(rev_report.pds_record_deleted);
    {
        let g = ds.inner.lock().unwrap();
        assert!(
            g.pds_records.contains_key(&(
                ALICE_DID.to_string(),
                "blue.catbird.chat.deviceRevocation".to_string(),
                alice_d2_dev.clone(),
            )),
            "deviceRevocation record must be published on PDS"
        );
        let forbidden_mutations = g
            .http_log
            .iter()
            .filter(|(_, url, body)| {
                (url.contains("/xrpc/com.atproto.repo.putRecord")
                    || url.contains("/xrpc/com.atproto.repo.deleteRecord"))
                    && String::from_utf8_lossy(body).contains("blue.catbird.chat.device")
            })
            .count();
        assert_eq!(
            forbidden_mutations, 0,
            "zero putRecord/deleteRecord mutations may target blue.catbird.chat.device*"
        );
        let plc_fetches = g
            .http_log
            .iter()
            .filter(|(_, url, _)| url.starts_with("https://plc.directory/did:plc:"))
            .count();
        assert!(
            plc_fetches >= 1,
            "did:plc resolution must query https://plc.directory/"
        );
    }

    // Multi-page `listRecords` (`140` synthetic sibling devices across 2 pages) succeeds, while
    // `>1,000` records (exceeding the 10-page cap) fails closed!
    for i in 0..140 {
        let extra_dev = format!("00000000-0000-4000-8000-{i:012}");
        ds.inner.lock().unwrap().pds_records.insert(
            (
                ALICE_DID.to_string(),
                "blue.catbird.chat.device".to_string(),
                extra_dev,
            ),
            json!({
                "$type": "blue.catbird.chat.device",
                "mlsSignaturePublicKey": { "$bytes": STANDARD.encode([0x42u8; 32]) },
                "homeDeliveryServiceDid": DS_DID,
                "algorithm": "ed25519",
                "createdAt": "2026-11-15T00:00:00.000Z",
            }),
        );
    }
    let cid = new_id();
    alice_d1
        .create_group(&cid, DS_DID, vec![BOB_DID.into()], None, Some("hi".into()))
        .expect("create DM across >100 paginated PDS device records");
    bob.sync().expect("bob syncs paginated DM");
    let pending = bob.list_requests(Some("incomingPending")).expect("reqs");
    assert_eq!(pending.len(), 1);

    // Missing `#atproto` key in DID document MUST fail closed during peer CARv1 verification.
    let carol_dev = new_id();
    let _carol = enrolled(&tmp, &ds, "car-carol", CAROL_DID, &carol_dev);
    ds.archive_auth.set_omit_atproto_key_for(Some(CAROL_DID));
    let missing_key_cid = new_id();
    let missing_key_err = alice_d1
        .create_group(
            &missing_key_cid,
            DS_DID,
            vec![CAROL_DID.into()],
            None,
            Some("must fail closed without #atproto key".into()),
        )
        .expect_err("missing #atproto key must fail closed");
    assert!(
        format!("{missing_key_err:?}").contains("atproto")
            || format!("{missing_key_err:?}").contains("CAR")
            || format!("{missing_key_err:?}").contains("proof")
            || format!("{missing_key_err:?}").contains("Pds"),
        "unexpected error for missing #atproto key: {missing_key_err:?}"
    );
    ds.archive_auth.set_omit_atproto_key_for(None);

    // MST commit `rev` rollback in CARv1 proof MUST fail closed once a higher `rev` was pinned!
    let ok_carol_cid = new_id();
    alice_d1
        .create_group(
            &ok_carol_cid,
            DS_DID,
            vec![CAROL_DID.into()],
            None,
            Some("pins initial commit rev 3lb2zzzzzzzzz".into()),
        )
        .expect("initial Carol DM pins commit rev");
    ds.archive_auth.set_repo_proof_fault(Some((
        CAROL_DID,
        "blue.catbird.chat.device",
        "rev_rollback",
    )));
    // Expire or clear Alice's short-lived directory cache so she re-verifies Carol's PDS CAR proof.
    alice_d1
        .db()
        .write_tx(|tx| tx.delete_account_meta(&format!("pds_device_keys:{CAROL_DID}")))
        .unwrap();
    let rollback_cid = new_id();
    let rollback_err = alice_d1
        .create_group(
            &rollback_cid,
            DS_DID,
            vec![CAROL_DID.into()],
            None,
            Some("must reject rolled-back commit rev".into()),
        )
        .expect_err("rolled-back MST commit rev must fail closed");
    assert!(
        format!("{rollback_err:?}").contains("rollback")
            || format!("{rollback_err:?}").contains("rev"),
        "expected rev rollback error, got {rollback_err:?}"
    );
    ds.archive_auth.set_repo_proof_fault(None);

    // Overflowing `listRecords` beyond 10 pages (`>1,000` records) fails closed (`DirectoryPaginationExceeded`).
    for i in 0..1005 {
        let extra_dev = format!("00000000-0000-4000-8000-{i:012}");
        ds.inner.lock().unwrap().pds_records.insert(
            (
                CAROL_DID.to_string(),
                "blue.catbird.chat.device".to_string(),
                extra_dev,
            ),
            json!({
                "$type": "blue.catbird.chat.device",
                "mlsSignaturePublicKey": { "$bytes": STANDARD.encode([0x43u8; 32]) },
                "homeDeliveryServiceDid": DS_DID,
                "algorithm": "ed25519",
                "createdAt": "2026-11-15T00:00:00.000Z",
            }),
        );
    }
    alice_d1
        .db()
        .write_tx(|tx| tx.delete_account_meta(&format!("pds_device_keys:{CAROL_DID}")))
        .unwrap();
    let cap_cid = new_id();
    let cap_err = alice_d1
        .create_group(
            &cap_cid,
            DS_DID,
            vec![CAROL_DID.into()],
            None,
            Some("must fail closed past 10 pages".into()),
        )
        .expect_err("listRecords truncation past 10 pages must fail closed");
    assert!(
        format!("{cap_err:?}").contains("Pagination")
            || format!("{cap_err:?}").contains("pagination")
            || format!("{cap_err:?}").contains("exceeded")
            || format!("{cap_err:?}").contains("10"),
        "expected pagination cap failure, got {cap_err:?}"
    );
}
