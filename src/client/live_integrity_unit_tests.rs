//! Integrity evidence on the live receive paths: strict per-sender counters, payload-pruned
//! entries, own-receipt slots and signed account deletions.

use super::*;
use crate::client::send_counter;

const BOB_M1: &str = "44444444-4444-4444-8444-444444444401";
const BOB_M2: &str = "44444444-4444-4444-8444-444444444402";
const BOB_M3: &str = "44444444-4444-4444-8444-444444444403";

/// A message the notification extension decrypted and retained before foreground sync saw its
/// entry: the display row plus `native.message` evidence without a receipt. Returns the entry's
/// sequencer receipt.
#[allow(clippy::too_many_arguments)]
fn stage_nse_message(
    client: &CatbirdMlsClient,
    group_id: &[u8],
    sk: &P256SigningKey,
    msg_id: &str,
    sender_did: &str,
    sender_dev: &str,
    seq: i64,
    nse_counter: Option<u64>,
) -> Value {
    let sender_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let payload_json = serde_json::to_string(&MLSMessagePayload::text("hello unit")).unwrap();
    let nonce = [0x24u8; 32];
    let commitment = compute_archive_commitment(&nonce, payload_json.as_bytes());
    let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
        CONVO_ID,
        msg_id,
        &commitment,
    );
    let attestation = OriginalSenderArchiveAttestationEnvelope {
        sender_did: sender_did.to_string(),
        sender_device_id: sender_dev.to_string(),
        sender_transport_public_key: sender_signer.public().to_vec(),
        signature: sender_signer.sign(&transcript).unwrap(),
    };
    let mut evidence = json!({
        "version": 1,
        "message_id": msg_id,
        "conversation_id": CONVO_ID,
        "group_id_hex": hex::encode(group_id),
        "epoch": 0u64,
        "expected_member_dids": [ALICE_DID],
        "seq": 0i64,
        "sender_did": sender_did,
        "sender_device_id": sender_dev,
        "sequencer_did": SEQUENCER_DID,
        "space_uri": Value::Null,
        "plaintext_json": payload_json,
        "labyrinth_frame_json": payload_json,
        "mls_ciphertext_b64": STANDARD.encode([1u8; 16]),
        "frame_nonce_b64": STANDARD.encode(nonce),
        "sequencer_receipt_json": Value::Null,
        "original_sender_attestation_json": serde_json::to_string(&attestation).unwrap(),
        "created_at_ms": 1_000i64,
    });
    client
        .db
        .write_tx(|tx| {
            if let Some(counter) = nse_counter {
                // What the extension records in the transaction that stores the message.
                send_counter::record_peer_send_counter(
                    tx,
                    CONVO_ID,
                    0,
                    0,
                    sender_did,
                    sender_dev,
                    Some(counter),
                    seq,
                    1_000,
                )?;
                evidence[chat_wire::NSE_SEND_COUNTER_RECORDED] = json!(counter);
            }
            tx.insert_message(&MessageRow {
                message_id: msg_id.to_string(),
                conversation_id: CONVO_ID.to_string(),
                group_id: group_id.to_vec(),
                epoch: 0,
                seq: 0,
                sender_did: sender_did.to_string(),
                sender_device_id: sender_dev.to_string(),
                plaintext_json: payload_json.clone(),
                created_at_ms: 1_000,
                is_own: sender_did == ALICE_DID,
            })?;
            tx.put_labyrinth_state(
                &format!("native.message:{CONVO_ID}:{msg_id}"),
                &serde_json::to_vec(&evidence)?,
                1_000,
            )
        })
        .unwrap();
    sign_app_receipt(
        sk,
        SEQUENCER_DID,
        CONVO_ID,
        0,
        group_id,
        0,
        sender_did,
        sender_dev,
        msg_id,
        seq as u64,
        commitment,
    )
}

fn counter_evidence(client: &CatbirdMlsClient) -> Vec<send_counter::SendCounterEvidence> {
    client
        .db
        .read_tx(|tx| send_counter::list_send_counter_evidence(tx, CONVO_ID))
        .unwrap()
}

fn sequencer_key(state: &Arc<Mutex<SyncMockState>>) -> P256SigningKey {
    state
        .lock()
        .unwrap()
        .authority_keys
        .get(SEQUENCER_DID)
        .unwrap()
        .clone()
}

#[test]
fn a_skipped_peer_counter_within_an_epoch_is_recorded_without_blocking_delivery() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "gap",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (_, group_id, _) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 5, &[]);
    let sk = sequencer_key(&state);
    for (msg, seq, counter) in [(BOB_M1, 6, 1u64), (BOB_M2, 7, 3)] {
        let receipt = stage_nse_message(&client, &group_id, &sk, msg, BOB_DID, DEV_B1, seq, None);
        client
            .finish_received_archive_evidence(
                CONVO_ID,
                msg,
                seq,
                msg,
                &receipt,
                Some((BOB_DID, DEV_B1)),
                Some(counter),
                DEV_A1,
            )
            .expect("a counter gap never blocks delivery");
    }
    let evidence = counter_evidence(&client);
    assert_eq!(evidence.len(), 1, "one gap record: {evidence:?}");
    assert_eq!(evidence[0].kind, "gap");
    assert_eq!(evidence[0].seq, 7);
    assert_eq!(evidence[0].expected, Some(2));
    assert_eq!(evidence[0].received, 3);
    assert_eq!(evidence[0].sender_did, BOB_DID);
    assert!(evidence[0].same_epoch);
}

#[test]
fn extension_then_foreground_interleaving_records_no_gap() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "nse",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (_, group_id, _) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 5, &[]);
    let sk = sequencer_key(&state);
    // The extension applies seq 6 and 7 (it learned counter 1 for seq 6 only); foreground sync
    // then completes both and applies seq 8 itself.
    let r1 = stage_nse_message(&client, &group_id, &sk, BOB_M1, BOB_DID, DEV_B1, 6, Some(1));
    let r2 = stage_nse_message(&client, &group_id, &sk, BOB_M2, BOB_DID, DEV_B1, 7, None);
    for (msg, seq, receipt, counter) in [(BOB_M1, 6, &r1, 1u64), (BOB_M2, 7, &r2, 2)] {
        client
            .finish_received_archive_evidence(
                CONVO_ID,
                msg,
                seq,
                msg,
                receipt,
                Some((BOB_DID, DEV_B1)),
                Some(counter),
                DEV_A1,
            )
            .expect("foreground completion of an extension-applied entry");
    }
    let r3 = stage_nse_message(&client, &group_id, &sk, BOB_M3, BOB_DID, DEV_B1, 8, None);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            BOB_M3,
            8,
            BOB_M3,
            &r3,
            Some((BOB_DID, DEV_B1)),
            Some(3),
            DEV_A1,
        )
        .unwrap();
    assert_eq!(counter_evidence(&client), vec![], "zero gap records");
    let key = chat_wire::peer_send_counter_key(CONVO_ID, 0, 0, BOB_DID, DEV_B1);
    assert_eq!(
        client.db.read_tx(|tx| tx.get_account_meta(&key)).unwrap(),
        Some("3".to_string())
    );
}

#[test]
fn an_entry_without_a_learnable_counter_keeps_the_next_counter_exact() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "unknown",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (_, group_id, _) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 5, &[]);
    let sk = sequencer_key(&state);
    let r1 = stage_nse_message(&client, &group_id, &sk, BOB_M1, BOB_DID, DEV_B1, 6, None);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            BOB_M1,
            6,
            BOB_M1,
            &r1,
            Some((BOB_DID, DEV_B1)),
            Some(1),
            DEV_A1,
        )
        .unwrap();
    // Seq 7 completes without its counter (its payload was pruned after the extension held it).
    let r2 = stage_nse_message(&client, &group_id, &sk, BOB_M2, BOB_DID, DEV_B1, 7, None);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            BOB_M2,
            7,
            BOB_M2,
            &r2,
            Some((BOB_DID, DEV_B1)),
            None,
            DEV_A1,
        )
        .unwrap();
    // Counter 4 at seq 8 means Bob's counter 3 never reached this device.
    let r3 = stage_nse_message(&client, &group_id, &sk, BOB_M3, BOB_DID, DEV_B1, 8, None);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            BOB_M3,
            8,
            BOB_M3,
            &r3,
            Some((BOB_DID, DEV_B1)),
            Some(4),
            DEV_A1,
        )
        .unwrap();
    let evidence = counter_evidence(&client);
    assert_eq!(evidence.len(), 1, "{evidence:?}");
    assert_eq!(
        (
            evidence[0].expected,
            evidence[0].received,
            evidence[0].skipped
        ),
        (Some(3), 4, 1)
    );
}

#[test]
fn counters_compare_across_epochs_only_through_commits_this_device_applied() {
    let db = crate::storage::MlsAccountDb::open_in_memory_for_test().unwrap();
    let bob = (BOB_DID.to_string(), DEV_B1.to_string());
    let carol = (CAROL_DID.to_string(), DEV_C1.to_string());
    let both: std::collections::BTreeSet<_> = [bob.clone(), carol.clone()].into();
    let only_bob: std::collections::BTreeSet<_> = [bob.clone()].into();
    db.write_tx(|tx| {
        let rec = |epoch, did, dev, counter, seq| {
            send_counter::record_peer_send_counter(
                tx,
                CONVO_ID,
                0,
                epoch,
                did,
                dev,
                Some(counter),
                seq,
                1,
            )
        };
        // Without any applied Commit, a new epoch is a fresh baseline.
        rec(1, BOB_DID, DEV_B1, 5, 1)?;
        rec(2, BOB_DID, DEV_B1, 9, 2)?;
        // Commit 2 -> 3 applied here, Bob and Carol stay: Bob's next counter must follow.
        rec(2, CAROL_DID, DEV_C1, 3, 3)?;
        send_counter::advance_send_counter_epoch_chain(tx, CONVO_ID, 0, 2, 3, &both, 1)?;
        rec(3, BOB_DID, DEV_B1, 11, 5)?;
        // Commit 3 -> 4 removes Carol; she is re-added later: her continuity is gone.
        send_counter::advance_send_counter_epoch_chain(tx, CONVO_ID, 0, 3, 4, &only_bob, 1)?;
        send_counter::advance_send_counter_epoch_chain(tx, CONVO_ID, 0, 4, 5, &both, 1)?;
        rec(5, CAROL_DID, DEV_C1, 10, 7)?;
        // Across an applied Commit a counter that did not increase is evidence, never an error.
        send_counter::advance_send_counter_epoch_chain(tx, CONVO_ID, 0, 5, 6, &both, 1)?;
        rec(6, CAROL_DID, DEV_C1, 2, 8)?;
        // A Commit from an epoch this device never reached restarts the chain: Bob's epoch-3
        // counter is no longer comparable.
        send_counter::advance_send_counter_epoch_chain(tx, CONVO_ID, 0, 8, 9, &both, 1)?;
        rec(9, BOB_DID, DEV_B1, 30, 9).map(|_| ())
    })
    .unwrap();
    let evidence = db
        .read_tx(|tx| send_counter::list_send_counter_evidence(tx, CONVO_ID))
        .unwrap();
    let summary: Vec<_> = evidence
        .iter()
        .map(|e| (e.seq, e.kind.as_str(), e.expected, e.received, e.same_epoch))
        .collect();
    assert_eq!(
        summary,
        vec![
            (5, "gap", Some(10), 11, false),
            (8, "regressed", None, 2, false)
        ]
    );
    // Within an epoch a non-increasing counter is still refused.
    let refused = db.write_tx(|tx| {
        send_counter::record_peer_send_counter(tx, CONVO_ID, 0, 9, BOB_DID, DEV_B1, Some(30), 11, 1)
    });
    assert!(refused.is_err());
}

const OWN_M1: &str = "55555555-5555-4555-8555-555555555501";

fn insert_row(
    client: &CatbirdMlsClient,
    group_id: &[u8],
    id: &str,
    did: &str,
    dev: &str,
    seq: i64,
) {
    client
        .db
        .write_tx(|tx| {
            tx.insert_message(&MessageRow {
                message_id: id.to_string(),
                conversation_id: CONVO_ID.to_string(),
                group_id: group_id.to_vec(),
                epoch: 0,
                seq,
                sender_did: did.to_string(),
                sender_device_id: dev.to_string(),
                plaintext_json: "{}".to_string(),
                created_at_ms: 1_000,
                is_own: did == ALICE_DID,
            })
        })
        .unwrap();
}

/// A `payloadPruned` application entry of `sender` at `seq`, under the sequencer receipt.
fn pruned_entry(
    state: &Arc<Mutex<SyncMockState>>,
    group_id: &[u8],
    epoch: u64,
    msg_id: &str,
    sender_did: &str,
    sender_dev: &str,
    seq: i64,
) -> Value {
    let sk = sequencer_key(state);
    json!({
        "$type": crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
        "entryId": msg_id,
        "conversationId": CONVO_ID,
        "seq": seq,
        "payloadPruned": true,
        "sequencerReceipt": sign_app_receipt(
            &sk, SEQUENCER_DID, CONVO_ID, 0, group_id, epoch, sender_did, sender_dev, msg_id,
            seq as u64, [9u8; 32],
        ),
    })
}

fn apply_served_entries(client: &CatbirdMlsClient, signer: &SignatureKeyPair) {
    let convo_row = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    client
        .apply_conversation_entries(DEV_A1, signer, &convo_row, &mut pass)
        .unwrap();
}

#[test]
fn an_entry_served_at_a_seq_receipted_for_an_own_message_is_recorded_not_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "own",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (signer, group_id, coords) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 5, &[]);
    let epoch = coords["epoch"].as_u64().unwrap();
    let bob = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    {
        let mut st = state.lock().unwrap();
        st.pds_devices.insert(
            ALICE_DID.to_string(),
            vec![(DEV_A1.to_string(), signer.public().to_vec())],
        );
        st.pds_devices.insert(
            BOB_DID.to_string(),
            vec![(DEV_B1.to_string(), bob.public().to_vec())],
        );
    }
    // The sequencer receipted an own message at seq 6, then serves Bob's entry there.
    insert_row(&client, &group_id, OWN_M1, ALICE_DID, DEV_A1, 6);
    let served = pruned_entry(&state, &group_id, epoch, BOB_M1, BOB_DID, DEV_B1, 6);
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(5, vec![served]);
    apply_served_entries(&client, &signer);
    let mismatches = client
        .db
        .read_tx(|tx| send_counter::list_own_receipt_mismatches(tx, CONVO_ID))
        .unwrap();
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert_eq!(mismatches[0].kind, "entry-differs");
    assert_eq!(mismatches[0].seq, 6);
    assert_eq!(mismatches[0].own_message_id, OWN_M1);
    assert_eq!(mismatches[0].other_message_id.as_deref(), Some(BOB_M1));
    // Never blocks: the cursor moved past the entry.
    let convo = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    assert_eq!(convo.last_seq, 6);
}

#[test]
fn an_own_receipt_for_a_seq_another_message_holds_is_recorded() {
    let db = crate::storage::MlsAccountDb::open_in_memory_for_test().unwrap();
    db.write_tx(|tx| {
        tx.insert_message(&MessageRow {
            message_id: BOB_M1.to_string(),
            conversation_id: CONVO_ID.to_string(),
            group_id: vec![1; 32],
            epoch: 0,
            seq: 7,
            sender_did: BOB_DID.to_string(),
            sender_device_id: DEV_B1.to_string(),
            plaintext_json: "{}".to_string(),
            created_at_ms: 1,
            is_own: false,
        })?;
        send_counter::check_own_receipt_slot(tx, CONVO_ID, 8, OWN_M1, 1)?;
        send_counter::check_own_receipt_slot(tx, CONVO_ID, 7, OWN_M1, 1)
    })
    .unwrap();
    let mismatches = db
        .read_tx(|tx| send_counter::list_own_receipt_mismatches(tx, CONVO_ID))
        .unwrap();
    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        (mismatches[0].seq, mismatches[0].kind.as_str()),
        (7, "slot-taken")
    );
}
