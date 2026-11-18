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
    let export: Value = serde_json::from_str(
        &client
            .export_conversation_integrity_evidence_json(CONVO_ID)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(export["sendCounterEvidence"][0]["kind"], "gap");
    assert_eq!(export["unverifiedAccountDeletions"], json!([]));
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
    // Within an epoch a non-increasing counter is evidence and cannot lower the high-water mark.
    db.write_tx(|tx| {
        send_counter::record_peer_send_counter(tx, CONVO_ID, 0, 9, BOB_DID, DEV_B1, Some(30), 11, 1)
    })
    .unwrap();
    db.write_tx(|tx| {
        send_counter::record_peer_send_counter(tx, CONVO_ID, 0, 9, BOB_DID, DEV_B1, Some(31), 12, 1)
    })
    .unwrap();
    let evidence = db
        .read_tx(|tx| send_counter::list_send_counter_evidence(tx, CONVO_ID))
        .unwrap();
    assert_eq!(evidence.last().unwrap().kind, "regressed");
    assert_eq!(evidence.last().unwrap().seq, 11);
    let high_water = db
        .read_tx(|tx| {
            tx.get_account_meta(&chat_wire::peer_send_counter_key(
                CONVO_ID, 0, 9, BOB_DID, DEV_B1,
            ))
        })
        .unwrap();
    assert_eq!(high_water.as_deref(), Some("31"));
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
        .apply_conversation_entries(DEV_A1, signer, &convo_row, &mut pass, &mut Vec::new())
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

#[test]
fn a_pruned_entry_never_received_leaves_evidence_and_a_placeholder_without_inventing_a_counter() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "pruned",
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
    // Bob's counter 2 was verified at seq 5.
    client
        .db
        .write_tx(|tx| {
            send_counter::record_peer_send_counter(
                tx,
                CONVO_ID,
                0,
                epoch as i64,
                BOB_DID,
                DEV_B1,
                Some(2),
                5,
                1,
            )
            .map(|_| ())
        })
        .unwrap();
    let served = pruned_entry(&state, &group_id, epoch, BOB_M1, BOB_DID, DEV_B1, 6);
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(5, vec![served]);
    apply_served_entries(&client, &signer);

    let row = client
        .db
        .read_tx(|tx| tx.get_message(BOB_M1))
        .unwrap()
        .expect("placeholder row");
    assert_eq!(row.seq, 6);
    assert!(row
        .plaintext_json
        .contains(chat_wire::UNAVAILABLE_MESSAGE_NOTICE));
    let evidence: chat_wire::UnavailableEntryEvidence = serde_json::from_slice(
        &client
            .db
            .read_tx(|tx| {
                tx.get_labyrinth_state(&chat_wire::unavailable_message_key(CONVO_ID, BOB_M1))
            })
            .unwrap()
            .expect("receipt evidence"),
    )
    .unwrap();
    assert_eq!((evidence.seq, evidence.sender_did.as_str()), (6, BOB_DID));
    assert_eq!(evidence.receipt["entryId"], BOB_M1);
    let per_epoch = chat_wire::peer_send_counter_key(CONVO_ID, 0, epoch as i64, BOB_DID, DEV_B1);
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_account_meta(&per_epoch))
            .unwrap(),
        Some("2".to_string()),
        "the pruned entry does not bump the counter"
    );

    // Bob's next message carries 4: the pruned entry held 3, so there is no gap.
    let receipt = stage_nse_message(
        &client,
        &group_id,
        &sequencer_key(&state),
        BOB_M2,
        BOB_DID,
        DEV_B1,
        7,
        None,
    );
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            BOB_M2,
            7,
            BOB_M2,
            &receipt,
            Some((BOB_DID, DEV_B1)),
            Some(4),
            DEV_A1,
        )
        .unwrap();
    assert_eq!(counter_evidence(&client), vec![]);
}

// --- Signed account deletions ---

use crate::client::deletion_authority::{self as authority, UnverifiedDeletionReason};
use crate::client::live_sync::live_integrity::AccountDeletionDecision;

const DELETION_OP: &str = "0123456789abcdef0123456789abcdef";
const SIGNED_AT: &str = "2026-11-16T12:00:00.000Z";
const SIGNED_AT_MS: i64 = 1_794_830_400_000;

fn deletion_write(signer: &SignatureKeyPair, device: &str, op: &str, signed_at: &str) -> Value {
    let body = serde_json::to_vec(&json!({
        "operationId": op,
        "actorDeviceId": device,
        "endpointNsid": authority::DELETE_ACCOUNT_DATA_NSID,
        "payloadSha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "signedAt": signed_at,
    }))
    .unwrap();
    let signature = signer
        .sign(&crate::labyrinth::write_auth::WriteBody::signing_input(
            &body,
        ))
        .unwrap();
    json!({
        "writeBody": { "$bytes": STANDARD.encode(&body) },
        "payloadBytes": { "$bytes": STANDARD.encode(b"{}") },
        "signature": { "$bytes": STANDARD.encode(signature) },
    })
}

#[allow(clippy::too_many_arguments)]
fn deletion_entry(
    state: &Arc<Mutex<SyncMockState>>,
    cid: &str,
    deleted_did: &str,
    seq: i64,
    entry_id: &str,
    actor_write: Option<Value>,
    key_proof: Option<Vec<u8>>,
) -> Value {
    let sk = sequencer_key(state);
    let received_at = "2026-11-16T12:01:00.000Z";
    let key_id = expected_receipt_key_id(SEQUENCER_DID);
    let seq_text = seq.to_string();
    let fields = [
        SEQUENCER_DID,
        cid,
        deleted_did,
        seq_text.as_str(),
        entry_id,
        received_at,
    ];
    let transcript = chat_wire::account_deletion_authority_signing_bytes(&key_id, &fields).unwrap();
    use p256::ecdsa::signature::Signer as _;
    let sig: p256::ecdsa::Signature = sk.sign(&transcript);
    let sig = sig.normalize_s().unwrap_or(sig).to_bytes().to_vec();
    let mut entry = json!({
        "$type": crate::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND,
        "conversationId": cid,
        "sequencerDid": SEQUENCER_DID,
        "seq": seq,
        "deletedDid": deleted_did,
        "entryId": entry_id,
        "receivedAt": received_at,
        "sequencerAuthority": {
            "sequencerDid": SEQUENCER_DID,
            "keyId": key_id,
            "signature": { "$bytes": STANDARD.encode(&sig) },
        }
    });
    if let Some(actor_write) = actor_write {
        entry["actorWrite"] = actor_write;
    }
    if let Some(proof) = key_proof {
        entry["keyProof"] = json!({ "$bytes": STANDARD.encode(proof) });
    }
    entry
}

/// Alice's client with Bob holding a leaf in the conversation; returns Bob's leaf signer.
fn client_with_bob_leaf(
    tmp: &tempfile::TempDir,
) -> (
    Arc<CatbirdMlsClient>,
    Arc<Mutex<SyncMockState>>,
    SignatureKeyPair,
    SignatureKeyPair,
    Vec<u8>,
) {
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        tmp,
        "deletion",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (bob_signer, bob_kp, _) = build_kp_value_and_bundle(&client, BOB_DID, DEV_B1);
    state.lock().unwrap().pds_devices.insert(
        BOB_DID.to_string(),
        vec![(DEV_B1.to_string(), bob_signer.public().to_vec())],
    );
    let (alice_signer, group_id, _) =
        seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 5, &[bob_kp]);
    state.lock().unwrap().pds_devices.insert(
        ALICE_DID.to_string(),
        vec![(DEV_A1.to_string(), alice_signer.public().to_vec())],
    );
    (client, state, alice_signer, bob_signer, group_id)
}

fn message_ids(client: &CatbirdMlsClient) -> Vec<String> {
    let mut ids: Vec<String> = client
        .list_messages(CONVO_ID, None, 50)
        .unwrap()
        .into_iter()
        .map(|m| m.message_id)
        .collect();
    ids.sort();
    ids
}

#[test]
fn a_valid_local_leaf_deletion_is_quarantined_without_nonrevocation_proof() {
    let tmp = tempfile::tempdir().unwrap();
    let (client, state, alice_signer, bob_signer, group_id) = client_with_bob_leaf(&tmp);
    let before = SIGNED_AT_MS;
    let after = SIGNED_AT_MS + authority::DELETION_CLOCK_SKEW_MS + 1;
    client
        .db
        .write_tx(|tx| {
            for (id, at) in [(BOB_M1, before), (BOB_M2, after)] {
                tx.insert_message(&MessageRow {
                    message_id: id.into(),
                    conversation_id: CONVO_ID.into(),
                    group_id: group_id.clone(),
                    epoch: 0,
                    seq: 3,
                    sender_did: BOB_DID.into(),
                    sender_device_id: DEV_B1.into(),
                    plaintext_json: "{}".into(),
                    created_at_ms: at,
                    is_own: false,
                })?;
            }
            Ok(())
        })
        .unwrap();
    let write = deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT);
    let entry = deletion_entry(&state, CONVO_ID, BOB_DID, 6, BOB_M3, Some(write), None);
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(5, vec![entry]);
    let convo = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    let mut pass = EntryPass {
        max_seq: convo.last_seq,
        ..EntryPass::default()
    };
    assert!(client
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo, &mut pass, &mut Vec::new())
        .unwrap_err()
        .to_string()
        .contains("AccountDeletionUnverified"));
    assert_eq!(
        message_ids(&client),
        vec![BOB_M1.to_string(), BOB_M2.to_string()]
    );
    assert!(client
        .db
        .read_tx(|tx| tx.get_labyrinth_state(&chat_wire::account_deletion_key(CONVO_ID, BOB_DID)))
        .unwrap()
        .is_none());
    assert_eq!(
        client.unverified_account_deletions(CONVO_ID).unwrap()[0].reason,
        UnverifiedDeletionReason::RevocationStatusUnproven,
    );
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_conversation(CONVO_ID))
            .unwrap()
            .unwrap()
            .last_seq,
        5,
    );
}

#[test]
fn deletion_uses_stored_receipt_time_for_message_and_queued_copy() {
    let db = crate::storage::MlsAccountDb::open_in_memory_for_test().unwrap();
    let bound = SIGNED_AT_MS + authority::DELETION_CLOCK_SKEW_MS;
    let stored = |issued_at_ms| {
        serde_json::to_string(&chat_wire::StoredArchivedReceipt {
            sequencer_did: SEQUENCER_DID.into(),
            conversation_id: CONVO_ID.into(),
            group_id: vec![1; 32],
            epoch: 0,
            sender_device_did_url: format!("{BOB_DID}#device"),
            entry_id: BOB_M1.into(),
            archive_commitment: vec![2; 32],
            seq: 3,
            issued_at_ms,
            key_id: "test".into(),
            signature: vec![3; 64],
            generation: 0,
            original_sender_attestation: None,
        })
        .unwrap()
    };
    let marker = authority::StoredAccountDeletion::Signed(authority::AppliedAccountDeletion {
        seq: 6,
        signed_at_ms: SIGNED_AT_MS,
        operation_id: DELETION_OP.into(),
        actor_device_id: None,
    });
    db.write_tx(|tx| {
        for (id, local_at, receipt_at) in
            [(BOB_M1, bound + 1, bound), (BOB_M2, bound - 1, bound + 1)]
        {
            tx.insert_message(&MessageRow {
                message_id: id.into(),
                conversation_id: CONVO_ID.into(),
                group_id: vec![1; 32],
                epoch: 0,
                seq: 3,
                sender_did: BOB_DID.into(),
                sender_device_id: DEV_B1.into(),
                plaintext_json: "{}".into(),
                created_at_ms: local_at,
                is_own: false,
            })?;
            tx.put_labyrinth_state(
                &format!("native.message:{CONVO_ID}:{id}"),
                &serde_json::to_vec(&json!({ "sequencer_receipt_json": stored(receipt_at) }))?,
                local_at,
            )?;
            let queued_id = format!("queue:{id}");
            tx.enqueue_labyrinth_item(&crate::storage::LabyrinthQueueRow {
                item_id: queued_id,
                conversation_id: CONVO_ID.into(),
                group_id_hex: "01".into(),
                seq: 3,
                payload_bytes: serde_json::to_vec(&json!({
                    "sender_did": BOB_DID,
                    "created_at_ms": local_at,
                    "sequencer_receipt_json": stored(receipt_at),
                }))?,
                created_at_ms: local_at,
            })?;
        }
        tx.put_labyrinth_state(
            &format!("native.message:{CONVO_ID}:{BOB_M3}"),
            &serde_json::to_vec(&json!({ "sequencer_receipt_json": stored(bound) }))?,
            bound,
        )?;
        assert_eq!(
            crate::client::live_sync::live_integrity::purge_covered_messages(
                tx, CONVO_ID, BOB_DID, &marker,
            )?,
            1,
        );
        assert!(tx.get_message(BOB_M1)?.is_none());
        assert!(tx.get_message(BOB_M2)?.is_some());
        assert!(tx
            .get_labyrinth_state(&format!("native.message:{CONVO_ID}:{BOB_M1}"))?
            .is_none());
        assert!(tx
            .get_labyrinth_state(&format!("native.message:{CONVO_ID}:{BOB_M2}"))?
            .is_some());
        assert!(tx
            .get_labyrinth_state(&format!("native.message:{CONVO_ID}:{BOB_M3}"))?
            .is_none());
        let remaining = tx.list_labyrinth_queue(Some(CONVO_ID), 10)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].item_id, format!("queue:{BOB_M2}"));
        Ok(())
    })
    .unwrap();
}

#[test]
fn c33_deletion_scrubs_request_copies_and_preserves_consent_and_uncovered_openings() {
    use crate::client::live_sync::live_integrity::{
        migrate_opening_deletions, opening_receipt_key, reapply_opening_deletion,
    };
    let tmp = tempfile::tempdir().unwrap();
    let (client, _, _, _, _) = client_with_bob_leaf(&tmp);
    let now = SIGNED_AT_MS + authority::DELETION_CLOCK_SKEW_MS;
    let marker = authority::StoredAccountDeletion::Signed(authority::AppliedAccountDeletion {
        seq: 6,
        signed_at_ms: SIGNED_AT_MS,
        operation_id: DELETION_OP.into(),
        actor_device_id: Some(DEV_B1.into()),
    });
    let receipt =
        |mid: &str, sender: &str, seq: u64, issued_at_ms: i64| chat_wire::StoredArchivedReceipt {
            sequencer_did: SEQUENCER_DID.into(),
            conversation_id: CONVO_ID.into(),
            group_id: vec![2; 32],
            epoch: 1,
            sender_device_did_url: format!("{sender}#{DEV_B1}"),
            entry_id: mid.into(),
            archive_commitment: vec![3; 32],
            seq,
            issued_at_ms,
            key_id: "test".into(),
            signature: vec![4; 64],
            generation: 0,
            original_sender_attestation: None,
        };
    let stage_key = format!("c33_pending_opening:{CONVO_ID}");
    let first = crate::client::QueuedLabyrinthArchivePayload {
        version: 1,
        message_id: BOB_M1.into(),
        conversation_id: CONVO_ID.into(),
        group_id_hex: "02".into(),
        epoch: 1,
        expected_member_dids: vec![],
        seq: 3,
        sender_did: BOB_DID.into(),
        sender_device_id: DEV_B1.into(),
        sequencer_did: SEQUENCER_DID.into(),
        space_uri: None,
        plaintext_json: "old preview".into(),
        labyrinth_frame_json: "old plaintext".into(),
        mls_ciphertext_b64: String::new(),
        frame_nonce_b64: None,
        sequencer_receipt_json: Some(
            serde_json::to_string(&receipt(BOB_M1, BOB_DID, 3, now)).unwrap(),
        ),
        original_sender_attestation_json: None,
        created_at_ms: now + 100,
    };
    let store_stage = |tx: &crate::storage::SqlTx<'_>| {
        tx.put_account_meta(&stage_key, &serde_json::to_string(&first)?, now)?;
        tx.put_labyrinth_state(
            &format!("native.message:{CONVO_ID}:{BOB_M1}"),
            &serde_json::to_vec(&first)?,
            now,
        )
    };
    client
        .db
        .write_tx(|tx| {
            for (mid, did, consent) in [
                (BOB_M1, BOB_DID, "accepted"),
                (BOB_M2, BOB_DID, "outgoingPending"),
                (BOB_M3, ALICE_DID, "incomingPending"),
                ("legacy-orphan", BOB_DID, "incomingPending"),
            ] {
                tx.upsert_request(&crate::storage::RequestRow {
                    request_id: mid.into(),
                    conversation_id: CONVO_ID.into(),
                    sender_did: did.into(),
                    recipient_did: ALICE_DID.into(),
                    consent: consent.into(),
                    first_message_id: Some(mid.into()),
                    first_message_archived: false,
                    payload_json: "visible preview".into(),
                    expires_at_ms: 0,
                    updated_at_ms: now,
                })?;
            }
            store_stage(tx)?;
            tx.enqueue_labyrinth_item(&crate::storage::LabyrinthQueueRow {
                item_id: BOB_M1.into(),
                conversation_id: CONVO_ID.into(),
                group_id_hex: "02".into(),
                seq: 3,
                payload_bytes: serde_json::to_vec(&first)?,
                created_at_ms: now + 100,
            })?;
            tx.put_labyrinth_state(
                &opening_receipt_key(CONVO_ID, BOB_M2),
                &serde_json::to_vec(&receipt(BOB_M2, BOB_DID, 4, now + 1))?,
                now,
            )?;
            tx.put_labyrinth_state(
                &chat_wire::account_deletion_key(CONVO_ID, BOB_DID),
                &marker.encode().unwrap(),
                now,
            )?;
            tx.delete_account_meta("c33_opening_erasure_v1")?;
            migrate_opening_deletions(tx, now)?;
            let rows = tx.list_requests(None)?;
            for (mid, expected, consent) in [
                (BOB_M1, "{}", "accepted"),
                (BOB_M2, "visible preview", "outgoingPending"),
                (BOB_M3, "visible preview", "incomingPending"),
                ("legacy-orphan", "{}", "incomingPending"),
            ] {
                let row = rows.iter().find(|r| r.request_id == mid).unwrap();
                assert_eq!(row.payload_json, expected);
                assert_eq!(row.consent, consent);
            }
            assert!(tx.get_account_meta(&stage_key)?.is_none());
            assert!(tx
                .get_labyrinth_state(&format!("native.message:{CONVO_ID}:{BOB_M1}"))?
                .is_none());
            assert!(tx.list_labyrinth_queue(Some(CONVO_ID), 10)?.is_empty());
            store_stage(tx)?;
            reapply_opening_deletion(tx, CONVO_ID, BOB_DID)?;
            assert!(tx.get_account_meta(&stage_key)?.is_none());
            store_stage(tx)
        })
        .unwrap();
    client.archive_accepted_opening_messages(CONVO_ID).unwrap();
    client
        .db
        .read_tx(|tx| {
            assert!(tx.get_account_meta(&stage_key)?.is_none());
            assert!(tx.list_labyrinth_queue(Some(CONVO_ID), 10)?.is_empty());
            Ok(())
        })
        .unwrap();
}

#[test]
fn forged_unsigned_and_genuine_deletions_hold_cursor_without_purging() {
    let tmp = tempfile::tempdir().unwrap();
    let (client, state, alice_signer, bob_signer, group_id) = client_with_bob_leaf(&tmp);
    insert_row(&client, &group_id, BOB_M1, BOB_DID, DEV_B1, 3);
    let forger = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let try_sync = || {
        let convo = client
            .db
            .read_tx(|tx| tx.get_conversation(CONVO_ID))
            .unwrap()
            .unwrap();
        let mut pass = EntryPass {
            max_seq: convo.last_seq,
            ..EntryPass::default()
        };
        client.apply_conversation_entries(DEV_A1, &alice_signer, &convo, &mut pass, &mut Vec::new())
    };
    let cursor = || {
        client
            .db
            .read_tx(|tx| tx.get_conversation(CONVO_ID))
            .unwrap()
            .unwrap()
            .last_seq
    };
    for (write, reason) in [
        (
            Some(deletion_write(&forger, DEV_B1, DELETION_OP, SIGNED_AT)),
            UnverifiedDeletionReason::BadSignature,
        ),
        (None, UnverifiedDeletionReason::NoActorWrite),
    ] {
        let entry = deletion_entry(&state, CONVO_ID, BOB_DID, 6, BOB_M2, write, None);
        state
            .lock()
            .unwrap()
            .entries_by_after
            .insert(5, vec![entry]);
        assert!(try_sync()
            .unwrap_err()
            .to_string()
            .contains("AccountDeletionUnverified"));
        assert_eq!(cursor(), 5, "an unresolved deletion holds the live cursor");
        assert_eq!(message_ids(&client), vec![BOB_M1.to_string()]);
        assert_eq!(
            client.unverified_account_deletions(CONVO_ID).unwrap()[0].reason,
            reason,
        );
    }

    // Even the genuine actor signature cannot prove historical non-revocation.
    let genuine = deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT);
    let first = deletion_entry(&state, CONVO_ID, BOB_DID, 6, BOB_M2, Some(genuine), None);
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(5, vec![first]);
    assert!(try_sync()
        .unwrap_err()
        .to_string()
        .contains("AccountDeletionUnverified"));
    assert_eq!(cursor(), 5);
    assert_eq!(message_ids(&client), vec![BOB_M1.to_string()]);
    assert_eq!(
        client.unverified_account_deletions(CONVO_ID).unwrap()[0].reason,
        UnverifiedDeletionReason::RevocationStatusUnproven,
    );
}

#[test]
fn revocation_at_signed_instant_is_rejected_and_later_revocation_does_not_authorize_purge() {
    let tmp = tempfile::tempdir().unwrap();
    let (client, state, _, bob_signer, _) = client_with_bob_leaf(&tmp);
    let entry = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        6,
        BOB_M3,
        Some(deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT)),
        None,
    );
    let key = authority::verified_device_revocation_key(BOB_DID, DEV_B1);
    client
        .db
        .write_tx(|tx| tx.put_account_meta(&key, &SIGNED_AT_MS.to_string(), 1))
        .unwrap();
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::DeviceRevokedAtSignedAt,
            ..
        }
    ));
    client
        .db
        .write_tx(|tx| tx.put_account_meta(&key, &(SIGNED_AT_MS + 1).to_string(), 1))
        .unwrap();
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::RevocationStatusUnproven,
            ..
        }
    ));
}

#[test]
fn deletion_operation_dedupe_is_rechecked_in_the_apply_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let (client, state, alice_signer, bob_signer, _) = client_with_bob_leaf(&tmp);
    let first = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        6,
        BOB_M2,
        Some(deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT)),
        None,
    );
    let later = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        7,
        BOB_M3,
        Some(deletion_write(
            &bob_signer,
            DEV_B1,
            "fedcba9876543210fedcba9876543210",
            SIGNED_AT,
        )),
        None,
    );
    // Exercise the lower-level idempotency transaction with synthetic Apply decisions. The
    // public authorizer currently quarantines both until historical status proof exists.
    let first_decision = AccountDeletionDecision::Apply {
        deleted_did: BOB_DID.into(),
        seq: 6,
        write: authority::parse_actor_write(&first).unwrap(),
    };
    let later_decision = AccountDeletionDecision::Apply {
        deleted_did: BOB_DID.into(),
        seq: 7,
        write: authority::parse_actor_write(&later).unwrap(),
    };
    client
        .apply_account_deletion_decision(CONVO_ID, &first, &first_decision)
        .unwrap();
    client
        .apply_account_deletion_decision(CONVO_ID, &later, &later_decision)
        .unwrap();
    let marker = client
        .db
        .read_tx(|tx| tx.get_labyrinth_state(&chat_wire::account_deletion_key(CONVO_ID, BOB_DID)))
        .unwrap()
        .and_then(|raw| authority::AppliedAccountDeletion::decode(&raw))
        .unwrap();
    assert_eq!(marker.seq(), 7);
    assert!(marker.operation(DELETION_OP).is_some());
    assert!(marker
        .operation("fedcba9876543210fedcba9876543210")
        .is_some());
    // A replay at another sequence leaves the two original cutoffs intact.
    client
        .db
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "UPDATE conversations SET last_seq = 7 WHERE conversation_id = ?1",
                    rusqlite::params![CONVO_ID],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .unwrap();
    let replayed_live = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        8,
        BOB_M3,
        Some(deletion_write(
            &bob_signer,
            DEV_B1,
            "0123456789abcdef0123456789abcdef",
            SIGNED_AT,
        )),
        None,
    );
    let convo = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(convo.last_seq, vec![replayed_live]);
    let mut pass = EntryPass {
        max_seq: convo.last_seq,
        ..EntryPass::default()
    };
    client
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo, &mut pass, &mut Vec::new())
        .expect("replayed accountDeletedEntry must advance sync cursor after quarantining evidence");
    let convo_after = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    assert_eq!(convo_after.last_seq, 8);
    let marker_after = client
        .db
        .read_tx(|tx| tx.get_labyrinth_state(&chat_wire::account_deletion_key(CONVO_ID, BOB_DID)))
        .unwrap()
        .and_then(|raw| authority::AppliedAccountDeletion::decode(&raw))
        .unwrap();
    assert_eq!(marker_after.seq(), 7);
    assert!(client
        .unverified_account_deletions(CONVO_ID)
        .unwrap()
        .iter()
        .any(|ev| ev.seq == 8 && ev.reason == UnverifiedDeletionReason::Replayed));
}

#[test]
fn a_deletion_sequenced_for_another_conversation_is_kept_as_evidence_only() {
    let tmp = tempfile::tempdir().unwrap();
    let (client, state, alice_signer, bob_signer, group_id) = client_with_bob_leaf(&tmp);
    insert_row(&client, &group_id, BOB_M1, BOB_DID, DEV_B1, 3);
    let write = deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT);
    let mut other = deletion_entry(
        &state,
        "22222222-2222-4222-8222-222222222222",
        BOB_DID,
        6,
        BOB_M2,
        Some(write),
        None,
    );
    other["conversationId"] = json!("22222222-2222-4222-8222-222222222222");
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(5, vec![other]);
    apply_served_entries(&client, &alice_signer);
    assert_eq!(message_ids(&client), vec![BOB_M1.to_string()]);
    let kept = client.unverified_account_deletions(CONVO_ID).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].reason, UnverifiedDeletionReason::OtherConversation);
    let convo = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    assert_eq!(convo.last_seq, 6);

    // One this conversation's sequencer did not sign stops the sync below it, with no effect.
    let write = deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT);
    let mut edited = deletion_entry(&state, CONVO_ID, BOB_DID, 7, BOB_M3, Some(write), None);
    edited["deletedDid"] = json!(ALICE_DID);
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(6, vec![edited]);
    let mut pass = EntryPass {
        max_seq: convo.last_seq,
        ..EntryPass::default()
    };
    let error = client
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo, &mut pass, &mut Vec::new())
        .unwrap_err();
    assert!(error.to_string().contains("account deletion"), "{error}");
    assert_eq!(
        client.unverified_account_deletions(CONVO_ID).unwrap().len(),
        1
    );
    let convo = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    assert_eq!(convo.last_seq, 6);
    assert_eq!(message_ids(&client), vec![BOB_M1.to_string()]);
}

#[cfg(feature = "labyrinth")]
#[test]
fn a_fresh_device_verifies_a_deletion_through_its_key_proof() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "fresh",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    // No local conversation, no leaf of Bob and no PDS record: only the proof remains.
    let bob_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let record = json!({
        "$type": "blue.catbird.chat.device",
        "algorithm": "Ed25519",
        "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(bob_signer.public()) },
        "createdAt": "2026-11-14T00:00:00.000Z",
    });
    let (_, cbor) =
        crate::labyrinth::repo_proof::encode_atproto_json_record_dagcbor(&record).unwrap();
    let signing_key = atproto_spaces::tokens::SpaceSigningKey::from_p256_secret(
        &plc_atproto_secret(BOB_DID),
        format!("{BOB_DID}#atproto"),
    );
    let (_, proof) = crate::labyrinth::repo_proof::build_repo_proof_car_v1(
        BOB_DID,
        "3lb2zzzzzzzzz",
        &[(format!("blue.catbird.chat.device/{DEV_B1}"), cbor.clone())],
        &signing_key,
    )
    .unwrap();
    let write = deletion_write(&bob_signer, DEV_B1, DELETION_OP, SIGNED_AT);
    let entry = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        6,
        BOB_M2,
        Some(write.clone()),
        Some(proof.clone()),
    );
    state.lock().unwrap().fail_next_did_resolve_for = Some(BOB_DID.into());
    assert!(client
        .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
        .unwrap_err()
        .to_string()
        .contains("injected DID resolver outage"));
    let did_doc = serde_json::to_vec(&plc_did_doc(BOB_DID)).unwrap();
    assert_eq!(
        authority::device_key_from_key_proof(&proof, BOB_DID, DEV_B1, SIGNED_AT_MS, &did_doc,),
        Some(bob_signer.public().to_vec()),
        "server-shaped chat.device record is bound by its CAR path",
    );
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::RevocationStatusUnproven,
            ..
        }
    ));
    // The canonical record has no deviceId field. Its identity comes from the signed MST path.
    let (_, wrong_path_proof) = crate::labyrinth::repo_proof::build_repo_proof_car_v1(
        BOB_DID,
        "3lb2zzzzzzzzz",
        &[(format!("blue.catbird.chat.device/{DEV_A1}"), cbor.clone())],
        &signing_key,
    )
    .unwrap();
    let wrong_path = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        6,
        BOB_M2,
        Some(write.clone()),
        Some(wrong_path_proof),
    );
    assert!(authority::device_key_from_key_proof(
        &authority::key_proof_bytes(&wrong_path).unwrap(),
        BOB_DID,
        DEV_B1,
        SIGNED_AT_MS,
        &did_doc,
    )
    .is_none());
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &wrong_path)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::DeviceKeyUnavailable,
            ..
        }
    ));
    // Even a later observed revocation does not prove that an earlier one was absent.
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &authority::verified_device_revocation_key(BOB_DID, DEV_B1),
                &(SIGNED_AT_MS + 1).to_string(),
                1,
            )
        })
        .unwrap();
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::RevocationStatusUnproven,
            ..
        }
    ));
    // A later enrollment cannot authorize a deletion signed before the device existed.
    let mut future_record = record.clone();
    future_record["createdAt"] = json!("2026-11-17T00:00:00.000Z");
    let (_, future_cbor) =
        crate::labyrinth::repo_proof::encode_atproto_json_record_dagcbor(&future_record).unwrap();
    let (_, future_proof) = crate::labyrinth::repo_proof::build_repo_proof_car_v1(
        BOB_DID,
        "3lb3zzzzzzzzz",
        &[(format!("blue.catbird.chat.device/{DEV_B1}"), future_cbor)],
        &signing_key,
    )
    .unwrap();
    let future_entry = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        6,
        BOB_M2,
        Some(write.clone()),
        Some(future_proof),
    );
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &future_entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::DeviceKeyUnavailable,
            ..
        }
    ));
    // A proof of another device key does not lend its authority to a forged request.
    let forger = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let forged = deletion_write(&forger, DEV_B1, DELETION_OP, SIGNED_AT);
    let entry = deletion_entry(
        &state,
        CONVO_ID,
        BOB_DID,
        6,
        BOB_M2,
        Some(forged),
        Some(proof),
    );
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::BadSignature,
            ..
        }
    ));
    // Without the proof the same genuine request has no key to verify against.
    let entry = deletion_entry(&state, CONVO_ID, BOB_DID, 6, BOB_M2, Some(write), None);
    assert!(matches!(
        client
            .authorize_account_deletion(CONVO_ID, SEQUENCER_DID, &entry)
            .unwrap(),
        AccountDeletionDecision::Unverified {
            reason: UnverifiedDeletionReason::DeviceKeyUnavailable,
            ..
        }
    ));
}
