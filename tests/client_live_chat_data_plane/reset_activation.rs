//! Reset activation: admin authority by the verified roster, `reset_conversation`'s journaled own
//! activation and its echo, and the reset-retired device's rejoin.

use super::*;

/// `cid`'s verified roster as `client` holds it.
fn roster(client: &CatbirdMlsClient, cid: &str) -> Option<Value> {
    client
        .db()
        .read_tx(|tx| tx.get_account_meta(&chat_wire::conversation_roster_key(cid)))
        .unwrap()
        .map(|raw| serde_json::from_str(&raw).unwrap())
}

/// What a refused reset leaves as it was on `client`: the conversation's group, generation, epoch
/// and cursor, its recorded coordinates, its MLS members and its verified roster.
type ResetState = (
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<String>,
    Option<Vec<String>>,
    Option<Value>,
);

fn reset_state(client: &CatbirdMlsClient, cid: &str) -> ResetState {
    let row = client
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap();
    (
        row.group_id,
        row.generation,
        row.epoch,
        row.last_seq,
        stored_coordinates(client, cid),
        client.list_members(cid).ok(),
        roster(client, cid),
    )
}

fn acked(ds: &SharedMockDs, cid: &str, device: &str) -> Option<i64> {
    ds.inner
        .lock()
        .unwrap()
        .acked_watermarks
        .get(&(cid.to_owned(), device.to_owned()))
        .copied()
}

/// How many requests mls-ds saw on `account`'s session.
fn requests_from(ds: &SharedMockDs, account: &str) -> usize {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(session, _, _)| session == account)
        .count()
}

fn reset_journal_count(client: &CatbirdMlsClient, cid: &str) -> i64 {
    client
        .db()
        .read_tx(|tx| {
            tx.conn()
                .query_row(
                    "SELECT count(*) FROM pending_ops \
                     WHERE op_kind = 'reset_activation' \
                     AND json_extract(payload_json, '$.conversation_id') = ?1",
                    [cid],
                    |row| row.get(0),
                )
                .map_err(|error| MLSError::Internal(error.to_string()))
        })
        .unwrap()
}

fn activation_requests(ds: &SharedMockDs) -> Vec<Value> {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.activateReset"))
        .map(|(_, _, body)| serde_json::from_slice(body).unwrap())
        .collect()
}

/// The one conversation `client`'s sync reports failing: `cid`, with its error.
fn sync_failure(client: &CatbirdMlsClient, cid: &str) -> MLSError {
    match client.sync() {
        Err(MLSError::SyncIncomplete { mut failures, .. }) => {
            assert_eq!(failures.len(), 1, "{failures:?}");
            let failure = failures.remove(0);
            assert_eq!(failure.conversation_id, cid);
            *failure.error
        }
        other => panic!("expected {cid} to fail sync, got {other:?}"),
    }
}

/// mls-ds's participant rows of `cid`, as a reset manifest echoes them.
pub(super) fn manifest_participants(ds: &SharedMockDs, cid: &str) -> Value {
    let g = ds.inner.lock().unwrap();
    g.conversations[cid]["participants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let mut participant = json!({
                "userDid": row["userDid"], "role": row["role"], "status": row["status"],
            });
            if let Some(provenance) = row.get("invitationProvenance") {
                participant["invitationProvenance"] = provenance.clone();
            }
            participant
        })
        .collect()
}

/// A reset activation of `prior`'s conversation signed by the device `(did, device)`, opening
/// its successor on a fresh group.
pub(super) fn activation(
    signer: &SignatureKeyPair,
    did: &str,
    device: &str,
    prior: &Value,
    participants: &Value,
) -> Value {
    let cid = prior["conversationId"].as_str().unwrap();
    let generation = prior["generation"].as_i64().unwrap() + 1;
    let mut retired = prior.clone();
    retired["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
    retired["lifecycle"] = json!("superseded");
    let bytes = |byte: u8| json!({ "$bytes": STANDARD.encode([byte; 32]) });
    let (transition, ciphertext, group_info) = (new_id(), [0x63_u8; 48], [0x64_u8; 64]);
    let key = signer.public();
    let body = json!({
        "$type": "blue.catbird.chat.defs#resetActivationBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
        "resetRequestId": new_id(), "transitionId": transition, "idempotencyKey": transition,
        "conversationKind": "group", "authGeneration": 1,
        "prior": prior, "retired": retired,
        "successor": {
            "conversationId": cid, "generation": generation, "stateVersion": 0,
            "groupId": bytes(0x5a), "epoch": 0, "groupContextHash": bytes(0x61),
            "confirmationTag": bytes(0x62), "lifecycle": "active",
        },
        "manifest": {
            "participants": participants,
            "actorLeaf": { "userDid": did, "deviceId": device, "leafOrigin": "genesis" },
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage", "contentType": "groupInfo",
            "bytes": { "$bytes": STANDARD.encode(group_info) },
            "sha256": STANDARD.encode(Sha256::digest(group_info)),
        },
        "metadataSnapshot": {
            "authorProof": {
                "authGenerationAtOrigin": 1, "authorDeviceId": device, "authorDid": did,
                "authorKeyId": derive_key_id(key), "deviceStatusAtOrigin": "active",
                "originSeq": 1, "originTransitionId": transition, "roleAtOrigin": "admin",
                "signaturePublicKey": { "$bytes": STANDARD.encode(key) },
            },
            "ciphertext": { "$bytes": STANDARD.encode(ciphertext) },
            "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "coordinate": {
                "conversationId": STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes()),
                "generation": generation, "epoch": 0, "groupId": bytes(0x5a),
                "groupContextHash": bytes(0x61), "confirmationTag": bytes(0x62),
            },
            "metadataVersion": 2, "nonce": { "$bytes": STANDARD.encode([0x65_u8; 12]) },
            "originTransitionId": transition,
        },
        "signedAt": "2026-11-07T00:00:00.000Z",
    });
    signed_by(
        signer,
        did,
        device,
        CanonicalOperation::ActivateReset,
        &body,
    )
}

/// mls-ds sequences `signed_request` as `cid`'s next entry, a `resetActivationEntry`.
pub(super) fn serve(ds: &SharedMockDs, cid: &str, signed_request: Value) {
    let mut g = ds.inner.lock().unwrap();
    let entries = g.entries.get_mut(cid).unwrap();
    let seq = entries.len() as i64 + 1;
    entries.push(json!({
        "$type": "blue.catbird.chat.defs#resetActivationEntry",
        "entryId": new_id(), "conversationId": cid, "seq": seq,
        "receivedAt": "2026-11-07T00:00:00.000Z", "signedRequest": signed_request,
    }));
}

fn unserve(ds: &SharedMockDs, cid: &str) {
    ds.inner.lock().unwrap().entries.get_mut(cid).unwrap().pop();
}

fn conversation(client: &CatbirdMlsClient, cid: &str) -> catbird_mls::storage::ConversationRow {
    client
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap()
}

/// `cid`'s last sequenced entry: `(seq, its signed transitionId, its canonical successor)`.
fn last_activation(ds: &SharedMockDs, cid: &str) -> (i64, String, Value) {
    let g = ds.inner.lock().unwrap();
    let entry = g.entries[cid].last().unwrap();
    assert_eq!(
        entry["$type"],
        "blue.catbird.chat.defs#resetActivationEntry"
    );
    let body = &entry["signedRequest"]["body"];
    (
        entry["seq"].as_i64().unwrap(),
        body["transitionId"].as_str().unwrap().to_owned(),
        chat_wire::canonicalize_wire_coordinate(&body["successor"], Some(cid)).unwrap(),
    )
}

fn journaled(client: &CatbirdMlsClient, transition_id: &str) -> bool {
    client
        .db()
        .read_tx(|tx| tx.get_pending_op("reset_activation", transition_id))
        .unwrap()
        .is_some()
}

/// A reset activation takes effect only from an active admin by this device's verified roster,
/// checked before any effect. Member Bob's activation served to creator Alice, whose roster
/// lists Bob a member, fails her sync `InsufficientPermissions`; admin Alice's activation served to
/// Bob once he holds no verified roster fails his `RosterUnverified`. Neither moves the row,
/// coordinates, MLS group, roster, cursor or acknowledgement. `reset_conversation` refuses the
/// same way before any request: Bob as a member, and Bob without a roster.
///
/// Fail-before: sync applied any participant device's activation, so Bob's retired Alice's leaf;
/// `reset_conversation` did not exist.
#[test]
fn non_admin_reset_activation_is_refused_before_any_effect() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let alice_roster = roster(alice, cid).expect("alice's creation roster");
    assert_eq!(alice_roster[BOB_DID]["role"], "member");
    let prior: Value = serde_json::from_str(&stored_coordinates(alice, cid).unwrap()).unwrap();
    let participants = manifest_participants(ds, cid);

    let before = (reset_state(alice, cid), acked(ds, cid, &f.alice_dev));
    serve(
        ds,
        cid,
        activation(
            &enrolled_signer(bob),
            BOB_DID,
            &f.bob_dev,
            &prior,
            &participants,
        ),
    );
    let error = sync_failure(alice, cid);
    assert!(
        matches!(error, MLSError::InsufficientPermissions { .. }),
        "{error:?}"
    );
    assert_eq!(
        (reset_state(alice, cid), acked(ds, cid, &f.alice_dev)),
        before
    );
    unserve(ds, cid);

    // Bob's verified roster, as Alice's, lists him a member: he may not reset.
    bob.db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &chat_wire::conversation_roster_key(cid),
                &alice_roster.to_string(),
                0,
            )
        })
        .unwrap();
    let sent = requests_from(ds, BOB_DID);
    let error = bob
        .reset_conversation(cid)
        .expect_err("a member never resets");
    assert!(
        matches!(error, MLSError::InsufficientPermissions { .. }),
        "{error:?}"
    );
    bob.db()
        .write_tx(|tx| tx.delete_account_meta(&chat_wire::conversation_roster_key(cid)))
        .unwrap();
    let error = bob
        .reset_conversation(cid)
        .expect_err("no roster, no admin");
    assert!(
        matches!(error, MLSError::RosterUnverified { .. }),
        "{error:?}"
    );
    assert_eq!(
        requests_from(ds, BOB_DID),
        sent,
        "refused before any request"
    );

    let before = (reset_state(bob, cid), acked(ds, cid, &f.bob_dev));
    serve(
        ds,
        cid,
        activation(
            &enrolled_signer(alice),
            ALICE_DID,
            &f.alice_dev,
            &prior,
            &participants,
        ),
    );
    let error = sync_failure(bob, cid);
    assert!(
        matches!(error, MLSError::RosterUnverified { .. }),
        "{error:?}"
    );
    assert_eq!((reset_state(bob, cid), acked(ds, cid, &f.bob_dev)), before);
}

/// A reset request's own answer is not authority until it is the exact submitted request and its
/// I13 receipt verifies. A dishonest home that removes or forges only that answer's receipt gets
/// no activation request, journal, cursor, coordinate or MLS-state change.
///
/// Fail-before: `reset_conversation` discarded this answer and activated from the later entry scan.
#[test]
fn reset_request_answer_requires_its_exact_i13_receipt() {
    let mut violations = Vec::new();
    for fault in ["missingReceipt", "forgedReceipt"] {
        let f = send_order_fixture(false);
        let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
        alice.sync().expect("alice is caught up");
        let before = reset_state(alice, cid);
        ds.inner.lock().unwrap().next_reset_request_fault = Some(fault);

        let result = alice.reset_conversation(cid);
        if !matches!(&result, Err(MLSError::Cryptography(_))) {
            violations.push(format!("{fault}: answer was not refused: {result:?}"));
        }
        if reset_state(alice, cid) != before {
            violations.push(format!("{fault}: reset state changed"));
        }
        if !activation_requests(ds).is_empty() {
            violations.push(format!("{fault}: activation was submitted"));
        }
        if reset_journal_count(alice, cid) != 0 {
            violations.push(format!("{fault}: activation was journaled"));
        }
    }
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A state view and `getEntries` page that invent this device's pending reset at a higher seq are
/// not an activation origin. No activation is signed at that fake tail and nothing is journaled.
///
/// Fail-before: the unverified state view selected the request ID and the unverified entry scan
/// selected `fake_seq + 1` as the metadata author proof's origin.
#[test]
fn fake_pending_reset_tail_never_becomes_an_activation_origin() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    alice.sync().expect("alice is caught up");
    let before = reset_state(alice, cid);
    let fake_seq = conversation(alice, cid).last_seq + 20;
    ds.inner.lock().unwrap().fake_pending_reset_seq = Some(fake_seq);

    alice
        .reset_conversation(cid)
        .expect_err("the invented non-contiguous tail is refused");
    assert!(
        activation_requests(ds)
            .iter()
            .all(
                |request| request["signedRequest"]["body"]["metadataSnapshot"]["authorProof"]
                    ["originSeq"]
                    .as_i64()
                    != Some(fake_seq + 1)
            ),
        "the fake tail must never enter a signed activation"
    );
    assert_eq!(reset_state(alice, cid), before);
    assert_eq!(reset_journal_count(alice, cid), 0);
}

/// An active admin by its verified roster resets. Alice's `reset_conversation` verifies and syncs
/// her own request through the ordinary contiguous path, then journals the staged successor and
/// applies it once mls-ds's answer verifies: a fresh group at the next generation's epoch 0 with
/// Alice its only member, its coordinate and the manifest's roster, the journal gone. The verified
/// request and activation move the cursor through the activation; its later echo is idempotent.
/// An own activation she never journaled is then refused with nothing changed.
///
/// Fail-before: there was no `reset_conversation`, and sync refused every activation signed by
/// this device.
#[test]
fn admin_reset_activates_and_its_echo_is_idempotent() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    alice.sync().expect("alice is caught up");
    let before = conversation(alice, cid);
    let verified_roster = roster(alice, cid).expect("alice's creation roster");

    let reset = alice.reset_conversation(cid).expect("alice resets");
    let (reset_seq, transition_id, successor) = last_activation(ds, cid);
    assert_eq!(
        reset_seq,
        before.last_seq + 2,
        "her request, then the activation"
    );
    assert_eq!(
        (
            reset.generation,
            reset.epoch,
            reset.last_seq,
            reset.group_id.clone()
        ),
        (
            before.generation + 1,
            0,
            reset_seq,
            chat_wire::json_bytes(&successor["groupId"]).unwrap()
        )
    );
    assert_ne!(reset.group_id, before.group_id);
    assert_eq!(
        reset.space_uri,
        Some(format!(
            "at:space/{DS_DID}/blue.catbird.labyrinth.conversation/{cid}-{}",
            reset.generation
        )),
        "the successor generation's conversation Space"
    );
    assert_eq!(stored_coordinates(alice, cid), Some(successor.to_string()));
    assert_eq!(
        alice.list_members(cid).unwrap(),
        vec![ALICE_DID.to_string()]
    );
    assert_eq!(roster(alice, cid), Some(verified_roster.clone()));
    for did in [ALICE_DID, BOB_DID] {
        assert!(
            alice
                .db()
                .read_tx(|tx| {
                    tx.get_account_meta(&chat_wire::verified_participant_admission_key(cid, did))
                })
                .unwrap()
                .is_some(),
            "the member-signed reset manifest carries {did}'s admission marker"
        );
    }
    assert!(!journaled(alice, &transition_id), "the answer consumed it");

    alice.sync().expect("the echo verifies");
    let echoed = conversation(alice, cid);
    assert_eq!(echoed.last_seq, reset_seq);
    assert_eq!(
        catbird_mls::storage::ConversationRow {
            updated_at_ms: reset.updated_at_ms,
            ..echoed
        },
        reset,
        "the echo is idempotent"
    );
    assert_eq!(stored_coordinates(alice, cid), Some(successor.to_string()));
    assert_eq!(roster(alice, cid), Some(verified_roster));

    let current: Value = serde_json::from_str(&stored_coordinates(alice, cid).unwrap()).unwrap();
    let unjournaled = activation(
        &enrolled_signer(alice),
        ALICE_DID,
        &f.alice_dev,
        &current,
        &manifest_participants(ds, cid),
    );
    let before = reset_state(alice, cid);
    serve(ds, cid, unjournaled);
    let error = sync_failure(alice, cid).to_string();
    assert!(error.contains("has no journal"), "{error}");
    assert_eq!(reset_state(alice, cid), before);
    unserve(ds, cid);
}

/// mls-ds sequences Alice's activation but its answer is lost: only her separately verified reset
/// request has moved the cursor and the activation journal stays. Her next sync verifies the echo
/// of her own activation and applies exactly the journaled successor (group, coordinate, roster,
/// cursor); another sync changes nothing, and she sends in the successor generation.
///
/// Fail-before: sync refused every activation signed by this device, so a lost answer left Alice
/// on the retired generation for good.
#[test]
fn lost_reset_answer_applies_the_journaled_successor_on_its_echo() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    alice.sync().expect("alice is caught up");
    let before = reset_state(alice, cid);
    let generation = conversation(alice, cid).generation;
    let verified_roster = roster(alice, cid).expect("alice's creation roster");

    ds.inner.lock().unwrap().lose_next_reset_response = true;
    alice
        .reset_conversation(cid)
        .expect_err("the answer is lost");
    let mut after_request = before.clone();
    after_request.3 += 1;
    assert_eq!(
        reset_state(alice, cid),
        after_request,
        "only the verified reset request applies before the activation echo"
    );
    let (reset_seq, transition_id, successor) = last_activation(ds, cid);
    assert!(journaled(alice, &transition_id));

    alice.sync().expect("the echo applies the journal");
    let row = conversation(alice, cid);
    assert_eq!(
        (row.generation, row.epoch, row.last_seq, row.group_id),
        (
            generation + 1,
            0,
            reset_seq,
            chat_wire::json_bytes(&successor["groupId"]).unwrap()
        )
    );
    assert_eq!(stored_coordinates(alice, cid), Some(successor.to_string()));
    assert_eq!(
        alice.list_members(cid).unwrap(),
        vec![ALICE_DID.to_string()]
    );
    assert_eq!(roster(alice, cid), Some(verified_roster));
    assert!(!journaled(alice, &transition_id), "the echo consumed it");

    let after = reset_state(alice, cid);
    alice.sync().expect("nothing new");
    assert_eq!(reset_state(alice, cid), after);
    alice
        .send_message(cid, &new_id(), "successor generation")
        .expect("alice sends in the successor");
}

/// A reset-activation answer is not authority until its I13 receipt verifies. A forged answer
/// leaves the staged successor journaled; the genuine sequenced echo applies it.
#[test]
fn reset_activation_answer_requires_its_i13_receipt() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    alice.sync().expect("alice is caught up");
    let before = reset_state(alice, cid);
    let generation = conversation(alice, cid).generation;

    ds.inner.lock().unwrap().forge_next_reset_activation_receipt = true;
    let error = alice
        .reset_conversation(cid)
        .expect_err("an activation answer with a forged receipt is refused");
    assert!(
        error.to_string().contains("I13") || error.to_string().contains("receipt"),
        "{error}"
    );
    let mut after_request = before.clone();
    after_request.3 += 1;
    assert_eq!(
        reset_state(alice, cid),
        after_request,
        "only the separately verified reset request may apply"
    );
    let (reset_seq, transition_id, successor) = last_activation(ds, cid);
    assert!(journaled(alice, &transition_id));

    alice.sync().expect("the genuine activation echo applies");
    let row = conversation(alice, cid);
    assert_eq!(
        (row.generation, row.epoch, row.last_seq, row.group_id),
        (
            generation + 1,
            0,
            reset_seq,
            chat_wire::json_bytes(&successor["groupId"]).unwrap()
        )
    );
    assert_eq!(stored_coordinates(alice, cid), Some(successor.to_string()));
    assert!(!journaled(alice, &transition_id));
}

/// A device retired by a reset rejoins through its own signed request and a verified Welcome.
/// Admin Alice resets and sends in the successor generation. Bob's sync verifies her activation
/// against the roster he verified when he joined, retires his leaf, takes the manifest's roster
/// and signs his add bound to the successor; while retired he reads nothing past the reset, so
/// syncing again changes nothing. Alice's sync fulfills his add from his verified signed request,
/// entitled by her roster (Bob holds no leaf), attesting that roster in the Welcome; Bob's sync
/// joins his existing conversation row from it, keeping his history. Both then exchange
/// messages, and Bob's roster is Alice's. The activation replayed at a later seq names a state
/// Bob already left and fails his sync with nothing changed.
///
/// Fail-before: a reset-retired device never requested its own recovery, no fulfiller accepted a
/// zero-leaf requester, and the retired row counted as already joined.
#[test]
fn reset_retired_device_rejoins_through_its_signed_request_and_verified_welcome() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    alice.send_message(cid, &new_id(), "before").unwrap();
    bob.sync().expect("bob reads alice");
    let joined = conversation(bob, cid);
    assert!(roster(bob, cid).is_some(), "bob's attested roster");

    let reset = alice.reset_conversation(cid).expect("alice resets");
    // mls-ds serves Bob's reset-closed device the control entries up to the reset, nothing after.
    let (reset_seq, _, _) = last_activation(ds, cid);
    ds.inner
        .lock()
        .unwrap()
        .readable_until
        .insert(f.bob_dev.clone(), reset_seq);
    alice
        .send_message(cid, &new_id(), "successor, before bob rejoins")
        .unwrap();
    bob.sync().expect("bob retires and requests his add");
    let retired = conversation(bob, cid);
    assert_eq!(
        (retired.generation, retired.group_id.clone()),
        (reset.generation, reset.group_id.clone())
    );
    assert!(
        bob.list_members(cid).is_err(),
        "bob holds no successor leaf"
    );
    assert_eq!(roster(bob, cid), roster(alice, cid));
    bob.sync()
        .expect("a retired row reads nothing past its reset");
    assert_eq!(conversation(bob, cid), retired);

    alice.sync().expect("alice fulfills bob's signed request");
    // The fulfillment opens Bob's next membership interval.
    ds.inner.lock().unwrap().readable_until.remove(&f.bob_dev);
    assert_eq!(
        alice.list_members(cid).unwrap(),
        vec![ALICE_DID.to_string(), BOB_DID.to_string()]
    );
    bob.sync().expect("bob joins from the verified Welcome");
    let rejoined = conversation(bob, cid);
    assert_eq!(
        (
            rejoined.conversation_id.clone(),
            rejoined.generation,
            rejoined.group_id.clone()
        ),
        (joined.conversation_id, reset.generation, reset.group_id)
    );
    let coordinates = |client: &CatbirdMlsClient| {
        let raw: Value = serde_json::from_str(&stored_coordinates(client, cid).unwrap()).unwrap();
        chat_wire::canonicalize_wire_coordinate(&raw, Some(cid)).unwrap()
    };
    assert_eq!(coordinates(bob), coordinates(alice));
    assert_eq!(roster(bob, cid), roster(alice, cid));
    assert!(
        timeline_after(bob, cid, 0)
            .iter()
            .any(|(_, text)| text == "before"),
        "bob keeps his history"
    );

    let (to_bob, to_alice) = (new_id(), new_id());
    alice
        .send_message(cid, &to_bob, "after reset, alice")
        .unwrap();
    bob.sync().expect("bob reads the successor");
    bob.send_message(cid, &to_alice, "after reset, bob")
        .unwrap();
    alice.sync().expect("alice reads bob");
    assert!(timeline_after(bob, cid, rejoined.last_seq)
        .iter()
        .any(|(_, text)| text == "after reset, alice"));
    assert!(timeline_after(alice, cid, rejoined.last_seq)
        .iter()
        .any(|(_, text)| text == "after reset, bob"));

    // The activation replayed at a later seq names a state Bob already left: refused.
    let replay =
        ds.inner.lock().unwrap().entries[cid][reset_seq as usize - 1]["signedRequest"].clone();
    let before = reset_state(bob, cid);
    serve(ds, cid, replay);
    let error = sync_failure(bob, cid).to_string();
    assert!(
        error.contains("prior is not this device's current coordinate"),
        "{error}"
    );
    assert_eq!(reset_state(bob, cid), before);
}
