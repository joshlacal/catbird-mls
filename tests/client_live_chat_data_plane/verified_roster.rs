//! The verified roster (`conversation_roster:{cid}`): recorded at creation, kept current by every
//! verified transition, and attested to a recovery joiner only by its verified fulfiller; and this
//! device's own leaf-recovery requests.

use super::reset_activation::{activation, manifest_participants, serve};
use super::*;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};

/// `cid`'s verified roster as `client` holds it.
fn roster(client: &CatbirdMlsClient, cid: &str) -> Option<Value> {
    client
        .db()
        .read_tx(|tx| tx.get_account_meta(&chat_wire::conversation_roster_key(cid)))
        .unwrap()
        .map(|raw| serde_json::from_str(&raw).unwrap())
}

/// The roster of `(did, role, status)` rows.
fn roster_of(rows: &[(&str, &str, &str)]) -> Value {
    rows.iter()
        .map(|(did, role, status)| ((*did).to_owned(), json!({ "role": role, "status": status })))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// The `requestLeafRecovery` bodies `device` signed, oldest first, their `prior` canonical.
fn recovery_requests(ds: &SharedMockDs, device: &str) -> Vec<Value> {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.ends_with("/xrpc/blue.catbird.chat.requestLeafRecovery"))
        .map(|(_, _, body)| {
            let mut body =
                serde_json::from_slice::<Value>(body).unwrap()["signedRequest"]["body"].take();
            body["prior"] = chat_wire::canonicalize_wire_coordinate(&body["prior"], None).unwrap();
            body
        })
        .filter(|body| body["actorDeviceId"] == device)
        .collect()
}

/// `cid`'s current coordinate as mls-ds presents it, canonical.
fn ds_coordinate(ds: &SharedMockDs, cid: &str) -> Value {
    chat_wire::canonicalize_wire_coordinate(
        &ds.inner.lock().unwrap().conversations[cid]["coordinates"],
        Some(cid),
    )
    .unwrap()
}

/// mls-ds sequences `signed_request` as `cid`'s next `policyEntry`; returns its seq.
fn serve_policy(ds: &SharedMockDs, cid: &str, signed_request: Value) -> i64 {
    let mut g = ds.inner.lock().unwrap();
    let entries = g.entries.get_mut(cid).unwrap();
    let seq = entries.len() as i64 + 1;
    entries.push(json!({
        "$type": "blue.catbird.chat.defs#policyEntry",
        "entryId": new_id(), "conversationId": cid, "seq": seq,
        "receivedAt": "2026-11-07T00:00:00.000Z", "signedRequest": signed_request,
    }));
    seq
}

/// A device that signs: `(signer, did, device)`.
type Signing<'a> = (&'a SignatureKeyPair, &'a str, &'a str);

/// A recovery fulfillment built outside any client: `committer` creates a fresh conversation's
/// group and commits the add of a reserved KeyPackage of Bob's `bob_device` (and of `fulfiller`'s,
/// when that is another device), the Welcome's GroupInfo carrying `attestation(cid)`; `fulfiller`
/// signs the fulfillment, built on `template` (a real one). mls-ds then holds the conversation,
/// that fulfillment at seq 1 and Bob's Welcome. Returns the conversation ID.
fn serve_fulfillment(
    ds: &SharedMockDs,
    template: &Value,
    committer: Signing<'_>,
    fulfiller: Signing<'_>,
    bob_device: &str,
    attestation: impl Fn(&str) -> Option<Extension>,
) -> String {
    const SUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let cid = new_id();
    let provider = openmls_libcrux_crypto::Provider::new().unwrap();
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[SUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let leaf = |(signer, did, device): Signing<'_>| CredentialWithKey {
        credential: BasicCredential::new(format!("{did}#{device}").into_bytes()).into(),
        signature_key: signer.public().into(),
    };
    let mut group = MlsGroup::new_with_group_id(
        &provider,
        committer.0,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .capabilities(capabilities.clone())
            .use_ratchet_tree_extension(true)
            .build(),
        GroupId::from_slice(&rand::random::<[u8; 32]>()),
        leaf(committer),
    )
    .unwrap();
    let coordinate = |group: &MlsGroup, state_version: i64| {
        let (hash, tag) = chat_wire::compute_group_context_hash_and_tag(group, &provider).unwrap();
        json!({
            "conversationId": cid, "generation": 0, "stateVersion": state_version,
            "groupId": { "$bytes": STANDARD.encode(group.group_id().as_slice()) },
            "epoch": group.epoch().as_u64(),
            "groupContextHash": { "$bytes": STANDARD.encode(hash) },
            "confirmationTag": { "$bytes": STANDARD.encode(tag) },
            "lifecycle": "active",
        })
    };
    let prior = coordinate(&group, 1);
    let reserved = ds
        .inner
        .lock()
        .unwrap()
        .convo_kps
        .get_mut(&(BOB_DID.to_owned(), bob_device.to_owned()))
        .and_then(Vec::pop)
        .expect("a KeyPackage of bob's device");
    let MlsMessageBodyIn::KeyPackage(bob_package) =
        MlsMessageIn::tls_deserialize_exact(chat_wire::json_bytes(&reserved["bytes"]).unwrap())
            .unwrap()
            .extract()
    else {
        panic!("bob's reserved KeyPackage");
    };
    let mut adds = vec![bob_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap()];
    if (fulfiller.1, fulfiller.2) != (committer.1, committer.2) {
        adds.push(
            KeyPackage::builder()
                .leaf_node_capabilities(capabilities)
                .build(SUITE, &provider, fulfiller.0, leaf(fulfiller))
                .unwrap()
                .key_package()
                .clone(),
        );
    }
    let mut builder = group
        .commit_builder()
        .propose_adds(adds)
        .load_psks(provider.storage())
        .unwrap();
    if let Some(extension) = attestation(&cid) {
        builder = builder
            .create_group_info_with_extensions([extension])
            .unwrap();
    }
    let bundle = builder
        .build(provider.rand(), provider.crypto(), committer.0, |_| true)
        .unwrap()
        .stage_commit(&provider)
        .unwrap();
    let welcome = bundle
        .to_welcome_msg()
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    group.merge_pending_commit(&provider).unwrap();
    let next = coordinate(&group, 2);

    let (request, transition, welcome_id) = (new_id(), new_id(), new_id());
    let reference = &reserved["keyPackageRef"];
    let mut body = template.clone();
    body["transitionId"] = json!(transition);
    body["idempotencyKey"] = json!(transition);
    body["recoveryRequestId"] = json!(request);
    body["prior"] = prior;
    body["next"] = next.clone();
    body["manifest"] = json!({
        "participantChanges": [],
        "leafChanges": [{
            "$type": "blue.catbird.chat.defs#addLeafByRecovery",
            "userDid": BOB_DID, "deviceId": bob_device, "recoveryRequestId": request,
            "keyPackageRef": reference,
        }],
        "leafRecoveryRequestId": request,
        "welcomeBundle": {
            "welcomeId": welcome_id, "framing": "mlsMessage", "contentType": "welcome",
            "opaqueWelcome": { "$bytes": STANDARD.encode(&welcome) },
            "sha256": STANDARD.encode(Sha256::digest(&welcome)),
            "deliveries": [{
                "recipientDid": BOB_DID, "recipientDeviceId": bob_device,
                "provenance": { "recoveryRequestId": request, "keyPackageRef": reference },
            }],
        },
    });
    let signed = signed_by(
        fulfiller.0,
        fulfiller.1,
        fulfiller.2,
        CanonicalOperation::SubmitTransition,
        &body,
    );
    let mut g = ds.inner.lock().unwrap();
    g.conversations.insert(
        cid.clone(),
        json!({
            "conversationKind": "group", "sequencerDid": DS_DID, "coordinates": next,
            "participants": [
                { "userDid": fulfiller.1, "role": "admin", "status": "active", "leafCount": 1 },
                { "userDid": BOB_DID, "role": "member", "status": "active", "leafCount": 1 },
            ],
            "leaves": [
                { "userDid": fulfiller.1, "deviceId": fulfiller.2, "leafOrigin": "genesis" },
                { "userDid": BOB_DID, "deviceId": bob_device, "leafOrigin": "recovery" },
            ],
            "snapshotSeq": 1,
        }),
    );
    g.entries.insert(
        cid.clone(),
        vec![json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
            "entryId": transition, "conversationId": cid, "seq": 1,
            "receivedAt": "2026-11-07T00:00:00.000Z", "signedRequest": signed,
        })],
    );
    g.pending_welcomes
        .entry((BOB_DID.to_owned(), bob_device.to_owned()))
        .or_default()
        .push(json!({
            "welcomeId": welcome_id, "conversationId": cid, "sequencerDid": DS_DID,
            "transitionSeq": 1, "coordinates": next,
            "opaqueWelcome": { "$bytes": STANDARD.encode(&welcome) },
        }));
    cid
}

/// The creator's verified roster is the manifest she signed, kept current by each verified
/// transition exactly once: her invitation's verified answer, Bob's acceptance, her own role
/// change mls-ds sequenced while its answer was lost, and her removal's verified answers, whose
/// echoes then move only her cursor. A policy Bob, a member, signed to make himself admin fails
/// her sync `InsufficientPermissions`, and one whose signature does not verify fails it too:
/// neither changes her roster, coordinates or cursor.
///
/// Fail-before (cut 9a2708e1): no roster existed (`live_plane.rs` `create_group_conversation_live`
/// recorded none) and the `live_sync.rs` policy arm applied any leaf's policy, a member's role
/// escalation included.
#[test]
fn creator_tracks_the_verified_roster_through_verified_entries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_dev = new_id();
    let alice = enrolled(&tmp, &ds, "alice", ALICE_DID, &alice_dev);
    let bob_dev = new_id();
    let bob = enrolled(&tmp, &ds, "bob", BOB_DID, &bob_dev);
    let _eve = enrolled(&tmp, &ds, "eve", EVE_DID, &new_id());
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Roster".into()),
            None,
        )
        .expect("alice creates the group");
    assert_eq!(
        roster(&alice, &cid),
        Some(roster_of(&[
            (ALICE_DID, "admin", "active"),
            (BOB_DID, "member", "pending"),
        ])),
        "creation: the manifest alice signed"
    );

    alice
        .add_group_members(&cid, vec![EVE_DID.to_string()])
        .expect("alice invites eve");
    let invited = roster_of(&[
        (ALICE_DID, "admin", "active"),
        (BOB_DID, "member", "pending"),
        (EVE_DID, "member", "pending"),
    ]);
    assert_eq!(
        roster(&alice, &cid),
        Some(invited),
        "her invitation's answer"
    );

    bob.sync().expect("bob accepts");
    alice
        .sync()
        .expect("alice applies bob's acceptance and adds his device");
    assert_eq!(
        roster(&alice, &cid),
        Some(roster_of(&[
            (ALICE_DID, "admin", "active"),
            (BOB_DID, "member", "active"),
            (EVE_DID, "member", "pending"),
        ])),
        "bob's verified acceptance"
    );

    // A policy step from mls-ds's coordinate making Bob admin, signed by `(signer, did, device)`.
    let promote_bob = |signer: &SignatureKeyPair, did: &str, device: &str| {
        let prior = ds_coordinate(&ds, &cid);
        let mut next = prior.clone();
        next["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
        let transition = new_id();
        let body = json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\0",
            "transitionId": transition, "idempotencyKey": transition, "authGeneration": 1,
            "prior": prior, "next": next,
            "participantChanges": [{
                "$type": "blue.catbird.chat.defs#changeParticipantRole",
                "userDid": BOB_DID, "role": "admin",
            }],
            "signedAt": "2026-11-07T00:00:00.000Z",
        });
        signed_by(
            signer,
            did,
            device,
            CanonicalOperation::SubmitTransition,
            &body,
        )
    };
    let local = || {
        (
            roster(&alice, &cid),
            stored_coordinates(&alice, &cid),
            last_seq(&alice, &cid),
        )
    };
    let unserve = || {
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(&cid)
            .unwrap()
            .pop();
    };
    let before = local();

    serve_policy(
        &ds,
        &cid,
        promote_bob(&enrolled_signer(&bob), BOB_DID, &bob_dev),
    );
    let error = alice.sync().expect_err("a member's own promotion");
    assert!(
        matches!(&error, MLSError::SyncIncomplete { failures, .. }
            if failures.len() == 1
                && matches!(*failures[0].error, MLSError::InsufficientPermissions { .. })),
        "{error:?}"
    );
    assert_eq!(local(), before, "escalation refused before any effect");
    unserve();

    let alice_signer = enrolled_signer(&alice);
    let mut forged = promote_bob(&alice_signer, ALICE_DID, &alice_dev);
    forged["signature"] = json!(STANDARD.encode([7u8; 64]));
    serve_policy(&ds, &cid, forged);
    let error = alice.sync().expect_err("a forged signature").to_string();
    assert!(error.contains("verify signed transition"), "{error}");
    assert_eq!(local(), before, "forgery refused before any effect");
    unserve();

    // Alice's own promotion of Bob, sequenced while its answer was lost, applies from its echo.
    let promotion = promote_bob(&alice_signer, ALICE_DID, &alice_dev);
    ds.inner
        .lock()
        .unwrap()
        .conversations
        .get_mut(&cid)
        .unwrap()["coordinates"] = promotion["body"]["next"].clone();
    let seq = serve_policy(&ds, &cid, promotion);
    alice.sync().expect("alice's own promotion applies once");
    assert_eq!(last_seq(&alice, &cid), seq);
    assert_eq!(
        roster(&alice, &cid),
        Some(roster_of(&[
            (ALICE_DID, "admin", "active"),
            (BOB_DID, "admin", "active"),
            (EVE_DID, "member", "pending"),
        ])),
        "her verified role change"
    );

    alice
        .remove_group_member(MemberRole::Admin, &cid, BOB_DID)
        .expect("alice removes bob");
    let removed = roster_of(&[
        (ALICE_DID, "admin", "active"),
        (EVE_DID, "member", "pending"),
    ]);
    assert_eq!(
        roster(&alice, &cid),
        Some(removed.clone()),
        "her removal's answers"
    );
    alice
        .sync()
        .expect("the removal's echoes move only her cursor");
    assert_eq!(roster(&alice, &cid), Some(removed));
}

/// A recovery joiner's verified roster comes only from the roster attestation in its Welcome's
/// GroupInfo, signed by exactly its verified fulfiller's leaf. Bob, joining through Alice's
/// fulfillment, holds exactly Alice's roster. Fulfillments built outside any client, of fresh
/// conversations, each a Welcome Bob joins: with a valid attestation by its fulfiller Carol it
/// grants Carol's roster; one carrying none, one attesting a roster that does not hold every leaf,
/// one attesting another generation, and one whose GroupInfo Eve signed although Carol fulfilled
/// it, grant none. No later sync, whatever participants mls-ds names in their states, creates one.
///
/// Fail-before (cut 9a2708e1): `live_sync.rs` `join_pending_welcome` recorded no roster from any
/// Welcome, and no creator held one to attest.
#[test]
fn recovery_welcome_attests_the_fulfillers_roster_and_nothing_else_does() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    assert!(roster(alice, cid).is_some(), "alice's verified roster");
    assert_eq!(
        roster(bob, cid),
        roster(alice, cid),
        "attested by his fulfiller"
    );

    let template = ds.inner.lock().unwrap().entries[cid]
        .iter()
        .map(|entry| entry["signedRequest"]["body"].clone())
        .find(|body| body["$type"] == "blue.catbird.chat.defs#leafRecoveryFulfillmentBody")
        .expect("alice's fulfillment of bob");
    bob.replenish_key_packages(8)
        .expect("bob publishes KeyPackages");
    let carol_dev = new_id();
    let carol_signer = enrolled_signer(&enrolled(&f.tmp, ds, "carol", CAROL_DID, &carol_dev));
    let carol = (&carol_signer, CAROL_DID, carol_dev.as_str());
    let eve_signer = enrolled_signer(&f.eve);
    let eve_dev = enrolled_device(ds, EVE_DID);
    let eve = (&eve_signer, EVE_DID, eve_dev.as_str());
    let carols = roster_of(&[
        (BOB_DID, "member", "active"),
        (CAROL_DID, "admin", "active"),
    ]);
    let with_eve = roster_of(&[
        (BOB_DID, "member", "active"),
        (CAROL_DID, "admin", "active"),
        (EVE_DID, "member", "active"),
    ]);
    let attest = |generation: i64, roster: &Value| {
        let roster = roster.clone();
        move |cid: &str| {
            Some(chat_wire::roster_attestation_extension(cid, generation, &roster).unwrap())
        }
    };
    let valid = serve_fulfillment(ds, &template, carol, carol, &f.bob_dev, attest(0, &carols));
    let refused = [
        (
            "no attestation",
            serve_fulfillment(ds, &template, carol, carol, &f.bob_dev, |_| None),
        ),
        (
            "a roster without the fulfiller's leaf",
            serve_fulfillment(
                ds,
                &template,
                carol,
                carol,
                &f.bob_dev,
                attest(0, &roster_of(&[(BOB_DID, "member", "active")])),
            ),
        ),
        (
            "another generation",
            serve_fulfillment(ds, &template, carol, carol, &f.bob_dev, attest(1, &carols)),
        ),
        (
            "a GroupInfo another member signed",
            serve_fulfillment(ds, &template, eve, carol, &f.bob_dev, attest(0, &with_eve)),
        ),
    ];

    bob.sync().expect("bob joins every verified Welcome");
    let joined = |cid: &str| bob.list_members(cid).is_ok();
    assert!(joined(&valid));
    assert_eq!(
        roster(bob, &valid),
        Some(carols.clone()),
        "carol's attestation"
    );
    for (case, cid) in &refused {
        assert!(joined(cid), "{case}: the join still proceeds");
        assert_eq!(roster(bob, cid), None, "{case}");
    }

    bob.sync().expect("bob syncs his conversations");
    assert_eq!(roster(bob, &valid), Some(carols));
    for (case, cid) in &refused {
        assert_eq!(roster(bob, cid), None, "{case}: no state view creates one");
    }
}

/// Each device requests its own leaf recovery once per coordinate. Eve, invited, accepts instead
/// and never requests, nor once Alice removes her. Bob's new device, holding nothing of the group
/// his account is active in, signs one `add` bound to mls-ds's coordinate, and no second. After a
/// verified reset retires Bob's leaf (mls-ds then serves his old device no entry past it), his
/// sync signs one `add` bound to the successor and reads no entry past the reset; his next sync
/// signs nothing; once another transition moves the coordinate, or his request expires, his next
/// sync renews it bound to the coordinate then current.
///
/// Fail-before (cut 9a2708e1): no device ever requested its own recovery (`live_sync.rs`
/// `sync_inventory_item`, `sync_one_conversation`), and a retired row still read its entries.
#[test]
fn retired_and_new_devices_request_once_per_coordinate() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);

    let eve_dev = enrolled_device(ds, EVE_DID);
    f.eve.sync().expect("eve accepts her invitation");
    f.eve.sync().expect("her acceptance opened her request");
    alice
        .remove_group_member(MemberRole::Admin, cid, EVE_DID)
        .expect("alice removes eve");
    f.eve.sync().expect("eve, removed, owes nothing");
    assert!(recovery_requests(ds, &eve_dev).is_empty());

    let bob2_dev = new_id();
    let bob2 = enrolled(&f.tmp, ds, "bob2", BOB_DID, &bob2_dev);
    bob2.sync().expect("bob's new device requests its add");
    bob2.sync().expect("its request stays open");
    let requested = recovery_requests(ds, &bob2_dev);
    assert_eq!(requested.len(), 1, "one request");
    assert_eq!(
        (&requested[0]["recoveryKind"], &requested[0]["prior"]),
        (&json!("add"), &ds_coordinate(ds, cid))
    );

    bob.replenish_key_packages(4)
        .expect("bob publishes KeyPackages");
    serve(
        ds,
        cid,
        activation(
            &enrolled_signer(alice),
            ALICE_DID,
            &f.alice_dev,
            &ds_coordinate(ds, cid),
            &manifest_participants(ds, cid),
        ),
    );
    let (reset_seq, successor) = {
        let mut g = ds.inner.lock().unwrap();
        let entry = g.entries[cid].last().unwrap().clone();
        let successor = chat_wire::canonicalize_wire_coordinate(
            &entry["signedRequest"]["body"]["successor"],
            Some(cid),
        )
        .unwrap();
        // mls-ds after the activation: its successor's one leaf is Alice's, every open request is
        // superseded, and Bob's old device reads no entry past the reset.
        let state = g.conversations.get_mut(cid).unwrap();
        state["coordinates"] = entry["signedRequest"]["body"]["successor"].clone();
        state["leaves"] =
            json!([{ "userDid": ALICE_DID, "deviceId": f.alice_dev, "leafOrigin": "genesis" }]);
        for participant in state["participants"].as_array_mut().unwrap() {
            participant["leafCount"] = json!(usize::from(participant["userDid"] == ALICE_DID));
        }
        for request in g.leaf_recoveries.get_mut(cid).into_iter().flatten() {
            if request["status"] == "open" {
                request["status"] = json!("superseded");
            }
        }
        let seq = entry["seq"].as_i64().unwrap();
        g.readable_until.insert(f.bob_dev.clone(), seq);
        (seq, successor)
    };
    let bob_reads_past = |seq: i64| {
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.getEntries"))
            .map(|(_, url, _)| query_map(url))
            .filter(|query| {
                query.get("actorDeviceId") == Some(&f.bob_dev)
                    && query.get("conversationId").map(String::as_str) == Some(cid)
                    && query
                        .get("afterSeq")
                        .and_then(|after| after.parse::<i64>().ok())
                        .is_some_and(|after| after >= seq)
            })
            .count()
    };

    bob.sync().expect("bob retires and requests his add");
    let retired = bob
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap();
    assert_eq!(retired.last_seq, reset_seq);
    assert!(bob.list_members(cid).is_err(), "bob holds no leaf");
    let requested = recovery_requests(ds, &f.bob_dev);
    assert_eq!(requested.len(), 1, "one request");
    assert_eq!(
        (&requested[0]["recoveryKind"], &requested[0]["prior"]),
        (&json!("add"), &successor)
    );
    bob.sync().expect("his request stays open");
    assert_eq!(
        recovery_requests(ds, &f.bob_dev).len(),
        1,
        "no second request"
    );

    let moved = {
        let mut g = ds.inner.lock().unwrap();
        let coordinates = &mut g.conversations.get_mut(cid).unwrap()["coordinates"];
        let version = coordinates["stateVersion"].as_i64().unwrap();
        coordinates["stateVersion"] = json!(version + 1);
        let moved = chat_wire::canonicalize_wire_coordinate(coordinates, None).unwrap();
        for request in g.leaf_recoveries.get_mut(cid).into_iter().flatten() {
            if request["status"] == "open" {
                request["status"] = json!("superseded");
            }
        }
        moved
    };
    bob.sync().expect("bob renews at the moved coordinate");
    let requested = recovery_requests(ds, &f.bob_dev);
    assert_eq!(requested.len(), 2, "renewed once");
    assert_eq!(requested[1]["prior"], moved);

    bob.db()
        .write_tx(|tx| {
            let key = chat_wire::own_leaf_recovery_key(cid);
            let mut record: Value = serde_json::from_str(&tx.get_account_meta(&key)?.unwrap())?;
            record["expiresAtMs"] = json!(0);
            tx.put_account_meta(&key, &record.to_string(), 0)
        })
        .unwrap();
    for request in ds
        .inner
        .lock()
        .unwrap()
        .leaf_recoveries
        .get_mut(cid)
        .into_iter()
        .flatten()
    {
        if request["status"] == "open" {
            request["status"] = json!("expired");
        }
    }
    bob.sync().expect("bob renews his expired request");
    let requested = recovery_requests(ds, &f.bob_dev);
    assert_eq!(requested.len(), 3, "renewed once more");
    assert_eq!(requested[2]["prior"], moved);
    assert_ne!(
        requested[2]["recoveryRequestId"],
        requested[1]["recoveryRequestId"]
    );
    assert_eq!(bob_reads_past(reset_seq), 0, "no entry read past the reset");
}
