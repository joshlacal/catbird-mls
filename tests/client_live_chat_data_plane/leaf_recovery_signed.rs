//! Leaf-recovery fulfillment from the requester's own signed request: what mls-ds lists never
//! makes a member add or replace a device by itself.

use super::*;

/// `did#device`'s `requestLeafRecovery` of `kind`, signed by `signer` at `cid`'s current
/// coordinate as mls-ds presents it and submitted on `did`'s session: mls-ds's answer.
fn request_recovery(
    ds: &SharedMockDs,
    signer: &SignatureKeyPair,
    did: &str,
    device: &str,
    cid: &str,
    kind: &str,
) -> Value {
    let prior = ds.inner.lock().unwrap().conversations[cid]["coordinates"].clone();
    let body = chat_wire::leaf_recovery_request_body(
        &new_id(),
        did,
        device,
        &derive_key_id(signer.public()),
        1,
        &prior,
        kind,
        &chat_wire::now_rfc3339_millis(),
    )
    .unwrap();
    let prepared = chat_wire::sign_clean_chat_mutation(
        did,
        device,
        Some(1),
        CanonicalOperation::RequestLeafRecovery,
        &body,
        signer,
    )
    .unwrap();
    let answer = ds
        .execute(
            did,
            PlatformHttpRequest {
                method: "POST".into(),
                url: format!("{DS_URL}{}", prepared.path),
                headers: Vec::new(),
                body: prepared.body,
            },
        )
        .unwrap();
    serde_json::from_slice(&answer.body).unwrap()
}

/// Every signed `leafRecoveryFulfillmentBody` mls-ds received from `device`, oldest first.
fn fulfillments(ds: &SharedMockDs, device: &str) -> Vec<Value> {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.ends_with("/xrpc/blue.catbird.chat.submitTransition"))
        .map(|(_, _, body)| {
            serde_json::from_slice::<Value>(body).unwrap()["signedRequest"]["body"].clone()
        })
        .filter(|body| {
            body["$type"] == "blue.catbird.chat.defs#leafRecoveryFulfillmentBody"
                && body["actorDeviceId"] == device
        })
        .collect()
}

/// `(did#device, leaf encryption key)` of every leaf of `client`'s MLS group of `cid`, sorted.
fn leaves(client: &CatbirdMlsClient, cid: &str) -> Vec<(String, Vec<u8>)> {
    client
        .db()
        .write_tx(|tx| {
            let convo = tx.get_conversation(cid)?.unwrap();
            let provider = tx.openmls_provider();
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .map_err(|e| MLSError::Internal(format!("{e:?}")))?
                .unwrap();
            let mut leaves: Vec<_> = group
                .members()
                .map(|member| {
                    let identity = member.credential.serialized_content().to_vec();
                    (String::from_utf8(identity).unwrap(), member.encryption_key)
                })
                .collect();
            leaves.sort();
            Ok(leaves)
        })
        .unwrap()
}

fn identities(client: &CatbirdMlsClient, cid: &str) -> Vec<String> {
    leaves(client, cid)
        .into_iter()
        .map(|(identity, _)| identity)
        .collect()
}

fn epoch(client: &CatbirdMlsClient, cid: &str) -> i64 {
    client
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap()
        .epoch
}

/// mls-ds lists exactly `views` as `cid`'s pending recoveries.
fn list(ds: &SharedMockDs, cid: &str, views: Vec<Value>) {
    ds.inner
        .lock()
        .unwrap()
        .leaf_recoveries
        .insert(cid.to_owned(), views);
}

/// A delivery service cannot make a member add a device. In a conversation where Alice's
/// device is the only leaf, mls-ds lists, one at a time: her second device's request without its
/// signature; a stranger's validly signed add; that device's genuine signed request with a
/// signature that no longer verifies, or presented under another request ID, kind, device, key
/// ID, auth generation or coordinate, or reserving another device's KeyPackage. The first two
/// are no work; each of the others fails Alice's sync of that conversation. After every one
/// Alice has submitted nothing and her leaves, epoch, coordinates, cursor and acknowledgement
/// are unchanged. The genuine request then adds her second device once.
///
/// Fail-before: cut 9a2708e1 (`fulfill_pending_leaf_recoveries`) fulfilled any listed open add
/// bound to the state coordinate whose KeyPackage was its account's own, so the unsigned view
/// added the device; R4SecurityClose's interim (`fulfill_authorized_leaf_recovery`) returned
/// before reading any request without an acceptance authorization, so no forged view failed
/// and the genuine request was never fulfilled.
#[test]
fn malicious_ds_recovery_views_never_add_a_device() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_dev = new_id();
    let alice = enrolled(&tmp, &ds, "alice", ALICE_DID, &alice_dev);
    let _bob = enrolled(&tmp, &ds, "bob", BOB_DID, &new_id());
    let alice2_dev = new_id();
    let alice2 = enrolled(&tmp, &ds, "alice2", ALICE_DID, &alice2_dev);
    let carol_dev = new_id();
    let carol = enrolled(&tmp, &ds, "carol", CAROL_DID, &carol_dev);
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Recovery".into()),
            Some("group".into()),
        )
        .expect("alice creates the group; bob never accepts");
    alice.sync().expect("alice syncs");
    let cid = cid.as_str();
    let local = || {
        let submits = ds
            .inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(_, url, _)| url.ends_with("/xrpc/blue.catbird.chat.submitTransition"))
            .count();
        let ack = ds
            .inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.to_owned(), alice_dev.clone()))
            .copied();
        (
            submits,
            identities(&alice, cid),
            epoch(&alice, cid),
            stored_coordinates(&alice, cid),
            last_seq(&alice, cid),
            ack,
        )
    };
    let before = local();
    assert_eq!(before.1, [format!("{ALICE_DID}#{alice_dev}")]);

    let genuine = request_recovery(
        &ds,
        &enrolled_signer(&alice2),
        ALICE_DID,
        &alice2_dev,
        cid,
        "add",
    )["recovery"]
        .clone();
    assert_eq!(genuine["status"], "open", "{genuine}");
    let stranger = request_recovery(
        &ds,
        &enrolled_signer(&carol),
        CAROL_DID,
        &carol_dev,
        cid,
        "add",
    )["recovery"]
        .clone();
    let carol_package = ds
        .inner
        .lock()
        .unwrap()
        .convo_kps
        .get_mut(&(CAROL_DID.to_owned(), carol_dev.clone()))
        .and_then(Vec::pop)
        .expect("carol's KeyPackage");
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut view = genuine.clone();
        edit(&mut view);
        view
    };

    for (case, view) in [
        (
            "an unsigned request",
            edited(&|view| {
                view.as_object_mut().unwrap().remove("signedRequest");
            }),
        ),
        ("a stranger's signed add", stranger),
    ] {
        list(&ds, cid, vec![view]);
        alice
            .sync()
            .unwrap_or_else(|error| panic!("{case} is no work: {error:?}"));
        assert_eq!(local(), before, "{case}");
    }

    let mut other_coordinate = genuine["boundCoordinate"].clone();
    other_coordinate["stateVersion"] =
        json!(other_coordinate["stateVersion"].as_i64().unwrap() + 1);
    let carol_key_id = derive_key_id(enrolled_signer(&carol).public());
    let refused = [
        (
            "a signature that does not verify",
            edited(&|view| {
                view["signedRequest"]["body"]["signedAt"] = json!("2026-11-07T00:00:00.000Z")
            }),
            "verify signed transition",
        ),
        (
            "another request ID",
            edited(&|view| view["recoveryRequestId"] = json!(new_id())),
            "not the authorized request",
        ),
        (
            "another kind",
            edited(&|view| view["recoveryKind"] = json!("replace")),
            "not the authorized request",
        ),
        (
            "another device",
            edited(&|view| {
                view["requesterDid"] = json!(CAROL_DID);
                view["requesterDeviceId"] = json!(carol_dev);
                view["reservation"]["requesterDid"] = json!(CAROL_DID);
                view["reservation"]["requesterDeviceId"] = json!(carol_dev);
            }),
            "verify signed transition",
        ),
        (
            "another key ID",
            edited(&|view| view["reservation"]["requesterKeyId"] = json!(carol_key_id)),
            "not the authorized request",
        ),
        (
            "another auth generation",
            edited(&|view| view["reservation"]["requesterAuthGeneration"] = json!(2)),
            "not the authorized request",
        ),
        (
            "another coordinate",
            edited(&|view| view["boundCoordinate"] = other_coordinate.clone()),
            "not bound to the current coordinate",
        ),
        (
            "another device's KeyPackage",
            edited(&|view| {
                view["reservation"]["keyPackage"] = carol_package.clone();
                view["reservation"]["keyPackageRef"] = carol_package["keyPackageRef"].clone();
            }),
            "not the authorized device's own",
        ),
    ];
    for (case, view, reason) in refused {
        list(&ds, cid, vec![view]);
        let error = alice.sync().expect_err(case);
        assert!(
            matches!(&error, MLSError::SyncIncomplete { failures, .. }
                if failures.len() == 1 && failures[0].conversation_id == cid),
            "{case}: {error:?}"
        );
        assert!(error.to_string().contains(reason), "{case}: {error}");
        assert_eq!(local(), before, "{case}");
    }

    list(&ds, cid, vec![genuine.clone()]);
    alice.sync().expect("the genuine signed request");
    let added = fulfillments(&ds, &alice_dev);
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["recoveryRequestId"], genuine["recoveryRequestId"]);
    assert_eq!(epoch(&alice, cid), before.2 + 1);
    assert!(identities(&alice, cid).contains(&format!("{ALICE_DID}#{alice2_dev}")));
}

/// An existing member's new device joins from its own signed request, once. Bob, a joined
/// member, enrolls a second device, which signs an add request. Alice's sync fulfills it with
/// exactly one Add whose Welcome attests her verified roster, the new device joins from the
/// Welcome holding that roster, and it and Alice exchange messages. mls-ds then lists the
/// consumed request again, as first listed and rebound to the current coordinate: Alice adds
/// nothing.
///
/// Fail-before: R4SecurityClose's interim (`fulfill_authorized_leaf_recovery`) fulfilled only
/// acceptance authorizations, so the signed request was never fulfilled and the device never
/// joined; cut 9a2708e1 (`fulfill_pending_leaf_recoveries`) attached no roster to the Welcome,
/// so the device joined without one, and fulfilled any listed add bound to the state
/// coordinate, so the rebound consumed request made Alice add the device again and her sync
/// failed.
#[test]
fn existing_members_new_device_is_added_once_from_its_signed_request() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    let bob2_dev = new_id();
    let bob2 = enrolled(&f.tmp, ds, "bob2", BOB_DID, &bob2_dev);
    let request = request_recovery(ds, &enrolled_signer(&bob2), BOB_DID, &bob2_dev, cid, "add")
        ["recovery"]
        .clone();
    assert_eq!(request["status"], "open", "{request}");
    let earlier = fulfillments(ds, &f.alice_dev).len();

    alice.sync().expect("alice fulfills bob's new device");
    let added = fulfillments(ds, &f.alice_dev);
    assert_eq!(added.len(), earlier + 1, "exactly one fulfillment");
    let added = added.last().unwrap();
    assert_eq!(added["recoveryRequestId"], request["recoveryRequestId"]);
    assert_eq!(
        added["manifest"]["leafChanges"],
        json!([{
            "$type": "blue.catbird.chat.defs#addLeafByRecovery",
            "userDid": BOB_DID,
            "deviceId": bob2_dev,
            "recoveryRequestId": request["recoveryRequestId"],
            "keyPackageRef": request["reservation"]["keyPackageRef"],
        }])
    );

    bob2.sync()
        .expect("bob's new device joins from the Welcome");
    assert!(identities(alice, cid).contains(&format!("{BOB_DID}#{bob2_dev}")));
    assert_eq!(identities(&bob2, cid), identities(alice, cid));
    let roster = |client: &CatbirdMlsClient| {
        client
            .db()
            .read_tx(|tx| tx.get_account_meta(&chat_wire::conversation_roster_key(cid)))
            .unwrap()
            .map(|raw| serde_json::from_str::<Value>(&raw).unwrap())
    };
    assert!(roster(alice).is_some(), "alice holds a verified roster");
    assert_eq!(
        roster(&bob2),
        roster(alice),
        "the Welcome attests alice's roster"
    );
    bob2.send_message(cid, &new_id(), "from bob's new device")
        .expect("bob's new device sends");
    alice.sync().expect("alice receives");
    assert!(timeline_after(alice, cid, 0)
        .iter()
        .any(|(_, text)| text == "from bob's new device"));
    alice
        .send_message(cid, &new_id(), "to bob's new device")
        .expect("alice sends");
    bob2.sync().expect("bob's new device receives");
    assert!(timeline_after(&bob2, cid, 0)
        .iter()
        .any(|(_, text)| text == "to bob's new device"));

    let joined_epoch = epoch(alice, cid);
    let current = ds.inner.lock().unwrap().conversations[cid]["coordinates"].clone();
    let mut rebound = request.clone();
    rebound["boundCoordinate"] = current.clone();
    rebound["reservation"]["boundCoordinate"] = current;
    for (case, view) in [("as first listed", request), ("rebound", rebound)] {
        list(ds, cid, vec![view]);
        alice
            .sync()
            .unwrap_or_else(|error| panic!("{case}: a consumed request is no work: {error:?}"));
        assert_eq!(
            (fulfillments(ds, &f.alice_dev).len(), epoch(alice, cid)),
            (earlier + 1, joined_epoch),
            "{case}"
        );
    }
}

/// A `replace` re-adds exactly the requester device's current leaf, and only from another
/// account. Bob's second device joins (as above); then Bob's first device signs a replace.
/// Bob's second device, of the requester's own account, leaves it alone. Alice fulfills it with
/// one Commit that removes exactly Bob's leaf and adds his new KeyPackage (`removeLeaf`, then
/// `addLeafByRecovery`); Eve, a third member, and Bob's second device process it to Alice's
/// leaves: every identity stays and, besides the committer's own, only Bob's leaf is new.
///
/// Fail-before: cut 9a2708e1 (`fulfill_pending_leaf_recoveries`) fulfilled only `add` requests
/// and R4SecurityClose's interim (`fulfill_authorized_leaf_recovery`) only acceptance
/// authorizations, so neither ever replaced the leaf.
#[test]
fn signed_replace_removes_and_readds_the_exact_leaf() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, eve) = (&f.ds, f.cid.as_str(), &f.alice, &f.eve);
    eve.sync().expect("eve accepts");
    alice.sync().expect("alice adds eve");
    eve.sync().expect("eve joins");
    let bob2_dev = new_id();
    let bob2 = enrolled(&f.tmp, ds, "bob2", BOB_DID, &bob2_dev);
    request_recovery(ds, &enrolled_signer(&bob2), BOB_DID, &bob2_dev, cid, "add");
    alice.sync().expect("alice adds bob's second device");
    bob2.sync().expect("bob's second device joins");
    eve.sync().expect("eve applies the add");

    let request = request_recovery(
        ds,
        &enrolled_signer(&f.bob),
        BOB_DID,
        &f.bob_dev,
        cid,
        "replace",
    )["recovery"]
        .clone();
    assert_eq!(request["recoveryKind"], "replace", "{request}");
    let entries = ds.entry_count(cid);
    bob2.sync()
        .expect("a replace of its own account is no work");
    assert!(fulfillments(ds, &bob2_dev).is_empty());
    assert_eq!(ds.entry_count(cid), entries);

    let before = leaves(alice, cid);
    alice.sync().expect("alice replaces bob's leaf");
    let replace = fulfillments(ds, &f.alice_dev)
        .pop()
        .expect("alice's fulfillment");
    assert_eq!(replace["recoveryRequestId"], request["recoveryRequestId"]);
    assert_eq!(
        replace["manifest"]["leafChanges"],
        json!([
            {
                "$type": "blue.catbird.chat.defs#removeLeaf",
                "userDid": BOB_DID,
                "deviceId": f.bob_dev,
            },
            {
                "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                "userDid": BOB_DID,
                "deviceId": f.bob_dev,
                "recoveryRequestId": request["recoveryRequestId"],
                "keyPackageRef": request["reservation"]["keyPackageRef"],
            },
        ])
    );
    let after = leaves(alice, cid);
    let bob_leaf = format!("{BOB_DID}#{}", f.bob_dev);
    let committer = format!("{ALICE_DID}#{}", f.alice_dev);
    assert_eq!(
        after
            .iter()
            .map(|(identity, _)| identity)
            .collect::<Vec<_>>(),
        before
            .iter()
            .map(|(identity, _)| identity)
            .collect::<Vec<_>>(),
        "every leaf stays"
    );
    for ((identity, old), (_, new)) in before.iter().zip(&after) {
        if *identity != committer {
            assert_eq!(old != new, *identity == bob_leaf, "{identity}");
        }
    }

    eve.sync().expect("eve processes the replace");
    assert_eq!(leaves(eve, cid), after);
    bob2.sync()
        .expect("bob's second device processes the replace");
    assert_eq!(leaves(&bob2, cid), after);
}
