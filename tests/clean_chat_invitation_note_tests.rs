//! C28: Group-note separation (core component qualification).
//! Note is bound to authentic invitation, recipient, and authority.
//! No target-group leaf, Welcome, exporter secret, or app history before group acceptance.
//! Partial note delivery retry does not duplicate invitation.
//!
//! Note on test boundaries:
//! - This suite qualifies the client-side core orchestrator, outbox, and crypto logic in-memory.
//! - The live dedicated-DB shipping-router lost-response committed note publication and retry
//!   qualification (with real PostgreSQL row locks and fault transport) is in
//!   `mls-ds/e2e-tests/tests/encrypted_request_c28.rs`.
#![allow(dead_code)]
mod e2e_harness;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::{
    decode_strict_json, direct_request as protocol, project_signed_body, SignedMutationKind,
    SigningTranscript,
};
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op, CredentialStore, MLSStorageBackend,
};
use catbird_mls::{
    DirectRequestInput, DirectRequestOutcome, RequestConsent, RequestCrypto, RequestPreview,
};
use e2e_harness::TestWorld;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn receipt_authority() -> (p256::ecdsa::SigningKey, Vec<u8>, String) {
    let key = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(true);
    let id = protocol::direct_request_receipt_key_id(point.as_bytes()).unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(point.as_bytes());
    let doc = serde_json::to_vec(&json!({
        "id": "did:web:chat.catbird.blue",
        "verificationMethod": [{
            "id": id,
            "controller": "did:web:chat.catbird.blue",
            "type": "Multikey",
            "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey),
        }]
    }))
    .unwrap();
    (key, doc, id)
}

fn es256(key: &p256::ecdsa::SigningKey, bytes: &[u8]) -> String {
    let sig: p256::ecdsa::Signature = key.sign(bytes);
    STANDARD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
}

fn utc(delta: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(delta))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn last_request(world: &TestWorld, op: Op) -> Value {
    let requests = world.delivery_service().submitted_prepared_requests();
    serde_json::from_slice(
        requests
            .iter()
            .rev()
            .find(|r| r.operation == op)
            .unwrap()
            .body
            .as_ref()
            .unwrap(),
    )
    .unwrap()
}

/// Every body the transport actually submitted for one canonical operation, in
/// call order. This is the server/transport-observed record of what the note
/// outbox sent, independent of anything the client believes.
fn submissions(world: &TestWorld, op: Op) -> Vec<Value> {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == op)
        .map(|r| serde_json::from_slice(r.body.as_deref().unwrap()).unwrap())
        .collect()
}

/// Bob's prepared recipient selection: a real key package and a real signed
/// grant, labeled with Bob's registered device.
async fn recipient_selection(world: &TestWorld) -> Value {
    let bob = world.client("Bob");
    let bob_device = bob
        .credentials
        .get_device_uuid(&bob.did)
        .await
        .unwrap()
        .unwrap();
    let identity = format!("{}#{bob_device}", bob.did).into_bytes();
    let package = bob
        .orchestrator
        .mls_context()
        .create_key_package(identity.clone())
        .unwrap();
    let bob_public = bob
        .orchestrator
        .mls_context()
        .identity_public_key(String::from_utf8(identity.clone()).unwrap())
        .unwrap();
    let grant_id = uuid::Uuid::new_v4().to_string();
    let grant = json!({
        "$type": "blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-GRANT\0",
        "protocolVersion": "2",
        "actorDid": bob.did,
        "actorDeviceId": bob_device,
        "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
        "authGeneration": 1,
        "grantId": grant_id,
        "grantRevision": 1,
        "purpose": "direct-request-bootstrap",
        "profile": "encryptedIntroduction1",
        "keyPackageRef": STANDARD.encode(&package.hash_ref),
        "keyPackageSha256": STANDARD.encode(Sha256::digest(&package.key_package_data)),
        "expiresAt": utc(29 * 86400),
        "idempotencyKey": grant_id,
        "signedAt": utc(0),
    });
    let signature = bob
        .orchestrator
        .mls_context()
        .sign_with_identity_key(
            String::from_utf8(identity).unwrap(),
            protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Grant,
                &serde_json::to_vec(&grant).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    json!({
        "actorDid": bob.did,
        "actorDeviceId": bob_device,
        "keyId": grant["keyId"],
        "authGeneration": 1,
        "keyPackage": {
            "framing": "mlsMessage",
            "contentType": "keyPackage",
            "bytes": STANDARD.encode(&package.key_package_data),
            "sha256": STANDARD.encode(Sha256::digest(&package.key_package_data)),
            "keyPackageRef": STANDARD.encode(&package.hash_ref),
        },
        "grant": {
            "body": grant,
            "signature": STANDARD.encode(signature),
        }
    })
}

/// A receipt-authority-signed preparation echoing the exact prepare request.
fn signed_preparation(
    prepare: &Value,
    prepare_request_digest: &[u8],
    authority: &p256::ecdsa::SigningKey,
    method: &str,
    selected: Value,
) -> Value {
    let mut preparation = json!({
        "protocolVersion": "2",
        "requestId": prepare["requestId"],
        "firstMessageId": prepare["firstMessageId"],
        "conversationId": prepare["conversationId"],
        "recipientDid": prepare["recipientDid"],
        "origin": prepare["origin"],
        "profile": prepare["profile"],
        "creator": {
            "actorDid": prepare["actorDid"],
            "actorDeviceId": prepare["actorDeviceId"],
            "keyId": prepare["keyId"],
            "authGeneration": prepare["authGeneration"],
        },
        "selectedDevices": [selected],
        "preparedAt": utc(0),
        "leaseExpiresAt": utc(600),
        "minimumImportUntil": utc(7 * 86400 + 300 - 5),
        "preparationRequestDigest": STANDARD.encode(prepare_request_digest),
        "authorityDid": "did:web:chat.catbird.blue",
        "receiptKeyId": method,
    });
    let signing = protocol::direct_request_preparation_signing_bytes(
        &serde_json::to_vec(&preparation).unwrap(),
    )
    .unwrap();
    preparation["preparationDigest"] = json!(STANDARD.encode(Sha256::digest(&signing)));
    preparation["preparationSignature"] = json!(es256(authority, &signing));
    preparation
}

fn prepared_outcome(preparation: Value) -> Value {
    json!({
        "outcome": {
            "$type": "blue.catbird.chat.defs#directRequestPreparedOutcome",
            "preparation": preparation,
        }
    })
}

/// The authority's signed published receipt for the exact submitted publish bytes.
fn published_receipt(
    authority: &p256::ecdsa::SigningKey,
    method: &str,
    prepare_request_digest: &[u8],
    signed_publish: &Value,
    publish_request_digest: &[u8],
) -> Value {
    let p = &signed_publish["body"];
    let body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": "did:web:chat.catbird.blue",
        "keyId": method,
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestPublishedReceipt",
            "requestId": p["requestId"],
            "requestKind": "publish",
            "requestDigest": STANDARD.encode(publish_request_digest),
            "preparationRequestDigest": STANDARD.encode(prepare_request_digest),
            "actorDid": p["actorDid"],
            "actorDeviceId": p["actorDeviceId"],
            "actorKeyId": p["keyId"],
            "authGeneration": p["authGeneration"],
            "conversationId": p["conversationId"],
            "firstMessageId": p["firstMessageId"],
            "coordinates": p["next"],
            "recordedAt": utc(0),
        }
    });
    json!({
        "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "signature": es256(
            authority,
            &protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Outcome,
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap(),
        ),
        "body": body,
    })
}

/// Sets up a group where Alice is admin and Bob is a pending invitee via a signed policy transition.
async fn setup_target_group(
    world: &TestWorld,
    invitation_id: &str,
) -> (String, Value, Value, String) {
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let members = vec![bob.did.clone(), "did:plc:cccccccccccccccccccccccc".into()];
    let mut view = alice
        .orchestrator
        .create_group("Target Group", Some(&members), None)
        .await
        .unwrap();
    let wrapper = last_request(world, Op::CreateConversation);
    let b = &wrapper["signedRequest"]["body"];
    let mut participants = b["manifest"]["participants"].clone();
    for p in participants.as_array_mut().unwrap() {
        p["leafCount"] = json!(if p["status"] == "active" { 1 } else { 0 });
    }
    let prior_state = json!({
        "conversationKind": b["conversationKind"],
        "coordinates": b["next"],
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "participants": participants,
        "leaves": [{
            "userDid": b["actorDid"],
            "deviceId": b["actorDeviceId"],
            "deviceStatus": "active",
            "leafOrigin": "genesis",
            "keyId": b["keyId"],
        }],
        "metadataSnapshot": b["metadataSnapshot"],
        "snapshotSeq": 1,
    });
    let cid = view.conversation_id.clone();
    let alice_device = b["actorDeviceId"].as_str().unwrap().to_string();
    let alice_pubkey = alice
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{}#{alice_device}", alice.did))
        .unwrap();
    alice
        .credentials
        .set_authorized_device_keys(&alice.did, vec![alice_pubkey.clone()]);

    let mut group_state = prior_state.clone();
    group_state["coordinates"]["stateVersion"] = json!(3);
    group_state["snapshotSeq"] = json!(3);
    let provenance = json!({
        "invitationTransitionId": invitation_id,
        "invitedByDid": alice.did,
        "invitedByDeviceId": alice_device,
    });
    group_state["participants"][1]["status"] = json!("pending");
    group_state["participants"][1]["leafCount"] = json!(0);
    group_state["participants"][1]["invitationProvenance"] = provenance.clone();

    let invitation_body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\0",
        "transitionId": invitation_id,
        "idempotencyKey": invitation_id,
        "actorDid": alice.did,
        "actorDeviceId": alice_device,
        "keyId": b["keyId"],
        "authGeneration": 1,
        "prior": prior_state["coordinates"],
        "next": group_state["coordinates"],
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#addParticipant",
            "userDid": bob.did,
            "role": "member",
            "status": "pending",
            "invitationProvenance": provenance,
        }],
        "signedAt": utc(0),
    });

    let strict = decode_strict_json(&serde_json::to_vec(&invitation_body).unwrap()).unwrap();
    let transcript = SigningTranscript::build_for(
        SignedMutationKind::PolicyTransition,
        &project_signed_body(SignedMutationKind::PolicyTransition, &strict).unwrap(),
    )
    .unwrap();

    let signature = alice
        .orchestrator
        .mls_context()
        .sign_with_identity_key(
            format!("{}#{}", alice.did, alice_device),
            transcript.bytes().to_vec(),
        )
        .unwrap();

    let invitation_entry = json!({
        "$type": "blue.catbird.chat.defs#policyEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": cid,
        "seq": 3,
        "signedRequest": {
            "body": invitation_body,
            "signature": STANDARD.encode(signature),
        },
        "receivedAt": utc(0),
    });

    view.canonical_state = Some(
        catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
            &serde_json::to_vec(&group_state).unwrap(),
        )
        .unwrap(),
    );
    world.delivery_service().set_conversation_view_for_test(&cid, view);
    world.delivery_service().set_lifecycle_state_for_test(&cid, group_state.clone());

    (cid, group_state, invitation_entry, alice_device)
}

#[tokio::test(flavor = "multi_thread")]
async fn c28_note_bound_to_authentic_invitation_recipient_and_authority() {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let (_authority, doc, _method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }

    let invitation_id = uuid::Uuid::new_v4().to_string();
    let (target_cid, group_state, invitation_entry, alice_device) =
        setup_target_group(&world, &invitation_id).await;

    // 1. Valid authentic invitation lookup
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [invitation_entry], "hasMore": false, "nextAfterSeq": 3}),
    );

    let link = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(link.authority_did, "did:web:chat.catbird.blue");
    assert_eq!(link.conversation_id, target_cid);
    assert_eq!(link.invitation_transition_id, invitation_id);
    assert_eq!(link.invited_by_did, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(link.invited_by_device_id, alice_device);
    assert_eq!(link.recipient_did, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");

    // 2. Mismatched recipient: query for uninvited user -> returns None
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    let uninvited_ref = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:dddddddddddddddddddddddd")
        .await
        .unwrap();
    assert!(uninvited_ref.is_none());

    // 3. Forged invitation entry: transition ID tampered to another recipient -> returns Err
    let mut forged_entry = invitation_entry.clone();
    forged_entry["signedRequest"]["body"]["participantChanges"][0]["userDid"] =
        json!("did:plc:cccccccccccccccccccccccc");
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [forged_entry], "hasMore": false, "nextAfterSeq": 3}),
    );
    assert!(world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .is_err());

    // 4. Closed target group: lifecycle is closed -> returns None
    let mut closed_state = group_state.clone();
    closed_state["coordinates"]["lifecycle"] = json!("superseded");
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": closed_state}),
    );
    let closed_ref = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .unwrap();
    assert!(closed_ref.is_none());

    // 5. Already accepted: Bob is active, not pending -> returns None
    let mut accepted_state = group_state.clone();
    accepted_state["participants"][1]["status"] = json!("active");
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": accepted_state}),
    );
    let accepted_ref = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .unwrap();
    assert!(accepted_ref.is_none());

    // 6. Direct request validation rejects mismatched/spliced invitation reference
    let mut spliced_link = link.clone();
    spliced_link.recipient_did = "did:plc:cccccccccccccccccccccccc".into();
    let bad_input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Direct note with spliced invitation".into(),
        invitation: Some(spliced_link),
    };
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    let bad_result = world
        .client("Alice")
        .orchestrator
        .start_direct_request(bad_input)
        .await;
    assert!(bad_result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn c28_no_target_group_leaf_welcome_or_secrets_before_acceptance() {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let (authority, doc, method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }

    let invitation_id = uuid::Uuid::new_v4().to_string();
    let (target_cid, group_state, invitation_entry, _alice_dev) =
        setup_target_group(&world, &invitation_id).await;
    let target_gid = STANDARD
        .decode(group_state["coordinates"]["groupId"].as_str().unwrap())
        .unwrap();

    // 1. Alice resolves authentic invitation link
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [invitation_entry.clone()], "hasMore": false, "nextAfterSeq": 3}),
    );
    let invitation_ref = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .unwrap()
        .unwrap();

    // 2. Alice starts direct request with the group note
    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Please join our group chat".into(),
        invitation: Some(invitation_ref.clone()),
    };

    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [invitation_entry], "hasMore": false, "nextAfterSeq": 3}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error": "unavailable"}),
    );

    let _unknown = world
        .client("Alice")
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();

    let original = last_request(&world, Op::PrepareDirectRequest);
    let prepare = original["signedRequest"]["body"].clone();
    let pubkey = {
        let alice = world.client("Alice");
        let dev = alice
            .credentials
            .get_device_uuid(&alice.did)
            .await
            .unwrap()
            .unwrap();
        alice
            .orchestrator
            .mls_context()
            .identity_public_key(format!("{}#{dev}", alice.did))
            .unwrap()
    };
    let verified = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&original["signedRequest"]).unwrap(),
        &pubkey,
    )
    .unwrap();

    let preparation = signed_preparation(
        &prepare,
        verified.request_digest(),
        &authority,
        &method,
        recipient_selection(&world).await,
    );

    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        200,
        prepared_outcome(preparation),
    );

    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        503,
        json!({"error": "lost"}),
    );

    let _retry = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();

    let publication = last_request(&world, Op::PublishDirectRequest);
    let p = publication["signedRequest"]["body"].clone();
    let verified_publish = protocol::verify_signed_request(
        protocol::DirectRequestKind::Publish,
        &serde_json::to_vec(&publication["signedRequest"]).unwrap(),
        &pubkey,
    )
    .unwrap();

    let receipt = published_receipt(
        &authority,
        &method,
        verified.request_digest(),
        &publication["signedRequest"],
        verified_publish.request_digest(),
    );

    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        200,
        json!({"outcome": receipt}),
    );

    let sent = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(sent, DirectRequestOutcome::RequestSent { .. }));

    let direct_cid = p["conversationId"].as_str().unwrap().to_string();

    // 3. Bob receives and previews the direct request note
    let publication_entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": direct_cid,
        "seq": 1,
        "signedRequest": publication["signedRequest"],
        "receivedAt": receipt["body"]["receipt"]["recordedAt"].clone(),
    });

    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [publication_entry], "hasMore": false, "nextAfterSeq": 1}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetDirectRequestOutcome,
        200,
        json!({"outcome": receipt}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error": "offline"}),
    );

    let bob_preview = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(&direct_cid)
        .await
        .unwrap();

    assert_eq!(bob_preview.consent, RequestConsent::IncomingPending);
    assert_eq!(bob_preview.crypto, RequestCrypto::Ready);
    match &bob_preview.preview {
        Some(RequestPreview::Ready { text, invitation }) => {
            assert_eq!(text, "Please join our group chat");
            assert_eq!(invitation.as_ref(), Some(&invitation_ref));
        }
        other => panic!("Expected RequestPreview::Ready with invitation, got: {other:?}"),
    }

    // 4. CRITICAL C28 ASSERTIONS:
    // Bob has previewed the direct note, BUT:
    // - NO target-group leaf node in Bob's MLS context
    assert!(
        world
            .client("Bob")
            .orchestrator
            .mls_context()
            .get_epoch(target_gid.clone())
            .is_err(),
        "Bob must NOT have a leaf or group context for the target group before acceptance"
    );

    // - NO target-group Welcome has been imported
    assert!(
        world
            .client("Bob")
            .storage
            .get_group_state(&hex::encode(&target_gid))
            .await
            .unwrap()
            .is_none(),
        "Bob must NOT possess group state for the target group before acceptance"
    );

    // - NO target-group exporter secrets or epoch secrets
    assert!(
        world
            .client("Bob")
            .orchestrator
            .mls_context()
            .export_secret(target_gid.clone(), "test-label".into(), vec![], 32)
            .is_err(),
        "Bob must NOT possess exporter secrets for the target group before acceptance"
    );

    // - NO target-group application message history
    assert!(
        world
            .client("Bob")
            .storage
            .get_conversation_messages(&target_cid)
            .is_empty(),
        "Bob must NOT have target group message history before group acceptance"
    );

    // - Target group consent is separate: Bob does not have an accepted conversation for target group
    assert!(
        world
            .client("Bob")
            .storage
            .get_conversation("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", &target_cid)
            .await
            .unwrap()
            .is_none(),
        "Target group consent is separate; direct note preview must not accept the target group"
    );
}

/// Core in-memory outbox qualification: note retry does not duplicate invitation.
/// Live shipping router, dedicated PostgreSQL database, and DeterministicFaultTransport
/// qualification lives in `mls-ds/e2e-tests/tests/encrypted_request_c28.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn c28_partial_note_delivery_retry_does_not_duplicate_invitation() {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let (authority, doc, method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }

    let invitation_id = uuid::Uuid::new_v4().to_string();
    let (target_cid, group_state, invitation_entry, _alice_dev) =
        setup_target_group(&world, &invitation_id).await;

    // The invitation-bearing mutations the target group has seen so far. The
    // note attempt and its retry must add none of them.
    let group_creations_before_note = submissions(&world, Op::CreateConversation).len();
    let transitions_before_note = submissions(&world, Op::SubmitTransition).len();

    let alice_pubkey = {
        let alice = world.client("Alice");
        let device = alice
            .credentials
            .get_device_uuid(&alice.did)
            .await
            .unwrap()
            .unwrap();
        alice
            .orchestrator
            .mls_context()
            .identity_public_key(format!("{}#{device}", alice.did))
            .unwrap()
    };

    let invitation_ref = {
        world.delivery_service().queue_request_operation_response(
            Op::GetConversationState,
            200,
            json!({"state": group_state}),
        );
        world.delivery_service().queue_request_operation_response(
            Op::GetEntries,
            200,
            json!({"entries": [invitation_entry.clone()], "hasMore": false, "nextAfterSeq": 3}),
        );
        world
            .client("Alice")
            .orchestrator
            .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
            .await
            .unwrap()
            .unwrap()
    };
    assert_eq!(invitation_ref.invitation_transition_id, invitation_id);

    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Please join our group chat".into(),
        invitation: Some(invitation_ref.clone()),
    };

    // 1. Transport drops the first prepare response. The note outbox retains an
    //    unresolved attempt carrying the exact invitation.
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [invitation_entry.clone()], "hasMore": false, "nextAfterSeq": 3}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error": "unavailable"}),
    );
    let first = world
        .client("Alice")
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();
    assert!(matches!(first, DirectRequestOutcome::OutcomeUnknown { .. }));

    let prepare_bodies = submissions(&world, Op::PrepareDirectRequest);
    assert_eq!(prepare_bodies.len(), 1);
    let verified_prepare = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare_bodies[0]["signedRequest"]).unwrap(),
        &alice_pubkey,
    )
    .unwrap();
    let prepare = prepare_bodies[0]["signedRequest"]["body"].clone();

    // 2. The server answers that exact prepare; the publish response is lost.
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        200,
        prepared_outcome(signed_preparation(
            &prepare,
            verified_prepare.request_digest(),
            &authority,
            &method,
            recipient_selection(&world).await,
        )),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        503,
        json!({"error": "lost"}),
    );
    let second = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(second, DirectRequestOutcome::OutcomeUnknown { .. }));

    let lost_publish = submissions(&world, Op::PublishDirectRequest);
    assert_eq!(lost_publish.len(), 1, "first publish reached the transport");
    let verified_publish = protocol::verify_signed_request(
        protocol::DirectRequestKind::Publish,
        &serde_json::to_vec(&lost_publish[0]["signedRequest"]).unwrap(),
        &alice_pubkey,
    )
    .unwrap();
    let p = lost_publish[0]["signedRequest"]["body"].clone();
    assert_eq!(p["requestId"], prepare["requestId"]);

    // 3. Retry the unresolved attempt; the authority confirms the same request.
    let receipt = published_receipt(
        &authority,
        &method,
        verified_prepare.request_digest(),
        &lost_publish[0]["signedRequest"],
        verified_publish.request_digest(),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        200,
        json!({"outcome": receipt}),
    );
    let sent = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(sent, DirectRequestOutcome::RequestSent { .. }));

    // 3a. Transport-observed retry: the same two requests replayed byte-for-byte.
    //     The retry minted no second request identity and no second introduction.
    let publish_bodies = submissions(&world, Op::PublishDirectRequest);
    assert_eq!(publish_bodies.len(), 2, "publish retried through the outbox");
    assert_eq!(
        publish_bodies[0], publish_bodies[1],
        "lost-response retry must replay the identical publication"
    );
    let prepare_bodies = submissions(&world, Op::PrepareDirectRequest);
    assert_eq!(prepare_bodies.len(), 2, "prepare retried through the outbox");
    assert_eq!(prepare_bodies[0], prepare_bodies[1]);

    // 3b. The retry submitted no new invitation-bearing mutation to the target
    //     group: no creation and no policy transition was resubmitted.
    assert_eq!(
        submissions(&world, Op::CreateConversation).len(),
        group_creations_before_note
    );
    assert_eq!(
        submissions(&world, Op::SubmitTransition).len(),
        transitions_before_note
    );

    // 3c. The production resolver, re-run against the server's current target
    //     group snapshot after the retry, still yields the identical single
    //     invitation (two pending rows for the recipient would be an error, none
    //     a `None`).
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [invitation_entry.clone()], "hasMore": false, "nextAfterSeq": 3}),
    );
    let retry_ref = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry_ref, invitation_ref);

    // 4. Recipient projection: the single published introduction decrypts for
    //    Bob with the original target-group invitation, exactly once.
    let direct_cid = p["conversationId"].as_str().unwrap().to_string();
    let publication_entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": direct_cid,
        "seq": 1,
        "signedRequest": lost_publish[0]["signedRequest"],
        "receivedAt": receipt["body"]["receipt"]["recordedAt"].clone(),
    });
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [publication_entry], "hasMore": false, "nextAfterSeq": 1}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetDirectRequestOutcome,
        200,
        json!({"outcome": receipt}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error": "offline"}),
    );

    let bob_view = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(&direct_cid)
        .await
        .unwrap();
    assert_eq!(bob_view.crypto, RequestCrypto::Ready);
    match &bob_view.preview {
        Some(RequestPreview::Ready { text, invitation }) => {
            assert_eq!(text, "Please join our group chat");
            assert_eq!(
                invitation.as_ref(),
                Some(&invitation_ref),
                "recipient must see the original invitation, not a duplicate"
            );
            assert_eq!(
                invitation.as_ref().unwrap().invitation_transition_id,
                invitation_id
            );
        }
        other => panic!("Expected one decrypted introduction, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c28_group_note_embed_requires_accepted_direct_channel() {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let (_authority, doc, _method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }

    let invitation_id = uuid::Uuid::new_v4().to_string();
    let (target_cid, group_state, invitation_entry, _alice_dev) =
        setup_target_group(&world, &invitation_id).await;

    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries": [invitation_entry.clone()], "hasMore": false, "nextAfterSeq": 3}),
    );

    let invitation_ref = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&target_cid, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await
        .unwrap()
        .unwrap();

    let embed =
        catbird_mls::orchestrator::types::MLSEmbedData::group_invitation(invitation_ref.clone())
            .unwrap();

    // 1. Direct conversation where directRequest consent is pending (not accepted)
    let pending_cid = uuid::Uuid::new_v4().to_string();
    let pending_direct_state = json!({
        "conversationKind": "direct",
        "coordinates": {
            "conversationId": pending_cid,
            "groupId": STANDARD.encode([11u8; 32]),
            "generation": 0,
            "stateVersion": 1,
            "epoch": 1,
            "lifecycle": "active",
            "groupContextHash": STANDARD.encode([22u8; 32]),
            "confirmationTag": STANDARD.encode([33u8; 32]),
        },
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "participants": [
            {
                "userDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "role": "admin",
                "status": "active",
                "leafCount": 1,
            },
            {
                "userDid": "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
                "role": "admin",
                "status": "pending",
                "leafCount": 1,
                "invitationProvenance": {
                    "invitationTransitionId": uuid::Uuid::new_v4().to_string(),
                    "invitedByDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                    "invitedByDeviceId": uuid::Uuid::new_v4().to_string(),
                }
            }
        ],
        "leaves": [
            {
                "userDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "deviceId": uuid::Uuid::new_v4().to_string(),
                "deviceStatus": "active",
                "leafOrigin": "genesis",
                "keyId": "key1",
            }
        ],
        "directRequest": {
            "requestId": uuid::Uuid::new_v4().to_string(),
            "firstMessageId": uuid::Uuid::new_v4().to_string(),
            "senderDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "recipientDid": "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
            "consent": "outgoingPending",
        },
        "snapshotSeq": 1,
    });

    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": pending_direct_state}),
    );

    let err = world
        .client("Alice")
        .orchestrator
        .send_message_with_embed(&pending_cid, "Here is an invite", embed.clone())
        .await;
    assert!(
        err.is_err(),
        "Sending group note to an unaccepted direct chat must fail"
    );

    // 2. Direct conversation with wrong recipient (Charlie instead of Bob)
    let wrong_peer_cid = uuid::Uuid::new_v4().to_string();
    let wrong_peer_state = json!({
        "conversationKind": "direct",
        "coordinates": {
            "conversationId": wrong_peer_cid,
            "groupId": STANDARD.encode([44u8; 32]),
            "generation": 0,
            "stateVersion": 1,
            "epoch": 1,
            "lifecycle": "active",
            "groupContextHash": STANDARD.encode([55u8; 32]),
            "confirmationTag": STANDARD.encode([66u8; 32]),
        },
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "participants": [
            {
                "userDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "role": "admin",
                "status": "active",
                "leafCount": 1,
            },
            {
                "userDid": "did:plc:cccccccccccccccccccccccc",
                "role": "admin",
                "status": "active",
                "leafCount": 1,
            }
        ],
        "leaves": [
            {
                "userDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "deviceId": uuid::Uuid::new_v4().to_string(),
                "deviceStatus": "active",
                "leafOrigin": "genesis",
                "keyId": "key1",
            },
            {
                "userDid": "did:plc:cccccccccccccccccccccccc",
                "deviceId": uuid::Uuid::new_v4().to_string(),
                "deviceStatus": "active",
                "leafOrigin": "genesis",
                "keyId": "key2",
            }
        ],
        "snapshotSeq": 1,
    });

    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state": wrong_peer_state}),
    );

    let wrong_err = world
        .client("Alice")
        .orchestrator
        .send_message_with_embed(&wrong_peer_cid, "Here is an invite", embed.clone())
        .await;
    assert!(
        wrong_err.is_err(),
        "Sending group note to a direct chat with wrong recipient must fail"
    );
}
