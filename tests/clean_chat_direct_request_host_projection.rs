//! C16: Host projection crash recovery.
//! Publication and crypto receipt succeed, then host projection write fails.
//! On reopen, projection is replayed only, first-message count stays one,
//! and native ratchet never rolls back.
#![allow(dead_code)]
mod e2e_harness;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op, CredentialStore, MLSStorageBackend,
    OrchestratorError,
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

#[tokio::test(flavor = "multi_thread")]
async fn c16_sender_host_projection_crash_replays_projection_only() {
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

    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "C16 test direct request".into(),
        invitation: None,
    };

    // 1. Initial attempt fails before prepare response
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error": "unavailable"}),
    );
    let unknown = world
        .client("Alice")
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();
    assert!(matches!(
        unknown,
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));

    // 2. Prepare Alice's request and build Bob's grant
    let original = last_request(&world, Op::PrepareDirectRequest);
    let prepare = &original["signedRequest"]["body"];
    let (device, pubkey) = {
        let alice = world.client("Alice");
        let dev = alice
            .credentials
            .get_device_uuid(&alice.did)
            .await
            .unwrap()
            .unwrap();
        let pk = alice
            .orchestrator
            .mls_context()
            .identity_public_key(format!("{}#{dev}", alice.did))
            .unwrap();
        (dev, pk)
    };
    let verified = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&original["signedRequest"]).unwrap(),
        &pubkey,
    )
    .unwrap();

    let (package, signature, grant, bob_device) = {
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
        (package, signature, grant, bob_device)
    };

    let selected = json!({
        "actorDid": "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
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
    });
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
        "preparationRequestDigest": STANDARD.encode(verified.request_digest()),
        "authorityDid": "did:web:chat.catbird.blue",
        "receiptKeyId": method,
    });
    let signing = protocol::direct_request_preparation_signing_bytes(
        &serde_json::to_vec(&preparation).unwrap(),
    )
    .unwrap();
    preparation["preparationDigest"] = json!(STANDARD.encode(Sha256::digest(&signing)));
    preparation["preparationSignature"] = json!(es256(&authority, &signing));

    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        200,
        json!({
            "outcome": {
                "$type": "blue.catbird.chat.defs#directRequestPreparedOutcome",
                "preparation": preparation,
            }
        }),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        503,
        json!({"error": "lost"}),
    );
    let retry = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(retry, DirectRequestOutcome::OutcomeUnknown { .. }));

    let publication = last_request(&world, Op::PublishDirectRequest);
    let p = &publication["signedRequest"]["body"];
    let verified_publish = protocol::verify_signed_request(
        protocol::DirectRequestKind::Publish,
        &serde_json::to_vec(&publication["signedRequest"]).unwrap(),
        &pubkey,
    )
    .unwrap();

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
            "requestDigest": STANDARD.encode(verified_publish.request_digest()),
            "preparationRequestDigest": STANDARD.encode(verified.request_digest()),
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
    let receipt = json!({
        "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "signature": es256(
            &authority,
            &protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Outcome,
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap(),
        ),
        "body": body,
    });

    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        200,
        json!({"outcome": receipt}),
    );

    let cid = p["conversationId"].as_str().unwrap().to_string();
    let first_msg_id = p["firstMessageId"].as_str().unwrap().to_string();
    let gid = STANDARD
        .decode(p["next"]["groupId"].as_str().unwrap())
        .unwrap();

    // 3. INJECT FAULT: Publication succeeds, but host projection write fails!
    world.client("Alice").storage.fail_next_ensure_conversation_exists();

    let crash_result = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await;

    // Must fail on the injected storage call
    assert!(
        matches!(&crash_result, Err(OrchestratorError::Storage(msg)) if msg.contains("ensure_conversation_exists")),
        "Expected storage failure during host projection write: {crash_result:?}"
    );

    // 4. Verify post-crash state before reopen:
    // - Native crypto adoption succeeded: group exists in MLS context at epoch 1
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        1,
        "Native group must be adopted at epoch 1 before host projection"
    );

    // - Host storage has NOT completed conversation projection
    assert!(
        world
            .client("Alice")
            .storage
            .get_conversation("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", &cid)
            .await
            .unwrap()
            .is_none(),
        "Host conversation must be absent when host write fails"
    );

    // - First message in host storage is 0
    assert_eq!(
        world.client("Alice").storage.get_conversation_messages(&cid).len(),
        0,
        "No messages should be in host storage yet"
    );

    // 5. REOPEN: Restart Alice
    world.restart_client("Alice").await;

    // - Native ratchet never rolled back: epoch remains 1
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        1,
        "Native ratchet must never roll back across reopen"
    );

    // - Host storage still absent before resume
    assert!(
        world
            .client("Alice")
            .storage
            .get_conversation("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", &cid)
            .await
            .unwrap()
            .is_none(),
        "Host conversation remains absent until resume replays projection"
    );

    // 6. REPLAY PROJECTION:
    let ds_requests_before = world.delivery_service().submitted_prepared_requests().len();

    let sent = world
        .client("Alice")
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();

    assert!(
        matches!(&sent, DirectRequestOutcome::RequestSent { conversation_id, message_id, .. } if conversation_id == &cid && message_id == &first_msg_id),
        "Replay must succeed with RequestSent, matching conversation_id and first_message_id: {sent:?}"
    );

    // - Replay must NOT issue any new delivery service requests (replays projection only!)
    let ds_requests_after = world.delivery_service().submitted_prepared_requests().len();
    assert_eq!(
        ds_requests_before, ds_requests_after,
        "Reopen must replay projection only; zero delivery service requests sent"
    );

    // - Host storage now has conversation projected
    assert!(
        world
            .client("Alice")
            .storage
            .get_conversation("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", &cid)
            .await
            .unwrap()
            .is_some(),
        "Host storage must now contain the projected conversation"
    );

    // - Native ratchet never rolled back (still epoch 1)
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        1,
        "Native ratchet must remain at epoch 1 (never roll back or advance)"
    );

    // - First-message count stays one in preview and projection
    let preview = world
        .client("Alice")
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    assert_eq!(preview.consent, RequestConsent::OutgoingPending);
    assert_eq!(preview.first_message_id, Some(first_msg_id.clone()));
    assert_eq!(preview.crypto, RequestCrypto::Ready);

    // 7. RECIPIENT PROJECTION CRASH RECOVERY:
    // Bob receives the published direct request entries and outcome receipt.
    let publication_entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": cid,
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

    // Inject host write failure on Bob during Welcome import projection
    world.client("Bob").storage.fail_next_ensure_conversation_exists();

    let bob_crash = world.client("Bob").orchestrator.refresh_request_preview(&cid).await;
    assert!(
        matches!(&bob_crash, Err(OrchestratorError::Storage(msg)) if msg.contains("ensure_conversation_exists")),
        "Expected storage failure on Bob during host projection write: {bob_crash:?}"
    );

    // Bob's native MLS context has already imported the group at epoch 1
    assert_eq!(
        world.client("Bob").orchestrator.mls_context().get_epoch(gid.clone()).unwrap(),
        1,
        "Bob's native group must be imported at epoch 1 before host write"
    );

    // Reopen Bob
    world.restart_client("Bob").await;

    // Bob's native ratchet never rolled back
    assert_eq!(
        world.client("Bob").orchestrator.mls_context().get_epoch(gid.clone()).unwrap(),
        1,
        "Bob's native ratchet must stay at epoch 1 across reopen"
    );

    // Replay projection on Bob
    let bob_preview = world.client("Bob").orchestrator.refresh_request_preview(&cid).await.unwrap();
    assert_eq!(bob_preview.consent, RequestConsent::IncomingPending);
    assert_eq!(bob_preview.crypto, RequestCrypto::Ready);
    assert_eq!(bob_preview.first_message_id, Some(first_msg_id.clone()));
    assert_eq!(
        bob_preview.preview,
        Some(RequestPreview::Ready {
            text: input.text.clone(),
            invitation: None,
        })
    );

    // Bob's host storage now has conversation projected
    assert!(
        world
            .client("Bob")
            .storage
            .get_conversation("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", &cid)
            .await
            .unwrap()
            .is_some(),
        "Bob's host storage must contain the conversation after projection replay"
    );
}
