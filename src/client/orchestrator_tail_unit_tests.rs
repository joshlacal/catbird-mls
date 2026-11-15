//! Fast deterministic `--lib` unit tests under `client::` covering orchestrator direct-request
//! commands/controls/projection/receive boundaries, group invitation references, and authorized
//! leaf recovery verification.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::chat_v2::transcript::direct_request as protocol;
use crate::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
};
use crate::orchestrator::canonical_transport::{CanonicalOperation as Op, PreparedRequest};
use crate::orchestrator::direct_requests::test_exports::{
    normalize_acceptance_proof_with_i13, normalize_control_sequencer_receipt,
    verify_acceptance_proof_with_i13,
};
use crate::orchestrator::direct_requests::{normalized_close_entry, DirectRequestProjection};
use crate::orchestrator::{
    CredentialStore, IncomingEnvelope, MLSAPIClient, MlsCryptoContext,
};
use crate::recovery_e2e_harness::mock_api_client::direct_request_i13;
use crate::recovery_e2e_harness::TestWorld;
use crate::{
    DirectRequestInput, DirectRequestOutcome, RequestConsent, RequestCrypto, RequestPreview,
};

fn utc(delta: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(delta))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn es256(key: &p256::ecdsa::SigningKey, bytes: &[u8]) -> String {
    let sig: p256::ecdsa::Signature = key.sign(bytes);
    STANDARD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
}

fn receipt_authority() -> (p256::ecdsa::SigningKey, Vec<u8>, String) {
    let key = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(true);
    let id = protocol::direct_request_receipt_key_id(point.as_bytes()).unwrap();
    let doc = direct_request_i13::authority_document(&key, &id, "did:web:chat.catbird.blue");
    (key, doc, id)
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
async fn direct_request_commands_controls_projection_and_receive_unit_guards() {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let authority_did = "did:web:chat.catbird.blue";
    let (authority, doc, method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }

    // 1. Alice prepares + publishes a direct request to Bob.
    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: world.client("Bob").did.clone(),
        text: "Real encrypted request".into(),
        invitation: None,
    };
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error": "unavailable"}),
    );
    assert!(matches!(
        world
            .client("Alice")
            .orchestrator
            .start_direct_request(input.clone())
            .await
            .unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));

    let original = last_request(&world, Op::PrepareDirectRequest);
    let prepare = &original["signedRequest"]["body"];
    let alice_did = world.client("Alice").did.clone();
    let alice_device = world
        .client("Alice")
        .credentials
        .get_device_uuid(&alice_did)
        .await
        .unwrap()
        .unwrap();
    let alice_pubkey = world
        .client("Alice")
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{alice_did}#{alice_device}"))
        .unwrap();
    let verified_prepare = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&original["signedRequest"]).unwrap(),
        &alice_pubkey,
    )
    .unwrap();

    let bob_did = world.client("Bob").did.clone();
    let bob_device = world
        .client("Bob")
        .credentials
        .get_device_uuid(&bob_did)
        .await
        .unwrap()
        .unwrap();
    let bob_identity = format!("{bob_did}#{bob_device}");
    let package = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .create_key_package(bob_identity.as_bytes().to_vec())
        .unwrap();
    let bob_public = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .identity_public_key(bob_identity.clone())
        .unwrap();

    let grant_id = uuid::Uuid::new_v4().to_string();
    let grant = json!({
        "$type": "blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-GRANT\0",
        "protocolVersion": "2",
        "actorDid": bob_did,
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
    let grant_sig = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .sign_with_identity_key(
            bob_identity,
            protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Grant,
                &serde_json::to_vec(&grant).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let selected = json!({
        "actorDid": bob_did,
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
        "grant": { "body": grant, "signature": STANDARD.encode(grant_sig) },
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
        "minimumImportUntil": utc(7 * 86400 + 295),
        "preparationRequestDigest": STANDARD.encode(verified_prepare.request_digest()),
        "authorityDid": authority_did,
        "receiptKeyId": method,
    });
    let prep_signing =
        protocol::direct_request_preparation_signing_bytes(&serde_json::to_vec(&preparation).unwrap())
            .unwrap();
    preparation["preparationDigest"] = json!(STANDARD.encode(Sha256::digest(&prep_signing)));
    preparation["preparationSignature"] = json!(es256(&authority, &prep_signing));

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
    assert!(matches!(
        world
            .client("Alice")
            .orchestrator
            .resume_direct_request(&input.draft_id)
            .await
            .unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));

    let publication = last_request(&world, Op::PublishDirectRequest);
    let p = &publication["signedRequest"]["body"];
    let cid = p["conversationId"].as_str().unwrap().to_string();
    let verified_publish = protocol::verify_signed_request(
        protocol::DirectRequestKind::Publish,
        &serde_json::to_vec(&publication["signedRequest"]).unwrap(),
        &alice_pubkey,
    )
    .unwrap();
    let receipt_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": authority_did,
        "keyId": method,
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestPublishedReceipt",
            "requestId": p["requestId"],
            "requestKind": "publish",
            "requestDigest": STANDARD.encode(verified_publish.request_digest()),
            "preparationRequestDigest": STANDARD.encode(verified_prepare.request_digest()),
            "actorDid": p["actorDid"],
            "actorDeviceId": p["actorDeviceId"],
            "actorKeyId": p["keyId"],
            "authGeneration": p["authGeneration"],
            "conversationId": p["conversationId"],
            "firstMessageId": p["firstMessageId"],
            "coordinates": p["next"],
            "recordedAt": utc(0),
            "sequencerReceipt": direct_request_i13::receipt(&authority, p, 1, authority_did),
        }
    });
    let pub_receipt = json!({
        "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "signature": es256(
            &authority,
            &protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Outcome,
                &serde_json::to_vec(&receipt_body).unwrap(),
            )
            .unwrap(),
        ),
        "body": receipt_body,
    });
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        200,
        json!({ "outcome": pub_receipt }),
    );
    assert!(matches!(
        world
            .client("Alice")
            .orchestrator
            .resume_direct_request(&input.draft_id)
            .await
            .unwrap(),
        DirectRequestOutcome::RequestSent { .. }
    ));

    // 2. Bob previews the opening (`DirectRequestProjection::verify_proofs`) and consumes
    //    `directRequestEntry` via `consume_request_control`.
    world
        .client("Bob")
        .credentials
        .set_authorized_device_keys(&alice_did, vec![alice_pubkey.clone()]);
    world
        .client("Bob")
        .credentials
        .set_authorized_device_keys(&bob_did, vec![bob_public.clone()]);
    world
        .client("Alice")
        .credentials
        .set_authorized_device_keys(&alice_did, vec![alice_pubkey.clone()]);
    world
        .client("Alice")
        .credentials
        .set_authorized_device_keys(&bob_did, vec![bob_public.clone()]);

    let publication_entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": p["firstMessageId"],
        "conversationId": cid,
        "seq": 1,
        "signedRequest": publication["signedRequest"],
        "receivedAt": pub_receipt["body"]["receipt"]["recordedAt"],
        "sequencerReceipt": pub_receipt["body"]["receipt"]["sequencerReceipt"],
        "publicationReceipt": pub_receipt,
    });
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({ "entries": [publication_entry], "nextAfterSeq": 1, "hasMore": false }),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({ "error": "offline" }),
    );
    let bob_view = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    assert_eq!(bob_view.consent, RequestConsent::IncomingPending);
    assert_eq!(bob_view.crypto, RequestCrypto::Ready);
    assert_eq!(
        bob_view.preview,
        Some(RequestPreview::Ready {
            invitation: None,
            text: "Real encrypted request".into(),
        })
    );

    // `consume_request_control` on `directRequestEntry` stores `publication_entry` and returns `Ok(None)`.
    let pub_envelope = IncomingEnvelope::from_canonical_entry(&publication_entry, &cid)
        .unwrap()
        .unwrap();
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({ "error": "offline" }),
    );
    assert!(world
        .client("Bob")
        .orchestrator
        .consume_request_control(&pub_envelope)
        .await
        .unwrap()
        .is_none());
    let bob_raw_after_entry = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .read_direct_request_projection(&cid)
        .unwrap()
        .unwrap();
    let bob_proj_val: Value = serde_json::from_slice(&bob_raw_after_entry).unwrap();
    assert!(bob_proj_val["publication_entry"].is_object());

    // 3. `try_accept_direct_request`:
    //    - Missing conversation returns `Ok(None)`.
    //    - Rotate I13 receipt key `#mls-receipt-2` in Bob's & Alice's `credentials` authority doc
    //      while keeping `method` (the direct-request outcome/commit key) unchanged so ONLY the
    //      `decode_p256_sec1_from_did_doc` branch of `||` triggers authority-doc merge!
    assert!(world
        .client("Bob")
        .orchestrator
        .try_accept_direct_request("00000000-0000-4000-8000-000000000099")
        .await
        .unwrap()
        .is_none());

    let rotated_i13 = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let rotated_i13_kid = format!("{authority_did}#mls-receipt-2");
    let rotated_req_method = protocol::direct_request_receipt_key_id(
        rotated_i13.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let rotated_doc_only: Value = serde_json::from_slice(&direct_request_i13::authority_document(
        &rotated_i13,
        &rotated_req_method,
        authority_did,
    ))
    .unwrap();
    let mut merged_doc: Value = serde_json::from_slice(&doc).unwrap();
    let mut rotated_vm = rotated_doc_only["verificationMethod"][1].clone();
    rotated_vm["id"] = json!(rotated_i13_kid);
    merged_doc["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(rotated_vm);
    let merged_doc_bytes = serde_json::to_vec(&merged_doc).unwrap();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(merged_doc_bytes.clone());
    }

    world.delivery_service().queue_request_operation_response(
        Op::AcceptConversation,
        503,
        json!({ "error": "lost" }),
    );
    assert!(world
        .client("Bob")
        .orchestrator
        .try_accept_direct_request(&cid)
        .await
        .is_err());

    let pending_accept = last_request(&world, Op::AcceptConversation);
    let accepted = &pending_accept["directRequest"]["body"];
    let verified_accept = protocol::verify_signed_request(
        protocol::DirectRequestKind::Accept,
        &serde_json::to_vec(&pending_accept["directRequest"]).unwrap(),
        &bob_public,
    )
    .unwrap();
    let accept_entry = json!({
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": cid,
        "seq": 2,
        "signedRequest": pending_accept["directRequest"],
        "receivedAt": utc(0),
    });
    let acceptance_receipt = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceCommitReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPTANCE-COMMIT\0",
        "protocolVersion": "2",
        "authorityDid": authority_did,
        "keyId": method,
        "requestId": accepted["requestId"],
        "acceptanceDigest": STANDARD.encode(verified_accept.request_digest()),
        "entryHash": STANDARD.encode(
            protocol::direct_request_acceptance_entry_hash(&serde_json::to_vec(&accept_entry).unwrap()).unwrap()
        ),
        "prior": accepted["prior"],
        "next": accepted["next"],
        "recordedAt": utc(0),
    });
    let mut proof = json!({
        "entry": accept_entry,
        "receipt": {
            "body": acceptance_receipt,
            "signature": es256(
                &authority,
                &protocol::direct_request_signing_bytes(
                    protocol::DirectRequestKind::AcceptanceCommit,
                    &serde_json::to_vec(&acceptance_receipt).unwrap(),
                )
                .unwrap(),
            ),
        }
    });
    let accept_seq_receipt = direct_request_i13::control_receipt_at_with_key_id(
        &rotated_i13,
        accepted,
        &accepted["next"],
        proof["entry"]["entryId"].as_str().unwrap(),
        2,
        proof["entry"]["receivedAt"].as_str().unwrap(),
        *verified_accept.request_digest(),
        authority_did,
        &rotated_i13_kid,
    );
    proof["entry"]["sequencerReceipt"] = accept_seq_receipt.clone();

    // Direct unit checks on projection helpers (`normalize_*` and `verify_acceptance_proof_with_i13`).
    let mut ctrl_with_receipt = json!({ "sequencerReceipt": accept_seq_receipt });
    let norm_ctrl_receipt = normalize_control_sequencer_receipt(&mut ctrl_with_receipt).unwrap();
    assert_eq!(norm_ctrl_receipt["kid"], rotated_i13_kid);
    let (norm_legacy_proof, norm_seq_receipt) =
        normalize_acceptance_proof_with_i13(proof.clone()).unwrap();
    assert_eq!(norm_seq_receipt["kid"], rotated_i13_kid);
    assert_eq!(norm_legacy_proof["receipt"]["body"]["keyId"], method);
    let auth_key_bytes = protocol::resolve_direct_request_receipt_key_for_authority(
        authority_did,
        &merged_doc_bytes,
        &method,
    )
    .unwrap();
    let i13_key_bytes = crate::client::chat_wire::decode_p256_sec1_from_did_doc(
        &merged_doc_bytes,
        authority_did,
        &rotated_i13_kid,
    )
    .unwrap();
    let verified_proof_val = verify_acceptance_proof_with_i13(
        authority_did,
        &norm_legacy_proof,
        &norm_seq_receipt,
        &auth_key_bytes,
        &i13_key_bytes,
        &bob_public,
    )
    .unwrap();
    assert_eq!(
        verified_proof_val["entry"]["signedRequest"]["body"]["actorDid"],
        bob_did
    );

    world.delivery_service().queue_request_operation_response(
        Op::AcceptConversation,
        200,
        json!({
            "coordinates": accepted["next"],
            "acceptanceProof": proof,
        }),
    );
    let accept_out = world
        .client("Bob")
        .orchestrator
        .try_accept_direct_request(&cid)
        .await
        .unwrap()
        .expect("try_accept_direct_request must return Some(result)");
    assert_eq!(
        accept_out["coordinates"],
        crate::client::chat_wire::canonicalize_wire_coordinate(&accepted["next"], None).unwrap()
    );

    // Verify accepted projection view returns `RequestConsent::Accepted`.
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({ "error": "offline" }),
    );
    assert_eq!(
        world
            .client("Bob")
            .orchestrator
            .refresh_request_preview(&cid)
            .await
            .unwrap()
            .consent,
        RequestConsent::Accepted
    );

    // 4. Direct unit checks on `Alice.orchestrator.refresh_request_acceptance_for_test`:
    //    - Case A: `acceptanceProof` is `null` and coordinates differ -> returns `Ok(false)`.
    //    - Case B: `acceptanceProof` has valid proof signed under rotated `#mls-receipt-2` ->
    //      merges authority doc, updates projection, and returns `Ok(true)`.
    let state_accepted = json!({
        "conversationKind": "direct",
        "sequencerDid": authority_did,
        "coordinates": accepted["next"],
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "participants": [
            { "userDid": p["actorDid"], "role": "admin", "status": "active", "leafCount": 1 },
            {
                "userDid": p["recipientDid"],
                "role": "admin",
                "status": "active",
                "leafCount": 1,
                "invitationProvenance": {
                    "invitationTransitionId": p["requestId"],
                    "invitedByDid": p["actorDid"],
                    "invitedByDeviceId": p["actorDeviceId"],
                }
            }
        ],
        "leaves": [
            {
                "userDid": p["actorDid"],
                "deviceId": p["actorDeviceId"],
                "leafOrigin": "genesis",
                "keyId": p["keyId"],
                "deviceStatus": "active",
            },
            {
                "userDid": p["recipientDid"],
                "deviceId": bob_device,
                "leafOrigin": "keyPackage",
                "joinKeyPackageRef": STANDARD.encode(&package.hash_ref),
                "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
                "deviceStatus": "active",
            }
        ],
        "metadataSnapshot": p["artifacts"]["metadataSnapshot"],
        "snapshotSeq": 2,
        "directRequest": {
            "requestId": p["requestId"],
            "firstMessageId": p["firstMessageId"],
            "senderDid": p["actorDid"],
            "recipientDid": p["recipientDid"],
            "consent": "accepted",
            "importUntil": p["importUntil"],
            "contextHash": p["contextHash"],
            "preparationDigest": p["preparationDigest"],
            "acceptanceProof": proof,
        }
    });

    let mut alice_raw_opt = world
        .client("Alice")
        .orchestrator
        .mls_context()
        .read_direct_request_projection(&cid)
        .unwrap();
    let mut alice_proj: DirectRequestProjection =
        serde_json::from_slice(alice_raw_opt.as_ref().unwrap()).unwrap();
    assert!(alice_proj.acceptance_proof.is_none());

    let mut state_unaccepted = state_accepted.clone();
    state_unaccepted["directRequest"]
        .as_object_mut()
        .unwrap()
        .remove("acceptanceProof");
    state_unaccepted["directRequest"]["consent"] = json!("pending");
    state_unaccepted["coordinates"]["stateVersion"] = json!(99);
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({ "state": state_unaccepted }),
    );
    let refreshed_false = world
        .client("Alice")
        .orchestrator
        .refresh_request_acceptance_for_test(
            &cid,
            &alice_did,
            &alice_device,
            &mut alice_proj,
            &mut alice_raw_opt,
        )
        .await
        .unwrap();
    assert!(!refreshed_false);
    assert!(alice_proj.acceptance_proof.is_none());

    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({ "state": state_accepted.clone() }),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetDeviceKey,
        200,
        json!({
            "ownerDid": bob_did,
            "deviceId": bob_device,
            "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
            "signaturePublicKey": STANDARD.encode(&bob_public),
        }),
    );
    let refreshed_true = world
        .client("Alice")
        .orchestrator
        .refresh_request_acceptance_for_test(
            &cid,
            &alice_did,
            &alice_device,
            &mut alice_proj,
            &mut alice_raw_opt,
        )
        .await
        .unwrap();
    assert!(refreshed_true);
    assert!(alice_proj.acceptance_proof.is_some());

    // 5. `consume_request_control` on `directRequestAcceptanceEntry` materializes the encrypted
    //    introduction message (`Ok(Some(Message))`).
    let mut acceptance_entry = proof["entry"].clone();
    acceptance_entry["$type"] = json!("blue.catbird.chat.defs#directRequestAcceptanceEntry");
    let acceptance_env = IncomingEnvelope::from_canonical_entry(&acceptance_entry, &cid)
        .unwrap()
        .unwrap();
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({ "state": state_accepted.clone() }),
    );
    let intro_msg = world
        .client("Alice")
        .orchestrator
        .consume_request_control(&acceptance_env)
        .await
        .unwrap()
        .expect("consume_request_control must materialize introduction on acceptance entry");
    assert_eq!(intro_msg.text, "Real encrypted request");

    // 6. `normalized_close_entry` + `retain_verified_request_close` transition consent to `Closed`.
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({ "state": state_accepted }),
    );
    world.delivery_service().queue_request_operation_response(
        Op::CloseConversation,
        503,
        json!({ "error": "lost" }),
    );
    assert!(world
        .client("Alice")
        .orchestrator
        .close_direct_request(&cid)
        .await
        .is_err());
    let close_req = last_request(&world, Op::CloseConversation);
    let close_body = &close_req["signedRequest"]["body"];
    let tombstone = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseTombstone",
        "conversationId": cid,
        "conversationKind": "direct",
        "retired": close_body["retired"],
        "closedByDid": close_body["actorDid"],
        "closedByDeviceId": close_body["actorDeviceId"],
        "terminalSeq": 3,
        "closedAt": utc(0),
    });
    let close_strict = decode_strict_json(&serde_json::to_vec(close_body).unwrap()).unwrap();
    let close_transcript = SigningTranscript::build_for(
        SignedMutationKind::ConversationClose,
        &project_signed_body(SignedMutationKind::ConversationClose, &close_strict).unwrap(),
    )
    .unwrap();
    let mut close_entry = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": cid,
        "seq": 3,
        "signedRequest": close_req["signedRequest"],
        "receivedAt": tombstone["closedAt"],
        "tombstone": tombstone,
    });
    close_entry["sequencerReceipt"] = direct_request_i13::control_receipt_at_with_key_id(
        &rotated_i13,
        close_body,
        &close_body["retired"],
        close_entry["entryId"].as_str().unwrap(),
        3,
        close_entry["receivedAt"].as_str().unwrap(),
        *close_transcript.request_digest(),
        authority_did,
        &rotated_i13_kid,
    );
    let norm_close = normalized_close_entry(close_entry).unwrap();
    assert_eq!(
        norm_close["$type"],
        "blue.catbird.chat.defs#conversationCloseEntry"
    );

    world
        .client("Alice")
        .orchestrator
        .retain_verified_request_close(&cid, &norm_close, &alice_pubkey)
        .await
        .unwrap();
    let views = world
        .client("Alice")
        .orchestrator
        .list_direct_request_views()
        .await
        .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].consent, RequestConsent::Closed);
}

#[tokio::test(flavor = "multi_thread")]
async fn group_invitation_reference_returns_verified_policy_invitation() {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let (receipt_key, document, _) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(document.clone());
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let members = vec![bob_did.clone(), "did:plc:cccccccccccccccccccccccc".into()];
    let mut view = alice
        .orchestrator
        .create_group("Target Group", Some(&members), None)
        .await
        .unwrap();
    let wrapper = last_request(&world, Op::CreateConversation);
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
        .set_authorized_device_keys(&alice.did, vec![alice_pubkey]);

    let invitation_id = uuid::Uuid::new_v4().to_string();
    let mut group_state = prior_state.clone();
    group_state["coordinates"]["stateVersion"] = json!(3);
    group_state["snapshotSeq"] = json!(3);
    group_state["sequencerDid"] = json!("did:web:chat.catbird.blue");
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
            "userDid": bob_did,
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
    let entry_id = uuid::Uuid::new_v4().to_string();
    let received_at = utc(0);
    let invitation_entry = json!({
        "$type": "blue.catbird.chat.defs#policyEntry",
        "entryId": entry_id,
        "conversationId": cid,
        "seq": 3,
        "signedRequest": {
            "body": invitation_body,
            "signature": STANDARD.encode(signature),
        },
        "receivedAt": received_at,
        "sequencerReceipt": direct_request_i13::control_receipt(
            &receipt_key,
            &invitation_body,
            &entry_id,
            3,
            &received_at,
            *transcript.request_digest(),
            "did:web:chat.catbird.blue",
        ),
    });

    view.canonical_state = Some(
        crate::orchestrator::canonical_transport::decode_conversation_state(
            &serde_json::to_vec(&group_state).unwrap(),
        )
        .unwrap(),
    );
    world
        .delivery_service()
        .set_conversation_view_for_test(&cid, view);
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, group_state.clone());

    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({ "state": group_state }),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({ "entries": [invitation_entry], "hasMore": false, "nextAfterSeq": 3 }),
    );

    let link = world
        .client("Alice")
        .orchestrator
        .get_group_invitation_reference(&cid, &bob_did)
        .await
        .unwrap()
        .expect("get_group_invitation_reference must return Some");
    assert_eq!(link.invitation_transition_id, invitation_id);
    assert_eq!(link.recipient_did, bob_did);
}

#[tokio::test(flavor = "multi_thread")]
async fn authorized_leaf_recovery_verifies_entitlement_and_extracts_key_package() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let created = world
        .client("Alice")
        .orchestrator
        .create_group("recovery unit", None, None)
        .await
        .unwrap();
    let cid = created.conversation_id.clone();
    let did = world.client("Alice").did.clone();
    let alice_dev1 = world
        .client("Alice")
        .orchestrator
        .require_actor_device_id()
        .await
        .unwrap();
    let alice_dev1_pub = world
        .client("Alice")
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{did}#{alice_dev1}"))
        .unwrap();

    world.add_client_with_did("AliceDev2", &did).await;
    world.register_device("AliceDev2").await.unwrap();
    let dev2 = world.client("AliceDev2");
    dev2.orchestrator.accept_conversation(&cid).await.unwrap();
    let dev2_id = dev2.orchestrator.require_actor_device_id().await.unwrap();
    let dev2_pub = dev2
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{did}#{dev2_id}"))
        .unwrap();

    world
        .client("Alice")
        .credentials
        .set_authorized_device_keys(&did, vec![alice_dev1_pub, dev2_pub]);

    let resp = dev2
        .orchestrator
        .api_client()
        .submit_prepared_request(PreparedRequest {
            operation: Op::GetLeafRecoveryInbox,
            method: "GET".into(),
            path: format!(
                "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={dev2_id}&inventorySessionId=018f3f6a-7b2c-4d91-8a5e-0f123456789a&limit=100"
            ),
            body: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let page: Value = serde_json::from_slice(&resp.body).unwrap();
    let recovery = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["conversationId"] == cid)
        .unwrap()
        .clone();
    dev2.orchestrator
        .recovery_tracker()
        .lock()
        .await
        .note_leaf_recovery_requested_at(&cid, Instant::now() - Duration::from_secs(301));

    let state_resp = world
        .client("Alice")
        .orchestrator
        .api_client()
        .submit_prepared_request(PreparedRequest {
            operation: Op::GetConversationState,
            method: "GET".into(),
            path: format!(
                "/xrpc/blue.catbird.chat.getConversationState?actorDeviceId={alice_dev1}&conversationId={cid}"
            ),
            body: None,
        })
        .await
        .unwrap();
    assert_eq!(state_resp.status, 200);
    let state_json: Value = serde_json::from_slice(&state_resp.body).unwrap();
    let coord = &state_json["state"]["coordinates"];
    let entitled_leaves = vec![(did.clone(), alice_dev1.clone())];

    let (auth, kp_bytes, kp_ref) = world
        .client("Alice")
        .orchestrator
        .authorized_leaf_recovery_for_test(
            &recovery,
            coord,
            &cid,
            &entitled_leaves,
            &did,
            &alice_dev1,
        )
        .await
        .unwrap();
    assert_eq!(auth["requesterDid"], did);
    assert_eq!(auth["requesterDeviceId"], dev2_id);
    assert!(kp_bytes.len() > 64);
    assert!(kp_ref.len() >= 16);

    // Unentitled requester (empty leaves) MUST be rejected (`!entitled` guard).
    assert!(world
        .client("Alice")
        .orchestrator
        .authorized_leaf_recovery_for_test(&recovery, coord, &cid, &[], &did, &alice_dev1)
        .await
        .is_err());
}
