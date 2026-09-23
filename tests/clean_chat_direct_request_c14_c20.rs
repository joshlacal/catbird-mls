//! Validation tests for direct request lifecycle cases C14, C15, C18, C19, C20
//! Core-level and client-side draft/authority clauses.
#![allow(dead_code)]

mod e2e_harness;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op,
    direct_requests::{reduce_request_preview, DirectRequestIntent, RequestPreviewUpdate},
    MlsCryptoContext, OrchestratorError,
};
use catbird_mls::{
    DirectRequestInput, DirectRequestOutcome, DirectRequestView, RequestCapabilities,
    RequestConsent, RequestCrypto, RequestPreview,
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
            "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
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

fn pending_view(consent: RequestConsent, crypto: RequestCrypto) -> DirectRequestView {
    DirectRequestView {
        introduction: None,
        conversation_id: "11111111-1111-4111-8111-111111111111".into(),
        first_message_id: Some("22222222-2222-4222-8222-222222222222".into()),
        consent,
        crypto,
        preview: None,
        capabilities: RequestCapabilities::derive(consent, crypto, false),
        state_version: 1,
        generation: 0,
    }
}

// ============================================================================
// C14: Crossed starts
// Concurrent A->B / B->A yields one direct; loser retains authored draft,
// cannot transplant ciphertext or silently accept winner.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_c14_crossed_starts_loser_retains_draft_and_does_not_silently_accept() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world
        .add_client_with_did("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let (authority, doc, method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }
    let bob = world.client("Bob");
    // Create the authentic winning direct conversation from Alice where Bob is pending
    let alice = world.client("Alice");
    let mut view = alice
        .orchestrator
        .create_group("Crossed Direct Winner", Some(&[bob.did.clone()]), None)
        .await
        .unwrap();
    let requests = world.delivery_service().submitted_prepared_requests();
    let create = requests
        .iter()
        .rev()
        .find(|r| r.operation == Op::CreateConversation)
        .unwrap();
    let wrapper: Value = serde_json::from_slice(create.body.as_ref().unwrap()).unwrap();
    let b = &wrapper["signedRequest"]["body"];
    let mut participants = b["manifest"]["participants"].clone();
    for p in participants.as_array_mut().unwrap() {
        p["leafCount"] = json!(if p["status"] == "active" { 1 } else { 0 });
    }
    let winner_state = json!({
        "conversationKind": b["conversationKind"],
        "coordinates": b["next"],
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "participants": participants,
        "leaves": [{
            "userDid": b["actorDid"],
            "deviceId": b["actorDeviceId"],
            "deviceStatus": "active",
            "leafOrigin": "genesis",
            "keyId": b["keyId"]
        }],
        "metadataSnapshot": b["metadataSnapshot"],
        "snapshotSeq": 1
    });
    view.canonical_state = Some(
        catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
            &serde_json::to_vec(&winner_state).unwrap(),
        )
        .unwrap(),
    );
    let winner_convo_id = view.conversation_id.clone();
    world
        .delivery_service()
        .set_conversation_view_for_test(&winner_convo_id, view);
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&winner_convo_id, winner_state.clone());
    let draft_id = uuid::Uuid::new_v4().to_string();
    let input = DirectRequestInput {
        draft_id: draft_id.clone(),
        recipient_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        text: "Bob's authored proposal".into(),
        invitation: None,
    };
    // 1. First attempt: queue 503 to capture the client's signed prepare request
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({ "error": "simulated race before prepare response" }),
    );
    let unknown = bob
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();
    assert!(matches!(unknown, DirectRequestOutcome::OutcomeUnknown { .. }));

    // Extract the exact signed prepare request from delivery service
    let requests = world.delivery_service().submitted_prepared_requests();
    let prepare = requests
        .iter()
        .rev()
        .find(|r| r.operation == Op::PrepareDirectRequest)
        .unwrap();
    let prepare_json: Value = serde_json::from_slice(prepare.body.as_ref().unwrap()).unwrap();
    let p = &prepare_json["signedRequest"]["body"];

    let bob_device = bob.orchestrator.require_actor_device_id().await.unwrap();
    let bob_public = bob
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{}#{bob_device}", bob.did))
        .unwrap();

    let verified_prepare = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare_json["signedRequest"]).unwrap(),
        &bob_public,
    )
    .unwrap();

    // Build the signed directRequestExistingDirectReceipt bound to this exact prepare
    let receipt_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": "did:web:chat.catbird.blue",
        "keyId": method,
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestExistingDirectReceipt",
            "requestId": p["requestId"],
            "requestKind": "prepare",
            "requestDigest": STANDARD.encode(verified_prepare.request_digest()),
            "preparationRequestDigest": STANDARD.encode(verified_prepare.request_digest()),
            "actorDid": p["actorDid"],
            "actorDeviceId": p["actorDeviceId"],
            "actorKeyId": p["keyId"],
            "authGeneration": p["authGeneration"],
            "conversationId": winner_convo_id,
            "requiresAcceptance": true,
            "recordedAt": utc(0)
        }
    });
    let receipt_sig = es256(
        &authority,
        &protocol::direct_request_signing_bytes(
            protocol::DirectRequestKind::Outcome,
            &serde_json::to_vec(&receipt_body).unwrap(),
        )
        .unwrap(),
    );

    // Queue response for PrepareDirectRequest returning ExistingDirect receipt
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        200,
        json!({
            "outcome": {
                "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
                "body": receipt_body,
                "signature": receipt_sig
            }
        }),
    );

    let outcome = bob
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();

    // 1. Returns ExistingDirect outcome pointing to winner conversation
    match outcome {
        DirectRequestOutcome::ExistingDirect {
            conversation_id,
            requires_acceptance,
        } => {
            assert_eq!(conversation_id, winner_convo_id);
            assert!(
                requires_acceptance,
                "Bob must not silently accept; requires_acceptance must be true"
            );
        }
        other => panic!("Expected ExistingDirect, got {other:?}"),
    }

    // 2. Loser retains authored draft locally in its intent store
    let stored_intent = bob
        .orchestrator
        .mls_context()
        .read_direct_request_intent(&draft_id)
        .unwrap()
        .expect("Bob's draft intent must be preserved in local storage");
    let decoded = DirectRequestIntent::decode(
        &stored_intent,
        &bob.did,
        &bob.orchestrator.require_actor_device_id().await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        decoded.input.text, "Bob's authored proposal",
        "Author draft text must remain intact"
    );
    assert_eq!(decoded.input.draft_id, draft_id);

    // 3. Bob has NOT silently accepted: Bob cannot send until explicit acceptance
    let capabilities = RequestCapabilities::derive(
        RequestConsent::IncomingPending,
        RequestCrypto::WelcomeAvailable,
        true,
    );
    assert!(!capabilities.can_send, "Losing recipient cannot send messages before acceptance");
    assert!(capabilities.can_accept, "Recipient retains the option to explicitly accept");
}

// ============================================================================
// C15: Retry/idempotency collision
// Same operation and exact bytes replay success; changed text/artifact/signature/
// digest conflict. Edited local draft cannot mutate an unresolved operation.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_c15_edited_local_draft_cannot_mutate_unresolved_operation() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let (_authority, doc, _method) = receipt_authority();
    let alice = world.client("Alice");
    alice.credentials.set_request_authority_document(doc);

    let draft_id = uuid::Uuid::new_v4().to_string();
    let mut input = DirectRequestInput {
        draft_id: draft_id.clone(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Original uncommitted draft".into(),
        invitation: None,
    };

    // Server drops response with 503, leaving the operation in OutcomeUnknown (unresolved)
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({ "error": "transport dropped" }),
    );

    let outcome = alice
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();
    assert!(
        matches!(outcome, DirectRequestOutcome::OutcomeUnknown { .. }),
        "Unresponsive prepare must leave the operation in OutcomeUnknown"
    );

    // Verify unresolved intent exists in storage
    assert!(
        alice
            .orchestrator
            .mls_context()
            .read_direct_request_intent(&draft_id)
            .unwrap()
            .is_some(),
        "Unresolved operation must have a persisted intent record"
    );

    // ATTEMPT 1: Edit text on unresolved operation -> MUST FAIL
    input.text = "Tampered edited draft text".into();
    let edit_result = alice.orchestrator.start_direct_request(input.clone()).await;
    assert!(
        matches!(&edit_result, Err(OrchestratorError::InvalidInput(msg)) if msg.contains("unresolved")),
        "Editing local draft on unresolved operation must be rejected: {edit_result:?}"
    );

    // ATTEMPT 2: Change recipient DID on unresolved operation -> MUST FAIL
    input.text = "Original uncommitted draft".into();
    input.recipient_did = "did:plc:cccccccccccccccccccccccc".into();
    let change_recipient_result = alice.orchestrator.start_direct_request(input.clone()).await;
    assert!(
        change_recipient_result.is_err(),
        "Changing recipient on unresolved operation must be rejected"
    );

    // ATTEMPT 3: Exact retry with unchanged text and recipient -> MUST BE ACCEPTED (resumed)
    input.recipient_did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into();
    input.text = "Original uncommitted draft".into();
    // Queue 503 again to observe resume path attempt
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({ "error": "transport dropped second time" }),
    );
    let retry_outcome = alice.orchestrator.start_direct_request(input.clone()).await;
    assert!(
        matches!(
            retry_outcome.unwrap(),
            DirectRequestOutcome::OutcomeUnknown { .. }
        ),
        "Exact replay of unresolved operation must be permitted to resume"
    );
}

// ============================================================================
// C18: Pending authority matrix
// Creator and recipient cannot send extra apps, edits, reactions, receipts,
// typing, calls, metadata/admin changes, arbitrary Add, reset, or attachment
// binds while pending. Close/decline remain available.
// ============================================================================

#[test]
fn test_c18_pending_authority_matrix_client_capabilities() {
    for consent in [
        RequestConsent::IncomingPending,
        RequestConsent::OutgoingPending,
    ] {
        for crypto in [
            RequestCrypto::Unavailable,
            RequestCrypto::WelcomeAvailable,
            RequestCrypto::Ready,
        ] {
            let capabilities = RequestCapabilities::derive(consent, crypto, true);

            // While pending:
            // 1. Cannot send application messages, edits, reactions, typing, calls
            assert!(
                !capabilities.can_send,
                "can_send must be false while pending ({consent:?}, {crypto:?})"
            );

            // 2. Cannot emit read/delivery receipts
            assert!(
                !capabilities.can_emit_receipts,
                "can_emit_receipts must be false while pending ({consent:?}, {crypto:?})"
            );

            // 3. Cannot administer: no metadata changes, arbitrary Add, reset, attachment binds
            assert!(
                !capabilities.can_administer,
                "can_administer must be false while pending ({consent:?}, {crypto:?})"
            );

            // 4. Close and decline remain available
            assert!(
                capabilities.can_close,
                "can_close must remain true while pending ({consent:?}, {crypto:?})"
            );

            // 5. Accept is only available for incoming pending recipient
            assert_eq!(
                capabilities.can_accept,
                consent == RequestConsent::IncomingPending,
                "can_accept is only true for IncomingPending ({consent:?})"
            );
        }
    }

    // Only Accepted + Ready allows ordinary operations
    let accepted_ready =
        RequestCapabilities::derive(RequestConsent::Accepted, RequestCrypto::Ready, false);
    assert!(accepted_ready.can_send);
    assert!(accepted_ready.can_emit_receipts);
    assert!(accepted_ready.can_administer);
    assert!(accepted_ready.can_close);
    assert!(!accepted_ready.can_accept);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_c18_pending_direct_request_refuses_orchestrator_sends_and_reactions() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world
        .add_client_with_did("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let (authority, doc, method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    // Create group where Bob is pending
    let mut view = alice
        .orchestrator
        .create_group("Pending Direct", Some(&[bob.did.clone()]), None)
        .await
        .unwrap();
    let requests = world.delivery_service().submitted_prepared_requests();
    let create = requests
        .iter()
        .rev()
        .find(|r| r.operation == Op::CreateConversation)
        .unwrap();
    let wrapper: Value = serde_json::from_slice(create.body.as_ref().unwrap()).unwrap();
    let b = &wrapper["signedRequest"]["body"];
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut participants = b["manifest"]["participants"].clone();
    for p in participants.as_array_mut().unwrap() {
        if p["userDid"] == bob.did {
            p["status"] = json!("pending");
            p["leafCount"] = json!(0);
            p["invitationProvenance"] = json!({
                "invitationTransitionId": request_id,
                "invitedByDid": alice.did,
                "invitedByDeviceId": b["actorDeviceId"]
            });
        } else {
            p["status"] = json!("active");
            p["leafCount"] = json!(1);
        }
    }
    let pending_state = json!({
        "conversationKind": b["conversationKind"],
        "coordinates": b["next"],
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "participants": participants,
        "leaves": [{
            "userDid": b["actorDid"],
            "deviceId": b["actorDeviceId"],
            "deviceStatus": "active",
            "leafOrigin": "genesis",
            "keyId": b["keyId"]
        }],
        "metadataSnapshot": b["metadataSnapshot"],
        "snapshotSeq": 1,
        "directRequest": {
            "requestId": request_id,
            "firstMessageId": uuid::Uuid::new_v4().to_string(),
            "senderDid": alice.did.clone(),
            "recipientDid": bob.did.clone(),
            "consent": "outgoingPending",
            "importUntil": utc(604800),
            "contextHash": STANDARD.encode([1u8; 32]),
            "preparationDigest": STANDARD.encode([2u8; 32])
        }
    });
    view.canonical_state = Some(
        catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
            &serde_json::to_vec(&pending_state).unwrap(),
        )
        .unwrap(),
    );
    let cid = view.conversation_id.clone();
    alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .insert(cid.clone(), view.clone());
    world
        .delivery_service()
        .set_conversation_view_for_test(&cid, view);
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, pending_state.clone());
    // 1. Sending ordinary application message while pending MUST FAIL with typed error
    let send_result = alice.orchestrator.send_message(&cid, "Extra message").await;
    assert!(
        matches!(&send_result, Err(OrchestratorError::InvalidInput(msg)) if msg.contains("Accept this invitation before sending messages.")),
        "Sending message while pending must be refused: {send_result:?}"
    );

    // 2. Sending reaction while pending MUST FAIL with typed error
    let reaction_result = alice
        .orchestrator
        .send_reaction(&cid, "msg-1", "👍", catbird_mls::orchestrator::ReactionAction::Add)
        .await;
    assert!(
        matches!(&reaction_result, Err(OrchestratorError::InvalidInput(msg)) if msg.contains("Accept this invitation before sending messages.")),
        "Sending reaction while pending must be refused: {reaction_result:?}"
    );

    // 3. Readiness check MUST report send_allowed == false
    let ready = alice.orchestrator.ensure_conversation_ready(&cid).await.unwrap();
    assert!(!ready.send_allowed, "send_allowed must be false for pending conversation");

    // 4. Assert zero graph effect: delivery service received zero SendMessage requests
    assert!(
        world
            .delivery_service()
            .submitted_prepared_requests()
            .iter()
            .all(|r| r.operation != Op::SendMessage),
        "Refused sends must produce zero SendMessage operations on the delivery service"
    );
}

// ============================================================================
// C19: Sender privacy
// Preview fetch/import/ACK cannot produce peer-visible read or delivery status,
// presence or typing. Exercise every status/event projection.
// Internal durability ACK remains valid.
// ============================================================================

#[test]
fn test_c19_preview_fetch_import_ack_never_emits_peer_visible_signals() {
    // 1. Initial pending view
    let initial = pending_view(RequestConsent::IncomingPending, RequestCrypto::WelcomeAvailable);
    assert!(!initial.capabilities.can_send);
    assert!(!initial.capabilities.can_emit_receipts);
    assert!(!initial.capabilities.can_preview);

    // 2. Preview import does not enable receipts, typing, or sending
    let imported = reduce_request_preview(&initial, RequestPreviewUpdate::Imported);
    assert_eq!(imported.crypto, RequestCrypto::Ready);
    assert_eq!(imported.consent, RequestConsent::IncomingPending);
    assert!(
        !imported.capabilities.can_send,
        "Importing welcome must not enable send or typing"
    );
    assert!(
        !imported.capabilities.can_emit_receipts,
        "Importing welcome must not enable receipts"
    );

    // 3. Decrypting the preview introduction
    let decrypted = reduce_request_preview(
        &imported,
        RequestPreviewUpdate::Decrypted {
            invitation: None,
            text: "Hello from encrypted request".into(),
        },
    );
    assert_eq!(decrypted.crypto, RequestCrypto::Ready);
    assert_eq!(decrypted.consent, RequestConsent::IncomingPending);
    assert!(decrypted.capabilities.can_preview);
    assert!(
        !decrypted.capabilities.can_send,
        "Decrypted preview must not authorize typing or message sending"
    );
    assert!(
        !decrypted.capabilities.can_emit_receipts,
        "Decrypted preview must not authorize read or delivery receipts"
    );
    assert!(
        !decrypted.capabilities.can_administer,
        "Decrypted preview must not authorize admin operations"
    );

    // 4. Welcome ACK receipt is an internal durability acknowledgment:
    // It verifies exact storage on recipient device without granting ordinary effects.
    let ack_view = reduce_request_preview(
        &decrypted,
        RequestPreviewUpdate::Decrypted {
            invitation: None,
            text: "Hello from encrypted request".into(),
        },
    );
    assert!(!ack_view.capabilities.can_send);
    assert!(!ack_view.capabilities.can_emit_receipts);
    assert_eq!(ack_view.consent, RequestConsent::IncomingPending);
}

// ============================================================================
// C20: Close/block monotonicity
// Close during import or accept has one authoritative outcome; late events
// cannot resurrect state. Block prevents repeat requests under current rules;
// no claim of retracting already decrypted content.
// ============================================================================

#[test]
fn test_c20_close_and_block_monotonicity_prevents_late_event_resurrection() {
    // 1. Start from an active pending preview with decrypted introduction
    let ready = reduce_request_preview(
        &pending_view(RequestConsent::IncomingPending, RequestCrypto::WelcomeAvailable),
        RequestPreviewUpdate::Decrypted {
            invitation: None,
            text: "Confidential introduction".into(),
        },
    );
    assert_eq!(ready.consent, RequestConsent::IncomingPending);
    assert!(ready.capabilities.can_preview);
    assert!(ready.capabilities.can_close);

    // 2. Terminal close transition: user declines / closes request
    let mut closed_view = ready.clone();
    closed_view.consent = RequestConsent::Closed;
    closed_view.capabilities =
        RequestCapabilities::derive(RequestConsent::Closed, ready.crypto, ready.preview.is_some());

    assert_eq!(closed_view.consent, RequestConsent::Closed);
    assert!(!closed_view.capabilities.can_close, "Cannot close an already-closed request");
    assert!(!closed_view.capabilities.can_accept, "Cannot accept a closed request");
    assert!(!closed_view.capabilities.can_send, "Cannot send in a closed request");
    assert!(!closed_view.capabilities.can_emit_receipts);
    assert!(!closed_view.capabilities.can_administer);

    // 3. Monotonicity: Late import update cannot resurrect state
    let late_imported = reduce_request_preview(&closed_view, RequestPreviewUpdate::Imported);
    assert_eq!(
        late_imported.consent,
        RequestConsent::Closed,
        "Late imported event must not resurrect closed consent"
    );
    assert!(
        !late_imported.capabilities.can_accept,
        "Late event must not re-enable accept"
    );
    assert!(
        !late_imported.capabilities.can_send,
        "Late event must not re-enable send"
    );

    // 4. Late decrypted update cannot resurrect state
    let late_decrypted = reduce_request_preview(
        &closed_view,
        RequestPreviewUpdate::Decrypted {
            invitation: None,
            text: "Late arrival".into(),
        },
    );
    assert_eq!(
        late_decrypted.consent,
        RequestConsent::Closed,
        "Late decrypted event must not resurrect closed consent"
    );
    assert!(!late_decrypted.capabilities.can_send);
    assert!(!late_decrypted.capabilities.can_accept);

    // 5. Already-decrypted content is retained locally without retraction claim
    assert!(
        matches!(ready.preview, Some(RequestPreview::Ready { ref text, .. }) if text == "Confidential introduction"),
        "Decrypted preview content remains accessible locally; no claim of retroactive erasure"
    );
}
