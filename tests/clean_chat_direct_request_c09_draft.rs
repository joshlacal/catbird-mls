//! C09: when the delivery service finds no eligible recipient device, the real
//! native orchestrator keeps the authored draft and emits no invitation.
//!
//! The rejected receipt has exactly the field set the live shipping router
//! returns for `RecipientKeysUnavailable` (see e2e `encrypted_request_c08_c09`)
//! and is signed by the same fixture receipt authority key.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::direct_requests::DirectRequestIntent;
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op, CredentialStore, MlsCryptoContext,
};
use catbird_mls::{DirectRequestInput, DirectRequestOutcome};
use e2e_harness::TestWorld;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};

fn receipt_authority() -> (p256::ecdsa::SigningKey, Vec<u8>, String) {
    let key = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(true);
    let id = protocol::direct_request_receipt_key_id(point.as_bytes()).unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(point.as_bytes());
    let doc = serde_json::to_vec(&json!({"id":"did:web:chat.catbird.blue","verificationMethod":[{
        "id":id,"controller":"did:web:chat.catbird.blue","type":"Multikey",
        "publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)}]}))
    .unwrap();
    (key, doc, id)
}

fn last_prepare(world: &TestWorld) -> Value {
    let requests = world.delivery_service().submitted_prepared_requests();
    let request = requests
        .iter()
        .rev()
        .find(|r| r.operation == Op::PrepareDirectRequest)
        .expect("prepare submitted");
    serde_json::from_slice(request.body.as_ref().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_no_eligible_recipient_retains_draft_and_emits_no_invitation() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let (authority, doc, method) = receipt_authority();
    let alice = world.client("Alice");
    alice.credentials.set_request_authority_document(doc);
    let draft_text = "Draft kept when no recipient device is eligible";
    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: draft_text.into(),
        invitation: None,
    };

    // First delivery is lost so the exact persisted prepare can be bound by the
    // server receipt; the resume retries those exact bytes.
    world
        .delivery_service()
        .queue_request_operation_response(Op::PrepareDirectRequest, 503, json!({"error":"lost"}));
    assert!(matches!(
        alice.orchestrator.start_direct_request(input.clone()).await.unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));
    let prepare = last_prepare(&world);
    let device = alice.credentials.get_device_uuid(&alice.did).await.unwrap().unwrap();
    let public = alice
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{}#{device}", alice.did))
        .unwrap();
    let verified = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare["signedRequest"]).unwrap(),
        &public,
    )
    .unwrap();
    let p = verified.body();
    let digest = STANDARD.encode(verified.request_digest());
    let body = json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\0","protocolVersion":"2",
        "authorityDid":"did:web:chat.catbird.blue","keyId":method,
        "receipt":{"$type":"blue.catbird.chat.defs#directRequestRejectedReceipt",
            "requestId":p["requestId"],"requestDigest":digest,"preparationRequestDigest":digest,
            "actorDid":p["actorDid"],"actorDeviceId":p["actorDeviceId"],"actorKeyId":p["keyId"],
            "authGeneration":p["authGeneration"],"requestKind":"prepare",
            "recordedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "code":"RecipientKeysUnavailable"}});
    let signature: p256::ecdsa::Signature = authority.sign(
        &protocol::direct_request_signing_bytes(
            protocol::DirectRequestKind::Outcome,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap(),
    );
    let signature = STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes());
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        200,
        json!({"outcome":{"$type":"blue.catbird.chat.defs#signedDirectRequestReceipt",
            "body":body,"signature":signature}}),
    );

    let outcome = alice
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    match outcome {
        DirectRequestOutcome::TerminalNotPublished { code, request_id } => {
            assert_eq!(code, "RecipientKeysUnavailable");
            assert_eq!(Value::String(request_id), p["requestId"]);
        }
        other => panic!("expected terminal not-published outcome, got {other:?}"),
    }
    assert_eq!(prepare, last_prepare(&world), "resume retried the exact prepare");

    // No invitation: nothing was published, no bootstrap crypto/Welcome was
    // built, and no local request projection (conversation) exists.
    let requests = world.delivery_service().submitted_prepared_requests();
    assert!(requests.iter().all(|r| r.operation != Op::PublishDirectRequest));
    let context = alice.orchestrator.mls_context();
    assert!(context.list_direct_request_journal().unwrap().is_empty());
    assert!(context.list_direct_request_projections().unwrap().is_empty());

    // The authored draft is retained in durable core storage with its terminal proof.
    let raw = context.read_direct_request_intent(&input.draft_id).unwrap().unwrap();
    let intent = DirectRequestIntent::decode(&raw, &alice.did, &device).unwrap();
    assert_eq!(intent.input.text, draft_text);
    assert_eq!(intent.input.recipient_did, input.recipient_did);
    assert!(intent.terminal_response.is_some());
    assert!(!intent.publication_attempted);
    println!("C09 core: RecipientKeysUnavailable -> TerminalNotPublished; no publish RPC, empty journal/projections; draft retained with text");

    // Survives process restart byte-for-byte and stays reusable: sending again
    // from the same draft starts a fresh attempt instead of losing the text.
    world.restart_client("Alice").await;
    let alice = world.client("Alice");
    let context = alice.orchestrator.mls_context();
    assert_eq!(
        context.read_direct_request_intent(&input.draft_id).unwrap().unwrap(),
        raw
    );
    // Identical input replays the retained terminal proof without a new RPC.
    let submitted = world.delivery_service().submitted_prepared_requests().len();
    assert!(matches!(
        alice.orchestrator.start_direct_request(input.clone()).await.unwrap(),
        DirectRequestOutcome::TerminalNotPublished { ref code, .. } if code == "RecipientKeysUnavailable"
    ));
    assert_eq!(world.delivery_service().submitted_prepared_requests().len(), submitted);
    // Sending the (edited) draft again opens a fresh attempt.
    let mut edited = input.clone();
    edited.text = format!("{draft_text} (retry)");
    world
        .delivery_service()
        .queue_request_operation_response(Op::PrepareDirectRequest, 503, json!({"error":"lost"}));
    assert!(matches!(
        alice.orchestrator.start_direct_request(edited.clone()).await.unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));
    let retry = last_prepare(&world);
    assert_ne!(retry["signedRequest"]["body"]["requestId"], p["requestId"]);
    let intent = DirectRequestIntent::decode(
        &context.read_direct_request_intent(&input.draft_id).unwrap().unwrap(),
        &alice.did,
        &device,
    )
    .unwrap();
    assert_eq!(intent.previous_attempts.len(), 1);
    assert_eq!(intent.input.text, edited.text);
    println!("C09 core: draft survives restart byte-identically; identical resend replays the terminal proof with no RPC; edited resend from the same draft opens a fresh attempt retaining the prior terminal attempt");
}
