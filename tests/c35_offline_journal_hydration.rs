//! C35 Clause 4: Offline journal hydration and ownership protection
//!
//! Proves on native core via its real public API (catbird-mls integration test
//! using the real orchestrator + SQLite store):
//! 1. With a journal holding an unresolved outcome (published-unknown request send)
//!    and the network unavailable (delivery service dropping requests), the
//!    engine reaches Ready within a tight bound (< 500 ms).
//! 2. Ownership is protected: initializing a different DID against this journal/context
//!    is refused / fails closed, and attempting to mutate the unresolved draft is rejected.
//! 3. Outcome resolution runs only once the network returns.
//! 4. Counterfactuals: wrong/foreign DID fails closed; tampered draft fails closed;
//!    offline retry remains unresolved.

#![allow(dead_code)]

mod e2e_harness;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op,
    CredentialStore, MlsCryptoContext, MLSOrchestrator, OrchestratorConfig, OrchestratorError,
};
use catbird_mls::{DirectRequestInput, DirectRequestOutcome, MLSContext};
use e2e_harness::TestWorld;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};

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

fn last_prepare(world: &TestWorld) -> Value {
    let requests = world.delivery_service().submitted_prepared_requests();
    let req = requests
        .iter()
        .rev()
        .find(|r| r.operation == Op::PrepareDirectRequest)
        .expect("missing prepare request");
    serde_json::from_slice(req.body.as_ref().unwrap()).expect("invalid json prepare")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_c35_core_offline_journal_hydration_and_ownership_protection() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let (authority, doc, method) = receipt_authority();
    world
        .client("Alice")
        .credentials
        .set_request_authority_document(doc.clone());

    let alice = world.client("Alice");
    let alice_did = alice.did.clone();
    let db_path = alice._temp_dir.join("mls.db");
    let keychain = alice.keychain.clone();
    let draft_id = uuid::Uuid::new_v4().to_string();

    let input = DirectRequestInput {
        draft_id: draft_id.clone(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Original uncommitted draft for offline hydration test".into(),
        invitation: None,
    };

    // 1. Induce unresolved outcome: delivery service drops response with 503
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({ "error": "transport dropped" }),
    );

    let initial_outcome = alice
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();

    let request_id = match &initial_outcome {
        DirectRequestOutcome::OutcomeUnknown { request_id } => {
            println!("Initial attempt entered OutcomeUnknown: {}", request_id);
            request_id.clone()
        }
        other => panic!("expected OutcomeUnknown, got: {:?}", other),
    };

    // Verify unresolved intent exists in SQLite storage
    assert!(
        alice
            .orchestrator
            .mls_context()
            .read_direct_request_intent(&draft_id)
            .unwrap()
            .is_some(),
        "unresolved operation must have persisted intent in SQLite storage"
    );

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
    let p = verified.body().clone();
    let digest = STANDARD.encode(verified.request_digest());

    // 2. Network becomes unavailable: queue continuous 503s
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({ "error": "gateway unavailable / network offline" }),
    );

    let transport_count_before = world.delivery_service().submitted_prepared_requests().len();

    // 3. Reopen: close previous context and create fresh MLSContext + MLSOrchestrator on same SQLite DB
    alice
        .orchestrator
        .mls_context()
        .flush_and_prepare_close()
        .expect("flush before reopen");

    let reopened_context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        "test-key-Alice".to_string(),
        Box::new(keychain.clone()),
    )
    .expect("reopen MLSContext on SQLite store");

    let reopened_orch = MLSOrchestrator::new(
        reopened_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(&alice_did)),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );

    // Measure offline initialization latency to Ready
    let init_start = Instant::now();
    reopened_orch
        .initialize(&alice_did)
        .await
        .expect("offline initialization must succeed and reach Ready");
    let init_elapsed = init_start.elapsed();
    println!("Offline initialization to Ready took: {:?}", init_elapsed);

    // Must reach Ready well within bound (< 500ms)
    assert!(
        init_elapsed < Duration::from_millis(500),
        "offline initialization took too long: {:?}",
        init_elapsed
    );

    // Verify 0 network requests occurred during offline initialization
    let transport_count_after_init = world.delivery_service().submitted_prepared_requests().len();
    assert_eq!(
        transport_count_before, transport_count_after_init,
        "offline hydration must issue 0 network requests"
    );

    // 4. Ownership protection:
    // Counterfactual A: Attempting to initialize another DID on this journal fails closed
    let foreign_context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        "test-key-Alice".to_string(),
        Box::new(keychain.clone()),
    )
    .expect("open MLSContext for foreign DID check");

    let foreign_orch = MLSOrchestrator::new(
        foreign_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as("did:plc:mallory9999999999999999")),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );

    let foreign_init = foreign_orch
        .initialize("did:plc:mallory9999999999999999")
        .await;
    println!("Foreign DID initialization result: {:?}", foreign_init);
    assert!(
        foreign_init.is_err(),
        "initializing another DID on Alice's journal must fail closed"
    );

    // Counterfactual B: Mutating unresolved draft with different content is rejected
    let mut tampered_input = input.clone();
    tampered_input.text = "Tampered content that violates ownership".into();
    let tampered_result = reopened_orch.start_direct_request(tampered_input).await;
    println!("Tampered content send result: {:?}", tampered_result);
    assert!(
        matches!(&tampered_result, Err(OrchestratorError::InvalidInput(msg)) if msg.contains("unresolved")),
        "mutating draft text of owned unresolved operation must be rejected: {:?}",
        tampered_result
    );

    // Counterfactual C: While network remains offline, resume remains unresolved
    let offline_retry = reopened_orch
        .resume_direct_request(&draft_id)
        .await
        .unwrap();
    assert!(
        matches!(offline_retry, DirectRequestOutcome::OutcomeUnknown { .. }),
        "while network is offline, resume must stay in OutcomeUnknown"
    );

    // 5. Outcome resolution runs ONLY once the network returns
    // Build valid signed receipt for delivery service to return
    let receipt_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": "did:web:chat.catbird.blue",
        "keyId": method,
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestRejectedReceipt",
            "requestId": p["requestId"],
            "requestDigest": digest,
            "preparationRequestDigest": digest,
            "actorDid": p["actorDid"],
            "actorDeviceId": p["actorDeviceId"],
            "actorKeyId": p["keyId"],
            "authGeneration": p["authGeneration"],
            "requestKind": "prepare",
            "recordedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "code": "RecipientKeysUnavailable"
        }
    });
    let signature: p256::ecdsa::Signature = authority.sign(
        &protocol::direct_request_signing_bytes(
            protocol::DirectRequestKind::Outcome,
            &serde_json::to_vec(&receipt_body).unwrap(),
        )
        .unwrap(),
    );
    let signature_b64 = STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes());

    // Network returns: delivery service now responds with signed receipt
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        200,
        json!({
            "outcome": {
                "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
                "body": receipt_body,
                "signature": signature_b64
            }
        }),
    );

    let online_resolution = reopened_orch
        .resume_direct_request(&draft_id)
        .await
        .unwrap();
    println!("Online resolution result: {:?}", online_resolution);
    match online_resolution {
        DirectRequestOutcome::TerminalNotPublished { code, request_id: res_id } => {
            assert_eq!(code, "RecipientKeysUnavailable");
            assert_eq!(res_id, request_id);
        }
        other => panic!("expected TerminalNotPublished outcome, got: {:?}", other),
    }

    println!("C35 CORE OFFLINE HYDRATION: ALL ASSERTIONS AND COUNTERFACTUALS PASS");
}
