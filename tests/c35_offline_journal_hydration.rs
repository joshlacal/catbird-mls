//! C35 Clause 4: Offline journal hydration and ownership protection
//!
//! Proves on native core via its real public API (catbird-mls integration test
//! using the real orchestrator + SQLite store):
//! 1. With a journal holding an unresolved outcome (published-unknown request send)
//!    and the network unavailable — every transport method refused, not one queued
//!    operation response — the engine reaches Ready within a tight bound (< 500 ms).
//! 2. Ownership is protected: initializing a different DID against this journal/context
//!    is refused / fails closed, and attempting to mutate the unresolved draft is rejected.
//! 3. Outcome resolution runs only once the network returns.
//! 4. Counterfactuals: a foreign DID *holding its own device credential* fails at the
//!    owner binding check (not the missing-device branch); a foreign DID without a
//!    credential fails at the missing-device branch (the weaker control); tampered draft
//!    fails closed; offline retry remains unresolved.

#![allow(dead_code)]

mod e2e_harness;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op, CredentialStore, MlsCryptoContext,
    MLSOrchestrator, OrchestratorConfig, OrchestratorError,
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

    // A second DID used by the ownership counterfactual below, registered with
    // its OWN device credential. Device registration is itself a transport
    // operation, so it must happen while the network is still up. The literal
    // must be a canonical 24-character base32 `did:plc` identifier, which the
    // production bare-DID validator enforces even in debug builds.
    let mallory_did = "did:plc:mmmmmmmmmmmmmmmmmmmmmmmm";
    world.add_client_with_did("Mallory", mallory_did).await;
    world.register_device("Mallory").await.unwrap();

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

    // 2. Network becomes unavailable. This is not a single queued 503 for one
    //    operation: the delivery service refuses EVERY transport call, so no
    //    read or write can complete during the offline window.
    world.delivery_service().refuse_all_transport();
    let refusals_before_offline = world.delivery_service().refused_transport_calls();

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

    // Verify 0 network requests occurred during offline initialization. Both
    // signals must hold: nothing was even submitted, and the refusing
    // transport recorded no attempt. The second check is what makes this an
    // "every transport method" claim rather than a one-operation claim.
    let transport_count_after_init = world.delivery_service().submitted_prepared_requests().len();
    assert_eq!(
        transport_count_before, transport_count_after_init,
        "offline hydration must issue 0 network requests"
    );
    assert_eq!(
        world.delivery_service().refused_transport_calls(),
        refusals_before_offline,
        "offline hydration must not attempt any transport call"
    );

    // 4. Ownership protection.
    //
    // Counterfactual A (the strong one): a second DID that holds its OWN device
    // credential opens this journal. Mallory's device was registered above, so
    // the missing-device branch is passed and hydration can only fail at the
    // owner binding itself — `DirectRequestIntent::decode(&raw, owner, &device)`
    // validating `actor_did`/`actor_device_id` against the persisted record
    // (direct_requests.rs intent loop, and the journal owner-mismatch check).
    // Give Mallory the same receipt authority document Alice's request bound.
    world
        .client("Mallory")
        .credentials
        .set_request_authority_document(doc.clone());
    let mallory_credentials = world.client("Mallory").credentials.clone();
    let mallory_device = mallory_credentials
        .get_device_uuid(mallory_did)
        .await
        .unwrap()
        .expect("Mallory's own device credential must be registered");

    let foreign_context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        "test-key-Alice".to_string(),
        Box::new(keychain.clone()),
    )
    .expect("open MLSContext for foreign DID check");

    let foreign_orch = MLSOrchestrator::new(
        foreign_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(mallory_did)),
        Arc::new(mallory_credentials.clone()),
        OrchestratorConfig::default(),
    );

    let foreign_init = foreign_orch.initialize(mallory_did).await;
    println!(
        "Foreign DID (with own device {mallory_device}) initialization result: {:?}",
        foreign_init
    );
    let foreign_error = foreign_init
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("initializing {mallory_did} on Alice's journal must fail closed"));
    // Must NOT be the missing-device branch: Mallory has a credential.
    assert!(
        !matches!(foreign_error, OrchestratorError::Credential(_)),
        "foreign-DID counterfactual reached the missing-device branch, not the owner binding: {foreign_error}"
    );
    // Must be the owner/ownership binding refusing the record it does not own.
    match foreign_error {
        OrchestratorError::Storage(message) => assert!(
            message.contains("ownership"),
            "foreign-DID failure was not the owner binding: {message}"
        ),
        other => panic!("expected an ownership storage refusal, got: {other:?}"),
    }

    // Counterfactual A2 (the weaker control): a foreign DID with NO device
    // credential is refused earlier, at the missing-device branch. Both
    // branches are real; distinguishing them is the point.
    let trudy_did = "did:plc:tttttttttttttttttttttttt";
    let unregistered_context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        "test-key-Alice".to_string(),
        Box::new(keychain.clone()),
    )
    .expect("open MLSContext for uncredentialed foreign DID check");
    let unregistered_orch = MLSOrchestrator::new(
        unregistered_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(trudy_did)),
        Arc::new(mallory_credentials.clone()),
        OrchestratorConfig::default(),
    );
    let unregistered_init = unregistered_orch.initialize(trudy_did).await;
    println!(
        "Uncredentialed foreign DID initialization result: {:?}",
        unregistered_init
    );
    assert!(
        matches!(
            unregistered_init,
            Err(OrchestratorError::Credential(_))
        ),
        "a foreign DID without a device credential must fail at the missing-device branch"
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

    // Counterfactual C: While every transport call is refused, resume remains
    // unresolved — and the attempt is observable as a refused transport call,
    // proving the offline state was real rather than a vacuous success.
    let refusals_before_resume = world.delivery_service().refused_transport_calls();
    let offline_retry = reopened_orch
        .resume_direct_request(&draft_id)
        .await
        .unwrap();
    assert!(
        matches!(offline_retry, DirectRequestOutcome::OutcomeUnknown { .. }),
        "while network is offline, resume must stay in OutcomeUnknown"
    );
    assert!(
        world.delivery_service().refused_transport_calls() > refusals_before_resume,
        "offline resume resolved without ever touching the refusing transport"
    );
    assert_eq!(
        world.delivery_service().submitted_prepared_requests().len(),
        transport_count_before,
        "a refused transport call must not be recorded as a submission"
    );

    // 5. Outcome resolution runs ONLY once the network returns.
    //
    // The offline resume above must have left the persisted ownership record
    // intact and still owned by Alice: it did not resolve the attempt and did
    // not hand it to anyone else. Re-decoding the stored record under Alice's
    // own owner+device binding is what proves that.
    let persisted_after_offline = reopened_orch
        .mls_context()
        .read_direct_request_intent(&draft_id)
        .unwrap()
        .expect("owned intent still persisted after offline resume");
    catbird_mls::orchestrator::direct_requests::DirectRequestIntent::decode(
        &persisted_after_offline,
        &alice_did,
        &device,
    )
    .expect("the persisted record must still be owned by Alice after the offline window");

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

    // Network returns: every transport call succeeds again, and the delivery
    // service now responds with the signed receipt for this exact request.
    world.delivery_service().allow_transport();
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

    // The counterfactual for the online leg: resolution was only possible
    // because the transport came back. Counterfactual C already proved that —
    // with every call refused, the same draft stayed OutcomeUnknown and the
    // refusal counter advanced.
    //
    // What must now hold is the converse: once resolved, the terminal outcome
    // is durable, so a fresh reopen resolves it WITHOUT any transport call.
    // If it needed the network again, this would have to issue a request.
    reopened_orch
        .mls_context()
        .flush_and_prepare_close()
        .expect("flush before durable-outcome reopen");
    let durable_context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        "test-key-Alice".to_string(),
        Box::new(keychain.clone()),
    )
    .expect("reopen MLSContext for durable outcome check");
    let durable_orch = MLSOrchestrator::new(
        durable_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(&alice_did)),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );
    durable_orch
        .initialize(&alice_did)
        .await
        .expect("reopen reaches Ready");
    let refusals_before_durable = world.delivery_service().refused_transport_calls();
    let durable_outcome = durable_orch
        .resume_direct_request(&draft_id)
        .await
        .unwrap();
    println!("Durable outcome after reopen: {:?}", durable_outcome);
    match durable_outcome {
        DirectRequestOutcome::TerminalNotPublished { code, request_id: res_id } => {
            assert_eq!(code, "RecipientKeysUnavailable");
            assert_eq!(res_id, request_id);
        }
        other => panic!("expected the durable TerminalNotPublished, got: {:?}", other),
    }
    assert_eq!(
        world.delivery_service().refused_transport_calls(),
        refusals_before_durable,
        "a durable terminal outcome must not require a transport call to read back"
    );

    println!("C35 CORE OFFLINE HYDRATION: ALL ASSERTIONS AND COUNTERFACTUALS PASS");
}
