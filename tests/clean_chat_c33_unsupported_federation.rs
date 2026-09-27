//! Case C33: Unsupported federation.
//!
//! Validation-table row (line 60 of the validation plan):
//!   "Cross-authority preparation returns typed unsupported capability; retains
//!    draft, consumes no cross-authority lease, and never falls back to legacy
//!    message/Welcome storage."
//!
//! Design authority (`2026-09-19-encrypted-message-requests-design.md:132`):
//!   "Initial atomic publication is limited to one canonical clean-chat
//!    authority owning pair uniqueness, grants, packages, and persistence.
//!    Existing federation routes do not establish this transaction. Unsupported
//!    cross-authority attempts retain the draft and report unavailable support;
//!    a distributed transaction is a separate design and must not fall back to
//!    legacy delivery."
//!
//! ## Why the receipt authority is the cross-authority boundary
//!
//! Every request attempt is bound to exactly one canonical authority document
//! obtained from an authenticated resolver
//! (`CredentialStore::direct_request_receipt_authority_document`). That document
//! is the only source of the receipt verification method a preparation response
//! may reference, and `resolve_direct_request_receipt_key` additionally requires
//! the document `id` to be exactly `did:web:chat.catbird.blue`. Grants,
//! reservations, pair uniqueness and persistence all live inside that one
//! authority's transaction. When an account cannot resolve that authority — its
//! recipient is reachable only through a foreign federation authority — there is
//! no canonical transaction to join, and `start_direct_request` must report
//! unavailable support instead of degrading to legacy delivery.
//!
//! Nothing here is simulated: the real `MLSOrchestrator::start_direct_request`
//! runs, and the real mock delivery service records every wire request the
//! orchestrator actually submits.

#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{CredentialStore, MlsCryptoContext, MLSStorageBackend, OrchestratorError};
use catbird_mls::{DirectRequestInput, MLSError};
use e2e_harness::TestWorld;
use serde_json::json;

/// A foreign federation authority. `resolve_direct_request_receipt_key` refuses
/// any document whose `id` is not the canonical `did:web:chat.catbird.blue`, so
/// this document is a cross-authority document by construction.
const FOREIGN_AUTHORITY: &str = "did:web:chat.federation.example";

fn authority_document(authority_id: &str, key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(true);
    let method_id = protocol::direct_request_receipt_key_id(point.as_bytes()).unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(point.as_bytes());
    serde_json::to_vec(&json!({
        "id": authority_id,
        "verificationMethod": [{
            "id": method_id,
            "controller": authority_id,
            "type": "Multikey",
            "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey),
        }],
    }))
    .unwrap()
}

/// A structurally valid receipt authority document owned by a *foreign*
/// authority; it carries a usable P-256 receipt method so the only reason to
/// refuse it is the authority identity.
fn foreign_authority_document() -> Vec<u8> {
    authority_document(
        FOREIGN_AUTHORITY,
        &p256::ecdsa::SigningKey::from_slice(&[0x5c; 32]).unwrap(),
    )
}

fn draft_input() -> DirectRequestInput {
    DirectRequestInput {
        draft_id: "33333333-3333-4333-8333-333333333333".into(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Cross-authority draft text to be retained".into(),
        invitation: None,
    }
}

/// Clause 4, applied to every wire request this client actually submitted:
/// no legacy federation delivery (`deliverMessage`/`deliverWelcome`/
/// `submitCommit`) and no legacy `blue.catbird.mlsDS.*` surface may appear.
fn assert_no_legacy_fallback(world: &TestWorld) {
    for request in world.delivery_service().submitted_prepared_requests() {
        let path = request.path.as_str();
        assert!(
            !path.contains("deliverMessage")
                && !path.contains("deliverWelcome")
                && !path.contains("submitCommit"),
            "cross-authority refusal must not fall back to legacy federation delivery: {path}"
        );
        assert!(
            !path.contains("mlsDS."),
            "cross-authority refusal must not route through the legacy mlsDS federation surface: {path}"
        );
    }
}

/// Every durable ownership record the request path can create, read directly
/// from the real native store.
fn ownership_records(client: &e2e_harness::TestClient) -> (bool, usize, usize, usize) {
    let context = client.orchestrator.mls_context();
    (
        context
            .read_direct_request_intent("33333333-3333-4333-8333-333333333333")
            .expect("read intent")
            .is_some(),
        context
            .list_direct_request_intents()
            .expect("list intents")
            .len(),
        context
            .list_direct_request_journal()
            .expect("list journal")
            .len(),
        context
            .list_direct_request_projections()
            .expect("list projections")
            .len(),
    )
}

/// Clauses 1-4: an account whose recipient is reachable only through a foreign
/// authority cannot resolve the canonical receipt authority, so preparation
/// must return the typed unsupported capability, retain the draft, consume no
/// lease, and submit nothing at all.
#[tokio::test(flavor = "multi_thread")]
async fn c33_unsupported_cross_authority_refused_before_any_reservation() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let client = world.client("Alice");

    // Cross-authority: no canonical receipt authority is resolvable for this
    // account's recipient, so the request has no canonical transaction to join.
    assert_eq!(
        client
            .credentials
            .direct_request_receipt_authority_document("did:web:chat.catbird.blue")
            .await
            .expect("authority resolution"),
        None,
        "cross-authority fixture must resolve no canonical authority"
    );

    let input = draft_input();
    let before = world.delivery_service().submitted_prepared_requests().len();

    let result = client.orchestrator.start_direct_request(input.clone()).await;

    // Clause 1: typed unsupported capability — not a generic storage failure,
    // not an input-validation rejection, and not a silent success.
    match &result {
        Err(OrchestratorError::Mls(MLSError::OperationNotSupported { reason })) => {
            assert_eq!(
                reason, "Direct request receipt authority resolution unavailable",
                "unsupported-capability reason must name the authority boundary"
            );
        }
        other => panic!("expected typed OperationNotSupported, got {other:?}"),
    }

    // Clause 2: draft retained — the caller's input is untouched and no durable
    // ownership record was created for it.
    assert_eq!(input, draft_input());
    assert_eq!(
        ownership_records(client),
        (false, 0, 0, 0),
        "no intent, journal or projection may exist for a refused draft"
    );

    // Clause 3: no cross-authority lease. The bootstrap journal is the native
    // reservation of the recipient's selected device packages; the projection
    // records the adopted publication. Neither may exist.
    assert!(
        client
            .orchestrator
            .mls_context()
            .list_direct_request_journal()
            .unwrap()
            .is_empty(),
        "no bootstrap journal may exist: no lease was consumed"
    );

    // Clause 4: zero wire traffic after the refusal. In particular no
    // `prepareDirectRequest`, which would have reserved the server-side attempt,
    // its packages and its budget, and no legacy federation fallback.
    assert_eq!(
        world.delivery_service().submitted_prepared_requests().len(),
        before,
        "cross-authority refusal must submit no request at all"
    );
    assert!(
        !world
            .delivery_service()
            .submitted_prepared_requests()
            .iter()
            .any(|r| format!("{:?}", r.operation).contains("DirectRequest")),
        "no direct-request operation may reach the delivery service"
    );
    assert_no_legacy_fallback(&world);
}

/// Cross-authority, resolver-returns-a-foreign-document form. A structurally
/// valid document naming another authority is the unsupported cross-authority
/// case: it must return the same typed unsupported capability, reserve nothing
/// and send nothing. A malformed document stays a storage-class refusal.
#[tokio::test(flavor = "multi_thread")]
async fn c33_foreign_authority_document_never_accepted() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let client = world.client("Alice");

    let foreign = foreign_authority_document();
    client
        .credentials
        .set_request_authority_document(foreign.clone());

    // The installed document is genuinely foreign, not malformed: it parses,
    // carries a real receipt method, and is still refused by the canonical
    // resolver purely because of its authority identity.
    let parsed: serde_json::Value = serde_json::from_slice(&foreign).unwrap();
    assert_eq!(parsed["id"], json!(FOREIGN_AUTHORITY));
    let method = parsed["verificationMethod"][0]["id"].as_str().unwrap();
    assert!(
        protocol::direct_request_receipt_key_id(
            &p256::ecdsa::SigningKey::from_slice(&[0x5c; 32])
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
        )
        .unwrap()
            == method
    );
    assert!(
        protocol::resolve_direct_request_receipt_key(&foreign, method).is_err(),
        "a foreign-authority document must never resolve a canonical receipt key"
    );

    let input = draft_input();
    let before = world.delivery_service().submitted_prepared_requests().len();
    let result = client.orchestrator.start_direct_request(input.clone()).await;

    // Refused, and refused before any ownership record exists.
    assert!(
        result.is_err(),
        "a foreign authority document must never authorize a request: {result:?}"
    );
    assert!(
        !format!("{:?}", result.as_ref().unwrap_err()).contains("OutcomeUnknown"),
        "a foreign authority must not produce a request outcome"
    );
    assert_eq!(
        ownership_records(client),
        (false, 0, 0, 0),
        "foreign authority must reserve nothing: {result:?}"
    );
    assert_eq!(
        world.delivery_service().submitted_prepared_requests().len(),
        before,
        "foreign authority must submit no wire request"
    );
    assert_no_legacy_fallback(&world);

    // Clause 1 for the foreign-document branch: typed unsupported capability.
    match result.unwrap_err() {
        OrchestratorError::Mls(MLSError::OperationNotSupported { reason }) => assert_eq!(
            reason,
            "Direct request receipt authority is not the canonical authority"
        ),
        other => panic!("foreign authority must be a typed unsupported capability, got {other:?}"),
    }

    // A malformed document is not a federation question: it keeps the
    // ownership-record refusal, so the typed capability is not a catch-all.
    client
        .credentials
        .set_request_authority_document(b"{\"id\":\"did:web:chat.federation.example\"}".to_vec());
    let malformed = client.orchestrator.start_direct_request(draft_input()).await;
    assert!(
        matches!(malformed, Err(OrchestratorError::Storage(_))),
        "malformed authority document must not be reported as unsupported federation: {malformed:?}"
    );
    assert_eq!(ownership_records(client), (false, 0, 0, 0));
    assert_eq!(
        world.delivery_service().submitted_prepared_requests().len(),
        before
    );
}

#[test]
fn deterministic_coordinator_derivation_contract() {
    let alice_home = "did:web:alice-chat.example";
    let bob_home = "did:web:bob-chat.example";

    // Lexicographic minimum
    let coord1 = protocol::derive_deterministic_coordinator(alice_home, bob_home).unwrap();
    let coord2 = protocol::derive_deterministic_coordinator(bob_home, alice_home).unwrap();
    assert_eq!(coord1, "did:web:alice-chat.example");
    assert_eq!(
        coord1, coord2,
        "opposite-direction race must converge on the exact same coordinator"
    );

    // Canonical local + foreign
    let local = "did:web:chat.catbird.blue";
    let foreign = "did:web:chat.federation.example";
    let coord_local = protocol::derive_deterministic_coordinator(local, foreign).unwrap();
    assert_eq!(coord_local, local);
    let coord_local_rev = protocol::derive_deterministic_coordinator(foreign, local).unwrap();
    assert_eq!(coord_local_rev, local);

    // Invalid non-bare DIDs rejected
    assert!(protocol::derive_deterministic_coordinator("not-a-did", local).is_err());
    assert!(protocol::derive_deterministic_coordinator("did:web:host#fragment", local).is_err());
    assert!(protocol::derive_deterministic_coordinator(local, "did:web:host/path").is_err());
}

fn authority_doc_for_authority(authority_id: &str, key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(true);
    let method_id =
        protocol::direct_request_receipt_key_id_for_authority(authority_id, point.as_bytes())
            .unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(point.as_bytes());
    serde_json::to_vec(&json!({
        "id": authority_id,
        "verificationMethod": [{
            "id": method_id,
            "controller": authority_id,
            "type": "Multikey",
            "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey),
        }],
    }))
    .unwrap()
}

#[test]
fn foreign_valid_authority_vs_forged_receipt_and_retained_trust() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use p256::ecdsa::signature::Signer as _;

    let foreign_key = p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap();
    let foreign_doc = authority_doc_for_authority(FOREIGN_AUTHORITY, &foreign_key);
    let point = foreign_key.verifying_key().to_encoded_point(true);
    let foreign_key_id =
        protocol::direct_request_receipt_key_id_for_authority(FOREIGN_AUTHORITY, point.as_bytes())
            .unwrap();

    // 1. Foreign authority document resolves when expected authority matches
    let resolved = protocol::resolve_direct_request_receipt_key_for_authority(
        FOREIGN_AUTHORITY,
        &foreign_doc,
        &foreign_key_id,
    )
    .expect("resolves with matching expected authority");
    assert_eq!(resolved, point.as_bytes());

    // 2. Canonical resolver refuses foreign document (no silent cross-authority expansion)
    assert!(
        protocol::resolve_direct_request_receipt_key(&foreign_doc, &foreign_key_id).is_err(),
        "canonical resolver must reject foreign authority document"
    );

    // 3. Construct a genuine foreign outcome receipt
    let receipt_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": FOREIGN_AUTHORITY,
        "keyId": foreign_key_id,
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestRejectedReceipt",
            "requestId": "12345678-1234-4234-8234-123456789abc",
            "requestKind": "publish",
            "requestDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "preparationRequestDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "actorDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "actorDeviceId": "11111111-1111-4111-8111-111111111111",
            "code": "RecipientAuthorityUnsupported"
        }
    });
    let transcript = protocol::direct_request_signing_bytes(
        protocol::DirectRequestKind::Outcome,
        &serde_json::to_vec(&receipt_body).unwrap(),
    )
    .unwrap();
    let sig: p256::ecdsa::Signature = foreign_key.sign(&transcript);
    let signed_receipt = json!({
        "body": receipt_body,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let raw_signed_receipt = serde_json::to_vec(&signed_receipt).unwrap();

    // 4. Verifies under expected foreign authority
    let verified = protocol::verify_received_signed_request_for_authority(
        FOREIGN_AUTHORITY,
        protocol::DirectRequestKind::Outcome,
        &raw_signed_receipt,
        &resolved,
    )
    .expect("verifies under expected foreign authority");
    assert_eq!(verified.body()["authorityDid"], json!(FOREIGN_AUTHORITY));

    // 5. Rejects under expected canonical authority (no receipt self-trust)
    assert!(
        protocol::verify_received_signed_request(
            protocol::DirectRequestKind::Outcome,
            &raw_signed_receipt,
            &resolved,
        )
        .is_err(),
        "must not verify when caller expects canonical authority"
    );

    // 6. Attacker forging receipt: attacker claims evil authority or tampers with authorityDid
    let attacker_key = p256::ecdsa::SigningKey::from_slice(&[0x66; 32]).unwrap();
    let attacker_point = attacker_key.verifying_key().to_encoded_point(true);
    let evil_authority = "did:web:attacker.example";
    let evil_doc = authority_doc_for_authority(evil_authority, &attacker_key);
    let evil_key_id = protocol::direct_request_receipt_key_id_for_authority(
        evil_authority,
        attacker_point.as_bytes(),
    )
    .unwrap();

    // Verifier expecting FOREIGN_AUTHORITY refuses evil_doc
    assert!(
        protocol::resolve_direct_request_receipt_key_for_authority(
            FOREIGN_AUTHORITY,
            &evil_doc,
            &evil_key_id,
        )
        .is_err(),
        "verifier expecting foreign authority must reject attacker doc"
    );

    // Forged receipt signed by attacker claiming evil authority
    let forged_receipt_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": evil_authority,
        "keyId": evil_key_id,
        "receipt": receipt_body["receipt"],
    });
    let forged_transcript = protocol::direct_request_signing_bytes(
        protocol::DirectRequestKind::Outcome,
        &serde_json::to_vec(&forged_receipt_body).unwrap(),
    )
    .unwrap();
    let forged_sig: p256::ecdsa::Signature = attacker_key.sign(&forged_transcript);
    let forged_receipt = json!({
        "body": forged_receipt_body,
        "signature": STANDARD.encode(forged_sig.to_bytes()),
    });
    let raw_forged = serde_json::to_vec(&forged_receipt).unwrap();

    // Verifier expecting FOREIGN_AUTHORITY rejects forged receipt even with attacker's key
    assert!(
        protocol::verify_received_signed_request_for_authority(
            FOREIGN_AUTHORITY,
            protocol::DirectRequestKind::Outcome,
            &raw_forged,
            attacker_point.as_bytes(),
        )
        .is_err(),
        "forged receipt must fail when authorityDid does not match expected authority"
    );

    // 7. Retained document trust: document validation retains trust for the specified expected authority
    assert!(
        catbird_mls::orchestrator::direct_request_intent::validate_authority_document_for_expected_authority(
            &foreign_doc,
            FOREIGN_AUTHORITY,
        )
        .is_ok(),
        "retained authority document validates for its expected authority"
    );
    assert!(
        catbird_mls::orchestrator::direct_request_intent::validate_authority_document_for_expected_authority(
            &foreign_doc,
            "did:web:chat.catbird.blue",
        )
        .is_err(),
        "retained foreign document refused when canonical is expected"
    );
}
