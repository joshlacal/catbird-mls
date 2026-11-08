//! C21 core: a device outside a direct request's addressed set (for example
//! enrolled after publication) is refused the request entry with the typed
//! `NotEntitled`. Its app-facing view must be the truthful unavailable state,
//! not an error; every other entry failure still propagates.
//!
//! The conversation state below is the exact `getConversationState` response
//! the live shipping fixture returned to such a device after acceptance
//! (mls-ds e2e C21 run); it carries no private material.
#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op, MlsCryptoContext, OrchestratorError,
};
use catbird_mls::{RequestConsent, RequestCrypto, RequestPreview};
use e2e_harness::mock_api_client::direct_request_i13;
use e2e_harness::TestWorld;
use serde_json::{json, Value};

const CAPTURED: &str = include_str!("fixtures/direct_request_unaddressed_accepted_state.json");

async fn world_for(did: &str) -> TestWorld {
    let mut world = TestWorld::new();
    world.add_client_with_did("Late", did).await;
    world.register_device("Late").await.unwrap();
    world
}

fn captured() -> (Value, String, String) {
    let captured: Value = serde_json::from_str(CAPTURED).unwrap();
    let owner = captured["ownerDid"].as_str().unwrap().to_owned();
    let cid = captured["conversationId"].as_str().unwrap().to_owned();
    (captured, owner, cid)
}

fn not_entitled() -> Value {
    json!({"error":"NotEntitled","message":"NotEntitled"})
}

#[tokio::test(flavor = "multi_thread")]
async fn not_entitled_request_entry_projects_unaddressed_unavailable_state() {
    let (captured, owner, cid) = captured();
    let world = world_for(&owner).await;
    let service = world.delivery_service();
    service.queue_request_operation_response(Op::GetEntries, 400, not_entitled());
    service.queue_request_operation_response(
        Op::GetConversationState,
        200,
        captured["getConversationState"].clone(),
    );
    let client = world.client("Late");
    let view = client
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    let coordinates = &captured["getConversationState"]["state"]["coordinates"];
    assert_eq!(view.conversation_id, cid);
    assert_eq!(view.consent, RequestConsent::Accepted);
    assert_eq!(view.crypto, RequestCrypto::Unavailable);
    assert_eq!(
        view.preview,
        Some(RequestPreview::Unavailable {
            code: "DeviceNotAddressed".into()
        })
    );
    assert_eq!(
        view.introduction, None,
        "no introduction without the publication"
    );
    assert_eq!(view.first_message_id, None);
    assert!(!view.capabilities.can_preview && !view.capabilities.can_send);
    assert!(!view.capabilities.can_emit_receipts && !view.capabilities.can_administer);
    assert!(view.capabilities.can_close, "account close stays available");
    assert_eq!(
        Some(view.state_version),
        coordinates["stateVersion"].as_u64()
    );
    assert_eq!(Some(view.generation), coordinates["generation"].as_u64());
    // Derived, never retained: later recovery cannot inherit a projection.
    assert!(client
        .orchestrator
        .mls_context()
        .read_direct_request_projection(&cid)
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_entry_failures_still_propagate() {
    let (captured, owner, cid) = captured();
    for (status, body) in [
        (
            400,
            json!({"error":"InvalidRequest","message":"InvalidRequest"}),
        ),
        (503, json!({"error":"Unavailable"})),
    ] {
        let world = world_for(&owner).await;
        let service = world.delivery_service();
        service.queue_request_operation_response(Op::GetEntries, status, body);
        service.queue_request_operation_response(
            Op::GetConversationState,
            200,
            captured["getConversationState"].clone(),
        );
        let result = world
            .client("Late")
            .orchestrator
            .refresh_request_preview(&cid)
            .await;
        assert!(
            matches!(result, Err(OrchestratorError::ServerError { status: s, .. }) if s == status),
            "{status} must propagate, got {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unaddressed_view_requires_the_reader_to_be_a_request_party() {
    let (captured, _, cid) = captured();
    let world = world_for("did:plc:cccccccccccccccccccccccc").await;
    let service = world.delivery_service();
    service.queue_request_operation_response(Op::GetEntries, 400, not_entitled());
    service.queue_request_operation_response(
        Op::GetConversationState,
        200,
        captured["getConversationState"].clone(),
    );
    let result = world
        .client("Late")
        .orchestrator
        .refresh_request_preview(&cid)
        .await;
    assert!(
        matches!(result, Err(OrchestratorError::InvalidInput(_))),
        "a non-party must not get a request view: {result:?}"
    );
}

const AUTHORITY: &str = "did:web:chat.catbird.blue";

/// A `directRequestEntry` as served after O7 pruned its opening ciphertext:
/// no `signedRequest`, `payloadPruned: true`, receipts verbatim and authority-signed.
fn pruned_opening(captured: &Value, cid: &str, actor: &Value) -> (Vec<u8>, Value) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use catbird_mls::chat_v2::transcript::direct_request as protocol;
    use p256::ecdsa::signature::Signer;
    let key = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let method = protocol::direct_request_receipt_key_id(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let doc = direct_request_i13::authority_document(&key, &method, AUTHORITY);
    let state = &captured["getConversationState"]["state"];
    let mut coordinates = state["coordinates"].clone();
    for field in ["confirmationTag", "groupContextHash", "groupId"] {
        coordinates[field] = coordinates[field]["$bytes"].clone();
    }
    coordinates["stateVersion"] = json!(1);
    let first_message_id = uuid::Uuid::new_v4().to_string();
    let recorded_at = "2026-09-23T14:57:50.000Z";
    let publication = json!({
        "conversationId": cid, "next": coordinates, "firstMessageId": first_message_id,
        "actorDid": actor,
        "actorDeviceId": uuid::Uuid::new_v4().to_string(),
        "archiveCommitment": STANDARD.encode([7u8; 32]), "signedAt": recorded_at,
    });
    let sequencer = direct_request_i13::receipt(&key, &publication, 1, AUTHORITY);
    let body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0", "protocolVersion": "2",
        "authorityDid": AUTHORITY, "keyId": method,
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestPublishedReceipt",
            "requestId": uuid::Uuid::new_v4().to_string(), "requestKind": "publish",
            "requestDigest": STANDARD.encode([1u8; 32]),
            "preparationRequestDigest": STANDARD.encode([2u8; 32]),
            "actorDid": publication["actorDid"], "actorDeviceId": publication["actorDeviceId"],
            "actorKeyId": "tRfE1zg0D4RSnWLEuIWfY1DRmc3G_Um9RTvMIX9Gd3c", "authGeneration": 1,
            "conversationId": cid, "firstMessageId": first_message_id,
            "coordinates": coordinates, "recordedAt": recorded_at,
            "sequencerReceipt": sequencer,
        },
    });
    let signature: p256::ecdsa::Signature = key.sign(
        &protocol::direct_request_signing_bytes(
            protocol::DirectRequestKind::Outcome,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap(),
    );
    let signature = signature.normalize_s().unwrap_or(signature);
    let entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": first_message_id, "conversationId": cid, "seq": 1,
        "receivedAt": recorded_at, "sequencerReceipt": sequencer,
        "publicationReceipt": {
            "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
            "body": body, "signature": STANDARD.encode(signature.to_bytes()),
        },
        "payloadPruned": true,
    });
    (doc, entry)
}

fn entries(entry: &Value) -> Value {
    json!({"entries":[entry],"hasMore":false,"nextAfterSeq":1})
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_device_sees_pruned_opening_as_declared_terminal_state() {
    let (captured, owner, cid) = captured();
    let sender = &captured["getConversationState"]["state"]["directRequest"]["senderDid"];
    let (doc, entry) = pruned_opening(&captured, &cid, sender);
    let world = world_for(&owner).await;
    let client = world.client("Late");
    client.credentials.set_request_authority_document(doc);
    let state = &captured["getConversationState"]["state"]["directRequest"];
    for party in ["senderDid", "recipientDid"] {
        client
            .credentials
            .set_chat_declaration_authority(state[party].as_str().unwrap(), Some(AUTHORITY));
    }
    let service = world.delivery_service();

    // Receipts that do not bind this exact row are rejected under the two-party state authority.
    let mut forged_seq = entry.clone();
    forged_seq["sequencerReceipt"]["seq"] = json!(2);
    let mut forged_id = entry.clone();
    forged_id["entryId"] = json!(uuid::Uuid::new_v4().to_string());
    let mut forged_signature = entry.clone();
    forged_signature["publicationReceipt"]["body"]["receipt"]["recordedAt"] =
        json!("2026-09-23T14:57:51.000Z");
    forged_signature["receivedAt"] = json!("2026-09-23T14:57:51.000Z");
    let mut unflagged = entry.clone();
    unflagged.as_object_mut().unwrap().remove("payloadPruned");
    for (name, forged) in [
        ("sequencer receipt mismatch", forged_seq),
        ("entry identity mismatch", forged_id),
        ("unsigned receipt edit", forged_signature),
        ("omitted body without payloadPruned", unflagged),
    ] {
        service.queue_request_operation_response(Op::GetEntries, 200, entries(&forged));
        service.queue_request_operation_response(
            Op::GetConversationState,
            200,
            captured["getConversationState"].clone(),
        );
        assert!(
            matches!(
                client.orchestrator.refresh_request_preview(&cid).await,
                Err(OrchestratorError::InvalidInput(_))
            ),
            "{name} must be rejected"
        );
    }

    service.queue_request_operation_response(Op::GetEntries, 200, entries(&entry));
    service.queue_request_operation_response(
        Op::GetConversationState,
        200,
        captured["getConversationState"].clone(),
    );
    let view = client
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .expect("a verified pruned opening is a terminal view, not an error");
    assert_eq!(view.consent, RequestConsent::Accepted);
    assert_eq!(view.crypto, RequestCrypto::Unavailable);
    assert_eq!(
        view.preview,
        Some(RequestPreview::Unavailable {
            code: "OpeningPruned".into()
        })
    );
    assert!(!view.capabilities.can_preview && !view.capabilities.can_send);
    assert!(client
        .orchestrator
        .mls_context()
        .read_direct_request_projection(&cid)
        .unwrap()
        .is_none());
    // The pruned row still maps to its exact control row identity for paging.
    let envelope = catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&entry, &cid)
        .unwrap()
        .unwrap();
    assert_eq!(envelope.server_sequence, Some(1));
    assert_eq!(
        envelope.server_message_id.as_deref(),
        entry["entryId"].as_str()
    );
    assert_eq!(
        envelope.sender_did,
        captured["getConversationState"]["state"]["directRequest"]["senderDid"]
    );
    // A page may carry a different pruned row than the refresh above. The consumed row itself
    // must bind its entry identity and signed publication before the shared cursor can advance.
    let mut forged_consumed = entry.clone();
    forged_consumed["entryId"] = json!(uuid::Uuid::new_v4().to_string());
    let forged_envelope =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&forged_consumed, &cid)
            .unwrap()
            .unwrap();
    service.queue_request_operation_response(
        Op::GetConversationState,
        200,
        captured["getConversationState"].clone(),
    );
    service.queue_incoming_page(vec![forged_envelope], Some("1".into()));
    assert!(
        client
            .orchestrator
            .fetch_messages(&cid, None, 100, None, None, None)
            .await
            .is_err(),
        "a separately refreshed publication must not authenticate a forged consumed row"
    );

    let exact_envelope =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&entry, &cid)
            .unwrap()
            .unwrap();
    service.queue_request_operation_response(
        Op::GetConversationState,
        200,
        captured["getConversationState"].clone(),
    );
    service.queue_incoming_page(vec![exact_envelope], Some("1".into()));
    let (messages, _) = client
        .orchestrator
        .fetch_messages(&cid, None, 100, None, None, None)
        .await
        .expect("the exact authenticated pruned row advances without a message");
    assert!(messages.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn pruned_opening_must_name_the_states_request_sender() {
    let (captured, owner, cid) = captured();
    // Validly signed receipts of a request by someone else cannot stand in for this one.
    let (doc, entry) = pruned_opening(&captured, &cid, &json!("did:plc:cccccccccccccccccccccccc"));
    let world = world_for(&owner).await;
    let client = world.client("Late");
    client.credentials.set_request_authority_document(doc);
    let state = &captured["getConversationState"]["state"]["directRequest"];
    for party in ["senderDid", "recipientDid"] {
        client
            .credentials
            .set_chat_declaration_authority(state[party].as_str().unwrap(), Some(AUTHORITY));
    }
    let state = captured["getConversationState"].clone();
    let service = world.delivery_service();
    service.queue_request_operation_response(Op::GetEntries, 200, entries(&entry));
    service.queue_request_operation_response(Op::GetConversationState, 200, state);
    assert!(matches!(
        client.orchestrator.refresh_request_preview(&cid).await,
        Err(OrchestratorError::InvalidInput(_))
    ));
}
