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
    let view = client.orchestrator.refresh_request_preview(&cid).await.unwrap();
    let coordinates = &captured["getConversationState"]["state"]["coordinates"];
    assert_eq!(view.conversation_id, cid);
    assert_eq!(view.consent, RequestConsent::Accepted);
    assert_eq!(view.crypto, RequestCrypto::Unavailable);
    assert_eq!(
        view.preview,
        Some(RequestPreview::Unavailable { code: "DeviceNotAddressed".into() })
    );
    assert_eq!(view.introduction, None, "no introduction without the publication");
    assert_eq!(view.first_message_id, None);
    assert!(!view.capabilities.can_preview && !view.capabilities.can_send);
    assert!(!view.capabilities.can_emit_receipts && !view.capabilities.can_administer);
    assert!(view.capabilities.can_close, "account close stays available");
    assert_eq!(Some(view.state_version), coordinates["stateVersion"].as_u64());
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
        (400, json!({"error":"InvalidRequest","message":"InvalidRequest"})),
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
