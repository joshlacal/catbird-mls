//! An AlreadyOpen response needs exact requester-inbox evidence, not a guessed success.
#![allow(dead_code)]

mod e2e_harness;

use std::time::{Duration, Instant};

use catbird_mls::orchestrator::canonical_transport::{
    CanonicalOperation, GatewayResponse, PreparedRequest,
};
use catbird_mls::orchestrator::error::OrchestratorError;
use catbird_mls::orchestrator::MLSAPIClient;
use e2e_harness::TestWorld;
use serde_json::{json, Value};

struct Fixture {
    world: TestWorld,
    conversation_id: String,
    group_id: Vec<u8>,
    recovery: Value,
}

async fn outstanding_recovery() -> Fixture {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let created = world
        .client("Alice")
        .orchestrator
        .create_group("recovery conflict", None, None)
        .await
        .unwrap();
    let conversation_id = created.conversation_id;
    let alice = world.client("Alice");
    let group_id =
        hex::decode(&alice.orchestrator.conversations().lock().await[&conversation_id].group_id)
            .unwrap();
    let did = alice.did.clone();
    world.add_client_with_did("AliceDev2", &did).await;
    world.register_device("AliceDev2").await.unwrap();
    let device = world.client("AliceDev2");
    device
        .orchestrator
        .accept_conversation(&conversation_id)
        .await
        .unwrap();
    let device_id = device.orchestrator.require_actor_device_id().await.unwrap();
    // Capture the actual server-side row created by that signed public request.
    let response = device.orchestrator.api_client().submit_prepared_request(PreparedRequest {
        operation: CanonicalOperation::GetLeafRecoveryInbox,
        method: "GET".into(),
        path: format!("/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={device_id}&inventorySessionId=018f3f6a-7b2c-4d91-8a5e-0f123456789a&limit=100"),
        body: None,
    }).await.unwrap();
    assert_eq!(response.status, 200);
    let page: Value = serde_json::from_slice(&response.body).unwrap();
    let recovery = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["conversationId"] == conversation_id)
        .unwrap()
        .clone();
    assert_eq!(recovery["requesterDid"], did);
    assert_eq!(recovery["requesterDeviceId"], device_id);
    assert_eq!(recovery["status"], "open");
    assert_eq!(recovery["recoveryKind"], "add");
    device
        .orchestrator
        .recovery_tracker()
        .lock()
        .await
        .note_leaf_recovery_requested_at(
            &conversation_id,
            Instant::now() - Duration::from_secs(301),
        );
    Fixture {
        world,
        conversation_id,
        group_id,
        recovery,
    }
}

fn count(world: &TestWorld, operation: CanonicalOperation) -> usize {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|request| request.operation == operation)
        .count()
}

fn response(status: u16, body: Value) -> GatewayResponse {
    GatewayResponse {
        status,
        content_type: Some("application/json".into()),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn page(items: Vec<Value>, next: Option<&str>) -> GatewayResponse {
    let mut body = json!({
        "items": items,
        "inventorySessionId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "snapshotEventCursor": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "snapshotExpiresAt": "2026-08-20T12:00:00.000Z",
        "hasMore": next.is_some(),
    });
    if let Some(next) = next {
        body["nextPageCursor"] = json!(next);
    }
    response(200, body)
}

fn assert_no_replacement(fixture: &Fixture, packages_before: usize) {
    let world = &fixture.world;
    assert_eq!(
        count(world, CanonicalOperation::RequestLeafRecovery),
        2,
        "one initial request and one conflicting attempt; no retry with another request ID"
    );
    assert_eq!(count(world, CanonicalOperation::RequestReset), 0);
    assert_eq!(count(world, CanonicalOperation::ActivateReset), 0);
    assert_eq!(
        world
            .delivery_service()
            .bootstrap_reset_group_call_count(&fixture.conversation_id),
        0
    );
    assert_eq!(
        world
            .delivery_service()
            .key_package_count(&world.client("Alice").did),
        packages_before,
        "conflict resolution must preserve the existing reservation and remaining KeyPackages"
    );
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(fixture.group_id.clone())
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn already_open_refreshes_mismatched_session_and_returns_the_retained_request() {
    let fixture = outstanding_recovery().await;
    let world = &fixture.world;
    let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
    let sessions_before = count(world, CanonicalOperation::GetConversations);
    let packages_before = world
        .delivery_service()
        .key_package_count(&world.client("Alice").did);
    world
        .delivery_service()
        .set_leaf_recovery_inbox_responses(vec![response(
            400,
            json!({"error": "InventorySessionMismatch"}),
        )]);

    let outcome = world
        .client("AliceDev2")
        .orchestrator
        .accept_conversation(&fixture.conversation_id)
        .await
        .unwrap();

    assert_eq!(
        outcome["recovery"]["recoveryRequestId"], fixture.recovery["recoveryRequestId"],
        "AlreadyOpen must return the proven row, not fabricate leafRecovery:open"
    );
    assert!(
        outcome["recovery"] == fixture.recovery,
        "the entire retained recovery row must be returned unchanged"
    );
    assert_eq!(
        count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
        2
    );
    assert_eq!(
        count(world, CanonicalOperation::GetConversations) - sessions_before,
        2
    );
    world
        .client("AliceDev2")
        .orchestrator
        .accept_conversation(&fixture.conversation_id)
        .await
        .expect("verified outstanding recovery prevents another immediate request");
    assert_no_replacement(&fixture, packages_before);
}

#[tokio::test(flavor = "multi_thread")]
async fn already_open_refreshes_an_expired_inventory_session_once() {
    let fixture = outstanding_recovery().await;
    let world = &fixture.world;
    let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
    let sessions_before = count(world, CanonicalOperation::GetConversations);
    let packages_before = world
        .delivery_service()
        .key_package_count(&world.client("Alice").did);
    world
        .delivery_service()
        .set_leaf_recovery_inbox_responses(vec![response(
            400,
            json!({"error": "InventorySessionExpired"}),
        )]);

    let outcome = world
        .client("AliceDev2")
        .orchestrator
        .accept_conversation(&fixture.conversation_id)
        .await
        .unwrap();

    assert!(
        outcome["recovery"] == fixture.recovery,
        "the entire retained recovery row must be returned unchanged"
    );
    assert_eq!(
        count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
        2
    );
    assert_eq!(
        count(world, CanonicalOperation::GetConversations) - sessions_before,
        2
    );
    assert_no_replacement(&fixture, packages_before);
}

fn assert_server_error(error: OrchestratorError, expected_status: u16, expected_code: &str) {
    match error {
        OrchestratorError::ServerError { status, body } => {
            assert_eq!(status, expected_status);
            assert_eq!(
                serde_json::from_str::<Value>(&body).unwrap()["error"],
                expected_code
            );
        }
        other => panic!(
            "expected original server error {expected_status}/{expected_code}, got {other:?}"
        ),
    }
}

fn assert_request_error(error: OrchestratorError, expected_status: u16, expected_code: &str) {
    match error {
        OrchestratorError::Api(message) => {
            let (context, body) = message.split_once(": ").expect("request error body");
            assert_eq!(
                context,
                format!("request_leaf_recovery failed with status {expected_status}")
            );
            assert_eq!(
                serde_json::from_str::<Value>(body).unwrap()["error"],
                expected_code
            );
        }
        other => panic!(
            "expected original request error {expected_status}/{expected_code}, got {other:?}"
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inbox_proof_errors_propagate_without_fabricating_an_open_request() {
    for (status, code) in [
        (500, "DatabaseFailure"),
        (401, "AccountSessionExpired"),
        (400, "NotAuthorized"),
    ] {
        let fixture = outstanding_recovery().await;
        let world = &fixture.world;
        let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
        let sessions_before = count(world, CanonicalOperation::GetConversations);
        let packages_before = world
            .delivery_service()
            .key_package_count(&world.client("Alice").did);
        world
            .delivery_service()
            .set_leaf_recovery_inbox_responses(vec![response(status, json!({"error": code}))]);

        let error = world
            .client("AliceDev2")
            .orchestrator
            .accept_conversation(&fixture.conversation_id)
            .await
            .expect_err("failed inbox evidence must never become recovery success");

        assert_server_error(error, status, code);
        assert_eq!(
            count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
            1
        );
        assert_eq!(
            count(world, CanonicalOperation::GetConversations) - sessions_before,
            1
        );
        assert_no_replacement(&fixture, packages_before);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_inventory_session_failure_stops_before_a_third_proof_attempt() {
    let fixture = outstanding_recovery().await;
    let world = &fixture.world;
    let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
    let sessions_before = count(world, CanonicalOperation::GetConversations);
    let packages_before = world
        .delivery_service()
        .key_package_count(&world.client("Alice").did);
    world
        .delivery_service()
        .set_leaf_recovery_inbox_responses(vec![
            response(400, json!({"error": "InventorySessionMismatch"})),
            response(400, json!({"error": "InventorySessionExpired"})),
        ]);

    let error = world
        .client("AliceDev2")
        .orchestrator
        .accept_conversation(&fixture.conversation_id)
        .await
        .expect_err("a valid fallback inbox must not be reached after two failed sessions");

    assert_server_error(error, 400, "InventorySessionExpired");
    assert_eq!(
        count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
        2
    );
    assert_eq!(
        count(world, CanonicalOperation::GetConversations) - sessions_before,
        2
    );
    assert_no_replacement(&fixture, packages_before);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_exact_400_error_code_can_trigger_conflict_recovery() {
    for (status, code, message) in [
        (409, "LeafRecoveryAlreadyOpen", "request remains open"),
        (500, "LeafRecoveryAlreadyOpen", "request remains open"),
        (
            400,
            "InvalidRequest",
            "LeafRecoveryAlreadyOpen is merely message text",
        ),
    ] {
        let fixture = outstanding_recovery().await;
        let world = &fixture.world;
        let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
        let packages_before = world
            .delivery_service()
            .key_package_count(&world.client("Alice").did);
        world
            .delivery_service()
            .set_next_leaf_recovery_response(response(
                status,
                json!({
                    "error": code, "message": message,
                }),
            ));

        let error = world
            .client("AliceDev2")
            .orchestrator
            .accept_conversation(&fixture.conversation_id)
            .await
            .expect_err(
                "a different status or message substring cannot authorize recovery success",
            );

        assert_request_error(error, status, code);
        assert_eq!(
            count(world, CanonicalOperation::GetLeafRecoveryInbox),
            inbox_before
        );
        assert_no_replacement(&fixture, packages_before);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inbox_session_error_names_at_non_400_status_do_not_trigger_refresh() {
    for status in [401, 409, 500] {
        let fixture = outstanding_recovery().await;
        let world = &fixture.world;
        let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
        let sessions_before = count(world, CanonicalOperation::GetConversations);
        world
            .delivery_service()
            .set_leaf_recovery_inbox_responses(vec![response(
                status,
                json!({
                    "error": "InventorySessionMismatch",
                }),
            )]);

        let error = world
            .client("AliceDev2")
            .orchestrator
            .accept_conversation(&fixture.conversation_id)
            .await
            .unwrap_err();

        assert_server_error(error, status, "InventorySessionMismatch");
        assert_eq!(
            count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
            1
        );
        assert_eq!(
            count(world, CanonicalOperation::GetConversations) - sessions_before,
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_inbox_row_must_match_owner_device_kind_full_coordinate_and_live_deadline() {
    for (pointer, value) in [
        ("/requesterDid", json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")),
        (
            "/requesterDeviceId",
            json!("00000000-0000-4000-8000-000000000001"),
        ),
        ("/recoveryKind", json!("replace")),
        ("/boundCoordinate/stateVersion", json!(99)),
        (
            "/boundCoordinate/groupContextHash",
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        ),
        (
            "/boundCoordinate/confirmationTag",
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        ),
        ("/expiresAt", json!("2000-01-01T00:00:00.000Z")),
        ("/status", json!("fulfilled")),
    ] {
        let fixture = outstanding_recovery().await;
        let world = &fixture.world;
        let mut different = fixture.recovery.clone();
        let field = different.pointer_mut(pointer).unwrap();
        assert_ne!(
            *field, value,
            "fixture mutation {pointer} must change the proof"
        );
        *field = value;
        let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
        let packages_before = world
            .delivery_service()
            .key_package_count(&world.client("Alice").did);
        world
            .delivery_service()
            .set_leaf_recovery_inbox_responses(vec![page(vec![different], None)]);

        let error = world
            .client("AliceDev2")
            .orchestrator
            .accept_conversation(&fixture.conversation_id)
            .await
            .expect_err(&format!(
                "inexact {pointer} cannot prove this device's request"
            ));

        assert_request_error(error, 400, "LeafRecoveryAlreadyOpen");
        assert_eq!(
            count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
            1
        );
        assert_no_replacement(&fixture, packages_before);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_request_on_the_third_inbox_page_is_returned_without_resubmission() {
    let fixture = outstanding_recovery().await;
    let world = &fixture.world;
    let mut older = fixture.recovery.clone();
    older["status"] = json!("cancelled");
    older["recoveryRequestId"] = json!("00000000-0000-4000-8000-000000000002");
    let mut oldest = older.clone();
    oldest["recoveryRequestId"] = json!("00000000-0000-4000-8000-000000000001");
    let inbox_before = count(world, CanonicalOperation::GetLeafRecoveryInbox);
    let sessions_before = count(world, CanonicalOperation::GetConversations);
    let packages_before = world
        .delivery_service()
        .key_package_count(&world.client("Alice").did);
    world
        .delivery_service()
        .set_leaf_recovery_inbox_responses(vec![
            page(vec![oldest], Some("page-two")),
            page(vec![older], Some("page-three")),
            page(vec![fixture.recovery.clone()], None),
        ]);

    let outcome = world
        .client("AliceDev2")
        .orchestrator
        .accept_conversation(&fixture.conversation_id)
        .await
        .unwrap();

    assert!(
        outcome["recovery"] == fixture.recovery,
        "the exact retained request on page three must be returned unchanged"
    );
    assert_eq!(
        count(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
        3
    );
    assert_eq!(
        count(world, CanonicalOperation::GetConversations) - sessions_before,
        1
    );
    let reads: Vec<_> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|request| request.operation == CanonicalOperation::GetLeafRecoveryInbox)
        .skip(inbox_before)
        .collect();
    assert!(reads[1].path.contains("pageCursor=page-two"));
    assert!(reads[2].path.contains("pageCursor=page-three"));
    assert_no_replacement(&fixture, packages_before);
}
