//! Clean-chat reset from a device with no local MLS state.
//!
//! Scenario from production (2026-09-03): a reinstalled device is an active
//! admin of a conversation whose only MLS leaf belonged to its own wiped
//! predecessor. No External Commit path exists (no GroupInfo endpoint), and
//! nobody can fulfil its leaf recovery. The device must `requestReset` +
//! `activateReset` from server state alone.

#![allow(dead_code)]

mod e2e_harness;

use std::time::{Duration, Instant};

use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use catbird_mls::orchestrator::reset_flow::ResetOutcome;
use catbird_mls::orchestrator::types::ConversationState;
use e2e_harness::TestWorld;

/// Alice creates a conversation on device 1; device 2 (same DID, no local
/// group) is the reinstalled device. Returns the conversation id and the
/// device id of the dead genesis leaf.
async fn world_with_leafless_second_device(world: &mut TestWorld) -> (String, String) {
    world.add_client("Alice").await;
    world.register_device("Alice").await.expect("register alice device 1");
    let alice = world.client("Alice");
    let created = alice
        .orchestrator
        .create_group("alice group", None, None)
        .await
        .expect("create conversation");
    let dev1 = alice
        .orchestrator
        .require_actor_device_id()
        .await
        .expect("device 1 id");
    let alice_did = alice.did.clone();

    world.add_client_with_did("AliceDev2", &alice_did).await;
    world.register_device("AliceDev2").await.expect("register alice device 2");
    world.delivery_service().set_bootstrap_reset_group_success(true);
    (created.conversation_id, dev1)
}

fn leaf(user_did: &str, device_id: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "userDid": user_did,
        "deviceId": device_id,
        "leafOrigin": "genesis",
        "keyId": "k",
        "deviceStatus": status
    })
}

fn count(world: &TestWorld, op: CanonicalOperation) -> usize {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|r| r.operation == op)
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn leafless_admin_with_no_foreign_leaf_resets_instead_of_waiting() {
    let mut world = TestWorld::new();
    let (convo_id, dead_device) = world_with_leafless_second_device(&mut world).await;
    let alice_did = world.client("Alice").did.clone();
    world
        .delivery_service()
        .set_conversation_leaves_for_test(&convo_id, vec![leaf(&alice_did, &dead_device, "active")]);
    let dev2 = world.client("AliceDev2");
    let before = world.delivery_service().conversation_ids();
    assert_eq!(before, vec![convo_id.clone()]);

    let outcome = dev2
        .orchestrator
        .accept_conversation(&convo_id)
        .await
        .expect("accept_conversation escalates to reset");
    assert_eq!(outcome["epoch"], 0, "reset activated here; caller is back in the group");

    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 0, "no doomed leaf recovery");
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 1);
    assert_eq!(world.delivery_service().bootstrap_reset_group_call_count(&convo_id), 1);

    // The activation body is what the server validates byte-for-byte.
    let bodies = world.delivery_service().activate_reset_bodies();
    let body = &bodies[0];
    assert_eq!(body["$type"], "blue.catbird.chat.defs#resetActivationBody");
    assert_eq!(body["conversationKind"], "group");
    assert_eq!(body["prior"]["stateVersion"], 0);
    assert_eq!(body["prior"]["lifecycle"], "active");
    assert_eq!(body["retired"]["stateVersion"], 1);
    assert_eq!(body["retired"]["lifecycle"], "superseded");
    assert_eq!(body["retired"]["groupId"], body["prior"]["groupId"]);
    assert_eq!(body["successor"]["generation"], 1);
    assert_eq!(body["successor"]["epoch"], 0);
    assert_eq!(body["successor"]["stateVersion"], 0);
    assert_ne!(body["successor"]["groupId"], body["prior"]["groupId"]);
    assert_eq!(body["manifest"]["actorLeaf"]["userDid"], alice_did);
    assert_eq!(body["manifest"]["actorLeaf"]["leafOrigin"], "genesis");
    assert_eq!(body["manifest"]["participants"][0]["userDid"], alice_did);
    assert_eq!(body["manifest"]["participants"][0]["status"], "active");
    assert_eq!(body["metadataSnapshot"]["metadataVersion"], 2);
    assert_eq!(body["metadataSnapshot"]["originTransitionId"], body["transitionId"]);
    let request_bodies: Vec<serde_json::Value> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::RequestReset)
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(r.body.as_deref()?).ok())
        .map(|v| v["signedRequest"]["body"].clone())
        .collect();
    assert_eq!(request_bodies[0]["reason"], "localStateLost");
    assert_eq!(body["resetRequestId"], request_bodies[0]["resetRequestId"]);

    // Device 2 now holds the successor genesis leaf and is Active locally.
    // (The signed transcript canonicalizes `{"$bytes": …}` to a bare base64 string.)
    use base64::Engine as _;
    let successor_group_b64 = body["successor"]["groupId"]
        .as_str()
        .or_else(|| body["successor"]["groupId"]["$bytes"].as_str())
        .expect("successor groupId");
    let new_group_hex = hex::encode(
        base64::engine::general_purpose::STANDARD
            .decode(successor_group_b64)
            .expect("base64 group id"),
    );
    assert_eq!(
        dev2.orchestrator
            .mls_context()
            .get_epoch(hex::decode(&new_group_hex).unwrap())
            .expect("successor group exists locally"),
        0
    );
    let view = dev2
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&convo_id)
        .cloned()
        .expect("conversation view");
    assert_eq!(view.group_id, new_group_hex);
    assert_eq!(
        dev2.orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&convo_id),
        Some(&ConversationState::Active)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn leafless_admin_waits_on_live_peer_leaf_then_escalates_after_ttl() {
    let mut world = TestWorld::new();
    let (convo_id, _dead_device) = world_with_leafless_second_device(&mut world).await;
    world
        .delivery_service()
        .set_conversation_leaves_for_test(&convo_id, vec![leaf("did:plc:bob", "bob-device", "active")]);
    let dev2 = world.client("AliceDev2");

    // Bob's live leaf can add us: request leaf recovery, do not reset.
    dev2.orchestrator
        .accept_conversation(&convo_id)
        .await
        .expect("leaf recovery requested");
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 1);
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 0);

    // While the request is open, re-syncing must not spam the server.
    let again = dev2
        .orchestrator
        .accept_conversation(&convo_id)
        .await
        .expect("open request short-circuits");
    assert_eq!(again["leafRecovery"], "open");
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 1);

    // Once the server TTL has lapsed unfulfilled, nobody is coming: reset.
    dev2.orchestrator
        .recovery_tracker()
        .lock()
        .await
        .note_leaf_recovery_requested_at(&convo_id, Instant::now() - Duration::from_secs(301));
    let outcome = dev2
        .orchestrator
        .accept_conversation(&convo_id)
        .await
        .expect("expired wait escalates");
    assert_eq!(outcome["epoch"], 0, "reset activated here; caller is back in the group");
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 1);
    assert_eq!(world.delivery_service().bootstrap_reset_group_call_count(&convo_id), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn leafless_member_without_leaf_info_keeps_requesting_leaf_recovery() {
    // A server that reports no `leaves` gives no evidence nobody can help:
    // never auto-reset on a guess.
    let mut world = TestWorld::new();
    let (convo_id, _dead_device) = world_with_leafless_second_device(&mut world).await;
    let dev2 = world.client("AliceDev2");
    dev2.orchestrator
        .accept_conversation(&convo_id)
        .await
        .expect("leaf recovery requested");
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 1);
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn manual_reset_works_without_local_group() {
    let mut world = TestWorld::new();
    let (convo_id, _dead_device) = world_with_leafless_second_device(&mut world).await;
    let dev2 = world.client("AliceDev2");

    dev2.orchestrator
        .user_confirmed_manual_reset(&convo_id)
        .await
        .expect("manual reset from a blank device");

    assert_eq!(count(&world, CanonicalOperation::RequestReset), 1);
    assert_eq!(world.delivery_service().bootstrap_reset_group_call_count(&convo_id), 1);
    let bodies = world.delivery_service().activate_reset_bodies();
    assert_eq!(bodies.len(), 1);
    let request_reason = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .find(|r| r.operation == CanonicalOperation::RequestReset)
        .and_then(|r| serde_json::from_slice::<serde_json::Value>(r.body.as_deref()?).ok())
        .map(|v| v["signedRequest"]["body"]["reason"].clone())
        .expect("reset request body");
    assert_eq!(request_reason, "manualRecovery");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_admin_member_only_requests_reset() {
    let mut world = TestWorld::new();
    let (convo_id, dead_device) = world_with_leafless_second_device(&mut world).await;
    let alice_did = world.client("Alice").did.clone();
    world.delivery_service().set_conversation_participants_for_test(
        &convo_id,
        vec![
            serde_json::json!({ "userDid": alice_did, "role": "member", "status": "active", "leafCount": 1 }),
            serde_json::json!({ "userDid": "did:plc:zed", "role": "admin", "status": "active", "leafCount": 0 }),
        ],
    );
    world
        .delivery_service()
        .set_conversation_leaves_for_test(&convo_id, vec![leaf(&alice_did, &dead_device, "active")]);
    let dev2 = world.client("AliceDev2");

    let outcome = dev2
        .orchestrator
        .reset_conversation(&convo_id, "localStateLost")
        .await
        .expect("member can request");
    assert_eq!(outcome, ResetOutcome::Requested);
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 1);
    assert_eq!(world.delivery_service().bootstrap_reset_group_call_count(&convo_id), 0);
}
