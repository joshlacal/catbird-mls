//! Regression coverage for account-level exit on devices without usable MLS keys.
#![allow(dead_code)]

mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use catbird_mls::orchestrator::{ConversationState, MLSStorageBackend};
use e2e_harness::TestWorld;
use serde_json::{json, Value};

fn state(convo_id: &str, group_id: &str, kind: &str, participants: Value) -> Value {
    json!({
        "conversationKind": kind,
        "coordinates": {
            "conversationId": convo_id, "groupId": STANDARD.encode(hex::decode(group_id).unwrap()),
            "generation": 3, "epoch": 7, "stateVersion": 19, "lifecycle": "active",
            "confirmationTag": STANDARD.encode([9;32]), "groupContextHash": STANDARD.encode([8;32])
        },
        "participants": participants,
        "metadataSnapshot": {"metadataVersion": 1},
        "leaves": []
    })
}

fn body(world: &TestWorld, op: CanonicalOperation) -> Value {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .rev()
        .find(|r| r.operation == op)
        .and_then(|r| serde_json::from_slice::<Value>(r.body.as_deref()?).ok())
        .map(|v| v["signedRequest"]["body"].clone())
        .expect("submitted operation")
}

fn count(world: &TestWorld, op: CanonicalOperation) -> usize {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|r| r.operation == op)
        .count()
}

async fn setup(world: &mut TestWorld) -> (String, String, String) {
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let created = alice
        .orchestrator
        .create_group("exit test", None, None)
        .await
        .unwrap();
    (created.conversation_id, created.group_id, alice.did.clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_close_from_new_device_uses_server_coordinates_without_mls_group() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "direct",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1},
                {"userDid":"did:plc:bob", "role":"admin", "status":"pending", "leafCount":0}
            ]),
        ),
    );
    world.add_client_with_did("Alice2", &did).await;
    world.register_device("Alice2").await.unwrap();
    world
        .client("Alice2")
        .orchestrator
        .leave_group(&cid)
        .await
        .expect("close without local group");
    assert_eq!(
        count(&world, CanonicalOperation::RequestLeave),
        0,
        "direct chats must close"
    );
    let request = body(&world, CanonicalOperation::CloseConversation);
    assert_eq!(request["prior"]["generation"], 3);
    assert_eq!(request["prior"]["epoch"], 7);
    assert_eq!(request["prior"]["stateVersion"], 19);
    assert_eq!(request["retired"]["stateVersion"], 20);
    assert_eq!(request["retired"]["lifecycle"], "superseded");
    assert_eq!(
        request["prior"]["confirmationTag"],
        STANDARD.encode([9; 32])
    );
    assert!(world.delivery_service().members_of(&cid).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_group_leave_preserves_keys_and_reuses_pending_request() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "group",
            json!([
                {"userDid": did, "role":"member", "status":"active", "leafCount":2},
                {"userDid":"did:plc:bob", "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    let alice = world.client("Alice");
    for _ in 0..2 {
        let error = alice
            .orchestrator
            .leave_group(&cid)
            .await
            .expect_err("leave is pending");
        assert!(
            error.to_string().contains("conversation_leave_pending: "),
            "{error}"
        );
    }
    assert_eq!(
        count(&world, CanonicalOperation::RequestLeave),
        1,
        "adopt the durable request on retry"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&gid).unwrap())
            .unwrap(),
        0
    );
    assert!(alice
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        body(&world, CanonicalOperation::RequestLeave)["prior"]["generation"],
        3
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_leaf_group_leave_removes_immediately_at_current_state_version() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "group",
            json!([
                {"userDid": did, "role":"member", "status":"pending", "leafCount":0},
                {"userDid":"did:plc:bob", "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    world
        .client("Alice")
        .orchestrator
        .leave_group(&cid)
        .await
        .unwrap();
    let request = body(&world, CanonicalOperation::RequestLeave);
    assert_eq!(request["$type"], "blue.catbird.chat.defs#zeroLeafLeaveBody");
    assert_eq!(request["next"]["stateVersion"], 20);
    assert_eq!(request["next"]["epoch"], 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn last_admin_with_other_participants_must_handoff_and_preserves_local_state() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "group",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1},
                {"userDid":"did:plc:bob", "role":"member", "status":"active", "leafCount":1}
            ]),
        ),
    );
    let error = world
        .client("Alice")
        .orchestrator
        .leave_group(&cid)
        .await
        .expect_err("last admin");
    assert!(
        error.to_string().contains("another member an admin"),
        "{error}"
    );
    assert_eq!(count(&world, CanonicalOperation::RequestLeave), 0);
    assert_eq!(count(&world, CanonicalOperation::CloseConversation), 0);
    assert!(world
        .client("Alice")
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_close_keeps_local_conversation_and_crypto() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "direct",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    world
        .delivery_service()
        .set_next_leave_custom_response(409, json!({"error":"StaleCoordinates"}));
    let alice = world.client("Alice");
    assert!(alice.orchestrator.leave_group(&cid).await.is_err());
    assert!(alice
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&gid).unwrap())
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sole_group_admin_closes_instead_of_requesting_unfulfillable_leave() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "group",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    world
        .client("Alice")
        .orchestrator
        .leave_group(&cid)
        .await
        .unwrap();
    assert_eq!(count(&world, CanonicalOperation::RequestLeave), 0);
    assert_eq!(
        body(&world, CanonicalOperation::CloseConversation)["conversationKind"],
        "group"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn incomplete_server_coordinates_never_fall_back_to_local_crypto_or_zero() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    let mut snapshot = state(
        &cid,
        &gid,
        "direct",
        json!([
            {"userDid": did, "role":"admin", "status":"active", "leafCount":1}
        ]),
    );
    snapshot["coordinates"]
        .as_object_mut()
        .unwrap()
        .remove("confirmationTag");
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, snapshot);
    assert!(world
        .client("Alice")
        .orchestrator
        .leave_group(&cid)
        .await
        .is_err());
    assert_eq!(count(&world, CanonicalOperation::CloseConversation), 0);
    assert_eq!(count(&world, CanonicalOperation::RequestLeave), 0);
    assert!(world
        .client("Alice")
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_success_response_does_not_delete_local_state() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "direct",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    world
        .delivery_service()
        .set_next_leave_custom_response(200, json!({"result":{"left":true}}));
    assert!(world
        .client("Alice")
        .orchestrator
        .leave_group(&cid)
        .await
        .is_err());
    assert!(world
        .client("Alice")
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_conversation_retry_finishes_failed_terminal_projection_from_exact_saved_entry() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "direct",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    let alice = world.client("Alice");
    alice.storage.fail_next_set_conversation_state();
    assert!(
        alice.orchestrator.leave_group(&cid).await.is_err(),
        "server closed but local terminal projection failed"
    );
    assert!(alice
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
    alice
        .orchestrator
        .leave_group(&cid)
        .await
        .expect("retry projects the exact saved accepted entry");
    assert_eq!(count(&world, CanonicalOperation::CloseConversation), 1);
    assert!(alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(gid).unwrap())
        .is_ok());
    assert_eq!(alice.storage.get_conversation_state(&cid).await.unwrap(), Some(ConversationState::Closed));
}

#[tokio::test(flavor = "multi_thread")]
async fn retired_tombstone_for_different_local_group_does_not_delete_current_group() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    let unrelated = "77".repeat(32);
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &unrelated,
            "direct",
            json!([
                {"userDid": did, "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    let alice = world.client("Alice");
    alice.storage.fail_next_mark_pending_local_delete();
    assert!(alice.orchestrator.leave_group(&cid).await.is_err());
    assert!(
        alice.orchestrator.leave_group(&cid).await.is_err(),
        "unmatched terminal group is not current local group proof"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(gid).unwrap())
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_accepted_leave_is_not_reported_as_live_pending() {
    let mut world = TestWorld::new();
    let (cid, gid, did) = setup(&mut world).await;
    world.delivery_service().set_lifecycle_state_for_test(
        &cid,
        state(
            &cid,
            &gid,
            "group",
            json!([
                {"userDid": did, "role":"member", "status":"active", "leafCount":1},
                {"userDid":"did:plc:bob", "role":"admin", "status":"active", "leafCount":1}
            ]),
        ),
    );
    world.delivery_service().set_leave_request_ttl_for_test(-1);
    let error = world
        .client("Alice")
        .orchestrator
        .leave_group(&cid)
        .await
        .expect_err("expired request");
    assert!(
        !error.to_string().contains("conversation_leave_pending: "),
        "{error}"
    );
    assert!(world
        .client("Alice")
        .storage
        .get_conversation(&did, &cid)
        .await
        .unwrap()
        .is_some());
}
