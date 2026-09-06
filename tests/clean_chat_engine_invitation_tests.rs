//! The UI member-add route creates participant consent before any MLS leaf Add.
#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::orchestrator::{
    canonical_transport::{CanonicalOperation, PreparedRequest},
    MLSAPIClient, MLSStorageBackend, MlsCryptoContext, OrchestratorConfig,
};
use catbird_mls::{CreateConversationRequest, EngineLifecycle, MLSContext, MlsEngine};
use e2e_harness::{
    mock_api_client::MockDeliveryService, mock_credentials::MockCredentials,
    mock_storage::MockStorage, TestWorld,
};
use serde_json::{json, Value};
use std::sync::Arc;

type Engine = MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext>;
fn engine_for(world: &TestWorld, name: &str) -> Engine {
    let client = world.client(name);
    let engine = MlsEngine::new(
        client.orchestrator.mls_context().clone(),
        Arc::new(client.storage.clone()),
        Arc::new(world.delivery_service().clone_as(&client.did)),
        Arc::new(client.credentials.clone()),
        Arc::new(EngineLifecycle::default()),
        OrchestratorConfig::default(),
    );
    engine.initialize_user(&client.did).unwrap();
    engine
}
async fn world() -> TestWorld {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
        ("Charlie", "did:plc:cccccccccccccccccccccccc"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    world
}
async fn state(world: &TestWorld, actor: &str, cid: &str) -> Value {
    let client = world.client(actor);
    let device = client.orchestrator.require_actor_device_id().await.unwrap();
    let response = world.delivery_service().clone_as(&client.did).submit_prepared_request(PreparedRequest {
        operation:CanonicalOperation::GetConversationState,method:"GET".into(),path:format!("/xrpc/blue.catbird.chat.getConversationState?conversationId={cid}&actorDeviceId={device}"),body:None,
    }).await.unwrap();
    assert_eq!(response.status, 200);
    serde_json::from_slice(&response.body).unwrap()
}
fn changed(cid: &str) -> String {
    json!({"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":cid})
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_add_invites_without_adding_a_leaf_until_recipient_accepts() {
    let world = world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let engine = engine_for(&world, "Alice");
    let created = engine
        .create_conversation(CreateConversationRequest {
            name: "Invitation route".into(),
            member_dids: vec![],
            description: None,
        })
        .unwrap()
        .conversation;
    let cid = &created.conversation_id;
    let gid = hex::decode(&created.group_id).unwrap();
    let actor = alice.orchestrator.require_actor_device_id().await.unwrap();
    world.delivery_service().set_conversation_leaves_for_test(
        cid,
        vec![json!({"userDid":alice.did,"deviceId":actor,"deviceStatus":"active","leafIndex":0})],
    );
    let leaves_before = alice
        .orchestrator
        .mls_context()
        .group_member_identities(gid.clone())
        .unwrap();
    let before = world.delivery_service().submitted_prepared_requests().len();
    let invited = engine
        .add_members(cid, &[bob.did.clone()])
        .expect("UI add should submit an invitation policy");
    assert_eq!(
        invited.conversation.epoch, 0,
        "inviting cannot advance the MLS epoch"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        0
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .group_member_identities(gid.clone())
            .unwrap(),
        leaves_before
    );
    assert!(
        invited
            .conversation
            .members
            .iter()
            .any(|member| member.did == bob.did),
        "refreshed snapshot includes the invited participant"
    );
    let pending = state(&world, "Alice", cid).await;
    assert_eq!(
        pending["state"]["participants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["userDid"] == bob.did)
            .unwrap()["status"],
        "pending"
    );
    let requests = world.delivery_service().submitted_prepared_requests();
    let transitions: Vec<_> = requests[before..]
        .iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .collect();
    assert_eq!(transitions.len(), 1);
    let policy: Value = serde_json::from_slice(transitions[0].body.as_ref().unwrap()).unwrap();
    let policy = &policy["signedRequest"]["body"];
    assert_eq!(
        policy["$type"],
        "blue.catbird.chat.defs#policyTransitionBody"
    );
    assert_eq!(policy["participantChanges"][0]["status"], "pending");
    assert!(policy.get("commit").is_none());
    assert!(
        policy.get("manifest").is_none(),
        "policy invitation cannot stage MLS Add or Welcome"
    );
    assert_eq!(
        alice
            .orchestrator
            .fulfill_pending_leaf_recoveries()
            .await
            .unwrap(),
        0
    );
    let acceptance = bob.orchestrator.accept_conversation(cid).await.unwrap();
    let recovery_id = acceptance["recovery"]["recoveryRequestId"]
        .as_str()
        .unwrap();
    let accepted = state(&world, "Alice", cid).await;
    assert_eq!(
        accepted["state"]["participants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["userDid"] == bob.did)
            .unwrap()["status"],
        "active"
    );
    let bob_engine = engine_for(&world, "Bob");
    bob_engine.process_server_event(&changed(cid)).unwrap();
    assert_eq!(
        world
            .delivery_service()
            .submitted_prepared_requests()
            .iter()
            .filter(|request| request.operation == CanonicalOperation::RequestLeafRecovery)
            .count(),
        0,
        "reuse the exact Add reservation created atomically by acceptance"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        0,
        "accepting and requesting still wait for a current device Commit"
    );
    engine.process_server_event(&changed(cid)).unwrap();
    let submissions = world.delivery_service().submitted_prepared_requests();
    let fulfilled = submissions
        .iter()
        .filter(|request| request.operation == CanonicalOperation::SubmitTransition)
        .last()
        .unwrap();
    let fulfilled: Value = serde_json::from_slice(fulfilled.body.as_ref().unwrap()).unwrap();
    assert_eq!(
        fulfilled["signedRequest"]["body"]["recoveryRequestId"],
        recovery_id
    );
    bob_engine.process_server_event(&json!({"$type":"blue.catbird.chat.defs#welcomeAvailableEvent","conversationId":cid,"welcomeId":uuid::Uuid::new_v4().to_string()}).to_string()).unwrap();
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        1
    );
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        1
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .group_member_identities(gid)
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_add_rejects_a_direct_conversation_without_crypto_mutation() {
    let world = world().await;
    let engine = engine_for(&world, "Alice");
    let created = engine
        .create_conversation(CreateConversationRequest {
            name: "Direct".into(),
            member_dids: vec![world.client("Bob").did.clone()],
            description: None,
        })
        .unwrap()
        .conversation;
    let gid = hex::decode(&created.group_id).unwrap();
    let before = world.delivery_service().submitted_prepared_requests().len();
    let error = engine
        .add_members(
            &created.conversation_id,
            &[world.client("Charlie").did.clone()],
        )
        .unwrap_err();
    assert!(error.to_string().contains("direct"), "{error}");
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        0
    );
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .group_member_identities(gid)
            .unwrap()
            .len(),
        1
    );
    assert!(
        !world.delivery_service().submitted_prepared_requests()[before..]
            .iter()
            .any(|r| r.operation == CanonicalOperation::SubmitTransition)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_add_preserves_crypto_when_server_rejects_a_non_admin() {
    let world = world().await;
    let engine = engine_for(&world, "Alice");
    let created = engine
        .create_conversation(CreateConversationRequest {
            name: "Admin authority".into(),
            member_dids: vec![],
            description: None,
        })
        .unwrap()
        .conversation;
    let mut authoritative = state(&world, "Alice", &created.conversation_id).await["state"].clone();
    authoritative["participants"][0]["role"] = json!("member");
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&created.conversation_id, authoritative);
    let error = engine
        .add_members(&created.conversation_id, &[world.client("Bob").did.clone()])
        .unwrap_err();
    assert!(
        error.to_string().contains("403"),
        "server policy authority must reject non-admin invitations: {error}"
    );
    let gid = hex::decode(&created.group_id).unwrap();
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(gid.clone())
            .unwrap(),
        0
    );
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .group_member_identities(gid)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        world
            .client("Alice")
            .storage
            .get_group_state(&created.group_id)
            .await
            .unwrap()
            .unwrap()
            .epoch,
        0
    );
}
