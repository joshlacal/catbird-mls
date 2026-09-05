//! The UI member-add route creates participant consent before any MLS leaf Add.
#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::orchestrator::{
    canonical_transport::{CanonicalOperation, PreparedRequest},
    EngineEvent, MLSAPIClient, MLSStorageBackend, MlsCryptoContext, OrchestratorConfig,
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

#[tokio::test(flavor = "multi_thread")]
async fn fresh_recipient_native_sync_yields_durable_pending_invitation_without_crypto_mutation() {
    let mut world = world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let engine = engine_for(&world, "Alice");
    let created = engine
        .create_conversation(CreateConversationRequest {
            name: "Pending sync test".into(),
            member_dids: vec![],
            description: None,
        })
        .unwrap()
        .conversation;
    let cid = &created.conversation_id;
    let gid = hex::decode(&created.group_id).unwrap();

    // Alice invites Bob via UI add, creating a policy invitation (status == "pending", leafCount == 0)
    engine
        .add_members(cid, &[bob.did.clone()])
        .expect("UI add should submit an invitation policy");

    // Bob is a fresh recipient: no local MLS group, no stored conversation rows
    assert!(
        !bob.orchestrator
            .mls_context()
            .group_is_active(gid.clone())
            .unwrap_or(false),
        "fresh recipient must not have an active MLS group"
    );
    assert!(
        bob.storage
            .list_conversations(&bob.did)
            .await
            .unwrap()
            .is_empty(),
        "fresh recipient storage must be empty before sync"
    );

    let bob_requests_before = world
        .delivery_service()
        .submitted_prepared_requests()
        .len();

    // Bob runs native sync_with_server
    bob.orchestrator
        .sync_with_server(false)
        .await
        .expect("fresh recipient sync must succeed");

    // 1. Durable storage row was materialized
    let stored_convos = bob
        .storage
        .list_conversations(&bob.did)
        .await
        .unwrap();
    assert_eq!(stored_convos.len(), 1, "durable conversation row must exist");
    assert_eq!(stored_convos[0].conversation_id, *cid);


    // 3. Conversation display snapshot yields the pending conversation with canonical policy
    let snapshot = bob
        .orchestrator
        .conversation_display_snapshot(&bob.did)
        .await
        .unwrap();
    assert_eq!(snapshot.len(), 1);
    let displayed = &snapshot[0];
    assert_eq!(displayed.conversation_id, *cid);
    assert_eq!(displayed.epoch, 0);
    let canonical = displayed
        .canonical_state
        .as_ref()
        .expect("canonical_state must be present in display snapshot");
    let bob_participant = canonical
        .participants
        .iter()
        .find(|p| p.user_did.as_str() == bob.did)
        .expect("bob must be in canonical participants");
    assert_eq!(bob_participant.status.as_str(), "pending");
    assert_eq!(bob_participant.role.as_str(), "member");

    // 4. Invariant: NO cryptographic admission or network mutation occurred before acceptance
    assert!(
        !bob.orchestrator
            .mls_context()
            .group_is_active(gid.clone())
            .unwrap_or(false),
        "recipient must NOT join MLS group or create a leaf before acceptance"
    );
    let transitions_by_bob = world
        .delivery_service()
        .submitted_prepared_requests()[bob_requests_before..]
        .iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .count();
    assert_eq!(transitions_by_bob, 0, "no transitions may be submitted by pending recipient");

    // 5. Restart visibility: restart Bob and verify pending invitation remains visible without local leaf
    world.restart_client("Bob").await;
    let bob = world.client("Bob");

    let restart_snapshot = bob
        .orchestrator
        .conversation_display_snapshot(&bob.did)
        .await
        .unwrap();
    assert_eq!(restart_snapshot.len(), 1, "pending conversation must be visible after restart");
    assert_eq!(restart_snapshot[0].conversation_id, *cid);
    let restart_canonical = restart_snapshot[0]
        .canonical_state
        .as_ref()
        .expect("canonical_state must survive restart");
    let restart_bob_p = restart_canonical
        .participants
        .iter()
        .find(|p| p.user_did.as_str() == bob.did)
        .unwrap();
    assert_eq!(restart_bob_p.status.as_str(), "pending");

    assert!(
        !bob.orchestrator
            .mls_context()
            .group_is_active(gid)
            .unwrap_or(false),
        "restarted client must NOT have an active MLS group before acceptance"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_recipient_live_batch_yields_durable_pending_invitation_with_restart_visibility() {
    let mut world = world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let engine = engine_for(&world, "Alice");
    let created = engine
        .create_conversation(CreateConversationRequest {
            name: "Live batch invite test".into(),
            member_dids: vec![],
            description: None,
        })
        .unwrap()
        .conversation;
    let cid = &created.conversation_id;
    let gid = hex::decode(&created.group_id).unwrap();

    engine
        .add_members(cid, &[bob.did.clone()])
        .expect("UI add should submit an invitation policy");

    // Bob processes an inventoryHintBatch event
    let batch = json!({
        "$type": "blue.catbird.internal#inventoryHintBatch",
        "events": [
            json!({
                "$type": "blue.catbird.chat.defs#conversationChangedEvent",
                "conversationId": cid,
            })
        ]
    });
    let bob_engine = engine_for(&world, "Bob");
    let events = bob_engine
        .process_server_event(&batch.to_string())
        .expect("live batch processing must succeed");

    // Pending admission must emit updated event
    assert!(
        events.iter().any(|e| matches!(e, EngineEvent::ConversationUpdated { convo_id } if convo_id == cid)),
        "live batch must emit ConversationUpdated event for pending invitation"
    );

    // Display snapshot yields the pending invitation
    let snapshot = bob
        .orchestrator
        .conversation_display_snapshot(&bob.did)
        .await
        .unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].conversation_id, *cid);
    assert!(
        snapshot[0].canonical_state.is_some(),
        "canonical_state must be projected after live batch"
    );

    // Invariant: no local MLS group created
    assert!(
        !bob.orchestrator
            .mls_context()
            .group_is_active(gid.clone())
            .unwrap_or(false)
    );

    // Restart Bob and verify visibility
    world.restart_client("Bob").await;
    let bob = world.client("Bob");

    let restart_snapshot = bob
        .orchestrator
        .conversation_display_snapshot(&bob.did)
        .await
        .unwrap();
    assert_eq!(restart_snapshot.len(), 1);
    assert_eq!(restart_snapshot[0].conversation_id, *cid);
    assert!(
        restart_snapshot[0].canonical_state.is_some(),
        "canonical_state must survive restart after live batch"
    );
    assert!(
        !bob.orchestrator
            .mls_context()
            .group_is_active(gid)
            .unwrap_or(false)
    );
}
