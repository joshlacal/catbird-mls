//! Reopening an existing direct chat must restore device access or accept the
//! caller's pending invitation instead of inventing a device-membership error.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use catbird_mls::orchestrator::{types::ConversationState, MLSStorageBackend};
use e2e_harness::TestWorld;
use serde_json::json;

fn count(world: &TestWorld, operation: CanonicalOperation) -> usize {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|r| r.operation == operation)
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn accepting_healthy_existing_membership_never_requests_recovery_or_reset() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let initial = alice
        .orchestrator
        .create_group("healthy", None, None)
        .await
        .unwrap();
    let create_body = world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .find(|r| r.operation == CanonicalOperation::CreateConversation)
        .map(|r| {
            serde_json::from_slice::<serde_json::Value>(r.body.as_ref().unwrap()).unwrap()
                ["signedRequest"]["body"]
                .clone()
        })
        .unwrap();
    world.delivery_service().set_lifecycle_state_for_test(
        &initial.conversation_id,
        json!({
            "conversationKind":"group", "coordinates":create_body["next"],
            "participants":[{"userDid":alice.did,"role":"admin","status":"active","leafCount":1}],
            "metadataSnapshot":{"metadataVersion":1}
        }),
    );
    for _ in 0..2 {
        alice
            .orchestrator
            .accept_conversation(&initial.conversation_id)
            .await
            .unwrap();
    }
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 0);
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 0);
    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(&initial.group_id).unwrap()));
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_group_object_with_stale_coordinates_is_recoverable_instead_of_active() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let initial = alice
        .orchestrator
        .create_group("existing", Some(&[bob.did.clone()]), None)
        .await
        .unwrap();
    let snapshot = json!({
        "conversationKind":"direct", "coordinates":{
            "conversationId":initial.conversation_id,"groupId":STANDARD.encode(hex::decode(&initial.group_id).unwrap()),
            "epoch":7,"stateVersion":8,"generation":0,"lifecycle":"active",
            "confirmationTag":STANDARD.encode([9;32]),"groupContextHash":STANDARD.encode([8;32])
        },
        "participants":[
            {"userDid":alice.did,"role":"admin","status":"active","leafCount":1},
            {"userDid":bob.did,"role":"admin","status":"active","leafCount":1}
        ],
        "leaves":[
            {"userDid":alice.did,"deviceId":alice.orchestrator.require_actor_device_id().await.unwrap(),"deviceStatus":"active"},
            {"userDid":bob.did,"deviceId":bob.orchestrator.require_actor_device_id().await.unwrap(),"deviceStatus":"active"}
        ],
        "metadataSnapshot":{"metadataVersion":1}
    });
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&initial.conversation_id, snapshot.clone());
    world.delivery_service().set_next_create_custom_response(200, json!({"result":{
        "$type":"blue.catbird.chat.defs#existingDirectConversationResult", "conversationKind":"direct",
        "conversationId":initial.conversation_id,"coordinates":snapshot["coordinates"]
    }}));
    let reopened = alice
        .orchestrator
        .create_group("reopen", Some(&[bob.did.clone()]), None)
        .await
        .unwrap();
    assert_eq!(reopened.conversation_id, initial.conversation_id);
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 1);
    assert_eq!(count(&world, CanonicalOperation::RequestReset), 0);
    assert_eq!(
        alice
            .storage
            .get_conversation_state(&initial.conversation_id)
            .await
            .unwrap(),
        Some(ConversationState::NeedsRejoin)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_from_pending_invitee_accepts_exact_authorized_pair() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let alice_device = alice.orchestrator.require_actor_device_id().await.unwrap();
    let initial = alice
        .orchestrator
        .create_group("existing", Some(&[bob.did.clone()]), None)
        .await
        .unwrap();
    world
        .delivery_service()
        .set_conversation_participants_for_test(
            &initial.conversation_id,
            vec![
                json!({"userDid":alice.did,"role":"admin","status":"active","leafCount":1}),
                json!({"userDid":bob.did,"role":"admin","status":"pending","leafCount":0,
                "invitationProvenance":{
                    "invitationTransitionId":"11111111-1111-4111-8111-111111111111",
                    "invitedByDid":alice.did,"invitedByDeviceId":alice_device
                }}),
            ],
        );
    world
        .delivery_service()
        .set_next_create_custom_response(400, json!({"error":"ConversationAlreadyExists"}));
    let reopened = bob
        .orchestrator
        .create_group("reopen", Some(&[alice.did.clone()]), None)
        .await
        .expect("adopt visible pending invitation");
    assert_eq!(reopened.conversation_id, initial.conversation_id);
    assert_eq!(reopened.group_id, initial.group_id);
    assert_eq!(count(&world, CanonicalOperation::AcceptConversation), 1);
    assert_eq!(
        bob.storage
            .get_conversation_state(&initial.conversation_id)
            .await
            .unwrap(),
        Some(ConversationState::NeedsRejoin)
    );
    assert!(
        bob.orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap()
            .is_empty(),
        "temporary create group was removed"
    );
    assert_eq!(bob.storage.pending_local_delete_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_without_entitled_match_does_not_claim_device_membership_or_accept() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    world
        .delivery_service()
        .set_next_create_custom_response(400, json!({"error":"ConversationAlreadyExists"}));
    let error = alice
        .orchestrator
        .create_group("existing", Some(&["did:plc:bob".into()]), None)
        .await
        .expect_err("no authorized match");
    assert!(!error.to_string().contains("this device has not been added"));
    assert!(error
        .to_string()
        .contains("Check your conversations and invitations"));
    assert_eq!(count(&world, CanonicalOperation::AcceptConversation), 0);
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 0);
    assert!(alice
        .orchestrator
        .mls_context()
        .list_local_group_ids()
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_duplicate_without_local_keys_requests_device_access_and_stays_recoverable() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let initial = alice
        .orchestrator
        .create_group("existing", Some(&[bob_did.clone()]), None)
        .await
        .unwrap();
    let did = alice.did.clone();
    world.add_client_with_did("Alice2", &did).await;
    world.register_device("Alice2").await.unwrap();
    world.delivery_service().set_next_create_custom_response(
        200,
        json!({"result":{
            "$type":"blue.catbird.chat.defs#existingDirectConversationResult",
            "conversationKind":"direct", "conversationId":initial.conversation_id,
            "coordinates":{"groupId":STANDARD.encode(hex::decode(&initial.group_id).unwrap())}
        }}),
    );
    let alice2 = world.client("Alice2");
    let reopened = alice2
        .orchestrator
        .create_group("reopen", Some(&[bob_did]), None)
        .await
        .unwrap();
    assert_eq!(reopened.conversation_id, initial.conversation_id);
    assert_eq!(count(&world, CanonicalOperation::RequestLeafRecovery), 1);
    assert_eq!(
        alice2
            .storage
            .get_conversation_state(&initial.conversation_id)
            .await
            .unwrap(),
        Some(ConversationState::NeedsRejoin)
    );
    assert!(alice2
        .orchestrator
        .mls_context()
        .list_local_group_ids()
        .unwrap()
        .is_empty());
}
