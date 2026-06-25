#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    ConversationReadyResult, ConversationRecoveryState, ConversationState,
};
use e2e_harness::TestWorld;

#[tokio::test(flavor = "multi_thread")]
async fn healthy_local_group_returns_send_allowed_without_recovery_io() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Ready", None, None)
        .await
        .expect("create_group failed");

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("healthy local group should be ready");

    assert_eq!(
        result,
        ConversationReadyResult {
            recovery_state: ConversationRecoveryState::Healthy,
            epoch: Some(0),
            send_allowed: true,
        }
    );
    assert_eq!(
        world
            .delivery_service()
            .welcome_fetch_count(&convo.conversation_id),
        0
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&convo.conversation_id),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_local_group_uses_welcome_before_external_commit() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    let _alice_did = world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("Welcome path", Some(&[bob_did.clone()]), None)
        .await
        .expect("create_group failed");

    let result = bob
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("welcome join should make conversation ready");

    assert_eq!(result.recovery_state, ConversationRecoveryState::Healthy);
    assert_eq!(result.epoch, Some(1));
    assert!(result.send_allowed);
    assert_eq!(
        world
            .delivery_service()
            .welcome_fetch_count(&convo.conversation_id),
        1
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&convo.conversation_id),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_without_welcome_attempts_bootstrap_before_external_commit() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Reset path", None, None)
        .await
        .expect("create_group failed");

    let new_group_id =
        hex::decode("00112233445566778899aabbccddeeff").expect("fixture must be valid hex");
    alice
        .orchestrator
        .record_group_reset(&convo.conversation_id, new_group_id, 1)
        .await
        .expect("record_group_reset failed");
    world
        .delivery_service()
        .clear_group_info_for_test(&convo.conversation_id);

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("readiness should surface recovery state instead of generic failure");

    assert!(matches!(
        result.recovery_state,
        ConversationRecoveryState::ResetPending | ConversationRecoveryState::UnrecoverableLocal
    ));
    assert_eq!(result.epoch, None);
    assert!(!result.send_allowed);
    assert_eq!(
        world
            .delivery_service()
            .welcome_fetch_count(&convo.conversation_id),
        1
    );
    assert_eq!(
        world
            .delivery_service()
            .bootstrap_reset_group_call_count(&convo.conversation_id),
        1
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&convo.conversation_id),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn needs_rejoin_returns_recovery_vocabulary_instead_of_generic_error() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Needs rejoin", None, None)
        .await
        .expect("create_group failed");

    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(
            convo.conversation_id.clone(),
            ConversationState::NeedsRejoin,
        );

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("needs_rejoin should project a recovery state");

    assert_eq!(
        result.recovery_state,
        ConversationRecoveryState::NeedsRejoin
    );
    assert!(!result.send_allowed);
}

#[tokio::test(flavor = "multi_thread")]
async fn unrecoverable_local_returns_recovery_vocabulary_without_attempting_rejoin() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Failed state", None, None)
        .await
        .expect("create_group failed");

    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(convo.conversation_id.clone(), ConversationState::Failed);

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("failed state should project unrecoverable-local");

    assert_eq!(
        result.recovery_state,
        ConversationRecoveryState::UnrecoverableLocal
    );
    assert!(!result.send_allowed);
    assert_eq!(
        world
            .delivery_service()
            .welcome_fetch_count(&convo.conversation_id),
        0
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&convo.conversation_id),
        0
    );
}
