#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    error::OrchestratorError, ConversationReadyResult, ConversationRecoveryState, ConversationState,
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
async fn durable_reset_pending_existing_target_after_suspend_stays_not_ready() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Reset predecessor", None, None)
        .await
        .expect("create predecessor group");
    let target = alice
        .orchestrator
        .create_group("Materialized reset target", None, None)
        .await
        .expect("create reset target group");

    alice
        .orchestrator
        .record_group_reset(
            &convo.conversation_id,
            hex::decode(&target.group_id).expect("target group id must be hex"),
            41,
        )
        .await
        .expect("persist ResetPending");
    alice.orchestrator.suspend().await.expect("suspend");
    alice
        .orchestrator
        .resume_after_suspend(&did)
        .await
        .expect("resume");

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("durable ResetPending should project as not ready");

    assert_eq!(
        result,
        ConversationReadyResult {
            recovery_state: ConversationRecoveryState::ResetPending,
            epoch: None,
            send_allowed: false,
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_reset_authority_read_failure_after_suspend_propagates_closed() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Unreadable reset predecessor", None, None)
        .await
        .expect("create predecessor group");
    let target = alice
        .orchestrator
        .create_group("Unreadable reset target", None, None)
        .await
        .expect("create reset target group");

    alice
        .orchestrator
        .record_group_reset(
            &convo.conversation_id,
            hex::decode(&target.group_id).expect("target group id must be hex"),
            42,
        )
        .await
        .expect("persist ResetPending");
    alice.orchestrator.suspend().await.expect("suspend");
    alice
        .orchestrator
        .resume_after_suspend(&did)
        .await
        .expect("resume");
    alice
        .storage
        .fail_next_get_conversation_state_for(&convo.conversation_id);

    let error = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect_err("unreadable durable reset authority must fail closed");

    assert!(matches!(error, OrchestratorError::Storage(_)));
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
        .create_group("Welcome path", None, None)
        .await
        .expect("create_group failed");
    alice
        .orchestrator
        .add_members(&convo.conversation_id, &[bob_did.clone()])
        .await
        .expect("add bob");

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
        hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").expect("fixture must be valid hex");
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

    assert_eq!(result.recovery_state, ConversationRecoveryState::Healthy);
    assert_eq!(result.epoch, Some(0));
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
async fn stale_needs_rejoin_on_healthy_local_group_clears_without_recovery_io() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Needs rejoin", None, None)
        .await
        .expect("create_group failed");
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&convo.conversation_id, 0);

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
        .expect("stale needs_rejoin on a healthy local group should clear");

    assert_eq!(
        result,
        ConversationReadyResult {
            recovery_state: ConversationRecoveryState::Healthy,
            epoch: Some(1),
            send_allowed: true,
        }
    );
    assert_eq!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&convo.conversation_id),
        Some(&ConversationState::Active)
    );
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
async fn needs_rejoin_survives_local_epoch_probe_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Needs rejoin closed context", None, None)
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

    alice
        .orchestrator
        .mls_context()
        .flush_and_prepare_close()
        .expect("closing test context should succeed");

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("needs-rejoin should survive epoch probe failures");

    assert_eq!(
        result,
        ConversationReadyResult {
            recovery_state: ConversationRecoveryState::NeedsRejoin,
            epoch: None,
            send_allowed: false,
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_survives_local_epoch_probe_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Reset pending closed context", None, None)
        .await
        .expect("create_group failed");

    let new_group_id =
        hex::decode("11223344556677889900aabbccddeeff").expect("fixture must be valid hex");
    alice
        .orchestrator
        .record_group_reset(&convo.conversation_id, new_group_id, 1)
        .await
        .expect("record_group_reset failed");

    alice
        .orchestrator
        .mls_context()
        .flush_and_prepare_close()
        .expect("closing test context should succeed");

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("reset-pending should survive epoch probe failures");

    assert_eq!(
        result,
        ConversationReadyResult {
            recovery_state: ConversationRecoveryState::ResetPending,
            epoch: None,
            send_allowed: false,
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn epoch_behind_survives_local_epoch_probe_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Fork detected closed context", None, None)
        .await
        .expect("create_group failed");

    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(
            convo.conversation_id.clone(),
            ConversationState::ForkDetected,
        );

    alice
        .orchestrator
        .mls_context()
        .flush_and_prepare_close()
        .expect("closing test context should succeed");

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("fork-detected should survive epoch probe failures");

    assert_eq!(
        result,
        ConversationReadyResult {
            recovery_state: ConversationRecoveryState::EpochBehind,
            epoch: None,
            send_allowed: false,
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn join_or_rejoin_failure_returns_non_ready_non_healthy_result() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    let _alice_did = world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("Recovery failure", Some(&[bob_did.clone()]), None)
        .await
        .expect("create_group failed");

    world.delivery_service().fail_next_get_welcome();
    world
        .delivery_service()
        .clear_group_info_for_test(&convo.conversation_id);

    let result = bob
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("non-ready recovery state should be returned instead of a generic failure");

    assert!(!result.send_allowed);
    assert_ne!(result.recovery_state, ConversationRecoveryState::Healthy);
    assert_eq!(result.epoch, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn known_non_ready_state_survives_local_epoch_probe_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Closed context", None, None)
        .await
        .expect("create_group failed");

    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(convo.conversation_id.clone(), ConversationState::Failed);

    alice
        .orchestrator
        .mls_context()
        .flush_and_prepare_close()
        .expect("closing test context should succeed");

    let result = alice
        .orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("known non-ready states should survive epoch probe failures");

    assert_eq!(
        result.recovery_state,
        ConversationRecoveryState::UnrecoverableLocal
    );
    assert_eq!(result.epoch, None);
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
