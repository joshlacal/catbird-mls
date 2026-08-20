//! Direct-Welcome conversation lookup must traverse bounded pagination rather
//! than assuming the target is present in the first 100 conversations.

mod e2e_harness;

use catbird_mls::orchestrator::{MLSAPIClient, MLSStorageBackend, OrchestratorError};
use catbird_mls::MLSError;
use chrono::{Duration, Utc};
use e2e_harness::TestWorld;

#[derive(Clone, Copy)]
enum JoinWriteFailure {
    SetGroupState,
    EnsureConversation,
    UpdateJoinInfo,
}

impl JoinWriteFailure {
    fn injected_error(self) -> &'static str {
        match self {
            Self::SetGroupState => "injected set_group_state failure",
            Self::EnsureConversation => "injected ensure_conversation_exists failure",
            Self::UpdateJoinInfo => "injected update_join_info failure",
        }
    }
}

async fn assert_failed_join_is_fully_rolled_back(failure: JoinWriteFailure) {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let target = world
        .client("Alice")
        .orchestrator
        .create_group("welcome-write-rollback", None, None)
        .await
        .expect("create target conversation");
    world
        .client("Alice")
        .orchestrator
        .add_members(&target.conversation_id, std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let bob = world.client("Bob");
    let welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&target.conversation_id)
        .await
        .expect("fetch Bob's Welcome");

    match failure {
        JoinWriteFailure::SetGroupState => bob.storage.fail_next_set_group_state(),
        JoinWriteFailure::EnsureConversation => {
            bob.storage.fail_next_ensure_conversation_exists();
        }
        JoinWriteFailure::UpdateJoinInfo => bob.storage.fail_next_update_join_info(),
    }

    let error = bob
        .orchestrator
        .join_group(&welcome)
        .await
        .expect_err("injected durable-write failure must reject the Welcome");
    assert!(
        error.to_string().contains(failure.injected_error()),
        "unexpected join error: {error}"
    );

    let group_id = hex::decode(&target.group_id).unwrap();
    assert!(
        !bob.orchestrator
            .mls_context()
            .group_exists(group_id.clone()),
        "failed join must durably delete the just-processed OpenMLS group"
    );
    let encrypt_error = match bob
        .orchestrator
        .mls_context()
        .encrypt_message(group_id, b"must not encrypt".to_vec())
    {
        Ok(_) => panic!("rolled-back group must not remain usable for encryption"),
        Err(error) => error,
    };
    assert!(matches!(encrypt_error, MLSError::GroupNotFound { .. }));

    assert!(
        !bob.orchestrator
            .conversations()
            .lock()
            .await
            .contains_key(&target.conversation_id),
        "failed join must not publish a conversation cache entry"
    );
    assert!(
        !bob.orchestrator
            .group_states()
            .lock()
            .await
            .contains_key(&target.group_id),
        "failed join must not publish a GroupState cache entry"
    );
    assert!(
        !bob.storage.has_group_state(&target.group_id),
        "failed join must compensate the durable GroupState write"
    );
    assert!(
        bob.storage
            .get_conversation(&bob.did, &target.conversation_id)
            .await
            .expect("read durable conversation after rollback")
            .is_none(),
        "failed join must compensate a newly-created conversation projection"
    );

    let send_error = bob
        .orchestrator
        .send_message(&target.conversation_id, "must not send")
        .await
        .expect_err("failed join must not be resolvable by the send path");
    assert!(matches!(
        send_error,
        OrchestratorError::NotJoined { convo_id } if convo_id == target.conversation_id
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn join_group_finds_welcome_target_beyond_first_conversation_page() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let bob = world.client("Bob");
    for index in 0..100 {
        bob.orchestrator
            .api_client()
            .create_conversation(&format!("filler-{index:03}"), None, None, None, None)
            .await
            .expect("create filler conversation");
    }

    let target = world
        .client("Alice")
        .orchestrator
        .create_group("welcome-page-two", None, None)
        .await
        .expect("create target conversation");
    world
        .client("Alice")
        .orchestrator
        .add_members(&target.conversation_id, std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    world
        .delivery_service()
        .set_conversation_created_at_for_test(
            &target.conversation_id,
            Utc::now() + Duration::days(1),
        );

    let welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&target.conversation_id)
        .await
        .expect("fetch Bob's Welcome");
    let joined = bob
        .orchestrator
        .join_group(&welcome)
        .await
        .expect("bounded lookup must reach the second page");

    assert_eq!(joined.conversation_id, target.conversation_id);
    assert_eq!(joined.group_id, target.group_id);
    assert!(bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(&target.group_id).unwrap()));
}

#[tokio::test(flavor = "multi_thread")]
async fn join_group_rolls_back_crypto_state_when_conversation_lookup_fails() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let target = world
        .client("Alice")
        .orchestrator
        .create_group("welcome-lookup-rollback", None, None)
        .await
        .expect("create target conversation");
    world
        .client("Alice")
        .orchestrator
        .add_members(&target.conversation_id, std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let bob = world.client("Bob");
    let welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&target.conversation_id)
        .await
        .expect("fetch Bob's Welcome");
    world
        .delivery_service()
        .remove_conversation_for_test(&target.conversation_id);

    let error = bob
        .orchestrator
        .join_group(&welcome)
        .await
        .expect_err("missing conversation mapping must reject the Welcome");
    assert!(error.to_string().contains("Conversation not found"));
    assert!(
        !bob.orchestrator
            .mls_context()
            .group_exists(hex::decode(&target.group_id).unwrap()),
        "failed lookup must delete the just-processed Welcome group"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn join_group_set_group_state_failure_rolls_back_the_whole_join() {
    assert_failed_join_is_fully_rolled_back(JoinWriteFailure::SetGroupState).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn join_group_conversation_write_failure_rolls_back_the_whole_join() {
    assert_failed_join_is_fully_rolled_back(JoinWriteFailure::EnsureConversation).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn join_group_join_info_failure_rolls_back_the_whole_join() {
    assert_failed_join_is_fully_rolled_back(JoinWriteFailure::UpdateJoinInfo).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn join_or_rejoin_projection_failure_withholds_cache_and_active_success() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let target = world
        .client("Alice")
        .orchestrator
        .create_group("welcome-recovery-persist-first", None, None)
        .await
        .expect("create target conversation");
    world
        .client("Alice")
        .orchestrator
        .add_members(&target.conversation_id, std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let bob = world.client("Bob");
    bob.storage.fail_next_set_group_state();

    let error = bob
        .orchestrator
        .join_or_rejoin(&target.conversation_id)
        .await
        .expect_err("durable projection failure must reject Welcome recovery success");
    assert!(
        error
            .to_string()
            .contains("injected set_group_state failure"),
        "unexpected recovery error: {error}"
    );
    assert!(
        !bob.orchestrator
            .group_states()
            .lock()
            .await
            .contains_key(&target.group_id),
        "failed durable projection must not publish a GroupState cache entry"
    );
    assert!(
        !bob.storage.has_group_state(&target.group_id),
        "failed durable projection must not be reported as persisted"
    );
    assert!(
        bob.storage.has_rejoin_flag(&target.conversation_id),
        "failed post-Welcome projection must enter durable recovery"
    );
}
