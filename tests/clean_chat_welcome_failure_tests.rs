//! Transient control-plane read failures must not authorize membership mutation.
#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use e2e_harness::TestWorld;

#[tokio::test(flavor = "multi_thread")]
async fn welcome_read_failure_preserves_error_without_external_commit_or_reset() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("read failure", None, None)
        .await
        .unwrap();
    let did = alice.did.clone();
    world.add_client_with_did("AlicePhone", &did).await;
    world.register_device("AlicePhone").await.unwrap();
    world.delivery_service().fail_next_get_welcome();

    let error = world
        .client("AlicePhone")
        .orchestrator
        .join_or_rejoin(&conversation.conversation_id)
        .await
        .expect_err("a failed Welcome read must remain a failed read");

    assert!(
        error.to_string().contains("injected get_welcome failure"),
        "original error lost: {error}"
    );
    assert_eq!(
        world
            .delivery_service()
            .get_group_info_call_count(&conversation.conversation_id),
        0
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation.conversation_id),
        0
    );
    assert!(
        !world
            .delivery_service()
            .submitted_prepared_requests()
            .iter()
            .any(|request| {
                matches!(
                    request.operation,
                    CanonicalOperation::RequestReset
                        | CanonicalOperation::ActivateReset
                        | CanonicalOperation::RequestLeafRecovery
                )
            }),
        "transient failure must not mutate recovery state on the server"
    );
    assert_eq!(
        world
            .delivery_service()
            .conversation_epoch(&conversation.conversation_id),
        Some(0)
    );
}
