//! Local-delete durability tests use the internal cleanup boundary directly.
//!
//! Public account exit retains a terminal conversation projection and is not
//! the destructive cleanup operation whose retry intent is exercised here.

use crate::orchestrator::{
    constants, ConversationState, MLSStorageBackend, OrchestratorConfig, PersistedRecoveryBackoff,
};
use crate::recovery_e2e_harness::TestWorld;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Normal force_delete_local path: intent is written and then cleared, so a
/// healthy run leaves no pending rows behind.
#[tokio::test(flavor = "multi_thread")]
async fn force_delete_local_clears_its_intent() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.3 intent", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Exercise the private cleanup boundary without introducing account-exit
    // proof or server lifecycle requirements into the local durability test.
    alice
        .orchestrator
        .force_delete_local(&convo_id)
        .await
        .expect("local cleanup should succeed");

    assert_eq!(
        alice.storage.pending_local_delete_count(),
        0,
        "force_delete_local must clear its intent after completing"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &convo_id)
            .await
            .unwrap()
            .is_none(),
        "local cleanup should delete the local conversation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_pending_delete_intent_write_refuses_destructive_cleanup() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("intent write failure", None, None)
        .await
        .expect("create group");
    let conversation_id = conversation.conversation_id.clone();
    let group_id = hex::decode(&conversation.group_id).expect("group id");
    alice.storage.fail_next_mark_pending_local_delete();

    let deletion_error = alice
        .orchestrator
        .force_delete_local(&conversation_id)
        .await
        .expect_err("intent-write failure must surface incomplete cleanup");
    assert!(
        deletion_error.to_string().contains("local deletion")
            && deletion_error.to_string().contains("incomplete"),
        "unexpected cleanup error: {deletion_error}"
    );

    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        alice.orchestrator.mls_context().group_exists(group_id),
        "without a durable retry intent, local MLS secrets must not be deleted"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &conversation_id)
            .await
            .expect("read conversation")
            .is_some(),
        "without a durable retry intent, the conversation mapping must remain discoverable"
    );
}

/// FIX-5: a real delete-step failure keeps the pending-delete intent so the
/// next pass retries; the retry (where the missing MLS group is a
/// NotFound-class success) completes and clears the intent.
#[tokio::test(flavor = "multi_thread")]
async fn failed_delete_step_keeps_intent_then_retry_clears_it() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("FIX-5 keep intent", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // First pass: storage delete fails — the intent must survive.
    alice.storage.fail_next_delete_conversations();
    let deletion_error = alice
        .orchestrator
        .force_delete_local(&convo_id)
        .await
        .expect_err("cleanup must surface incomplete local deletion");
    assert!(
        deletion_error
            .to_string()
            .contains("durable retry intent retained"),
        "unexpected deletion failure: {deletion_error}"
    );
    assert_eq!(
        alice.storage.pending_local_delete_count(),
        1,
        "FIX-5 REGRESSION: pending-delete intent was cleared even though a \
         delete step failed"
    );

    // Reopen the same native database. The startup sweep finds the deleted
    // MLS group absent and retries the application storage deletion.
    world.restart_client("Alice").await;
    let alice = world.client("Alice");
    assert_eq!(
        alice.storage.pending_local_delete_count(),
        0,
        "startup sweep retry must complete the delete and clear the intent"
    );
    assert!(alice
        .storage
        .get_conversation(&alice.did, &convo_id)
        .await
        .unwrap()
        .is_none());
}

/// A force-delete pass must not treat a failed reset-authority read as
/// evidence that no committed reset row exists. Otherwise it can report
/// success, clear its retry intent, and strand the committed row forever.
#[tokio::test(flavor = "multi_thread")]
async fn reset_authority_read_failure_keeps_delete_intent_and_committed_reset() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("generation-bound delete", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    alice
        .storage
        .mark_reset_pending(&convo_id, &"ab".repeat(32), 2, now_ms())
        .await
        .expect("seed committed reset authority");
    alice
        .storage
        .fail_get_conversation_state_after_successful_reads(&convo_id, 2);
    let deletion_error = alice
        .orchestrator
        .force_delete_local(&convo_id)
        .await
        .expect_err("unreadable reset authority must surface incomplete cleanup");
    assert!(
        deletion_error.to_string().contains("incomplete"),
        "unexpected cleanup error: {deletion_error}"
    );

    assert_eq!(
        alice.storage.pending_local_delete_count(),
        1,
        "reset-authority read failure must keep the delete intent"
    );
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .expect("committed reset authority must survive")
            .reset_generation,
        2
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_delete_generation_mismatch_keeps_intent_then_retry_clears_without_active() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("generation mismatch delete retry", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    alice
        .orchestrator
        .record_group_reset(&convo_id, vec![0xcd; 32], 7)
        .await
        .expect("commit reset authority");
    alice
        .storage
        .force_next_clear_reset_pending_for_delete_false();
    let deletion_error = alice
        .orchestrator
        .force_delete_local(&convo_id)
        .await
        .expect_err("generation mismatch must surface retained cleanup work");
    assert!(
        deletion_error.to_string().contains("incomplete"),
        "unexpected cleanup error: {deletion_error}"
    );
    assert_eq!(alice.storage.pending_local_delete_count(), 1);
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .expect("mismatched delete CAS must preserve reset authority")
            .reset_generation,
        7
    );
    assert!(
        !matches!(
            alice
                .storage
                .get_conversation_state(&convo_id)
                .await
                .expect("durable reset remains readable"),
            Some(ConversationState::Active)
        ),
        "delete-specific reset cleanup must never project Active"
    );

    world.restart_client("Alice").await;
    let alice = world.client("Alice");
    assert_eq!(
        alice.storage.pending_local_delete_count(),
        0,
        "startup retry must clear the exact reset generation and delete intent"
    );
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .is_none(),
        "retry must remove the committed reset payload"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &convo_id)
            .await
            .unwrap()
            .is_none(),
        "retry must leave the conversation deleted, not Active"
    );
}

/// FIX-6: force_delete_local must also delete the conversation's recovery
/// state. A maxed-out backoff row left behind would be re-imported by
/// hydration and gate a re-added conversation with the same server
/// conversation_id.
#[tokio::test(flavor = "multi_thread")]
async fn local_delete_clears_recovery_state_no_ghost_after_restart() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("FIX-6 recovery cleanup", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let max = OrchestratorConfig::default().max_rejoin_attempts;
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: convo_id.clone(),
            failed_rejoin_count: max,
            last_attempt_at_ms: now_ms(),
            quarantined_until_ms: Some(
                now_ms() + constants::RECOVERY_BACKOFF_TTL.as_millis() as i64,
            ),
        });

    // The private cleanup contract must clear recovery state together with
    // the local conversation, without depending on account-exit semantics.
    alice
        .orchestrator
        .force_delete_local(&convo_id)
        .await
        .expect("local cleanup should succeed");

    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff(&convo_id)
            .is_none(),
        "FIX-6 REGRESSION: local delete left the persisted backoff row behind"
    );

    world.restart_client("Alice").await;
    let alice = world.client("Alice");
    {
        let tracker = alice.orchestrator.recovery_tracker().lock().await;
        assert!(
            !tracker.is_maxed_out(&convo_id),
            "FIX-6 REGRESSION: hydration re-imported recovery state for a \
             deleted conversation"
        );
        assert_eq!(tracker.failed_attempts(&convo_id), 0);
        assert!(!tracker.should_skip(&convo_id));
    }
}
