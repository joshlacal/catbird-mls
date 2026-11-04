//! Local-delete durability tests use the internal cleanup boundary directly.
//!
//! Public account exit retains a terminal conversation projection and is not
//! the destructive cleanup operation whose retry intent is exercised here.

use std::sync::Arc;

use crate::orchestrator::{
    constants, ConversationState, CredentialStore, GroupState, MLSOrchestrator, MLSStorageBackend,
    OrchestratorConfig, PersistedRecoveryBackoff,
};
use crate::recovery_e2e_harness::TestWorld;
use crate::GroupConfig;

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

// The three lifecycle-bound cleanup tests below came from
// tests/resolved_conversation_context_tests.rs, where they drove cleanup via
// `leave_group`. Since 0b6b4e90 that is the canonical account exit, which
// retains native state (b37ace4d), so they call the cleanup boundary.

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_local_delete_removes_every_materialized_predecessor_and_target() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");

    let conversation = alice
        .orchestrator
        .create_group("reset-pending local delete", None, None)
        .await
        .expect("create predecessor group");
    let conversation_id = conversation.conversation_id.clone();
    let predecessor_group = hex::decode(&conversation.group_id).expect("predecessor group id");
    let mls_did = alice
        .credentials
        .get_mls_did(&alice.did)
        .await
        .expect("read Alice MLS DID")
        .expect("registered Alice MLS DID");

    // Simulate an additional locally materialized predecessor left by an
    // interrupted earlier transition. Its explicit stable-conversation
    // binding is the only durable discovery path for its epoch secrets.
    let older_predecessor = vec![0x31; 32];
    let older_predecessor_id = hex::encode(&older_predecessor);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.clone().into_bytes(),
            older_predecessor.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize older predecessor");
    alice.orchestrator.group_states().lock().await.insert(
        older_predecessor_id.clone(),
        GroupState {
            group_id: older_predecessor_id,
            conversation_id: conversation_id.clone(),
            epoch: 0,
            members: vec![alice.did.clone()],
        },
    );

    // Reproduce the crash window after the atomic reset authority commit but
    // before record_group_reset deleted the old local groups. The durable
    // conversation mapping still names the predecessor while reset authority
    // names a distinct, already materialized target.
    let reset_target = vec![0x32; 32];
    let reset_target_id = hex::encode(&reset_target);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.into_bytes(),
            reset_target.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize reset target");
    alice
        .storage
        .mark_reset_pending(&conversation_id, &reset_target_id, 7, 1_700_000_000_000)
        .await
        .expect("commit reset authority");

    for group_id in [&predecessor_group, &older_predecessor, &reset_target] {
        assert!(alice
            .orchestrator
            .mls_context()
            .group_exists(group_id.clone()));
    }

    alice
        .orchestrator
        .force_delete_local(&conversation_id)
        .await
        .expect("local delete must clean every lifecycle-bound local group");

    for (label, group_id) in [
        ("mapped predecessor", predecessor_group),
        ("older bound predecessor", older_predecessor),
        ("reset target", reset_target),
    ] {
        assert!(
            !alice.orchestrator.mls_context().group_exists(group_id),
            "local delete must remove {label} before dropping reset authority"
        );
    }
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .is_none(),
        "successful cleanup may clear reset authority only after all local groups are gone"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &conversation_id)
            .await
            .expect("read durable conversation")
            .is_none(),
        "successful cleanup removes the durable conversation mapping"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_delete_rediscovers_all_persisted_predecessors_after_intent_crash() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("restart-safe predecessor delete", None, None)
        .await
        .expect("create mapped predecessor");
    let conversation_id = conversation.conversation_id.clone();
    let mapped_predecessor = hex::decode(&conversation.group_id).expect("mapped predecessor");
    let mls_did = alice
        .credentials
        .get_mls_did(&alice.did)
        .await
        .expect("read MLS DID")
        .expect("registered MLS DID");

    let extra_predecessor = vec![0x41; 32];
    let extra_predecessor_id = hex::encode(&extra_predecessor);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.clone().into_bytes(),
            extra_predecessor.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize extra predecessor");
    let extra_state = GroupState {
        group_id: extra_predecessor_id.clone(),
        conversation_id: conversation_id.clone(),
        epoch: 0,
        members: vec![alice.did.clone()],
    };
    alice
        .storage
        .set_group_state(&extra_state)
        .await
        .expect("persist extra predecessor binding");
    alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .insert(extra_predecessor_id.clone(), extra_state);

    let reset_target = vec![0x42; 32];
    let reset_target_id = hex::encode(&reset_target);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.into_bytes(),
            reset_target.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize reset target");
    alice
        .storage
        .mark_reset_pending(&conversation_id, &reset_target_id, 9, 1_700_000_000_000)
        .await
        .expect("commit reset authority");
    // Force the exact reset clear CAS to lose its race after the captured MLS
    // groups and group-state rows were deleted. This preserves the pending
    // intent, reset authority, and durable conversation mapping at the crash
    // point. The retry intent must therefore remain complete and idempotent
    // even though no live projection can rediscover the captured groups.
    alice
        .storage
        .force_next_clear_reset_pending_for_delete_false();
    let deletion_error = alice
        .orchestrator
        .force_delete_local(&conversation_id)
        .await
        .expect_err("local delete must surface incomplete lifecycle-bound deletion");
    assert!(
        deletion_error
            .to_string()
            .contains("durable retry intent retained"),
        "unexpected incomplete deletion error: {deletion_error}"
    );
    assert_eq!(alice.storage.pending_local_delete_count(), 1);
    assert!(
        !alice.storage.has_group_state(&extra_predecessor_id),
        "exact group-state cleanup completes before the reset-generation CAS"
    );
    for group_id in [&mapped_predecessor, &extra_predecessor, &reset_target] {
        assert!(!alice
            .orchestrator
            .mls_context()
            .group_exists(group_id.clone()));
    }

    // Crash before reset/conversation cleanup. A fresh process has no
    // in-memory group-state cache and the groups are already absent from its
    // MLS manifest, so only the durable intent can complete the exact
    // lifecycle-bound cleanup.
    world.restart_client("Alice").await;
    let alice = world.client("Alice");

    for (label, group_id) in [
        ("mapped predecessor", mapped_predecessor),
        ("persisted extra predecessor", extra_predecessor),
        ("reset target", reset_target),
    ] {
        assert!(
            !alice.orchestrator.mls_context().group_exists(group_id),
            "startup reconcile must delete {label} before clearing its intent"
        );
    }
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        !alice.storage.has_group_state(&extra_predecessor_id),
        "startup retry must remove stale predecessor group-state rows named only by the durable intent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_local_delete_from_alice_never_replays_in_bob_lifecycle() {
    let bob_did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    // Only Bob's native context is used: a separate lifecycle that shares
    // Alice's app storage.
    world.add_client_with_did("Bob", bob_did).await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("tenant-bound pending delete", None, None)
        .await
        .expect("create Alice group");
    let conversation_id = conversation.conversation_id.clone();
    let target = vec![0x51; 32];
    let target_id = hex::encode(&target);
    alice
        .storage
        .mark_reset_pending(&conversation_id, &target_id, 11, 1_700_000_000_000)
        .await
        .expect("commit Alice reset authority");
    alice
        .storage
        .force_next_clear_reset_pending_for_delete_false();
    let deletion_error = alice
        .orchestrator
        .force_delete_local(&conversation_id)
        .await
        .expect_err("Alice's incomplete deletion must remain visible to her lifecycle");
    assert!(
        deletion_error
            .to_string()
            .contains("durable retry intent retained"),
        "unexpected incomplete deletion error: {deletion_error}"
    );
    assert_eq!(alice.storage.pending_local_delete_count(), 1);

    let bob_context = Arc::clone(world.client("Bob").orchestrator.mls_context());
    bob_context
        .create_group_with_id(
            bob_did.as_bytes().to_vec(),
            target.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize Bob group at colliding bytes");
    let bob_orchestrator = MLSOrchestrator::new(
        bob_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(bob_did)),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );
    bob_orchestrator
        .initialize(bob_did)
        .await
        .expect("Bob initialization must leave Alice cleanup pending");

    assert!(
        bob_orchestrator.mls_context().group_exists(target),
        "Alice's pending delete must never remove Bob's group at colliding bytes"
    );
    assert_eq!(
        alice.storage.pending_local_delete_count(),
        1,
        "tenant mismatch must keep Alice's intent for an Alice lifecycle"
    );
}
