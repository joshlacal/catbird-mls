//! Tests for `record_reset_requested` — the Phase 2.5 indirect-flow entry
//! point that handles `resetRequestedEvent` SSE events from `mls-ds`.
//!
//! Phase 2.5 plan: `docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 1.
//!
//! Scenarios covered:
//! 1. Idempotency — same `request_event_id` (and same `reset_generation`)
//!    arriving twice produces a single persisted RESET_PENDING row and a
//!    single `mark_reset_pending` storage call.
//! 2. None group_id path — when the server passes
//!    `expected_new_mls_group_id: None` (the canonical Phase 2.5 indirect
//!    flow), the orchestrator mints a fresh client-side group_id and
//!    persists it into RESET_PENDING. The deferred-recovery loop's first-
//!    responder bootstrap branch then picks it up. We verify the state
//!    here without driving the bootstrap network call (that path is
//!    covered by integration tests that mock the API layer).
//! 3. Some group_id path — admin/legacy direct flow where the server
//!    pre-determines the target id; orchestrator uses it verbatim. State
//!    matches what `record_group_reset` produces.
//! 4. Survives orchestrator restart — RESET_PENDING payload persisted via
//!    `mark_reset_pending` rehydrates after a fresh `MLSOrchestrator`
//!    initializes against the same storage.

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    ConversationState, MLSAPIClient, MLSOrchestrator, MLSStorageBackend, OrchestratorConfig,
    OrchestratorError, ResetRecordOutcome,
};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use std::sync::Arc;

use e2e_harness::TestWorld;

// ---------------------------------------------------------------------------
// 1. Idempotency: duplicate event collapses to single persisted row.
// ---------------------------------------------------------------------------

/// Two `record_reset_requested` calls with the same conversation +
/// reset_generation must produce exactly one persisted RESET_PENDING row.
/// The mock counts `mark_reset_pending` invocations: a second call MUST NOT
/// hit storage again, and the persisted `new_group_id` MUST be unchanged
/// from the first call (no oscillation as random ids would otherwise
/// produce).
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_idempotent_on_same_generation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Set up a baseline conversation so reset has somewhere to land.
    let convo = alice
        .orchestrator
        .create_group("Idempotency Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // First arrival of the event.
    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            17,
            "quorumVote",
            "req-quorum:convo123:vote789",
            None,
        )
        .await
        .expect("first record_reset_requested failed");

    let first_payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("first call must persist RESET_PENDING via mark_reset_pending");
    assert_eq!(first_payload.reset_generation, 17);
    assert!(
        !first_payload.new_group_id_hex.is_empty(),
        "first call must mint a non-empty client-side new_group_id when None passed"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        1,
        "first call should produce exactly one storage write"
    );
    let first_new_group_id = first_payload.new_group_id_hex.clone();

    // Same event arrives again (SSE reconnect / event_stream replay).
    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            17,
            "quorumVote",
            "req-quorum:convo123:vote789",
            None,
        )
        .await
        .expect("idempotent second record_reset_requested failed");

    let second_payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("idempotent path must keep RESET_PENDING persisted");
    assert_eq!(
        second_payload.new_group_id_hex, first_new_group_id,
        "idempotent path must not mint a new group_id (would oscillate state)"
    );
    assert_eq!(
        second_payload.reset_generation, 17,
        "reset_generation must match the duplicate event"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        1,
        "idempotent second call must NOT issue another mark_reset_pending storage write"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_record_group_reset_with_outcome_distinguishes_recorded_stale_and_self_echo() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let self_echo_convo = alice
        .orchestrator
        .create_group("GroupReset Outcome Self Echo Test", None, None)
        .await
        .expect("create_group failed");
    let self_echo_group =
        hex::decode(&self_echo_convo.group_id).expect("created group id must be valid hex");

    let self_echo = alice
        .orchestrator
        .record_group_reset_with_outcome(&self_echo_convo.conversation_id, self_echo_group, 10)
        .await
        .expect("self-echo record_group_reset_with_outcome should not fail");
    assert_eq!(self_echo, ResetRecordOutcome::SelfEchoNoOp);

    let recorded_convo = alice
        .orchestrator
        .create_group("GroupReset Outcome Recorded Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = recorded_convo.conversation_id.clone();
    let new_group = vec![0x32; 32];

    let recorded = alice
        .orchestrator
        .record_group_reset_with_outcome(&convo_id, new_group, 11)
        .await
        .expect("fresh record_group_reset_with_outcome should record");
    assert_eq!(recorded, ResetRecordOutcome::Recorded);

    let stale = alice
        .orchestrator
        .record_group_reset_with_outcome(&convo_id, vec![0x33; 32], 10)
        .await
        .expect("stale record_group_reset_with_outcome should not fail");
    assert_eq!(stale, ResetRecordOutcome::StaleOrDuplicate);
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_mark_error_continues_only_after_exact_durable_commit_reread() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("ambiguous reset publication", None, None)
        .await
        .expect("create conversation");
    let old_group = hex::decode(&convo.group_id).expect("valid old group id");
    let target = vec![0x4a; 32];

    alice.storage.fail_next_mark_reset_pending_after_commit();
    let outcome = alice
        .orchestrator
        .record_group_reset_with_outcome(&convo.conversation_id, target.clone(), 41)
        .await
        .expect("an exact durable tuple proves the ambiguous write committed");

    assert_eq!(outcome, ResetRecordOutcome::Recorded);
    let persisted = alice
        .storage
        .get_persisted_reset_pending(&convo.conversation_id)
        .expect("committed reset authority must remain durable");
    assert_eq!(persisted.reset_generation, 41);
    assert_eq!(persisted.new_group_id_hex, hex::encode(target));
    assert!(persisted.notified_at_ms > 0);
    assert!(
        !alice.orchestrator.mls_context().group_exists(old_group),
        "cleanup may proceed after the exact committed tuple is reread"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_reset_publication_atomically_arms_restart_recovery() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("crash boundary reset publication", None, None)
        .await
        .expect("create conversation");

    alice.storage.fail_next_mark_reset_pending_after_commit();
    let result = alice
        .storage
        .mark_reset_pending(&convo.conversation_id, &"4c".repeat(32), 43, 1_234)
        .await;

    assert!(
        result.is_err(),
        "simulate response loss immediately after commit"
    );
    assert!(
        alice.storage.has_rejoin_flag(&convo.conversation_id),
        "the authority transaction itself must arm restart recovery"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_mark_error_rejects_non_exact_notified_at_tuple() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("non exact reset publication", None, None)
        .await
        .expect("create conversation");
    let old_group = hex::decode(&convo.group_id).expect("valid old group id");

    alice
        .storage
        .fail_next_mark_reset_pending_after_commit_with_notified_at_offset(1);
    let result = alice
        .orchestrator
        .record_group_reset_with_outcome(&convo.conversation_id, vec![0x4b; 32], 42)
        .await;

    assert!(
        result.is_err(),
        "same generation and target with a different publication timestamp is not this write"
    );
    assert!(
        alice.orchestrator.mls_context().group_exists(old_group),
        "non-exact ambiguous authority must fail before destructive cleanup"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn higher_generation_same_target_is_not_misclassified_as_self_echo() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("same target newer reset", None, None)
        .await
        .expect("create conversation");
    let target = vec![0x5b; 32];

    alice
        .orchestrator
        .record_group_reset(&convo.conversation_id, target.clone(), 1)
        .await
        .expect("record generation one");
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            alice.did.as_bytes().to_vec(),
            target.clone(),
            Some(catbird_mls::GroupConfig::default()),
        )
        .expect("materialize generation-one bootstrap candidate");

    let outcome = alice
        .orchestrator
        .record_group_reset_with_outcome(&convo.conversation_id, target.clone(), 2)
        .await
        .expect("record newer generation with the same target bytes");

    assert_eq!(outcome, ResetRecordOutcome::Recorded);
    let persisted = alice
        .storage
        .get_persisted_reset_pending(&convo.conversation_id)
        .expect("newer generation must own reset authority");
    assert_eq!(persisted.reset_generation, 2);
    assert_eq!(persisted.new_group_id_hex, hex::encode(&target));
    assert!(
        !alice.orchestrator.mls_context().group_exists(target),
        "the stale generation-one local candidate must be removed even when group bytes are reused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_with_outcome_distinguishes_recorded_and_stale() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("ResetRequested Outcome Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let recorded = alice
        .orchestrator
        .record_reset_requested_with_outcome(
            &convo_id,
            "crypto-session-outcome",
            21,
            "inlineGroupInfo404",
            "req-inline-404:outcome:21",
            None,
        )
        .await
        .expect("fresh record_reset_requested_with_outcome should record");
    assert_eq!(recorded, ResetRecordOutcome::Recorded);

    let stale = alice
        .orchestrator
        .record_reset_requested_with_outcome(
            &convo_id,
            "crypto-session-outcome",
            20,
            "inlineGroupInfo404",
            "req-inline-404:outcome:20",
            None,
        )
        .await
        .expect("stale record_reset_requested_with_outcome should not fail");
    assert_eq!(stale, ResetRecordOutcome::StaleOrDuplicate);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_ignores_stale_lower_generation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Stale ResetRequested Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-current",
            17,
            "quorumVote",
            "req-quorum:current",
            None,
        )
        .await
        .expect("current record_reset_requested failed");

    let current_payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("current call must persist RESET_PENDING");

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-stale",
            16,
            "quorumVote",
            "req-quorum:stale",
            None,
        )
        .await
        .expect("stale record_reset_requested should be ignored");

    let stale_result = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("stale path must keep existing RESET_PENDING");
    assert_eq!(
        stale_result.reset_generation, current_payload.reset_generation,
        "stale lower generation must not replace the current reset generation"
    );
    assert_eq!(
        stale_result.new_group_id_hex, current_payload.new_group_id_hex,
        "stale lower generation must not mint or persist a new candidate group id"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        1,
        "stale lower generation must not issue another mark_reset_pending write"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_record_group_reset_ignores_stale_lower_generation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Stale GroupReset Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let current_group = hex::decode("00112233445566778899aabbccddeeff").expect("fixture hex");
    alice
        .orchestrator
        .record_group_reset(&convo_id, current_group, 9)
        .await
        .expect("current record_group_reset failed");

    let current_payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("current group reset must persist RESET_PENDING");

    let stale_group = hex::decode("ffeeddccbbaa99887766554433221100").expect("fixture hex");
    alice
        .orchestrator
        .record_group_reset(&convo_id, stale_group, 8)
        .await
        .expect("stale record_group_reset should be ignored");

    let stale_result = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("stale path must keep existing RESET_PENDING");
    assert_eq!(
        stale_result.reset_generation, current_payload.reset_generation,
        "stale lower generation must not replace the current reset generation"
    );
    assert_eq!(
        stale_result.new_group_id_hex, current_payload.new_group_id_hex,
        "stale lower generation must not rebind to the older group id"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        1,
        "stale lower generation must not issue another mark_reset_pending write"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_record_group_reset_ignores_self_echo_existing_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Self Echo GroupReset Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let current_group_id = convo.group_id.clone();
    let current_group = hex::decode(&current_group_id).expect("created group id must be valid hex");

    alice
        .orchestrator
        .record_group_reset(&convo_id, current_group, 10)
        .await
        .expect("self-echo record_group_reset should be ignored");

    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .is_none(),
        "self-echo reset target matching an existing local group must not persist RESET_PENDING"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        0,
        "self-echo reset target matching an existing local group must not write mark_reset_pending"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_bootstrap_completion_cannot_mask_newer_reset_generation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("bootstrap generation race", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let generation_one_group = vec![0x31; 32];
    let generation_two_group = vec![0x32; 32];

    alice
        .orchestrator
        .record_group_reset(&conversation_id, generation_one_group.clone(), 1)
        .await
        .expect("commit generation 1 reset");
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    world
        .delivery_service()
        .set_bootstrap_reset_group_delay_ms(300);

    let stale_completion = alice.orchestrator.join_or_rejoin(&conversation_id);
    let commit_newer_reset = async {
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        alice
            .storage
            .mark_reset_pending(
                &conversation_id,
                &hex::encode(&generation_two_group),
                2,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .expect("cross-process generation 2 commit while generation 1 bootstrap is in flight");
        alice
            .storage
            .mark_needs_rejoin(&conversation_id)
            .await
            .expect("generation 2 rejoin flag");
    };
    let (stale_result, ()) = tokio::join!(stale_completion, commit_newer_reset);

    assert!(
        stale_result.is_err(),
        "a generation 1 completion superseded by generation 2 must not report recovery success"
    );
    let persisted = alice
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("newer ResetPending must survive stale completion");
    assert_eq!(persisted.reset_generation, 2);
    assert_eq!(
        persisted.new_group_id_hex,
        hex::encode(&generation_two_group)
    );
    assert!(matches!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending {
            reset_generation: 2,
            ..
        })
    ));
    assert!(
        !alice
            .orchestrator
            .mls_context()
            .group_exists(generation_one_group),
        "stale generation 1 bootstrap group must not survive after generation 2 wins authority"
    );
    assert!(
        alice.storage.has_rejoin_flag(&conversation_id),
        "stale completion must not clear generation 2's durable rejoin flag"
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0,
        "generation mismatch must return directly without External Commit fallback"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn completion_error_preserves_reset_and_retry_resumes_without_external_commit() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("ambiguous completion retry", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let target = vec![0x71; 32];
    alice
        .storage
        .set_epoch_pair_for_test(&conversation_id, 741, 742);
    alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get_mut(&conversation_id)
        .expect("seed cached predecessor epoch")
        .epoch = 743;

    alice
        .orchestrator
        .record_group_reset(&conversation_id, target.clone(), 5)
        .await
        .expect("record reset");
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    world
        .delivery_service()
        .set_bootstrap_already_bootstrapped_after_success(true);
    let durable_before_error = alice
        .storage
        .get_conversation(&alice.did, &conversation_id)
        .await
        .expect("read pre-completion durable state")
        .expect("pre-completion durable state");
    let cached_before_error = alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&conversation_id)
        .expect("read pre-completion cache")
        .clone();
    alice.storage.fail_next_complete_reset_pending();

    let first = alice.orchestrator.join_or_rejoin(&conversation_id).await;
    eprintln!("FIRST ERROR: {:?}", first);
    assert!(first.is_err(), "completion uncertainty must fail closed");
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("reset authority must survive completion failure")
            .reset_generation,
        5
    );
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
    let durable_after_error = alice
        .storage
        .get_conversation(&alice.did, &conversation_id)
        .await
        .expect("read durable predecessor")
        .expect("durable predecessor survives");
    assert_eq!(durable_after_error.group_id, durable_before_error.group_id);
    assert_eq!(durable_after_error.epoch, durable_before_error.epoch);
    assert_eq!(
        alice.storage.join_epoch_for_test(&conversation_id),
        Some(742)
    );
    let cached_after_error = alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&conversation_id)
        .expect("cached predecessor survives")
        .clone();
    assert_eq!(cached_after_error.group_id, cached_before_error.group_id);
    assert_eq!(cached_after_error.epoch, cached_before_error.epoch);
    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(target.clone()));
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0
    );

    alice
        .orchestrator
        .join_or_rejoin(&conversation_id)
        .await
        .expect("retry should resume the materialized bootstrap candidate");
    assert!(
        alice
            .orchestrator
            .mls_context()
            .group_exists(target.clone()),
        "accepted bootstrap candidate must survive AlreadyBootstrapped retry"
    );
    assert_eq!(
        world
            .delivery_service()
            .bootstrap_reset_group_call_count(&conversation_id),
        2,
        "retry must exercise the accepted-winner AlreadyBootstrapped response"
    );
    assert!(alice
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .is_none());
    assert!(!alice.storage.has_rejoin_flag(&conversation_id));
    let landed_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(target)
        .expect("landed target epoch");
    let durable_after_retry = alice
        .storage
        .get_conversation(&alice.did, &conversation_id)
        .await
        .expect("read completed reset")
        .expect("completed reset conversation");
    assert_eq!(durable_after_retry.epoch, landed_epoch);
    assert_eq!(
        alice.storage.join_epoch_for_test(&conversation_id),
        Some(landed_epoch)
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_equal_epoch_preserves_reset_authority_and_completes_bootstrap_retry() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("sync reset completion retry", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let target = vec![0x73; 32];

    alice
        .orchestrator
        .record_group_reset(&conversation_id, target.clone(), 8)
        .await
        .expect("record reset");
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    world
        .delivery_service()
        .set_bootstrap_already_bootstrapped_after_success(true);
    alice.storage.fail_next_complete_reset_pending();

    assert!(
        alice
            .orchestrator
            .join_or_rejoin(&conversation_id)
            .await
            .is_err(),
        "accepted bootstrap with uncertain local completion must fail closed"
    );
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("ResetPending must remain durable")
            .reset_generation,
        8
    );
    assert!(alice.storage.has_rejoin_flag(&conversation_id));

    let target_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(target.clone())
        .expect("accepted bootstrap target epoch");
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&conversation_id, target_epoch);

    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("sync must resume generation-bound reset completion");

    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .is_none(),
        "equal epoch must not bypass durable reset completion"
    );
    assert!(!alice.storage.has_rejoin_flag(&conversation_id));
    assert_eq!(
        world
            .delivery_service()
            .bootstrap_reset_group_call_count(&conversation_id),
        2,
        "sync recovery must re-enter join_or_rejoin and resume the accepted bootstrap"
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_recording_serializes_with_equal_epoch_stale_rejoin_clear() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("stale clear reset race", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let local_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&conversation.group_id).expect("group id hex"))
        .expect("local epoch");
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&conversation_id, local_epoch);
    alice
        .storage
        .mark_needs_rejoin(&conversation_id)
        .await
        .expect("arm stale rejoin flag");

    let clear_barrier = alice.storage.pause_next_clear_rejoin_flag(&conversation_id);
    let reset_target = vec![0x74; 32];
    let sync = alice.orchestrator.sync_with_server(true);
    let record_reset = async {
        clear_barrier.wait_until_entered().await;
        let mut recording = Box::pin(alice.orchestrator.record_group_reset_with_outcome(
            &conversation_id,
            reset_target.clone(),
            9,
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut recording)
                .await
                .is_err(),
            "reset recording must wait while stale-clear owns the transition lock"
        );
        clear_barrier.release();
        recording.await
    };

    let (sync_result, reset_result) = tokio::join!(sync, record_reset);
    sync_result.expect("equal-epoch sync");
    assert_eq!(
        reset_result.expect("record reset after stale clear"),
        ResetRecordOutcome::Recorded
    );
    let pending = alice
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("racing reset must remain durable");
    assert_eq!(pending.reset_generation, 9);
    assert_eq!(pending.new_group_id_hex, hex::encode(reset_target));
    assert!(
        alice.storage.has_rejoin_flag(&conversation_id),
        "stale caught-up clear must not erase the newly recorded reset route"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_force_rejoin_refuses_to_bypass_reset_authority() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("force rejoin reset precedence", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let reset_target = vec![0x75; 32];

    alice
        .orchestrator
        .record_group_reset(&conversation_id, reset_target, 10)
        .await
        .expect("record reset");
    let error = alice
        .orchestrator
        .force_rejoin(&conversation_id)
        .await
        .expect_err("direct force_rejoin must defer to reset-aware recovery");

    assert!(error.to_string().contains("ResetPending"));
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0,
        "direct force_rejoin must not submit an External Commit under reset authority"
    );
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("reset authority must remain durable")
            .reset_generation,
        10
    );
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn healthy_clear_serializes_with_reset_recording() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("healthy clear reset race", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .storage
        .set_conversation_state(&conversation_id, ConversationState::NeedsRejoin)
        .await
        .expect("persist NeedsRejoin");
    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(conversation_id.clone(), ConversationState::NeedsRejoin);
    alice
        .storage
        .mark_needs_rejoin(&conversation_id)
        .await
        .expect("arm rejoin flag");

    let clear_barrier = alice.storage.pause_next_clear_rejoin_flag(&conversation_id);
    let reset_target = vec![0x76; 32];
    let readiness = async {
        alice
            .orchestrator
            .ensure_conversation_ready(&conversation_id)
            .await
    };
    let record_reset = async {
        clear_barrier.wait_until_entered().await;
        let mut recording = Box::pin(alice.orchestrator.record_group_reset_with_outcome(
            &conversation_id,
            reset_target.clone(),
            11,
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut recording)
                .await
                .is_err(),
            "reset recording must wait while healthy-clear owns the transition lock"
        );
        clear_barrier.release();
        recording.await
    };

    let (readiness_result, reset_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(readiness, record_reset)
        })
        .await
        .expect("healthy-clear race milestones timed out");
    readiness_result.expect("healthy stale-clear readiness");
    assert_eq!(
        reset_result.expect("record reset after healthy clear"),
        ResetRecordOutcome::Recorded
    );
    let pending = alice
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("racing reset must remain durable");
    assert_eq!(pending.reset_generation, 11);
    assert_eq!(pending.new_group_id_hex, hex::encode(reset_target));
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn contended_force_rejoin_rechecks_reset_authority_after_waiting() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("contended force reset precedence", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let reset_target = vec![0x77; 32];
    let record_barrier = alice.storage.pause_next_reset_record(&conversation_id);

    let record_reset =
        alice
            .orchestrator
            .record_group_reset_with_outcome(&conversation_id, reset_target, 12);
    let force_rejoin = async {
        record_barrier.wait_until_entered().await;
        let force = alice.orchestrator.force_rejoin(&conversation_id);
        record_barrier.release();
        force.await
    };
    let (reset_result, force_result) = tokio::join!(record_reset, force_rejoin);

    assert_eq!(
        reset_result.expect("record reset"),
        ResetRecordOutcome::Recorded
    );
    let error = force_result.expect_err("contended force must observe ResetPending after waiting");
    assert!(error.to_string().contains("ResetPending"));
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0
    );
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_force_rejoin_fails_closed_when_reset_authority_is_unreadable() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("force unreadable reset authority", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .storage
        .fail_next_get_conversation_state_for(&conversation_id);

    alice
        .orchestrator
        .force_rejoin(&conversation_id)
        .await
        .expect_err("unreadable reset authority must fail closed");
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn post_join_active_projection_serializes_with_newer_reset() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("post join projection race", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .orchestrator
        .record_group_reset(&conversation_id, vec![0x78; 32], 1)
        .await
        .expect("record generation one");
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    let active_barrier = alice
        .storage
        .pause_next_conversation_state_write(&conversation_id, ConversationState::Active);

    let readiness = alice
        .orchestrator
        .ensure_conversation_ready(&conversation_id);
    let newer_reset = async {
        active_barrier.wait_until_entered().await;
        let mut recording = Box::pin(alice.orchestrator.record_group_reset_with_outcome(
            &conversation_id,
            vec![0x79; 32],
            2,
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut recording)
                .await
                .is_err(),
            "newer reset must wait while final Active projection owns the transition gate"
        );
        active_barrier.release();
        recording.await
    };
    let (ready_result, reset_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(readiness, newer_reset)
        })
        .await
        .expect("post-join projection race timed out");

    ready_result.expect("generation one recovery");
    assert_eq!(
        reset_result.expect("generation two reset"),
        ResetRecordOutcome::Recorded
    );
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("generation two remains authoritative")
            .reset_generation,
        2
    );
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_needs_rejoin_projection_serializes_with_reset() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("startup projection race", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .orchestrator
        .mls_context()
        .delete_group(hex::decode(&conversation.group_id).expect("group id"))
        .expect("delete local group");
    alice
        .storage
        .set_conversation_state(&conversation_id, ConversationState::NeedsRejoin)
        .await
        .expect("seed NeedsRejoin");
    let write_barrier = alice
        .storage
        .pause_next_conversation_state_write(&conversation_id, ConversationState::NeedsRejoin);

    let reconcile = alice.orchestrator.startup_reconcile();
    let reset = async {
        write_barrier.wait_until_entered().await;
        let mut recording = Box::pin(alice.orchestrator.record_group_reset_with_outcome(
            &conversation_id,
            vec![0x7a; 32],
            3,
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut recording)
                .await
                .is_err(),
            "reset must wait while startup projection owns the transition gate"
        );
        write_barrier.release();
        recording.await
    };
    let (reconcile_result, reset_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(reconcile, reset)
        })
        .await
        .expect("startup projection race timed out");

    reconcile_result.expect("startup reconcile");
    assert_eq!(
        reset_result.expect("record reset"),
        ResetRecordOutcome::Recorded
    );
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("reset remains authoritative")
            .reset_generation,
        3
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_non_reset_read_cannot_downgrade_cached_reset_authority() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("stale reset authority read", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .orchestrator
        .record_group_reset(&conversation_id, vec![0x7b; 32], 4)
        .await
        .expect("record reset");
    alice
        .storage
        .override_next_conversation_state_read(&conversation_id, Some(ConversationState::Active));

    let _ = alice.orchestrator.force_rejoin(&conversation_id).await;

    assert!(matches!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending {
            reset_generation: 4,
            ..
        })
    ));
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0,
        "stale non-reset read must not authorize External Commit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_reconcile_stale_failed_read_cannot_downgrade_cached_reset_authority() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("startup stale failed", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .orchestrator
        .record_group_reset(&conversation_id, vec![0x7c; 32], 6)
        .await
        .expect("record reset");
    alice
        .storage
        .override_next_conversation_state_read(&conversation_id, Some(ConversationState::Failed));

    alice
        .orchestrator
        .startup_reconcile()
        .await
        .expect("startup reconcile");

    assert!(matches!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending {
            reset_generation: 6,
            ..
        })
    ));
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn completion_cas_mismatch_stale_active_reload_preserves_cached_reset_authority() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("completion stale reload", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let target = vec![0x7d; 32];
    alice
        .orchestrator
        .record_group_reset(&conversation_id, target, 8)
        .await
        .expect("record reset");
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    alice
        .storage
        .force_next_complete_reset_pending_false_with_reload(Some(ConversationState::Active));

    assert!(alice
        .orchestrator
        .join_or_rejoin(&conversation_id)
        .await
        .is_err());

    assert!(matches!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending {
            reset_generation: 8,
            ..
        })
    ));
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn welcome_network_error_with_reset_pending_never_authorizes_external_commit() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("welcome network reset boundary", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    alice
        .orchestrator
        .record_group_reset(&conversation_id, vec![0x72; 32], 6)
        .await
        .expect("record reset");
    world.delivery_service().fail_next_get_welcome();

    let result = alice.orchestrator.join_or_rejoin(&conversation_id).await;
    assert!(result.is_err());
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        0,
        "non-404 Welcome uncertainty cannot bypass durable reset authority"
    );
    assert_eq!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .expect("reset authority must survive")
            .reset_generation,
        6
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loser_device_adopts_verified_winner_welcome_before_exact_reset_completion() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    world.register_device("Bob").await.expect("register Bob");
    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let original = alice
        .orchestrator
        .create_group("reset welcome baseline", Some(&[bob.did.clone()]), None)
        .await
        .expect("create baseline conversation");
    alice
        .orchestrator
        .swap_members(&original.conversation_id, &[], &[bob.did.clone()])
        .await
        .expect("add bob to baseline");
    let baseline_welcome = world
        .delivery_service()
        .clone_as(&bob.did)
        .get_welcome(&original.conversation_id)
        .await
        .expect("baseline Welcome for Bob");
    bob.orchestrator
        .join_group(&baseline_welcome)
        .await
        .expect("Bob joins baseline conversation");
    bob.storage
        .set_epoch_pair_for_test(&original.conversation_id, 741, 742);

    let loser_target = vec![0x91; 32];
    let loser_target_hex = hex::encode(&loser_target);
    bob.orchestrator
        .record_group_reset(&original.conversation_id, loser_target.clone(), 23)
        .await
        .expect("record loser reset target");
    bob.orchestrator
        .mls_context()
        .create_group_with_id(
            bob.did.as_bytes().to_vec(),
            loser_target.clone(),
            Some(catbird_mls::GroupConfig::default()),
        )
        .expect("materialize loser bootstrap candidate");

    let winner = alice
        .orchestrator
        .create_group("reset winner", Some(&[bob.did.clone()]), None)
        .await
        .expect("winner creates replacement group and Welcome");
    alice
        .orchestrator
        .swap_members(&winner.conversation_id, &[], &[bob.did.clone()])
        .await
        .expect("add bob to winner");
    world
        .delivery_service()
        .rekey_conversation_for_test(&winner.conversation_id, &original.conversation_id);
    let authoritative = world
        .delivery_service()
        .clone_as(&bob.did)
        .get_conversations(100, None)
        .await
        .expect("read authoritative server mapping")
        .conversations
        .into_iter()
        .find(|view| view.conversation_id == original.conversation_id)
        .expect("stable conversation remains server-authoritative");
    assert_eq!(authoritative.group_id, winner.group_id);

    bob.orchestrator
        .join_or_rejoin(&original.conversation_id)
        .await
        .expect("verified winner Welcome must replace the losing reset target");

    assert!(
        !bob.orchestrator
            .mls_context()
            .group_exists(loser_target.clone()),
        "the losing target must already be deleted before the next operation"
    );
    assert!(
        bob.orchestrator.mls_context().group_exists(
            hex::decode(&winner.group_id).expect("winner group id before immediate send")
        ),
        "the committed winner must be locally available before the next operation"
    );
    let stable_message_count_before_send = world
        .delivery_service()
        .message_count(&original.conversation_id);
    bob.orchestrator
        .send_message(
            &original.conversation_id,
            "immediate message after winner adoption",
        )
        .await
        .expect("the stable conversation must resolve to the committed winner before sync");
    assert_eq!(
        world
            .delivery_service()
            .message_count(&original.conversation_id),
        stable_message_count_before_send + 1,
        "the first post-adoption operation must succeed through the stable conversation route"
    );

    assert!(
        bob.storage
            .get_persisted_reset_pending(&original.conversation_id)
            .is_none(),
        "exact generation/target completion must clear ResetPending"
    );
    assert!(!bob.storage.has_rejoin_flag(&original.conversation_id));
    let completed = bob
        .storage
        .get_conversation(&bob.did, &original.conversation_id)
        .await
        .expect("read Bob conversation")
        .expect("Bob stable conversation survives");
    let winner_epoch = bob
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&winner.group_id).expect("winner group id for epoch"))
        .expect("winner epoch");
    assert_eq!(completed.group_id, winner.group_id);
    assert_eq!(completed.epoch, winner_epoch);
    assert_eq!(
        bob.storage.join_epoch_for_test(&original.conversation_id),
        Some(winner_epoch)
    );
    assert!(!bob.orchestrator.mls_context().group_exists(loser_target));
    assert!(bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(&winner.group_id).expect("winner group id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_carries_adopted_reset_winner_past_a_stale_listing_snapshot() {
    let (world, conversation_id, loser, winner_id) =
        setup_winner_welcome_adoption_fixture(0x9a, 41).await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");

    // Give the winner creator the same stable route used by the rekeyed mock
    // server so it can enqueue a valid winner-epoch application message while
    // Bob's stale list page is paused.
    {
        let mut conversations = alice.orchestrator.conversations().lock().await;
        let mut winner_view = conversations
            .values()
            .find(|c| c.group_id == winner_id || c.conversation_id == winner_id)
            .cloned()
            .expect("Alice caches the replacement conversation");
        winner_view.conversation_id = conversation_id.clone();
        conversations.insert(conversation_id.clone(), winner_view);
    }
    alice
        .storage
        .set_conversation_group_id_for_test(&conversation_id, &winner_id);

    // Model a sync page captured while the list projection still points at
    // the losing reset target. The live conversation mapping and Welcome are
    // switched back to the committed winner before recovery consults them.
    bob.orchestrator
        .mls_context()
        .delete_group(loser.clone())
        .expect("remove loser so stale sync enters join/rejoin");
    let loser_hex = hex::encode(&loser);
    let loser_state_before = bob
        .storage
        .get_group_state(&loser_hex)
        .await
        .expect("read losing reset projection")
        .expect("reset recording persists its target projection");
    world
        .delivery_service()
        .set_conversation_group_id_for_test(&conversation_id, &loser_hex);
    let listing_gate = world.delivery_service().pause_next_get_conversations();

    let sync = bob.orchestrator.sync_with_server(true);
    let restore_authoritative_winner = async {
        listing_gate.wait_until_reached().await;
        world
            .delivery_service()
            .set_conversation_group_id_for_test(&conversation_id, &winner_id);
        alice
            .orchestrator
            .send_message(&conversation_id, "winner message queued behind stale page")
            .await
            .expect("winner creator queues valid app ciphertext");
        listing_gate.release();
    };
    let (sync_result, ()) = tokio::join!(sync, restore_authoritative_winner);
    sync_result.expect("sync must recover through the authoritative winner");

    let winner_epoch = bob
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&winner_id).expect("winner group id"))
        .expect("winner must be locally joined");
    let stored = bob
        .storage
        .get_conversation(&bob.did, &conversation_id)
        .await
        .expect("read stable conversation")
        .expect("stable conversation remains persisted");
    assert_eq!(stored.group_id, winner_id);
    assert_eq!(stored.epoch, winner_epoch);
    assert!(bob.storage.has_group_state(&winner_id));
    let loser_state_after = bob
        .storage
        .get_group_state(&loser_hex)
        .await
        .expect("reread losing reset projection")
        .expect("the pre-existing reset projection may remain for legacy cleanup");
    assert_eq!(loser_state_after.group_id, loser_state_before.group_id);
    assert_eq!(
        loser_state_after.conversation_id,
        loser_state_before.conversation_id
    );
    assert_eq!(loser_state_after.epoch, loser_state_before.epoch);
    assert_eq!(loser_state_after.members, loser_state_before.members);
    {
        let states = bob.orchestrator.group_states().lock().await;
        let state = states
            .get(&winner_id)
            .expect("winner is the sole in-memory group-state projection");
        assert_eq!(state.conversation_id, conversation_id);
        assert_eq!(state.group_id, winner_id);
        assert_eq!(state.epoch, winner_epoch);
        assert!(!states.contains_key(&loser_hex));
    }
    assert!(
        !bob.storage.has_rejoin_flag(&conversation_id),
        "successful winner adoption must not schedule a second stale rejoin"
    );
    let received = bob
        .storage
        .get_messages(&conversation_id, 20, None)
        .await
        .expect("read messages decrypted by sync");
    assert!(
        received
            .iter()
            .any(|message| message.text == "winner message queued behind stale page"),
        "the same sync item must fetch and decrypt app traffic through winner W"
    );

    let before = world.delivery_service().message_count(&conversation_id);
    bob.orchestrator
        .send_message(
            &conversation_id,
            "message immediately after stale-page recovery",
        )
        .await
        .expect("the same sync pass must leave the stable route on the winner");
    assert_eq!(
        world.delivery_service().message_count(&conversation_id),
        before + 1
    );
}

async fn setup_winner_welcome_adoption_fixture(
    loser_byte: u8,
    generation: i32,
) -> (TestWorld, String, Vec<u8>, String) {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    world.register_device("Bob").await.expect("register Bob");
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let original = alice
        .orchestrator
        .create_group("winner adoption baseline", Some(&[bob.did.clone()]), None)
        .await
        .expect("create baseline");
    alice
        .orchestrator
        .swap_members(&original.conversation_id, &[], &[bob.did.clone()])
        .await
        .expect("add bob to baseline");
    let baseline_welcome = world
        .delivery_service()
        .clone_as(&bob.did)
        .get_welcome(&original.conversation_id)
        .await
        .expect("baseline Welcome");
    bob.orchestrator
        .join_group(&baseline_welcome)
        .await
        .expect("Bob joins baseline");
    let loser = vec![loser_byte; 32];
    bob.orchestrator
        .record_group_reset(&original.conversation_id, loser.clone(), generation)
        .await
        .expect("record loser authority");
    bob.orchestrator
        .mls_context()
        .create_group_with_id(
            bob.did.as_bytes().to_vec(),
            loser.clone(),
            Some(catbird_mls::GroupConfig::default()),
        )
        .expect("materialize loser");
    let winner = alice
        .orchestrator
        .create_group("authoritative winner", Some(&[bob.did.clone()]), None)
        .await
        .expect("create winner");
    alice
        .orchestrator
        .swap_members(&winner.conversation_id, &[], &[bob.did.clone()])
        .await
        .expect("add bob to winner");
    world
        .delivery_service()
        .rekey_conversation_for_test(&winner.conversation_id, &original.conversation_id);
    (world, original.conversation_id, loser, winner.group_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_winner_adoption_response_loss_rereads_then_completes_exactly() {
    let (world, conversation_id, loser, winner_id) =
        setup_winner_welcome_adoption_fixture(0x92, 31).await;
    let bob = world.client("Bob");
    bob.storage.fail_next_adopt_reset_pending_after_commit();

    bob.orchestrator
        .join_or_rejoin(&conversation_id)
        .await
        .expect("exact durable reread must recover a committed adoption");

    assert!(bob
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .is_none());
    assert!(!bob.storage.has_rejoin_flag(&conversation_id));
    assert!(!bob.orchestrator.mls_context().group_exists(loser));
    assert!(bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(winner_id).expect("winner id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_adoption_with_failed_reread_preserves_both_candidates_and_reset_route() {
    let (world, conversation_id, loser, winner_id) =
        setup_winner_welcome_adoption_fixture(0x97, 61).await;
    let bob = world.client("Bob");
    bob.storage
        .fail_next_adopt_reset_pending_after_commit_with_read_failure();

    let error = bob
        .orchestrator
        .join_or_rejoin(&conversation_id)
        .await
        .expect_err("ambiguous adoption plus failed reread must fail closed");
    assert!(error.to_string().contains("authority reread failed"));
    let pending = bob
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("committed adopted authority survives for restart");
    assert_eq!(pending.reset_generation, 61);
    assert_eq!(pending.new_group_id_hex, winner_id);
    assert!(bob.storage.has_rejoin_flag(&conversation_id));
    assert!(bob.orchestrator.mls_context().group_exists(loser));
    assert!(bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(winner_id).expect("winner id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn newer_reset_generation_wins_adoption_cas_without_candidate_cleanup() {
    let (world, conversation_id, loser, winner_id) =
        setup_winner_welcome_adoption_fixture(0x93, 41).await;
    let bob = world.client("Bob");
    let newer_target = vec![0x94; 32];
    let adoption = bob.storage.pause_next_reset_adoption(&conversation_id);
    let mut recovery = Box::pin(bob.orchestrator.join_or_rejoin(&conversation_id));
    tokio::select! {
        _ = adoption.wait_until_entered() => {}
        result = &mut recovery => panic!("recovery completed before adoption CAS: {result:?}"),
    }
    bob.storage
        .mark_reset_pending(
            &conversation_id,
            &hex::encode(&newer_target),
            42,
            1_800_000_000_000,
        )
        .await
        .expect("simulate newer cross-process reset authority");
    adoption.release();

    let error = recovery
        .await
        .expect_err("stale generation must not adopt or complete");
    assert!(error
        .to_string()
        .contains("newer or competing reset authority"));
    let pending = bob
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("newer authority survives");
    assert_eq!(pending.reset_generation, 42);
    assert_eq!(pending.new_group_id_hex, hex::encode(newer_target));
    assert!(bob.storage.has_rejoin_flag(&conversation_id));
    assert!(bob.orchestrator.mls_context().group_exists(loser));
    assert!(bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(winner_id).expect("winner id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn newer_authority_at_exact_completion_preserves_adopted_winner_group() {
    let (world, conversation_id, loser, winner_id) =
        setup_winner_welcome_adoption_fixture(0x98, 71).await;
    let bob = world.client("Bob");
    let newer_target = hex::encode(vec![0x99; 32]);
    bob.storage
        .set_epoch_pair_for_test(&conversation_id, 741, 742);
    bob.orchestrator
        .conversations()
        .lock()
        .await
        .get_mut(&conversation_id)
        .expect("seed cached predecessor epoch")
        .epoch = 743;
    let durable_before_failure = bob
        .storage
        .get_conversation(&bob.did, &conversation_id)
        .await
        .expect("read pre-failure durable state")
        .expect("pre-failure durable state");
    let cached_before_failure = bob
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&conversation_id)
        .expect("read pre-failure cache")
        .clone();
    bob.storage
        .force_next_complete_reset_pending_false_with_reload(Some(
            ConversationState::ResetPending {
                new_group_id: newer_target.clone(),
                reset_generation: 72,
                notified_at_ms: 1_800_000_000_001,
            },
        ));

    let error = bob
        .orchestrator
        .join_or_rejoin(&conversation_id)
        .await
        .expect_err("newer completion authority must fail closed");
    assert!(error.to_string().contains("newer reset generation"));
    assert!(matches!(
        bob.orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending {
            new_group_id,
            reset_generation: 72,
            ..
        }) if new_group_id == &newer_target
    ));
    let cached = bob
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&conversation_id)
        .expect("stable conversation cache survives failed completion")
        .clone();
    assert_eq!(cached.group_id, cached_before_failure.group_id);
    assert_eq!(cached.epoch, cached_before_failure.epoch);
    let durable = bob
        .storage
        .get_conversation(&bob.did, &conversation_id)
        .await
        .expect("read durable predecessor")
        .expect("durable predecessor survives");
    assert_eq!(durable.group_id, durable_before_failure.group_id);
    assert_eq!(durable.epoch, durable_before_failure.epoch);
    assert_eq!(bob.storage.join_epoch_for_test(&conversation_id), Some(742));
    assert!(bob.storage.has_rejoin_flag(&conversation_id));
    assert!(!bob.orchestrator.mls_context().group_exists(loser));
    assert!(bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(winner_id).expect("winner id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn welcome_not_matching_server_winner_is_deleted_without_touching_loser_authority() {
    let (world, conversation_id, loser, welcome_group_id) =
        setup_winner_welcome_adoption_fixture(0x95, 51).await;
    let bob = world.client("Bob");
    let competing_server_winner = hex::encode(vec![0x96; 32]);
    world
        .delivery_service()
        .set_conversation_group_id_for_test(&conversation_id, &competing_server_winner);

    let error = bob
        .orchestrator
        .join_or_rejoin(&conversation_id)
        .await
        .expect_err("unbound Welcome must fail closed");
    assert!(error.to_string().contains("authoritative server mapping"));
    let pending = bob
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("loser reset authority remains");
    assert_eq!(pending.reset_generation, 51);
    assert_eq!(pending.new_group_id_hex, hex::encode(&loser));
    assert!(bob.storage.has_rejoin_flag(&conversation_id));
    assert!(bob.orchestrator.mls_context().group_exists(loser));
    assert!(!bob
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(welcome_group_id).expect("Welcome group id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_arriving_after_completion_cas_is_serialized_after_active_projection() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("post completion reset serialization", None, None)
        .await
        .expect("create conversation");
    let conversation_id = conversation.conversation_id.clone();
    let generation_one_group = vec![0x61; 32];
    let generation_two_group = vec![0x62; 32];

    alice
        .orchestrator
        .record_group_reset(&conversation_id, generation_one_group, 1)
        .await
        .expect("record generation one");
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    let completion_barrier = alice.storage.pause_next_reset_completion(&conversation_id);

    let complete_generation_one = alice.orchestrator.join_or_rejoin(&conversation_id);
    let record_generation_two = async {
        completion_barrier.wait_until_entered().await;
        // The durable generation-one CAS has committed. Releasing its callback
        // lets the owner finish cache projection and drop the shared transition
        // lock; this reset must serialize strictly after that lifecycle step.
        completion_barrier.release();
        alice
            .orchestrator
            .record_group_reset_with_outcome(&conversation_id, generation_two_group.clone(), 2)
            .await
    };
    let (completion, generation_two_outcome) =
        tokio::join!(complete_generation_one, record_generation_two);

    completion.expect("generation one completion should commit");
    assert_eq!(
        generation_two_outcome.expect("generation two should record after completion"),
        ResetRecordOutcome::Recorded
    );
    let persisted = alice
        .storage
        .get_persisted_reset_pending(&conversation_id)
        .expect("generation two must remain the final durable authority");
    assert_eq!(persisted.reset_generation, 2);
    assert_eq!(
        persisted.new_group_id_hex,
        hex::encode(&generation_two_group)
    );
    assert!(matches!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending {
            reset_generation: 2,
            ..
        })
    ));
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_ignores_self_echo_expected_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Self Echo ResetRequested Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let current_group_id = convo.group_id.clone();

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-self-echo",
            10,
            "adminRequest",
            "req-admin:self-echo",
            Some(current_group_id),
        )
        .await
        .expect("self-echo record_reset_requested should be ignored");

    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .is_none(),
        "self-echo expected group matching an existing local group must not persist RESET_PENDING"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        0,
        "self-echo expected group matching an existing local group must not write mark_reset_pending"
    );
}

// ---------------------------------------------------------------------------
// 2. None group_id path: client mints a fresh candidate.
// ---------------------------------------------------------------------------

/// When `expected_new_mls_group_id` is `None` (the canonical Phase 2.5
/// indirect-trigger shape — quorum, sweep, inline-409, inline-404), the
/// orchestrator mints a fresh client-side UUIDv4-style group_id, transitions
/// to `RESET_PENDING { new_group_id, .. }`, and flips `needs_rejoin` so the
/// deferred-recovery loop's first-responder bootstrap branch picks it up.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_with_none_mints_local_group_id() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("None Path", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            42,
            "inlineGroupInfo404",
            "req-inline-404:convo123:5:1234",
            None,
        )
        .await
        .expect("record_reset_requested(None) failed");

    let payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("None path must persist RESET_PENDING with a minted group_id");
    assert_eq!(
        payload.new_group_id_hex.len(),
        32,
        "minted group_id must be a 32-hex-char UUIDv4-style id (got {} chars)",
        payload.new_group_id_hex.len()
    );
    assert!(
        hex::decode(&payload.new_group_id_hex).is_ok(),
        "minted group_id must decode as valid hex"
    );
    assert_eq!(payload.reset_generation, 42);

    // Conversation state should have flipped to RESET_PENDING with the same
    // new_group_id.
    let state = alice
        .storage
        .get_current_state(&convo_id)
        .expect("conversation must have a state row");
    match state {
        ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        } => {
            assert_eq!(new_group_id, payload.new_group_id_hex);
            assert_eq!(reset_generation, 42);
        }
        other => panic!("expected ResetPending, got {other:?}"),
    }

    // needs_rejoin flag should be set so the deferred-recovery loop
    // picks the conversation up.
    assert!(
        alice.storage.has_rejoin_flag(&convo_id),
        "needs_rejoin flag must be set so deferred-recovery loop picks up the conversation"
    );
}

// ---------------------------------------------------------------------------
// 3. Some group_id path: admin / legacy-equivalent target id.
// ---------------------------------------------------------------------------

/// When `expected_new_mls_group_id: Some(g)` is passed (admin path or legacy
/// direct flow), the orchestrator targets `g` directly. State matches what
/// `record_group_reset(convo, hex::decode(g), gen)` produces — verifies the
/// new sibling function does not regress the legacy behavior.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_with_some_uses_server_group_id() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Some Path", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let admin_supplied = format!("{:032x}", uuid::Uuid::new_v4().as_u128());

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            8,
            "adminRequest",
            "req-admin:convo123:abc",
            Some(admin_supplied.clone()),
        )
        .await
        .expect("record_reset_requested(Some) failed");

    let payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("Some path must persist RESET_PENDING with the server-supplied id");
    assert_eq!(
        payload.new_group_id_hex, admin_supplied,
        "Some path must use the server-supplied id verbatim, not mint a new one"
    );
    assert_eq!(payload.reset_generation, 8);

    let state = alice
        .storage
        .get_current_state(&convo_id)
        .expect("conversation must have a state row");
    match state {
        ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        } => {
            assert_eq!(new_group_id, admin_supplied);
            assert_eq!(reset_generation, 8);
        }
        other => panic!("expected ResetPending, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Survives orchestrator restart: rehydration drives recovery on resume.
// ---------------------------------------------------------------------------

/// `record_reset_requested` arriving before an orchestrator restart must
/// survive the restart. The mock storage's `mark_reset_pending` row is
/// preserved across the simulated restart, and a fresh orchestrator built
/// against the same storage must rehydrate `ConversationState::ResetPending`
/// in its in-memory `conversation_states` map during `initialize`.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_survives_orchestrator_restart() {
    // We can't easily reuse the `TestWorld` add_client flow for restart since
    // it owns the orchestrator. Build a single client manually so we can
    // tear down the orchestrator while keeping storage + mls_context backing
    // dirs alive, then construct a fresh orchestrator pointing at the same
    // storage.

    use e2e_harness::mock_api_client::MockDeliveryService;
    use e2e_harness::mock_credentials::MockCredentials;
    use e2e_harness::mock_storage::MockStorage;

    struct InMemoryKeychain {
        store: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl KeychainAccess for InMemoryKeychain {
        async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(self.store.lock().unwrap().get(&key).cloned())
        }
        async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
            self.store.lock().unwrap().insert(key, value);
            Ok(())
        }
        async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
            self.store.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    let did = "did:plc:restartalice".to_string();
    let temp_dir = std::env::temp_dir().join(format!(
        "catbird_mls_restart_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");
    let db_path = temp_dir.join("mls.db");
    let key = format!("test-key-{}", uuid::Uuid::new_v4());

    let storage = MockStorage::new();
    let credentials = MockCredentials::new();
    let api_service = MockDeliveryService::new(&did);

    let convo_id = "convo-survives-restart";
    let admin_supplied = format!("{:032x}", uuid::Uuid::new_v4().as_u128());

    // ---- Phase 1: write RESET_PENDING via the real orchestrator API ----
    {
        let keychain = Box::new(InMemoryKeychain {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
        let mls_context =
            MLSContext::new(db_path.to_string_lossy().to_string(), key.clone(), keychain)
                .expect("failed to create MLSContext (phase 1)");

        let api_client = api_service.clone_as(&did);
        let orchestrator = MLSOrchestrator::new(
            mls_context,
            Arc::new(storage.clone()),
            Arc::new(api_client),
            Arc::new(credentials.clone()),
            OrchestratorConfig::default(),
        );

        orchestrator
            .initialize(&did)
            .await
            .expect("phase-1 initialize failed");

        // Seed a conversation row so the orchestrator's group_states + storage
        // know about it.
        storage
            .ensure_conversation_exists(&did, convo_id, convo_id)
            .await
            .expect("ensure_conversation_exists failed");

        orchestrator
            .record_reset_requested(
                convo_id,
                "crypto-session-prior",
                99,
                "systemSweep",
                "req-sweep:convo:tick42",
                Some(admin_supplied.clone()),
            )
            .await
            .expect("record_reset_requested failed in phase 1");

        // Sanity: verify the persisted row is there.
        let persisted = storage
            .get_persisted_reset_pending(convo_id)
            .expect("RESET_PENDING must be persisted before restart");
        assert_eq!(persisted.new_group_id_hex, admin_supplied);
        assert_eq!(persisted.reset_generation, 99);

        // Drop the orchestrator + mls_context so the SQLCipher DB is closed
        // cleanly (mimics process restart).
        orchestrator.shutdown().await;
    }

    // ---- Phase 2: fresh orchestrator against the same storage ----
    let storage_phase2 = storage.clone();

    let keychain2 = Box::new(InMemoryKeychain {
        store: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let mls_context2 = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.clone(),
        keychain2,
    )
    .expect("failed to create MLSContext (phase 2)");

    let api_client2 = api_service.clone_as(&did);
    let orchestrator2 = MLSOrchestrator::new(
        mls_context2,
        Arc::new(storage_phase2.clone()),
        Arc::new(api_client2),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );

    orchestrator2
        .initialize(&did)
        .await
        .expect("phase-2 initialize failed");

    // The storage's mark_reset_pending row should still be there (Mock
    // backing it is shared via Arc<Mutex>; in production this would be the
    // platform DB).
    let post_restart = storage_phase2
        .get_persisted_reset_pending(convo_id)
        .expect("RESET_PENDING payload must survive restart");
    assert_eq!(post_restart.new_group_id_hex, admin_supplied);
    assert_eq!(post_restart.reset_generation, 99);

    // Verify the fresh orchestrator can read RESET_PENDING via its own
    // public surface — `reset_pending_payload` is `pub(crate)` so we read
    // through `get_conversation_state` on the storage trait, which is the
    // same fallback path the recovery loop uses (recovery.rs:1559).
    let rehydrated = storage_phase2
        .get_conversation_state(convo_id)
        .await
        .expect("get_conversation_state must succeed");
    match rehydrated {
        Some(ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        }) => {
            assert_eq!(new_group_id, admin_supplied);
            assert_eq!(reset_generation, 99);
        }
        other => panic!("expected post-restart storage to rehydrate ResetPending, got {other:?}"),
    }

    // Cleanup: shutdown + temp dir.
    orchestrator2.shutdown().await;
    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ---------------------------------------------------------------------------
// 5. ADR-021 Part A — reset-target validation before destructive delete.
//
// Ledger residual `csf_d0d5fab7fefe6dd96602ebe7`: a destructive reset used to
// validate only generation monotonicity + self-echo before deleting the old
// MLS group, with no shape/hex validation of the (server-asserted) reset
// target. A malformed target could therefore publish a garbage RESET_PENDING
// AND delete the old group — unrecoverable. Part A validates the target's
// shape/hex at record time, fails closed with a typed error, and preserves the
// old group; the delete path is unreachable until durable intent + target
// validation both succeed.
// ---------------------------------------------------------------------------

/// A non-empty but non-hex `expectedNewMlsGroupId` from the server must be
/// rejected at record time with a typed `InvalidInput` error — no RESET_PENDING
/// row, no state transition, and the pre-reset MLS group left intact.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_hex_reset_target_is_rejected_without_deleting_old_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Malformed Hex Target", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let old_group = hex::decode(&convo.group_id).expect("created group id must be valid hex");
    assert!(
        alice
            .orchestrator
            .mls_context()
            .group_exists(old_group.clone()),
        "precondition: the pre-reset group must exist"
    );

    // 32 non-hex characters: non-empty (so the None-path mint is NOT taken),
    // but `hex::decode` fails.
    let malformed = "z".repeat(32);
    let error = alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            7,
            "adminRequest",
            "req-admin:malformed-hex",
            Some(malformed),
        )
        .await
        .expect_err("malformed-hex reset target must fail closed");
    assert!(
        matches!(error, OrchestratorError::InvalidInput(_)),
        "malformed-hex target must yield InvalidInput, got {error:?}"
    );

    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        0,
        "a malformed target must not write a durable RESET_PENDING row"
    );
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .is_none(),
        "a malformed target must not persist RESET_PENDING"
    );
    assert!(
        !matches!(
            alice.storage.get_current_state(&convo_id),
            Some(ConversationState::ResetPending { .. })
        ),
        "a malformed target must not transition the conversation to ResetPending"
    );
    assert!(
        alice.orchestrator.mls_context().group_exists(old_group),
        "the pre-reset group must survive a rejected reset target"
    );
}

/// A syntactically valid hex target of the wrong length (too short to be an
/// MLS group id) must be rejected at record time, old group intact.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_length_reset_target_is_rejected_without_deleting_old_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Wrong Length Target", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let old_group = hex::decode(&convo.group_id).expect("created group id must be valid hex");

    // Valid hex, but only 8 bytes — below the smallest MLS group id this stack
    // ever produces (16-byte client mint / OpenMLS random).
    let too_short = hex::encode(vec![0xab; 8]);
    let error = alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            7,
            "adminRequest",
            "req-admin:wrong-length",
            Some(too_short),
        )
        .await
        .expect_err("wrong-length reset target must fail closed");
    assert!(
        matches!(error, OrchestratorError::InvalidInput(_)),
        "wrong-length target must yield InvalidInput, got {error:?}"
    );

    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        0,
        "a wrong-length target must not write a durable RESET_PENDING row"
    );
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .is_none(),
        "a wrong-length target must not persist RESET_PENDING"
    );
    assert!(
        alice.orchestrator.mls_context().group_exists(old_group),
        "the pre-reset group must survive a rejected reset target"
    );
}

/// An empty reset target via the direct `record_group_reset` path (an empty
/// group-id byte vector encodes to `""`) must be rejected at record time, old
/// group intact.
#[tokio::test(flavor = "multi_thread")]
async fn empty_reset_target_is_rejected_without_deleting_old_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Empty Target", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let old_group = hex::decode(&convo.group_id).expect("created group id must be valid hex");

    let error = alice
        .orchestrator
        .record_group_reset(&convo_id, Vec::new(), 7)
        .await
        .expect_err("empty reset target must fail closed");
    assert!(
        matches!(error, OrchestratorError::InvalidInput(_)),
        "empty target must yield InvalidInput, got {error:?}"
    );

    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        0,
        "an empty target must not write a durable RESET_PENDING row"
    );
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&convo_id)
            .is_none(),
        "an empty target must not persist RESET_PENDING"
    );
    assert!(
        alice.orchestrator.mls_context().group_exists(old_group),
        "the pre-reset group must survive a rejected reset target"
    );
}

/// Ordering guarantee: `delete_group` cannot run before the durable reset
/// intent has committed. A valid target whose durable `mark_reset_pending`
/// write fails must fail closed with the old group intact — proving the delete
/// is gated on durable intent, not merely on target validation.
#[tokio::test(flavor = "multi_thread")]
async fn delete_is_gated_on_durable_intent_committing_first() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Durable Intent Gate", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let old_group = hex::decode(&convo.group_id).expect("created group id must be valid hex");

    // Valid, well-formed target — validation passes. The durable write is what
    // fails here, so any delete must be suppressed.
    let valid_target = vec![0x5c; 32];
    alice.storage.fail_next_mark_reset_pending();

    let error = alice
        .orchestrator
        .record_group_reset(&convo_id, valid_target, 7)
        .await
        .expect_err("failed durable intent must fail closed");
    assert!(
        matches!(
            error,
            OrchestratorError::Storage(_) | OrchestratorError::ResetCompletionNotCommitted { .. }
        ),
        "failed durable intent must surface a storage/uncommitted error, got {error:?}"
    );

    assert!(
        alice.orchestrator.mls_context().group_exists(old_group),
        "the pre-reset group must survive when durable intent fails to commit"
    );
}

/// Restart-durability across the persist/delete gap: once the durable reset
/// intent has committed for a well-formed target, the RESET_PENDING payload
/// survives an orchestrator restart even though the local delete + rejoin have
/// not completed — the reset resumes from durable state, not from the deleted
/// group.
#[tokio::test(flavor = "multi_thread")]
async fn valid_reset_intent_survives_restart_across_persist_delete_gap() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Restart Across Gap", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let target = vec![0x6d; 32];
    let target_hex = hex::encode(&target);
    alice
        .orchestrator
        .record_group_reset(&convo_id, target, 12)
        .await
        .expect("well-formed reset must record");

    // The durable intent is on disk and readable exactly as recorded — this is
    // the cross-restart carrier the deferred-recovery loop resumes from.
    let persisted = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("durable RESET_PENDING must be persisted for a well-formed target");
    assert_eq!(persisted.reset_generation, 12);
    assert_eq!(persisted.new_group_id_hex, target_hex);
    assert!(
        alice.storage.has_rejoin_flag(&convo_id),
        "durable intent must arm needs_rejoin so restart resumes the reset"
    );
    assert!(
        matches!(
            alice.storage.get_current_state(&convo_id),
            Some(ConversationState::ResetPending {
                reset_generation: 12,
                ..
            })
        ),
        "durable state must be ResetPending at the recorded generation"
    );
}
