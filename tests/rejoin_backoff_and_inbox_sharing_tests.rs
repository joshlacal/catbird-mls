//! Tests proving leaf-recovery backoff, cooldown, inbox sharing, and waiting outcome.
//!
//! (a) A pass with a live unexpired recovery request mints ZERO new requests.
//! (b) A burst of passes over five absent-group conversations performs one inbox fetch
//!     and at most one recovery request per conversation.
//! (c) Cooldown is honoured across passes and released on expiry or fulfilment.
//! (d) A rejoin that cannot proceed reports a waiting outcome with retry-after
//!     rather than an immediate-retry error.

mod e2e_harness;

use std::time::{Duration, Instant};

use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
use catbird_mls::orchestrator::DeferredRecoveryOutcome;
use catbird_mls::orchestrator::types::ConversationState;
use catbird_mls::orchestrator::MLSStorageBackend;
use e2e_harness::TestWorld;
use serde_json::json;

fn leaf(user_did: &str, device_id: &str, status: &str) -> serde_json::Value {
    json!({
        "userDid": user_did,
        "deviceId": device_id,
        "leafOrigin": "genesis",
        "keyId": "k",
        "deviceStatus": status
    })
}

fn count_operations(world: &TestWorld, op: CanonicalOperation) -> usize {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|r| r.operation == op)
        .count()
}

/// Helper: sets up Alice with Device 1 and Device 2 on `alice_did`,
/// creating a conversation where Device 1 is the active leaf.
/// Device 2 has no local MLS group (absent).
async fn setup_leafless_second_device(world: &mut TestWorld, convo_name: &str) -> (String, String, String) {
    let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    world.add_client_with_did("Alice", alice_did).await;
    world.register_device("Alice").await.expect("register alice device 1");

    let alice = world.client("Alice");
    let dev1_id = alice
        .orchestrator
        .require_actor_device_id()
        .await
        .expect("device 1 id");

    let created = alice
        .orchestrator
        .create_group(convo_name, None, None)
        .await
        .expect("create conversation");
    let convo_id = created.conversation_id;

    // Register second device on same account
    world.add_client_with_did("AliceDev2", alice_did).await;
    world.register_device("AliceDev2").await.expect("register alice device 2");

    // Device 1 holds an active leaf on server
    world.delivery_service().set_conversation_leaves_for_test(
        &convo_id,
        vec![leaf(alice_did, &dev1_id, "active")],
    );

    (convo_id, dev1_id, alice_did.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pass_with_live_unexpired_request_mints_zero_new_requests() {
    let mut world = TestWorld::new();
    let (_convo_id, _dev1_id, _alice_did) =
        setup_leafless_second_device(&mut world, "Live Request No Re-mint Test").await;

    let dev2 = world.client("AliceDev2");

    // Pass 1: AliceDev2 performs server sync.
    // Local MLS group is absent in FFI. Sibling Dev1 holds an active leaf.
    // Must mint exactly 1 RequestLeafRecovery.
    dev2.orchestrator.sync_with_server(false).await.expect("sync pass 1 succeeds");

    let requests_after_pass1 = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(
        requests_after_pass1, 1,
        "first pass must open exactly 1 leaf recovery request"
    );

    // Pass 2: Reconcile runs again while the recovery request is live and unexpired.
    // Must consult the live request / cooldown and mint ZERO new requests!
    dev2.orchestrator.sync_with_server(false).await.expect("sync pass 2 succeeds");

    let requests_after_pass2 = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(
        requests_after_pass2, 1,
        "second pass with live unexpired request must mint ZERO new requests (reused)"
    );

    // Pass 3: Another pass still mints ZERO new requests.
    dev2.orchestrator.sync_with_server(false).await.expect("sync pass 3 succeeds");

    let requests_after_pass3 = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(
        requests_after_pass3, 1,
        "subsequent pass with live request must continue minting ZERO new requests"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_burst_of_passes_over_five_absent_conversations_shares_inbox() {
    let mut world = TestWorld::new();
    let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    world.add_client_with_did("Alice", alice_did).await;
    world.register_device("Alice").await.expect("register alice device 1");

    let alice = world.client("Alice");
    let dev1_id = alice
        .orchestrator
        .require_actor_device_id()
        .await
        .expect("device 1 id");

    // Create 5 conversations with Alice Dev1 as active leaf
    let mut convo_ids = Vec::new();
    for i in 0..5 {
        let created = alice
            .orchestrator
            .create_group(&format!("convo_{i}"), None, None)
            .await
            .expect("create conversation");
        world.delivery_service().set_conversation_leaves_for_test(
            &created.conversation_id,
            vec![leaf(alice_did, &dev1_id, "active")],
        );
        convo_ids.push(created.conversation_id);
    }

    // Register AliceDev2 on same account (starts with absent local groups)
    world.add_client_with_did("AliceDev2", alice_did).await;
    world.register_device("AliceDev2").await.expect("register alice device 2");
    let dev2 = world.client("AliceDev2");

    // Initial state: 0 inbox fetches, 0 recovery requests
    assert_eq!(count_operations(&world, CanonicalOperation::GetLeafRecoveryInbox), 0);
    assert_eq!(count_operations(&world, CanonicalOperation::RequestLeafRecovery), 0);

    // --- Pass 1 ---
    // AliceDev2 syncs all 5 conversations with absent local groups.
    // Thanks to pass-level inbox sharing, GetLeafRecoveryInbox must be fetched
    // at most ONCE for the entire pass (not 5 times!).
    dev2.orchestrator.sync_with_server(false).await.expect("pass 1 succeeds");

    let inbox_fetches_pass1 = count_operations(&world, CanonicalOperation::GetLeafRecoveryInbox);
    let recovery_mints_pass1 = count_operations(&world, CanonicalOperation::RequestLeafRecovery);

    assert_eq!(
        inbox_fetches_pass1, 1,
        "pass 1 must perform exactly ONE inbox fetch shared across all 5 conversations (was 5)"
    );
    assert_eq!(
        recovery_mints_pass1, 5,
        "pass 1 must perform at most one recovery request per conversation (5 total)"
    );

    // --- Burst of 3 subsequent passes ---
    for pass in 2..=4 {
        dev2.orchestrator.sync_with_server(false).await.expect(&format!("pass {pass} succeeds"));
    }

    let recovery_mints_total = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(
        recovery_mints_total, 5,
        "burst of passes must mint ZERO additional requests across all 5 conversations (reused + cooldown)"
    );

    // In each subsequent pass, inbox fetch is at most 1 per pass
    let inbox_fetches_total = count_operations(&world, CanonicalOperation::GetLeafRecoveryInbox);
    assert!(
        inbox_fetches_total <= 4,
        "burst of 4 passes performs at most 1 inbox fetch per pass (total: {inbox_fetches_total})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cooldown_honoured_across_passes_and_released_on_expiry_or_fulfilment() {
    let mut world = TestWorld::new();
    let (convo_id, _dev1_id, _alice_did) =
        setup_leafless_second_device(&mut world, "Cooldown Expiry and Fulfilment Test").await;

    let dev2 = world.client("AliceDev2");

    // Pass 1: Mint leaf recovery request
    dev2.orchestrator.sync_with_server(false).await.expect("pass 1 succeeds");
    assert_eq!(count_operations(&world, CanonicalOperation::RequestLeafRecovery), 1);

    // Verify cooldown is active
    let cooldown = dev2
        .orchestrator
        .recovery_tracker()
        .lock()
        .await
        .leaf_recovery_cooldown_remaining(&convo_id);
    assert!(
        cooldown.is_some(),
        "cooldown must be active immediately after recovery request"
    );

    // Gate skips sync rejoin while cooldown is active
    let should_rejoin = dev2.orchestrator.should_attempt_sync_rejoin(&convo_id).await;
    assert!(
        !should_rejoin,
        "should_attempt_sync_rejoin must be false while liveRequest cooldown is active"
    );

    // --- Part A: Expiry releases cooldown immediately ---
    // Simulate request expiry by setting requested_at to 305 seconds ago (> 300s TTL)
    dev2.orchestrator
        .recovery_tracker()
        .lock()
        .await
        .note_leaf_recovery_requested_at(&convo_id, Instant::now() - Duration::from_secs(305));

    let cooldown_after_expiry = dev2
        .orchestrator
        .recovery_tracker()
        .lock()
        .await
        .leaf_recovery_cooldown_remaining(&convo_id);
    assert!(
        cooldown_after_expiry.is_none(),
        "expiry must release the cooldown immediately (cooldown_remaining is None)"
    );

    // --- Part B: Fulfilment releases cooldown immediately ---
    // Re-arm recovery request
    dev2.orchestrator
        .recovery_tracker()
        .lock()
        .await
        .note_leaf_recovery_requested(&convo_id);

    let rearmed_cooldown = dev2
        .orchestrator
        .recovery_tracker()
        .lock()
        .await
        .leaf_recovery_cooldown_remaining(&convo_id);
    assert!(rearmed_cooldown.is_some(), "re-armed request has active cooldown");

    // Fulfilment signal arrives (e.g. clear_leaf_recovery_wait or group change)
    dev2.orchestrator
        .recovery_tracker()
        .lock()
        .await
        .clear_leaf_recovery_wait(&convo_id);

    let cooldown_after_fulfilment = dev2
        .orchestrator
        .recovery_tracker()
        .lock()
        .await
        .leaf_recovery_cooldown_remaining(&convo_id);
    assert!(
        cooldown_after_fulfilment.is_none(),
        "fulfilment signal must release the cooldown immediately"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rejoin_cannot_proceed_reports_waiting_with_retry_after() {
    let mut world = TestWorld::new();
    let (convo_id, _dev1_id, _alice_did) =
        setup_leafless_second_device(&mut world, "Waiting Outcome Test").await;

    let dev2 = world.client("AliceDev2");

    // Pass 1: opens recovery request
    dev2.orchestrator.sync_with_server(false).await.expect("pass 1 succeeds");

    // Consume deferred recovery on this waiting conversation
    let outcome = dev2
        .orchestrator
        .consume_deferred_recovery_for_conversation(&convo_id, Some(1), None)
        .await
        .expect("consume_deferred_recovery should succeed with Waiting, not error");

    match outcome {
        DeferredRecoveryOutcome::Waiting { retry_after } => {
            assert!(
                retry_after > Duration::from_secs(0),
                "waiting outcome must carry positive retry_after"
            );
            assert!(
                retry_after <= Duration::from_secs(300),
                "waiting retry_after should be bounded by request TTL"
            );
        }
        other => panic!("expected DeferredRecoveryOutcome::Waiting, got: {:?}", std::mem::discriminant(&other)),
    }

    // Stored conversation state remains honest: still NeedsRejoin, not marked Active or deleted
    let needs_rejoin = dev2
        .orchestrator
        .storage()
        .needs_rejoin(&convo_id)
        .await
        .expect("needs_rejoin storage query succeeds");
    assert!(
        needs_rejoin,
        "conversation stored state must remain honest (needs_rejoin is true)"
    );

    let state = dev2
        .orchestrator
        .storage()
        .get_conversation_state(&convo_id)
        .await
        .expect("get_conversation_state succeeds")
        .expect("state exists");
    assert_eq!(
        state,
        ConversationState::NeedsRejoin,
        "stored conversation state must be NeedsRejoin"
    );

    // run_deferred_recovery report must count this as waiting, NOT failure
    let report = dev2
        .orchestrator
        .run_deferred_recovery("test_waiting_sweep")
        .await
        .expect("run_deferred_recovery succeeds");
    assert_eq!(report.failed, 0, "waiting conversation must not count as failure");
    assert!(
        report.waiting >= 1 || report.skipped >= 1,
        "waiting conversation must be counted in waiting/skipped report: {report:?}"
    );
}
