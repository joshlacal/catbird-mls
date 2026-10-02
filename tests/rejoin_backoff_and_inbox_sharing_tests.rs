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

use catbird_mls::orchestrator::canonical_transport::{CanonicalOperation, GatewayResponse};
use catbird_mls::orchestrator::error::OrchestratorError;
use catbird_mls::orchestrator::types::ConversationState;
use catbird_mls::orchestrator::DeferredRecoveryOutcome;
use catbird_mls::orchestrator::MLSStorageBackend;
use e2e_harness::TestWorld;
use serde_json::{json, Value};

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
async fn setup_leafless_second_device(
    world: &mut TestWorld,
    convo_name: &str,
) -> (String, String, String) {
    let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    world.add_client_with_did("Alice", alice_did).await;
    world
        .register_device("Alice")
        .await
        .expect("register alice device 1");

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
    world
        .register_device("AliceDev2")
        .await
        .expect("register alice device 2");

    // Device 1 holds an active leaf on server
    world
        .delivery_service()
        .set_conversation_leaves_for_test(&convo_id, vec![leaf(alice_did, &dev1_id, "active")]);

    (convo_id, dev1_id, alice_did.to_string())
}

struct RecoveryBatchFixture {
    world: TestWorld,
    conversations: Vec<(String, Vec<u8>, u64)>,
    packages_before: usize,
    requests_before: usize,
}

async fn outstanding_recovery_batch() -> RecoveryBatchFixture {
    let mut world = TestWorld::new();
    let (first, dev1_id, alice_did) =
        setup_leafless_second_device(&mut world, "expiry batch first").await;
    let second = world
        .client("Alice")
        .orchestrator
        .create_group("expiry batch second", None, None)
        .await
        .unwrap()
        .conversation_id;
    world
        .delivery_service()
        .set_conversation_leaves_for_test(&second, vec![leaf(&alice_did, &dev1_id, "active")]);
    world
        .client("AliceDev2")
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("initial sync opens one recovery request per absent group");

    let requests_before = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(requests_before, 2);
    let mut conversations = Vec::new();
    for conversation_id in [first, second] {
        let alice = world.client("Alice");
        let group_id = hex::decode(
            &alice.orchestrator.conversations().lock().await[&conversation_id].group_id,
        )
        .unwrap();
        let epoch = alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id.clone())
            .unwrap();
        conversations.push((conversation_id, group_id, epoch));
    }
    let packages_before = world.delivery_service().key_package_count(&alice_did);
    RecoveryBatchFixture {
        world,
        conversations,
        packages_before,
        requests_before,
    }
}

fn inventory_page(expiry: Option<Value>, next: Option<&str>) -> GatewayResponse {
    let mut body = json!({
        "items": [],
        "inventorySessionId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "snapshotEventCursor": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "hasMore": next.is_some(),
    });
    if let Some(expiry) = expiry {
        body["snapshotExpiresAt"] = expiry;
    }
    if let Some(next) = next {
        body["nextPageCursor"] = json!(next);
    }
    GatewayResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn valid_expiry() -> Option<Value> {
    // Raw readers bind this server expiry; the authenticated-ingest path owns
    // clock freshness. Keep this historical fixture usable without a fake clock.
    Some(json!("2026-08-20T12:00:00.000Z"))
}

fn invalid_expiries() -> Vec<(&'static str, Option<Value>)> {
    vec![
        ("missing", None),
        ("null", Some(Value::Null)),
        ("non-string", Some(json!(1724155200))),
        ("invalid date", Some(json!("2026-02-30T12:00:00.000Z"))),
    ]
}

async fn assert_batch_preserved(fixture: &RecoveryBatchFixture) {
    let world = &fixture.world;
    assert_eq!(
        count_operations(world, CanonicalOperation::RequestLeafRecovery),
        fixture.requests_before,
        "invalid shared evidence must not replace an outstanding recovery request"
    );
    assert_eq!(count_operations(world, CanonicalOperation::RequestReset), 0);
    assert_eq!(
        count_operations(world, CanonicalOperation::ActivateReset),
        0
    );
    assert_eq!(
        world
            .delivery_service()
            .key_package_count(&world.client("Alice").did),
        fixture.packages_before,
        "all existing reservations and remaining KeyPackages must survive"
    );
    for (conversation_id, group_id, epoch) in &fixture.conversations {
        assert_eq!(
            world
                .delivery_service()
                .bootstrap_reset_group_call_count(conversation_id),
            0
        );
        assert_eq!(
            world
                .client("Alice")
                .orchestrator
                .mls_context()
                .get_epoch(group_id.clone())
                .unwrap(),
            *epoch,
            "the active sibling's group must keep its original epoch"
        );
        let device = world.client("AliceDev2");
        assert!(
            device
                .orchestrator
                .mls_context()
                .get_epoch(group_id.clone())
                .is_err(),
            "invalid evidence must not fabricate a local group"
        );
        assert!(device.storage.needs_rejoin(conversation_id).await.unwrap());
        assert_eq!(
            device
                .storage
                .get_conversation_state(conversation_id)
                .await
                .unwrap(),
            Some(ConversationState::NeedsRejoin)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_recovery_batch_rejects_missing_or_malformed_inventory_expiry() {
    for (case, expiry) in invalid_expiries() {
        let fixture = outstanding_recovery_batch().await;
        let world = &fixture.world;
        let sessions_before = count_operations(world, CanonicalOperation::GetConversations);
        let inbox_before = count_operations(world, CanonicalOperation::GetLeafRecoveryInbox);
        world
            .delivery_service()
            .set_next_inventory_result_for_test(Ok(inventory_page(expiry.clone(), None)));
        // Matching malformed metadata in both readers must not bypass expiry
        // validation or silently convert an absent value into unbound evidence.
        world
            .delivery_service()
            .set_leaf_recovery_inbox_responses(vec![inventory_page(expiry, None)]);

        let error = world
            .client("AliceDev2")
            .orchestrator
            .run_deferred_recovery("malformed-inventory-expiry")
            .await
            .expect_err(&format!(
                "{case} allocation expiry cannot authorize a batch"
            ));

        assert!(
            matches!(error, OrchestratorError::InvalidInput(_)),
            "{case}: expected an invalid inventory error, got {error:?}"
        );
        assert_eq!(
            count_operations(world, CanonicalOperation::GetConversations) - sessions_before,
            1
        );
        assert_eq!(
            count_operations(world, CanonicalOperation::GetLeafRecoveryInbox),
            inbox_before,
            "{case}: reject before allocating any shared inbox evidence"
        );
        assert_batch_preserved(&fixture).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_recovery_batch_rejects_missing_malformed_or_changed_inventory_continuation_expiry() {
    let mut cases = invalid_expiries();
    cases.push(("changed", Some(json!("2026-08-20T12:00:01.000Z"))));
    for (case, expiry) in cases {
        let fixture = outstanding_recovery_batch().await;
        let world = &fixture.world;
        let sessions_before = count_operations(world, CanonicalOperation::GetConversations);
        let inbox_before = count_operations(world, CanonicalOperation::GetLeafRecoveryInbox);
        world
            .delivery_service()
            .queue_inventory_result_for_test(Ok(inventory_page(
                valid_expiry(),
                Some("inventory-page-two"),
            )));
        world
            .delivery_service()
            .queue_inventory_result_for_test(Ok(inventory_page(expiry, None)));

        let error = world
            .client("AliceDev2")
            .orchestrator
            .run_deferred_recovery("changed-inventory-continuation-expiry")
            .await
            .expect_err(&format!(
                "{case} continuation expiry cannot authorize a batch"
            ));

        assert!(
            matches!(error, OrchestratorError::InvalidInput(_)),
            "{case}: expected an invalid inventory error, got {error:?}"
        );
        assert_eq!(
            count_operations(world, CanonicalOperation::GetConversations) - sessions_before,
            2
        );
        assert_eq!(
            count_operations(world, CanonicalOperation::GetLeafRecoveryInbox),
            inbox_before,
            "{case}: all inventory pages must agree before sharing inbox evidence"
        );
        assert_batch_preserved(&fixture).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_recovery_batch_rejects_missing_malformed_or_changed_inbox_expiry_on_every_page() {
    for bad_page_index in 0..=1 {
        let mut cases = invalid_expiries();
        cases.push(("changed", Some(json!("2026-08-20T12:00:01.000Z"))));
        for (case, expiry) in cases {
            let fixture = outstanding_recovery_batch().await;
            let world = &fixture.world;
            let sessions_before = count_operations(world, CanonicalOperation::GetConversations);
            let inbox_before = count_operations(world, CanonicalOperation::GetLeafRecoveryInbox);
            let mut pages = Vec::new();
            if bad_page_index == 1 {
                pages.push(inventory_page(valid_expiry(), Some("inbox-page-two")));
            }
            pages.push(inventory_page(expiry, None));
            world
                .delivery_service()
                .set_leaf_recovery_inbox_responses(pages);

            let error = world
                .client("AliceDev2")
                .orchestrator
                .run_deferred_recovery("malformed-inbox-expiry")
                .await
                .expect_err(&format!(
                    "{case} inbox expiry on page {bad_page_index} cannot authorize a batch"
                ));

            assert!(
                matches!(error, OrchestratorError::InvalidInput(_)),
                "{case}: expected an invalid inbox error, got {error:?}"
            );
            assert_eq!(
                count_operations(world, CanonicalOperation::GetConversations) - sessions_before,
                1
            );
            assert_eq!(
                count_operations(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
                bad_page_index + 1
            );
            assert_batch_preserved(&fixture).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_recovery_batch_shares_paginated_inbox_with_unchanged_valid_expiry() {
    let fixture = outstanding_recovery_batch().await;
    let world = &fixture.world;
    let sessions_before = count_operations(world, CanonicalOperation::GetConversations);
    let inbox_before = count_operations(world, CanonicalOperation::GetLeafRecoveryInbox);
    for next in [Some("inventory-page-two"), None] {
        world
            .delivery_service()
            .queue_inventory_result_for_test(Ok(inventory_page(valid_expiry(), next)));
    }
    world
        .delivery_service()
        .set_leaf_recovery_inbox_responses(vec![
            inventory_page(valid_expiry(), Some("inbox-page-two")),
            inventory_page(valid_expiry(), None),
        ]);

    let report = world
        .client("AliceDev2")
        .orchestrator
        .run_deferred_recovery("valid-paginated-expiry")
        .await
        .expect("valid bound expiry remains usable by both batch readers");

    assert_eq!(report.failed, 0);
    assert_eq!(report.waiting, 2);
    assert_eq!(
        count_operations(world, CanonicalOperation::GetConversations) - sessions_before,
        2
    );
    assert_eq!(
        count_operations(world, CanonicalOperation::GetLeafRecoveryInbox) - inbox_before,
        2,
        "the same two-page inbox is shared by both waiting conversations"
    );
    assert_batch_preserved(&fixture).await;
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
    dev2.orchestrator
        .sync_with_server(false)
        .await
        .expect("sync pass 1 succeeds");

    let requests_after_pass1 = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(
        requests_after_pass1, 1,
        "first pass must open exactly 1 leaf recovery request"
    );

    // Pass 2: Reconcile runs again while the recovery request is live and unexpired.
    // Must consult the live request / cooldown and mint ZERO new requests!
    dev2.orchestrator
        .sync_with_server(false)
        .await
        .expect("sync pass 2 succeeds");

    let requests_after_pass2 = count_operations(&world, CanonicalOperation::RequestLeafRecovery);
    assert_eq!(
        requests_after_pass2, 1,
        "second pass with live unexpired request must mint ZERO new requests (reused)"
    );

    // Pass 3: Another pass still mints ZERO new requests.
    dev2.orchestrator
        .sync_with_server(false)
        .await
        .expect("sync pass 3 succeeds");

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
    world
        .register_device("Alice")
        .await
        .expect("register alice device 1");

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
    world
        .register_device("AliceDev2")
        .await
        .expect("register alice device 2");
    let dev2 = world.client("AliceDev2");

    // Initial state: 0 inbox fetches, 0 recovery requests
    assert_eq!(
        count_operations(&world, CanonicalOperation::GetLeafRecoveryInbox),
        0
    );
    assert_eq!(
        count_operations(&world, CanonicalOperation::RequestLeafRecovery),
        0
    );

    // --- Pass 1 ---
    // AliceDev2 syncs all 5 conversations with absent local groups.
    // Thanks to pass-level inbox sharing, GetLeafRecoveryInbox must be fetched
    // at most ONCE for the entire pass (not 5 times!).
    dev2.orchestrator
        .sync_with_server(false)
        .await
        .expect("pass 1 succeeds");

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
        dev2.orchestrator
            .sync_with_server(false)
            .await
            .expect(&format!("pass {pass} succeeds"));
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
    dev2.orchestrator
        .sync_with_server(false)
        .await
        .expect("pass 1 succeeds");
    assert_eq!(
        count_operations(&world, CanonicalOperation::RequestLeafRecovery),
        1
    );

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
    let should_rejoin = dev2
        .orchestrator
        .should_attempt_sync_rejoin(&convo_id)
        .await;
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
    assert!(
        rearmed_cooldown.is_some(),
        "re-armed request has active cooldown"
    );

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
    dev2.orchestrator
        .sync_with_server(false)
        .await
        .expect("pass 1 succeeds");

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
        other => panic!(
            "expected DeferredRecoveryOutcome::Waiting, got: {:?}",
            std::mem::discriminant(&other)
        ),
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
    assert_eq!(
        report.failed, 0,
        "waiting conversation must not count as failure"
    );
    assert!(
        report.waiting >= 1 || report.skipped >= 1,
        "waiting conversation must be counted in waiting/skipped report: {report:?}"
    );
}
