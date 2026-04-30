//! Integration tests reproducing critical state machine bugs in the MLS orchestrator.
//!
//! These tests exercise the orchestrator's messaging, group lifecycle, sync, and
//! recovery flows using the E2E test harness (TestWorld + mock backends).
//!
//! Tests marked `#[ignore]` reproduce **known bugs** documented in the Phase 0
//! analysis. Run with `cargo test -- --ignored` to see failures.
//!
//! Bug references:
//!   - state-machine-messaging.md  (messaging flow bugs)
//!   - state-machine-groups.md     (group lifecycle bugs)
//!   - state-machine-recovery.md   (recovery / sync bugs)

#![allow(dead_code)]

mod e2e_harness;

// Re-use the TestWorld / TestClient infrastructure from e2e_harness.
use catbird_mls::orchestrator::error::{OrchestratorError, Result as OrcResult};
use catbird_mls::orchestrator::MLSAPIClient;
use e2e_harness::TestWorld;

// ---------------------------------------------------------------------------
// 1. Golden-path smoke test — should always pass
// ---------------------------------------------------------------------------

/// Smoke test: Alice creates a group, registers devices, sends a message.
/// Validates the happy path through:
///   create_group → ensure_device_registered → send_message → local storage
#[tokio::test(flavor = "multi_thread")]
async fn test_send_message_basic() {
    let mut world = TestWorld::new();

    // Set up two clients
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    // Register devices (generates key packages, registers with server)
    let _alice_mls_did = world
        .register_device("Alice")
        .await
        .expect("Alice device registration failed");
    let _bob_mls_did = world
        .register_device("Bob")
        .await
        .expect("Bob device registration failed");

    let alice = world.client("Alice");

    // Alice creates a group (no initial members — avoids MLS commit mismatch
    // with mock server which doesn't exchange real commit_data)
    let convo = alice
        .orchestrator
        .create_group("Test Chat", None, None)
        .await
        .expect("create_group failed");

    let group_id = &convo.group_id;

    // Alice sends a message
    let sent = alice
        .orchestrator
        .send_message(group_id, "Hello from Alice!")
        .await
        .expect("send_message failed");

    assert_eq!(sent.text, "Hello from Alice!");
    assert!(sent.is_own);

    // Verify the message was stored locally for Alice
    let alice_msgs = alice.storage.get_conversation_messages(group_id);
    assert!(
        !alice_msgs.is_empty(),
        "Alice should have stored the sent message"
    );
    assert_eq!(alice_msgs[0].text, "Hello from Alice!");
}

// ---------------------------------------------------------------------------
// 2. Self-message echo dedup bug
// ---------------------------------------------------------------------------

/// FIXED: Self-echo dedup now works across restarts via persistent pending_messages.
///
/// The mock now uses client-provided message IDs (send_message_with_id), and the
/// orchestrator persists pending_messages to storage. After clearing the in-memory
/// own_commits and pending_messages (simulating app restart), the persistent storage
/// fallback in process_incoming correctly deduplicates the echo.
///
/// Three dedup layers:
///   1. message_exists() — catches echoes when local storage has the message ID
///   2. own_commits hash — in-memory fast path for ciphertext matching
///   3. pending_messages — persistent fallback for self-echo after restart
///
/// Ref: state-machine-messaging.md §3
#[tokio::test(flavor = "multi_thread")]
async fn test_self_message_echo() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Create a solo group
    let convo = alice
        .orchestrator
        .create_group("Solo", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    // Send a message (inserts into own_commits, in-memory pending_messages, AND persistent storage)
    let _sent = alice
        .orchestrator
        .send_message(group_id, "echo test")
        .await
        .expect("send_message failed");

    // Clear BOTH in-memory caches to fully simulate app restart
    // (own_commits and pending_messages are in-memory only)
    alice.orchestrator.own_commits().lock().await.clear();
    alice.orchestrator.pending_messages().lock().await.clear();

    // Fetch messages from server — Alice's own message echoes back.
    // Dedup must still work via persistent pending_messages in storage.
    let (fetched, _cursor) = alice
        .orchestrator
        .fetch_messages(group_id, None, 100, None, None, None)
        .await
        .expect("fetch_messages failed");

    // Echo should be deduped — either by message_exists (local storage has the
    // same ID) or by persistent pending_messages fallback.
    assert!(
        fetched.is_empty(),
        "Own message echo should be deduped after restart simulation, \
         but got {} messages — dedup is broken",
        fetched.len()
    );

    // Verify no duplicate was stored: storage should still have exactly 1 message
    let all_msgs = alice.storage.get_conversation_messages(group_id);
    assert_eq!(
        all_msgs.len(),
        1,
        "Should have exactly 1 message (original), got {}",
        all_msgs.len()
    );
    assert_eq!(all_msgs[0].text, "echo test");
}

// ---------------------------------------------------------------------------
// 3. Commit messages don't advance epoch
// ---------------------------------------------------------------------------

/// REGRESSION TEST FOR TASK #58:
/// `decrypt_message` stages an incoming commit in `pending_incoming_merges` but
/// does NOT merge it into the local MLS group. Callers of the orchestrator's
/// HTTP-sync path (`process_incoming`, reached from `fetch_messages` and
/// `sync_with_server`) must explicitly call `merge_incoming_commit` to advance
/// the local epoch. Task #58 wired that call into the commit branch at
/// `messaging.rs:672-718`.
///
/// Scenario (multi-client, exercises the fixed branch):
///   1. Alice creates a group with Bob as an initial member (epoch 1 on both).
///   2. Bob joins via the Welcome the mock fanned out to him.
///   3. Carol registers so Bob can fetch her key package.
///   4. Bob adds Carol — produces a commit at epoch 2 on Bob's side; the mock
///      stores the commit ciphertext as a message in the conversation so other
///      members (Alice) will see it.
///   5. Alice's `fetch_messages` pulls Bob's commit; `process_incoming` calls
///      `decrypt_message` (stages the commit) and then — thanks to #58 —
///      `merge_incoming_commit` (merges it into Alice's MLS group).
///
/// Assertion target: `mls_context.get_epoch(group_id)` — the AUTHORITATIVE
/// local MLS epoch, NOT the cached `group_states.epoch`. The cached value is
/// written directly by the `messaging.rs:722-736` block after a successful
/// stage, so it advances even without the #58 merge call; asserting on the
/// cache would make this test pass with or without the fix.
///
/// Without the #58 fix: `decrypt_message` stages the commit but never merges
/// it. Alice's authoritative MLS epoch stays at 1, even though the cached
/// `group_states.epoch` advances to 2. The assertion below therefore FAILS,
/// proving the test exercises the fixed path.
///
/// Ref: commit 3cc27ec, state-machine-messaging.md §6.
#[tokio::test(flavor = "multi_thread")]
async fn test_commit_messages_advance_epoch() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Carol").await;

    // Registering a device publishes an initial batch of key packages.
    let _a = world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();
    let _c = world.register_device("Carol").await.unwrap();

    // ----- Step 1: Alice creates the group with Bob as an initial member.
    // `create_group_inner` runs `mls_context.add_members(bob_kp)`, ships the
    // commit + Welcome to the mock server, and merges Alice's pending commit
    // locally. Alice ends at epoch 1.
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Epoch Test", Some(&[bob_did.clone()]), None)
        .await
        .expect("alice create_group failed");
    let group_id = convo.group_id.clone();
    let group_id_bytes = hex::decode(&group_id).expect("invalid group id hex");

    let alice_epoch_after_create = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes.clone())
        .expect("alice get_epoch after create failed");
    assert_eq!(
        alice_epoch_after_create, 1,
        "Alice's MLS epoch should be 1 after creating the group with Bob",
    );

    // ----- Step 2: Bob joins via the Welcome fanned out by the mock.
    let bob = world.client("Bob");
    let bob_welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&group_id)
        .await
        .expect("bob get_welcome failed");
    let bob_convo = bob
        .orchestrator
        .join_group(&bob_welcome)
        .await
        .expect("bob join_group failed");
    assert_eq!(bob_convo.group_id, group_id);
    let bob_epoch_after_join = bob
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes.clone())
        .expect("bob get_epoch after join failed");
    assert_eq!(
        bob_epoch_after_join, 1,
        "Bob's MLS epoch should be 1 after joining via Welcome",
    );

    // ----- Step 3: Bob commits `add_members(Carol)`. Bob's local MLS epoch
    // advances to 2; the mock stores Bob's commit ciphertext as a message in
    // the conversation, which Alice's next `fetch_messages` will pull.
    let carol_did = world.client("Carol").did.clone();
    bob.orchestrator
        .add_members(&group_id, &[carol_did])
        .await
        .expect("bob add_members(carol) failed");
    let bob_epoch_after_add = bob
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes.clone())
        .expect("bob get_epoch after add_members failed");
    assert_eq!(
        bob_epoch_after_add, 2,
        "Bob's MLS epoch should be 2 after adding Carol",
    );

    // ----- Step 4: Alice syncs. Her `process_incoming` hits the commit branch
    // at `messaging.rs:653`, decrypts the staged commit, and — with the #58
    // fix — calls `merge_incoming_commit` to advance her authoritative MLS
    // epoch from 1 to 2. Without the fix, `decrypt_message` stages the commit
    // but never merges it; the cached `group_states.epoch` still advances (via
    // the block at `messaging.rs:722-736`), but `mls_context.get_epoch`
    // remains at 1, which is what we assert on below.
    let alice = world.client("Alice");
    let (_fetched, _cursor) = alice
        .orchestrator
        .fetch_messages(&group_id, None, 100, None, None, None)
        .await
        .expect("alice fetch_messages failed");

    let alice_epoch_after_sync = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes)
        .expect("alice get_epoch after sync failed");

    assert_eq!(
        alice_epoch_after_sync, 2,
        "Alice's AUTHORITATIVE MLS epoch must advance to 2 after processing \
         Bob's incoming commit. Got {alice_epoch_after_sync}. This fails when \
         `process_incoming`'s commit branch stages the commit without calling \
         `merge_incoming_commit` — the exact gap task #58 (commit 3cc27ec) \
         closed.",
    );
}

// ---------------------------------------------------------------------------
// 4. Circuit breaker is a permanent death spiral
// ---------------------------------------------------------------------------

/// BUG: Once consecutive_sync_failures >= max_consecutive_sync_failures (5),
/// sync_with_server returns Ok(()) without doing anything. Since success
/// resets the counter (sync.rs:56) but sync never runs, the counter never
/// resets. The circuit breaker is permanent.
///
/// Scenario: Inject N consecutive sync failures to trip the breaker, then
/// restore server health. Verify that sync NEVER recovers.
///
/// Ref: state-machine-messaging.md §5 (sync.rs:28-37), state-machine-recovery.md §7.5
///
/// Expected fix: Add a timeout/backoff that eventually resets the counter,
/// or return a distinct error when circuit-broken so callers can act.
#[tokio::test(flavor = "multi_thread")]
async fn test_circuit_breaker_recovery() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Create a conversation so sync has something to work with
    alice
        .orchestrator
        .create_group("Circuit Test", None, None)
        .await
        .expect("create_group failed");

    // Inject enough failures to trip the circuit breaker (default max = 5)
    // Each sync calls get_conversations, which we'll make fail.
    world.delivery_service().fail_get_conversations_n_times(6);

    for i in 0..6 {
        let result = alice.orchestrator.sync_with_server(false).await;
        // First 5 should fail, 6th might be silently skipped
        if i < 5 {
            assert!(result.is_err(), "Sync #{i} should have failed");
        }
    }

    // Circuit breaker is now tripped. Even though the server is healthy,
    // sync should be permanently skipped.
    // Make the server healthy again (no more injected failures).

    // Try syncing multiple times — with the bug, ALL will silently succeed
    // (Ok(())) without actually syncing.
    let mut any_sync_ran = false;
    for _ in 0..10 {
        let result = alice.orchestrator.sync_with_server(false).await;
        // If sync actually ran and succeeded, the circuit breaker should reset.
        // But with the bug, it never runs.
        if result.is_err() {
            // If it errors, sync at least attempted to run
            any_sync_ran = true;
        }
    }

    // The real test: after "recovery", does the sync actually contact the server?
    // With the bug, it doesn't — sync is permanently dead.
    // We verify by checking that at least one sync attempt actually ran.
    // A working circuit breaker would eventually retry after a cooldown.
    assert!(
        any_sync_ran,
        "After server recovery, sync should eventually resume, \
         but circuit breaker is permanently tripped"
    );
}

// ---------------------------------------------------------------------------
// 5. Server rejection leaves orphaned pending commit
// ---------------------------------------------------------------------------

/// BUG: When add_members() sends a commit to the server and the server
/// rejects it (returns success=false), the function returns MemberSyncFailed.
/// But the pending commit created by mls_context.add_members() is never
/// cleared. Subsequent operations on the group will fail because OpenMLS
/// rejects creating a new commit while one is pending.
///
/// Ref: state-machine-groups.md §4 (groups.rs:297-299), §8 Invariant 3
///
/// Expected fix: On server rejection, call mls_context.clear_pending_commit()
/// to discard the orphaned commit.
#[tokio::test(flavor = "multi_thread")]
async fn test_add_members_server_rejection_cleanup() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    let _a = world.register_device("Alice").await.unwrap();
    let _b = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    // Alice creates a group
    let convo = alice
        .orchestrator
        .create_group("Rejection Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    // Make the server reject the next add_members (returns success=false)
    world.delivery_service().reject_next_add_members();

    // Alice tries to add Bob — should fail with MemberSyncFailed
    let result = alice
        .orchestrator
        .add_members(group_id, &[bob.did.clone()])
        .await;
    assert!(
        result.is_err(),
        "add_members should fail on server rejection"
    );

    // Now try the same operation again — adding Bob.
    // With the bug: this fails because the pending commit from the rejected
    // add is still lingering in OpenMLS.
    let result2 = alice
        .orchestrator
        .add_members(group_id, &[bob.did.clone()])
        .await;

    assert!(
        result2.is_ok(),
        "After server rejection, subsequent add_members should succeed, \
         but the orphaned pending commit blocks it: {:?}",
        result2.err()
    );
}

// ---------------------------------------------------------------------------
// 6. Force rejoin cleans state
// ---------------------------------------------------------------------------

/// Tests that force_rejoin properly cleans up old MLS state and allows the
/// client to resume operations in the new epoch.
///
/// Note: force_rejoin's delete_group only removes from the in-memory HashMap,
/// NOT from OpenMLS SQLite storage (state-machine-recovery.md §1.2).
/// This test verifies the functional flow works even if storage leaks.
#[tokio::test(flavor = "multi_thread")]
async fn test_force_rejoin_cleans_state() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;

    let _a = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Create a group
    let convo = alice
        .orchestrator
        .create_group("Rejoin Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    let epoch_before = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(group_id)
        .map(|gs| gs.epoch)
        .unwrap_or(0);

    // Publish group info (needed for force_rejoin's get_group_info)
    // (create_group already publishes it, so this should be available)

    // Force rejoin
    let result = alice.orchestrator.force_rejoin(group_id).await;
    assert!(result.is_ok(), "force_rejoin failed: {:?}", result.err());

    // Verify epoch advanced after rejoin
    let epoch_after = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(group_id)
        .map(|gs| gs.epoch)
        .unwrap_or(0);

    assert!(
        epoch_after > epoch_before,
        "Epoch should advance after force_rejoin (before={}, after={})",
        epoch_before,
        epoch_after
    );

    // Verify Alice can still send messages in the new epoch
    let send_result = alice
        .orchestrator
        .send_message(group_id, "After rejoin")
        .await;
    assert!(
        send_result.is_ok(),
        "Should be able to send messages after rejoin: {:?}",
        send_result.err()
    );
}

// ---------------------------------------------------------------------------
// 7. Message decryption across epoch advance
// ---------------------------------------------------------------------------

/// Tests that a message can be sent at epoch N, then another operation advances
/// the epoch, and the client can still send at the new epoch.
///
/// Ref: state-machine-messaging.md §6 — max_past_epochs config
#[tokio::test(flavor = "multi_thread")]
async fn test_message_after_epoch_advance() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;

    let _a = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Alice creates a group
    let convo = alice
        .orchestrator
        .create_group("Epoch Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    // Send a message at the current epoch
    let msg1 = alice
        .orchestrator
        .send_message(group_id, "Before epoch advance")
        .await
        .expect("send_message failed");

    let epoch_before = msg1.epoch;

    // Force rejoin to advance the epoch (simulates an epoch advance)
    alice
        .orchestrator
        .force_rejoin(group_id)
        .await
        .expect("force_rejoin failed");

    let epoch_after = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(group_id)
        .map(|gs| gs.epoch)
        .unwrap_or(0);

    assert!(
        epoch_after > epoch_before,
        "Epoch should have advanced after force_rejoin"
    );

    // Verify Alice can still send at the new epoch
    let msg2 = alice
        .orchestrator
        .send_message(group_id, "After epoch advance")
        .await;
    assert!(
        msg2.is_ok(),
        "Should be able to send at new epoch: {:?}",
        msg2.err()
    );
}

// ---------------------------------------------------------------------------
// 8. Concurrent sync doesn't deadlock
// ---------------------------------------------------------------------------

/// BUG: sync_in_progress is a Mutex<bool> that is manually released
/// (sync.rs:52). If do_sync() panics, the flag is never reset to false,
/// permanently blocking all future syncs.
///
/// This test verifies that two concurrent sync calls don't deadlock and
/// that the sync_in_progress flag is always properly reset.
///
/// Ref: state-machine-messaging.md §5 (sync.rs:41-52)
///
/// Expected fix: Use a proper RAII guard (e.g., MutexGuard or scopeguard)
/// instead of manual flag management.
#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_sync_not_blocked() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Create a conversation for sync to discover
    alice
        .orchestrator
        .create_group("Concurrent Sync Test", None, None)
        .await
        .expect("create_group failed");

    // Run two syncs concurrently. One should proceed, the other should
    // return Ok(()) immediately (already syncing).
    let sync1 = alice.orchestrator.sync_with_server(false);
    let sync2 = alice.orchestrator.sync_with_server(false);

    let (r1, r2): (OrcResult<()>, OrcResult<()>) = tokio::join!(sync1, sync2);

    // Both should complete without error (one runs, one skips)
    assert!(r1.is_ok(), "First sync failed: {:?}", r1.err());
    assert!(r2.is_ok(), "Second sync failed: {:?}", r2.err());

    // After both complete, sync_in_progress should be reset to false.
    // Verify by running another sync — it should not be permanently blocked.
    let r3: OrcResult<()> = alice.orchestrator.sync_with_server(false).await;
    assert!(
        r3.is_ok(),
        "Sync after concurrent syncs should work, but sync_in_progress \
         may be stuck: {:?}",
        r3.err()
    );
}

// ---------------------------------------------------------------------------
// 9. Concurrent rejoin dedup
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_force_rejoin_deduped() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Concurrent Rejoin Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    world
        .delivery_service()
        .set_process_external_commit_delay_ms(100);

    let rejoin1 = alice.orchestrator.force_rejoin(group_id);
    let rejoin2 = alice.orchestrator.force_rejoin(group_id);
    let (r1, r2): (OrcResult<()>, OrcResult<()>) = tokio::join!(rejoin1, rejoin2);

    assert!(r1.is_ok(), "First force_rejoin failed: {:?}", r1.err());
    assert!(r2.is_ok(), "Second force_rejoin failed: {:?}", r2.err());
    assert_eq!(
        world.delivery_service().external_commit_count(group_id),
        1,
        "Only one external commit should be sent for concurrent force_rejoin calls"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_join_or_rejoin_deduped() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Concurrent Join Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    let group_id_bytes = hex::decode(group_id).expect("invalid group id hex");
    alice
        .orchestrator
        .mls_context()
        .delete_group(group_id_bytes)
        .expect("delete_group failed");

    world
        .delivery_service()
        .set_process_external_commit_delay_ms(100);

    let join1 = alice.orchestrator.join_or_rejoin(group_id);
    let join2 = alice.orchestrator.join_or_rejoin(group_id);
    let (r1, r2): (OrcResult<u64>, OrcResult<u64>) = tokio::join!(join1, join2);

    assert!(r1.is_ok(), "First join_or_rejoin failed: {:?}", r1.err());
    assert!(r2.is_ok(), "Second join_or_rejoin failed: {:?}", r2.err());
    assert_eq!(
        world.delivery_service().external_commit_count(group_id),
        1,
        "Only one external commit should be sent for concurrent join_or_rejoin calls"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sync_rejoin_skips_when_attempt_in_flight() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Sync Rejoin InFlight Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();

    let group_id_bytes = hex::decode(&group_id).expect("invalid group id hex");
    alice
        .orchestrator
        .mls_context()
        .delete_group(group_id_bytes)
        .expect("delete_group failed");
    alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .remove(&group_id);

    world
        .delivery_service()
        .set_process_external_commit_delay_ms(350);

    let in_flight_rejoin = alice.orchestrator.force_rejoin(&group_id);
    let sync_while_rejoin_in_flight = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        let result = alice.orchestrator.sync_with_server(false).await;
        (result, started.elapsed())
    };

    let (rejoin_result, (sync_result, sync_elapsed)): (
        OrcResult<()>,
        (OrcResult<()>, std::time::Duration),
    ) = tokio::join!(in_flight_rejoin, sync_while_rejoin_in_flight);

    assert!(
        rejoin_result.is_ok(),
        "Force rejoin should succeed: {:?}",
        rejoin_result.err()
    );
    assert!(
        sync_result.is_ok(),
        "Sync should complete while rejoin is in-flight: {:?}",
        sync_result.err()
    );
    assert!(
        sync_elapsed < std::time::Duration::from_millis(250),
        "Sync should skip in-flight rejoin instead of waiting; elapsed={sync_elapsed:?}"
    );
    assert_eq!(
        world.delivery_service().external_commit_count(&group_id),
        1,
        "Sync should not trigger a second external commit while rejoin is in-flight"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sync_rejoin_uses_stable_conversation_id_when_group_id_differs() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Stable Conversation ID Rejoin Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();
    let conversation_id = format!("convo-{group_id}");

    world
        .delivery_service()
        .rekey_conversation_for_test(&group_id, &conversation_id);

    let group_id_bytes = hex::decode(&group_id).expect("invalid group id hex");
    alice
        .orchestrator
        .mls_context()
        .delete_group(group_id_bytes.clone())
        .expect("delete_group failed");

    let result = alice.orchestrator.sync_with_server(false).await;
    assert!(result.is_ok(), "sync failed: {:?}", result.err());

    assert_eq!(
        world
            .delivery_service()
            .get_group_info_call_count(&conversation_id),
        1,
        "sync rejoin should fetch GroupInfo by stable conversation ID"
    );
    assert_eq!(
        world
            .delivery_service()
            .get_group_info_call_count(&group_id),
        0,
        "sync rejoin must not fetch GroupInfo by mutable MLS group ID"
    );
    assert_eq!(
        world
            .delivery_service()
            .external_commit_count(&conversation_id),
        1,
        "External Commit should be submitted against the stable conversation ID"
    );
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id_bytes)
            .is_ok(),
        "External Commit should restore local MLS state for the original group ID"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_force_rejoin_cooldown_suppresses_immediate_retry() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Rejoin Cooldown Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    world.delivery_service().fail_next_get_group_info();

    let first = alice.orchestrator.force_rejoin(group_id).await;
    assert!(first.is_err(), "First force_rejoin should fail");

    let second = alice.orchestrator.force_rejoin(group_id).await;
    match second {
        Err(OrchestratorError::RecoveryFailed(msg)) => {
            assert!(
                msg.contains("cooldown"),
                "Expected cooldown suppression, got: {msg}"
            );
        }
        other => panic!("Expected RecoveryFailed cooldown error, got: {other:?}"),
    }

    assert_eq!(
        world.delivery_service().get_group_info_call_count(group_id),
        1,
        "Cooldown retry should not call get_group_info again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_join_or_rejoin_cooldown_suppresses_immediate_retry() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Join Cooldown Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    let group_id_bytes = hex::decode(group_id).expect("invalid group id hex");
    alice
        .orchestrator
        .mls_context()
        .delete_group(group_id_bytes)
        .expect("delete_group failed");

    world.delivery_service().fail_next_get_group_info();

    let first = alice.orchestrator.join_or_rejoin(group_id).await;
    assert!(first.is_err(), "First join_or_rejoin should fail");

    let second = alice.orchestrator.join_or_rejoin(group_id).await;
    match second {
        Err(OrchestratorError::RecoveryFailed(msg)) => {
            assert!(
                msg.contains("cooldown"),
                "Expected cooldown suppression, got: {msg}"
            );
        }
        other => panic!("Expected RecoveryFailed cooldown error, got: {other:?}"),
    }

    assert_eq!(
        world.delivery_service().get_group_info_call_count(group_id),
        1,
        "Cooldown retry should not call get_group_info again"
    );
}
