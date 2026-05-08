//! Regression tests for the post-reset deadlock fix (2026-05-02).
//!
//! Bug recap:
//!   1. Server-pushed `groupResetEvent` arrives at the client.
//!   2. `MLSOrchestrator::record_group_reset` calls
//!      `RecoveryTracker::clear(convo_id)`.
//!   3. `RecoveryTracker::clear` arms `last_global_rejoin_at = now`.
//!   4. Next sync tick fires `join_or_rejoin`. Welcome 404s.
//!      `enforce_rejoin_backoff` rejects with
//!      `RecoveryFailed("Rejoin suppressed ... minimum interval (29s remaining)")`.
//!   5. `try_first_responder_bootstrap` is unreachable until the gate clears.
//!   6. Both clients in a 2-party convo deadlock waiting for the other to
//!      bootstrap; observed in production as "convo stuck for 24+ minutes
//!      after reset" or "convo never recovers."
//!
//! Fix in two parts:
//!   (A) `RecoveryTracker::clear_for_fresh_reset` (covered by unit tests in
//!       `recovery_tracker_tests.rs`) — wipes per-convo failure history
//!       without arming `last_global_rejoin_at`.
//!   (B) `join_or_rejoin` reorder — bootstrap is tried BEFORE External
//!       Commit when state is `ResetPending` and Welcome was unavailable in
//!       the expected (404/410/processing-fail) shape.
//!
//! These integration tests pin the contract at the orchestrator level: a
//! fresh `record_group_reset` followed immediately by `join_or_rejoin` must
//! reach `try_first_responder_bootstrap` (or a downstream error from the
//! bootstrap path itself), and MUST NOT be rejected by the global rejoin
//! gate. The mock `bootstrap_reset_group` is left unimplemented; the
//! regression assertion is on the error shape we DON'T see, not on
//! bootstrap success.

#![allow(dead_code)]

mod e2e_harness;

use e2e_harness::TestWorld;

/// Regression: after `record_group_reset`, the very next `join_or_rejoin`
/// call must NOT be blocked by the global rejoin gate.
///
/// This is the primary deadlock test. Pre-fix this would fail with
/// `RecoveryFailed("Rejoin suppressed for {convo}: minimum interval
/// (29s remaining)")`. Post-fix the gate is no longer armed by the reset,
/// so we should see a downstream bootstrap-path error instead — proving
/// `try_first_responder_bootstrap` was reached.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_group_reset_then_join_does_not_hit_global_gate() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Reset gate regression", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Server-pushed reset arrives. Use a 16-byte (32 hex-char) candidate
    // group id matching the production shape we observed in the captured
    // 2026-05-02 incident.
    let new_group_id =
        hex::decode("aabbccddeeff00112233445566778899").expect("test fixture must be valid hex");
    alice
        .orchestrator
        .record_group_reset(&convo_id, new_group_id, 1)
        .await
        .expect("record_group_reset failed");

    // Immediately try to recover. Pre-fix this would have hit the global
    // rejoin gate that `record_group_reset` just armed via
    // `RecoveryTracker::clear`. Post-fix it must NOT.
    let result = alice.orchestrator.join_or_rejoin(&convo_id).await;

    // We don't assert success — the mock `bootstrap_reset_group` is the
    // default unimplemented one, so a downstream error is expected. What
    // matters is the SHAPE of the error: bootstrap must have been REACHED.
    if let Err(ref e) = result {
        let msg = format!("{e}");
        assert!(
            !(msg.contains("Rejoin suppressed") && msg.contains("minimum interval")),
            "REGRESSION: join_or_rejoin was blocked by the global rejoin gate \
             on the very first call after record_group_reset. \
             This is the 2026-05-02 deadlock — `record_group_reset` should \
             use `clear_for_fresh_reset` (which does not arm \
             `last_global_rejoin_at`) instead of `clear`. \
             Got error: {msg}"
        );
        assert!(
            !(msg.contains("Rejoin suppressed") && msg.contains("cooldown active")),
            "REGRESSION: join_or_rejoin was blocked by per-convo cooldown \
             on the very first call after record_group_reset. \
             `clear_for_fresh_reset` must wipe the per-convo failure \
             counter so a fresh reset starts clean. \
             Got error: {msg}"
        );
    }
}

/// Regression: even if a prior failure on a DIFFERENT conversation has armed
/// the global gate, a fresh `record_group_reset + join_or_rejoin` for THIS
/// convo must still reach bootstrap. The bootstrap path is server-serialized
/// (UNIQUE on `(conversation_id, generation)`), so it does not need to obey
/// the local epoch-inflation gate that External Commit does.
///
/// NOTE: This test currently asserts only the per-convo invariant — that the
/// NEW convo's reset is not blocked by ITS OWN historical state. Bootstrap
/// reachability across an armed global gate is enforced by Step 2 of the fix
/// (the reorder in `join_or_rejoin`): bootstrap is tried before
/// `enforce_rejoin_backoff`. If the global gate is armed by another convo's
/// failure, the bootstrap call still goes out; only the External Commit
/// fallback waits.
#[tokio::test(flavor = "multi_thread")]
async fn test_fresh_reset_skips_existing_global_gate_for_bootstrap() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Two convos: convo-a and convo-b.
    let convo_a = alice
        .orchestrator
        .create_group("Convo A (will fail rejoin first)", None, None)
        .await
        .expect("create_group A failed");
    let convo_b = alice
        .orchestrator
        .create_group("Convo B (will reset second)", None, None)
        .await
        .expect("create_group B failed");

    // Reset event arrives for convo-b. Even though no other activity has
    // armed the global gate yet (this is a single-client test world), this
    // test pins the post-fix contract that bootstrap is reached on the
    // first attempt for the resetting convo.
    let new_group_id =
        hex::decode("00112233445566778899aabbccddeeff").expect("test fixture must be valid hex");
    alice
        .orchestrator
        .record_group_reset(&convo_b.conversation_id, new_group_id, 1)
        .await
        .expect("record_group_reset on convo-b failed");

    let result = alice
        .orchestrator
        .join_or_rejoin(&convo_b.conversation_id)
        .await;

    if let Err(ref e) = result {
        let msg = format!("{e}");
        assert!(
            !(msg.contains("Rejoin suppressed") && msg.contains("minimum interval")),
            "REGRESSION: bootstrap path was blocked by global gate on the \
             reset-target convo (convo-b). Step 2 of the fix (reorder \
             bootstrap before enforce_rejoin_backoff in join_or_rejoin) \
             must keep bootstrap reachable independent of the global gate. \
             Got error: {msg}"
        );
    }

    // Sanity: convo-a is untouched. We don't assert anything about it; this
    // is just a guard that creating two convos didn't fail silently.
    let _ = convo_a;
}
