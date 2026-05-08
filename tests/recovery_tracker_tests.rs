use catbird_mls::orchestrator::recovery::{GroupInfo404Tracker, RecoveryTracker};
use std::time::Duration;

#[test]
fn test_rejoin_backoff_matches_spec() {
    let tracker = RecoveryTracker::new(3);

    // Spec §10: REJOIN_BACKOFF = [30s, 2m, 10m]
    assert_eq!(tracker.cooldown_for_attempts(1), Duration::from_secs(30));
    assert_eq!(tracker.cooldown_for_attempts(2), Duration::from_secs(120));
    assert_eq!(tracker.cooldown_for_attempts(3), Duration::from_secs(600));

    // Attempt 0 should have no cooldown
    assert_eq!(tracker.cooldown_for_attempts(0), Duration::from_secs(0));
}

#[test]
fn test_backoff_beyond_max_uses_last() {
    let tracker = RecoveryTracker::new(5);

    // Beyond 3 attempts should use last backoff (10m)
    assert_eq!(tracker.cooldown_for_attempts(4), Duration::from_secs(600));
    assert_eq!(tracker.cooldown_for_attempts(10), Duration::from_secs(600));
}

#[test]
fn test_groupinfo_404_circuit_breaker() {
    let mut tracker = GroupInfo404Tracker::new();

    // First two 404s: not tripped
    tracker.record_404("convo-1");
    assert!(!tracker.is_tripped("convo-1"));
    tracker.record_404("convo-1");
    assert!(!tracker.is_tripped("convo-1"));

    // Third 404: tripped
    tracker.record_404("convo-1");
    assert!(tracker.is_tripped("convo-1"));

    // Different conversation: not tripped
    assert!(!tracker.is_tripped("convo-2"));
}

#[test]
fn test_groupinfo_404_clears_on_success() {
    let mut tracker = GroupInfo404Tracker::new();

    tracker.record_404("convo-1");
    tracker.record_404("convo-1");
    tracker.clear("convo-1");

    // After clearing, should not be tripped even after one more 404
    tracker.record_404("convo-1");
    assert!(!tracker.is_tripped("convo-1"));
}

#[test]
fn test_min_rejoin_interval_is_global() {
    let mut tracker = RecoveryTracker::new(3);

    // Record a successful rejoin for conversation A
    tracker.clear("convo-a");

    // Conversation B should also be blocked by the global interval
    assert!(
        tracker.should_skip("convo-b"),
        "Global MIN_REJOIN_INTERVAL should block different conversations"
    );
}

// ---------------------------------------------------------------------------
// `clear_for_fresh_reset` regression tests for the 2026-05-02 deadlock fix.
//
// The bug: `MLSOrchestrator::persist_reset_pending_state` previously called
// `RecoveryTracker::clear`, which armed `last_global_rejoin_at`. That arming
// blocked `try_first_responder_bootstrap` (which lives behind
// `enforce_rejoin_backoff`) for ≥30 s after every server-pushed reset event,
// creating the deadlock where two clients sat behind their own gates waiting
// for the other to bootstrap.
//
// `clear_for_fresh_reset` is the new method that wipes per-convo failure
// history without arming the global gate or recording a fake "successful
// rejoin." These tests pin that contract so the bug can't silently come back.
// ---------------------------------------------------------------------------

#[test]
fn test_clear_for_fresh_reset_does_not_arm_global_gate() {
    let mut tracker = RecoveryTracker::new(3);

    // Sanity: empty tracker doesn't gate anything.
    assert!(!tracker.should_skip("convo-y"));

    // Server-pushed reset arrives for convo-x. This is NOT an attempt by
    // this client; the gate must remain open.
    tracker.clear_for_fresh_reset("convo-x");

    assert!(
        !tracker.should_skip("convo-y"),
        "clear_for_fresh_reset must not arm the global rejoin gate \
         (regression: arming the gate here is what blocked first-responder \
         bootstrap for ≥30 s after every reset)"
    );
    assert!(
        !tracker.should_skip("convo-x"),
        "clear_for_fresh_reset must not arm the gate even for the convo it was called on \
         — the imminent first-responder bootstrap has to be reachable on the next sync tick"
    );
}

#[test]
fn test_clear_for_fresh_reset_preserves_existing_global_gate() {
    let mut tracker = RecoveryTracker::new(3);

    // Arm the global gate via a real failure on convo-a.
    tracker.record_failure("convo-a");
    assert!(
        tracker.should_skip("convo-b"),
        "Sanity: gate should be armed by record_failure"
    );

    // Reset event for an unrelated convo arrives. Must not unarm the gate.
    tracker.clear_for_fresh_reset("convo-c");

    assert!(
        tracker.should_skip("convo-b"),
        "clear_for_fresh_reset must not unarm an already-armed global gate \
         — the gate was set by a real attempt and still carries valid spiral protection"
    );
}

#[test]
fn test_clear_for_fresh_reset_clears_per_convo_failures() {
    let mut tracker = RecoveryTracker::new(3);

    // Two failures stack up on convo-x.
    tracker.record_failure("convo-x");
    tracker.record_failure("convo-x");
    assert_eq!(tracker.failed_attempts("convo-x"), 2);

    // Server reset wipes the per-convo failure counter — fresh start.
    tracker.clear_for_fresh_reset("convo-x");
    assert_eq!(
        tracker.failed_attempts("convo-x"),
        0,
        "clear_for_fresh_reset must reset the per-convo failure counter to 0 \
         so the fresh reset's bootstrap doesn't inherit prior backoff"
    );
}

#[test]
fn test_clear_for_fresh_reset_clears_per_convo_cooldown() {
    let mut tracker = RecoveryTracker::new(3);

    // One failure: per-convo cooldown is now active for convo-x.
    tracker.record_failure("convo-x");
    assert!(
        tracker.cooldown_remaining("convo-x").is_some(),
        "Sanity: per-convo cooldown should be active after one failure"
    );

    // Server reset wipes it.
    tracker.clear_for_fresh_reset("convo-x");
    assert!(
        tracker.cooldown_remaining("convo-x").is_none(),
        "clear_for_fresh_reset must clear the per-convo cooldown \
         (the global gate may still apply, but THAT one isn't this method's job)"
    );
}
