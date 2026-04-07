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
