use catbird_mls::orchestrator::recovery::RecoveryTracker;
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
