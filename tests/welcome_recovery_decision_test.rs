use std::time::Duration;

use catbird_mls::orchestrator::welcome_recovery::{
    decide_welcome_recovery, LastRecoveryError, ReissueAttemptLog, WelcomeRecoveryDecision,
    WelcomeRecoveryInput,
};

#[test]
fn fresh_key_package_failure_requests_reissue() {
    let decision = decide_welcome_recovery(WelcomeRecoveryInput {
        attempts: ReissueAttemptLog::default(),
        last_error: LastRecoveryError::NoMatchingKeyPackage,
        has_groupinfo: true,
        last_seen_epoch: 7,
        now_ms: 0,
    });

    assert!(matches!(
        decision,
        WelcomeRecoveryDecision::RequestReissue {
            retry_after: Duration::ZERO,
            ..
        }
    ));
}

#[test]
fn third_reissue_failure_allows_external_commit_with_history_gap() {
    let decision = decide_welcome_recovery(WelcomeRecoveryInput {
        attempts: ReissueAttemptLog::with_attempt_count(3),
        last_error: LastRecoveryError::NoMatchingKeyPackage,
        has_groupinfo: true,
        last_seen_epoch: 42,
        now_ms: 0,
    });

    assert_eq!(
        decision,
        WelcomeRecoveryDecision::ExternalCommitWithHistoryGap {
            last_seen_epoch: 42
        }
    );
}

#[test]
fn exhausted_reissue_without_groupinfo_surrenders() {
    let decision = decide_welcome_recovery(WelcomeRecoveryInput {
        attempts: ReissueAttemptLog::with_attempt_count(3),
        last_error: LastRecoveryError::GroupInfoUnavailable { status: Some(410) },
        has_groupinfo: false,
        last_seen_epoch: 42,
        now_ms: 0,
    });

    assert_eq!(
        decision,
        WelcomeRecoveryDecision::Surrender {
            reason: "group_info_unavailable_410".to_string(),
            retry_after: None,
        }
    );
}

#[test]
fn second_reissue_waits_for_backoff_window() {
    let decision = decide_welcome_recovery(WelcomeRecoveryInput {
        attempts: ReissueAttemptLog::with_attempt_count(1),
        last_error: LastRecoveryError::NoMatchingKeyPackage,
        has_groupinfo: true,
        last_seen_epoch: 7,
        now_ms: 1_000,
    });

    assert_eq!(
        decision,
        WelcomeRecoveryDecision::RequestReissue {
            reason: "no_matching_key_package".to_string(),
            retry_after: Duration::from_secs(9),
        }
    );
}
