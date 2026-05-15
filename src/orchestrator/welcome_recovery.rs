use std::time::Duration;

use super::error::OrchestratorError;

pub const WELCOME_REISSUE_MAX_ATTEMPTS: usize = 3;

const WELCOME_REISSUE_BACKOFF: [Duration; WELCOME_REISSUE_MAX_ATTEMPTS] = [
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(5 * 60),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WelcomeRecoveryDecision {
    Accept {
        group_id: Vec<u8>,
        epoch: u64,
    },
    RequestReissue {
        reason: String,
        retry_after: Duration,
    },
    ExternalCommitWithHistoryGap {
        last_seen_epoch: u64,
    },
    Surrender {
        reason: String,
        retry_after: Option<Duration>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastRecoveryError {
    NoMatchingKeyPackage,
    NoMatchingEncryptionKey,
    WelcomeUnavailable { status: Option<u16> },
    GroupInfoUnavailable { status: Option<u16> },
    Irrecoverable { reason: String },
    Other { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReissueAttempt {
    pub attempted_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReissueAttemptLog {
    pub attempts: Vec<ReissueAttempt>,
}

impl ReissueAttemptLog {
    pub fn with_attempt_count(count: usize) -> Self {
        Self {
            attempts: (0..count)
                .map(|idx| ReissueAttempt {
                    attempted_at_ms: idx as i64,
                })
                .collect(),
        }
    }

    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    pub fn remaining_backoff(&self, now_ms: i64) -> Duration {
        if self.attempts.is_empty() {
            return Duration::ZERO;
        }
        let idx = self
            .attempt_count()
            .saturating_sub(1)
            .min(WELCOME_REISSUE_BACKOFF.len() - 1);
        let required = WELCOME_REISSUE_BACKOFF[idx];
        let Some(last_attempt) = self.attempts.last() else {
            return Duration::ZERO;
        };
        let elapsed_ms = now_ms.saturating_sub(last_attempt.attempted_at_ms).max(0) as u64;
        let elapsed = Duration::from_millis(elapsed_ms);
        required.saturating_sub(elapsed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeRecoveryInput {
    pub attempts: ReissueAttemptLog,
    pub last_error: LastRecoveryError,
    pub has_groupinfo: bool,
    pub last_seen_epoch: u64,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeReissueRequestResult {
    pub welcome_requested: bool,
    pub requested_at: String,
    pub inviter_device: Option<String>,
}

pub fn decide_welcome_recovery(input: WelcomeRecoveryInput) -> WelcomeRecoveryDecision {
    match input.last_error {
        LastRecoveryError::NoMatchingKeyPackage | LastRecoveryError::NoMatchingEncryptionKey => {
            if input.attempts.attempt_count() < WELCOME_REISSUE_MAX_ATTEMPTS {
                WelcomeRecoveryDecision::RequestReissue {
                    reason: "no_matching_key_package".to_string(),
                    retry_after: if input.attempts.attempt_count() == 0 {
                        Duration::ZERO
                    } else {
                        input.attempts.remaining_backoff(input.now_ms)
                    },
                }
            } else if input.has_groupinfo {
                WelcomeRecoveryDecision::ExternalCommitWithHistoryGap {
                    last_seen_epoch: input.last_seen_epoch,
                }
            } else {
                WelcomeRecoveryDecision::Surrender {
                    reason: "reissue_exhausted_group_info_unavailable".to_string(),
                    retry_after: None,
                }
            }
        }
        LastRecoveryError::GroupInfoUnavailable { status } => WelcomeRecoveryDecision::Surrender {
            reason: match status {
                Some(status) => format!("group_info_unavailable_{status}"),
                None => "group_info_unavailable".to_string(),
            },
            retry_after: None,
        },
        LastRecoveryError::Irrecoverable { reason } => WelcomeRecoveryDecision::Surrender {
            reason,
            retry_after: None,
        },
        LastRecoveryError::WelcomeUnavailable { .. } | LastRecoveryError::Other { .. } => {
            if input.has_groupinfo {
                WelcomeRecoveryDecision::ExternalCommitWithHistoryGap {
                    last_seen_epoch: input.last_seen_epoch,
                }
            } else {
                WelcomeRecoveryDecision::Surrender {
                    reason: "welcome_and_group_info_unavailable".to_string(),
                    retry_after: None,
                }
            }
        }
    }
}

pub fn classify_welcome_processing_error(err: &crate::MLSError) -> Option<LastRecoveryError> {
    match err {
        crate::MLSError::NoMatchingKeyPackage { .. } => {
            Some(LastRecoveryError::NoMatchingKeyPackage)
        }
        other => {
            let msg = other.to_string().to_lowercase();
            if msg.contains("nomatchingencryptionkey") || msg.contains("no matching encryption key")
            {
                Some(LastRecoveryError::NoMatchingEncryptionKey)
            } else {
                None
            }
        }
    }
}

pub fn classify_server_error(err: &OrchestratorError) -> LastRecoveryError {
    match err {
        OrchestratorError::ServerError { status, body } if *status == 404 || *status == 410 => {
            LastRecoveryError::WelcomeUnavailable {
                status: Some(*status),
            }
            .with_body(body)
        }
        OrchestratorError::ServerError { status, .. } => LastRecoveryError::Other {
            reason: format!("server_error_{status}"),
        },
        other => LastRecoveryError::Other {
            reason: other.to_string(),
        },
    }
}

impl LastRecoveryError {
    fn with_body(self, body: &str) -> Self {
        if body.to_lowercase().contains("groupinfo") {
            match self {
                LastRecoveryError::WelcomeUnavailable { status } => {
                    LastRecoveryError::GroupInfoUnavailable { status }
                }
                other => other,
            }
        } else {
            self
        }
    }
}
