//! Epoch-divergence recovery ladder (`Spec §5` & `AGENTS.md`: automated paths MUST NEVER use `force_rejoin`).

use serde::{Deserialize, Serialize};

/// Deterministic recovery action selected when local group state lags or diverges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Fetch and apply missing sequenced `Commit`s from `mls-ds`.
    CatchUpSequencedCommits { from_seq: i64, target_epoch: u64 },
    /// Request a Welcome/re-add from an active sibling device leaf on the same account.
    RequestSiblingLeafReadd { account_did: String },
    /// Request a Welcome reissue from an active conversation admin.
    RequestAdminWelcomeReissue { conversation_id: String },
    /// Surface explicit user-confirmed reset; automated `force_rejoin` external commits are forbidden.
    AwaitExplicitReset { reason: String },
}

/// Select the next safe recovery step without ever issuing an automated `force_rejoin` external commit.
pub fn select_recovery_action(
    conversation_id: &str,
    account_did: &str,
    local_epoch: Option<u64>,
    server_epoch: u64,
    last_local_seq: i64,
    commits_available_on_ds: bool,
    has_active_sibling_device: bool,
) -> RecoveryAction {
    if let Some(ep) = local_epoch {
        if ep < server_epoch && commits_available_on_ds {
            return RecoveryAction::CatchUpSequencedCommits {
                from_seq: last_local_seq.saturating_add(1),
                target_epoch: server_epoch,
            };
        }
    }
    if has_active_sibling_device {
        return RecoveryAction::RequestSiblingLeafReadd {
            account_did: account_did.to_owned(),
        };
    }
    if !conversation_id.is_empty() {
        return RecoveryAction::RequestAdminWelcomeReissue {
            conversation_id: conversation_id.to_owned(),
        };
    }
    RecoveryAction::AwaitExplicitReset {
        reason: "no sequenced commit catchup or active sibling/admin re-add available".into(),
    }
}
