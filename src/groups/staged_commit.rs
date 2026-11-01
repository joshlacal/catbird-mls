//! Staged-commit sequencing guard (`Spec §5 I5`: server acceptance strictly precedes local merge).

use crate::MLSError;

/// Tracks a locally staged MLS `Commit` awaiting authoritative sequencing acknowledgment
/// from `mls-ds` (`I5`). Merging locally before `mark_server_accepted` is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedCommitTicket {
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub target_epoch: u64,
    server_accepted_seq: Option<i64>,
}

impl StagedCommitTicket {
    pub fn new(conversation_id: impl Into<String>, group_id: Vec<u8>, target_epoch: u64) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            group_id,
            target_epoch,
            server_accepted_seq: None,
        }
    }

    pub fn mark_server_accepted(&mut self, assigned_seq: i64) -> Result<(), MLSError> {
        if assigned_seq <= 0 {
            return Err(MLSError::invalid_input(
                "I5: server-assigned seq must be strictly positive",
            ));
        }
        self.server_accepted_seq = Some(assigned_seq);
        Ok(())
    }

    pub fn ensure_ready_to_merge(&self) -> Result<i64, MLSError> {
        self.server_accepted_seq.ok_or_else(|| {
            MLSError::InvalidState(format!(
                "I5 violation: attempted to merge staged commit for {} (epoch {}) before server acknowledgment",
                self.conversation_id, self.target_epoch
            ))
        })
    }
}
