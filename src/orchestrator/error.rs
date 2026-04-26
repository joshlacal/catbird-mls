use thiserror::Error;

/// Errors that can occur during MLS orchestration operations.
#[derive(Error, Debug)]
pub enum OrchestratorError {
    #[error("MLS FFI error: {0}")]
    Mls(#[from] crate::MLSError),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Credential error: {0}")]
    Credential(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Group not found: {0}")]
    GroupNotFound(String),

    #[error("Conversation not found: {0}")]
    ConversationNotFound(String),

    #[error("Epoch mismatch: local={local}, remote={remote}")]
    EpochMismatch { local: u64, remote: u64 },

    #[error("Member already exists: {0}")]
    MemberAlreadyExists(String),

    #[error("Member sync failed")]
    MemberSyncFailed,

    #[error("Device limit reached: {current}/{max}")]
    DeviceLimitReached { current: u32, max: u32 },

    #[error("Key package exhausted")]
    KeyPackageExhausted,

    #[error("Duplicate message: {0}")]
    DuplicateMessage(String),

    #[error("Shutting down")]
    ShuttingDown,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Server error: status={status}, body={body}")]
    ServerError { status: u16, body: String },

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Sync paused: circuit breaker tripped after consecutive failures")]
    SyncPaused,

    /// The caller tried to send/receive in a conversation whose group is not
    /// joined locally. Callers must handle this explicitly (e.g. invoke
    /// `MLSOrchestrator::report_unrecoverable_local` to escalate server
    /// recovery, or replay the Welcome on the next sync). The orchestrator
    /// no longer auto-rejoins via External Commit on the hot send/decrypt
    /// paths — see task #43.
    #[error("Group not joined locally for conversation {convo_id}")]
    NotJoined { convo_id: String },
}

impl OrchestratorError {
    /// Whether this error indicates corrupted/malformed remote data that will
    /// never succeed on retry. Used by recovery to avoid burning rejoin
    /// attempts on permanently bad GroupInfo blobs.
    pub fn is_remote_data_error(&self) -> bool {
        let msg = self.to_string().to_lowercase();
        msg.contains("invalidvectorlength")
            || msg.contains("endofstream")
            || msg.contains("truncated")
            || msg.contains("malformed")
            || msg.contains("deseriali")
    }

    /// Whether this error represents a 429 Too Many Requests response.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, OrchestratorError::ServerError { status: 429, .. })
    }

    /// Whether this error represents a `createConvo` race-loss: the server
    /// returned 409 with the `ConvoAlreadyExists` lexicon error code,
    /// meaning a different DID won the first-responder bootstrap race for
    /// the same `groupId`. Race losers MUST discard their local pre-bootstrap
    /// MLS group and fall back to receiving the Welcome from the winner —
    /// they MUST NOT clear `reset_pending` (the deferred-recovery loop will
    /// retry Welcome on the next pass).
    ///
    /// Per `mls-ds/lexicon/blue/catbird/mlsChat/blue.catbird.mlsChat.createConvo.json`
    /// (task #16, Phase 1).
    pub fn is_create_convo_race_loss(&self) -> bool {
        match self {
            OrchestratorError::ServerError { status: 409, body } => {
                body.contains("ConvoAlreadyExists")
            }
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, OrchestratorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_create_convo_race_loss_matches_409_with_lexicon_code() {
        // The shape mls-ds returns when a race-loser hits createConvo with
        // a groupId someone else already claimed (lexicon task #16):
        // HTTP 409 with `{"error":"ConvoAlreadyExists","message":"..."}`.
        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"ConvoAlreadyExists","message":"caller lost first-responder race"}"#
                .to_string(),
        };
        assert!(
            err.is_create_convo_race_loss(),
            "409 with ConvoAlreadyExists in body must classify as race loss"
        );
    }

    #[test]
    fn is_create_convo_race_loss_rejects_other_409s() {
        // 409 with a different lexicon code (e.g. AlreadyMember) must NOT
        // be treated as a bootstrap race loss.
        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"AlreadyMember","message":"..."}"#.to_string(),
        };
        assert!(
            !err.is_create_convo_race_loss(),
            "409 with non-ConvoAlreadyExists code must not classify"
        );
    }

    #[test]
    fn is_create_convo_race_loss_rejects_other_statuses() {
        // Same body, wrong status: must not classify.
        let err = OrchestratorError::ServerError {
            status: 500,
            body: r#"{"error":"ConvoAlreadyExists"}"#.to_string(),
        };
        assert!(
            !err.is_create_convo_race_loss(),
            "non-409 statuses must not classify even with matching body"
        );

        // Network error: must not classify.
        let err = OrchestratorError::Api("connection refused".into());
        assert!(
            !err.is_create_convo_race_loss(),
            "non-ServerError variants must not classify"
        );
    }
}
