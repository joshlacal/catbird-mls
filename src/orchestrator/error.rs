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

    /// Server bootstrap succeeded, but the storage compare-and-clear could not
    /// confirm that this reset generation still owned recovery authority.
    #[error(
        "Reset completion not committed for conversation {convo_id}, generation {reset_generation}: {reason}"
    )]
    ResetCompletionNotCommitted {
        convo_id: String,
        reset_generation: i32,
        reason: String,
    },

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

    /// Layer 3 quarantine guard: the conversation is in Quarantined state, so
    /// send/encrypt and any auto-External-Commit path is refused. Callers should
    /// surface this to the UI (banner + disabled composer) and only clear via
    /// user-confirmed manual reset, server-pushed groupResetEvent, or a healthy
    /// peer commit.
    #[error("Conversation {convo_id} is quarantined ({reason})")]
    ConversationQuarantined { convo_id: String, reason: String },
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

    /// Whether the server reported that the acting device has no registered row.
    ///
    /// `blue.catbird.chat.*` answers `DeviceNotRegistered` with HTTP 401, and the
    /// code is defined to start automatic enrollment rather than a login prompt
    /// (see `RecoveryOutcome::NeedsEnrollment`). The device-readiness probe in
    /// `ensure_device_registered` must therefore read it as "there is no server
    /// device" and enroll, rather than aborting the way a real auth failure does.
    ///
    /// Deliberately keyed on the code and never on the bare status:
    /// `DeviceRevoked` and `DeviceBindingMismatch` also answer 401, and those must
    /// NOT silently mint a replacement device.
    pub fn is_device_not_registered(&self) -> bool {
        let body = match self {
            OrchestratorError::ServerError { status: 401, body } => body.as_str(),
            // The Swift/Kotlin FFI callbacks surface transport failures as `Api`.
            OrchestratorError::Api(message) => message.as_str(),
            _ => return false,
        };
        body.contains("DeviceNotRegistered")
    }

    pub fn is_reset_completion_not_committed(&self) -> bool {
        matches!(self, OrchestratorError::ResetCompletionNotCommitted { .. })
    }

    /// Whether this error represents a first-responder bootstrap race-loss:
    /// the server returned 409 with either lexicon code that signals
    /// "another caller won the race for this groupId/convoId":
    /// - `ConvoAlreadyExists` (legacy `createConvo` shape, retained for
    ///   backward compat during the createConvo→bootstrapResetGroup migration)
    /// - `AlreadyBootstrapped` (new `bootstrapResetGroup` shape, post task #17)
    ///
    /// Race losers MUST discard their local pre-bootstrap MLS group and
    /// fall back to receiving the Welcome from the winner — they MUST NOT
    /// clear `reset_pending` (the deferred-recovery loop will retry Welcome
    /// on the next pass).
    pub fn is_bootstrap_already_bootstrapped(&self) -> bool {
        match self {
            OrchestratorError::ServerError { status: 409, body } => {
                body.contains("ConvoAlreadyExists") || body.contains("AlreadyBootstrapped")
            }
            _ => false,
        }
    }

    /// Backward-compat alias. New code should call `is_bootstrap_already_bootstrapped`.
    #[deprecated(note = "use is_bootstrap_already_bootstrapped — same semantics, broader name")]
    pub fn is_create_convo_race_loss(&self) -> bool {
        self.is_bootstrap_already_bootstrapped()
    }

    /// Whether this error represents an active direct conversation existing between
    /// the caller and recipient pair where the caller/acting device is not an active member.
    pub fn is_direct_conversation_not_member(&self) -> bool {
        let raw = match self {
            OrchestratorError::ServerError { body, .. } => body.as_str(),
            OrchestratorError::Api(message) => message.as_str(),
            _ => return false,
        };
        error_code_equals(raw, "ConversationAlreadyExists")
    }
}

fn error_code_equals(raw: &str, expected: &str) -> bool {
    let trimmed = raw.trim();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(code) = val.get("error").and_then(|v| v.as_str()) {
            return code == expected;
        }
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&trimmed[start..=end]) {
                if let Some(code) = val.get("error").and_then(|v| v.as_str()) {
                    return code == expected;
                }
            }
        }
    }
    if !trimmed.is_empty() && !trimmed.contains('{') && !trimmed.contains(' ') {
        return trimmed == expected;
    }
    false
}

pub type Result<T> = std::result::Result<T, OrchestratorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_bootstrap_already_bootstrapped_matches_legacy_convo_already_exists() {
        // Pre-task-#18 shape that mls-ds returned when a race-loser hit
        // createConvo with a groupId someone else already claimed (lexicon
        // task #16): HTTP 409 with `{"error":"ConvoAlreadyExists","message":"..."}`.
        // Retained so any client that still receives the legacy code keeps
        // classifying correctly during the migration.
        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"ConvoAlreadyExists","message":"caller lost first-responder race"}"#
                .to_string(),
        };
        assert!(
            err.is_bootstrap_already_bootstrapped(),
            "409 with ConvoAlreadyExists in body must classify as race loss"
        );
    }

    #[test]
    fn is_bootstrap_already_bootstrapped_matches_new_bootstrap_already_bootstrapped() {
        // The new shape mls-ds returns from `bootstrapResetGroup` (task #17)
        // when another caller already populated the post-reset row's
        // group_info: HTTP 409 with `{"error":"AlreadyBootstrapped",...}`.
        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"AlreadyBootstrapped","message":"caller lost first-responder race"}"#
                .to_string(),
        };
        assert!(
            err.is_bootstrap_already_bootstrapped(),
            "409 with AlreadyBootstrapped in body must classify as race loss"
        );
    }

    #[test]
    fn is_bootstrap_already_bootstrapped_rejects_other_409s() {
        // 409 with a different lexicon code (e.g. AlreadyMember,
        // BootstrapTargetNotFound) must NOT be treated as a bootstrap race
        // loss — those are legitimate failures the caller must surface.
        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"AlreadyMember","message":"..."}"#.to_string(),
        };
        assert!(
            !err.is_bootstrap_already_bootstrapped(),
            "409 with unrelated lexicon code must not classify"
        );

        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"BootstrapTargetNotFound","message":"..."}"#.to_string(),
        };
        assert!(
            !err.is_bootstrap_already_bootstrapped(),
            "409 with sibling bootstrap error must not classify as race loss"
        );
    }

    #[test]
    fn is_bootstrap_already_bootstrapped_rejects_other_statuses() {
        // Same body, wrong status: must not classify.
        let err = OrchestratorError::ServerError {
            status: 500,
            body: r#"{"error":"AlreadyBootstrapped"}"#.to_string(),
        };
        assert!(
            !err.is_bootstrap_already_bootstrapped(),
            "non-409 statuses must not classify even with matching body"
        );

        // Network error: must not classify.
        let err = OrchestratorError::Api("connection refused".into());
        assert!(
            !err.is_bootstrap_already_bootstrapped(),
            "non-ServerError variants must not classify"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn is_create_convo_race_loss_alias_still_works() {
        // The deprecated alias must remain semantically identical so any
        // out-of-tree code that still calls it continues to work during the
        // migration.
        let err = OrchestratorError::ServerError {
            status: 409,
            body: r#"{"error":"AlreadyBootstrapped"}"#.to_string(),
        };
        assert!(err.is_create_convo_race_loss());
        assert_eq!(
            err.is_create_convo_race_loss(),
            err.is_bootstrap_already_bootstrapped()
        );
    }

    #[test]
    fn is_device_not_registered_matches_the_code_not_the_status() {
        // The device-scoped probe answer that must start enrollment.
        let err = OrchestratorError::ServerError {
            status: 401,
            body: r#"{"error":"DeviceNotRegistered"}"#.to_string(),
        };
        assert!(err.is_device_not_registered());

        // The FFI callbacks surface transport failures as `Api`.
        let err = OrchestratorError::Api(
            r#"status 401: {"error":"DeviceNotRegistered"}"#.to_string(),
        );
        assert!(err.is_device_not_registered());

        // Siblings that also answer 401 but must never mint a replacement device.
        for code in ["DeviceRevoked", "DeviceBindingMismatch", "NotAuthorized"] {
            let err = OrchestratorError::ServerError {
                status: 401,
                body: format!(r#"{{"error":"{code}"}}"#),
            };
            assert!(
                !err.is_device_not_registered(),
                "{code} must not classify as an unregistered device"
            );
        }

        // Unrelated failures must not classify.
        assert!(!OrchestratorError::Api("connection refused".into()).is_device_not_registered());
        assert!(!OrchestratorError::NotAuthenticated.is_device_not_registered());
    }

    #[test]
    fn is_direct_conversation_not_member_matches_lexicon_code() {
        let err = OrchestratorError::ServerError {
            status: 400,
            body: r#"{"error":"ConversationAlreadyExists","message":"ConversationAlreadyExists"}"#.to_string(),
        };
        assert!(err.is_direct_conversation_not_member(), "ConversationAlreadyExists must classify");

        let api_err = OrchestratorError::Api(
            r#"status 400: {"error":"ConversationAlreadyExists","message":"ConversationAlreadyExists"}"#.to_string(),
        );
        assert!(api_err.is_direct_conversation_not_member(), "ConversationAlreadyExists via Api must classify");

        // Bare error code must classify
        let bare_err = OrchestratorError::ServerError {
            status: 400,
            body: "ConversationAlreadyExists".to_string(),
        };
        assert!(bare_err.is_direct_conversation_not_member(), "Bare ConversationAlreadyExists must classify");

        // Removed speculative aliases MUST NOT classify (exact match, not substring).
        for alias in [
            "DirectConversationAlreadyExists",
            "DirectConversationExistsNotMember",
            "NotMember",
            "NotEntitled",
        ] {
            let server_err = OrchestratorError::ServerError {
                status: 400,
                body: format!(r#"{{"error":"{alias}","message":"{alias}"}}"#),
            };
            assert!(
                !server_err.is_direct_conversation_not_member(),
                "{alias} must NOT classify as direct conversation not member"
            );

            let api_err = OrchestratorError::Api(format!(r#"status 400: {{"error":"{alias}"}}"#));
            assert!(
                !api_err.is_direct_conversation_not_member(),
                "{alias} via Api must NOT classify"
            );

            let bare_alias = OrchestratorError::ServerError {
                status: 400,
                body: alias.to_string(),
            };
            assert!(
                !bare_alias.is_direct_conversation_not_member(),
                "{alias} bare must NOT classify"
            );
        }

        // Unrelated errors must not classify.
        let unrelated = OrchestratorError::ServerError {
            status: 400,
            body: r#"{"error":"InvalidRequest","message":"InvalidRequest"}"#.to_string(),
        };
        assert!(!unrelated.is_direct_conversation_not_member());
        assert!(!OrchestratorError::NotAuthenticated.is_direct_conversation_not_member());
        assert!(!OrchestratorError::Api("connection refused".into()).is_direct_conversation_not_member());
    }
}
