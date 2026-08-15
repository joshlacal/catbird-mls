use async_trait::async_trait;

use super::error::Result;
use super::types::*;

#[cfg(not(target_arch = "wasm32"))]
pub trait MLSStorageBackendBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> MLSStorageBackendBounds for T {}

#[cfg(target_arch = "wasm32")]
pub trait MLSStorageBackendBounds {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MLSStorageBackendBounds for T {}

/// Every `MLSStorageBackend` method that ships a default implementation.
///
/// Used by the orchestrator's init-time capabilities check (WS-5.6): any
/// method in this list that the backend does not report via
/// [`MLSStorageBackend::implemented_optional_methods`] is logged as a warning.
/// Security-authority defaults fail closed; legacy best-effort methods may
/// still no-op.
pub const OPTIONAL_STORAGE_METHODS: &[&str] = &[
    "get_conversation_state",
    "get_welcome_reissue_attempt_log",
    "record_welcome_reissue_attempt",
    "mark_reset_pending",
    "adopt_reset_pending_target",
    "complete_reset_pending",
    "clear_reset_pending_for_delete",
    "set_conversation_sequencer",
    "mark_quarantined",
    "clear_quarantine",
    "store_pending_message",
    "remove_pending_message",
    "store_sequencer_receipt",
    "get_sequencer_receipts",
    "clear_sequencer_receipts",
    "cleanup_old_epoch_data",
    "get_recovery_state",
    "set_recovery_backoff",
    "clear_recovery_backoff",
    "set_last_global_rejoin_attempt_at",
    "mark_pending_local_delete",
    "clear_pending_local_delete",
    "list_pending_local_deletes",
];

/// Recovery persistence methods that are optional at the Rust trait level for
/// source compatibility, but mandatory before an orchestrator may initialize.
/// Without all four, a process restart can erase the recovery rate limit.
pub const REQUIRED_RECOVERY_PERSISTENCE_METHODS: &[&str] = &[
    "get_recovery_state",
    "set_recovery_backoff",
    "clear_recovery_backoff",
    "set_last_global_rejoin_attempt_at",
];

pub(crate) fn require_recovery_persistence_capabilities<S: MLSStorageBackend + ?Sized>(
    storage: &S,
) -> Result<()> {
    let implemented = storage.implemented_optional_methods();
    if let Some(missing) = REQUIRED_RECOVERY_PERSISTENCE_METHODS
        .iter()
        .find(|method| !implemented.contains(method))
    {
        return Err(super::error::OrchestratorError::Storage(format!(
            "recovery rate limiting requires durable storage; backend does not declare {missing}"
        )));
    }
    Ok(())
}

/// Platform-agnostic storage backend for MLS orchestration state.
///
/// Implementations should persist data durably (e.g. SQLite, GRDB, Room).
/// All methods are async to allow non-blocking I/O.
///
/// Reset lifecycle writes require one serialized writer per tenant within a
/// process. Backends shared by multiple processes must additionally enforce
/// the documented generation comparisons with an atomic database transaction;
/// the in-process orchestrator lock cannot serialize another process.
///
/// This trait is not the OpenMLS cryptographic state store. Native Rust
/// engines keep OpenMLS group state, key packages, ratchets, and manifest
/// data inside `MLSContext` via `openmls_sqlite_storage` and
/// `HybridStorageProvider`. Platform callbacks project app-facing rows only:
/// conversation metadata, message rows, recovery flags, cursors, and other UI
/// or orchestration state that Swift/Kotlin/catmos own outside OpenMLS.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait MLSStorageBackend: MLSStorageBackendBounds {
    // -- Conversations --

    /// Ensure a conversation record exists, creating it if needed.
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()>;

    /// Update join info for a conversation.
    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()>;

    /// Fetch a single conversation by ID.
    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>>;

    /// List all conversations for a user.
    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>>;

    /// Delete conversations by IDs.
    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()>;

    /// Update conversation state.
    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()>;

    /// Read the persisted conversation state, if any.
    ///
    /// Used during orchestrator startup to rehydrate the in-memory
    /// `conversation_states` map so server-driven RESET_PENDING transitions
    /// (and any other persisted state) survive process restart.
    ///
    /// For `ResetPending`, implementations MUST reconstruct the full payload
    /// (`new_group_id`, `reset_generation`, `notified_at_ms`) from the
    /// columns written by `mark_reset_pending`.
    /// A `reset_pending` tag without that complete payload is not an
    /// authoritative transition and MUST return an error rather than a partial
    /// `ResetPending` value. This makes `mark_reset_pending` the durable commit
    /// point: callers fail closed during the tag-before-payload crash window.
    ///
    /// This read is mandatory for reset authority. The default fails closed so
    /// a partial adapter cannot silently erase an in-memory RESET_PENDING
    /// transition by reporting an authoritative absence.
    async fn get_conversation_state(
        &self,
        _conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        Err(super::error::OrchestratorError::Storage(
            "get_conversation_state is required for reset recovery".to_string(),
        ))
    }

    /// Mark a conversation as needing rejoin.
    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()>;

    /// Check if a conversation needs rejoin.
    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool>;

    /// Clear the rejoin flag for a conversation.
    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()>;

    /// Read persisted Welcome reissue attempts for the conversation.
    ///
    /// Backends should persist this counter durably so app restart does not
    /// reset the "ask inviter to reissue before External Commit" policy. The
    /// default empty log preserves backward compatibility for platforms that
    /// have not added the column/table yet.
    async fn get_welcome_reissue_attempt_log(
        &self,
        _conversation_id: &str,
    ) -> Result<super::welcome_recovery::ReissueAttemptLog> {
        Ok(super::welcome_recovery::ReissueAttemptLog::default())
    }

    /// Persist one Welcome reissue request attempt for the conversation.
    ///
    /// `attempted_at_ms` is Unix epoch milliseconds. Default no-op keeps old
    /// backends source-compatible; production backends should override before
    /// relying on cross-restart attempt exhaustion.
    async fn record_welcome_reissue_attempt(
        &self,
        _conversation_id: &str,
        _attempted_at_ms: i64,
    ) -> Result<()> {
        Ok(())
    }

    /// Persist a server-initiated RESET_PENDING transition (spec §8.6).
    ///
    /// `new_group_id_hex` is the hex-encoded group id the server handed down
    /// via `GroupResetEvent`. `reset_generation` is the monotonic reset
    /// counter. `notified_at_ms` is when the event was observed locally
    /// (Unix epoch ms).
    ///
    /// This method atomically publishes the `reset_pending` tag, full payload,
    /// and durable `needs_rejoin = true` route so that, after orchestrator
    /// restart, the platform layer can rehydrate a
    /// `ConversationState::ResetPending { .. }` and resume Phase 1 recovery.
    /// This operation is the sole authority-publication commit point and MUST
    /// atomically write the tag, complete payload, and rejoin route while
    /// rejecting stale generations. It MUST preserve the durable conversation-to-current-group
    /// mapping until strict predecessor deletion succeeds; same-generation
    /// replay uses that old mapping to resume cleanup after restart. It must
    /// never expose an incomplete reset tag. A returned
    /// error is ambiguous, so callers re-read durable state instead of rolling
    /// back a write that may already have committed.
    ///
    /// The same commit MUST also clear any persisted quarantine for the
    /// conversation. A server reset is a documented quarantine exit (ruling 2a,
    /// 2026-08-15), so the tag, complete payload, rejoin route, and quarantine
    /// clear are one commit — not a commit followed by a separate clear. The
    /// orchestrator still issues `clear_quarantine` afterwards as a backstop
    /// for pre-amendment backends, but a backend that defers the clear to that
    /// call can mint a row that is simultaneously reset-pending and
    /// quarantined whenever the process dies or that call fails, and such a
    /// row rehydrates quarantined forever: the replayed reset event takes the
    /// same-generation dedupe path and never reaches the clear again.
    async fn mark_reset_pending(
        &self,
        _conversation_id: &str,
        _new_group_id_hex: &str,
        _reset_generation: i32,
        _notified_at_ms: i64,
    ) -> Result<()> {
        Err(super::error::OrchestratorError::Storage(
            "mark_reset_pending is required for reset recovery".to_string(),
        ))
    }

    /// Atomically replace the target of an already committed RESET_PENDING
    /// transition with the server-verified winner of a reset race.
    ///
    /// The backend MUST require the exact stable conversation id, generation,
    /// and old target, plus a complete committed ResetPending payload. On
    /// success it changes only the pending target, preserving the generation,
    /// notification timestamp, ResetPending tag, durable rejoin route, current
    /// conversation mapping, and generation fences. An exact old/new target is
    /// an idempotent success. Missing or mismatched authority returns false
    /// without mutation.
    ///
    /// This operation never projects Active, clears reset authority, or deletes
    /// group state. Returned errors are commit-ambiguous; callers must reread
    /// durable authority before taking any destructive action (ADR-018).
    async fn adopt_reset_pending_target(
        &self,
        _conversation_id: &str,
        _expected_generation: i32,
        _expected_old_target: &str,
        _authoritative_new_target: &str,
    ) -> Result<bool> {
        Err(super::error::OrchestratorError::Storage(
            "adopt_reset_pending_target is required for reset recovery".to_string(),
        ))
    }

    /// Complete a persisted RESET_PENDING transition with causal generation
    /// binding.
    ///
    /// This operation MUST atomically verify the exact committed generation
    /// and target, project the durable conversation mapping to that target,
    /// atomically set both the current and join epochs to the authoritative
    /// landed MLS epoch, clear its payload, transition the durable state tag to
    /// Active, and clear the durable rejoin flag. It returns true only when that complete
    /// transaction commits. A generation or target mismatch returns false
    /// without changing any state.
    async fn complete_reset_pending(
        &self,
        _conversation_id: &str,
        _expected_generation: i32,
        _expected_new_group_id_hex: &str,
        _landed_epoch: u64,
    ) -> Result<bool> {
        Err(super::error::OrchestratorError::Storage(
            "complete_reset_pending is required for reset recovery".to_string(),
        ))
    }

    /// Remove an exact RESET_PENDING generation as part of local conversation
    /// deletion. This MUST NOT project Active. A mismatch returns false and
    /// leaves the pending-delete intent in place for a retry.
    async fn clear_reset_pending_for_delete(
        &self,
        _conversation_id: &str,
        _expected_generation: i32,
    ) -> Result<bool> {
        Err(super::error::OrchestratorError::Storage(
            "clear_reset_pending_for_delete is required for reset recovery".to_string(),
        ))
    }

    /// Persist the conversation→sequencer mapping (ADR-010 D4 rule 4 cache).
    ///
    /// `sequencer_did` is the base DID (no fragment) of the DS currently
    /// sequencing the conversation, as reported by `convoView.sequencerDid`.
    /// Routing does NOT consult this yet (WS-4 rung 3); rung 2 only records
    /// the mapping so the client-side cache exists before the routing flip.
    ///
    /// Default no-op for backward compat; platforms that don't override are
    /// surfaced by the WS-5.6 init-time capabilities check.
    async fn set_conversation_sequencer(
        &self,
        _conversation_id: &str,
        _sequencer_did: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// Persist a Layer 3 quarantine transition.
    ///
    /// reason_tag is the snake_case tag from QuarantineReason::tag() so
    /// the wire format is stable across orchestrator versions.
    /// since_ms is Unix-millis when quarantine was entered.
    /// Mirrors mark_reset_pending: no-op default, Phase-3 platforms override.
    async fn mark_quarantined(
        &self,
        _conversation_id: &str,
        _reason_tag: &str,
        _since_ms: i64,
    ) -> Result<()> {
        Ok(())
    }

    /// Clear any persisted quarantine payload after exit.
    async fn clear_quarantine(&self, _conversation_id: &str) -> Result<()> {
        Ok(())
    }

    // -- Messages --

    /// Store a decrypted message.
    async fn store_message(&self, message: &Message) -> Result<()>;

    /// Fetch messages for a conversation, ordered by sequence number.
    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>>;

    /// Check if a message has already been stored (deduplication).
    async fn message_exists(&self, message_id: &str) -> Result<bool>;

    // -- Sync Cursors --

    /// Get the current sync cursor.
    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor>;

    /// Update the sync cursor.
    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()>;

    // -- Group State --

    /// Store or update local group state.
    async fn set_group_state(&self, state: &GroupState) -> Result<()>;

    /// Get local group state.
    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>>;

    /// Delete group state.
    async fn delete_group_state(&self, group_id: &str) -> Result<()>;

    // -- Pending Messages (self-echo dedup across restarts) --

    /// Persist a pending message ID so self-echo dedup survives app restart.
    /// Default no-op for backward compatibility with existing backends.
    async fn store_pending_message(&self, _conversation_id: &str, _message_id: &str) -> Result<()> {
        Ok(())
    }

    /// Remove a pending message ID, returning true if it was present.
    /// Used during self-echo dedup as fallback when in-memory sets are empty.
    async fn remove_pending_message(&self, _message_id: &str) -> Result<bool> {
        Ok(false)
    }

    // -- Sequencer Receipts --

    /// Store a sequencer receipt for a successful commit.
    /// Default no-op for backward compatibility with existing backends.
    async fn store_sequencer_receipt(&self, _receipt: &SequencerReceipt) -> Result<()> {
        Ok(())
    }

    /// Get stored receipts for a conversation, optionally filtered by epoch.
    /// Returns receipts with `epoch >= since_epoch` when provided.
    async fn get_sequencer_receipts(
        &self,
        _convo_id: &str,
        _since_epoch: Option<i32>,
    ) -> Result<Vec<SequencerReceipt>> {
        Ok(vec![])
    }

    /// Delete ALL stored sequencer receipts for a conversation.
    ///
    /// Called when a server group reset is ingested (WS-3 stage 2 / backlog
    /// N44a): a reset rebuilds the MLS group from scratch, so epochs restart
    /// and comparing receipts across the reset boundary is meaningless — a
    /// stale pre-reset receipt at epoch N would false-positive the
    /// equivocation check against a genuine post-reset receipt at the same N.
    /// Default no-op for backward compatibility; backends that implement
    /// `store_sequencer_receipt` MUST implement this too or their
    /// equivocation detection mis-fires after the first reset.
    async fn clear_sequencer_receipts(&self, _conversation_id: &str) -> Result<()> {
        Ok(())
    }

    // -- Epoch Secret Cleanup --

    /// Clean up platform-side epoch data older than the retention window.
    ///
    /// Platform storage implementations (iOS GRDB, catmos SQLite) can override
    /// this to delete epoch-related records from their own tables.
    /// Default no-op for backward compatibility.
    async fn cleanup_old_epoch_data(
        &self,
        _conversation_id: &str,
        _retain_from_epoch: u64,
    ) -> Result<()> {
        Ok(())
    }

    // -- RecoveryTracker persistence (WS-5.4, invariant E7) --

    /// Read the persisted RecoveryTracker state for startup hydration.
    ///
    /// Hydration ignores entries whose `last_attempt_at_ms` is older than
    /// `constants::RECOVERY_BACKOFF_TTL` (24 h) and honors — never extends —
    /// remaining cooldown/quarantine. Returning an authoritative empty state
    /// from an omitted implementation would reset attacker-triggered backoff
    /// on every restart, so the default fails closed.
    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        Err(super::error::OrchestratorError::Storage(
            "get_recovery_state is required for recovery rate limiting".to_string(),
        ))
    }

    /// Write-through one conversation's rejoin-backoff snapshot. Called on
    /// every failed rejoin attempt (and on quarantine-lockout entry).
    ///
    /// This is security-relevant restart state. The default fails closed so a
    /// direct Rust backend cannot silently report durable success while
    /// dropping the rate-limit snapshot.
    async fn set_recovery_backoff(&self, _entry: &PersistedRecoveryBackoff) -> Result<()> {
        Err(super::error::OrchestratorError::Storage(
            "set_recovery_backoff is required for recovery rate limiting".to_string(),
        ))
    }

    /// Remove a conversation's persisted backoff entry. Called on successful
    /// rejoin and on server-initiated reset (fresh start).
    ///
    /// The default fails closed for the same reason as
    /// [`Self::set_recovery_backoff`]: callers must never mistake an omitted
    /// native implementation for a committed durable mutation.
    async fn clear_recovery_backoff(&self, _conversation_id: &str) -> Result<()> {
        Err(super::error::OrchestratorError::Storage(
            "clear_recovery_backoff is required for recovery rate limiting".to_string(),
        ))
    }

    /// Persist the global last-rejoin-attempt timestamp (epoch ms), which
    /// backs `MIN_REJOIN_INTERVAL` across restarts. The default fails closed;
    /// silently dropping this write would let restart bypass the global gate.
    async fn set_last_global_rejoin_attempt_at(&self, _at_ms: i64) -> Result<()> {
        Err(super::error::OrchestratorError::Storage(
            "set_last_global_rejoin_attempt_at is required for recovery rate limiting".to_string(),
        ))
    }

    // -- Pending local deletes (WS-5.3 crash-safe force_delete_local) --

    /// Record the intent to locally delete a conversation BEFORE the MLS-layer
    /// and storage deletes run. Idempotent. Default no-op.
    async fn mark_pending_local_delete(
        &self,
        _conversation_id: &str,
        _group_id_hex: Option<&str>,
    ) -> Result<()> {
        Ok(())
    }

    /// Clear a pending local-delete intent after all delete steps succeeded
    /// (NotFound-class outcomes — state already gone — count as success for
    /// the idempotent delete). When any step really fails the orchestrator
    /// keeps the intent so the next startup sweep retries. Default no-op.
    async fn clear_pending_local_delete(&self, _conversation_id: &str) -> Result<()> {
        Ok(())
    }

    /// List local deletes that were started but never completed (crash between
    /// intent and completion). Consumed by the startup reconcile sweep.
    /// Default empty.
    async fn list_pending_local_deletes(&self) -> Result<Vec<PendingLocalDelete>> {
        Ok(vec![])
    }

    // -- Capabilities (WS-5.6) --

    /// Names of the trait methods with defaults that this backend actually
    /// overrides. Most entries are informational and produce an init-time
    /// warning when absent. Entries in
    /// [`REQUIRED_RECOVERY_PERSISTENCE_METHODS`] are security capabilities:
    /// initialization is rejected when any are absent.
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[]
    }
}

#[cfg(test)]
mod fail_closed_default_tests {
    use super::*;

    struct MissingRecoveryBackoffStorage;

    #[async_trait]
    impl MLSStorageBackend for MissingRecoveryBackoffStorage {
        async fn ensure_conversation_exists(
            &self,
            _user_did: &str,
            _conversation_id: &str,
            _group_id: &str,
        ) -> Result<()> {
            unreachable!()
        }

        async fn update_join_info(
            &self,
            _conversation_id: &str,
            _user_did: &str,
            _join_method: JoinMethod,
            _join_epoch: u64,
        ) -> Result<()> {
            unreachable!()
        }

        async fn get_conversation(
            &self,
            _user_did: &str,
            _conversation_id: &str,
        ) -> Result<Option<ConversationView>> {
            unreachable!()
        }

        async fn list_conversations(&self, _user_did: &str) -> Result<Vec<ConversationView>> {
            unreachable!()
        }

        async fn delete_conversations(&self, _user_did: &str, _ids: &[&str]) -> Result<()> {
            unreachable!()
        }

        async fn set_conversation_state(
            &self,
            _conversation_id: &str,
            _state: ConversationState,
        ) -> Result<()> {
            unreachable!()
        }

        async fn mark_needs_rejoin(&self, _conversation_id: &str) -> Result<()> {
            unreachable!()
        }

        async fn needs_rejoin(&self, _conversation_id: &str) -> Result<bool> {
            unreachable!()
        }

        async fn clear_rejoin_flag(&self, _conversation_id: &str) -> Result<()> {
            unreachable!()
        }

        async fn store_message(&self, _message: &Message) -> Result<()> {
            unreachable!()
        }

        async fn get_messages(
            &self,
            _conversation_id: &str,
            _limit: u32,
            _before_sequence: Option<u64>,
        ) -> Result<Vec<Message>> {
            unreachable!()
        }

        async fn message_exists(&self, _message_id: &str) -> Result<bool> {
            unreachable!()
        }

        async fn get_sync_cursor(&self, _user_did: &str) -> Result<SyncCursor> {
            unreachable!()
        }

        async fn set_sync_cursor(&self, _user_did: &str, _cursor: &SyncCursor) -> Result<()> {
            unreachable!()
        }

        async fn set_group_state(&self, _state: &GroupState) -> Result<()> {
            unreachable!()
        }

        async fn get_group_state(&self, _group_id: &str) -> Result<Option<GroupState>> {
            unreachable!()
        }

        async fn delete_group_state(&self, _group_id: &str) -> Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn omitted_recovery_backoff_persistence_fails_closed() {
        let storage = MissingRecoveryBackoffStorage;
        let entry = PersistedRecoveryBackoff {
            conversation_id: "convo-security".to_string(),
            failed_rejoin_count: 3,
            last_attempt_at_ms: 1234,
            quarantined_until_ms: Some(5678),
        };

        let read_error = storage
            .get_recovery_state()
            .await
            .expect_err("omitted get_recovery_state must not report authoritative empty state");
        let set_error = storage
            .set_recovery_backoff(&entry)
            .await
            .expect_err("omitted set_recovery_backoff must not report durable success");
        let clear_error = storage
            .clear_recovery_backoff(&entry.conversation_id)
            .await
            .expect_err("omitted clear_recovery_backoff must not report durable success");
        let global_error = storage
            .set_last_global_rejoin_attempt_at(entry.last_attempt_at_ms)
            .await
            .expect_err("omitted global rejoin timestamp write must not report durable success");

        assert!(read_error.to_string().contains("get_recovery_state"));
        assert!(set_error.to_string().contains("set_recovery_backoff"));
        assert!(clear_error.to_string().contains("clear_recovery_backoff"));
        assert!(global_error
            .to_string()
            .contains("set_last_global_rejoin_attempt_at"));

        let initialization_error = require_recovery_persistence_capabilities(&storage)
            .expect_err("an omitted recovery persistence backend must be rejected at startup");
        assert!(initialization_error
            .to_string()
            .contains("get_recovery_state"));
    }
}
