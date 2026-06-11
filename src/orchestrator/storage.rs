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

/// Every `MLSStorageBackend` method that ships a default no-op impl.
///
/// Used by the orchestrator's init-time capabilities check (WS-5.6): any
/// method in this list that the backend does not report via
/// [`MLSStorageBackend::implemented_optional_methods`] is logged as a warning,
/// because state routed through a default no-op is silently dropped (e.g.
/// `mark_reset_pending` dropping a RESET_PENDING payload across restart).
pub const OPTIONAL_STORAGE_METHODS: &[&str] = &[
    "get_conversation_state",
    "get_welcome_reissue_attempt_log",
    "record_welcome_reissue_attempt",
    "mark_reset_pending",
    "clear_reset_pending",
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

/// Platform-agnostic storage backend for MLS orchestration state.
///
/// Implementations should persist data durably (e.g. SQLite, GRDB, Room).
/// All methods are async to allow non-blocking I/O.
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
    ///
    /// Default returns `Ok(None)` for backward compatibility; backends that
    /// persist state should override.
    async fn get_conversation_state(
        &self,
        _conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        Ok(None)
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
    /// The orchestrator uses `set_conversation_state` to flip the tag to
    /// `reset_pending` and this method to persist the payload so that, after
    /// orchestrator restart, the platform layer can rehydrate a
    /// `ConversationState::ResetPending { .. }` and resume Phase 1 recovery.
    ///
    /// Default no-op for backward compatibility; platforms should override
    /// before relying on RESET_PENDING persistence.
    async fn mark_reset_pending(
        &self,
        _conversation_id: &str,
        _new_group_id_hex: &str,
        _reset_generation: i32,
        _notified_at_ms: i64,
    ) -> Result<()> {
        Ok(())
    }

    /// Clear any persisted RESET_PENDING payload for a conversation (called
    /// after successful adoption of the new group).
    async fn clear_reset_pending(&self, _conversation_id: &str) -> Result<()> {
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
    /// remaining cooldown/quarantine. Default empty state preserves the
    /// pre-WS-5.4 "restart resets backoff" behavior for backends that have
    /// not added the table yet.
    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        Ok(PersistedRecoveryState::default())
    }

    /// Write-through one conversation's rejoin-backoff snapshot. Called on
    /// every failed rejoin attempt (and on quarantine-lockout entry). Default
    /// no-op for backward compatibility.
    async fn set_recovery_backoff(&self, _entry: &PersistedRecoveryBackoff) -> Result<()> {
        Ok(())
    }

    /// Remove a conversation's persisted backoff entry. Called on successful
    /// rejoin and on server-initiated reset (fresh start). Default no-op.
    async fn clear_recovery_backoff(&self, _conversation_id: &str) -> Result<()> {
        Ok(())
    }

    /// Persist the global last-rejoin-attempt timestamp (epoch ms), which
    /// backs `MIN_REJOIN_INTERVAL` across restarts. Default no-op.
    async fn set_last_global_rejoin_attempt_at(&self, _at_ms: i64) -> Result<()> {
        Ok(())
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

    /// Names of the optional (default no-op) trait methods this backend
    /// actually overrides. Purely informational: the orchestrator's init-time
    /// capabilities check warns about every method in
    /// [`OPTIONAL_STORAGE_METHODS`] not reported here, so silently-dropped
    /// state (default no-ops) is observable in logs. Backends that override
    /// optional methods should keep this list in sync; a stale list only
    /// produces a spurious warning, never a behavior change.
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[]
    }
}
