//! In-memory mock implementation of `MLSStorageBackend` for testing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use catbird_mls::orchestrator::welcome_recovery::{ReissueAttempt, ReissueAttemptLog};
use catbird_mls::orchestrator::{
    ConversationState, ConversationView, GroupState, JoinMethod, MLSStorageBackend, Message,
    OrchestratorError, PendingLocalDelete, PersistedRecoveryBackoff, PersistedRecoveryState,
    Result, SequencerReceipt, SyncCursor,
};

/// Tracks a conversation state transition for test verification.
#[derive(Debug, Clone)]
pub struct StateTransition {
    pub from: Option<ConversationState>,
    pub to: ConversationState,
}

/// Internal record for a conversation managed by MockStorage.
#[derive(Debug, Clone)]
struct ConversationRecord {
    conversation_id: String,
    user_did: String,
    group_id: String,
    state: ConversationState,
    needs_rejoin: bool,
    join_method: Option<JoinMethod>,
    join_epoch: Option<u64>,
    view: ConversationView,
    is_active: bool,
}

/// Persisted RESET_PENDING payload as `mark_reset_pending` would write it.
#[derive(Debug, Clone)]
pub struct PersistedResetPending {
    pub new_group_id_hex: String,
    pub reset_generation: i32,
    pub notified_at_ms: i64,
}

/// Shared inner state behind `Arc<Mutex<...>>`.
#[derive(Debug, Default)]
struct Inner {
    /// conversation_id -> ConversationRecord
    conversations: HashMap<String, ConversationRecord>,
    /// conversation_id -> Vec<Message>
    messages: HashMap<String, Vec<Message>>,
    /// group_id -> GroupState
    group_states: HashMap<String, GroupState>,
    /// user_did -> SyncCursor
    sync_cursors: HashMap<String, SyncCursor>,
    /// conversation_id -> Vec<StateTransition>
    state_transitions: HashMap<String, Vec<StateTransition>>,
    /// Pending message IDs for self-echo dedup (survives simulated restart)
    pending_messages: std::collections::HashSet<String>,
    /// conversation_id -> persisted RESET_PENDING payload (mirrors real
    /// platform storage's reset-pending lifecycle columns).
    reset_pending: HashMap<String, PersistedResetPending>,
    account_exit_reset_high_water: HashMap<String, i32>,
    lose_account_exit_projection_response: bool,
    /// Number of times `mark_reset_pending` has been called per conversation.
    /// Used by idempotency tests to assert duplicate calls collapse.
    mark_reset_pending_calls: HashMap<String, u32>,
    /// conversation_id -> Welcome reissue attempts.
    welcome_reissue_attempts: HashMap<String, Vec<ReissueAttempt>>,
    /// conversation_id -> persisted rejoin-backoff entry (WS-5.4 / E7).
    recovery_backoff: HashMap<String, PersistedRecoveryBackoff>,
    /// Persisted global last-rejoin-attempt timestamp (epoch ms).
    last_global_rejoin_attempt_at_ms: Option<i64>,
    fail_next_get_recovery_state: bool,
    /// One-shot failure injection for startup conversation inventory hydration.
    fail_next_list_conversations: bool,
    /// One-shot partial-write injection for recovery persistence ordering.
    fail_next_set_last_global_rejoin_attempt_at: bool,
    /// conversation_id -> pending local-delete intent (WS-5.3).
    pending_local_deletes: HashMap<String, PendingLocalDelete>,
    /// When set, the next `clear_rejoin_flag` call fails once (WS-5 FIX-1
    /// escalation tests). Mirrors the `fail_next_*` pattern in
    /// `mock_api_client.rs`.
    fail_next_clear_rejoin_flag: bool,
    /// When set, the next `delete_conversations` call fails once (WS-5 FIX-5
    /// keep-intent-on-failure tests).
    fail_next_delete_conversations: bool,
    fail_next_mark_pending_local_delete: bool,
    fail_clear_pending_local_delete_for: Option<String>,
    /// conversation_id -> persisted quarantine payload `(reason_tag,
    /// since_ms)` (Layer 3; mirrors the platform `mark_quarantined` /
    /// `clear_quarantine` columns).
    quarantines: HashMap<String, (String, i64)>,
    /// One-shot failure injections for the quarantine persist escalation
    /// tests (E7 follow-up R-2).
    fail_next_set_conversation_state: bool,
    fail_next_set_group_state: bool,
    fail_next_store_message: bool,
    fail_next_ensure_conversation_exists: bool,
    fail_next_update_join_info: bool,
    fail_next_mark_reset_pending: bool,
    fail_next_mark_reset_pending_after_commit: bool,
    fail_next_mark_reset_pending_after_commit_with_notified_at_offset: Option<i64>,
    fail_next_adopt_reset_pending_after_commit: bool,
    fail_next_adopt_reset_pending_after_commit_with_read_failure: bool,
    force_next_clear_reset_pending_for_delete_false: bool,
    fail_next_complete_reset_pending: bool,
    force_next_complete_reset_pending_false_reload: Option<Option<ConversationState>>,
    fail_next_get_conversation_state: bool,
    fail_next_needs_rejoin: bool,
    fail_next_conversation_state_for: Option<String>,
    next_conversation_state_override: Option<(String, Option<ConversationState>)>,
    fail_conversation_state_after_reads: Option<(String, u32)>,
    malformed_conversation_states: std::collections::HashSet<String>,
    fail_next_mark_quarantined: bool,
    fail_next_clear_quarantine: bool,
    /// Stored sequencer receipts (WS-3 equivocation detection tests).
    sequencer_receipts: Vec<SequencerReceipt>,
    /// conversation_id -> persisted sequencer DID (WS-4 rung 2; ADR-010 D4
    /// rule-4 client cache, written by `set_conversation_sequencer`).
    sequencer_mappings: HashMap<String, String>,
    /// Number of times `set_conversation_sequencer` has been called per
    /// conversation (asserts persist-only-on-change behavior).
    set_conversation_sequencer_calls: HashMap<String, u32>,
    /// Platform epoch-retention calls, recorded as `(conversation_id, cutoff)`.
    epoch_cleanup_calls: Vec<(String, u64)>,
    startup_probe_counts: StartupProbeCounts,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StartupProbeCounts {
    pub list_conversations: u32,
    pub get_conversation_state: u32,
    pub get_recovery_state: u32,
    pub list_pending_local_deletes: u32,
}

/// An in-memory mock of `MLSStorageBackend` suitable for unit and integration tests.
///
/// All state is stored behind `Arc<Mutex<...>>` so the mock can be cloned
/// and shared across tasks while still allowing test assertions on the
/// accumulated state.
#[derive(Debug, Clone)]
pub struct MockStorage {
    inner: Arc<Mutex<Inner>>,
    declare_pending_delete_capabilities: Arc<std::sync::atomic::AtomicBool>,
    conversation_state_read_barrier: Arc<Mutex<Option<(String, ConversationStateReadBarrier)>>>,
    reset_completion_barrier: Arc<Mutex<Option<(String, ResetCompletionBarrier)>>>,
    reset_record_barrier: Arc<Mutex<Option<(String, ResetCompletionBarrier)>>>,
    reset_adopt_barrier: Arc<Mutex<Option<(String, ResetCompletionBarrier)>>>,
    clear_rejoin_barrier: Arc<Mutex<Option<(String, ClearRejoinBarrier)>>>,
    conversation_state_write_barrier:
        Arc<Mutex<Option<(String, Option<ConversationState>, ClearRejoinBarrier)>>>,
    group_state_write_barrier: Arc<Mutex<Option<ClearRejoinBarrier>>>,
    pending_local_delete_write_barrier: Arc<Mutex<Option<(String, bool, ClearRejoinBarrier)>>>,
}

#[derive(Debug, Clone)]
pub struct ConversationStateReadBarrier {
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

impl ConversationStateReadBarrier {
    pub async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("conversation-state barrier entered semaphore closed")
            .forget();
    }

    pub fn release(&self) {
        self.release.add_permits(1);
    }
}

#[derive(Debug, Clone)]
pub struct ResetCompletionBarrier {
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug, Clone)]
pub struct ClearRejoinBarrier {
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

impl ClearRejoinBarrier {
    pub async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("clear-rejoin barrier entered semaphore closed")
            .forget();
    }

    pub fn release(&self) {
        self.release.add_permits(1);
    }
}

impl ResetCompletionBarrier {
    pub async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("reset-completion barrier entered semaphore closed")
            .forget();
    }

    pub fn release(&self) {
        self.release.add_permits(1);
    }
}

impl MockStorage {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            declare_pending_delete_capabilities: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            conversation_state_read_barrier: Arc::new(Mutex::new(None)),
            reset_completion_barrier: Arc::new(Mutex::new(None)),
            reset_record_barrier: Arc::new(Mutex::new(None)),
            reset_adopt_barrier: Arc::new(Mutex::new(None)),
            clear_rejoin_barrier: Arc::new(Mutex::new(None)),
            conversation_state_write_barrier: Arc::new(Mutex::new(None)),
            group_state_write_barrier: Arc::new(Mutex::new(None)),
            pending_local_delete_write_barrier: Arc::new(Mutex::new(None)),
        }
    }

    /// Test helper: replace the mutable MLS group projected by a durable
    /// conversation row without altering its stable conversation identity.
    pub fn set_conversation_group_id_for_test(&self, conversation_id: &str, group_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        let record = inner
            .conversations
            .get_mut(conversation_id)
            .unwrap_or_else(|| panic!("conversation {conversation_id} not found"));
        record.group_id = group_id.to_string();
        record.view.group_id = group_id.to_string();
    }

    /// Seed a full host inventory projection without changing lifecycle or history.
    pub fn set_conversation_view_for_test(&self, conversation_id: &str, view: ConversationView) {
        let mut inner = self.inner.lock().unwrap();
        let record = inner
            .conversations
            .get_mut(conversation_id)
            .expect("existing conversation");
        assert_eq!(view.conversation_id, conversation_id);
        assert_eq!(view.group_id, record.group_id);
        record.view = view;
    }

    pub fn omit_pending_delete_capabilities(&self) {
        self.declare_pending_delete_capabilities
            .store(false, std::sync::atomic::Ordering::Release);
    }

    pub fn fail_next_set_last_global_rejoin_attempt_at(&self) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_set_last_global_rejoin_attempt_at = true;
    }

    pub fn fail_next_get_recovery_state(&self) {
        self.inner.lock().unwrap().fail_next_get_recovery_state = true;
    }

    pub fn fail_next_list_conversations(&self) {
        self.inner.lock().unwrap().fail_next_list_conversations = true;
    }

    // ── Test helper methods ──────────────────────────────────────────────

    /// Returns the total number of stored conversations.
    pub fn conversation_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .conversations
            .values()
            .filter(|c| c.is_active)
            .count()
    }

    /// Returns all messages across every conversation, ordered by conversation id.
    #[allow(dead_code)]
    pub fn get_all_messages(&self) -> Vec<Message> {
        let inner = self.inner.lock().unwrap();
        let mut all: Vec<Message> = inner.messages.values().flatten().cloned().collect();
        all.sort_by(|a, b| {
            a.conversation_id
                .cmp(&b.conversation_id)
                .then(a.sequence_number.cmp(&b.sequence_number))
        });
        all
    }

    /// Returns all messages for a specific conversation.
    #[allow(dead_code)]
    pub fn get_conversation_messages(&self, conversation_id: &str) -> Vec<Message> {
        let inner = self.inner.lock().unwrap();
        inner
            .messages
            .get(conversation_id)
            .cloned()
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn epoch_cleanup_calls(&self) -> Vec<(String, u64)> {
        self.inner.lock().unwrap().epoch_cleanup_calls.clone()
    }

    /// Whether the conversation has the rejoin flag set.
    #[allow(dead_code)]
    pub fn has_rejoin_flag(&self, conversation_id: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .conversations
            .get(conversation_id)
            .map(|c| c.needs_rejoin)
            .unwrap_or(false)
    }

    /// Returns all recorded state transitions for a conversation.
    #[allow(dead_code)]
    pub fn get_state_transitions(&self, conversation_id: &str) -> Vec<StateTransition> {
        let inner = self.inner.lock().unwrap();
        inner
            .state_transitions
            .get(conversation_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the current `ConversationState` for a conversation, if it exists.
    #[allow(dead_code)]
    pub fn get_current_state(&self, conversation_id: &str) -> Option<ConversationState> {
        let inner = self.inner.lock().unwrap();
        inner
            .conversations
            .get(conversation_id)
            .map(|c| c.state.clone())
    }

    /// Whether a group state exists for the given group_id.
    #[allow(dead_code)]
    pub fn has_group_state(&self, group_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .group_states
            .contains_key(group_id)
    }

    /// Returns the total number of messages across all conversations.
    #[allow(dead_code)]
    pub fn total_message_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .messages
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Returns the persisted RESET_PENDING payload for a conversation, if
    /// any. Mirrors what a real platform storage backend would round-trip
    /// through its `mark_reset_pending`/`get_conversation_state` columns.
    #[allow(dead_code)]
    pub fn get_persisted_reset_pending(
        &self,
        conversation_id: &str,
    ) -> Option<PersistedResetPending> {
        self.inner
            .lock()
            .unwrap()
            .reset_pending
            .get(conversation_id)
            .cloned()
    }

    /// Returns the number of times `mark_reset_pending` has been invoked for
    /// a conversation. Used by idempotency tests to assert duplicate calls
    /// to `record_reset_requested` collapse rather than re-persist.
    #[allow(dead_code)]
    pub fn mark_reset_pending_call_count(&self, conversation_id: &str) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .mark_reset_pending_calls
            .get(conversation_id)
            .copied()
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn welcome_reissue_attempt_count(&self, conversation_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .welcome_reissue_attempts
            .get(conversation_id)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Returns the persisted rejoin-backoff entry for a conversation (WS-5.4).
    #[allow(dead_code)]
    pub fn get_persisted_recovery_backoff(
        &self,
        conversation_id: &str,
    ) -> Option<PersistedRecoveryBackoff> {
        self.inner
            .lock()
            .unwrap()
            .recovery_backoff
            .get(conversation_id)
            .cloned()
    }

    /// Returns the persisted global last-rejoin-attempt timestamp (WS-5.4).
    #[allow(dead_code)]
    pub fn get_persisted_last_global_rejoin_at_ms(&self) -> Option<i64> {
        self.inner.lock().unwrap().last_global_rejoin_attempt_at_ms
    }

    #[allow(dead_code)]
    pub fn startup_probe_counts(&self) -> StartupProbeCounts {
        self.inner.lock().unwrap().startup_probe_counts
    }

    /// Directly seed a persisted backoff entry, simulating state written by a
    /// previous process (restart/TTL tests).
    #[allow(dead_code)]
    pub fn seed_recovery_backoff(&self, entry: PersistedRecoveryBackoff) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .recovery_backoff
            .insert(entry.conversation_id.clone(), entry);
    }

    /// Directly seed a pending local-delete intent, simulating a crash between
    /// intent and completion (WS-5.3 reconcile tests).
    #[allow(dead_code)]
    pub fn seed_pending_local_delete(&self, intent: PendingLocalDelete) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .pending_local_deletes
            .insert(intent.conversation_id.clone(), intent);
    }

    /// Returns the current pending local-delete intents (WS-5.3).
    #[allow(dead_code)]
    pub fn pending_local_delete_count(&self) -> usize {
        self.inner.lock().unwrap().pending_local_deletes.len()
    }

    pub fn pending_local_delete_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self
            .inner
            .lock()
            .unwrap()
            .pending_local_deletes
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    pub fn join_epoch_for_test(&self, conversation_id: &str) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .conversations
            .get(conversation_id)
            .and_then(|record| record.join_epoch)
    }

    pub fn set_epoch_pair_for_test(
        &self,
        conversation_id: &str,
        current_epoch: u64,
        join_epoch: u64,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let record = inner
            .conversations
            .get_mut(conversation_id)
            .expect("conversation must exist before seeding epochs");
        record.view.epoch = current_epoch;
        record.join_epoch = Some(join_epoch);
    }

    pub fn remove_conversation_record_for_test(&self, conversation_id: &str) {
        self.inner
            .lock()
            .unwrap()
            .conversations
            .remove(conversation_id);
    }

    /// Make the next `clear_rejoin_flag` call fail once.
    #[allow(dead_code)]
    pub fn fail_next_clear_rejoin_flag(&self) {
        self.inner.lock().unwrap().fail_next_clear_rejoin_flag = true;
    }

    /// Make the next `delete_conversations` call fail once.
    #[allow(dead_code)]
    pub fn fail_next_delete_conversations(&self) {
        self.inner.lock().unwrap().fail_next_delete_conversations = true;
    }

    /// Make the next pending local-delete intent write fail once.
    pub fn fail_next_mark_pending_local_delete(&self) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_mark_pending_local_delete = true;
    }

    pub fn fail_next_clear_pending_local_delete(&self, conversation_id: &str) {
        self.inner
            .lock()
            .unwrap()
            .fail_clear_pending_local_delete_for = Some(conversation_id.to_string());
    }

    /// Make the next `set_conversation_state` call fail once (R-2
    /// quarantine-persist escalation tests).
    #[allow(dead_code)]
    pub fn fail_next_set_conversation_state(&self) {
        self.inner.lock().unwrap().fail_next_set_conversation_state = true;
    }

    pub fn lose_next_account_exit_projection_response(&self) {
        self.inner
            .lock()
            .unwrap()
            .lose_account_exit_projection_response = true;
    }

    pub fn fail_next_set_group_state(&self) {
        self.inner.lock().unwrap().fail_next_set_group_state = true;
    }

    pub fn fail_next_store_message(&self) {
        self.inner.lock().unwrap().fail_next_store_message = true;
    }

    pub fn fail_next_ensure_conversation_exists(&self) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_ensure_conversation_exists = true;
    }

    pub fn fail_next_update_join_info(&self) {
        self.inner.lock().unwrap().fail_next_update_join_info = true;
    }

    #[allow(dead_code)]
    pub fn fail_next_mark_reset_pending(&self) {
        self.inner.lock().unwrap().fail_next_mark_reset_pending = true;
    }

    pub fn fail_next_mark_reset_pending_after_commit(&self) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_mark_reset_pending_after_commit = true;
    }

    pub fn fail_next_mark_reset_pending_after_commit_with_notified_at_offset(&self, offset: i64) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_mark_reset_pending_after_commit_with_notified_at_offset = Some(offset);
    }

    pub fn force_next_clear_reset_pending_for_delete_false(&self) {
        self.inner
            .lock()
            .unwrap()
            .force_next_clear_reset_pending_for_delete_false = true;
    }

    pub fn fail_next_complete_reset_pending(&self) {
        self.inner.lock().unwrap().fail_next_complete_reset_pending = true;
    }

    pub fn fail_next_adopt_reset_pending_after_commit(&self) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_adopt_reset_pending_after_commit = true;
    }

    pub fn fail_next_adopt_reset_pending_after_commit_with_read_failure(&self) {
        self.inner
            .lock()
            .unwrap()
            .fail_next_adopt_reset_pending_after_commit_with_read_failure = true;
    }

    pub fn force_next_complete_reset_pending_false_with_reload(
        &self,
        reload: Option<ConversationState>,
    ) {
        self.inner
            .lock()
            .unwrap()
            .force_next_complete_reset_pending_false_reload = Some(reload);
    }

    /// Simulate a malformed persisted reset/quarantine sidecar that cannot be
    /// decoded by the platform storage adapter during startup hydration.
    pub fn fail_next_get_conversation_state(&self) {
        self.inner.lock().unwrap().fail_next_get_conversation_state = true;
    }
    pub fn fail_next_needs_rejoin(&self) {
        self.inner.lock().unwrap().fail_next_needs_rejoin = true;
    }

    #[allow(dead_code)]
    pub fn fail_next_get_conversation_state_for(&self, conversation_id: &str) {
        self.inner.lock().unwrap().fail_next_conversation_state_for =
            Some(conversation_id.to_string());
    }

    pub fn override_next_conversation_state_read(
        &self,
        conversation_id: &str,
        state: Option<ConversationState>,
    ) {
        self.inner.lock().unwrap().next_conversation_state_override =
            Some((conversation_id.to_string(), state));
    }

    #[allow(dead_code)]
    pub fn fail_get_conversation_state_after_successful_reads(
        &self,
        conversation_id: &str,
        successful_reads: u32,
    ) {
        self.inner
            .lock()
            .unwrap()
            .fail_conversation_state_after_reads =
            Some((conversation_id.to_string(), successful_reads));
    }

    /// Persistently fail decoding the security sidecar for one conversation,
    /// matching a malformed reset-pending or quarantine record across restart.
    #[allow(dead_code)]
    pub fn mark_conversation_state_malformed(&self, conversation_id: &str) {
        self.inner
            .lock()
            .unwrap()
            .malformed_conversation_states
            .insert(conversation_id.to_string());
    }

    /// Pause the next security-state read for `conversation_id` until the
    /// returned barrier is released. Used to deterministically exercise
    /// lifecycle operations racing startup hydration.
    #[allow(dead_code)]
    pub fn pause_next_conversation_state_read(
        &self,
        conversation_id: &str,
    ) -> ConversationStateReadBarrier {
        let barrier = ConversationStateReadBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.conversation_state_read_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), barrier.clone()));
        barrier
    }

    /// Pause the next rejoin-flag clear before it mutates durable state.
    pub fn pause_next_clear_rejoin_flag(&self, conversation_id: &str) -> ClearRejoinBarrier {
        let barrier = ClearRejoinBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.clear_rejoin_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), barrier.clone()));
        barrier
    }

    pub fn pause_next_conversation_state_write(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> ClearRejoinBarrier {
        let barrier = ClearRejoinBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.conversation_state_write_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), Some(state), barrier.clone()));
        barrier
    }

    pub fn pause_next_conversation_state_write_any(
        &self,
        conversation_id: &str,
    ) -> ClearRejoinBarrier {
        let barrier = ClearRejoinBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.conversation_state_write_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), None, barrier.clone()));
        barrier
    }

    pub fn pause_next_group_state_write(&self) -> ClearRejoinBarrier {
        let barrier = ClearRejoinBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.group_state_write_barrier.lock().unwrap() = Some(barrier.clone());
        barrier
    }

    pub fn pause_pending_local_delete_write(
        &self,
        conversation_id: &str,
        after_write: bool,
    ) -> ClearRejoinBarrier {
        let barrier = ClearRejoinBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.pending_local_delete_write_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), after_write, barrier.clone()));
        barrier
    }

    pub fn pause_next_pending_local_delete_write(&self, after_write: bool) -> ClearRejoinBarrier {
        self.pause_pending_local_delete_write("", after_write)
    }

    /// Pause the next successful reset-completion callback after its durable
    /// CAS has committed but before the callback returns to the orchestrator.
    pub fn pause_next_reset_completion(&self, conversation_id: &str) -> ResetCompletionBarrier {
        let barrier = ResetCompletionBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.reset_completion_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), barrier.clone()));
        barrier
    }

    /// Pause reset recording after ResetPending and needs_rejoin are durable,
    /// but before the transition-lock owner returns.
    pub fn pause_next_reset_record(&self, conversation_id: &str) -> ResetCompletionBarrier {
        let barrier = ResetCompletionBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.reset_record_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), barrier.clone()));
        barrier
    }

    pub fn pause_next_reset_adoption(&self, conversation_id: &str) -> ResetCompletionBarrier {
        let barrier = ResetCompletionBarrier {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        *self.reset_adopt_barrier.lock().unwrap() =
            Some((conversation_id.to_string(), barrier.clone()));
        barrier
    }

    /// Make the next `mark_quarantined` call fail once.
    #[allow(dead_code)]
    pub fn fail_next_mark_quarantined(&self) {
        self.inner.lock().unwrap().fail_next_mark_quarantined = true;
    }

    /// Make the next `clear_quarantine` call fail once.
    #[allow(dead_code)]
    pub fn fail_next_clear_quarantine(&self) {
        self.inner.lock().unwrap().fail_next_clear_quarantine = true;
    }

    /// Returns the persisted quarantine payload `(reason_tag, since_ms)` for
    /// `conversation_id`, if any.
    #[allow(dead_code)]
    pub fn get_persisted_quarantine(&self, conversation_id: &str) -> Option<(String, i64)> {
        self.inner
            .lock()
            .unwrap()
            .quarantines
            .get(conversation_id)
            .cloned()
    }

    /// Returns the persisted sequencer DID for `conversation_id` as written
    /// by `set_conversation_sequencer` (WS-4 rung 2; ADR-010 D4).
    #[allow(dead_code)]
    pub fn get_persisted_sequencer(&self, conversation_id: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .sequencer_mappings
            .get(conversation_id)
            .cloned()
    }

    /// Number of times `set_conversation_sequencer` was called for
    /// `conversation_id` (asserts persist-only-on-change behavior).
    #[allow(dead_code)]
    pub fn set_conversation_sequencer_call_count(&self, conversation_id: &str) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .set_conversation_sequencer_calls
            .get(conversation_id)
            .copied()
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn storage_projection_counts(&self) -> StorageProjectionCounts {
        let inner = self.inner.lock().unwrap();
        StorageProjectionCounts {
            conversations: inner.conversations.len(),
            group_states: inner.group_states.len(),
            messages: inner.messages.values().map(Vec::len).sum(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageProjectionCounts {
    pub conversations: usize,
    pub group_states: usize,
    pub messages: usize,
}

#[async_trait]
impl MLSStorageBackend for MockStorage {
    // ── Conversations ────────────────────────────────────────────────────

    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_ensure_conversation_exists {
            inner.fail_next_ensure_conversation_exists = false;
            return Err(OrchestratorError::Storage(
                "injected ensure_conversation_exists failure".to_string(),
            ));
        }
        if let Some(record) = inner.conversations.get_mut(conversation_id) {
            record.user_did = user_did.to_string();
            record.group_id = group_id.to_string();
            record.is_active = true;
            record.view.group_id = group_id.to_string();
        } else {
            inner.conversations.insert(
                conversation_id.to_string(),
                ConversationRecord {
                    conversation_id: conversation_id.to_string(),
                    user_did: user_did.to_string(),
                    group_id: group_id.to_string(),
                    state: ConversationState::Initializing,
                    needs_rejoin: false,
                    join_method: None,
                    join_epoch: None,
                    is_active: true,
                    view: ConversationView {
                        group_id: group_id.to_string(),
                        conversation_id: conversation_id.to_string(),
                        epoch: 0,
                        members: vec![],
                        metadata: None,
                        created_at: Some(chrono::Utc::now()),
                        updated_at: Some(chrono::Utc::now()),
                        sequencer_did: None,
                        canonical_state: None,
                    },
                },
            );
        }
        Ok(())
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        _user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_update_join_info {
            inner.fail_next_update_join_info = false;
            return Err(OrchestratorError::Storage(
                "injected update_join_info failure".to_string(),
            ));
        }
        let record = inner
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| OrchestratorError::ConversationNotFound(conversation_id.to_string()))?;
        record.join_method = Some(join_method);
        record.join_epoch = Some(join_epoch);
        record.view.epoch = join_epoch;
        Ok(())
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .conversations
            .get(conversation_id)
            .filter(|conversation| conversation.user_did == user_did && conversation.is_active)
            .map(|c| c.view.clone()))
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let mut inner = self.inner.lock().unwrap();
        inner.startup_probe_counts.list_conversations += 1;
        if inner.fail_next_list_conversations {
            inner.fail_next_list_conversations = false;
            return Err(OrchestratorError::Storage(
                "injected list_conversations failure".to_string(),
            ));
        }
        let views = inner
            .conversations
            .values()
            .filter(|c| c.user_did == user_did && c.is_active)
            .map(|c| c.view.clone())
            .collect();
        Ok(views)
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_delete_conversations {
            inner.fail_next_delete_conversations = false;
            return Err(OrchestratorError::Storage(
                "injected delete_conversations failure".to_string(),
            ));
        }
        for id in ids {
            if let Some(record) = inner.conversations.get_mut(*id) {
                if record.user_did == user_did {
                    record.is_active = false;
                    record.state = ConversationState::Failed;
                }
            }
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        let barrier = {
            let mut installed = self.conversation_state_write_barrier.lock().unwrap();
            match installed.take() {
                Some((target, expected, barrier))
                    if target == conversation_id
                        && expected.as_ref().is_none_or(|expected| expected == &state) =>
                {
                    Some(barrier)
                }
                other => {
                    *installed = other;
                    None
                }
            }
        };
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("conversation-state write barrier release semaphore closed")
                .forget();
        }

        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_set_conversation_state {
            inner.fail_next_set_conversation_state = false;
            return Err(OrchestratorError::Storage(
                "injected set_conversation_state failure".to_string(),
            ));
        }
        let prev = inner
            .conversations
            .get(conversation_id)
            .map(|c| c.state.clone());

        if let Some(record) = inner.conversations.get_mut(conversation_id) {
            match &state {
                ConversationState::Active => {
                    record.is_active = true;
                    record.needs_rejoin = false;
                }
                _ => {}
            }
            record.state = state.clone();
        }
        inner
            .state_transitions
            .entry(conversation_id.to_string())
            .or_default()
            .push(StateTransition {
                from: prev,
                to: state.clone(),
            });
        Ok(())
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(record) = inner.conversations.get_mut(conversation_id) {
            record.needs_rejoin = true;
        }
        Ok(())
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_needs_rejoin {
            inner.fail_next_needs_rejoin = false;
            return Err(OrchestratorError::Storage(
                "injected needs_rejoin read failure".to_string(),
            ));
        }
        Ok(inner
            .conversations
            .get(conversation_id)
            .map(|c| c.needs_rejoin)
            .unwrap_or(false))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        let barrier = {
            let mut installed = self.clear_rejoin_barrier.lock().unwrap();
            match installed.take() {
                Some((target, barrier)) if target == conversation_id => Some(barrier),
                other => {
                    *installed = other;
                    None
                }
            }
        };
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("clear-rejoin barrier release semaphore closed")
                .forget();
        }

        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_clear_rejoin_flag {
            inner.fail_next_clear_rejoin_flag = false;
            return Err(OrchestratorError::Storage(
                "injected clear_rejoin_flag failure".to_string(),
            ));
        }
        if let Some(record) = inner.conversations.get_mut(conversation_id) {
            record.needs_rejoin = false;
        }
        Ok(())
    }

    async fn get_welcome_reissue_attempt_log(
        &self,
        conversation_id: &str,
    ) -> Result<ReissueAttemptLog> {
        let inner = self.inner.lock().unwrap();
        Ok(ReissueAttemptLog {
            attempts: inner
                .welcome_reissue_attempts
                .get(conversation_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    async fn record_welcome_reissue_attempt(
        &self,
        conversation_id: &str,
        attempted_at_ms: i64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .welcome_reissue_attempts
            .entry(conversation_id.to_string())
            .or_default()
            .push(ReissueAttempt { attempted_at_ms });
        Ok(())
    }

    // ── Reset-pending payload (overrides default no-ops) ─────────────────
    //
    // Real platform storage backends (iOS GRDB, catmos SQLite) persist these
    // payload columns so a `groupResetEvent` or Phase 2.5 `resetRequestedEvent`
    // observed before orchestrator restart still drives recovery on resume
    // (see `storage.rs` doc on `mark_reset_pending`). The mock has to do the
    // same, otherwise the simulated-restart test silently passes against
    // empty state.

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.fail_next_mark_reset_pending {
                inner.fail_next_mark_reset_pending = false;
                return Err(OrchestratorError::Storage(
                    "injected mark_reset_pending failure".to_string(),
                ));
            }
            if inner
                .reset_pending
                .get(conversation_id)
                .is_some_and(|pending| pending.reset_generation >= reset_generation)
            {
                return Err(OrchestratorError::Storage(format!(
                    "stale reset generation {reset_generation}"
                )));
            }
            inner.reset_pending.insert(
                conversation_id.to_string(),
                PersistedResetPending {
                    new_group_id_hex: new_group_id_hex.to_string(),
                    reset_generation,
                    notified_at_ms,
                },
            );
            inner
                .account_exit_reset_high_water
                .entry(conversation_id.into())
                .and_modify(|high| *high = (*high).max(reset_generation))
                .or_insert(reset_generation);
            // Ruling 2a: the authority commit is also the quarantine exit, so
            // the persisted quarantine row goes away in this same critical
            // section. A backend that waits for the orchestrator's separate
            // `clear_quarantine` backstop can mint a row that is both
            // reset-pending and quarantined whenever that call fails.
            inner.quarantines.remove(conversation_id);
            *inner
                .mark_reset_pending_calls
                .entry(conversation_id.to_string())
                .or_insert(0) += 1;
            if let Some(record) = inner.conversations.get_mut(conversation_id) {
                record.state = ConversationState::ResetPending {
                    new_group_id: new_group_id_hex.to_string(),
                    reset_generation,
                    notified_at_ms,
                };
                record.needs_rejoin = true;
            }
            if let Some(offset) = inner
                .fail_next_mark_reset_pending_after_commit_with_notified_at_offset
                .take()
            {
                let durable_notified_at_ms = notified_at_ms.saturating_add(offset);
                if let Some(pending) = inner.reset_pending.get_mut(conversation_id) {
                    pending.notified_at_ms = durable_notified_at_ms;
                }
                if let Some(record) = inner.conversations.get_mut(conversation_id) {
                    record.state = ConversationState::ResetPending {
                        new_group_id: new_group_id_hex.to_string(),
                        reset_generation,
                        notified_at_ms: durable_notified_at_ms,
                    };
                }
                return Err(OrchestratorError::Storage(
                    "injected mark_reset_pending response loss after a non-exact durable commit"
                        .to_string(),
                ));
            }
            if inner.fail_next_mark_reset_pending_after_commit {
                inner.fail_next_mark_reset_pending_after_commit = false;
                return Err(OrchestratorError::Storage(
                    "injected mark_reset_pending response loss after commit".to_string(),
                ));
            }
        }

        let barrier = {
            let mut installed = self.reset_record_barrier.lock().unwrap();
            match installed.take() {
                Some((target, barrier)) if target == conversation_id => Some(barrier),
                other => {
                    *installed = other;
                    None
                }
            }
        };
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("reset-record barrier release semaphore closed")
                .forget();
        }
        Ok(())
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        let canonical_hex = |value: &str| {
            !value.is_empty()
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !canonical_hex(expected_old_target) || !canonical_hex(authoritative_new_target) {
            return Err(OrchestratorError::Storage(
                "reset target must be non-empty canonical hex".to_string(),
            ));
        }

        let barrier = {
            let mut installed = self.reset_adopt_barrier.lock().unwrap();
            match installed.take() {
                Some((target, barrier)) if target == conversation_id => Some(barrier),
                other => {
                    *installed = other;
                    None
                }
            }
        };
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("reset-adoption barrier release semaphore closed")
                .forget();
        }

        let mut inner = self.inner.lock().unwrap();
        let matches = inner
            .reset_pending
            .get(conversation_id)
            .is_some_and(|pending| {
                pending.reset_generation == expected_generation
                    && pending.new_group_id_hex == expected_old_target
            });
        if !matches {
            return Ok(false);
        }

        let notified_at_ms = inner
            .reset_pending
            .get(conversation_id)
            .expect("matched reset payload")
            .notified_at_ms;
        inner.reset_pending.insert(
            conversation_id.to_string(),
            PersistedResetPending {
                new_group_id_hex: authoritative_new_target.to_string(),
                reset_generation: expected_generation,
                notified_at_ms,
            },
        );
        if let Some(record) = inner.conversations.get_mut(conversation_id) {
            record.state = ConversationState::ResetPending {
                new_group_id: authoritative_new_target.to_string(),
                reset_generation: expected_generation,
                notified_at_ms,
            };
            record.needs_rejoin = true;
        }
        if inner.fail_next_adopt_reset_pending_after_commit_with_read_failure {
            inner.fail_next_adopt_reset_pending_after_commit_with_read_failure = false;
            inner.fail_next_get_conversation_state = true;
            return Err(OrchestratorError::Storage(
                "injected adoption response loss plus authority reread failure".to_string(),
            ));
        }
        if inner.fail_next_adopt_reset_pending_after_commit {
            inner.fail_next_adopt_reset_pending_after_commit = false;
            return Err(OrchestratorError::Storage(
                "injected adopt_reset_pending_target response loss after commit".to_string(),
            ));
        }
        Ok(true)
    }

    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_mark_quarantined {
            inner.fail_next_mark_quarantined = false;
            return Err(OrchestratorError::Storage(
                "injected mark_quarantined failure".to_string(),
            ));
        }
        inner.quarantines.insert(
            conversation_id.to_string(),
            (reason_tag.to_string(), since_ms),
        );
        Ok(())
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_clear_quarantine {
            inner.fail_next_clear_quarantine = false;
            return Err(OrchestratorError::Storage(
                "injected clear_quarantine failure".to_string(),
            ));
        }
        inner.quarantines.remove(conversation_id);
        Ok(())
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> Result<bool> {
        let cleared = {
            let mut inner = self.inner.lock().unwrap();
            if inner.fail_next_complete_reset_pending {
                inner.fail_next_complete_reset_pending = false;
                return Err(OrchestratorError::Storage(
                    "injected complete_reset_pending failure".to_string(),
                ));
            }
            if let Some(reload) = inner.force_next_complete_reset_pending_false_reload.take() {
                inner.next_conversation_state_override =
                    Some((conversation_id.to_string(), reload));
                false
            } else {
                let cleared = inner.conversations.contains_key(conversation_id)
                    && inner
                        .reset_pending
                        .get(conversation_id)
                        .is_some_and(|pending| {
                            pending.reset_generation == expected_generation
                                && pending.new_group_id_hex == expected_new_group_id_hex
                        });
                if cleared {
                    inner.reset_pending.remove(conversation_id);
                    let record = inner
                        .conversations
                        .get_mut(conversation_id)
                        .expect("conversation presence was part of the completion CAS");
                    record.group_id = expected_new_group_id_hex.to_string();
                    record.view.group_id = expected_new_group_id_hex.to_string();
                    record.view.epoch = landed_epoch;
                    record.join_epoch = Some(landed_epoch);
                    record.state = ConversationState::Active;
                    record.needs_rejoin = false;
                }
                cleared
            }
        };
        let barrier = {
            let mut installed = self.reset_completion_barrier.lock().unwrap();
            match installed.take() {
                Some((target, barrier)) if cleared && target == conversation_id => Some(barrier),
                other => {
                    *installed = other;
                    None
                }
            }
        };
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("reset-completion barrier release semaphore closed")
                .forget();
        }
        Ok(cleared)
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> Result<bool> {
        if !matches!(
            terminal_state,
            ConversationState::Closed | ConversationState::DeviceRemoved
        ) || expected_group_id_hex.len() != 64
            || !expected_group_id_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || terminal_epoch > 9_007_199_254_740_991
            || expected_reset_generation.is_some_and(|g| g <= 0)
        {
            return Err(OrchestratorError::Storage(
                "invalid account exit tuple".into(),
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_set_conversation_state {
            inner.fail_next_set_conversation_state = false;
            return Err(OrchestratorError::Storage(
                "injected account exit projection failure".into(),
            ));
        }
        let Some(record) = inner.conversations.get(conversation_id) else {
            return Ok(false);
        };
        let pending = inner.reset_pending.get(conversation_id);
        let same_terminal = record.state == terminal_state
            && record.group_id == expected_group_id_hex
            && record.view.epoch == terminal_epoch;
        if record.state == ConversationState::Closed && (!same_terminal || pending.is_some()) {
            return Ok(false);
        }
        let allowed = match (expected_reset_generation, pending) {
            (Some(expected), Some(pending)) => {
                expected == pending.reset_generation
                    && pending.new_group_id_hex == expected_group_id_hex
            }
            (Some(expected), None) => {
                same_terminal
                    && inner.account_exit_reset_high_water.get(conversation_id) == Some(&expected)
            }
            (None, None) => {
                !matches!(record.state, ConversationState::ResetPending { .. })
                    && record.group_id == expected_group_id_hex
            }
            (None, Some(_)) => false,
        };
        if !allowed
            || (record.group_id == expected_group_id_hex && record.view.epoch > terminal_epoch)
        {
            return Ok(false);
        }
        if let Some(generation) = expected_reset_generation {
            inner
                .account_exit_reset_high_water
                .insert(conversation_id.into(), generation);
        }
        inner.reset_pending.remove(conversation_id);
        let record = inner.conversations.get_mut(conversation_id).unwrap();
        record.group_id = expected_group_id_hex.into();
        record.view.group_id = expected_group_id_hex.into();
        record.view.epoch = terminal_epoch;
        record.state = terminal_state;
        record.needs_rejoin = false;
        if inner.lose_account_exit_projection_response {
            inner.lose_account_exit_projection_response = false;
            return Err(OrchestratorError::Storage(
                "injected lost account exit CAS response after commit".into(),
            ));
        }
        Ok(true)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner.force_next_clear_reset_pending_for_delete_false {
            inner.force_next_clear_reset_pending_for_delete_false = false;
            return Ok(false);
        }
        let cleared = inner
            .reset_pending
            .get(conversation_id)
            .is_some_and(|pending| pending.reset_generation == expected_generation);
        if cleared {
            inner.reset_pending.remove(conversation_id);
        }
        Ok(cleared)
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .sequencer_mappings
            .insert(conversation_id.to_string(), sequencer_did.to_string());
        *inner
            .set_conversation_sequencer_calls
            .entry(conversation_id.to_string())
            .or_insert(0) += 1;
        Ok(())
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let barrier = {
            let mut installed = self.conversation_state_read_barrier.lock().unwrap();
            match installed.take() {
                Some((target, barrier)) if target == conversation_id => Some(barrier),
                other => {
                    *installed = other;
                    None
                }
            }
        };
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("conversation-state barrier release semaphore closed")
                .forget();
        }

        let mut inner = self.inner.lock().unwrap();
        inner.startup_probe_counts.get_conversation_state += 1;
        if inner
            .next_conversation_state_override
            .as_ref()
            .is_some_and(|(target, _)| target == conversation_id)
        {
            return Ok(inner
                .next_conversation_state_override
                .take()
                .and_then(|(_, state)| state));
        }
        if inner.fail_next_conversation_state_for.as_deref() == Some(conversation_id) {
            inner.fail_next_conversation_state_for = None;
            return Err(OrchestratorError::Storage(
                "malformed persisted reset/quarantine sidecar".to_string(),
            ));
        }
        if inner.fail_next_get_conversation_state {
            inner.fail_next_get_conversation_state = false;
            return Err(OrchestratorError::Storage(
                "malformed persisted reset/quarantine sidecar".to_string(),
            ));
        }
        if let Some((target, remaining)) = inner.fail_conversation_state_after_reads.as_mut() {
            if target == conversation_id {
                if *remaining == 0 {
                    inner.fail_conversation_state_after_reads = None;
                    return Err(OrchestratorError::Storage(
                        "malformed persisted reset/quarantine sidecar".to_string(),
                    ));
                }
                *remaining -= 1;
            }
        }
        if inner
            .malformed_conversation_states
            .contains(conversation_id)
        {
            return Err(OrchestratorError::Storage(format!(
                "malformed persisted security state for {conversation_id}"
            )));
        }
        // Prefer the explicit reset_pending row when present so the rehydrated
        // state carries the payload regardless of whether
        // `set_conversation_state` was also called (matches the iOS/GRDB
        // backend, which reconstructs the enum from per-column data).
        if let Some(payload) = inner.reset_pending.get(conversation_id) {
            return Ok(Some(ConversationState::ResetPending {
                new_group_id: payload.new_group_id_hex.clone(),
                reset_generation: payload.reset_generation,
                notified_at_ms: payload.notified_at_ms,
            }));
        }
        let state = inner
            .conversations
            .get(conversation_id)
            .map(|c| c.state.clone());
        if matches!(state, Some(ConversationState::ResetPending { .. })) {
            return Err(OrchestratorError::Storage(format!(
                "incomplete reset_pending state for {conversation_id}: payload not committed"
            )));
        }
        Ok(state)
    }

    // ── Messages ─────────────────────────────────────────────────────────

    async fn store_message(&self, message: &Message) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_store_message {
            inner.fail_next_store_message = false;
            return Err(OrchestratorError::Storage(
                "injected store_message failure".to_string(),
            ));
        }
        inner
            .messages
            .entry(message.conversation_id.clone())
            .or_default()
            .push(message.clone());
        Ok(())
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        let inner = self.inner.lock().unwrap();
        let Some(msgs) = inner.messages.get(conversation_id) else {
            return Ok(vec![]);
        };

        let mut filtered: Vec<&Message> = msgs
            .iter()
            .filter(|m| {
                before_sequence
                    .map(|seq| m.sequence_number < seq)
                    .unwrap_or(true)
            })
            .collect();

        // Sort descending by sequence_number, then take `limit`, then reverse
        // to return in ascending order (oldest first).
        filtered.sort_by(|a, b| b.sequence_number.cmp(&a.sequence_number));
        filtered.truncate(limit as usize);
        filtered.reverse();

        Ok(filtered.into_iter().cloned().collect())
    }

    async fn message_exists(&self, message_id: &str) -> Result<bool> {
        let inner = self.inner.lock().unwrap();
        let exists = inner
            .messages
            .values()
            .any(|msgs| msgs.iter().any(|m| m.id == message_id));
        Ok(exists)
    }

    // ── Sync Cursors ─────────────────────────────────────────────────────

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .sync_cursors
            .get(user_did)
            .cloned()
            .unwrap_or_default())
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .sync_cursors
            .insert(user_did.to_string(), cursor.clone());
        Ok(())
    }

    // ── Group State ──────────────────────────────────────────────────────

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let barrier = self.group_state_write_barrier.lock().unwrap().take();
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("group-state write barrier release semaphore closed")
                .forget();
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_set_group_state {
            inner.fail_next_set_group_state = false;
            return Err(OrchestratorError::Storage(
                "injected set_group_state failure".to_string(),
            ));
        }
        inner
            .group_states
            .insert(state.group_id.clone(), state.clone());
        Ok(())
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let inner = self.inner.lock().unwrap();
        let state = inner.group_states.get(group_id).cloned().or_else(|| {
            inner
                .group_states
                .values()
                .find(|s| s.conversation_id == group_id || s.group_id == group_id)
                .cloned()
        });
        Ok(state)
    }

    async fn delete_group_state(&self, group_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.group_states.remove(group_id);
        Ok(())
    }

    // -- Pending Messages (self-echo dedup) ────────────────────────────────

    async fn store_pending_message(&self, _conversation_id: &str, message_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.pending_messages.insert(message_id.to_string());
        Ok(())
    }

    async fn remove_pending_message(&self, message_id: &str) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        Ok(inner.pending_messages.remove(message_id))
    }

    // ── Sequencer Receipts (WS-3 equivocation detection) ─────────────────

    async fn store_sequencer_receipt(&self, receipt: &SequencerReceipt) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.sequencer_receipts.push(receipt.clone());
        Ok(())
    }

    async fn get_sequencer_receipts(
        &self,
        convo_id: &str,
        since_epoch: Option<i32>,
    ) -> Result<Vec<SequencerReceipt>> {
        let inner = self.inner.lock().unwrap();
        let matched_gid = inner
            .conversations
            .values()
            .find(|c| c.conversation_id == convo_id)
            .map(|c| c.group_id.clone());
        let matched_cid = inner
            .conversations
            .values()
            .find(|c| c.group_id == convo_id)
            .map(|c| c.conversation_id.clone());
        Ok(inner
            .sequencer_receipts
            .iter()
            .filter(|r| {
                (r.convo_id == convo_id
                    || matched_gid.as_deref() == Some(&r.convo_id)
                    || matched_cid.as_deref() == Some(&r.convo_id))
                    && since_epoch.is_none_or(|e| r.epoch >= e)
            })
            .cloned()
            .collect())
    }

    async fn clear_sequencer_receipts(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let matched_gid = inner
            .conversations
            .values()
            .find(|c| c.conversation_id == conversation_id)
            .map(|c| c.group_id.clone());
        let matched_cid = inner
            .conversations
            .values()
            .find(|c| c.group_id == conversation_id)
            .map(|c| c.conversation_id.clone());
        inner.sequencer_receipts.retain(|r| {
            r.convo_id != conversation_id
                && matched_gid.as_deref() != Some(&r.convo_id)
                && matched_cid.as_deref() != Some(&r.convo_id)
        });
        Ok(())
    }

    async fn cleanup_old_epoch_data(
        &self,
        conversation_id: &str,
        retain_from_epoch: u64,
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .epoch_cleanup_calls
            .push((conversation_id.to_string(), retain_from_epoch));
        Ok(())
    }

    // ── RecoveryTracker persistence (WS-5.4 / E7) ────────────────────────

    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        let mut inner = self.inner.lock().unwrap();
        inner.startup_probe_counts.get_recovery_state += 1;
        if inner.fail_next_get_recovery_state {
            inner.fail_next_get_recovery_state = false;
            return Err(OrchestratorError::Storage(
                "injected recovery state read failure".to_string(),
            ));
        }
        Ok(PersistedRecoveryState {
            entries: inner.recovery_backoff.values().cloned().collect(),
            last_global_rejoin_attempt_at_ms: inner.last_global_rejoin_attempt_at_ms,
        })
    }

    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .recovery_backoff
            .insert(entry.conversation_id.clone(), entry.clone());
        Ok(())
    }

    async fn clear_recovery_backoff(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.recovery_backoff.remove(conversation_id);
        Ok(())
    }

    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_set_last_global_rejoin_attempt_at {
            inner.fail_next_set_last_global_rejoin_attempt_at = false;
            return Err(OrchestratorError::Storage(
                "injected global recovery timestamp failure".to_string(),
            ));
        }
        inner.last_global_rejoin_attempt_at_ms = Some(at_ms);
        Ok(())
    }

    // ── Pending local deletes (WS-5.3) ───────────────────────────────────

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> Result<()> {
        let barrier = {
            let mut configured = self.pending_local_delete_write_barrier.lock().unwrap();
            if configured
                .as_ref()
                .is_some_and(|(target, _, _)| target.is_empty() || target == conversation_id)
            {
                configured.take()
            } else {
                None
            }
        };
        if let Some((_, false, barrier)) = barrier.as_ref() {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("pending-delete pre-write barrier release semaphore closed")
                .forget();
        }
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.fail_next_mark_pending_local_delete {
                inner.fail_next_mark_pending_local_delete = false;
                return Err(OrchestratorError::Storage(
                    "injected mark_pending_local_delete failure".to_string(),
                ));
            }
            inner.pending_local_deletes.insert(
                conversation_id.to_string(),
                PendingLocalDelete {
                    conversation_id: conversation_id.to_string(),
                    group_id_hex: group_id_hex.map(|g| g.to_string()),
                },
            );
        }
        if let Some((_, true, barrier)) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire()
                .await
                .expect("pending-delete post-write barrier release semaphore closed")
                .forget();
        }
        Ok(())
    }

    async fn clear_pending_local_delete(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .fail_clear_pending_local_delete_for
            .as_deref()
            .is_some_and(|target| target == conversation_id)
        {
            inner.fail_clear_pending_local_delete_for = None;
            return Err(OrchestratorError::Storage(
                "injected clear_pending_local_delete failure".to_string(),
            ));
        }
        inner.pending_local_deletes.remove(conversation_id);
        Ok(())
    }

    async fn list_pending_local_deletes(&self) -> Result<Vec<PendingLocalDelete>> {
        let mut inner = self.inner.lock().unwrap();
        inner.startup_probe_counts.list_pending_local_deletes += 1;
        Ok(inner.pending_local_deletes.values().cloned().collect())
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        const WITHOUT_PENDING_DELETE: &[&str] = &[
            "get_conversation_state",
            "get_welcome_reissue_attempt_log",
            "record_welcome_reissue_attempt",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
            "set_conversation_sequencer",
            "mark_quarantined",
            "clear_quarantine",
            "store_pending_message",
            "remove_pending_message",
            "store_sequencer_receipt",
            "get_sequencer_receipts",
            "clear_sequencer_receipts",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
        ];
        const ALL: &[&str] = &[
            "get_conversation_state",
            "get_welcome_reissue_attempt_log",
            "record_welcome_reissue_attempt",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
            "set_conversation_sequencer",
            "mark_quarantined",
            "clear_quarantine",
            "store_pending_message",
            "remove_pending_message",
            "store_sequencer_receipt",
            "get_sequencer_receipts",
            "clear_sequencer_receipts",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
            "mark_pending_local_delete",
            "clear_pending_local_delete",
            "list_pending_local_deletes",
        ];
        if self
            .declare_pending_delete_capabilities
            .load(std::sync::atomic::Ordering::Acquire)
        {
            ALL
        } else {
            WITHOUT_PENDING_DELETE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_message(conv_id: &str, id: &str, seq: u64) -> Message {
        Message {
            id: id.to_string(),
            conversation_id: conv_id.to_string(),
            sender_did: "did:plc:test".to_string(),
            text: format!("msg-{}", seq),
            timestamp: Utc::now(),
            epoch: 1,
            sequence_number: seq,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        }
    }

    #[tokio::test]
    async fn ensure_conversation_is_idempotent() {
        let storage = MockStorage::new();
        storage
            .ensure_conversation_exists("did:plc:alice", "conv1", "group1")
            .await
            .unwrap();
        storage
            .ensure_conversation_exists("did:plc:alice", "conv1", "group1")
            .await
            .unwrap();
        assert_eq!(storage.conversation_count(), 1);
    }

    #[tokio::test]
    async fn store_and_retrieve_messages() {
        let storage = MockStorage::new();
        storage
            .ensure_conversation_exists("did:plc:alice", "conv1", "group1")
            .await
            .unwrap();

        for i in 1..=5 {
            storage
                .store_message(&make_message("conv1", &format!("m{}", i), i))
                .await
                .unwrap();
        }

        let all = storage.get_messages("conv1", 10, None).await.unwrap();
        assert_eq!(all.len(), 5);

        // Pagination: before_sequence=4 should return seq 1,2,3
        let page = storage.get_messages("conv1", 10, Some(4)).await.unwrap();
        assert_eq!(page.len(), 3);

        // Limit
        let limited = storage.get_messages("conv1", 2, None).await.unwrap();
        assert_eq!(limited.len(), 2);
        // Should return the last 2 (seq 4 and 5)
        assert_eq!(limited[0].sequence_number, 4);
        assert_eq!(limited[1].sequence_number, 5);
    }

    #[tokio::test]
    async fn message_exists_check() {
        let storage = MockStorage::new();
        storage
            .store_message(&make_message("conv1", "unique-id", 1))
            .await
            .unwrap();
        assert!(storage.message_exists("unique-id").await.unwrap());
        assert!(!storage.message_exists("missing-id").await.unwrap());
    }

    #[tokio::test]
    async fn rejoin_flag_lifecycle() {
        let storage = MockStorage::new();
        storage
            .ensure_conversation_exists("did:plc:alice", "conv1", "group1")
            .await
            .unwrap();

        assert!(!storage.has_rejoin_flag("conv1"));
        storage.mark_needs_rejoin("conv1").await.unwrap();
        assert!(storage.has_rejoin_flag("conv1"));
        storage.clear_rejoin_flag("conv1").await.unwrap();
        assert!(!storage.has_rejoin_flag("conv1"));
    }

    #[tokio::test]
    async fn state_transitions_tracked() {
        let storage = MockStorage::new();
        storage
            .ensure_conversation_exists("did:plc:alice", "conv1", "group1")
            .await
            .unwrap();
        storage
            .set_conversation_state("conv1", ConversationState::Active)
            .await
            .unwrap();
        storage
            .set_conversation_state("conv1", ConversationState::NeedsRejoin)
            .await
            .unwrap();

        let transitions = storage.get_state_transitions("conv1");
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].from, Some(ConversationState::Initializing));
        assert_eq!(transitions[0].to, ConversationState::Active);
        assert_eq!(transitions[1].from, Some(ConversationState::Active));
        assert_eq!(transitions[1].to, ConversationState::NeedsRejoin);
    }
}
