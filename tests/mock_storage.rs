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
    /// platform storage's `mark_reset_pending`/`clear_reset_pending` columns).
    reset_pending: HashMap<String, PersistedResetPending>,
    /// Number of times `mark_reset_pending` has been called per conversation.
    /// Used by idempotency tests to assert duplicate calls collapse.
    mark_reset_pending_calls: HashMap<String, u32>,
    /// conversation_id -> Welcome reissue attempts.
    welcome_reissue_attempts: HashMap<String, Vec<ReissueAttempt>>,
    /// conversation_id -> persisted rejoin-backoff entry (WS-5.4 / E7).
    recovery_backoff: HashMap<String, PersistedRecoveryBackoff>,
    /// Persisted global last-rejoin-attempt timestamp (epoch ms).
    last_global_rejoin_attempt_at_ms: Option<i64>,
    /// conversation_id -> pending local-delete intent (WS-5.3).
    pending_local_deletes: HashMap<String, PendingLocalDelete>,
    /// When set, the next `clear_rejoin_flag` call fails once (WS-5 FIX-1
    /// escalation tests). Mirrors the `fail_next_*` pattern in
    /// `mock_api_client.rs`.
    fail_next_clear_rejoin_flag: bool,
    /// When set, the next `delete_conversations` call fails once (WS-5 FIX-5
    /// keep-intent-on-failure tests).
    fail_next_delete_conversations: bool,
    /// conversation_id -> persisted quarantine payload `(reason_tag,
    /// since_ms)` (Layer 3; mirrors the platform `mark_quarantined` /
    /// `clear_quarantine` columns).
    quarantines: HashMap<String, (String, i64)>,
    /// One-shot failure injections for the quarantine persist escalation
    /// tests (E7 follow-up R-2).
    fail_next_set_conversation_state: bool,
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
}

/// An in-memory mock of `MLSStorageBackend` suitable for unit and integration tests.
///
/// All state is stored behind `Arc<Mutex<...>>` so the mock can be cloned
/// and shared across tasks while still allowing test assertions on the
/// accumulated state.
#[derive(Debug, Clone)]
pub struct MockStorage {
    inner: Arc<Mutex<Inner>>,
}

impl MockStorage {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    // ── Test helper methods ──────────────────────────────────────────────

    /// Returns the total number of stored conversations.
    #[allow(dead_code)]
    pub fn conversation_count(&self) -> usize {
        self.inner.lock().unwrap().conversations.len()
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

    /// Make the next `set_conversation_state` call fail once (R-2
    /// quarantine-persist escalation tests).
    #[allow(dead_code)]
    pub fn fail_next_set_conversation_state(&self) {
        self.inner.lock().unwrap().fail_next_set_conversation_state = true;
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
        inner
            .conversations
            .entry(conversation_id.to_string())
            .or_insert_with(|| ConversationRecord {
                conversation_id: conversation_id.to_string(),
                user_did: user_did.to_string(),
                group_id: group_id.to_string(),
                state: ConversationState::Initializing,
                needs_rejoin: false,
                join_method: None,
                join_epoch: None,
                view: ConversationView {
                    group_id: group_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    epoch: 0,
                    members: vec![],
                    metadata: None,
                    created_at: Some(chrono::Utc::now()),
                    updated_at: Some(chrono::Utc::now()),
                    sequencer_did: None,
                },
            });
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
        _user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .conversations
            .get(conversation_id)
            .map(|c| c.view.clone()))
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let inner = self.inner.lock().unwrap();
        let views = inner
            .conversations
            .values()
            .filter(|c| c.user_did == user_did)
            .map(|c| c.view.clone())
            .collect();
        Ok(views)
    }

    async fn delete_conversations(&self, _user_did: &str, ids: &[&str]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_next_delete_conversations {
            inner.fail_next_delete_conversations = false;
            return Err(OrchestratorError::Storage(
                "injected delete_conversations failure".to_string(),
            ));
        }
        for id in ids {
            inner.conversations.remove(*id);
            inner.messages.remove(*id);
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
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
            record.state = state.clone();
        }

        inner
            .state_transitions
            .entry(conversation_id.to_string())
            .or_default()
            .push(StateTransition {
                from: prev,
                to: state,
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
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .conversations
            .get(conversation_id)
            .map(|c| c.needs_rejoin)
            .unwrap_or(false))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
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
        let mut inner = self.inner.lock().unwrap();
        inner.reset_pending.insert(
            conversation_id.to_string(),
            PersistedResetPending {
                new_group_id_hex: new_group_id_hex.to_string(),
                reset_generation,
                notified_at_ms,
            },
        );
        *inner
            .mark_reset_pending_calls
            .entry(conversation_id.to_string())
            .or_insert(0) += 1;
        Ok(())
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

    async fn clear_reset_pending(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.reset_pending.remove(conversation_id);
        Ok(())
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
        let inner = self.inner.lock().unwrap();
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
        Ok(inner
            .conversations
            .get(conversation_id)
            .map(|c| c.state.clone()))
    }

    // ── Messages ─────────────────────────────────────────────────────────

    async fn store_message(&self, message: &Message) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
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
        let mut inner = self.inner.lock().unwrap();
        inner
            .group_states
            .insert(state.group_id.clone(), state.clone());
        Ok(())
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.group_states.get(group_id).cloned())
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
        Ok(inner
            .sequencer_receipts
            .iter()
            .filter(|r| r.convo_id == convo_id && since_epoch.is_none_or(|e| r.epoch >= e))
            .cloned()
            .collect())
    }

    async fn clear_sequencer_receipts(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .sequencer_receipts
            .retain(|r| r.convo_id != conversation_id);
        Ok(())
    }

    // ── RecoveryTracker persistence (WS-5.4 / E7) ────────────────────────

    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        let inner = self.inner.lock().unwrap();
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
        inner.last_global_rejoin_attempt_at_ms = Some(at_ms);
        Ok(())
    }

    // ── Pending local deletes (WS-5.3) ───────────────────────────────────

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.pending_local_deletes.insert(
            conversation_id.to_string(),
            PendingLocalDelete {
                conversation_id: conversation_id.to_string(),
                group_id_hex: group_id_hex.map(|g| g.to_string()),
            },
        );
        Ok(())
    }

    async fn clear_pending_local_delete(&self, conversation_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.pending_local_deletes.remove(conversation_id);
        Ok(())
    }

    async fn list_pending_local_deletes(&self) -> Result<Vec<PendingLocalDelete>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.pending_local_deletes.values().cloned().collect())
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "get_welcome_reissue_attempt_log",
            "record_welcome_reissue_attempt",
            "mark_reset_pending",
            "clear_reset_pending",
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
        ]
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
