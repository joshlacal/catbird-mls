//! In-memory mock implementation of `MLSStorageBackend` for testing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use catbird_mls::orchestrator::{
    ConversationState, ConversationView, GroupState, JoinMethod, MLSStorageBackend, Message,
    OrchestratorError, Result, SyncCursor,
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
        if let Some(record) = inner.conversations.get_mut(conversation_id) {
            record.needs_rejoin = false;
        }
        Ok(())
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
