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

    /// Mark a conversation as needing rejoin.
    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()>;

    /// Check if a conversation needs rejoin.
    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool>;

    /// Clear the rejoin flag for a conversation.
    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()>;

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
}
