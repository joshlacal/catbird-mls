//! High-level facade contract for easy-mode client APIs.
//!
//! The intent is to keep the lifecycle stable across Rust, UniFFI, and WASM layers
//! while hiding MLS state-machine details behind simple operations.

use std::sync::Arc;

/// Bootstrap/init operation for creating a ready-to-use client facade.
#[derive(Debug, Clone)]
pub struct BootstrapInitRequest {
    pub user_did: String,
}

/// Create a new conversation with optional metadata and initial participants.
#[derive(Debug, Clone)]
pub struct CreateConversationRequest {
    pub name: Option<String>,
    pub participant_dids: Vec<String>,
}

/// Participant membership operation for an existing conversation.
#[derive(Debug, Clone)]
pub enum ParticipantDelta {
    Add { participant_dids: Vec<String> },
    Remove { participant_dids: Vec<String> },
}

/// Conversation membership request (add/remove participants).
#[derive(Debug, Clone)]
pub struct ConversationParticipantsRequest {
    pub conversation_id: String,
    pub delta: ParticipantDelta,
}

/// Leave an existing conversation.
#[derive(Debug, Clone)]
pub struct LeaveConversationRequest {
    pub conversation_id: String,
}

/// Send a text message to a conversation.
#[derive(Debug, Clone)]
pub struct SendMessageRequest {
    pub conversation_id: String,
    pub text: String,
}

/// List historical messages in a conversation.
#[derive(Debug, Clone)]
pub struct MessageHistoryRequest {
    pub conversation_id: String,
    pub limit: Option<i32>,
    pub before_sequence: Option<u64>,
}

/// Fetch and decrypt new messages from the server.
#[derive(Debug, Clone)]
pub struct FetchMessagesRequest {
    pub conversation_id: String,
    pub cursor: Option<String>,
    pub limit: u32,
}

/// Update the read cursor for a conversation.
#[derive(Debug, Clone)]
pub struct UpdateCursorRequest {
    pub conversation_id: String,
    pub cursor: String,
}

/// Synchronize client state with remote server state.
#[derive(Debug, Clone, Copy)]
pub struct SyncRequest {
    pub full_sync: bool,
}

/// Recover a conversation that needs rejoin/rebuild.
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub conversation_id: String,
}

/// Explicit shutdown operation for releasing resources.
#[derive(Debug, Clone, Default)]
pub struct ShutdownRequest;

/// Lifecycle contract: bootstrap/init.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HighLevelBootstrapContract<S, A, C, P>: Sized {
    type Error;
    type Config;

    async fn bootstrap_init(
        request: BootstrapInitRequest,
        mls_context: Arc<P>,
        storage: Arc<S>,
        api_client: Arc<A>,
        credentials: Arc<C>,
        config: Self::Config,
    ) -> Result<Self, Self::Error>;
}

/// Conversation management contract.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HighLevelConversationContract {
    type Conversation;
    type Error;

    async fn list_conversations(&self) -> Result<Vec<Self::Conversation>, Self::Error>;
    async fn create_conversation(
        &self,
        request: CreateConversationRequest,
    ) -> Result<Self::Conversation, Self::Error>;
    async fn update_participants(
        &self,
        request: ConversationParticipantsRequest,
    ) -> Result<(), Self::Error>;
    async fn leave_conversation(
        &self,
        request: LeaveConversationRequest,
    ) -> Result<(), Self::Error>;
}

/// Messaging contract.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HighLevelMessagingContract {
    type Message;
    type Error;

    async fn send_message(&self, request: SendMessageRequest)
        -> Result<Self::Message, Self::Error>;
    async fn list_messages(
        &self,
        request: MessageHistoryRequest,
    ) -> Result<Vec<Self::Message>, Self::Error>;
    async fn fetch_new_messages(
        &self,
        request: FetchMessagesRequest,
    ) -> Result<Vec<Self::Message>, Self::Error>;
    async fn update_cursor(&self, request: UpdateCursorRequest) -> Result<(), Self::Error>;
}

/// Sync and recovery contract.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HighLevelSyncRecoveryContract {
    type Error;

    async fn sync(&self, request: SyncRequest) -> Result<(), Self::Error>;
    async fn recover_conversation(&self, request: RecoveryRequest) -> Result<(), Self::Error>;
}

/// Shutdown contract.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HighLevelShutdownContract {
    async fn shutdown(&self, request: ShutdownRequest);
}
