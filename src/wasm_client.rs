//! WASM-facing high-level facade aligned with the easy-mode contract.
//!
//! This mirrors the native `CatbirdClient` surface while keeping the implementation
//! free of native-only UniFFI/rusqlite assumptions.

use std::sync::Arc;

use crate::high_level_contract::{
    BootstrapInitRequest, ConversationParticipantsRequest, CreateConversationRequest,
    FetchMessagesRequest, HighLevelBootstrapContract, HighLevelConversationContract,
    HighLevelMessagingContract, HighLevelShutdownContract, HighLevelSyncRecoveryContract,
    LeaveConversationRequest, UpdateCursorRequest, MessageHistoryRequest, ParticipantDelta,
    RecoveryRequest, SendMessageRequest, ShutdownRequest, SyncRequest,
};
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::crypto_provider::MlsCryptoContext;
use crate::orchestrator::error::OrchestratorError;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::types::{ConversationView, MemberRole, Message};
use crate::orchestrator::{MLSOrchestrator, OrchestratorConfig};

/// A chat conversation view for easy-mode WASM hosts.
#[derive(Debug, Clone)]
pub struct WasmConversation {
    pub id: String,
    pub name: Option<String>,
    pub participants: Vec<WasmParticipant>,
    pub last_message: Option<WasmChatMessage>,
    pub unread_count: i32,
    pub created_at: Option<String>,
}

/// A participant in a conversation.
#[derive(Debug, Clone)]
pub struct WasmParticipant {
    pub did: String,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    /// "member" or "admin"
    pub role: String,
}

/// A message suitable for rendering in a chat UI.
#[derive(Debug, Clone)]
pub struct WasmChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub content: String,
    pub timestamp: String,
    pub is_own: bool,
}

fn convo_view_to_wasm_conversation(cv: &ConversationView) -> WasmConversation {
    WasmConversation {
        id: cv.group_id.clone(),
        name: cv.metadata.as_ref().and_then(|m| m.name.clone()),
        participants: cv
            .members
            .iter()
            .map(|m| WasmParticipant {
                did: m.did.clone(),
                handle: None,
                display_name: None,
                role: match m.role {
                    MemberRole::Admin => "admin".to_string(),
                    MemberRole::Member => "member".to_string(),
                },
            })
            .collect(),
        last_message: None,
        unread_count: 0,
        created_at: cv.created_at.map(|t| t.to_rfc3339()),
    }
}

fn message_to_wasm_chat_message(msg: &Message) -> WasmChatMessage {
    WasmChatMessage {
        id: msg.id.clone(),
        conversation_id: msg.conversation_id.clone(),
        sender_did: msg.sender_did.clone(),
        content: msg.text.clone(),
        timestamp: msg.timestamp.to_rfc3339(),
        is_own: msg.is_own,
    }
}

#[cfg(test)]
pub(crate) fn conversation_from_view_for_tests(cv: &ConversationView) -> WasmConversation {
    convo_view_to_wasm_conversation(cv)
}

#[cfg(test)]
pub(crate) fn message_from_view_for_tests(msg: &Message) -> WasmChatMessage {
    message_to_wasm_chat_message(msg)
}

/// High-level client facade for WASM hosts.
pub struct WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    orchestrator: Arc<MLSOrchestrator<S, A, C, P>>,
    user_did: String,
}

impl<S, A, C, P> WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    pub fn new(user_did: String, orchestrator: Arc<MLSOrchestrator<S, A, C, P>>) -> Self {
        Self {
            orchestrator,
            user_did,
        }
    }

    /// Contract-aligned bootstrap/init entrypoint.
    pub async fn bootstrap_init(
        request: BootstrapInitRequest,
        mls_context: Arc<P>,
        storage: Arc<S>,
        api_client: Arc<A>,
        credentials: Arc<C>,
        config: OrchestratorConfig,
    ) -> Result<Self, OrchestratorError> {
        let user_did = request.user_did;
        let orchestrator = Arc::new(MLSOrchestrator::new(
            mls_context,
            storage,
            api_client,
            credentials,
            config,
        ));

        orchestrator.initialize(&user_did).await?;
        orchestrator.ensure_device_registered().await?;
        orchestrator.replenish_if_needed().await?;

        Ok(Self {
            orchestrator,
            user_did,
        })
    }

    pub async fn conversations(&self) -> Result<Vec<WasmConversation>, OrchestratorError> {
        let convos = self
            .orchestrator
            .storage()
            .list_conversations(&self.user_did)
            .await?;
        Ok(convos.iter().map(convo_view_to_wasm_conversation).collect())
    }

    pub async fn create_conversation(
        &self,
        name: Option<String>,
        participant_dids: Vec<String>,
    ) -> Result<WasmConversation, OrchestratorError> {
        let convo = self
            .orchestrator
            .create_group(name.as_deref().unwrap_or(""), Some(&participant_dids), None)
            .await?;
        Ok(convo_view_to_wasm_conversation(&convo))
    }

    pub async fn send_message(
        &self,
        conversation_id: &str,
        text: &str,
    ) -> Result<WasmChatMessage, OrchestratorError> {
        let msg = self
            .orchestrator
            .send_message(conversation_id, text)
            .await?;
        Ok(message_to_wasm_chat_message(&msg))
    }

    pub async fn messages(
        &self,
        conversation_id: &str,
        limit: Option<i32>,
        before_sequence: Option<u64>,
    ) -> Result<Vec<WasmChatMessage>, OrchestratorError> {
        let limit = limit.unwrap_or(50) as u32;
        let messages = self
            .orchestrator
            .storage()
            .get_messages(conversation_id, limit, before_sequence)
            .await?;
        Ok(messages.iter().map(message_to_wasm_chat_message).collect())
    }

    pub async fn fetch_new_messages(
        &self,
        conversation_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WasmChatMessage>, OrchestratorError> {
        let (messages, _cursor) = self
            .orchestrator
            .fetch_messages(conversation_id, cursor, limit, None)
            .await?;
        Ok(messages.iter().map(message_to_wasm_chat_message).collect())
    }

    pub async fn add_participants(
        &self,
        conversation_id: &str,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator
            .add_members(conversation_id, &participant_dids)
            .await
    }

    pub async fn remove_participants(
        &self,
        conversation_id: &str,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator
            .remove_members(conversation_id, &participant_dids)
            .await
    }

    pub async fn leave_conversation(&self, conversation_id: &str) -> Result<(), OrchestratorError> {
        self.orchestrator.leave_group(conversation_id).await
    }

    pub async fn sync(&self, full_sync: bool) -> Result<(), OrchestratorError> {
        self.orchestrator.sync_with_server(full_sync).await
    }

    pub async fn rejoin_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator.force_rejoin(conversation_id).await
    }

    /// Update the read cursor for a conversation.
    pub async fn update_cursor(
        &self,
        _conversation_id: &str,
        _cursor: &str,
    ) -> Result<(), OrchestratorError> {
        // TODO: Delegate to orchestrator cursor update when read receipts are implemented
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.orchestrator.shutdown().await;
    }

    pub fn user_did(&self) -> &str {
        &self.user_did
    }

    pub fn orchestrator(&self) -> &Arc<MLSOrchestrator<S, A, C, P>> {
        &self.orchestrator
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<S, A, C, P> HighLevelBootstrapContract<S, A, C, P> for WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    type Error = OrchestratorError;
    type Config = OrchestratorConfig;

    async fn bootstrap_init(
        request: BootstrapInitRequest,
        mls_context: Arc<P>,
        storage: Arc<S>,
        api_client: Arc<A>,
        credentials: Arc<C>,
        config: Self::Config,
    ) -> Result<Self, Self::Error> {
        WasmCatbirdClient::bootstrap_init(
            request,
            mls_context,
            storage,
            api_client,
            credentials,
            config,
        )
        .await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<S, A, C, P> HighLevelConversationContract for WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    type Conversation = WasmConversation;
    type Error = OrchestratorError;

    async fn list_conversations(&self) -> Result<Vec<Self::Conversation>, Self::Error> {
        WasmCatbirdClient::conversations(self).await
    }

    async fn create_conversation(
        &self,
        request: CreateConversationRequest,
    ) -> Result<Self::Conversation, Self::Error> {
        WasmCatbirdClient::create_conversation(self, request.name, request.participant_dids).await
    }

    async fn update_participants(
        &self,
        request: ConversationParticipantsRequest,
    ) -> Result<(), Self::Error> {
        match request.delta {
            ParticipantDelta::Add { participant_dids } => {
                WasmCatbirdClient::add_participants(
                    self,
                    &request.conversation_id,
                    participant_dids,
                )
                .await
            }
            ParticipantDelta::Remove { participant_dids } => {
                WasmCatbirdClient::remove_participants(
                    self,
                    &request.conversation_id,
                    participant_dids,
                )
                .await
            }
        }
    }

    async fn leave_conversation(
        &self,
        request: LeaveConversationRequest,
    ) -> Result<(), Self::Error> {
        WasmCatbirdClient::leave_conversation(self, &request.conversation_id).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<S, A, C, P> HighLevelMessagingContract for WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    type Message = WasmChatMessage;
    type Error = OrchestratorError;

    async fn send_message(
        &self,
        request: SendMessageRequest,
    ) -> Result<Self::Message, Self::Error> {
        WasmCatbirdClient::send_message(self, &request.conversation_id, &request.text).await
    }

    async fn list_messages(
        &self,
        request: MessageHistoryRequest,
    ) -> Result<Vec<Self::Message>, Self::Error> {
        WasmCatbirdClient::messages(
            self,
            &request.conversation_id,
            request.limit,
            request.before_sequence,
        )
        .await
    }

    async fn fetch_new_messages(
        &self,
        request: FetchMessagesRequest,
    ) -> Result<Vec<Self::Message>, Self::Error> {
        WasmCatbirdClient::fetch_new_messages(
            self,
            &request.conversation_id,
            request.cursor.as_deref(),
            request.limit,
        )
        .await
    }

    async fn update_cursor(&self, request: UpdateCursorRequest) -> Result<(), Self::Error> {
        WasmCatbirdClient::update_cursor(self, &request.conversation_id, &request.cursor).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<S, A, C, P> HighLevelSyncRecoveryContract for WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    type Error = OrchestratorError;

    async fn sync(&self, request: SyncRequest) -> Result<(), Self::Error> {
        WasmCatbirdClient::sync(self, request.full_sync).await
    }

    async fn recover_conversation(&self, request: RecoveryRequest) -> Result<(), Self::Error> {
        WasmCatbirdClient::rejoin_conversation(self, &request.conversation_id).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<S, A, C, P> HighLevelShutdownContract for WasmCatbirdClient<S, A, C, P>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    P: MlsCryptoContext + 'static,
{
    async fn shutdown(&self, _request: ShutdownRequest) {
        WasmCatbirdClient::shutdown(self).await;
    }
}
