// CatbirdClient — high-level, MLS-free chat API
//
// Wraps the MLSOrchestrator to provide a simple conversations + messages interface.
// No MLS concepts (epochs, key packages, commits, etc.) are exposed.

use std::sync::Arc;
use tokio::sync::broadcast;

use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::error::OrchestratorError;
use crate::orchestrator::orchestrator::MLSOrchestrator;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::types::{ConversationView, MemberRole, Message};
use crate::orchestrator::MlsCryptoContext;

// ═══════════════════════════════════════════════════════════════════════════
// Public types — NO MLS concepts exposed
// ═══════════════════════════════════════════════════════════════════════════

/// A chat conversation, hiding all MLS group internals.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Conversation {
    pub id: String,
    pub name: Option<String>,
    pub participants: Vec<Participant>,
    pub last_message: Option<ChatMessage>,
    pub unread_count: i32,
    pub created_at: Option<String>,
}

/// A participant in a conversation.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Participant {
    pub did: String,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    /// "member", "admin", or "moderator"
    pub role: String,
}

/// A chat message with sender info and timestamps.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub content: String,
    pub timestamp: String,
    pub is_own: bool,
}

/// Events emitted by the chat system for reactive UIs.
#[derive(Debug, Clone)]
pub enum ChatEvent {
    MessageReceived {
        message: ChatMessage,
    },
    MessageSent {
        message: ChatMessage,
    },
    ParticipantJoined {
        conversation_id: String,
        participant: Participant,
    },
    ParticipantLeft {
        conversation_id: String,
        did: String,
    },
    ConversationUpdated {
        conversation: Conversation,
    },
    TypingStarted {
        conversation_id: String,
        did: String,
    },
    TypingStopped {
        conversation_id: String,
        did: String,
    },
    SyncCompleted,
    ConnectionChanged {
        connected: bool,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// Conversion helpers — map orchestrator types to client types
// ═══════════════════════════════════════════════════════════════════════════

fn convo_view_to_conversation(cv: &ConversationView) -> Conversation {
    Conversation {
        id: cv.group_id.clone(),
        name: cv.metadata.as_ref().and_then(|m| m.name.clone()),
        participants: cv
            .members
            .iter()
            .map(|m| Participant {
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

fn message_to_chat_message(msg: &Message) -> ChatMessage {
    ChatMessage {
        id: msg.id.clone(),
        conversation_id: msg.conversation_id.clone(),
        sender_did: msg.sender_did.clone(),
        content: msg.text.clone(),
        timestamp: msg.timestamp.to_rfc3339(),
        is_own: msg.is_own,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CatbirdClient — the simple, MLS-free API for chat
// ═══════════════════════════════════════════════════════════════════════════

/// CatbirdClient wraps the MLSOrchestrator to provide conversations, messages,
/// and events without exposing any MLS concepts (epochs, key packages, commits, etc.).
pub struct CatbirdClient<S, A, C, M>
where
    S: MLSStorageBackend + Send + Sync + 'static,
    A: MLSAPIClient + Send + Sync + 'static,
    C: CredentialStore + Send + Sync + 'static,
    M: MlsCryptoContext + 'static,
{
    orchestrator: Arc<MLSOrchestrator<S, A, C, M>>,
    event_tx: broadcast::Sender<ChatEvent>,
    user_did: String,
}

impl<S, A, C, M> CatbirdClient<S, A, C, M>
where
    S: MLSStorageBackend + Send + Sync + 'static,
    A: MLSAPIClient + Send + Sync + 'static,
    C: CredentialStore + Send + Sync + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Create a new CatbirdClient wrapping an already-constructed orchestrator.
    ///
    /// The orchestrator should already be initialized for `user_did`.
    pub fn new(user_did: String, orchestrator: Arc<MLSOrchestrator<S, A, C, M>>) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            orchestrator,
            event_tx,
            user_did,
        }
    }
}

/// Native-only factory that constructs a CatbirdClient with the concrete MLSContext.
#[cfg(not(target_arch = "wasm32"))]
impl<S, A, C> CatbirdClient<S, A, C, crate::api::MLSContext>
where
    S: MLSStorageBackend + Send + Sync + 'static,
    A: MLSAPIClient + Send + Sync + 'static,
    C: CredentialStore + Send + Sync + 'static,
{
    /// Create and initialize a new CatbirdClient from raw components.
    ///
    /// Internally: creates orchestrator, initializes for the user, registers device,
    /// and ensures key packages are available.
    pub async fn create(
        user_did: String,
        mls_context: Arc<crate::api::MLSContext>,
        storage: Arc<S>,
        api_client: Arc<A>,
        credentials: Arc<C>,
        config: crate::orchestrator::OrchestratorConfig,
    ) -> Result<Self, OrchestratorError> {
        let orchestrator = Arc::new(MLSOrchestrator::new(
            mls_context,
            storage,
            api_client,
            credentials,
            config,
        ));

        // Initialize for this user
        orchestrator.initialize(&user_did).await?;

        // Register device and ensure key packages
        orchestrator.ensure_device_registered().await?;
        orchestrator.replenish_if_needed().await?;

        let (event_tx, _) = broadcast::channel(256);
        Ok(Self {
            orchestrator,
            event_tx,
            user_did,
        })
    }
}

impl<S, A, C, M> CatbirdClient<S, A, C, M>
where
    S: MLSStorageBackend + Send + Sync + 'static,
    A: MLSAPIClient + Send + Sync + 'static,
    C: CredentialStore + Send + Sync + 'static,
    M: MlsCryptoContext + 'static,
{
    /// List all conversations for the current user.
    pub async fn conversations(&self) -> Result<Vec<Conversation>, OrchestratorError> {
        let convos = self
            .orchestrator
            .storage()
            .list_conversations(&self.user_did)
            .await?;
        Ok(convos.iter().map(convo_view_to_conversation).collect())
    }

    /// Create a new conversation with the given participants.
    pub async fn create_conversation(
        &self,
        name: Option<String>,
        participant_dids: Vec<String>,
    ) -> Result<Conversation, OrchestratorError> {
        let convo = self
            .orchestrator
            .create_group(name.as_deref().unwrap_or(""), Some(&participant_dids), None)
            .await?;

        let conversation = convo_view_to_conversation(&convo);

        let _ = self.event_tx.send(ChatEvent::ConversationUpdated {
            conversation: conversation.clone(),
        });

        Ok(conversation)
    }

    /// Send a text message to a conversation.
    pub async fn send_message(
        &self,
        conversation_id: &str,
        text: &str,
    ) -> Result<ChatMessage, OrchestratorError> {
        let msg = self
            .orchestrator
            .send_message(conversation_id, text)
            .await?;

        let chat_message = message_to_chat_message(&msg);

        let _ = self.event_tx.send(ChatEvent::MessageSent {
            message: chat_message.clone(),
        });

        Ok(chat_message)
    }

    /// Get message history for a conversation.
    pub async fn messages(
        &self,
        conversation_id: &str,
        limit: Option<i32>,
        before_sequence: Option<u64>,
    ) -> Result<Vec<ChatMessage>, OrchestratorError> {
        let limit = limit.unwrap_or(50) as u32;
        let messages = self
            .orchestrator
            .storage()
            .get_messages(conversation_id, limit, before_sequence)
            .await?;
        Ok(messages.iter().map(message_to_chat_message).collect())
    }

    /// Add participants to an existing conversation.
    pub async fn add_participants(
        &self,
        conversation_id: &str,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator
            .add_members(conversation_id, &participant_dids)
            .await?;

        for did in &participant_dids {
            let _ = self.event_tx.send(ChatEvent::ParticipantJoined {
                conversation_id: conversation_id.to_string(),
                participant: Participant {
                    did: did.clone(),
                    handle: None,
                    display_name: None,
                    role: "member".to_string(),
                },
            });
        }

        Ok(())
    }

    /// Remove participants from an existing conversation.
    pub async fn remove_participants(
        &self,
        conversation_id: &str,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator
            .remove_members(conversation_id, &participant_dids)
            .await?;

        for did in &participant_dids {
            let _ = self.event_tx.send(ChatEvent::ParticipantLeft {
                conversation_id: conversation_id.to_string(),
                did: did.clone(),
            });
        }

        Ok(())
    }

    /// Atomically swap participants in a single commit.
    pub async fn swap_participants(
        &self,
        conversation_id: &str,
        remove_dids: Vec<String>,
        add_dids: Vec<String>,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator
            .swap_members(conversation_id, &remove_dids, &add_dids)
            .await?;
        for did in &remove_dids {
            let _ = self.event_tx.send(ChatEvent::ParticipantLeft {
                conversation_id: conversation_id.to_string(),
                did: did.clone(),
            });
        }
        for did in &add_dids {
            let _ = self.event_tx.send(ChatEvent::ParticipantJoined {
                conversation_id: conversation_id.to_string(),
                participant: Participant {
                    did: did.clone(),
                    handle: None,
                    display_name: None,
                    role: "member".to_string(),
                },
            });
        }
        Ok(())
    }

    /// Leave a conversation.
    pub async fn leave_conversation(&self, conversation_id: &str) -> Result<(), OrchestratorError> {
        self.orchestrator.leave_group(conversation_id).await
    }

    /// Subscribe to chat events (new messages, participant changes, etc.).
    pub fn subscribe_events(&self) -> broadcast::Receiver<ChatEvent> {
        self.event_tx.subscribe()
    }

    /// Sync conversations and messages with the server.
    pub async fn sync(&self, full_sync: bool) -> Result<(), OrchestratorError> {
        self.orchestrator.sync_with_server(full_sync).await?;
        let _ = self.event_tx.send(ChatEvent::SyncCompleted);
        Ok(())
    }

    /// Fetch new messages for a conversation from the server, decrypt, and store.
    pub async fn fetch_new_messages(
        &self,
        conversation_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ChatMessage>, OrchestratorError> {
        let (messages, _new_cursor) = self
            .orchestrator
            .fetch_messages(conversation_id, cursor, limit, None, None, None)
            .await?;

        let chat_messages: Vec<ChatMessage> =
            messages.iter().map(message_to_chat_message).collect();

        // Emit events for received messages
        for msg in &chat_messages {
            if !msg.is_own {
                let _ = self.event_tx.send(ChatEvent::MessageReceived {
                    message: msg.clone(),
                });
            }
        }

        Ok(chat_messages)
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

    /// Force rejoin a conversation (recovery path).
    ///
    /// Task #43: demoted to `pub(crate)`. External Commit rejoin is no longer
    /// a platform-callable action — client-initiated External Commits were the
    /// root cause of production epoch inflation. Server-mediated recovery via
    /// the A7 reset pyramid is the current path; this method remains
    /// `pub(crate)` (currently unused but kept for parity with `WasmClient`
    /// during the transition).
    #[allow(dead_code)]
    pub(crate) async fn rejoin_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<(), OrchestratorError> {
        self.orchestrator.force_rejoin(conversation_id).await
    }

    /// Shut down the client, releasing resources.
    pub async fn shutdown(&self) {
        self.orchestrator.shutdown().await;
    }

    /// Get the current user's DID.
    pub fn user_did(&self) -> &str {
        &self.user_did
    }

    /// Access the underlying orchestrator (for advanced/escape-hatch use).
    pub fn orchestrator(&self) -> &Arc<MLSOrchestrator<S, A, C, M>> {
        &self.orchestrator
    }
}
