// UniFFI bridge for CatbirdClient
//
// Exposes the high-level CatbirdClient to Swift/Kotlin via UniFFI.
// Uses the same callback-based pattern as orchestrator_bridge.rs:
// Swift/Kotlin provides storage, API, and credential backends via callbacks.

use std::sync::Arc;

use crate::api::MLSContext;
use crate::client::{CatbirdClient, ChatMessage, Conversation};
use crate::orchestrator::OrchestratorConfig;
use crate::orchestrator_bridge::{
    FFIOrchestratorConfig, OrchestratorAPICallback, OrchestratorBridgeError,
    OrchestratorCredentialCallback, OrchestratorStorageCallback,
};

// Re-use the existing adapter types from orchestrator_bridge.
// Since they are private in that module, we re-define thin wrappers here
// that delegate to the same callbacks. An alternative would be to make the
// adapters pub(crate) in orchestrator_bridge — but creating them here keeps
// the two bridges independently evolvable.

use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::types::*;

// ═══════════════════════════════════════════════════════════════════════════
// Adapter types — identical to orchestrator_bridge but pub(crate)
// We import the conversion helpers from orchestrator_bridge where possible,
// but since those are private, we replicate the minimal set needed.
// ═══════════════════════════════════════════════════════════════════════════

struct ClientStorageAdapter(Arc<dyn OrchestratorStorageCallback>);
struct ClientAPIAdapter(Arc<dyn OrchestratorAPICallback>);
struct ClientCredentialAdapter(Arc<dyn OrchestratorCredentialCallback>);

// -- Conversion helpers (duplicated from orchestrator_bridge for independence) --

fn bridge_err(e: OrchestratorBridgeError) -> crate::orchestrator::error::OrchestratorError {
    match e {
        OrchestratorBridgeError::Storage { message } => {
            crate::orchestrator::error::OrchestratorError::Storage(message)
        }
        OrchestratorBridgeError::Api { message } => {
            crate::orchestrator::error::OrchestratorError::Api(message)
        }
        OrchestratorBridgeError::Credential { message } => {
            crate::orchestrator::error::OrchestratorError::Credential(message)
        }
        OrchestratorBridgeError::NotAuthenticated => {
            crate::orchestrator::error::OrchestratorError::NotAuthenticated
        }
        OrchestratorBridgeError::ShuttingDown => {
            crate::orchestrator::error::OrchestratorError::ShuttingDown
        }
        other => crate::orchestrator::error::OrchestratorError::Api(other.to_string()),
    }
}

fn ffi_to_convo_view(ffi: &crate::orchestrator_bridge::FFIConversationView) -> ConversationView {
    ConversationView {
        group_id: ffi.group_id.clone(),
        epoch: ffi.epoch,
        members: ffi
            .members
            .iter()
            .map(|m| MemberView {
                did: m.did.clone(),
                role: if m.role == "admin" {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect(),
        metadata: if ffi.name.is_some() || ffi.description.is_some() || ffi.avatar_url.is_some() {
            Some(ConversationMetadata {
                name: ffi.name.clone(),
                description: ffi.description.clone(),
                avatar_url: ffi.avatar_url.clone(),
            })
        } else {
            None
        },
        created_at: ffi
            .created_at
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        updated_at: ffi
            .updated_at
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
    }
}

fn ffi_to_message(ffi: &crate::orchestrator_bridge::FFIMessage) -> Message {
    use crate::orchestrator::types::DeliveryStatus;
    use crate::orchestrator_bridge::FFIDeliveryStatus;
    Message {
        id: ffi.id.clone(),
        conversation_id: ffi.conversation_id.clone(),
        sender_did: ffi.sender_did.clone(),
        text: ffi.text.clone(),
        timestamp: ffi
            .timestamp
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_else(|_| chrono::Utc::now()),
        epoch: ffi.epoch,
        sequence_number: ffi.sequence_number,
        is_own: ffi.is_own,
        delivery_status: ffi.delivery_status.as_ref().map(|s| match s {
            FFIDeliveryStatus::DeliveredToAll => DeliveryStatus::DeliveredToAll,
            FFIDeliveryStatus::Partial {
                acked_count,
                total_count,
            } => DeliveryStatus::Partial {
                acked_count: *acked_count,
                total_count: *total_count,
            },
            FFIDeliveryStatus::Pending => DeliveryStatus::Pending,
            FFIDeliveryStatus::LocalOnly => DeliveryStatus::LocalOnly,
        }),
    }
}

fn message_to_ffi(msg: &Message) -> crate::orchestrator_bridge::FFIMessage {
    use crate::orchestrator::types::DeliveryStatus;
    use crate::orchestrator_bridge::FFIDeliveryStatus;
    crate::orchestrator_bridge::FFIMessage {
        id: msg.id.clone(),
        conversation_id: msg.conversation_id.clone(),
        sender_did: msg.sender_did.clone(),
        text: msg.text.clone(),
        timestamp: msg.timestamp.to_rfc3339(),
        epoch: msg.epoch,
        sequence_number: msg.sequence_number,
        is_own: msg.is_own,
        delivery_status: msg.delivery_status.as_ref().map(|s| match s {
            DeliveryStatus::DeliveredToAll => FFIDeliveryStatus::DeliveredToAll,
            DeliveryStatus::Partial {
                acked_count,
                total_count,
            } => FFIDeliveryStatus::Partial {
                acked_count: *acked_count,
                total_count: *total_count,
            },
            DeliveryStatus::Pending => FFIDeliveryStatus::Pending,
            DeliveryStatus::LocalOnly => FFIDeliveryStatus::LocalOnly,
        }),
    }
}

fn join_method_to_string(jm: JoinMethod) -> String {
    match jm {
        JoinMethod::Creator => "creator".to_string(),
        JoinMethod::Welcome => "welcome".to_string(),
        JoinMethod::ExternalCommit => "external_commit".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MLSStorageBackend impl for ClientStorageAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl MLSStorageBackend for ClientStorageAdapter {
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .ensure_conversation_exists(
                user_did.to_string(),
                conversation_id.to_string(),
                group_id.to_string(),
            )
            .map_err(bridge_err)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .update_join_info(
                conversation_id.to_string(),
                user_did.to_string(),
                join_method_to_string(join_method),
                join_epoch,
            )
            .map_err(bridge_err)
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<Option<ConversationView>> {
        self.0
            .get_conversation(user_did.to_string(), conversation_id.to_string())
            .map(|opt| opt.map(|ffi| ffi_to_convo_view(&ffi)))
            .map_err(bridge_err)
    }

    async fn list_conversations(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Vec<ConversationView>> {
        self.0
            .list_conversations(user_did.to_string())
            .map(|v| v.iter().map(ffi_to_convo_view).collect())
            .map_err(bridge_err)
    }

    async fn delete_conversations(
        &self,
        user_did: &str,
        ids: &[&str],
    ) -> crate::orchestrator::Result<()> {
        self.0
            .delete_conversations(
                user_did.to_string(),
                ids.iter().map(|s| s.to_string()).collect(),
            )
            .map_err(bridge_err)
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> crate::orchestrator::Result<()> {
        let state_str = match state {
            ConversationState::Initializing => "initializing",
            ConversationState::Active => "active",
            ConversationState::NeedsRejoin => "needs_rejoin",
            ConversationState::Failed => "failed",
        };
        self.0
            .set_conversation_state(conversation_id.to_string(), state_str.to_string())
            .map_err(bridge_err)
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .mark_needs_rejoin(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .needs_rejoin(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .clear_rejoin_flag(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn store_message(&self, message: &Message) -> crate::orchestrator::Result<()> {
        self.0
            .store_message(message_to_ffi(message))
            .map_err(bridge_err)
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> crate::orchestrator::Result<Vec<Message>> {
        self.0
            .get_messages(conversation_id.to_string(), limit, before_sequence)
            .map(|v| v.iter().map(ffi_to_message).collect())
            .map_err(bridge_err)
    }

    async fn message_exists(&self, message_id: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .message_exists(message_id.to_string())
            .map_err(bridge_err)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> crate::orchestrator::Result<SyncCursor> {
        self.0
            .get_sync_cursor(user_did.to_string())
            .map(|ffi| SyncCursor {
                conversations_cursor: ffi.conversations_cursor,
                messages_cursor: ffi.messages_cursor,
            })
            .map_err(bridge_err)
    }

    async fn set_sync_cursor(
        &self,
        user_did: &str,
        cursor: &SyncCursor,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_sync_cursor(
                user_did.to_string(),
                crate::orchestrator_bridge::FFISyncCursor {
                    conversations_cursor: cursor.conversations_cursor.clone(),
                    messages_cursor: cursor.messages_cursor.clone(),
                },
            )
            .map_err(bridge_err)
    }

    async fn set_group_state(&self, state: &GroupState) -> crate::orchestrator::Result<()> {
        self.0
            .set_group_state(crate::orchestrator_bridge::FFIGroupState {
                group_id: state.group_id.clone(),
                conversation_id: state.conversation_id.clone(),
                epoch: state.epoch,
                members: state.members.clone(),
            })
            .map_err(bridge_err)
    }

    async fn get_group_state(
        &self,
        group_id: &str,
    ) -> crate::orchestrator::Result<Option<GroupState>> {
        self.0
            .get_group_state(group_id.to_string())
            .map(|opt| {
                opt.map(|ffi| GroupState {
                    group_id: ffi.group_id,
                    conversation_id: ffi.conversation_id,
                    epoch: ffi.epoch,
                    members: ffi.members,
                })
            })
            .map_err(bridge_err)
    }

    async fn delete_group_state(&self, group_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .delete_group_state(group_id.to_string())
            .map_err(bridge_err)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MLSAPIClient impl for ClientAPIAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl MLSAPIClient for ClientAPIAdapter {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.0.is_authenticated_as(did.to_string())
    }

    async fn current_did(&self) -> Option<String> {
        self.0.current_did()
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> crate::orchestrator::Result<ConversationListPage> {
        self.0
            .get_conversations(limit, cursor.map(|s| s.to_string()))
            .map(|ffi| ConversationListPage {
                conversations: ffi.conversations.iter().map(ffi_to_convo_view).collect(),
                cursor: ffi.cursor,
            })
            .map_err(bridge_err)
    }

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> crate::orchestrator::Result<CreateConversationResult> {
        self.0
            .create_conversation(
                group_id.to_string(),
                initial_members.map(|m| m.to_vec()),
                metadata.and_then(|m| m.name.clone()),
                metadata.and_then(|m| m.description.clone()),
                commit_data.map(|d| d.to_vec()),
                welcome_data.map(|d| d.to_vec()),
            )
            .map(|ffi| CreateConversationResult {
                conversation: ffi_to_convo_view(&ffi.conversation),
                commit_data: ffi.commit_data,
                welcome_data: ffi.welcome_data,
            })
            .map_err(bridge_err)
    }

    async fn leave_conversation(&self, convo_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .leave_conversation(convo_id.to_string())
            .map_err(bridge_err)
    }

    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> crate::orchestrator::Result<AddMembersServerResult> {
        self.0
            .add_members(
                convo_id.to_string(),
                member_dids.to_vec(),
                commit_data.to_vec(),
                welcome_data.map(|d| d.to_vec()),
            )
            .map(|ffi| AddMembersServerResult {
                success: ffi.success,
                new_epoch: ffi.new_epoch,
                receipt: None,
            })
            .map_err(bridge_err)
    }

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> crate::orchestrator::Result<()> {
        self.0
            .remove_members(
                convo_id.to_string(),
                member_dids.to_vec(),
                commit_data.to_vec(),
            )
            .map_err(bridge_err)
    }

    async fn send_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .send_message(convo_id.to_string(), ciphertext.to_vec(), epoch)
            .map_err(bridge_err)
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> crate::orchestrator::Result<(Vec<IncomingEnvelope>, Option<String>)> {
        self.0
            .get_messages(convo_id.to_string(), cursor.map(|s| s.to_string()), limit)
            .map(|ffi| {
                let envelopes = ffi
                    .envelopes
                    .iter()
                    .map(|e| IncomingEnvelope {
                        conversation_id: e.conversation_id.clone(),
                        sender_did: e.sender_did.clone(),
                        ciphertext: e.ciphertext.clone(),
                        timestamp: e
                            .timestamp
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .unwrap_or_else(|_| chrono::Utc::now()),
                        server_message_id: e.server_message_id.clone(),
                    })
                    .collect();
                (envelopes, ffi.cursor)
            })
            .map_err(bridge_err)
    }

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .publish_key_package(
                key_package.to_vec(),
                cipher_suite.to_string(),
                expires_at.to_string(),
            )
            .map_err(bridge_err)
    }

    async fn get_key_packages(
        &self,
        dids: &[String],
    ) -> crate::orchestrator::Result<Vec<KeyPackageRef>> {
        self.0
            .get_key_packages(dids.to_vec())
            .map(|v| {
                v.into_iter()
                    .map(|ffi| KeyPackageRef {
                        did: ffi.did,
                        key_package_data: ffi.key_package_data,
                        hash: ffi.hash,
                        cipher_suite: ffi.cipher_suite,
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn get_key_package_stats(&self) -> crate::orchestrator::Result<KeyPackageStats> {
        self.0
            .get_key_package_stats()
            .map(|ffi| KeyPackageStats {
                available: ffi.available,
                total: ffi.total,
            })
            .map_err(bridge_err)
    }

    async fn sync_key_packages(
        &self,
        local_hashes: &[String],
        device_id: &str,
    ) -> crate::orchestrator::Result<KeyPackageSyncResult> {
        self.0
            .sync_key_packages(local_hashes.to_vec(), device_id.to_string())
            .map(|ffi| KeyPackageSyncResult {
                orphaned_count: ffi.orphaned_count,
                deleted_count: ffi.deleted_count,
            })
            .map_err(bridge_err)
    }

    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> crate::orchestrator::Result<DeviceInfo> {
        self.0
            .register_device(
                device_uuid.to_string(),
                device_name.to_string(),
                mls_did.to_string(),
                signature_key.to_vec(),
                key_packages.to_vec(),
            )
            .map(|ffi| DeviceInfo {
                device_id: ffi.device_id,
                mls_did: ffi.mls_did,
                device_uuid: ffi.device_uuid,
                created_at: ffi
                    .created_at
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc)),
            })
            .map_err(bridge_err)
    }

    async fn list_devices(&self) -> crate::orchestrator::Result<Vec<DeviceInfo>> {
        self.0
            .list_devices()
            .map(|v| {
                v.into_iter()
                    .map(|ffi| DeviceInfo {
                        device_id: ffi.device_id,
                        mls_did: ffi.mls_did,
                        device_uuid: ffi.device_uuid,
                        created_at: ffi
                            .created_at
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc)),
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn remove_device(&self, device_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .remove_device(device_id.to_string())
            .map_err(bridge_err)
    }

    async fn publish_group_info(
        &self,
        convo_id: &str,
        group_info: &[u8],
    ) -> crate::orchestrator::Result<()> {
        self.0
            .publish_group_info(convo_id.to_string(), group_info.to_vec())
            .map_err(bridge_err)
    }

    async fn get_group_info(&self, convo_id: &str) -> crate::orchestrator::Result<Vec<u8>> {
        self.0
            .get_group_info(convo_id.to_string())
            .map_err(bridge_err)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CredentialStore impl for ClientCredentialAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl CredentialStore for ClientCredentialAdapter {
    async fn store_signing_key(
        &self,
        user_did: &str,
        key_data: &[u8],
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_signing_key(user_did.to_string(), key_data.to_vec())
            .map_err(bridge_err)
    }

    async fn get_signing_key(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Option<Vec<u8>>> {
        self.0
            .get_signing_key(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn delete_signing_key(&self, user_did: &str) -> crate::orchestrator::Result<()> {
        self.0
            .delete_signing_key(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn store_mls_did(
        &self,
        user_did: &str,
        mls_did: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_mls_did(user_did.to_string(), mls_did.to_string())
            .map_err(bridge_err)
    }

    async fn get_mls_did(&self, user_did: &str) -> crate::orchestrator::Result<Option<String>> {
        self.0.get_mls_did(user_did.to_string()).map_err(bridge_err)
    }

    async fn store_device_uuid(
        &self,
        user_did: &str,
        uuid: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_device_uuid(user_did.to_string(), uuid.to_string())
            .map_err(bridge_err)
    }

    async fn get_device_uuid(&self, user_did: &str) -> crate::orchestrator::Result<Option<String>> {
        self.0
            .get_device_uuid(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn has_credentials(&self, user_did: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .has_credentials(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn clear_all(&self, user_did: &str) -> crate::orchestrator::Result<()> {
        self.0.clear_all(user_did.to_string()).map_err(bridge_err)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Concrete type alias
// ═══════════════════════════════════════════════════════════════════════════

type ConcreteCatbirdClient =
    CatbirdClient<ClientStorageAdapter, ClientAPIAdapter, ClientCredentialAdapter>;

// ═══════════════════════════════════════════════════════════════════════════
// UniFFI-exported CatbirdClientBridge
// ═══════════════════════════════════════════════════════════════════════════

/// UniFFI-exported CatbirdClient — the simple chat API for Swift/Kotlin.
///
/// Provides conversations, messages, and sync without exposing any MLS internals.
/// Swift/Kotlin provides the platform-specific storage, API, and credential backends
/// via the same callback interfaces used by OrchestratorBridge.
#[derive(uniffi::Object)]
pub struct CatbirdClientBridge {
    inner: ConcreteCatbirdClient,
}

#[uniffi::export]
impl CatbirdClientBridge {
    /// Create and initialize a new CatbirdClient.
    ///
    /// - `user_did`: The authenticated user's DID
    /// - `mls_context`: The low-level MLS FFI context
    /// - `storage`: Platform storage callback (same as OrchestratorBridge)
    /// - `api_client`: Platform API client callback (same as OrchestratorBridge)
    /// - `credentials`: Platform credential store callback (same as OrchestratorBridge)
    /// - `config`: Orchestrator configuration
    #[uniffi::constructor]
    pub fn new(
        user_did: String,
        mls_context: Arc<MLSContext>,
        storage: Box<dyn OrchestratorStorageCallback>,
        api_client: Box<dyn OrchestratorAPICallback>,
        credentials: Box<dyn OrchestratorCredentialCallback>,
        config: FFIOrchestratorConfig,
    ) -> Result<Arc<Self>, OrchestratorBridgeError> {
        let orch_config = OrchestratorConfig {
            max_devices: config.max_devices,
            target_key_package_count: config.target_key_package_count,
            key_package_replenish_threshold: config.key_package_replenish_threshold,
            sync_cooldown_seconds: config.sync_cooldown_seconds,
            max_consecutive_sync_failures: config.max_consecutive_sync_failures,
            sync_pause_duration_seconds: config.sync_pause_duration_seconds,
            rejoin_cooldown_seconds: config.rejoin_cooldown_seconds,
            max_rejoin_attempts: config.max_rejoin_attempts,
            group_config: crate::GroupConfig::default(),
        };

        let client = crate::async_runtime::block_on(CatbirdClient::create(
            user_did,
            mls_context,
            Arc::new(ClientStorageAdapter(Arc::from(storage))),
            Arc::new(ClientAPIAdapter(Arc::from(api_client))),
            Arc::new(ClientCredentialAdapter(Arc::from(credentials))),
            orch_config,
        ))
        .map_err(OrchestratorBridgeError::from)?;

        Ok(Arc::new(Self { inner: client }))
    }

    // -- Conversations --

    /// List all conversations.
    pub fn conversations(&self) -> Result<Vec<Conversation>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.conversations())
            .map_err(OrchestratorBridgeError::from)
    }

    /// Create a new conversation.
    pub fn create_conversation(
        &self,
        name: Option<String>,
        participant_dids: Vec<String>,
    ) -> Result<Conversation, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.create_conversation(name, participant_dids))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Messaging --

    /// Send a text message to a conversation.
    pub fn send_message(
        &self,
        conversation_id: String,
        text: String,
    ) -> Result<ChatMessage, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.send_message(&conversation_id, &text))
            .map_err(OrchestratorBridgeError::from)
    }

    /// Get message history for a conversation.
    pub fn messages(
        &self,
        conversation_id: String,
        limit: Option<i32>,
        before_sequence: Option<u64>,
    ) -> Result<Vec<ChatMessage>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.messages(
            &conversation_id,
            limit,
            before_sequence,
        ))
        .map_err(OrchestratorBridgeError::from)
    }

    /// Fetch new messages from the server for a conversation.
    pub fn fetch_new_messages(
        &self,
        conversation_id: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<Vec<ChatMessage>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.fetch_new_messages(
            &conversation_id,
            cursor.as_deref(),
            limit,
        ))
        .map_err(OrchestratorBridgeError::from)
    }

    // -- Participants --

    /// Add participants to an existing conversation.
    pub fn add_participants(
        &self,
        conversation_id: String,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.inner
                .add_participants(&conversation_id, participant_dids),
        )
        .map_err(OrchestratorBridgeError::from)
    }

    /// Remove participants from a conversation.
    pub fn remove_participants(
        &self,
        conversation_id: String,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.inner
                .remove_participants(&conversation_id, participant_dids),
        )
        .map_err(OrchestratorBridgeError::from)
    }

    /// Leave a conversation.
    pub fn leave_conversation(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.leave_conversation(&conversation_id))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Sync --

    /// Sync conversations and messages with the server.
    pub fn sync(&self, full_sync: bool) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.sync(full_sync))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Recovery --

    /// Force rejoin a conversation (recovery from epoch desync).
    pub fn rejoin_conversation(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.rejoin_conversation(&conversation_id))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Read state --

    /// Mark a conversation as read up to a specific message.
    pub fn mark_read(
        &self,
        conversation_id: String,
        message_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.mark_read(&conversation_id, &message_id))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Lifecycle --

    /// Shut down the client, releasing all resources.
    pub fn shutdown(&self) {
        crate::async_runtime::block_on(self.inner.shutdown());
    }

    /// Get the current user's DID.
    pub fn user_did(&self) -> String {
        self.inner.user_did().to_string()
    }
}
