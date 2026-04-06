// UniFFI bridge for mls-orchestrator
//
// This module exposes the platform-agnostic MLSOrchestrator to Swift/Kotlin
// via UniFFI callback interfaces. The three platform traits (Storage, API, Credentials)
// are implemented by callback interfaces that delegate to Swift/Kotlin code.

use std::sync::Arc;

use crate::orchestrator::{
    AddMembersServerResult, ConversationListPage, ConversationMetadata, ConversationState,
    ConversationView, CreateConversationResult, CredentialStore, DeviceInfo, GroupState,
    IncomingEnvelope, JoinMethod, KeyPackageRef, KeyPackageStats, KeyPackageSyncResult,
    MLSAPIClient, MLSOrchestrator, MLSStorageBackend, MemberRole, MemberView, Message,
    OrchestratorConfig, OrchestratorError, SendMessageResponse, SyncCursor,
};

use crate::api::MLSContext;

// ═══════════════════════════════════════════════════════════════════════════
// UniFFI callback interfaces — implemented in Swift/Kotlin
// ═══════════════════════════════════════════════════════════════════════════

/// Storage backend callback interface for Swift/Kotlin.
///
/// All methods are synchronous from UniFFI's perspective — the Swift side
/// can use actors/dispatch internally.
#[uniffi::export(callback_interface)]
pub trait OrchestratorStorageCallback: Send + Sync {
    fn ensure_conversation_exists(
        &self,
        user_did: String,
        conversation_id: String,
        group_id: String,
    ) -> Result<(), OrchestratorBridgeError>;

    fn update_join_info(
        &self,
        conversation_id: String,
        user_did: String,
        join_method: String,
        join_epoch: u64,
    ) -> Result<(), OrchestratorBridgeError>;

    fn get_conversation(
        &self,
        user_did: String,
        conversation_id: String,
    ) -> Result<Option<FFIConversationView>, OrchestratorBridgeError>;

    fn list_conversations(
        &self,
        user_did: String,
    ) -> Result<Vec<FFIConversationView>, OrchestratorBridgeError>;

    fn delete_conversations(
        &self,
        user_did: String,
        ids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError>;

    fn set_conversation_state(
        &self,
        conversation_id: String,
        state: String,
    ) -> Result<(), OrchestratorBridgeError>;

    fn mark_needs_rejoin(&self, conversation_id: String) -> Result<(), OrchestratorBridgeError>;
    fn needs_rejoin(&self, conversation_id: String) -> Result<bool, OrchestratorBridgeError>;
    fn clear_rejoin_flag(&self, conversation_id: String) -> Result<(), OrchestratorBridgeError>;

    fn store_message(&self, message: FFIMessage) -> Result<(), OrchestratorBridgeError>;

    fn get_messages(
        &self,
        conversation_id: String,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<FFIMessage>, OrchestratorBridgeError>;

    fn message_exists(&self, message_id: String) -> Result<bool, OrchestratorBridgeError>;

    fn get_sync_cursor(&self, user_did: String) -> Result<FFISyncCursor, OrchestratorBridgeError>;
    fn set_sync_cursor(
        &self,
        user_did: String,
        cursor: FFISyncCursor,
    ) -> Result<(), OrchestratorBridgeError>;

    fn set_group_state(&self, state: FFIGroupState) -> Result<(), OrchestratorBridgeError>;
    fn get_group_state(
        &self,
        group_id: String,
    ) -> Result<Option<FFIGroupState>, OrchestratorBridgeError>;
    fn delete_group_state(&self, group_id: String) -> Result<(), OrchestratorBridgeError>;
}

/// API client callback interface for Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait OrchestratorAPICallback: Send + Sync {
    fn is_authenticated_as(&self, did: String) -> bool;
    fn current_did(&self) -> Option<String>;

    fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<FFIConversationListPage, OrchestratorBridgeError>;

    fn create_conversation(
        &self,
        group_id: String,
        initial_members: Option<Vec<String>>,
        metadata_name: Option<String>,
        metadata_description: Option<String>,
        commit_data: Option<Vec<u8>>,
        welcome_data: Option<Vec<u8>>,
    ) -> Result<FFICreateConversationResult, OrchestratorBridgeError>;

    fn leave_conversation(&self, convo_id: String) -> Result<(), OrchestratorBridgeError>;

    fn add_members(
        &self,
        convo_id: String,
        member_dids: Vec<String>,
        commit_data: Vec<u8>,
        welcome_data: Option<Vec<u8>>,
    ) -> Result<FFIAddMembersResult, OrchestratorBridgeError>;

    fn remove_members(
        &self,
        convo_id: String,
        member_dids: Vec<String>,
        commit_data: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError>;

    fn send_message(
        &self,
        convo_id: String,
        ciphertext: Vec<u8>,
        epoch: u64,
    ) -> Result<(), OrchestratorBridgeError>;

    fn get_messages(
        &self,
        convo_id: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<FFIMessagesPage, OrchestratorBridgeError>;

    fn publish_key_package(
        &self,
        key_package: Vec<u8>,
        cipher_suite: String,
        expires_at: String,
    ) -> Result<(), OrchestratorBridgeError>;

    fn get_key_packages(
        &self,
        dids: Vec<String>,
    ) -> Result<Vec<FFIKeyPackageRef>, OrchestratorBridgeError>;

    fn get_key_package_stats(&self) -> Result<FFIKeyPackageStats, OrchestratorBridgeError>;

    fn sync_key_packages(
        &self,
        local_hashes: Vec<String>,
        device_id: String,
    ) -> Result<FFIKeyPackageSyncResult, OrchestratorBridgeError>;

    fn register_device(
        &self,
        device_uuid: String,
        device_name: String,
        mls_did: String,
        signature_key: Vec<u8>,
        key_packages: Vec<Vec<u8>>,
    ) -> Result<FFIDeviceInfo, OrchestratorBridgeError>;

    fn list_devices(&self) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError>;
    fn remove_device(&self, device_id: String) -> Result<(), OrchestratorBridgeError>;

    fn publish_group_info(
        &self,
        convo_id: String,
        group_info: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError>;

    fn get_group_info(&self, convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError>;
}

/// Credential store callback interface for Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait OrchestratorCredentialCallback: Send + Sync {
    fn store_signing_key(
        &self,
        user_did: String,
        key_data: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError>;
    fn get_signing_key(&self, user_did: String)
        -> Result<Option<Vec<u8>>, OrchestratorBridgeError>;
    fn delete_signing_key(&self, user_did: String) -> Result<(), OrchestratorBridgeError>;
    fn store_mls_did(
        &self,
        user_did: String,
        mls_did: String,
    ) -> Result<(), OrchestratorBridgeError>;
    fn get_mls_did(&self, user_did: String) -> Result<Option<String>, OrchestratorBridgeError>;
    fn store_device_uuid(
        &self,
        user_did: String,
        uuid: String,
    ) -> Result<(), OrchestratorBridgeError>;
    fn get_device_uuid(&self, user_did: String) -> Result<Option<String>, OrchestratorBridgeError>;
    fn has_credentials(&self, user_did: String) -> Result<bool, OrchestratorBridgeError>;
    fn clear_all(&self, user_did: String) -> Result<(), OrchestratorBridgeError>;
}

// ═══════════════════════════════════════════════════════════════════════════
// FFI Record types — flat structs that cross the UniFFI boundary
// ═══════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Record, Clone)]
pub struct FFIMemberView {
    pub did: String,
    pub role: String, // "admin" or "member"
}

#[derive(uniffi::Record, Clone)]
pub struct FFIConversationView {
    pub group_id: String,
    pub epoch: u64,
    pub members: Vec<FFIMemberView>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub text: String,
    pub timestamp: String, // ISO8601
    pub epoch: u64,
    pub sequence_number: u64,
    pub is_own: bool,
    pub delivery_status: Option<FFIDeliveryStatus>,
    pub payload_json: Option<String>,
}

#[derive(uniffi::Enum, Clone)]
pub enum FFIDeliveryStatus {
    DeliveredToAll,
    Partial { acked_count: i32, total_count: i32 },
    Pending,
    LocalOnly,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIGroupState {
    pub group_id: String,
    pub conversation_id: String,
    pub epoch: u64,
    pub members: Vec<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFISyncCursor {
    pub conversations_cursor: Option<String>,
    pub messages_cursor: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIConversationListPage {
    pub conversations: Vec<FFIConversationView>,
    pub cursor: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFICreateConversationResult {
    pub conversation: FFIConversationView,
    pub commit_data: Option<Vec<u8>>,
    pub welcome_data: Option<Vec<u8>>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIAddMembersResult {
    pub success: bool,
    pub new_epoch: u64,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIKeyPackageRef {
    pub did: String,
    pub key_package_data: Vec<u8>,
    pub hash: Option<String>,
    pub cipher_suite: String,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIKeyPackageStats {
    pub available: u32,
    pub total: u32,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIKeyPackageSyncResult {
    pub orphaned_count: u32,
    pub deleted_count: u32,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIDeviceInfo {
    pub device_id: String,
    pub mls_did: String,
    pub device_uuid: String,
    pub created_at: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIMessagesPage {
    pub envelopes: Vec<FFIIncomingEnvelope>,
    pub cursor: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIIncomingEnvelope {
    pub conversation_id: String,
    pub sender_did: String,
    pub ciphertext: Vec<u8>,
    pub timestamp: String,
    pub server_message_id: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIOrchestratorConfig {
    pub max_devices: u32,
    pub target_key_package_count: u32,
    pub key_package_replenish_threshold: u32,
    pub sync_cooldown_seconds: u64,
    pub max_consecutive_sync_failures: u32,
    pub sync_pause_duration_seconds: u64,
    pub rejoin_cooldown_seconds: u64,
    pub max_rejoin_attempts: u32,
}

/// Result of preparing a voice message via the Rust Opus encoder.
#[derive(uniffi::Record, Clone)]
pub struct FFIVoicePrepareResult {
    pub opus_data: Vec<u8>,
    pub encrypted_blob: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub sha256: String,
    pub duration_ms: u64,
    pub waveform: Vec<f32>,
    pub size: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error type for the bridge
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OrchestratorBridgeError {
    #[error("Storage error: {message}")]
    Storage { message: String },
    #[error("API error: {message}")]
    Api { message: String },
    #[error("Credential error: {message}")]
    Credential { message: String },
    #[error("MLS error: {message}")]
    Mls { message: String },
    #[error("Not authenticated")]
    NotAuthenticated,
    #[error("Shutting down")]
    ShuttingDown,
    #[error("Conversation not found: {id}")]
    ConversationNotFound { id: String },
    #[error("Epoch mismatch: local={local}, remote={remote}")]
    EpochMismatch { local: u64, remote: u64 },
    #[error("Device limit reached")]
    DeviceLimitReached,
    #[error("Recovery failed: {message}")]
    RecoveryFailed { message: String },
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    #[error("Voice error: {message}")]
    Voice { message: String },
}

impl From<OrchestratorError> for OrchestratorBridgeError {
    fn from(e: OrchestratorError) -> Self {
        match e {
            OrchestratorError::Mls(e) => OrchestratorBridgeError::Mls {
                message: e.to_string(),
            },
            OrchestratorError::Storage(s) => OrchestratorBridgeError::Storage { message: s },
            OrchestratorError::Api(s) => OrchestratorBridgeError::Api { message: s },
            OrchestratorError::Credential(s) => OrchestratorBridgeError::Credential { message: s },
            OrchestratorError::NotAuthenticated => OrchestratorBridgeError::NotAuthenticated,
            OrchestratorError::ShuttingDown => OrchestratorBridgeError::ShuttingDown,
            OrchestratorError::ConversationNotFound(id) => {
                OrchestratorBridgeError::ConversationNotFound { id }
            }
            OrchestratorError::EpochMismatch { local, remote } => {
                OrchestratorBridgeError::EpochMismatch { local, remote }
            }
            OrchestratorError::DeviceLimitReached { .. } => {
                OrchestratorBridgeError::DeviceLimitReached
            }
            OrchestratorError::RecoveryFailed(s) => {
                OrchestratorBridgeError::RecoveryFailed { message: s }
            }
            OrchestratorError::InvalidInput(s) => {
                OrchestratorBridgeError::InvalidInput { message: s }
            }
            other => OrchestratorBridgeError::Api {
                message: other.to_string(),
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Adapter types — bridge UniFFI callbacks to async_trait impls
// ═══════════════════════════════════════════════════════════════════════════

/// Wraps OrchestratorStorageCallback to implement MLSStorageBackend.
struct StorageAdapter(Arc<dyn OrchestratorStorageCallback>);

/// Wraps OrchestratorAPICallback to implement MLSAPIClient.
struct APIAdapter(Arc<dyn OrchestratorAPICallback>);

/// Wraps OrchestratorCredentialCallback to implement CredentialStore.
struct CredentialAdapter(Arc<dyn OrchestratorCredentialCallback>);

// -- Conversion helpers --

fn convo_view_to_ffi(cv: &ConversationView) -> FFIConversationView {
    FFIConversationView {
        group_id: cv.group_id.clone(),
        epoch: cv.epoch,
        members: cv
            .members
            .iter()
            .map(|m| FFIMemberView {
                did: m.did.clone(),
                role: match m.role {
                    MemberRole::Admin => "admin".to_string(),
                    MemberRole::Member => "member".to_string(),
                },
            })
            .collect(),
        name: cv.metadata.as_ref().and_then(|m| m.name.clone()),
        description: cv.metadata.as_ref().and_then(|m| m.description.clone()),
        avatar_url: cv.metadata.as_ref().and_then(|m| m.avatar_url.clone()),
        created_at: cv.created_at.map(|t| t.to_rfc3339()),
        updated_at: cv.updated_at.map(|t| t.to_rfc3339()),
    }
}

fn ffi_to_convo_view(ffi: &FFIConversationView) -> ConversationView {
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

fn ffi_to_message(ffi: &FFIMessage) -> Message {
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
        delivery_status: ffi.delivery_status.as_ref().map(ffi_to_delivery_status),
        payload_json: ffi.payload_json.clone(),
    }
}

fn message_to_ffi(msg: &Message) -> FFIMessage {
    FFIMessage {
        id: msg.id.clone(),
        conversation_id: msg.conversation_id.clone(),
        sender_did: msg.sender_did.clone(),
        text: msg.text.clone(),
        timestamp: msg.timestamp.to_rfc3339(),
        epoch: msg.epoch,
        sequence_number: msg.sequence_number,
        is_own: msg.is_own,
        delivery_status: msg.delivery_status.as_ref().map(delivery_status_to_ffi),
        payload_json: msg.payload_json.clone(),
    }
}

fn ffi_to_delivery_status(ffi: &FFIDeliveryStatus) -> crate::orchestrator::types::DeliveryStatus {
    use crate::orchestrator::types::DeliveryStatus;
    match ffi {
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
    }
}

fn delivery_status_to_ffi(
    status: &crate::orchestrator::types::DeliveryStatus,
) -> FFIDeliveryStatus {
    use crate::orchestrator::types::DeliveryStatus;
    match status {
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
    }
}

fn join_method_to_string(jm: JoinMethod) -> String {
    match jm {
        JoinMethod::Creator => "creator".to_string(),
        JoinMethod::Welcome => "welcome".to_string(),
        JoinMethod::ExternalCommit => "external_commit".to_string(),
    }
}

fn bridge_err(e: OrchestratorBridgeError) -> OrchestratorError {
    match e {
        OrchestratorBridgeError::Storage { message } => OrchestratorError::Storage(message),
        OrchestratorBridgeError::Api { message } => OrchestratorError::Api(message),
        OrchestratorBridgeError::Credential { message } => OrchestratorError::Credential(message),
        OrchestratorBridgeError::NotAuthenticated => OrchestratorError::NotAuthenticated,
        OrchestratorBridgeError::ShuttingDown => OrchestratorError::ShuttingDown,
        other => OrchestratorError::Api(other.to_string()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MLSStorageBackend impl for StorageAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl MLSStorageBackend for StorageAdapter {
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
                FFISyncCursor {
                    conversations_cursor: cursor.conversations_cursor.clone(),
                    messages_cursor: cursor.messages_cursor.clone(),
                },
            )
            .map_err(bridge_err)
    }

    async fn set_group_state(&self, state: &GroupState) -> crate::orchestrator::Result<()> {
        self.0
            .set_group_state(FFIGroupState {
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
// MLSAPIClient impl for APIAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl MLSAPIClient for APIAdapter {
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
    ) -> crate::orchestrator::Result<SendMessageResponse> {
        self.0
            .send_message(convo_id.to_string(), ciphertext.to_vec(), epoch)
            .map_err(bridge_err)?;
        // FFI callback doesn't return server response; return defaults.
        // The Swift side will be updated separately to propagate seq/epoch.
        Ok(SendMessageResponse {
            message_id: String::new(),
            seq: 0,
            epoch,
        })
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
// CredentialStore impl for CredentialAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl CredentialStore for CredentialAdapter {
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
// The main UniFFI-exported object
// ═══════════════════════════════════════════════════════════════════════════

type ConcreteOrchestrator =
    MLSOrchestrator<StorageAdapter, APIAdapter, CredentialAdapter, MLSContext>;

/// UniFFI-exported MLS Orchestrator object.
///
/// Wraps the generic MLSOrchestrator with callback-based trait implementations.
/// Swift/Kotlin provides the platform-specific storage, API, and credential backends.
#[derive(uniffi::Object)]
pub struct OrchestratorBridge {
    inner: ConcreteOrchestrator,
}

#[uniffi::export]
impl OrchestratorBridge {
    /// Create a new orchestrator bridge.
    ///
    /// - `mls_context`: The low-level MLS FFI context (same as used directly)
    /// - `storage`: Platform storage callback
    /// - `api_client`: Platform API client callback
    /// - `credentials`: Platform credential store callback
    /// - `config`: Orchestrator configuration
    #[uniffi::constructor]
    pub fn new(
        mls_context: Arc<MLSContext>,
        storage: Box<dyn OrchestratorStorageCallback>,
        api_client: Box<dyn OrchestratorAPICallback>,
        credentials: Box<dyn OrchestratorCredentialCallback>,
        config: FFIOrchestratorConfig,
    ) -> Arc<Self> {
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

        let inner = MLSOrchestrator::new(
            mls_context,
            Arc::new(StorageAdapter(Arc::from(storage))),
            Arc::new(APIAdapter(Arc::from(api_client))),
            Arc::new(CredentialAdapter(Arc::from(credentials))),
            orch_config,
        );

        Arc::new(Self { inner })
    }

    /// Initialize the orchestrator for a user DID.
    pub fn initialize(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.initialize(&user_did))?;
        Ok(())
    }

    /// Shut down the orchestrator.
    pub fn shutdown(&self) {
        crate::async_runtime::block_on(self.inner.shutdown());
    }

    // -- Groups --

    /// Create a new MLS group/conversation.
    pub fn create_group(
        &self,
        name: String,
        initial_members: Option<Vec<String>>,
        description: Option<String>,
    ) -> Result<FFIConversationView, OrchestratorBridgeError> {
        let members_ref = initial_members.as_deref();
        let convo = crate::async_runtime::block_on(self.inner.create_group(
            &name,
            members_ref,
            description.as_deref(),
        ))?;
        Ok(convo_view_to_ffi(&convo))
    }

    /// Join an existing group via Welcome message.
    pub fn join_group(
        &self,
        welcome_data: Vec<u8>,
    ) -> Result<FFIConversationView, OrchestratorBridgeError> {
        let convo = crate::async_runtime::block_on(self.inner.join_group(&welcome_data))?;
        Ok(convo_view_to_ffi(&convo))
    }

    /// Add members to an existing group.
    pub fn add_members(
        &self,
        group_id: String,
        member_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.add_members(&group_id, &member_dids))?;
        Ok(())
    }

    /// Remove members from a group.
    pub fn remove_members(
        &self,
        group_id: String,
        member_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.remove_members(&group_id, &member_dids))?;
        Ok(())
    }

    /// Leave a conversation.
    pub fn leave_group(&self, convo_id: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.leave_group(&convo_id))?;
        Ok(())
    }

    // -- Messaging --

    /// Send a text message.
    pub fn send_message(
        &self,
        conversation_id: String,
        text: String,
    ) -> Result<FFIMessage, OrchestratorBridgeError> {
        let msg = crate::async_runtime::block_on(self.inner.send_message(&conversation_id, &text))?;
        Ok(message_to_ffi(&msg))
    }

    /// Encode PCM audio to Opus, extract waveform, encrypt blob.
    /// Returns the encrypted data + metadata needed to upload and send.
    pub fn prepare_voice_message(
        &self,
        pcm_path: String,
        sample_rate: u32,
    ) -> Result<FFIVoicePrepareResult, OrchestratorBridgeError> {
        let result = crate::voice::prepare_voice_message(&pcm_path, sample_rate).map_err(|e| {
            OrchestratorBridgeError::Voice {
                message: e.to_string(),
            }
        })?;
        Ok(FFIVoicePrepareResult {
            opus_data: result.opus_data,
            encrypted_blob: result.encrypted_blob,
            key: result.key,
            iv: result.iv,
            sha256: result.sha256,
            duration_ms: result.duration_ms,
            waveform: result.waveform,
            size: result.size,
        })
    }

    /// Decode Opus-in-OGG back to 16-bit LE mono PCM at 48kHz.
    /// iOS can't play OGG natively, so this decodes for AVAudioPlayer.
    pub fn decode_opus_to_pcm(
        &self,
        opus_data: Vec<u8>,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        crate::voice::decode_opus_to_pcm(&opus_data).map_err(|e| OrchestratorBridgeError::Voice {
            message: e.to_string(),
        })
    }

    /// Send a voice message (audio embed) to a conversation.
    /// Call prepare_voice_message first, upload the encrypted blob,
    /// then call this with the blob_id from the upload.
    pub fn send_voice_message(
        &self,
        conversation_id: String,
        blob_id: String,
        key: Vec<u8>,
        iv: Vec<u8>,
        sha256: String,
        size: u64,
        duration_ms: u64,
        waveform: Vec<f32>,
        transcript: Option<String>,
    ) -> Result<FFIMessage, OrchestratorBridgeError> {
        use crate::orchestrator::types::{MLSAudioEmbed, MLSEmbedData};

        let audio_embed = MLSAudioEmbed {
            blob_id,
            key,
            iv,
            sha256,
            content_type: "audio/ogg; codecs=opus".to_string(),
            size,
            duration_ms,
            waveform,
            transcript,
        };

        let embed = MLSEmbedData::audio(audio_embed).map_err(|e| {
            OrchestratorBridgeError::InvalidInput {
                message: format!("Failed to serialize audio embed: {e}"),
            }
        })?;

        let msg = crate::async_runtime::block_on(self.inner.send_message_with_embed(
            &conversation_id,
            "",
            embed,
        ))?;
        Ok(message_to_ffi(&msg))
    }

    /// Process an incoming encrypted envelope.
    pub fn process_incoming(
        &self,
        envelope: FFIIncomingEnvelope,
    ) -> Result<Option<FFIMessage>, OrchestratorBridgeError> {
        let inner_envelope = IncomingEnvelope {
            conversation_id: envelope.conversation_id,
            sender_did: envelope.sender_did,
            ciphertext: envelope.ciphertext,
            timestamp: envelope
                .timestamp
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap_or_else(|_| chrono::Utc::now()),
            server_message_id: envelope.server_message_id,
        };
        let result = crate::async_runtime::block_on(self.inner.process_incoming(&inner_envelope))?;
        Ok(result.map(|m| message_to_ffi(&m)))
    }

    /// Fetch and process new messages from server.
    pub fn fetch_messages(
        &self,
        conversation_id: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<FFIFetchMessagesResult, OrchestratorBridgeError> {
        let (messages, new_cursor) = crate::async_runtime::block_on(self.inner.fetch_messages(
            &conversation_id,
            cursor.as_deref(),
            limit,
        ))?;
        Ok(FFIFetchMessagesResult {
            messages: messages.iter().map(message_to_ffi).collect(),
            cursor: new_cursor,
        })
    }

    // -- Sync --

    /// Sync conversations with the server.
    pub fn sync_with_server(&self, full_sync: bool) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.sync_with_server(full_sync))?;
        Ok(())
    }

    // -- Key Packages --

    /// Publish a single key package.
    pub fn publish_key_package(&self) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.publish_key_package())?;
        Ok(())
    }

    /// Check and replenish key packages if needed.
    pub fn replenish_key_packages_if_needed(&self) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.replenish_if_needed())?;
        Ok(())
    }

    /// Get key package stats.
    pub fn get_key_package_stats(&self) -> Result<FFIKeyPackageStats, OrchestratorBridgeError> {
        let stats = crate::async_runtime::block_on(self.inner.get_key_package_stats())?;
        Ok(FFIKeyPackageStats {
            available: stats.available,
            total: stats.total,
        })
    }

    // -- Devices --

    /// Ensure device is registered with MLS service.
    pub fn ensure_device_registered(&self) -> Result<String, OrchestratorBridgeError> {
        let mls_did = crate::async_runtime::block_on(self.inner.ensure_device_registered())?;
        Ok(mls_did)
    }

    /// List registered devices.
    pub fn list_devices(&self) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError> {
        let devices = crate::async_runtime::block_on(self.inner.list_devices())?;
        Ok(devices
            .into_iter()
            .map(|d| FFIDeviceInfo {
                device_id: d.device_id,
                mls_did: d.mls_did,
                device_uuid: d.device_uuid,
                created_at: d.created_at.map(|t| t.to_rfc3339()),
            })
            .collect())
    }

    /// Remove a device.
    pub fn remove_device(&self, device_id: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.remove_device(&device_id))?;
        Ok(())
    }

    // -- Recovery --

    /// Force rejoin a conversation via External Commit.
    pub fn force_rejoin(&self, convo_id: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.force_rejoin(&convo_id))?;
        Ok(())
    }

    /// Perform full silent recovery.
    pub fn perform_silent_recovery(
        &self,
        conversation_ids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.perform_silent_recovery(&conversation_ids))?;
        Ok(())
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FFIFetchMessagesResult {
    pub messages: Vec<FFIMessage>,
    pub cursor: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Free voice utility functions — no bridge instance needed
// ═══════════════════════════════════════════════════════════════════════════

/// Encode PCM audio to Opus, extract waveform, encrypt blob.
/// This is a pure function — no bridge or MLS context needed.
#[uniffi::export]
pub fn ffi_prepare_voice_message(
    pcm_path: String,
    sample_rate: u32,
) -> Result<FFIVoicePrepareResult, OrchestratorBridgeError> {
    let result = crate::voice::prepare_voice_message(&pcm_path, sample_rate).map_err(|e| {
        OrchestratorBridgeError::Voice {
            message: e.to_string(),
        }
    })?;
    Ok(FFIVoicePrepareResult {
        opus_data: result.opus_data,
        encrypted_blob: result.encrypted_blob,
        key: result.key,
        iv: result.iv,
        sha256: result.sha256,
        duration_ms: result.duration_ms,
        waveform: result.waveform,
        size: result.size,
    })
}

/// Decode Opus-in-OGG back to 16-bit LE mono PCM at 48kHz.
/// iOS can't play OGG natively, so this decodes for AVAudioPlayer.
/// This is a pure function — no bridge or MLS context needed.
#[uniffi::export]
pub fn ffi_decode_opus_to_pcm(opus_data: Vec<u8>) -> Result<Vec<u8>, OrchestratorBridgeError> {
    crate::voice::decode_opus_to_pcm(&opus_data).map_err(|e| OrchestratorBridgeError::Voice {
        message: e.to_string(),
    })
}
