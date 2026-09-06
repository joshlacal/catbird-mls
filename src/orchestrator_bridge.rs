// UniFFI bridge for mls-orchestrator
//
// This module exposes the platform-agnostic MLSOrchestrator to Swift/Kotlin
// via UniFFI callback interfaces. The three platform traits (Storage, API, Credentials)
// are implemented by callback interfaces that delegate to Swift/Kotlin code.

use std::sync::Arc;
use std::time::Duration;

use crate::orchestrator::{
    AddMembersServerResult, CleanChatSigningAuthority, ConversationListPage, ConversationMetadata,
    ConversationState, ConversationView, CreateConversationResult, CredentialStore,
    DebugWipeLocalGroupResult, DeferredRecoveryReport, DeviceInfo, EngineEvent, GroupState,
    IncomingEnvelope, JoinMethod, KeyPackageRef, KeyPackageStats, KeyPackageSyncResult,
    MLSAPIClient, MLSOrchestrator, MLSStorageBackend, MemberRole, MemberView, Message,
    OrchestratorConfig, OrchestratorError, PendingLocalDelete, PersistedRecoveryBackoff,
    PersistedRecoveryState, ProcessExternalCommitResult, ResetRecordOutcome, SendMessageResponse,
    StartupReconcileReport, SyncCursor,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::orchestrator::{
    CleanChatOperationFfi, CleanChatPreparedRequestFfi, CleanChatSigningContextFfi,
    CleanChatTransportFfiError,
};

use crate::api::MLSContext;
use crate::engine::{
    CreateConversationRequest, EngineLifecycle, GroupMutationResult, LeaveResult, MlsEngine,
};
use crate::StorageLifecycleStatus;

#[path = "bridge_mappers.rs"]
pub(crate) mod bridge_mappers;

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

    fn complete_account_exit(
        &self,
        conversation_id: String,
        expected_group_id_hex: String,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: String,
    ) -> Result<bool, OrchestratorBridgeError>;

    fn get_conversation_state(
        &self,
        conversation_id: String,
    ) -> Result<Option<FFIConversationState>, OrchestratorBridgeError>;

    /// Persist the `RESET_PENDING` payload for a server-initiated group reset.
    ///
    /// Called from `MLSOrchestrator::record_group_reset` before any local MLS
    /// state mutation, so the platform can recover the pending-reset target on
    /// restart (spec §8.5 Phase 1 / ADR-001 level 3).
    ///
    /// - `conversation_id`: stable conversation id.
    /// - `new_group_id_hex`: hex-encoded new MLS group id advertised by the DS.
    /// - `reset_generation`: monotonic reset counter from the DS.
    /// - `notified_at_ms`: Unix millis when the notification was observed.
    ///
    /// This callback is mandatory. It is the sole authority-publication commit
    /// point and must atomically persist the state tag, complete tuple, and
    /// `needs_rejoin = true`, rejecting stale generations while preserving the
    /// old durable group mapping for restart-safe predecessor cleanup. Missing
    /// support fails closed.
    ///
    /// That same commit must also clear any persisted quarantine for the
    /// conversation: a server reset is a documented quarantine exit (ruling 2a,
    /// 2026-08-15), so tag, payload, rejoin route, and quarantine clear land
    /// together. Deferring the clear to the separate `clear_quarantine`
    /// callback leaves a window in which the platform can persist a row that
    /// is both reset-pending and quarantined, which rehydrates quarantined
    /// forever because the replayed reset dedupes before reaching the clear.
    fn mark_reset_pending(
        &self,
        conversation_id: String,
        new_group_id_hex: String,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<(), OrchestratorBridgeError>;

    /// Atomically adopt the server-verified winner of a reset race while
    /// preserving the exact committed ResetPending generation and payload.
    fn adopt_reset_pending_target(
        &self,
        conversation_id: String,
        expected_generation: i32,
        expected_old_target: String,
        authoritative_new_target: String,
    ) -> Result<bool, OrchestratorBridgeError>;

    /// Atomically complete an exact reset generation and target: project the
    /// durable group mapping to that target, clear its payload, project durable
    /// Active, and clear the durable rejoin flag.
    fn complete_reset_pending(
        &self,
        conversation_id: String,
        expected_generation: i32,
        expected_new_group_id_hex: String,
        landed_epoch: u64,
    ) -> Result<bool, OrchestratorBridgeError>;

    /// Clear an exact reset generation for local deletion without projecting
    /// Active.
    fn clear_reset_pending_for_delete(
        &self,
        conversation_id: String,
        expected_generation: i32,
    ) -> Result<bool, OrchestratorBridgeError>;

    fn mark_quarantined(
        &self,
        conversation_id: String,
        reason_tag: String,
        since_ms: i64,
    ) -> Result<(), OrchestratorBridgeError>;
    fn clear_quarantine(&self, conversation_id: String) -> Result<(), OrchestratorBridgeError>;

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

    fn store_pending_message(
        &self,
        conversation_id: String,
        message_id: String,
    ) -> Result<(), OrchestratorBridgeError>;
    fn remove_pending_message(&self, message_id: String) -> Result<bool, OrchestratorBridgeError>;

    fn store_sequencer_receipt(
        &self,
        receipt: FFISequencerReceipt,
    ) -> Result<(), OrchestratorBridgeError>;
    fn get_sequencer_receipts(
        &self,
        conversation_id: String,
        since_epoch: Option<i32>,
    ) -> Result<Vec<FFISequencerReceipt>, OrchestratorBridgeError>;
    fn clear_sequencer_receipts(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError>;

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

    // -- RecoveryTracker persistence (WS-5.4, invariant E7) --

    /// Read the persisted RecoveryTracker state for startup hydration.
    /// Return an empty state if the platform has not written any entries yet.
    fn get_recovery_state(&self) -> Result<FFIPersistedRecoveryState, OrchestratorBridgeError>;

    /// Write-through one conversation's rejoin-backoff snapshot. Called on
    /// every failed rejoin attempt (and on quarantine-lockout entry/expiry).
    fn set_recovery_backoff(
        &self,
        entry: FFIPersistedRecoveryBackoff,
    ) -> Result<(), OrchestratorBridgeError>;

    /// Remove a conversation's persisted backoff entry (successful rejoin,
    /// server reset, quarantine entry, stale-flag housekeeping, local delete).
    fn clear_recovery_backoff(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError>;

    /// Persist the global last-rejoin-attempt timestamp (epoch ms), which
    /// backs `MIN_REJOIN_INTERVAL` across restarts.
    fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> Result<(), OrchestratorBridgeError>;

    // -- Pending local deletes (WS-5.3 crash-safe force_delete_local) --

    /// Record the intent to locally delete a conversation BEFORE the
    /// MLS-layer and storage deletes run. Idempotent.
    fn mark_pending_local_delete(
        &self,
        conversation_id: String,
        group_id_hex: Option<String>,
    ) -> Result<(), OrchestratorBridgeError>;

    /// Clear a pending local-delete intent after all delete steps succeeded.
    fn clear_pending_local_delete(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError>;

    /// List local deletes that were started but never completed (crash
    /// between intent and completion). Consumed by the startup reconcile
    /// sweep.
    fn list_pending_local_deletes(
        &self,
    ) -> Result<Vec<FFIPendingLocalDelete>, OrchestratorBridgeError>;
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FFIGatewayResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FFIDeliveryStatusPair {
    pub message_id: String,
    pub status: FFIDeliveryStatus,
}

/// API client callback interface for Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait OrchestratorAPICallback: Send + Sync {
    fn is_authenticated_as(&self, did: String) -> bool;
    fn current_did(&self) -> Option<String>;

    fn submit_prepared_request(
        &self,
        method: String,
        nsid: String,
        body: Option<Vec<u8>>,
        query: Option<Vec<u8>>,
    ) -> Result<FFIGatewayResponse, OrchestratorBridgeError>;

    fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<FFIConversationListPage, OrchestratorBridgeError>;

    fn get_messages(
        &self,
        convo_id: String,
        cursor: Option<String>,
        limit: u32,
        message_type: Option<String>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<FFIMessagesPage, OrchestratorBridgeError>;

    fn get_key_packages(
        &self,
        actor_device_id: String,
        dids: Vec<String>,
    ) -> Result<Vec<FFIKeyPackageRef>, OrchestratorBridgeError>;

    fn get_key_package_stats(&self) -> Result<FFIKeyPackageStats, OrchestratorBridgeError>;

    fn sync_key_packages(
        &self,
        local_hashes: Vec<String>,
        device_id: String,
    ) -> Result<FFIKeyPackageSyncResult, OrchestratorBridgeError>;

    fn list_devices(
        &self,
        actor_device_id: String,
    ) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError>;

    fn get_group_info(&self, convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError>;

    fn get_welcome(&self, convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError>;

    fn get_delivery_status(
        &self,
        convo_id: String,
        message_ids: Vec<String>,
    ) -> Result<Vec<FFIDeliveryStatusPair>, OrchestratorBridgeError>;

    fn get_group_metadata_blob(
        &self,
        convo_id: String,
        group_id_hex: String,
        blob_locator: String,
    ) -> Result<Vec<u8>, OrchestratorBridgeError>;
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
    /// Sign an exact clean-chat transcript inside platform-owned key custody.
    /// Only the public key, signature, and atomic binding snapshot return;
    /// private key bytes never cross this callback boundary. Binding fields
    /// are intentionally returned by the authority rather than supplied by
    /// the caller, preventing an echo of untrusted claims.
    fn sign_clean_chat_transcript(
        &self,
        user_did: String,
        transcript: Vec<u8>,
        key_id: String,
    ) -> Result<Option<CleanChatSigningAuthorityFfi>, OrchestratorBridgeError>;
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
    fn get_authorized_device_keys(
        &self,
        user_did: String,
    ) -> Result<Option<Vec<Vec<u8>>>, OrchestratorBridgeError>;
}

/// Public-key/signature result for the non-exporting signed-request callback.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct CleanChatSigningAuthorityFfi {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub device_id: String,
    pub auth_generation: Option<i64>,
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
    /// Full canonical conversationState JSON; None is unknown admission.
    pub canonical_state_json: Option<String>,
    pub group_id: String,
    /// Stable conversation identifier (survives group resets).
    pub conversation_id: String,
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

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
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

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FFIConversationState {
    pub state: String,
    pub new_group_id: Option<String>,
    pub reset_generation: Option<i32>,
    pub notified_at_ms: Option<i64>,
    pub quarantine_reason: Option<String>,
    pub quarantined_since_ms: Option<i64>,
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

/// Versioned declaration of security-bearing persistence and credential
/// operations enabled for a bridge instance. Construction validates this
/// record before creating any orchestrator state.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SecurityStorageCapabilities {
    pub version: u16,
    pub reset_state: bool,
    pub quarantine: bool,
    pub pending_message_protection: bool,
    pub sequencer_receipts: bool,
    pub recovery_backoff: bool,
    pub pending_deletion: bool,
    pub authorized_device_resolution: bool,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FFISequencerReceipt {
    pub convo_id: String,
    pub epoch: i32,
    pub sequencer_term: u64,
    pub commit_hash: Vec<u8>,
    pub sequencer_did: String,
    pub issued_at: i64,
    pub signature: Vec<u8>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIAddMembersResult {
    pub success: bool,
    pub new_epoch: u64,
    pub receipt: Option<FFISequencerReceipt>,
}

/// Server acknowledgment for a sent message. `seq` is the server-assigned
/// conversation-global sequence number — the sole message-ordering authority.
#[derive(uniffi::Record, Clone)]
pub struct FFISendMessageResponse {
    pub message_id: String,
    pub seq: u64,
    pub epoch: u64,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIGroupMutationResult {
    pub conversation: FFIConversationView,
}

#[derive(uniffi::Record, Clone)]
pub struct FFILeaveResult {
    pub conversation_id: String,
    pub group_id: Option<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct FFIProcessExternalCommitResult {
    pub epoch: u64,
    pub rejoined_at: String,
    pub receipt: Option<FFISequencerReceipt>,
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
    pub key_id: Option<String>,
    pub signature_public_key: Option<Vec<u8>>,
    pub auth_generation: Option<i64>,
    pub status: Option<String>,
    pub available_package_count: Option<u32>,
    pub reserved_package_count: Option<u32>,
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
    pub server_sequence: Option<u64>,
    pub server_epoch: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FFIEngineEventKind {
    ConversationUpdated,
    MessageInserted,
    RecoveryStateChanged,
    NeedsUiRefresh,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FFIEngineEvent {
    pub kind: FFIEngineEventKind,
    pub conversation_id: String,
    pub message_id: Option<String>,
    pub recovery_state: Option<FFIConversationRecoveryState>,
}

#[derive(Clone, uniffi::Record)]
pub struct FFISendResult {
    pub message: FFIMessage,
    pub events: Vec<FFIEngineEvent>,
}

#[derive(Clone, uniffi::Record)]
pub struct FFIMessageProcessingResult {
    pub message: Option<FFIMessage>,
    pub events: Vec<FFIEngineEvent>,
}

/// FFI mirror of `PersistedRecoveryBackoff` (WS-5.4 / invariant E7). All
/// timestamps are Unix epoch milliseconds; the schema matches the Swift twin
/// (WS-6.4) so restart cannot reset backoff on any platform.
#[derive(uniffi::Record, Clone)]
pub struct FFIPersistedRecoveryBackoff {
    pub conversation_id: String,
    /// Consecutive failed rejoin attempts.
    pub failed_rejoin_count: u32,
    /// When the most recent rejoin attempt happened (epoch ms).
    pub last_attempt_at_ms: i64,
    /// When the maxed-out rejoin lockout expires (epoch ms). `None` when the
    /// conversation has not exhausted MAX_REJOIN_ATTEMPTS.
    pub quarantined_until_ms: Option<i64>,
}

/// FFI mirror of `PersistedRecoveryState` returned by
/// `OrchestratorStorageCallback::get_recovery_state` on startup (WS-5.4).
#[derive(uniffi::Record, Clone)]
pub struct FFIPersistedRecoveryState {
    pub entries: Vec<FFIPersistedRecoveryBackoff>,
    /// Last rejoin attempt on ANY conversation (epoch ms).
    pub last_global_rejoin_attempt_at_ms: Option<i64>,
}

/// FFI mirror of `PendingLocalDelete` — a persisted intent row for an
/// in-progress `force_delete_local` (WS-5.3 crash safety).
#[derive(uniffi::Record, Clone)]
pub struct FFIPendingLocalDelete {
    pub conversation_id: String,
    /// Hex group id bound to the conversation when the delete started.
    pub group_id_hex: Option<String>,
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

// ---------------------------------------------------------------------------
// Sender-side three-phase commit API surface (task #44)
// ---------------------------------------------------------------------------

/// Opaque handle returned by `stage_commit`. Carries the group id and a
/// per-orchestrator monotonic nonce so stale handles are rejected cleanly.
#[derive(uniffi::Record, Clone)]
pub struct FFIStagedCommitHandle {
    pub group_id: String,
    pub nonce: u64,
}

/// The kind of commit to stage. Each variant corresponds to an existing
/// atomic method on `OrchestratorBridge`.
#[derive(uniffi::Enum, Clone)]
pub enum FFICommitKind {
    /// Add new members. `key_packages` are the serialized key-package bytes
    /// the platform has already fetched from the DS for the given DIDs.
    AddMembers {
        member_dids: Vec<String>,
        key_packages: Vec<Vec<u8>>,
    },
    /// Remove members by DID (converted to identity bytes internally).
    RemoveMembers { member_dids: Vec<String> },
    /// Atomically swap membership: remove the listed DIDs and add new
    /// members from key packages, in a single commit.
    SwapMembers {
        remove_dids: Vec<String>,
        add_dids: Vec<String>,
        add_key_packages: Vec<Vec<u8>>,
    },
    /// GroupContextExtensions commit that updates the encrypted metadata
    /// blob. `group_info_extension` is the serialized `GroupMetadata` JSON.
    UpdateMetadata { group_info_extension: Vec<u8> },
}

/// Plan returned from `stage_commit` — ship this to the DS, then confirm.
#[derive(uniffi::Record, Clone)]
pub struct FFICommitPlan {
    pub handle: FFIStagedCommitHandle,
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Option<Vec<u8>>,
    pub group_info: Vec<u8>,
    pub source_epoch: u64,
    pub target_epoch: u64,
}

/// Summary returned from `confirm_commit`.
#[derive(uniffi::Record, Clone)]
pub struct FFIConfirmedCommit {
    pub new_epoch: u64,
    pub metadata_key: Option<Vec<u8>>,
    pub metadata_reference: Option<String>,
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

// Layer 3 Quarantine FFI surface
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum FFIQuarantineReason {
    PeerBadCommit,
    MultiPeerBadCommits,
    RepeatedFramingFailures,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum FFIQuarantineExitReason {
    PeerCommitSucceeded,
    ServerReset,
    UserConfirmedReset,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FFIQuarantineState {
    pub reason: FFIQuarantineReason,
    pub since_ms: i64,
    pub suspected_dids: Vec<String>,
}

fn qreason_to_ffi(r: crate::orchestrator::types::QuarantineReason) -> FFIQuarantineReason {
    use crate::orchestrator::types::QuarantineReason as Q;
    match r {
        Q::PeerBadCommit => FFIQuarantineReason::PeerBadCommit,
        Q::MultiPeerBadCommits => FFIQuarantineReason::MultiPeerBadCommits,
        Q::RepeatedFramingFailures => FFIQuarantineReason::RepeatedFramingFailures,
    }
}

#[allow(dead_code)]
fn ffi_to_qreason(r: &FFIQuarantineReason) -> crate::orchestrator::types::QuarantineReason {
    use crate::orchestrator::types::QuarantineReason as Q;
    match r {
        FFIQuarantineReason::PeerBadCommit => Q::PeerBadCommit,
        FFIQuarantineReason::MultiPeerBadCommits => Q::MultiPeerBadCommits,
        FFIQuarantineReason::RepeatedFramingFailures => Q::RepeatedFramingFailures,
    }
}

fn qexit_to_ffi(r: crate::orchestrator::types::QuarantineExitReason) -> FFIQuarantineExitReason {
    use crate::orchestrator::types::QuarantineExitReason as Q;
    match r {
        Q::PeerCommitSucceeded => FFIQuarantineExitReason::PeerCommitSucceeded,
        Q::ServerReset => FFIQuarantineExitReason::ServerReset,
        Q::UserConfirmedReset => FFIQuarantineExitReason::UserConfirmedReset,
    }
}

#[allow(dead_code)]
fn ffi_to_qexit(r: &FFIQuarantineExitReason) -> crate::orchestrator::types::QuarantineExitReason {
    use crate::orchestrator::types::QuarantineExitReason as Q;
    match r {
        FFIQuarantineExitReason::PeerCommitSucceeded => Q::PeerCommitSucceeded,
        FFIQuarantineExitReason::ServerReset => Q::ServerReset,
        FFIQuarantineExitReason::UserConfirmedReset => Q::UserConfirmedReset,
    }
}

/// UniFFI callback interface for orchestrator events (Layer 3 quarantine +
/// WS-5.2 recovery-storage escalation). Platforms (Android, catmos Tauri,
/// catmos-cli, web) implement this and register via
/// OrchestratorBridge::set_event_callback. Adding a method here requires a
/// binding regen on each platform before it compiles against the new
/// interface.
#[uniffi::export(callback_interface)]
pub trait OrchestratorEventCallback: Send + Sync {
    fn on_conversation_quarantined(
        &self,
        convo_id: String,
        reason: FFIQuarantineReason,
        suspected_dids: Vec<String>,
    );
    fn on_conversation_quarantine_cleared(&self, convo_id: String, via: FFIQuarantineExitReason);
    /// A recovery-critical storage write failed (WS-5.2). `operation` is the
    /// storage-trait method name (e.g. `mark_needs_rejoin`). Losing such a
    /// write silently cancels deferred recovery across restart — platforms
    /// should surface it (diagnostics, error UI) rather than ignore it.
    fn on_recovery_storage_write_failed(
        &self,
        conversation_id: String,
        operation: String,
        error: String,
    );
    /// A credential-binding check failed in warn-and-allow mode (WS-3 stage 1,
    /// ADR-009 D5). The operation continued; platforms should surface this in
    /// diagnostics/telemetry — a clean week of field data gates the enforce
    /// flip. `operation` is the ADR-009 D5 operation tag (`fetch`, `message`,
    /// ...). `convo_id` is `"<none>"` when no conversation is in scope yet
    /// (e.g. key-package fetch during group creation).
    fn on_credential_binding_warning(
        &self,
        convo_id: String,
        operation: String,
        expected_did: String,
        claimed_identity: String,
        reason: String,
    );
    /// Sequencer equivocation detected (WS-3 stage 1, ADR-009 D8 / E3): two
    /// receipts for the same `(conversation, epoch)` carry different commit
    /// hashes. Stage 1 is detection-only — the triggering operation
    /// continued. Hashes are hex-encoded.
    fn on_sequencer_equivocation(
        &self,
        convo_id: String,
        epoch: i32,
        stored_commit_hash_hex: String,
        new_commit_hash_hex: String,
        sequencer_did: String,
    );
}

/// Adapter so a UniFFI OrchestratorEventCallback can be installed via the
/// internal OrchestratorEventObserver trait the orchestrator core uses.
struct EventCallbackAdapter(Arc<dyn OrchestratorEventCallback>);

impl crate::orchestrator::event_observer::OrchestratorEventObserver for EventCallbackAdapter {
    fn on_conversation_quarantined(
        &self,
        convo_id: &str,
        reason: crate::orchestrator::types::QuarantineReason,
        suspected_dids: Vec<String>,
    ) {
        self.0.on_conversation_quarantined(
            convo_id.to_string(),
            qreason_to_ffi(reason),
            suspected_dids,
        );
    }
    fn on_conversation_quarantine_cleared(
        &self,
        convo_id: &str,
        via: crate::orchestrator::types::QuarantineExitReason,
    ) {
        self.0
            .on_conversation_quarantine_cleared(convo_id.to_string(), qexit_to_ffi(via));
    }
    fn on_recovery_storage_write_failed(&self, convo_id: &str, operation: &str, error: &str) {
        self.0.on_recovery_storage_write_failed(
            convo_id.to_string(),
            operation.to_string(),
            error.to_string(),
        );
    }
    fn on_credential_binding_warning(
        &self,
        convo_id: &str,
        operation: &str,
        expected_did: &str,
        claimed_identity: &str,
        reason: &str,
    ) {
        self.0.on_credential_binding_warning(
            convo_id.to_string(),
            operation.to_string(),
            expected_did.to_string(),
            claimed_identity.to_string(),
            reason.to_string(),
        );
    }
    fn on_sequencer_equivocation(
        &self,
        convo_id: &str,
        epoch: i32,
        stored_commit_hash_hex: &str,
        new_commit_hash_hex: &str,
        sequencer_did: &str,
    ) {
        self.0.on_sequencer_equivocation(
            convo_id.to_string(),
            epoch,
            stored_commit_hash_hex.to_string(),
            new_commit_hash_hex.to_string(),
            sequencer_did.to_string(),
        );
    }
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
    /// Server returned a structured HTTP error. Used by Welcome / GroupInfo
    /// fetch paths so the orchestrator can distinguish 404/410 ("no data
    /// available for this device") from transport-level failures.
    #[error("Server error: status={status}, body={body}")]
    ServerError { status: u16, body: String },
    #[error(
        "Missing security capability {capability} (contract version {required_version}, declared version {declared_version})"
    )]
    MissingSecurityCapability {
        capability: String,
        required_version: u16,
        declared_version: u16,
    },
    /// Layer 3 quarantine: send/encrypt or auto-rejoin was refused because the
    /// conversation is in Quarantined state. Platforms should surface this to
    /// the UI (banner + disabled composer) and only clear via
    /// user_confirmed_manual_reset, server-pushed groupResetEvent, or a healthy
    /// peer commit.
    #[error("Conversation {convo_id} is quarantined ({reason})")]
    ConversationQuarantined { convo_id: String, reason: String },
}

// FFI projection of Rust's internal `ConversationState` into the Swift
// `ConversationRecoveryState` vocabulary. This is additive: callers that do
// not opt into the orchestrator authority path can ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FFIConversationRecoveryState {
    Healthy,
    EpochBehind,
    GroupMissing,
    NeedsRejoin,
    Recovering,
    UnrecoverableLocal,
    ResetPending,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FFIJoinOrRejoinResult {
    pub epoch: u64,
    pub recovery_state: FFIConversationRecoveryState,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FFIConversationReadyResult {
    pub recovery_state: FFIConversationRecoveryState,
    pub epoch: Option<u64>,
    pub send_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FFIDebugWipeLocalGroupResult {
    pub conversation_id: String,
    pub group_id: Option<String>,
    pub deleted_local_group: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FFIStartupReconcileReport {
    pub scanned: u32,
    pub healthy: u32,
    pub needs_rejoin: u32,
    pub reset_pending: u32,
    pub unrecoverable_local: u32,
}

impl From<StartupReconcileReport> for FFIStartupReconcileReport {
    fn from(value: StartupReconcileReport) -> Self {
        Self {
            scanned: value.scanned,
            healthy: value.healthy,
            needs_rejoin: value.needs_rejoin,
            reset_pending: value.reset_pending,
            unrecoverable_local: value.unrecoverable_local,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FFIDeferredRecoveryReport {
    pub scanned: u32,
    pub attempted: u32,
    pub recovered: u32,
    pub skipped: u32,
    pub failed: u32,
}

impl From<DeferredRecoveryReport> for FFIDeferredRecoveryReport {
    fn from(value: DeferredRecoveryReport) -> Self {
        Self {
            scanned: value.scanned,
            attempted: value.attempted,
            recovered: value.recovered,
            skipped: value.skipped,
            failed: value.failed,
        }
    }
}

impl From<crate::orchestrator::ConversationReadyResult> for FFIConversationReadyResult {
    fn from(value: crate::orchestrator::ConversationReadyResult) -> Self {
        Self {
            recovery_state: ffi_conversation_recovery_state(value.recovery_state),
            epoch: value.epoch,
            send_allowed: value.send_allowed,
        }
    }
}

impl From<DebugWipeLocalGroupResult> for FFIDebugWipeLocalGroupResult {
    fn from(value: DebugWipeLocalGroupResult) -> Self {
        Self {
            conversation_id: value.conversation_id,
            group_id: value.group_id,
            deleted_local_group: value.deleted_local_group,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FFIResetRecordOutcome {
    Recorded,
    StaleOrDuplicate,
    SelfEchoNoOp,
}

impl From<ResetRecordOutcome> for FFIResetRecordOutcome {
    fn from(value: ResetRecordOutcome) -> Self {
        match value {
            ResetRecordOutcome::Recorded => FFIResetRecordOutcome::Recorded,
            ResetRecordOutcome::StaleOrDuplicate => FFIResetRecordOutcome::StaleOrDuplicate,
            ResetRecordOutcome::SelfEchoNoOp => FFIResetRecordOutcome::SelfEchoNoOp,
        }
    }
}

fn ffi_conversation_recovery_state(
    state: crate::orchestrator::ConversationRecoveryState,
) -> FFIConversationRecoveryState {
    match state {
        crate::orchestrator::ConversationRecoveryState::Healthy => {
            FFIConversationRecoveryState::Healthy
        }
        crate::orchestrator::ConversationRecoveryState::EpochBehind => {
            FFIConversationRecoveryState::EpochBehind
        }
        crate::orchestrator::ConversationRecoveryState::GroupMissing => {
            FFIConversationRecoveryState::GroupMissing
        }
        crate::orchestrator::ConversationRecoveryState::NeedsRejoin => {
            FFIConversationRecoveryState::NeedsRejoin
        }
        crate::orchestrator::ConversationRecoveryState::Recovering => {
            FFIConversationRecoveryState::Recovering
        }
        crate::orchestrator::ConversationRecoveryState::UnrecoverableLocal => {
            FFIConversationRecoveryState::UnrecoverableLocal
        }
        crate::orchestrator::ConversationRecoveryState::ResetPending => {
            FFIConversationRecoveryState::ResetPending
        }
    }
}

async fn project_conversation_recovery_state_for(
    inner: &ConcreteOrchestrator,
    conversation_id: &str,
) -> FFIConversationRecoveryState {
    ffi_conversation_recovery_state(
        inner
            .project_conversation_recovery_state(conversation_id)
            .await,
    )
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
            OrchestratorError::ResetCompletionNotCommitted {
                convo_id,
                reset_generation,
                reason,
            } => OrchestratorBridgeError::RecoveryFailed {
                message: format!(
                    "Reset completion not committed for conversation {convo_id}, generation {reset_generation}: {reason}"
                ),
            },
            OrchestratorError::InvalidInput(s) => {
                OrchestratorBridgeError::InvalidInput { message: s }
            }
            OrchestratorError::ServerError { status, body } => {
                OrchestratorBridgeError::ServerError { status, body }
            }
            OrchestratorError::ConversationQuarantined { convo_id, reason } => {
                OrchestratorBridgeError::ConversationQuarantined { convo_id, reason }
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
struct CredentialAdapter(
    Arc<dyn OrchestratorCredentialCallback>,
    Arc<std::sync::RwLock<std::collections::HashMap<String, i64>>>,
);

impl CredentialAdapter {
    fn new(callback: Arc<dyn OrchestratorCredentialCallback>) -> Self {
        Self(
            callback,
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        )
    }
}

// -- Conversion helpers --

fn convo_view_to_ffi(cv: &ConversationView) -> crate::orchestrator::Result<FFIConversationView> {
    crate::orchestrator::admission::validate_conversation_view(cv)?;
    let canonical_state_json = cv
        .canonical_state
        .as_ref()
        .map(|state| {
            crate::orchestrator::canonical_transport::encode_conversation_state(state)
                .map(|bytes| String::from_utf8(bytes).expect("JSON is UTF-8"))
                .map_err(|error| {
                    crate::orchestrator::OrchestratorError::InvalidInput(error.to_string())
                })
        })
        .transpose()?;
    Ok(FFIConversationView {
        canonical_state_json,
        group_id: cv.group_id.clone(),
        conversation_id: cv.conversation_id.clone(),
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
    })
}

fn ffi_to_convo_view(ffi: &FFIConversationView) -> crate::orchestrator::Result<ConversationView> {
    let canonical_state = ffi
        .canonical_state_json
        .as_ref()
        .map(|json| {
            crate::orchestrator::canonical_transport::decode_conversation_state(json.as_bytes())
                .map_err(|error| {
                    crate::orchestrator::OrchestratorError::InvalidInput(error.to_string())
                })
        })
        .transpose()?;
    let view = ConversationView {
        canonical_state,
        group_id: ffi.group_id.clone(),
        conversation_id: ffi.conversation_id.clone(),
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
        // FFIConversationView does not carry sequencerDid yet (WS-4 rung 3,
        // ADR-010 A6): UniFFI record shapes are deliberately unchanged in
        // rung 2.
        sequencer_did: None,
    };
    crate::orchestrator::admission::validate_conversation_view(&view)?;
    Ok(view)
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

pub(crate) fn ffi_incoming_envelope_to_internal(
    envelope: FFIIncomingEnvelope,
    server_epoch: Option<u64>,
) -> crate::orchestrator::Result<IncomingEnvelope> {
    if envelope
        .server_epoch
        .zip(server_epoch)
        .is_some_and(|(field, argument)| field != argument)
    {
        return Err(crate::orchestrator::OrchestratorError::InvalidInput(
            "Conflicting incoming message epochs".into(),
        ));
    }
    if envelope.server_sequence.is_some() {
        crate::chat_v2::ids::CanonicalTimestamp::parse(&envelope.timestamp).map_err(|_| {
            crate::orchestrator::OrchestratorError::InvalidInput(
                "Invalid canonical message timestamp".into(),
            )
        })?;
    }
    let timestamp = envelope
        .timestamp
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| {
            crate::orchestrator::OrchestratorError::InvalidInput(
                "Invalid incoming message timestamp".into(),
            )
        })?;
    let result = IncomingEnvelope {
        conversation_id: envelope.conversation_id,
        sender_did: envelope.sender_did,
        ciphertext: envelope.ciphertext,
        timestamp,
        server_message_id: envelope.server_message_id,
        server_sequence: envelope.server_sequence,
        server_epoch: envelope.server_epoch.or(server_epoch),
    };
    result.validate_server_metadata()?;
    Ok(result)
}

fn engine_event_to_ffi(event: &EngineEvent) -> FFIEngineEvent {
    match event {
        EngineEvent::ConversationUpdated { convo_id } => FFIEngineEvent {
            kind: FFIEngineEventKind::ConversationUpdated,
            conversation_id: convo_id.clone(),
            message_id: None,
            recovery_state: None,
        },
        EngineEvent::MessageInserted {
            message_id,
            convo_id,
        } => FFIEngineEvent {
            kind: FFIEngineEventKind::MessageInserted,
            conversation_id: convo_id.clone(),
            message_id: Some(message_id.clone()),
            recovery_state: None,
        },
        EngineEvent::RecoveryStateChanged { convo_id, state } => FFIEngineEvent {
            kind: FFIEngineEventKind::RecoveryStateChanged,
            conversation_id: convo_id.clone(),
            message_id: None,
            recovery_state: Some(ffi_conversation_recovery_state(*state)),
        },
        EngineEvent::NeedsUiRefresh { convo_id } => FFIEngineEvent {
            kind: FFIEngineEventKind::NeedsUiRefresh,
            conversation_id: convo_id.clone(),
            message_id: None,
            recovery_state: None,
        },
    }
}

fn engine_events_to_ffi(events: &[EngineEvent]) -> Vec<FFIEngineEvent> {
    events.iter().map(engine_event_to_ffi).collect()
}

fn ffi_reaction_action(
    action: &str,
) -> Result<crate::orchestrator::types::ReactionAction, OrchestratorBridgeError> {
    match action {
        "add" => Ok(crate::orchestrator::types::ReactionAction::Add),
        "remove" => Ok(crate::orchestrator::types::ReactionAction::Remove),
        other => Err(OrchestratorBridgeError::InvalidInput {
            message: format!("Unsupported reaction action: {other}"),
        }),
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

// -- Sender-side three-phase commit API (task #44) conversions --

fn ffi_commit_kind_to_internal(kind: FFICommitKind) -> crate::orchestrator::types::CommitKind {
    use crate::orchestrator::types::CommitKind;
    match kind {
        FFICommitKind::AddMembers {
            member_dids,
            key_packages,
        } => CommitKind::AddMembers {
            member_dids,
            key_packages: key_packages
                .into_iter()
                .map(|data| crate::KeyPackageData { data })
                .collect(),
        },
        FFICommitKind::RemoveMembers { member_dids } => CommitKind::RemoveMembers { member_dids },
        FFICommitKind::SwapMembers {
            remove_dids,
            add_dids,
            add_key_packages,
        } => CommitKind::SwapMembers {
            remove_dids,
            add_dids,
            add_key_packages: add_key_packages
                .into_iter()
                .map(|data| crate::KeyPackageData { data })
                .collect(),
        },
        FFICommitKind::UpdateMetadata {
            group_info_extension,
        } => CommitKind::UpdateMetadata {
            group_info_extension,
        },
    }
}

fn commit_plan_to_ffi(plan: &crate::orchestrator::types::CommitPlan) -> FFICommitPlan {
    FFICommitPlan {
        handle: FFIStagedCommitHandle {
            group_id: plan.handle.group_id.clone(),
            nonce: plan.handle.nonce,
        },
        commit_bytes: plan.commit_bytes.clone(),
        welcome_bytes: plan.welcome_bytes.clone(),
        group_info: plan.group_info.clone(),
        source_epoch: plan.source_epoch,
        target_epoch: plan.target_epoch,
    }
}

fn ffi_staged_handle_to_internal(
    handle: FFIStagedCommitHandle,
) -> crate::orchestrator::types::StagedCommitHandle {
    crate::orchestrator::types::StagedCommitHandle {
        group_id: handle.group_id,
        nonce: handle.nonce,
    }
}

fn bridge_err(e: OrchestratorBridgeError) -> OrchestratorError {
    bridge_mappers::bridge_error_to_internal(e)
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
            .map_err(bridge_err)?
            .as_ref()
            .map(ffi_to_convo_view)
            .transpose()
    }

    async fn list_conversations(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Vec<ConversationView>> {
        self.0
            .list_conversations(user_did.to_string())
            .map_err(bridge_err)?
            .iter()
            .map(ffi_to_convo_view)
            .collect()
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
        // This general projection callback never publishes ResetPending.
        // `mark_reset_pending` is the sole atomic tag + payload + rejoin-route
        // publication operation for that security authority.
        self.0
            .set_conversation_state(conversation_id.to_string(), state.tag().to_string())
            .map_err(bridge_err)
    }

    async fn clear_device_removal_after_verified_welcome(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_conversation_state(
                conversation_id.to_string(),
                "active_after_welcome".to_string(),
            )
            .map_err(bridge_err)
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> crate::orchestrator::Result<bool> {
        if !matches!(
            terminal_state,
            ConversationState::Closed | ConversationState::DeviceRemoved
        ) {
            return Err(crate::orchestrator::OrchestratorError::Storage(
                "invalid account exit state".into(),
            ));
        }
        self.0
            .complete_account_exit(
                conversation_id.into(),
                expected_group_id_hex.into(),
                expected_reset_generation,
                terminal_epoch,
                terminal_state.tag().into(),
            )
            .map_err(bridge_err)
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<Option<ConversationState>> {
        self.0
            .get_conversation_state(conversation_id.to_string())
            .map_err(bridge_err)?
            .map(bridge_mappers::ffi_conversation_state_to_internal)
            .transpose()
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .mark_reset_pending(
                conversation_id.to_string(),
                new_group_id_hex.to_string(),
                reset_generation,
                notified_at_ms,
            )
            .map_err(bridge_err)
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> crate::orchestrator::Result<bool> {
        self.0
            .adopt_reset_pending_target(
                conversation_id.to_string(),
                expected_generation,
                expected_old_target.to_string(),
                authoritative_new_target.to_string(),
            )
            .map_err(bridge_err)
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> crate::orchestrator::Result<bool> {
        self.0
            .complete_reset_pending(
                conversation_id.to_string(),
                expected_generation,
                expected_new_group_id_hex.to_string(),
                landed_epoch,
            )
            .map_err(bridge_err)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> crate::orchestrator::Result<bool> {
        self.0
            .clear_reset_pending_for_delete(conversation_id.to_string(), expected_generation)
            .map_err(bridge_err)
    }

    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .mark_quarantined(
                conversation_id.to_string(),
                reason_tag.to_string(),
                since_ms,
            )
            .map_err(bridge_err)
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .clear_quarantine(conversation_id.to_string())
            .map_err(bridge_err)
    }

    // WS-5.6 capabilities declaration: the bridge forwards these optional
    // methods to the platform callback; everything else still rides the
    // default no-ops (warned at orchestrator init).
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
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

    // -- RecoveryTracker persistence (WS-5.4, invariant E7) --

    async fn get_recovery_state(&self) -> crate::orchestrator::Result<PersistedRecoveryState> {
        self.0
            .get_recovery_state()
            .map(|ffi| PersistedRecoveryState {
                entries: ffi
                    .entries
                    .into_iter()
                    .map(|e| PersistedRecoveryBackoff {
                        conversation_id: e.conversation_id,
                        failed_rejoin_count: e.failed_rejoin_count,
                        last_attempt_at_ms: e.last_attempt_at_ms,
                        quarantined_until_ms: e.quarantined_until_ms,
                    })
                    .collect(),
                last_global_rejoin_attempt_at_ms: ffi.last_global_rejoin_attempt_at_ms,
            })
            .map_err(bridge_err)
    }

    async fn set_recovery_backoff(
        &self,
        entry: &PersistedRecoveryBackoff,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_recovery_backoff(FFIPersistedRecoveryBackoff {
                conversation_id: entry.conversation_id.clone(),
                failed_rejoin_count: entry.failed_rejoin_count,
                last_attempt_at_ms: entry.last_attempt_at_ms,
                quarantined_until_ms: entry.quarantined_until_ms,
            })
            .map_err(bridge_err)
    }

    async fn clear_recovery_backoff(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .clear_recovery_backoff(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn set_last_global_rejoin_attempt_at(
        &self,
        at_ms: i64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_last_global_rejoin_attempt_at(at_ms)
            .map_err(bridge_err)
    }

    // -- Pending local deletes (WS-5.3 crash-safe force_delete_local) --

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .mark_pending_local_delete(
                conversation_id.to_string(),
                group_id_hex.map(|s| s.to_string()),
            )
            .map_err(bridge_err)
    }

    async fn clear_pending_local_delete(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .clear_pending_local_delete(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn list_pending_local_deletes(
        &self,
    ) -> crate::orchestrator::Result<Vec<PendingLocalDelete>> {
        self.0
            .list_pending_local_deletes()
            .map(|v| {
                v.into_iter()
                    .map(|ffi| PendingLocalDelete {
                        conversation_id: ffi.conversation_id,
                        group_id_hex: ffi.group_id_hex,
                    })
                    .collect()
            })
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

    async fn store_pending_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_pending_message(conversation_id.to_string(), message_id.to_string())
            .map_err(bridge_err)
    }

    async fn remove_pending_message(&self, message_id: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .remove_pending_message(message_id.to_string())
            .map_err(bridge_err)
    }

    async fn store_sequencer_receipt(
        &self,
        receipt: &crate::orchestrator::types::SequencerReceipt,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_sequencer_receipt(bridge_mappers::receipt_to_ffi(receipt.clone()))
            .map_err(bridge_err)
    }

    async fn get_sequencer_receipts(
        &self,
        convo_id: &str,
        since_epoch: Option<i32>,
    ) -> crate::orchestrator::Result<Vec<crate::orchestrator::types::SequencerReceipt>> {
        self.0
            .get_sequencer_receipts(convo_id.to_string(), since_epoch)
            .map(|receipts| {
                receipts
                    .into_iter()
                    .map(bridge_mappers::ffi_receipt_to_internal)
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn clear_sequencer_receipts(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .clear_sequencer_receipts(conversation_id.to_string())
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

    async fn submit_prepared_request(
        &self,
        request: crate::orchestrator::canonical_transport::PreparedRequest,
    ) -> crate::orchestrator::Result<crate::orchestrator::canonical_transport::GatewayResponse>
    {
        let route = request.operation.route();
        let query_bytes = if request.method == "GET" && request.path.contains('?') {
            request
                .path
                .split_once('?')
                .map(|(_, q)| q.as_bytes().to_vec())
        } else {
            None
        };
        let ffi_res = self
            .0
            .submit_prepared_request(
                request.method,
                route.nsid.to_string(),
                request.body,
                query_bytes,
            )
            .map_err(bridge_err)?;
        Ok(crate::orchestrator::canonical_transport::GatewayResponse {
            status: ffi_res.status,
            content_type: ffi_res.content_type,
            body: ffi_res.body,
        })
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> crate::orchestrator::Result<ConversationListPage> {
        let ffi = self
            .0
            .get_conversations(limit, cursor.map(str::to_string))
            .map_err(bridge_err)?;
        Ok(ConversationListPage {
            conversations: ffi
                .conversations
                .iter()
                .map(ffi_to_convo_view)
                .collect::<crate::orchestrator::Result<Vec<_>>>()?,
            cursor: ffi.cursor,
        })
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> crate::orchestrator::Result<(Vec<IncomingEnvelope>, Option<String>)> {
        self.0
            .get_messages(
                convo_id.to_string(),
                cursor.map(|s| s.to_string()),
                limit,
                message_type.map(|s| s.to_string()),
                from_epoch,
                to_epoch,
            )
            .map_err(bridge_err)
            .and_then(|ffi| {
                let envelopes = ffi
                    .envelopes
                    .into_iter()
                    .map(|m| ffi_incoming_envelope_to_internal(m, None))
                    .collect::<crate::orchestrator::Result<Vec<_>>>()?;
                Ok((envelopes, ffi.cursor))
            })
    }

    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        dids: &[String],
    ) -> crate::orchestrator::Result<Vec<KeyPackageRef>> {
        self.0
            .get_key_packages(actor_device_id.to_string(), dids.to_vec())
            .map(|refs| {
                refs.into_iter()
                    .map(|r| KeyPackageRef {
                        did: r.did,
                        key_package_data: r.key_package_data,
                        hash: r.hash,
                        cipher_suite: r.cipher_suite,
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
    async fn list_devices(
        &self,
        actor_device_id: &str,
    ) -> crate::orchestrator::Result<Vec<DeviceInfo>> {
        self.0
            .list_devices(actor_device_id.to_string())
            .map(|devices| {
                devices
                    .into_iter()
                    .map(|d| DeviceInfo {
                        device_id: d.device_id,
                        mls_did: d.mls_did,
                        device_uuid: d.device_uuid,
                        created_at: d
                            .created_at
                            .as_ref()
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc)),
                        key_id: d.key_id,
                        signature_public_key: d.signature_public_key,
                        auth_generation: d.auth_generation,
                        status: d.status,
                        available_package_count: d.available_package_count,
                        reserved_package_count: d.reserved_package_count,
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn get_group_info(&self, convo_id: &str) -> crate::orchestrator::Result<Vec<u8>> {
        self.0
            .get_group_info(convo_id.to_string())
            .map_err(bridge_err)
    }

    async fn get_welcome(&self, convo_id: &str) -> crate::orchestrator::Result<Vec<u8>> {
        self.0.get_welcome(convo_id.to_string()).map_err(bridge_err)
    }

    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> crate::orchestrator::Result<Vec<(String, crate::orchestrator::types::DeliveryStatus)>>
    {
        self.0
            .get_delivery_status(convo_id.to_string(), message_ids.to_vec())
            .map(|list| {
                list.into_iter()
                    .map(|pair| (pair.message_id, ffi_to_delivery_status(&pair.status)))
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn get_group_metadata_blob(
        &self,
        convo_id: &str,
        group_id_hex: &str,
        blob_locator: &str,
    ) -> crate::orchestrator::Result<Vec<u8>> {
        self.0
            .get_group_metadata_blob(
                convo_id.to_string(),
                group_id_hex.to_string(),
                blob_locator.to_string(),
            )
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

    async fn sign_clean_chat_transcript(
        &self,
        user_did: &str,
        transcript: &[u8],
        key_id: &str,
    ) -> crate::orchestrator::Result<Option<CleanChatSigningAuthority>> {
        let authority = self
            .0
            .sign_clean_chat_transcript(
                user_did.to_string(),
                transcript.to_vec(),
                key_id.to_string(),
            )
            .map_err(bridge_err)?
            .map(|authority| {
                if let Some(gen) = authority.auth_generation {
                    if let Ok(mut lock) = self.1.write() {
                        lock.insert(user_did.to_string(), gen);
                    }
                }
                CleanChatSigningAuthority {
                    public_key: authority.public_key,
                    signature: authority.signature,
                    device_id: authority.device_id,
                    auth_generation: authority.auth_generation,
                }
            });
        Ok(authority)
    }

    async fn get_auth_generation(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Option<i64>> {
        if let Ok(lock) = self.1.read() {
            if let Some(&gen) = lock.get(user_did) {
                return Ok(Some(gen));
            }
        }
        Ok(Some(1))
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

    async fn get_authorized_device_keys(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Option<Vec<Vec<u8>>>> {
        self.0
            .get_authorized_device_keys(user_did.to_string())
            .map_err(bridge_err)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The main UniFFI-exported object
// ═══════════════════════════════════════════════════════════════════════════

type ConcreteOrchestrator =
    MLSOrchestrator<StorageAdapter, APIAdapter, CredentialAdapter, MLSContext>;
type ConcreteEngine = MlsEngine<StorageAdapter, APIAdapter, CredentialAdapter, MLSContext>;

/// UniFFI-exported MLS Orchestrator object.
///
/// Wraps the generic MLSOrchestrator with callback-based trait implementations.
/// Swift/Kotlin provides the platform-specific storage, API, and credential backends.
#[derive(uniffi::Object)]
pub struct OrchestratorBridge {
    inner: Arc<ConcreteOrchestrator>,
    engine: Arc<ConcreteEngine>,
    lifecycle_transition: std::sync::Mutex<()>,
    user_lifecycle_generation: std::sync::atomic::AtomicU64,
    user_lifecycle_transitions: std::sync::atomic::AtomicUsize,
}

struct UserLifecycleTransition<'a> {
    bridge: &'a OrchestratorBridge,
}

impl Drop for UserLifecycleTransition<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        self.bridge
            .user_lifecycle_generation
            .fetch_add(1, Ordering::SeqCst);
        self.bridge
            .user_lifecycle_transitions
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl OrchestratorBridge {
    fn begin_user_lifecycle_transition(&self) -> UserLifecycleTransition<'_> {
        use std::sync::atomic::Ordering;

        self.user_lifecycle_transitions
            .fetch_add(1, Ordering::SeqCst);
        self.user_lifecycle_generation
            .fetch_add(1, Ordering::SeqCst);
        UserLifecycleTransition { bridge: self }
    }

    fn stable_user_lifecycle_generation(&self) -> Result<u64, OrchestratorBridgeError> {
        use std::sync::atomic::Ordering;

        if self.user_lifecycle_transitions.load(Ordering::SeqCst) != 0 {
            return Err(OrchestratorBridgeError::NotAuthenticated);
        }
        let generation = self.user_lifecycle_generation.load(Ordering::SeqCst);
        if self.user_lifecycle_transitions.load(Ordering::SeqCst) != 0 {
            return Err(OrchestratorBridgeError::NotAuthenticated);
        }
        Ok(generation)
    }

    fn require_stable_user_lifecycle(
        &self,
        expected_generation: u64,
        expected_user_did: &str,
    ) -> Result<(), OrchestratorBridgeError> {
        use std::sync::atomic::Ordering;

        if self.user_lifecycle_transitions.load(Ordering::SeqCst) != 0
            || self.user_lifecycle_generation.load(Ordering::SeqCst) != expected_generation
        {
            return Err(OrchestratorBridgeError::NotAuthenticated);
        }
        let current_user_did = crate::async_runtime::block_on(self.inner.require_user_did())?;
        if current_user_did != expected_user_did
            || self.user_lifecycle_transitions.load(Ordering::SeqCst) != 0
            || self.user_lifecycle_generation.load(Ordering::SeqCst) != expected_generation
        {
            return Err(OrchestratorBridgeError::NotAuthenticated);
        }
        Ok(())
    }

    fn lock_lifecycle_transition(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, ()>, OrchestratorBridgeError> {
        self.lifecycle_transition
            .lock()
            .map_err(|_| OrchestratorBridgeError::InvalidInput {
                message: "orchestrator bridge lifecycle lock poisoned".to_string(),
            })
    }

    fn sign_device_auth_challenge_with_hook<F>(
        &self,
        challenge: Vec<u8>,
        before_sign: F,
    ) -> Result<Vec<u8>, OrchestratorBridgeError>
    where
        F: FnOnce(),
    {
        if challenge.is_empty() {
            return Err(OrchestratorBridgeError::InvalidInput {
                message: "device authentication challenge must not be empty".to_string(),
            });
        }

        let user_lifecycle_generation = self.stable_user_lifecycle_generation()?;
        let user_did = crate::async_runtime::block_on(self.inner.require_user_did())?;
        self.require_stable_user_lifecycle(user_lifecycle_generation, &user_did)?;

        // Credential callbacks may re-enter the bridge, so durable signer
        // reconciliation must happen before taking the non-reentrant mutex.
        // Any concurrent user transition is detected by the generation checks.
        if matches!(
            crate::async_runtime::block_on(self.inner.reconcile_durable_signer(&user_did))?,
            Some(false)
        ) {
            return Err(OrchestratorBridgeError::Mls {
                message: "durable registered signer could not be reconciled".to_string(),
            });
        }
        self.require_stable_user_lifecycle(user_lifecycle_generation, &user_did)?;

        let _lifecycle_transition = self.lock_lifecycle_transition()?;
        self.require_stable_user_lifecycle(user_lifecycle_generation, &user_did)?;
        before_sign();
        let signature = self
            .inner
            .mls_context()
            .sign_with_identity_key(user_did.clone(), challenge)
            .map_err(|error| OrchestratorBridgeError::Mls {
                message: error.to_string(),
            })?;

        // Never release a signature produced while the authenticated user or
        // lifecycle changed, even if the transition completed during signing.
        self.require_stable_user_lifecycle(user_lifecycle_generation, &user_did)?;

        if signature.len() != 64 {
            return Err(OrchestratorBridgeError::Mls {
                message: format!(
                    "device authentication signer returned {} bytes; expected 64-byte Ed25519 signature",
                    signature.len()
                ),
            });
        }

        Ok(signature)
    }

    fn shutdown_with_hook<F>(&self, before_lock: F)
    where
        F: FnOnce(),
    {
        before_lock();
        let _lifecycle_transition = self
            .lifecycle_transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::async_runtime::block_on(self.inner.shutdown());
    }
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
        capabilities: SecurityStorageCapabilities,
        config: FFIOrchestratorConfig,
    ) -> Result<Arc<Self>, OrchestratorBridgeError> {
        bridge_mappers::validate_security_capabilities(&capabilities)?;
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

        let storage = Arc::new(StorageAdapter(Arc::from(storage)));
        let api_client = Arc::new(APIAdapter(Arc::from(api_client)));
        let credentials = Arc::new(CredentialAdapter::new(Arc::from(credentials)));
        let engine = Arc::new(MlsEngine::new(
            mls_context,
            storage,
            api_client,
            credentials,
            Arc::new(EngineLifecycle::default()),
            orch_config,
        ));
        let inner = engine.orchestrator();

        Ok(Arc::new(Self {
            inner,
            engine,
            lifecycle_transition: std::sync::Mutex::new(()),
            user_lifecycle_generation: std::sync::atomic::AtomicU64::new(0),
            user_lifecycle_transitions: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// Initialize the orchestrator for a user DID.
    pub fn initialize(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
        let _user_lifecycle_transition = self.begin_user_lifecycle_transition();
        crate::async_runtime::block_on(self.inner.initialize(&user_did))?;
        Ok(())
    }

    /// Sign a server-issued device-authentication challenge with the
    /// initialized user's persistent MLS identity key.
    ///
    /// The caller cannot select an identity or access key material. The
    /// signature is bound to the user DID owned by this orchestrator's active
    /// lifecycle, and is therefore refused before initialization or after
    /// shutdown.
    pub fn sign_device_auth_challenge(
        &self,
        challenge: Vec<u8>,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        self.sign_device_auth_challenge_with_hook(challenge, || {})
    }

    /// Prepare a canonical clean-chat signed mutation.
    ///
    /// This method accepts only actor/device binding metadata. It deliberately
    /// returns no Authorization or DPoP proof: direct-DS and Nest-proxy
    /// adapters attach their own transport credentials after signing.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prepare_clean_chat_signed_request(
        &self,
        binding: CleanChatSigningContextFfi,
        operation: CleanChatOperationFfi,
        body_json: Vec<u8>,
    ) -> Result<CleanChatPreparedRequestFfi, CleanChatTransportFfiError> {
        let prepared =
            crate::async_runtime::block_on(self.inner.prepare_clean_chat_signed_request(
                binding.into(),
                operation.into(),
                body_json,
            ))
            .map_err(|error| CleanChatTransportFfiError::InvalidRequest {
                message: error.to_string(),
            })?;
        Ok(CleanChatPreparedRequestFfi {
            operation: prepared.operation.into(),
            method: prepared.method,
            path: prepared.path,
            body: prepared.body,
        })
    }
    /// Shut down the orchestrator.
    pub fn shutdown(&self) {
        self.shutdown_with_hook(|| {});
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
        Ok(convo_view_to_ffi(&convo)?)
    }

    /// Create a new MLS conversation through the Rust-owned engine and
    /// return the conversation snapshot needed by full-authority clients.
    pub fn create_conversation(
        &self,
        name: String,
        initial_members: Option<Vec<String>>,
        description: Option<String>,
    ) -> Result<FFICreateConversationResult, OrchestratorBridgeError> {
        let result = self
            .engine
            .create_conversation(CreateConversationRequest {
                name,
                member_dids: initial_members.unwrap_or_default(),
                description,
            })
            .map_err(OrchestratorBridgeError::from)?;
        Ok(FFICreateConversationResult {
            conversation: convo_view_to_ffi(&result.conversation)?,
            commit_data: result.commit_data,
            welcome_data: result.welcome_data,
        })
    }

    /// Join an existing group via Welcome message.
    pub fn join_group(
        &self,
        welcome_data: Vec<u8>,
    ) -> Result<FFIConversationView, OrchestratorBridgeError> {
        let convo = crate::async_runtime::block_on(self.inner.join_group(&welcome_data))?;
        Ok(convo_view_to_ffi(&convo)?)
    }

    /// Add members to an existing group.
    pub fn add_members(
        &self,
        group_id: String,
        member_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        // The exported parameter name is retained for ABI compatibility with
        // legacy callers that still pass the mutable MLS group id.
        crate::async_runtime::block_on(async {
            let resolved = self
                .inner
                .resolve_legacy_group_identifier(&group_id)
                .await?;
            if !member_dids.is_empty() {
                self.inner
                    .swap_members(&resolved.conversation_id, &[], &member_dids)
                    .await?;
            }
            Ok::<(), OrchestratorError>(())
        })?;
        Ok(())
    }

    /// Add members through the Rust-owned engine and return the updated
    /// conversation snapshot for full-authority clients.
    pub fn add_members_result(
        &self,
        conversation_id: String,
        member_dids: Vec<String>,
    ) -> Result<FFIGroupMutationResult, OrchestratorBridgeError> {
        let result: GroupMutationResult = self
            .engine
            .add_members(&conversation_id, &member_dids)
            .map_err(OrchestratorBridgeError::from)?;
        Ok(FFIGroupMutationResult {
            conversation: convo_view_to_ffi(&result.conversation)?,
        })
    }

    /// Remove members from a group.
    pub fn remove_members(
        &self,
        group_id: String,
        member_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        // The exported parameter name is retained for ABI compatibility with
        // legacy callers that still pass the mutable MLS group id.
        crate::async_runtime::block_on(async {
            let resolved = self
                .inner
                .resolve_legacy_group_identifier(&group_id)
                .await?;
            self.inner
                .remove_members(&resolved.conversation_id, &member_dids)
                .await
        })?;
        Ok(())
    }

    /// Remove members through the Rust-owned engine and return the updated
    /// conversation snapshot for full-authority clients.
    pub fn remove_members_result(
        &self,
        conversation_id: String,
        member_dids: Vec<String>,
    ) -> Result<FFIGroupMutationResult, OrchestratorBridgeError> {
        let result: GroupMutationResult = self
            .engine
            .remove_members(&conversation_id, &member_dids)
            .map_err(OrchestratorBridgeError::from)?;
        Ok(FFIGroupMutationResult {
            conversation: convo_view_to_ffi(&result.conversation)?,
        })
    }

    /// Atomically swap members in a single commit.
    pub fn swap_members(
        &self,
        group_id: String,
        remove_dids: Vec<String>,
        add_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        // The exported parameter name is retained for ABI compatibility with
        // legacy callers that still pass the mutable MLS group id.
        crate::async_runtime::block_on(async {
            let resolved = self
                .inner
                .resolve_legacy_group_identifier(&group_id)
                .await?;
            self.inner
                .swap_members(&resolved.conversation_id, &remove_dids, &add_dids)
                .await
        })?;
        Ok(())
    }

    /// Update a group's encrypted metadata (title / description / avatar) for
    /// full-authority (rustFull) clients.
    ///
    /// Stages a GroupContextExtensions commit that embeds a fresh
    /// `MetadataReference`, uploads the re-encrypted metadata blob, submits the
    /// commit, and merges locally. When `avatar_bytes` is provided the avatar
    /// image is encrypted at the SAME post-commit (epoch, metadata_version) and
    /// uploaded to `avatar_blob_locator`, so joiners can fetch + decrypt it.
    ///
    /// The whole desired metadata state must be supplied on every call (the
    /// commit replaces the blob): to rename without dropping the avatar, pass
    /// the current avatar bytes + locator alongside the new title.
    pub fn update_group_metadata_encrypted(
        &self,
        conversation_id: String,
        title: Option<String>,
        description: Option<String>,
        avatar_blob_locator: Option<String>,
        avatar_content_type: Option<String>,
        avatar_bytes: Option<Vec<u8>>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.update_group_metadata_encrypted(
            &conversation_id,
            title.as_deref(),
            description.as_deref(),
            avatar_blob_locator.as_deref(),
            avatar_content_type.as_deref(),
            avatar_bytes.as_deref(),
        ))?;
        Ok(())
    }

    /// Fulfill a Welcome-reissue request as an admin member (rustFull mode).
    /// Mirrors `swap_members` (no external commit): removes the recipient's
    /// stale leaf and re-adds them with a fresh key package, threading
    /// `request_id` as the server idempotency key so the delivery service marks
    /// the reissue request answered.
    pub fn respond_to_welcome_reissue(
        &self,
        convo_id: String,
        recipient_device_did: String,
        request_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.respond_to_welcome_reissue(
            &convo_id,
            &recipient_device_did,
            &request_id,
        ))?;
        Ok(())
    }

    // -- Sender-side three-phase commit API (task #44) --
    //
    // Additive surface for platforms that need to inspect / batch / retry
    // commits before confirming them locally. The existing `add_members` /
    // `remove_members` / `swap_members` / `update_group_metadata` methods
    // above are backward-compatible wrappers around the same API; platforms
    // can migrate to the three-phase API incrementally.

    /// Stage a commit without sending or merging it. Returns a plan; call
    /// [`confirm_commit`](Self::confirm_commit) on DS success or
    /// [`discard_pending`](Self::discard_pending) on failure.
    pub fn stage_commit(
        &self,
        conversation_id: String,
        kind: FFICommitKind,
    ) -> Result<FFICommitPlan, OrchestratorBridgeError> {
        let kind = ffi_commit_kind_to_internal(kind);
        let plan = crate::async_runtime::block_on(self.inner.stage_commit(&conversation_id, kind))?;
        Ok(commit_plan_to_ffi(&plan))
    }

    /// Confirm a previously staged commit: merges it locally, advances the
    /// epoch, publishes updated GroupInfo. Pass `server_epoch = 0` to skip
    /// the fence (for API paths that don't echo an epoch).
    pub fn confirm_commit(
        &self,
        handle: FFIStagedCommitHandle,
        server_epoch: u64,
    ) -> Result<FFIConfirmedCommit, OrchestratorBridgeError> {
        let confirmed = crate::async_runtime::block_on(
            self.inner
                .confirm_commit(ffi_staged_handle_to_internal(handle), server_epoch),
        )?;
        Ok(FFIConfirmedCommit {
            new_epoch: confirmed.new_epoch,
            metadata_key: confirmed.metadata_key,
            metadata_reference: confirmed.metadata_reference,
        })
    }

    /// Discard a staged commit without advancing the epoch. Clears the
    /// pending commit in the MLS crypto context.
    pub fn discard_pending(
        &self,
        handle: FFIStagedCommitHandle,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.inner
                .discard_pending(ffi_staged_handle_to_internal(handle)),
        )?;
        Ok(())
    }

    /// Leave a conversation.
    pub fn leave_group(&self, convo_id: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.leave_group(&convo_id))?;
        Ok(())
    }

    /// Leave a conversation through the Rust-owned engine and return the
    /// identifiers Swift needs to clean up local state immediately.
    pub fn leave_conversation(
        &self,
        conversation_id: String,
    ) -> Result<FFILeaveResult, OrchestratorBridgeError> {
        let result: LeaveResult = self
            .engine
            .leave_conversation(&conversation_id)
            .map_err(OrchestratorBridgeError::from)?;
        Ok(FFILeaveResult {
            conversation_id: result.conversation_id,
            group_id: result.group_id,
        })
    }

    /// Accept an invitation to a conversation (direct or group).
    pub fn accept_conversation(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.accept_conversation(&conversation_id))?;
        Ok(())
    }

    /// Fulfill an open leaf recovery request for a conversation.
    pub fn fulfill_leaf_recovery(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.fulfill_leaf_recovery(&conversation_id))?;
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

    /// Send a JSON-encoded MLS message payload envelope.
    pub fn send_payload_json(
        &self,
        conversation_id: String,
        payload_json: String,
    ) -> Result<FFIMessage, OrchestratorBridgeError> {
        let msg = crate::async_runtime::block_on(
            self.inner
                .send_payload_json(&conversation_id, &payload_json),
        )?;
        Ok(message_to_ffi(&msg))
    }

    /// Send a JSON-encoded MLS message payload through the Rust-owned engine.
    pub fn send_payload_result_json(
        &self,
        conversation_id: String,
        payload_json: String,
    ) -> Result<FFISendResult, OrchestratorBridgeError> {
        let result = self
            .engine
            .send_payload(&conversation_id, &payload_json)
            .map_err(OrchestratorBridgeError::from)?;
        Ok(FFISendResult {
            message: message_to_ffi(&result.message),
            events: engine_events_to_ffi(&result.events),
        })
    }

    /// Process a server event envelope through the Rust-owned engine.
    pub fn process_server_event(
        &self,
        event_json: String,
    ) -> Result<Vec<FFIEngineEvent>, OrchestratorBridgeError> {
        let events = self
            .engine
            .process_server_event(&event_json)
            .map_err(OrchestratorBridgeError::from)?;
        Ok(engine_events_to_ffi(&events))
    }

    /// Send an encrypted reaction payload.
    pub fn send_reaction(
        &self,
        conversation_id: String,
        message_id: String,
        emoji: String,
        action: String,
    ) -> Result<FFIMessage, OrchestratorBridgeError> {
        let action = ffi_reaction_action(&action)?;
        let msg = crate::async_runtime::block_on(self.inner.send_reaction(
            &conversation_id,
            &message_id,
            &emoji,
            action,
        ))?;
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
        let inner_envelope = ffi_incoming_envelope_to_internal(envelope, None)?;
        let result = crate::async_runtime::block_on(self.inner.process_incoming(&inner_envelope))?;
        Ok(result.map(|m| message_to_ffi(&m)))
    }

    /// Process an incoming encrypted envelope through the Rust-owned engine.
    pub fn process_incoming_message(
        &self,
        envelope: FFIIncomingEnvelope,
        server_epoch: Option<u64>,
    ) -> Result<FFIMessageProcessingResult, OrchestratorBridgeError> {
        let result = self
            .engine
            .process_incoming_message(ffi_incoming_envelope_to_internal(envelope, server_epoch)?)
            .map_err(OrchestratorBridgeError::from)?;
        Ok(FFIMessageProcessingResult {
            message: result.message.as_ref().map(message_to_ffi),
            events: engine_events_to_ffi(&result.events),
        })
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
            None,
            None,
            None,
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

    /// Return the current account's reconciled native display projection,
    /// retaining durable rows when no matching runtime view is available.
    pub fn list_conversations(
        &self,
        user_did: String,
    ) -> Result<Vec<FFIConversationView>, OrchestratorBridgeError> {
        let conversations =
            crate::async_runtime::block_on(self.inner.conversation_display_snapshot(&user_did))?;
        Ok(conversations
            .iter()
            .map(convo_view_to_ffi)
            .collect::<crate::orchestrator::Result<Vec<_>>>()?)
    }

    pub fn startup_reconcile(&self) -> Result<FFIStartupReconcileReport, OrchestratorBridgeError> {
        Ok(self.engine.startup_reconcile()?.into())
    }

    pub fn run_deferred_recovery(
        &self,
        reason: String,
    ) -> Result<FFIDeferredRecoveryReport, OrchestratorBridgeError> {
        Ok(self.engine.run_deferred_recovery(&reason)?.into())
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
                key_id: d.key_id,
                signature_public_key: d.signature_public_key,
                auth_generation: d.auth_generation,
                status: d.status,
                available_package_count: d.available_package_count,
                reserved_package_count: d.reserved_package_count,
            })
            .collect())
    }

    /// Remove a device.
    pub fn remove_device(&self, device_id: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.remove_device(&device_id))?;
        Ok(())
    }

    // -- Recovery --
    //
    // Task #43: `force_rejoin` is no longer exposed to platforms. Creating External
    // Commits from the client is the single biggest cause of epoch inflation
    // (observed epochs of 800+ in production). Recovery is now the server's job
    // via the A7 reset pyramid. Platforms that observe unrecoverable local state
    // should call `report_unrecoverable_local(convo_id, reason)` below.

    /// Task #43: report unrecoverable local state to the server so the A7 reset
    /// pyramid can take over (the server will eventually issue a GroupResetEvent
    /// to move all members to a new group).
    ///
    /// This does **not** touch local MLS state or create External Commits. It's
    /// a pure notification. Callback errors on the `report_recovery_failure`
    /// path are logged and swallowed internally.
    pub fn report_unrecoverable_local(
        &self,
        convo_id: String,
        reason: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.report_unrecoverable_local(&convo_id, &reason));
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

    /// Join or rejoin one conversation through the normal Rust recovery path.
    ///
    /// Unlike `perform_silent_recovery`, this does not delete or re-register
    /// the device. It delegates to `MLSOrchestrator::join_or_rejoin`, preserving
    /// the Welcome-first and ResetPending-bootstrap-before-External-Commit
    /// ordering used by sync and incoming-message recovery.
    pub fn join_or_rejoin(
        &self,
        convo_id: String,
    ) -> Result<FFIJoinOrRejoinResult, OrchestratorBridgeError> {
        crate::async_runtime::block_on(async {
            let epoch = self.inner.join_or_rejoin(&convo_id).await?;
            let recovery_state =
                project_conversation_recovery_state_for(&self.inner, &convo_id).await;
            Ok(FFIJoinOrRejoinResult {
                epoch,
                recovery_state,
            })
        })
    }

    /// Ensure one conversation is ready for open/send work using the same
    /// recovery ordering as the Rust recovery pipeline.
    pub fn ensure_conversation_ready(
        &self,
        convo_id: String,
    ) -> Result<FFIConversationReadyResult, OrchestratorBridgeError> {
        Ok(self.engine.ensure_conversation_ready(&convo_id)?.into())
    }

    /// Fault-injection hook used by rustFull E2E recovery tests.
    ///
    /// Deletes only local OpenMLS group state, preserves the conversation
    /// projection, and marks the conversation for Rust-owned rejoin.
    pub fn debug_wipe_local_group_for_recovery(
        &self,
        convo_id: String,
    ) -> Result<FFIDebugWipeLocalGroupResult, OrchestratorBridgeError> {
        Ok(self
            .engine
            .debug_wipe_local_group_for_recovery(&convo_id)?
            .into())
    }

    /// Project the orchestrator's current conversation recovery state into the
    /// Swift `ConversationRecoveryState` vocabulary.
    ///
    /// Unknown conversations default to `Healthy` so adding this method does not
    /// change behavior for clients that have not opted into Rust authority. When
    /// Rust has a cached group state but the low-level MLS context no longer has
    /// matching local group state, the projection reports `GroupMissing`.
    pub fn get_conversation_recovery_state(
        &self,
        conversation_id: String,
    ) -> Result<FFIConversationRecoveryState, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            project_conversation_recovery_state_for(&self.inner, &conversation_id),
        ))
    }

    /// Handle a server-initiated group reset (`GroupResetEvent` delivered via
    /// SSE/WS from the DS).
    ///
    /// **Deprecated alias for `record_group_reset` (WS-5.1, invariant S1).**
    /// This method no longer performs an inline `join_or_rejoin`: the
    /// orchestrator transitions the conversation to `RESET_PENDING`, persists
    /// the payload via `mark_reset_pending`, deletes the old local MLS group,
    /// atomically arms `needs_rejoin`, clears per-conversation recovery
    /// trackers, and rebinds the group id. The deferred-recovery loop driven by
    /// `sync_with_server` performs the actual rejoin on the next cycle —
    /// inline External Commits from event paths are the production
    /// epoch-inflation pattern (spec §8.5).
    ///
    /// - `convo_id`: stable conversation id.
    /// - `new_group_id_hex`: hex-encoded new MLS group id advertised by the DS.
    /// - `reset_generation`: monotonic reset counter from the DS.
    ///
    /// Kept for FFI ABI compatibility; new code should call
    /// `record_group_reset`.
    pub fn handle_group_reset(
        &self,
        convo_id: String,
        new_group_id_hex: String,
        reset_generation: i32,
    ) -> Result<(), OrchestratorBridgeError> {
        let new_group_id =
            hex::decode(&new_group_id_hex).map_err(|e| OrchestratorBridgeError::InvalidInput {
                message: format!("new_group_id_hex is not valid hex: {e}"),
            })?;
        #[allow(deprecated)]
        crate::async_runtime::block_on(self.inner.handle_group_reset(
            &convo_id,
            new_group_id,
            reset_generation,
        ))?;
        Ok(())
    }

    /// Persist a `groupResetEvent` WITHOUT performing inline recovery
    /// (spec §8.5 Phase 1, ADR-008 D2 deferred-recovery invariant).
    ///
    /// Platforms whose event/SSE/WS handler must not run External Commits
    /// inline (catmos, BIRDaemon, and Phase 3 iOS/Android event paths)
    /// should call this from the event handler. The deferred-recovery
    /// loop driven by `MLSOrchestrator::sync_with_server` will pick the
    /// conversation up via the `needs_rejoin` flag set here, then route
    /// it through `join_or_rejoin` — which now includes a first-responder
    /// bootstrap step gated on `ConversationState::ResetPending`.
    ///
    /// New code should prefer this over `handle_group_reset`. As of WS-5.1
    /// the legacy `handle_group_reset` is a pure deprecated alias for this
    /// method — its historical inline `join_or_rejoin` (the part that
    /// violated the "no External Commits in event handlers" invariant) has
    /// been removed; both entry points now only record deferred-recovery
    /// state.
    pub fn record_group_reset(
        &self,
        convo_id: String,
        new_group_id_hex: String,
        reset_generation: i32,
    ) -> Result<(), OrchestratorBridgeError> {
        let new_group_id =
            hex::decode(&new_group_id_hex).map_err(|e| OrchestratorBridgeError::InvalidInput {
                message: format!("new_group_id_hex is not valid hex: {e}"),
            })?;
        crate::async_runtime::block_on(self.inner.record_group_reset(
            &convo_id,
            new_group_id,
            reset_generation,
        ))?;
        Ok(())
    }

    /// Outcome-returning variant of `record_group_reset` for platforms that
    /// need to distinguish recorded resets from stale/self-echo no-ops before
    /// triggering UI notifications or sync work.
    pub fn record_group_reset_outcome(
        &self,
        convo_id: String,
        new_group_id_hex: String,
        reset_generation: i32,
    ) -> Result<FFIResetRecordOutcome, OrchestratorBridgeError> {
        let new_group_id =
            hex::decode(&new_group_id_hex).map_err(|e| OrchestratorBridgeError::InvalidInput {
                message: format!("new_group_id_hex is not valid hex: {e}"),
            })?;
        let outcome = crate::async_runtime::block_on(self.inner.record_group_reset_with_outcome(
            &convo_id,
            new_group_id,
            reset_generation,
        ))?;
        Ok(outcome.into())
    }

    /// Persist a Phase 2.5 `resetRequestedEvent` from the DS — the indirect-
    /// trigger SSE event where the server has NOT minted a new MLS group id
    /// and is asking subscribed clients to elect a first responder
    /// (`docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 1).
    ///
    /// Same deferred-recovery contract as `record_group_reset`: this writes
    /// `RESET_PENDING` state + payload, deletes the old local MLS group,
    /// clears recovery counters, and flips `needs_rejoin` so the next
    /// `MLSOrchestrator::sync_with_server` cycle drives `join_or_rejoin`,
    /// which already includes the first-responder bootstrap branch
    /// (`recovery.rs:1173-1215`). NO inline External Commit — preserves the
    /// "no External Commits in event handlers" invariant that orchestrator-
    /// using clients (catmos, BIRDaemon, WASM) rely on to avoid the
    /// epoch-inflation class of bug observed in March 2026.
    ///
    /// - `convo_id`: stable conversation id.
    /// - `crypto_session_id`: prior session id, now in `reset_requested`
    ///   server-side (lexicon `cryptoSessionId`).
    /// - `reset_generation`: monotonic per conversation (lexicon `generation`,
    ///   `i32` here to match the existing `reset_generation` field).
    /// - `trigger`: `quorumVote | systemSweep | inlineCommit409 |
    ///   inlineGroupInfo404 | adminRequest` (lexicon-owned set; logged here).
    /// - `request_event_id`: deterministic dedup key from the server (plan
    ///   §3 idempotency scheme).
    /// - `expected_new_mls_group_id_hex`: usually `None` (indirect triggers
    ///   never mint client-visible material per Phase 2.5 §1 locked decision);
    ///   admin path may pass `Some(hex_id)`. When `None`, this function mints
    ///   a fresh local UUIDv4-style 32-hex-char id for the client's race-
    ///   bootstrap candidate; the server's `crypto_sessions UNIQUE
    ///   (conversation_id, generation)` chokepoint constraint serializes the
    ///   winner, race losers see HTTP 409 `AlreadyBootstrapped` and drop
    ///   their pre-bootstrap MLS group cleanly.
    ///
    /// Idempotency: if the conversation is already `RESET_PENDING` at the
    /// same `reset_generation`, the call is a no-op (logged at INFO with the
    /// `request_event_id` for audit).
    pub fn record_reset_requested(
        &self,
        convo_id: String,
        crypto_session_id: String,
        reset_generation: i32,
        trigger: String,
        request_event_id: String,
        expected_new_mls_group_id_hex: Option<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        // Validate hex up-front when present so a malformed id surfaces as
        // `InvalidInput` rather than silently round-tripping into storage.
        if let Some(ref hex_id) = expected_new_mls_group_id_hex {
            if !hex_id.is_empty() {
                if let Err(e) = hex::decode(hex_id) {
                    return Err(OrchestratorBridgeError::InvalidInput {
                        message: format!("expected_new_mls_group_id_hex is not valid hex: {e}"),
                    });
                }
            }
        }
        crate::async_runtime::block_on(self.inner.record_reset_requested(
            &convo_id,
            &crypto_session_id,
            reset_generation,
            &trigger,
            &request_event_id,
            expected_new_mls_group_id_hex,
        ))?;
        Ok(())
    }

    /// Outcome-returning variant of `record_reset_requested` for platforms
    /// that need to avoid follow-up sync/UI churn when Rust classified the
    /// event as stale or self-echo.
    pub fn record_reset_requested_outcome(
        &self,
        convo_id: String,
        crypto_session_id: String,
        reset_generation: i32,
        trigger: String,
        request_event_id: String,
        expected_new_mls_group_id_hex: Option<String>,
    ) -> Result<FFIResetRecordOutcome, OrchestratorBridgeError> {
        // Validate hex up-front when present so a malformed id surfaces as
        // `InvalidInput` rather than silently round-tripping into storage.
        if let Some(ref hex_id) = expected_new_mls_group_id_hex {
            if !hex_id.is_empty() {
                if let Err(e) = hex::decode(hex_id) {
                    return Err(OrchestratorBridgeError::InvalidInput {
                        message: format!("expected_new_mls_group_id_hex is not valid hex: {e}"),
                    });
                }
            }
        }
        let outcome =
            crate::async_runtime::block_on(self.inner.record_reset_requested_with_outcome(
                &convo_id,
                &crypto_session_id,
                reset_generation,
                &trigger,
                &request_event_id,
                expected_new_mls_group_id_hex,
            ))?;
        Ok(outcome.into())
    }

    /// Return the RFC 9420 §8.7 `epoch_authenticator` for a group's current
    /// epoch.
    ///
    /// Platforms hex-encode this value when calling
    /// `OrchestratorAPICallback::report_recovery_failure` so that quorum-reset
    /// reports (spec §8.6 / ADR-002) are bound to a specific epoch. Returns
    /// the raw authenticator bytes.
    pub fn epoch_authenticator(
        &self,
        group_id: Vec<u8>,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        // MLSOrchestrator<S,A,C,M>::mls_context() exposes the underlying
        // MlsCryptoContext impl; for the UniFFI bridge this is MLSContext.
        self.inner
            .mls_context()
            .epoch_authenticator(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    // -- Layer 3 Quarantine FFI --

    /// Install (or replace) the Layer 3 event callback. Pass None to detach.
    pub fn set_event_callback(&self, callback: Option<Box<dyn OrchestratorEventCallback>>) {
        let observer: Option<
            Arc<dyn crate::orchestrator::event_observer::OrchestratorEventObserver>,
        > = callback.map(|cb| {
            let arc: Arc<dyn OrchestratorEventCallback> = Arc::from(cb);
            let adapter: Arc<dyn crate::orchestrator::event_observer::OrchestratorEventObserver> =
                Arc::new(EventCallbackAdapter(arc));
            adapter
        });
        crate::async_runtime::block_on(self.inner.set_event_observer(observer));
    }

    /// Opt in to returning/storing known non-displayable MLS control payloads
    /// from `process_incoming`.
    ///
    /// Defaults off for source compatibility with existing clients. Catbird iOS
    /// enables this in Rust-authoritative mode and handles the side effects in
    /// Swift after Rust has performed the MLS decrypt/process step.
    pub fn set_store_control_messages(&self, enabled: bool) {
        self.inner.set_store_control_messages(enabled);
    }

    /// Snapshot of a conversation quarantine state, if any.
    pub fn get_conversation_quarantine_state(
        &self,
        convo_id: String,
    ) -> Option<FFIQuarantineState> {
        crate::async_runtime::block_on(self.inner.get_conversation_quarantine_state(&convo_id)).map(
            |q| FFIQuarantineState {
                reason: qreason_to_ffi(q.reason),
                since_ms: q.since_ms,
                suspected_dids: q.suspected_dids,
            },
        )
    }

    /// User explicitly tapped Reset conversation in the UI. Reports a vote
    /// to the server (spec section 8.6 quorum) and clears local quarantine.
    pub fn user_confirmed_manual_reset(
        &self,
        convo_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.user_confirmed_manual_reset(&convo_id))?;
        Ok(())
    }
}

#[uniffi::export]
impl OrchestratorBridge {
    pub fn initialize_engine(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
        let _user_lifecycle_transition = self.begin_user_lifecycle_transition();
        self.engine.initialize_user(&user_did)?;
        Ok(())
    }

    pub fn prepare_for_suspend(
        &self,
        reason: String,
        deadline_ms: u64,
    ) -> Result<FFISuspendResult, OrchestratorBridgeError> {
        let _lifecycle_transition = self.lock_lifecycle_transition()?;
        let result = self
            .engine
            .prepare_for_suspend(&reason, Duration::from_millis(deadline_ms))?;
        Ok(FFISuspendResult {
            accepting_new_work: result.accepting_new_work,
            interrupted_contexts: result.interrupted_contexts,
        })
    }

    pub fn reattach_after_suspend(
        &self,
        user_did: String,
        reason: String,
    ) -> Result<(), OrchestratorBridgeError> {
        let _user_lifecycle_transition = self.begin_user_lifecycle_transition();
        self.engine.reattach_after_suspend(&user_did, &reason)?;
        Ok(())
    }

    pub fn resume_from_suspend(&self, reason: String) -> Result<(), OrchestratorBridgeError> {
        let _user_lifecycle_transition = self.begin_user_lifecycle_transition();
        self.engine.resume_from_suspend(&reason)?;
        Ok(())
    }

    pub fn interrupt_storage(&self, reason: String) -> Result<(), OrchestratorBridgeError> {
        let _ = self.engine.interrupt_storage(&reason)?;
        Ok(())
    }

    pub fn emergency_close(&self, reason: String) -> Result<(), OrchestratorBridgeError> {
        let _lifecycle_transition = self.lock_lifecycle_transition()?;
        let close_result = self.engine.emergency_close(&reason);
        crate::async_runtime::block_on(self.inner.shutdown());
        close_result.map_err(OrchestratorBridgeError::from)
    }

    pub fn storage_lifecycle_status(&self) -> StorageLifecycleStatus {
        self.engine.storage_lifecycle_status()
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FFIFetchMessagesResult {
    pub messages: Vec<FFIMessage>,
    pub cursor: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FFISuspendResult {
    pub accepting_new_work: bool,
    pub interrupted_contexts: u32,
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

// ═══════════════════════════════════════════════════════════════════════════
// Bridge unit tests (WS-5 FIX-4): the E7 persistence + WS-5.2 escalation
// surface must actually cross the UniFFI adapter layer, not ride the trait
// default no-ops.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn full_security_capabilities() -> SecurityStorageCapabilities {
        SecurityStorageCapabilities {
            version: bridge_mappers::SECURITY_STORAGE_CAPABILITIES_VERSION,
            reset_state: true,
            quarantine: true,
            pending_message_protection: true,
            sequencer_receipts: true,
            recovery_backoff: true,
            pending_deletion: true,
            authorized_device_resolution: true,
        }
    }
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // ── Event callback: WS-5.2 escalation must reach the platform ─────────

    /// (convo_id, operation, expected_did, claimed_identity, reason)
    type RecordedBindingWarning = (String, String, String, String, String);
    /// (convo_id, epoch, stored_commit_hash_hex, new_commit_hash_hex, sequencer_did)
    type RecordedEquivocation = (String, i32, String, String, String);

    #[derive(Default)]
    struct RecordingEventCallback {
        storage_failures: Mutex<Vec<(String, String, String)>>,
        binding_warnings: Mutex<Vec<RecordedBindingWarning>>,
        equivocations: Mutex<Vec<RecordedEquivocation>>,
    }

    impl OrchestratorEventCallback for RecordingEventCallback {
        fn on_conversation_quarantined(
            &self,
            _convo_id: String,
            _reason: FFIQuarantineReason,
            _suspected_dids: Vec<String>,
        ) {
        }
        fn on_conversation_quarantine_cleared(
            &self,
            _convo_id: String,
            _via: FFIQuarantineExitReason,
        ) {
        }
        fn on_recovery_storage_write_failed(
            &self,
            conversation_id: String,
            operation: String,
            error: String,
        ) {
            self.storage_failures
                .lock()
                .unwrap()
                .push((conversation_id, operation, error));
        }
        fn on_credential_binding_warning(
            &self,
            convo_id: String,
            operation: String,
            expected_did: String,
            claimed_identity: String,
            reason: String,
        ) {
            self.binding_warnings.lock().unwrap().push((
                convo_id,
                operation,
                expected_did,
                claimed_identity,
                reason,
            ));
        }
        fn on_sequencer_equivocation(
            &self,
            convo_id: String,
            epoch: i32,
            stored_commit_hash_hex: String,
            new_commit_hash_hex: String,
            sequencer_did: String,
        ) {
            self.equivocations.lock().unwrap().push((
                convo_id,
                epoch,
                stored_commit_hash_hex,
                new_commit_hash_hex,
                sequencer_did,
            ));
        }
    }

    #[test]
    fn event_adapter_forwards_recovery_storage_write_failed() {
        use crate::orchestrator::event_observer::OrchestratorEventObserver;

        let callback = Arc::new(RecordingEventCallback::default());
        let adapter = EventCallbackAdapter(callback.clone() as Arc<dyn OrchestratorEventCallback>);

        adapter.on_recovery_storage_write_failed("convo-1", "mark_needs_rejoin", "disk full");

        let captured = callback.storage_failures.lock().unwrap();
        assert_eq!(
            captured.as_slice(),
            &[(
                "convo-1".to_string(),
                "mark_needs_rejoin".to_string(),
                "disk full".to_string()
            )],
            "EventCallbackAdapter must forward WS-5.2 escalations across the bridge"
        );
    }

    #[test]
    fn ffi_reaction_action_accepts_only_supported_wire_values() {
        assert_eq!(
            ffi_reaction_action("add").unwrap(),
            crate::orchestrator::types::ReactionAction::Add
        );
        assert_eq!(
            ffi_reaction_action("remove").unwrap(),
            crate::orchestrator::types::ReactionAction::Remove
        );

        let err = ffi_reaction_action("toggle").unwrap_err();
        assert!(
            matches!(err, OrchestratorBridgeError::InvalidInput { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn event_adapter_forwards_credential_binding_warning() {
        use crate::orchestrator::event_observer::OrchestratorEventObserver;

        let callback = Arc::new(RecordingEventCallback::default());
        let adapter = EventCallbackAdapter(callback.clone() as Arc<dyn OrchestratorEventCallback>);

        adapter.on_credential_binding_warning(
            "convo-1",
            "message",
            "did:plc:alice",
            "did:plc:mallory",
            "credential DID does not match key-package owner",
        );

        let captured = callback.binding_warnings.lock().unwrap();
        assert_eq!(
            captured.as_slice(),
            &[(
                "convo-1".to_string(),
                "message".to_string(),
                "did:plc:alice".to_string(),
                "did:plc:mallory".to_string(),
                "credential DID does not match key-package owner".to_string()
            )],
            "EventCallbackAdapter must forward WS-3 credential-binding warnings across the bridge"
        );
    }

    #[test]
    fn event_adapter_forwards_sequencer_equivocation() {
        use crate::orchestrator::event_observer::OrchestratorEventObserver;

        let callback = Arc::new(RecordingEventCallback::default());
        let adapter = EventCallbackAdapter(callback.clone() as Arc<dyn OrchestratorEventCallback>);

        adapter.on_sequencer_equivocation("convo-2", 42, "aabb01", "ccdd02", "did:web:sequencer");

        let captured = callback.equivocations.lock().unwrap();
        assert_eq!(
            captured.as_slice(),
            &[(
                "convo-2".to_string(),
                42,
                "aabb01".to_string(),
                "ccdd02".to_string(),
                "did:web:sequencer".to_string()
            )],
            "EventCallbackAdapter must forward WS-3 equivocation detections across the bridge"
        );
    }

    // ── Storage callback: E7 backoff rows must round-trip the adapter ─────

    #[derive(Default)]
    struct RecordingStorageCallback {
        backoff: Mutex<std::collections::HashMap<String, FFIPersistedRecoveryBackoff>>,
        last_global_ms: Mutex<Option<i64>>,
        pending_deletes: Mutex<std::collections::HashMap<String, FFIPendingLocalDelete>>,
        conversation_states: Mutex<std::collections::HashMap<String, FFIConversationState>>,
        pending_messages: Mutex<std::collections::HashSet<String>>,
        receipts: Mutex<Vec<FFISequencerReceipt>>,
        reset_payload: Mutex<Option<(String, String, i32, i64)>>,
        reset_clear_requests: Mutex<Vec<(String, Option<i32>, Option<String>, Option<u64>)>>,
        reset_clear_applied: std::sync::atomic::AtomicBool,
        account_exit_requests: Mutex<Vec<(String, String, Option<i32>, u64, String)>>,
        quarantine_payload: Mutex<Option<(String, String, i64)>>,
        fail_security_writes: std::sync::atomic::AtomicBool,
    }

    impl RecordingStorageCallback {
        fn reject_injected_security_failure(&self) -> Result<(), OrchestratorBridgeError> {
            if self.fail_security_writes.load(Ordering::SeqCst) {
                Err(OrchestratorBridgeError::Storage {
                    message: "injected storage failure".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn account_exit_adapter_preserves_exact_cas_tuple_and_result() {
        let callback = Arc::new(RecordingStorageCallback::default());
        let adapter = StorageAdapter(callback.clone());
        let group = "ab".repeat(32);
        assert!(!adapter
            .complete_account_exit(
                "conversation",
                &group,
                Some(7),
                42,
                ConversationState::Closed
            )
            .await
            .unwrap());
        callback.reset_clear_applied.store(true, Ordering::SeqCst);
        assert!(adapter
            .complete_account_exit(
                "conversation",
                &group,
                Some(7),
                42,
                ConversationState::Closed
            )
            .await
            .unwrap());
        assert_eq!(
            callback.account_exit_requests.lock().unwrap().as_slice(),
            &[
                (
                    "conversation".into(),
                    group.clone(),
                    Some(7),
                    42,
                    "closed".into()
                ),
                (
                    "conversation".into(),
                    group.clone(),
                    Some(7),
                    42,
                    "closed".into()
                ),
            ]
        );
        assert!(adapter
            .complete_account_exit("conversation", &group, None, 42, ConversationState::Active)
            .await
            .is_err());
        assert_eq!(callback.account_exit_requests.lock().unwrap().len(), 2);
        callback.fail_security_writes.store(true, Ordering::SeqCst);
        assert!(adapter
            .complete_account_exit(
                "conversation",
                &group,
                Some(7),
                42,
                ConversationState::Closed
            )
            .await
            .is_err());
    }

    impl OrchestratorStorageCallback for RecordingStorageCallback {
        fn ensure_conversation_exists(
            &self,
            _user_did: String,
            _conversation_id: String,
            _group_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn update_join_info(
            &self,
            _conversation_id: String,
            _user_did: String,
            _join_method: String,
            _join_epoch: u64,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn get_conversation(
            &self,
            _user_did: String,
            _conversation_id: String,
        ) -> Result<Option<FFIConversationView>, OrchestratorBridgeError> {
            Ok(None)
        }
        fn list_conversations(
            &self,
            _user_did: String,
        ) -> Result<Vec<FFIConversationView>, OrchestratorBridgeError> {
            Ok(vec![])
        }
        fn delete_conversations(
            &self,
            _user_did: String,
            _ids: Vec<String>,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn set_conversation_state(
            &self,
            _conversation_id: String,
            _state: String,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn complete_account_exit(
            &self,
            conversation_id: String,
            expected_group_id_hex: String,
            expected_reset_generation: Option<i32>,
            terminal_epoch: u64,
            terminal_state: String,
        ) -> Result<bool, OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.account_exit_requests.lock().unwrap().push((
                conversation_id,
                expected_group_id_hex,
                expected_reset_generation,
                terminal_epoch,
                terminal_state,
            ));
            Ok(self.reset_clear_applied.load(Ordering::SeqCst))
        }
        fn get_conversation_state(
            &self,
            conversation_id: String,
        ) -> Result<Option<FFIConversationState>, OrchestratorBridgeError> {
            Ok(self
                .conversation_states
                .lock()
                .unwrap()
                .get(&conversation_id)
                .cloned())
        }
        fn mark_reset_pending(
            &self,
            conversation_id: String,
            new_group_id_hex: String,
            reset_generation: i32,
            notified_at_ms: i64,
        ) -> Result<(), OrchestratorBridgeError> {
            if self.fail_security_writes.load(Ordering::SeqCst) {
                return Err(OrchestratorBridgeError::Storage {
                    message: "injected storage failure".into(),
                });
            }
            // Ruling 2a: the authority commit is also the quarantine exit, so
            // drop this conversation's persisted quarantine row here — exactly
            // what `clear_quarantine` below does — rather than relying on that
            // separate call. `quarantine_payload` is an argument recorder, not
            // durable state, so it is left alone here just as `clear_quarantine`
            // leaves it alone.
            self.conversation_states
                .lock()
                .unwrap()
                .remove(&conversation_id);
            *self.reset_payload.lock().unwrap() = Some((
                conversation_id,
                new_group_id_hex,
                reset_generation,
                notified_at_ms,
            ));
            Ok(())
        }
        fn adopt_reset_pending_target(
            &self,
            conversation_id: String,
            expected_generation: i32,
            expected_old_target: String,
            authoritative_new_target: String,
        ) -> Result<bool, OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            let mut payload = self.reset_payload.lock().unwrap();
            let Some((stored_conversation, stored_target, stored_generation, notified_at_ms)) =
                payload.as_ref()
            else {
                return Ok(false);
            };
            if stored_conversation != &conversation_id
                || stored_generation != &expected_generation
                || stored_target != &expected_old_target
            {
                return Ok(false);
            }
            *payload = Some((
                conversation_id,
                authoritative_new_target,
                expected_generation,
                *notified_at_ms,
            ));
            Ok(true)
        }
        fn complete_reset_pending(
            &self,
            conversation_id: String,
            expected_generation: i32,
            expected_new_group_id_hex: String,
            landed_epoch: u64,
        ) -> Result<bool, OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.reset_clear_requests.lock().unwrap().push((
                conversation_id,
                Some(expected_generation),
                Some(expected_new_group_id_hex),
                Some(landed_epoch),
            ));
            Ok(self.reset_clear_applied.load(Ordering::SeqCst))
        }

        fn clear_reset_pending_for_delete(
            &self,
            conversation_id: String,
            expected_generation: i32,
        ) -> Result<bool, OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.reset_clear_requests.lock().unwrap().push((
                conversation_id,
                Some(expected_generation),
                None,
                None,
            ));
            Ok(self.reset_clear_applied.load(Ordering::SeqCst))
        }
        fn mark_quarantined(
            &self,
            conversation_id: String,
            reason_tag: String,
            since_ms: i64,
        ) -> Result<(), OrchestratorBridgeError> {
            if self.fail_security_writes.load(Ordering::SeqCst) {
                return Err(OrchestratorBridgeError::Storage {
                    message: "injected storage failure".into(),
                });
            }
            *self.quarantine_payload.lock().unwrap() =
                Some((conversation_id.clone(), reason_tag.clone(), since_ms));
            self.conversation_states.lock().unwrap().insert(
                conversation_id,
                FFIConversationState {
                    state: "quarantined".into(),
                    new_group_id: None,
                    reset_generation: None,
                    notified_at_ms: None,
                    quarantine_reason: Some(reason_tag),
                    quarantined_since_ms: Some(since_ms),
                },
            );
            Ok(())
        }
        fn clear_quarantine(&self, conversation_id: String) -> Result<(), OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.conversation_states
                .lock()
                .unwrap()
                .remove(&conversation_id);
            Ok(())
        }
        fn mark_needs_rejoin(
            &self,
            _conversation_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn needs_rejoin(&self, _conversation_id: String) -> Result<bool, OrchestratorBridgeError> {
            Ok(false)
        }
        fn clear_rejoin_flag(
            &self,
            _conversation_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn store_message(&self, _message: FFIMessage) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn get_messages(
            &self,
            _conversation_id: String,
            _limit: u32,
            _before_sequence: Option<u64>,
        ) -> Result<Vec<FFIMessage>, OrchestratorBridgeError> {
            Ok(vec![])
        }
        fn message_exists(&self, _message_id: String) -> Result<bool, OrchestratorBridgeError> {
            Ok(false)
        }
        fn store_pending_message(
            &self,
            _conversation_id: String,
            message_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.pending_messages.lock().unwrap().insert(message_id);
            Ok(())
        }
        fn remove_pending_message(
            &self,
            message_id: String,
        ) -> Result<bool, OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            Ok(self.pending_messages.lock().unwrap().remove(&message_id))
        }
        fn store_sequencer_receipt(
            &self,
            receipt: FFISequencerReceipt,
        ) -> Result<(), OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.receipts.lock().unwrap().push(receipt);
            Ok(())
        }
        fn get_sequencer_receipts(
            &self,
            conversation_id: String,
            since_epoch: Option<i32>,
        ) -> Result<Vec<FFISequencerReceipt>, OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            Ok(self
                .receipts
                .lock()
                .unwrap()
                .iter()
                .filter(|receipt| {
                    receipt.convo_id == conversation_id
                        && since_epoch.is_none_or(|epoch| receipt.epoch >= epoch)
                })
                .cloned()
                .collect())
        }
        fn clear_sequencer_receipts(
            &self,
            conversation_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.receipts
                .lock()
                .unwrap()
                .retain(|receipt| receipt.convo_id != conversation_id);
            Ok(())
        }
        fn get_sync_cursor(
            &self,
            _user_did: String,
        ) -> Result<FFISyncCursor, OrchestratorBridgeError> {
            Ok(FFISyncCursor {
                conversations_cursor: None,
                messages_cursor: None,
            })
        }
        fn set_sync_cursor(
            &self,
            _user_did: String,
            _cursor: FFISyncCursor,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn set_group_state(&self, _state: FFIGroupState) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn get_group_state(
            &self,
            _group_id: String,
        ) -> Result<Option<FFIGroupState>, OrchestratorBridgeError> {
            Ok(None)
        }
        fn delete_group_state(&self, _group_id: String) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn get_recovery_state(&self) -> Result<FFIPersistedRecoveryState, OrchestratorBridgeError> {
            let mut entries: Vec<FFIPersistedRecoveryBackoff> =
                self.backoff.lock().unwrap().values().cloned().collect();
            entries.sort_by(|a, b| a.conversation_id.cmp(&b.conversation_id));
            Ok(FFIPersistedRecoveryState {
                entries,
                last_global_rejoin_attempt_at_ms: *self.last_global_ms.lock().unwrap(),
            })
        }
        fn set_recovery_backoff(
            &self,
            entry: FFIPersistedRecoveryBackoff,
        ) -> Result<(), OrchestratorBridgeError> {
            if self.fail_security_writes.load(Ordering::SeqCst) {
                return Err(OrchestratorBridgeError::Storage {
                    message: "injected storage failure".into(),
                });
            }
            self.backoff
                .lock()
                .unwrap()
                .insert(entry.conversation_id.clone(), entry);
            Ok(())
        }
        fn clear_recovery_backoff(
            &self,
            conversation_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.backoff.lock().unwrap().remove(&conversation_id);
            Ok(())
        }
        fn set_last_global_rejoin_attempt_at(
            &self,
            at_ms: i64,
        ) -> Result<(), OrchestratorBridgeError> {
            if self.fail_security_writes.load(Ordering::SeqCst) {
                return Err(OrchestratorBridgeError::Storage {
                    message: "injected storage failure".into(),
                });
            }
            *self.last_global_ms.lock().unwrap() = Some(at_ms);
            Ok(())
        }
        fn mark_pending_local_delete(
            &self,
            conversation_id: String,
            group_id_hex: Option<String>,
        ) -> Result<(), OrchestratorBridgeError> {
            if self.fail_security_writes.load(Ordering::SeqCst) {
                return Err(OrchestratorBridgeError::Storage {
                    message: "injected storage failure".into(),
                });
            }
            self.pending_deletes.lock().unwrap().insert(
                conversation_id.clone(),
                FFIPendingLocalDelete {
                    conversation_id,
                    group_id_hex,
                },
            );
            Ok(())
        }
        fn clear_pending_local_delete(
            &self,
            conversation_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
            self.reject_injected_security_failure()?;
            self.pending_deletes
                .lock()
                .unwrap()
                .remove(&conversation_id);
            Ok(())
        }
        fn list_pending_local_deletes(
            &self,
        ) -> Result<Vec<FFIPendingLocalDelete>, OrchestratorBridgeError> {
            Ok(self
                .pending_deletes
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect())
        }
    }

    #[derive(Default)]
    struct RecordingKeychain {
        entries: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl crate::keychain::KeychainAccess for RecordingKeychain {
        async fn read(&self, key: String) -> Result<Option<Vec<u8>>, crate::MLSError> {
            Ok(self.entries.lock().unwrap().get(&key).cloned())
        }

        async fn write(&self, key: String, value: Vec<u8>) -> Result<(), crate::MLSError> {
            self.entries.lock().unwrap().insert(key, value);
            Ok(())
        }

        async fn delete(&self, key: String) -> Result<(), crate::MLSError> {
            self.entries.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    struct WelcomeCountingApiCallback {
        current_did: String,
        welcome_calls: Arc<AtomicUsize>,
        receipt_response: Mutex<Option<FFISequencerReceipt>>,
        server_status: std::sync::atomic::AtomicU16,
        registered_device: std::sync::OnceLock<FFIDeviceInfo>,
    }

    impl WelcomeCountingApiCallback {
        fn new(current_did: &str, welcome_calls: Arc<AtomicUsize>) -> Self {
            Self {
                current_did: current_did.to_string(),
                welcome_calls,
                receipt_response: Mutex::new(None),
                server_status: std::sync::atomic::AtomicU16::new(0),
                registered_device: std::sync::OnceLock::new(),
            }
        }
    }

    impl OrchestratorAPICallback for WelcomeCountingApiCallback {
        fn is_authenticated_as(&self, did: String) -> bool {
            did == self.current_did
        }

        fn current_did(&self) -> Option<String> {
            Some(self.current_did.clone())
        }

        fn get_conversations(
            &self,
            _limit: u32,
            _cursor: Option<String>,
        ) -> Result<FFIConversationListPage, OrchestratorBridgeError> {
            Ok(FFIConversationListPage {
                conversations: vec![],
                cursor: None,
            })
        }

        fn submit_prepared_request(
            &self,
            _method: String,
            nsid: String,
            body: Option<Vec<u8>>,
            _query: Option<Vec<u8>>,
        ) -> Result<FFIGatewayResponse, OrchestratorBridgeError> {
            if nsid == "blue.catbird.chat.getConversations" {
                return Ok(FFIGatewayResponse { status: 200, content_type: Some("application/json".into()), body: serde_json::to_vec(&serde_json::json!({
                    "items":[],"hasMore":false,"inventorySessionId":"00000000-0000-4000-8000-000000000002",
                    "snapshotEventCursor":"bridge-test-fence","snapshotExpiresAt":"2099-01-01T00:00:00.000Z"
                })).unwrap() });
            }
            if nsid == "blue.catbird.chat.getPendingWelcomes" {
                self.welcome_calls.fetch_add(1, Ordering::SeqCst);
                return Ok(FFIGatewayResponse {
                    status: 503,
                    content_type: Some("application/json".into()),
                    body: br#"{"error":"Unavailable"}"#.to_vec(),
                });
            }
            let resp_body = if nsid == "blue.catbird.chat.enrollDevice" {
                let inner = body
                    .as_deref()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
                    .unwrap_or_default();
                let inner_body = inner
                    .get("signedRequest")
                    .and_then(|signed| signed.get("body"))
                    .or_else(|| inner.get("body"))
                    .unwrap_or(&inner);
                let actor_did = inner_body
                    .get("actorDid")
                    .and_then(|did| did.as_str())
                    .unwrap_or(&self.current_did);
                let dev_id = inner_body
                    .get("deviceId")
                    .and_then(|device| device.as_str())
                    .unwrap_or("00000000-0000-4000-8000-000000000001");
                let key_id = inner_body
                    .get("keyId")
                    .and_then(|key| key.as_str())
                    .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                let sig_pk = inner_body
                    .get("signaturePublicKey")
                    .and_then(|key| {
                        key.as_str()
                            .or_else(|| key.get("$bytes").and_then(|bytes| bytes.as_str()))
                    })
                    .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                let signature_public_key = base64::engine::general_purpose::STANDARD
                    .decode(sig_pk)
                    .unwrap_or_else(|_| vec![0; 32]);
                let device = FFIDeviceInfo {
                    device_id: dev_id.to_string(),
                    mls_did: format!("{actor_did}#{dev_id}"),
                    device_uuid: dev_id.to_string(),
                    created_at: Some(
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ),
                    key_id: Some(key_id.to_string()),
                    signature_public_key: Some(signature_public_key),
                    auth_generation: Some(1),
                    status: Some("active".into()),
                    available_package_count: Some(50),
                    reserved_package_count: Some(0),
                };
                let _ = self.registered_device.set(device);
                serde_json::to_vec(&serde_json::json!({
                    "device": {
                        "deviceId": dev_id,
                        "keyId": key_id,
                        "signaturePublicKey": {
                            "$bytes": sig_pk
                        },
                        "authGeneration": 1,
                        "status": "active",
                        "availablePackageCount": 50,
                        "reservedPackageCount": 0,
                        "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "updatedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    }
                })).unwrap()
            } else {
                serde_json::to_vec(&serde_json::json!({"result": {}})).unwrap()
            };
            Ok(FFIGatewayResponse {
                status: 200,
                content_type: Some("application/json".into()),
                body: resp_body,
            })
        }

        fn get_messages(
            &self,
            _convo_id: String,
            _cursor: Option<String>,
            _limit: u32,
            _message_type: Option<String>,
            _from_epoch: Option<u32>,
            _to_epoch: Option<u32>,
        ) -> Result<FFIMessagesPage, OrchestratorBridgeError> {
            Ok(FFIMessagesPage {
                envelopes: vec![],
                cursor: None,
            })
        }

        fn get_delivery_status(
            &self,
            _convo_id: String,
            _message_ids: Vec<String>,
        ) -> Result<Vec<FFIDeliveryStatusPair>, OrchestratorBridgeError> {
            Ok(vec![])
        }
        fn get_key_packages(
            &self,
            _actor_device_id: String,
            _dids: Vec<String>,
        ) -> Result<Vec<FFIKeyPackageRef>, OrchestratorBridgeError> {
            Ok(vec![])
        }

        fn get_key_package_stats(&self) -> Result<FFIKeyPackageStats, OrchestratorBridgeError> {
            Ok(FFIKeyPackageStats {
                available: 0,
                total: 0,
            })
        }

        fn sync_key_packages(
            &self,
            _local_hashes: Vec<String>,
            _device_id: String,
        ) -> Result<FFIKeyPackageSyncResult, OrchestratorBridgeError> {
            Ok(FFIKeyPackageSyncResult {
                orphaned_count: 0,
                deleted_count: 0,
            })
        }

        fn list_devices(
            &self,
            _actor_device_id: String,
        ) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError> {
            Ok(self.registered_device.get().cloned().into_iter().collect())
        }

        fn get_group_info(&self, _convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::ServerError {
                status: 503,
                body: "bridge joinOrRejoin test stopped at GroupInfo".to_string(),
            })
        }

        fn get_welcome(&self, _convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError> {
            self.welcome_calls.fetch_add(1, Ordering::SeqCst);
            let status = self.server_status.load(Ordering::SeqCst);
            Err(OrchestratorBridgeError::ServerError {
                status: if status == 0 { 503 } else { status },
                body: if status == 409 {
                    r#"{"error":"AlreadyBootstrapped"}"#.to_string()
                } else {
                    "bridge server error".to_string()
                },
            })
        }

        fn get_group_metadata_blob(
            &self,
            _convo_id: String,
            _group_id_hex: String,
            _blob_locator: String,
        ) -> Result<Vec<u8>, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::ServerError {
                status: 404,
                body: "no metadata blob in test".into(),
            })
        }
    }

    #[derive(Default)]
    struct RecordingCredentialCallback {
        signing_keys: Mutex<HashMap<String, Vec<u8>>>,
        mls_dids: Mutex<HashMap<String, String>>,
        device_uuids: Mutex<HashMap<String, String>>,
        authorized_device_keys: Mutex<Option<Vec<Vec<u8>>>>,
        authorized_device_error: Mutex<Option<String>>,
    }

    impl OrchestratorCredentialCallback for RecordingCredentialCallback {
        fn store_signing_key(
            &self,
            user_did: String,
            key_data: Vec<u8>,
        ) -> Result<(), OrchestratorBridgeError> {
            self.signing_keys.lock().unwrap().insert(user_did, key_data);
            Ok(())
        }

        fn get_signing_key(
            &self,
            user_did: String,
        ) -> Result<Option<Vec<u8>>, OrchestratorBridgeError> {
            Ok(self.signing_keys.lock().unwrap().get(&user_did).cloned())
        }

        fn sign_clean_chat_transcript(
            &self,
            _user_did: String,
            _transcript: Vec<u8>,
            _key_id: String,
        ) -> Result<Option<CleanChatSigningAuthorityFfi>, OrchestratorBridgeError> {
            Ok(None)
        }

        fn delete_signing_key(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
            self.signing_keys.lock().unwrap().remove(&user_did);
            Ok(())
        }

        fn store_mls_did(
            &self,
            user_did: String,
            mls_did: String,
        ) -> Result<(), OrchestratorBridgeError> {
            self.mls_dids.lock().unwrap().insert(user_did, mls_did);
            Ok(())
        }

        fn get_mls_did(&self, user_did: String) -> Result<Option<String>, OrchestratorBridgeError> {
            Ok(self.mls_dids.lock().unwrap().get(&user_did).cloned())
        }

        fn store_device_uuid(
            &self,
            user_did: String,
            uuid: String,
        ) -> Result<(), OrchestratorBridgeError> {
            self.device_uuids.lock().unwrap().insert(user_did, uuid);
            Ok(())
        }

        fn get_device_uuid(
            &self,
            user_did: String,
        ) -> Result<Option<String>, OrchestratorBridgeError> {
            Ok(self.device_uuids.lock().unwrap().get(&user_did).cloned())
        }

        fn has_credentials(&self, user_did: String) -> Result<bool, OrchestratorBridgeError> {
            Ok(self.mls_dids.lock().unwrap().contains_key(&user_did)
                && self.device_uuids.lock().unwrap().contains_key(&user_did))
        }

        fn clear_all(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
            self.signing_keys.lock().unwrap().remove(&user_did);
            self.mls_dids.lock().unwrap().remove(&user_did);
            self.device_uuids.lock().unwrap().remove(&user_did);
            Ok(())
        }

        fn get_authorized_device_keys(
            &self,
            _user_did: String,
        ) -> Result<Option<Vec<Vec<u8>>>, OrchestratorBridgeError> {
            if let Some(message) = self.authorized_device_error.lock().unwrap().clone() {
                return Err(OrchestratorBridgeError::Credential { message });
            }
            Ok(self.authorized_device_keys.lock().unwrap().clone())
        }
    }

    #[test]
    fn both_bridge_adapters_forward_security_storage_and_authorized_devices_losslessly() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(RecordingStorageCallback::default());
            let receipt = crate::orchestrator::types::SequencerReceipt {
                convo_id: "convo-1".into(),
                epoch: 7,
                sequencer_term: 3,
                commit_hash: vec![1, 2],
                sequencer_did: "did:web:sequencer.example".into(),
                issued_at: 1234,
                signature: vec![3, 4],
            };
            let adapters: Vec<Box<dyn MLSStorageBackend>> = vec![
                Box::new(StorageAdapter(callback.clone())),
                Box::new(crate::client_bridge::ClientStorageAdapter(callback.clone())),
            ];

            for adapter in adapters {
                adapter
                    .store_pending_message("convo-1", "message-1")
                    .await
                    .expect("store pending message");
                assert!(adapter
                    .remove_pending_message("message-1")
                    .await
                    .expect("remove pending message"));
                adapter
                    .store_sequencer_receipt(&receipt)
                    .await
                    .expect("store receipt");
                let stored = adapter
                    .get_sequencer_receipts("convo-1", Some(7))
                    .await
                    .expect("get receipts");
                assert_eq!(stored[0].sequencer_term, 3);
                assert_eq!(stored[0].signature, vec![3, 4]);
            }

            let credential_callback = Arc::new(RecordingCredentialCallback::default());
            *credential_callback.authorized_device_keys.lock().unwrap() =
                Some(vec![vec![9, 8], vec![7, 6]]);
            let normal = CredentialAdapter::new(credential_callback.clone());
            let client =
                crate::client_bridge::ClientCredentialAdapter::new(credential_callback.clone());
            for adapter in [
                &normal as &dyn CredentialStore,
                &client as &dyn CredentialStore,
            ] {
                assert_eq!(
                    adapter
                        .get_authorized_device_keys("did:plc:alice")
                        .await
                        .expect("authorized device keys"),
                    Some(vec![vec![9, 8], vec![7, 6]])
                );
            }

            *credential_callback.authorized_device_error.lock().unwrap() =
                Some("keychain locked".into());
            for adapter in [
                &normal as &dyn CredentialStore,
                &client as &dyn CredentialStore,
            ] {
                assert!(matches!(
                    adapter.get_authorized_device_keys("did:plc:alice").await,
                    Err(OrchestratorError::Credential(message)) if message == "keychain locked"
                ));
            }
        });
    }

    fn test_receipt() -> FFISequencerReceipt {
        FFISequencerReceipt {
            convo_id: "convo-1".into(),
            epoch: 42,
            sequencer_term: 9,
            commit_hash: vec![1, 2, 3],
            sequencer_did: "did:web:sequencer.example".into(),
            issued_at: 1234,
            signature: vec![4, 5, 6],
        }
    }

    #[test]
    fn api_adapters_submit_prepared_requests() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            ));
            let normal = APIAdapter(callback.clone());
            let client = crate::client_bridge::ClientAPIAdapter(callback);

            for adapter in [&normal as &dyn MLSAPIClient, &client as &dyn MLSAPIClient] {
                let req = crate::orchestrator::canonical_transport::PreparedRequest {
                    operation: crate::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition,
                    method: "POST".into(),
                    path: "/xrpc/blue.catbird.chat.submitTransition".into(),
                    body: Some(b"{}".to_vec()),
                };
                let resp = adapter.submit_prepared_request(req).await.expect("submit");
                assert_eq!(resp.status, 200);
            }
        });
    }

    #[test]
    fn api_adapters_preserve_security_server_statuses_and_classifiers() {
        crate::async_runtime::block_on(async {
            for status in [404_u16, 409, 410, 429] {
                let callback = Arc::new(WelcomeCountingApiCallback::new(
                    "did:plc:alice",
                    Arc::new(AtomicUsize::new(0)),
                ));
                callback.server_status.store(status, Ordering::SeqCst);
                let normal = APIAdapter(callback.clone());
                let client = crate::client_bridge::ClientAPIAdapter(callback);

                for adapter in [&normal as &dyn MLSAPIClient, &client as &dyn MLSAPIClient] {
                    let error = adapter
                        .get_welcome("convo-1")
                        .await
                        .expect_err("configured server error");
                    assert!(matches!(
                        error,
                        OrchestratorError::ServerError { status: actual, .. } if actual == status
                    ));
                    assert_eq!(error.is_rate_limited(), status == 429);
                    assert_eq!(error.is_bootstrap_already_bootstrapped(), status == 409);
                }
            }
        });
    }

    #[test]
    fn client_storage_adapter_forwards_security_arguments_and_write_failures() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(RecordingStorageCallback::default());
            let adapter = crate::client_bridge::ClientStorageAdapter(callback.clone());
            adapter
                .mark_reset_pending("convo-reset", "aabb", 7, 1234)
                .await
                .expect("reset payload");
            assert!(adapter
                .adopt_reset_pending_target("convo-reset", 7, "aabb", "ccdd")
                .await
                .expect("reset winner adoption"));
            adapter
                .mark_quarantined("convo-quarantine", "peer_bad_commit", 2345)
                .await
                .expect("quarantine payload");
            adapter
                .set_recovery_backoff(&PersistedRecoveryBackoff {
                    conversation_id: "convo-backoff".into(),
                    failed_rejoin_count: 3,
                    last_attempt_at_ms: 3456,
                    quarantined_until_ms: Some(4567),
                })
                .await
                .expect("backoff payload");
            adapter
                .set_last_global_rejoin_attempt_at(5678)
                .await
                .expect("global timestamp");
            adapter
                .mark_pending_local_delete("convo-delete", Some("ccdd"))
                .await
                .expect("pending delete");

            assert_eq!(
                callback.reset_payload.lock().unwrap().clone(),
                Some(("convo-reset".into(), "ccdd".into(), 7, 1234))
            );
            assert_eq!(
                callback.quarantine_payload.lock().unwrap().clone(),
                Some(("convo-quarantine".into(), "peer_bad_commit".into(), 2345))
            );
            assert_eq!(
                callback
                    .backoff
                    .lock()
                    .unwrap()
                    .get("convo-backoff")
                    .cloned()
                    .expect("recorded backoff")
                    .quarantined_until_ms,
                Some(4567)
            );
            assert_eq!(*callback.last_global_ms.lock().unwrap(), Some(5678));
            assert_eq!(
                callback
                    .pending_deletes
                    .lock()
                    .unwrap()
                    .get("convo-delete")
                    .cloned()
                    .expect("recorded delete")
                    .group_id_hex,
                Some("ccdd".into())
            );

            callback.fail_security_writes.store(true, Ordering::SeqCst);
            assert!(matches!(
                adapter
                    .adopt_reset_pending_target("convo", 1, "aabb", "ccdd")
                    .await,
                Err(OrchestratorError::Storage(message)) if message == "injected storage failure"
            ));
            let failures = [
                adapter.mark_reset_pending("convo", "aabb", 1, 1).await,
                adapter
                    .mark_quarantined("convo", "peer_bad_commit", 1)
                    .await,
                adapter
                    .set_recovery_backoff(&PersistedRecoveryBackoff {
                        conversation_id: "convo".into(),
                        failed_rejoin_count: 1,
                        last_attempt_at_ms: 1,
                        quarantined_until_ms: None,
                    })
                    .await,
                adapter.set_last_global_rejoin_attempt_at(1).await,
                adapter.mark_pending_local_delete("convo", None).await,
            ];
            assert!(failures.into_iter().all(|result| matches!(
                result,
                Err(OrchestratorError::Storage(message)) if message == "injected storage failure"
            )));
        });
    }

    #[test]
    fn both_storage_adapters_decode_complete_and_reject_malformed_restart_state() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(RecordingStorageCallback::default());
            let adapters: Vec<Box<dyn MLSStorageBackend>> = vec![
                Box::new(StorageAdapter(callback.clone())),
                Box::new(crate::client_bridge::ClientStorageAdapter(callback.clone())),
            ];

            callback.conversation_states.lock().unwrap().insert(
                "reset".into(),
                FFIConversationState {
                    state: "reset_pending".into(),
                    new_group_id: Some("aabb".into()),
                    reset_generation: Some(9),
                    notified_at_ms: Some(1234),
                    quarantine_reason: None,
                    quarantined_since_ms: None,
                },
            );
            callback.conversation_states.lock().unwrap().insert(
                "quarantine".into(),
                FFIConversationState {
                    state: "quarantined".into(),
                    new_group_id: None,
                    reset_generation: None,
                    notified_at_ms: None,
                    quarantine_reason: Some("multi_peer_bad_commits".into()),
                    quarantined_since_ms: Some(5678),
                },
            );

            for adapter in &adapters {
                assert_eq!(
                    adapter.get_conversation_state("reset").await.unwrap(),
                    Some(ConversationState::ResetPending {
                        new_group_id: "aabb".into(),
                        reset_generation: 9,
                        notified_at_ms: 1234,
                    })
                );
                assert_eq!(
                    adapter.get_conversation_state("quarantine").await.unwrap(),
                    Some(ConversationState::Quarantined {
                        reason: crate::orchestrator::types::QuarantineReason::MultiPeerBadCommits,
                        since_ms: 5678,
                    })
                );
            }

            let malformed = [
                FFIConversationState {
                    state: "reset_pending".into(),
                    new_group_id: None,
                    reset_generation: Some(1),
                    notified_at_ms: Some(1),
                    quarantine_reason: None,
                    quarantined_since_ms: None,
                },
                FFIConversationState {
                    state: "quarantined".into(),
                    new_group_id: None,
                    reset_generation: None,
                    notified_at_ms: None,
                    quarantine_reason: None,
                    quarantined_since_ms: Some(1),
                },
                FFIConversationState {
                    state: "unknown".into(),
                    new_group_id: None,
                    reset_generation: None,
                    notified_at_ms: None,
                    quarantine_reason: None,
                    quarantined_since_ms: None,
                },
            ];
            for (index, state) in malformed.into_iter().enumerate() {
                let key = format!("malformed-{index}");
                callback
                    .conversation_states
                    .lock()
                    .unwrap()
                    .insert(key.clone(), state);
                for adapter in &adapters {
                    assert!(matches!(
                        adapter.get_conversation_state(&key).await,
                        Err(OrchestratorError::Storage(_))
                    ));
                }
            }
        });
    }

    /// Ruling 2a (2026-08-15): a server reset is a documented quarantine exit,
    /// and the exit belongs to the `mark_reset_pending` authority commit — not
    /// to the separate `clear_quarantine` callback issued after it. A backend
    /// that defers the clear to that callback can leave a row that is
    /// simultaneously reset-pending and quarantined, and such a row rehydrates
    /// quarantined forever because the replayed reset dedupes on generation
    /// before reaching the clear again. Both adapters must therefore see the
    /// quarantine gone the moment `mark_reset_pending` returns, with no
    /// `clear_quarantine` call in between.
    #[test]
    fn both_storage_adapters_exit_quarantine_inside_the_reset_authority_commit() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(RecordingStorageCallback::default());
            let adapters: Vec<(&str, Box<dyn MLSStorageBackend>)> = vec![
                (
                    "storage-adapter",
                    Box::new(StorageAdapter(callback.clone())),
                ),
                (
                    "client-storage-adapter",
                    Box::new(crate::client_bridge::ClientStorageAdapter(callback.clone())),
                ),
            ];

            for (convo_id, adapter) in &adapters {
                adapter
                    .mark_quarantined(convo_id, "multi_peer_bad_commits", 5678)
                    .await
                    .expect("seed persisted quarantine");
                assert!(
                    matches!(
                        adapter.get_conversation_state(convo_id).await.unwrap(),
                        Some(ConversationState::Quarantined { .. })
                    ),
                    "{convo_id}: quarantine must persist before the reset (test precondition)"
                );

                // No `clear_quarantine` call here — the authority commit alone
                // has to be the exit.
                adapter
                    .mark_reset_pending(convo_id, "aabb", 9, 1234)
                    .await
                    .expect("reset authority commit");

                assert_eq!(
                    adapter.get_conversation_state(convo_id).await.unwrap(),
                    None,
                    "RULING 2a REGRESSION ({convo_id}): the reset authority commit left \
                     persisted quarantine behind, minting a both-set row"
                );
            }

            // The reset payload still lands — the quarantine exit rides along
            // with the tag rather than replacing it.
            assert_eq!(
                callback.reset_payload.lock().unwrap().clone(),
                Some(("client-storage-adapter".into(), "aabb".into(), 9, 1234))
            );
        });
    }

    #[test]
    fn both_storage_adapters_propagate_pending_receipt_and_clear_failures() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(RecordingStorageCallback::default());
            callback.fail_security_writes.store(true, Ordering::SeqCst);
            let adapters: Vec<Box<dyn MLSStorageBackend>> = vec![
                Box::new(StorageAdapter(callback.clone())),
                Box::new(crate::client_bridge::ClientStorageAdapter(callback)),
            ];
            let receipt = crate::orchestrator::types::SequencerReceipt {
                convo_id: "convo".into(),
                epoch: 1,
                sequencer_term: 2,
                commit_hash: vec![1],
                sequencer_did: "did:web:sequencer".into(),
                issued_at: 1,
                signature: vec![2],
            };

            for adapter in adapters {
                assert_storage_failure(adapter.store_pending_message("convo", "message").await);
                assert!(matches!(
                    adapter.remove_pending_message("message").await,
                    Err(OrchestratorError::Storage(_))
                ));
                assert_storage_failure(adapter.store_sequencer_receipt(&receipt).await);
                assert!(matches!(
                    adapter.get_sequencer_receipts("convo", None).await,
                    Err(OrchestratorError::Storage(_))
                ));
                assert_storage_failure(adapter.clear_sequencer_receipts("convo").await);
                assert!(matches!(
                    adapter.complete_reset_pending("convo", 1, "target", 9).await,
                    Err(OrchestratorError::Storage(message))
                        if message == "injected storage failure"
                ));
                assert_storage_failure(adapter.clear_quarantine("convo").await);
                assert_storage_failure(adapter.clear_recovery_backoff("convo").await);
                assert_storage_failure(adapter.clear_pending_local_delete("convo").await);
            }
        });
    }

    #[test]
    fn both_storage_adapters_forward_reset_outcomes_and_generations_exactly() {
        crate::async_runtime::block_on(async {
            let callback = Arc::new(RecordingStorageCallback::default());
            let adapters: Vec<Box<dyn MLSStorageBackend>> = vec![
                Box::new(StorageAdapter(callback.clone())),
                Box::new(crate::client_bridge::ClientStorageAdapter(callback.clone())),
            ];

            assert!(!adapters[0]
                .complete_reset_pending("convo-a", 7, "target-a", 42)
                .await
                .expect("orchestrator adapter false completion"));
            callback.reset_clear_applied.store(true, Ordering::SeqCst);
            assert!(adapters[1]
                .clear_reset_pending_for_delete("convo-b", 8)
                .await
                .expect("client adapter true delete clear"));

            assert_eq!(
                callback.reset_clear_requests.lock().unwrap().as_slice(),
                &[
                    (
                        "convo-a".to_string(),
                        Some(7),
                        Some("target-a".to_string()),
                        Some(42),
                    ),
                    ("convo-b".to_string(), Some(8), None, None),
                ]
            );
        });
    }

    fn assert_storage_failure(result: crate::orchestrator::Result<()>) {
        assert!(matches!(
            result,
            Err(OrchestratorError::Storage(message)) if message == "injected storage failure"
        ));
    }

    #[test]
    fn orchestrator_bridge_construction_fails_before_startup_when_capability_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mls_context = MLSContext::new(
            dir.path()
                .join("missing-capability.sqlite")
                .to_string_lossy()
                .to_string(),
            "missing-capability-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let mut capabilities = full_security_capabilities();
        capabilities.sequencer_receipts = false;

        let result = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            capabilities,
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        );

        assert!(matches!(
            result,
            Err(OrchestratorBridgeError::MissingSecurityCapability {
                capability,
                required_version: 3,
                declared_version: 3,
            }) if capability == "sequencer_receipts"
        ));
    }

    #[test]
    fn catbird_client_construction_and_wrong_contract_version_fail_closed() {
        for (version, pending_messages, expected) in [
            (3_u16, false, "pending_message_protection"),
            (2_u16, true, "contract_version"),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let mls_context = MLSContext::new(
                dir.path()
                    .join("client-capability.sqlite")
                    .to_string_lossy()
                    .to_string(),
                "client-capability-test-key".to_string(),
                Box::new(RecordingKeychain::default()),
            )
            .expect("test MLSContext");
            let mut capabilities = full_security_capabilities();
            capabilities.version = version;
            capabilities.pending_message_protection = pending_messages;

            let result = crate::client_bridge::CatbirdClientBridge::new(
                "did:plc:alice".into(),
                mls_context,
                Box::new(RecordingStorageCallback::default()),
                Box::new(WelcomeCountingApiCallback::new(
                    "did:plc:alice",
                    Arc::new(AtomicUsize::new(0)),
                )),
                Box::new(RecordingCredentialCallback::default()),
                capabilities,
                FFIOrchestratorConfig {
                    max_devices: 5,
                    target_key_package_count: 1,
                    key_package_replenish_threshold: 1,
                    sync_cooldown_seconds: 0,
                    max_consecutive_sync_failures: 3,
                    sync_pause_duration_seconds: 1,
                    rejoin_cooldown_seconds: 0,
                    max_rejoin_attempts: 3,
                },
            );

            assert!(matches!(
                result,
                Err(OrchestratorBridgeError::MissingSecurityCapability { capability, .. })
                    if capability == expected
            ));
        }
    }

    #[test]
    fn orchestrator_bridge_join_or_rejoin_reaches_rust_recovery_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("bridge-join-or-rejoin.sqlite");
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "bridge-join-or-rejoin-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let welcome_calls = Arc::new(AtomicUsize::new(0));
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                welcome_calls.clone(),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");

        bridge
            .initialize("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string())
            .expect("bridge initialize");
        bridge
            .ensure_device_registered()
            .expect("registered test device");
        let result = bridge.join_or_rejoin("convo-bridge-probe".to_string());

        assert!(
            result.is_err(),
            "stubbed canonical Welcome response should stop recovery"
        );
        assert_eq!(
            welcome_calls.load(Ordering::SeqCst),
            1,
            "OrchestratorBridge.joinOrRejoin must call MLSOrchestrator::join_or_rejoin, whose first step probes Welcome"
        );
    }

    #[test]
    fn legacy_group_id_member_mutation_entry_points_reach_post_reset_stable_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mls_context = MLSContext::new(
            dir.path()
                .join("bridge-legacy-group-id-after-reset.sqlite")
                .to_string_lossy()
                .to_string(),
            "bridge-legacy-group-id-after-reset-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let stable_conversation_id = "stable-conversation-after-reset";
        let predecessor_group_id = "11".repeat(32);
        let reset_target_group_id = "22".repeat(32);
        let storage = RecordingStorageCallback::default();
        storage.conversation_states.lock().unwrap().insert(
            stable_conversation_id.into(),
            FFIConversationState {
                state: "reset_pending".into(),
                new_group_id: Some(reset_target_group_id.clone()),
                reset_generation: Some(7),
                notified_at_ms: Some(1_700_000_000_000),
                quarantine_reason: None,
                quarantined_since_ms: None,
            },
        );
        let credentials = RecordingCredentialCallback::default();
        credentials.device_uuids.lock().unwrap().insert(
            "did:plc:alice".into(),
            "00000000-0000-4000-8000-000000000001".into(),
        );
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(storage),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(credentials),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");
        bridge
            .initialize("did:plc:alice".to_string())
            .expect("bridge initialize");

        crate::async_runtime::block_on(async {
            bridge.inner.conversations().lock().await.insert(
                stable_conversation_id.into(),
                ConversationView {
                    group_id: predecessor_group_id,
                    conversation_id: stable_conversation_id.into(),
                    epoch: 3,
                    members: vec![],
                    metadata: None,
                    sequencer_did: None,
                    canonical_state: None,
                    created_at: None,
                    updated_at: None,
                },
            );
            bridge.inner.conversation_states().lock().await.insert(
                stable_conversation_id.into(),
                ConversationState::ResetPending {
                    new_group_id: reset_target_group_id.clone(),
                    reset_generation: 7,
                    notified_at_ms: 1_700_000_000_000,
                },
            );
        });

        assert!(
            bridge
                .add_members(reset_target_group_id.clone(), vec![])
                .is_ok(),
            "add_members translates post-reset group_id and completes policy invitation"
        );
        let results = [
            (
                "remove_members",
                bridge.remove_members(reset_target_group_id.clone(), vec![]),
            ),
            (
                "swap_members",
                bridge.swap_members(reset_target_group_id.clone(), vec![], vec![]),
            ),
        ];
        for (operation, result) in results {
            assert!(
                matches!(
                    result,
                    Err(OrchestratorBridgeError::Mls { message })
                        if message.contains(&reset_target_group_id)
                ),
                "{operation} must translate the documented post-reset group_id to its stable conversation and reach the target MLS group before failing on this intentionally unmaterialized fixture"
            );
        }
    }

    #[test]
    fn legacy_group_id_bridge_rejects_stable_id_collision_with_another_current_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mls_context = MLSContext::new(
            dir.path()
                .join("bridge-legacy-group-id-ambiguity.sqlite")
                .to_string_lossy()
                .to_string(),
            "bridge-legacy-group-id-ambiguity-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");
        bridge
            .initialize("did:plc:alice".to_string())
            .expect("bridge initialize");

        let colliding_identifier = "33".repeat(32);
        crate::async_runtime::block_on(async {
            let mut conversations = bridge.inner.conversations().lock().await;
            conversations.insert(
                colliding_identifier.clone(),
                ConversationView {
                    group_id: "44".repeat(32),
                    conversation_id: colliding_identifier.clone(),
                    epoch: 1,
                    members: vec![],
                    metadata: None,
                    sequencer_did: None,
                    canonical_state: None,
                    created_at: None,
                    updated_at: None,
                },
            );
            conversations.insert(
                "other-stable-conversation".into(),
                ConversationView {
                    group_id: colliding_identifier.clone(),
                    conversation_id: "other-stable-conversation".into(),
                    epoch: 1,
                    members: vec![],
                    metadata: None,
                    sequencer_did: None,
                    canonical_state: None,
                    created_at: None,
                    updated_at: None,
                },
            );
        });

        assert!(matches!(
            bridge.add_members(colliding_identifier, vec![]),
            Err(OrchestratorBridgeError::InvalidInput { message })
                if message.contains("resolves to 2 stable conversations")
        ));
    }

    #[test]
    fn orchestrator_bridge_debug_wipe_local_group_uses_engine_auth_guard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("bridge-debug-wipe-local-group.sqlite");
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "bridge-debug-wipe-local-group-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");

        let err = bridge
            .debug_wipe_local_group_for_recovery("convo-bridge-probe".to_string())
            .expect_err("debug wipe must require engine initialization");

        assert!(
            matches!(err, OrchestratorBridgeError::NotAuthenticated),
            "debug wipe should route through MlsEngine and preserve its auth guard, got {err:?}"
        );
    }

    #[test]
    fn orchestrator_bridge_engine_shutdown_reinitialize_allows_sync() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("bridge-engine-lifecycle.sqlite");
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "bridge-engine-lifecycle-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");

        bridge
            .initialize("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string())
            .expect("bridge initialize");
        bridge
            .ensure_device_registered()
            .expect("registered test device");
        bridge.shutdown();
        bridge
            .initialize("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string())
            .expect("bridge reinitialize");
        bridge
            .sync_with_server(false)
            .expect("sync should succeed after bridge shutdown and reinitialize");

        bridge.shutdown();
        let shutdown_result = crate::async_runtime::block_on(bridge.inner.check_shutdown());
        assert!(
            matches!(shutdown_result, Err(OrchestratorError::ShuttingDown)),
            "second bridge shutdown must reach the raw orchestrator after public reinitialize"
        );
    }

    #[test]
    fn initialize_engine_rebinds_after_legacy_initialize_changes_orchestrator_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("bridge-engine-mixed-init.sqlite");
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "bridge-engine-mixed-init-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");

        bridge
            .initialize_engine("did:plc:alice".to_string())
            .expect("engine initialize alice");
        bridge
            .initialize("did:plc:bob".to_string())
            .expect("legacy initialize bob");
        bridge
            .initialize_engine("did:plc:alice".to_string())
            .expect("engine reinitialize alice");

        let current_user =
            crate::async_runtime::block_on(async { bridge.inner.require_user_did().await.ok() });

        assert_eq!(
            current_user.as_deref(),
            Some("did:plc:alice"),
            "engine initialize must reconcile its cached DID with the actual raw orchestrator user"
        );
    }

    #[test]
    fn initialize_engine_clears_raw_state_after_legacy_rebind_while_suspended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("bridge-engine-mixed-phase-rebind.sqlite");
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "bridge-engine-mixed-phase-rebind-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");

        bridge
            .initialize_engine("did:plc:alice".to_string())
            .expect("engine initialize alice");
        bridge
            .engine
            .shutdown(crate::ShutdownReason::AppSuspend)
            .expect("suspend engine");
        bridge
            .initialize("did:plc:bob".to_string())
            .expect("legacy initialize bob");

        crate::async_runtime::block_on(async {
            bridge.inner.conversations().lock().await.insert(
                "bob-convo".to_string(),
                ConversationView {
                    group_id: "b1".to_string(),
                    conversation_id: "bob-convo".to_string(),
                    epoch: 11,
                    members: vec![MemberView {
                        did: "did:plc:bob".to_string(),
                        role: MemberRole::Admin,
                    }],
                    metadata: None,
                    created_at: None,
                    updated_at: None,
                    sequencer_did: None,
                    canonical_state: None,
                },
            );
            bridge.inner.group_states().lock().await.insert(
                "b1".to_string(),
                GroupState {
                    group_id: "b1".to_string(),
                    conversation_id: "bob-convo".to_string(),
                    epoch: 11,
                    members: vec!["did:plc:bob".to_string()],
                },
            );
            bridge
                .inner
                .conversation_states()
                .lock()
                .await
                .insert("bob-convo".to_string(), ConversationState::NeedsRejoin);
        });

        bridge
            .initialize_engine("did:plc:alice".to_string())
            .expect("engine resume alice");

        let (current_user, conversation_count, group_state_count, conversation_state_count) =
            crate::async_runtime::block_on(async {
                (
                    bridge.inner.require_user_did().await.ok(),
                    bridge.inner.conversations().lock().await.len(),
                    bridge.inner.group_states().lock().await.len(),
                    bridge.inner.conversation_states().lock().await.len(),
                )
            });

        assert_eq!(current_user.as_deref(), Some("did:plc:alice"));
        assert_eq!(
            conversation_count, 0,
            "engine reinitialize must clear Bob conversation cache after suspended legacy rebind"
        );
        assert_eq!(
            group_state_count, 0,
            "engine reinitialize must clear Bob group cache after suspended legacy rebind"
        );
        assert_eq!(
            conversation_state_count, 0,
            "engine reinitialize must clear Bob recovery cache after suspended legacy rebind"
        );
    }

    #[test]
    fn initialize_engine_clears_user_scoped_cache_when_did_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("bridge-engine-did-reset.sqlite");
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "bridge-engine-did-reset-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(RecordingCredentialCallback::default()),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");

        bridge
            .initialize_engine("did:plc:alice".to_string())
            .expect("engine initialize alice");

        crate::async_runtime::block_on(async {
            bridge.inner.conversations().lock().await.insert(
                "alice-convo".to_string(),
                ConversationView {
                    group_id: "a1".to_string(),
                    conversation_id: "alice-convo".to_string(),
                    epoch: 7,
                    members: vec![MemberView {
                        did: "did:plc:alice".to_string(),
                        role: MemberRole::Admin,
                    }],
                    metadata: None,
                    created_at: None,
                    updated_at: None,
                    sequencer_did: None,
                    canonical_state: None,
                },
            );
            bridge.inner.group_states().lock().await.insert(
                "a1".to_string(),
                GroupState {
                    group_id: "a1".to_string(),
                    conversation_id: "alice-convo".to_string(),
                    epoch: 7,
                    members: vec!["did:plc:alice".to_string()],
                },
            );
            bridge
                .inner
                .conversation_states()
                .lock()
                .await
                .insert("alice-convo".to_string(), ConversationState::NeedsRejoin);
        });

        bridge
            .initialize_engine("did:plc:bob".to_string())
            .expect("engine initialize bob");

        let (current_user, conversation_count, group_state_count, conversation_state_count) =
            crate::async_runtime::block_on(async {
                (
                    bridge.inner.require_user_did().await.ok(),
                    bridge.inner.conversations().lock().await.len(),
                    bridge.inner.group_states().lock().await.len(),
                    bridge.inner.conversation_states().lock().await.len(),
                )
            });

        assert_eq!(current_user.as_deref(), Some("did:plc:bob"));
        assert_eq!(
            conversation_count, 0,
            "Bob must not inherit Alice conversation cache entries after engine rebinding"
        );
        assert_eq!(
            group_state_count, 0,
            "Bob must not inherit Alice group-state cache entries after engine rebinding"
        );
        assert_eq!(
            conversation_state_count, 0,
            "Bob must not inherit Alice recovery state after engine rebinding"
        );
    }

    #[test]
    fn conversation_recovery_projection_matches_swift_vocabulary() {
        fn project_conversation_recovery_state(
            state: Option<&ConversationState>,
        ) -> FFIConversationRecoveryState {
            let projected = match state {
                None | Some(ConversationState::Active) => {
                    crate::orchestrator::ConversationRecoveryState::Healthy
                }
                Some(ConversationState::Initializing) => {
                    crate::orchestrator::ConversationRecoveryState::Recovering
                }
                Some(ConversationState::ForkDetected) => {
                    crate::orchestrator::ConversationRecoveryState::EpochBehind
                }
                Some(ConversationState::NeedsRejoin) => {
                    crate::orchestrator::ConversationRecoveryState::NeedsRejoin
                }
                Some(ConversationState::ResetPending { .. }) => {
                    crate::orchestrator::ConversationRecoveryState::ResetPending
                }
                Some(ConversationState::Closed)
                | Some(ConversationState::DeviceRemoved)
                | Some(ConversationState::Quarantined { .. })
                | Some(ConversationState::Failed) => {
                    crate::orchestrator::ConversationRecoveryState::UnrecoverableLocal
                }
            };
            ffi_conversation_recovery_state(projected)
        }

        assert_eq!(
            project_conversation_recovery_state(None),
            FFIConversationRecoveryState::Healthy
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::Active)),
            FFIConversationRecoveryState::Healthy
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::Initializing)),
            FFIConversationRecoveryState::Recovering
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::ForkDetected)),
            FFIConversationRecoveryState::EpochBehind
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::NeedsRejoin)),
            FFIConversationRecoveryState::NeedsRejoin
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::ResetPending {
                new_group_id: "aabb".to_string(),
                reset_generation: 7,
                notified_at_ms: 1_700_000_000_000,
            })),
            FFIConversationRecoveryState::ResetPending
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::Quarantined {
                reason: crate::orchestrator::QuarantineReason::PeerBadCommit,
                since_ms: 1_700_000_000_000,
            })),
            FFIConversationRecoveryState::UnrecoverableLocal
        );
        assert_eq!(
            project_conversation_recovery_state(Some(&ConversationState::Failed)),
            FFIConversationRecoveryState::UnrecoverableLocal
        );
    }

    #[tokio::test]
    async fn storage_adapter_round_trips_recovery_backoff() {
        let callback = Arc::new(RecordingStorageCallback::default());
        let adapter = StorageAdapter(callback.clone() as Arc<dyn OrchestratorStorageCallback>);

        // set → get
        let entry = PersistedRecoveryBackoff {
            conversation_id: "convo-rt".to_string(),
            failed_rejoin_count: 2,
            last_attempt_at_ms: 1_700_000_000_000,
            quarantined_until_ms: Some(1_700_086_400_000),
        };
        adapter
            .set_recovery_backoff(&entry)
            .await
            .expect("set_recovery_backoff must forward");
        adapter
            .set_last_global_rejoin_attempt_at(1_700_000_000_500)
            .await
            .expect("set_last_global_rejoin_attempt_at must forward");

        let state = adapter
            .get_recovery_state()
            .await
            .expect("get_recovery_state must forward");
        assert_eq!(state.entries, vec![entry.clone()]);
        assert_eq!(
            state.last_global_rejoin_attempt_at_ms,
            Some(1_700_000_000_500)
        );

        // clear → empty
        adapter
            .clear_recovery_backoff("convo-rt")
            .await
            .expect("clear_recovery_backoff must forward");
        let state = adapter.get_recovery_state().await.unwrap();
        assert!(
            state.entries.is_empty(),
            "cleared backoff entry must not survive the adapter round-trip"
        );
    }

    #[tokio::test]
    async fn storage_adapter_round_trips_pending_local_deletes() {
        let callback = Arc::new(RecordingStorageCallback::default());
        let adapter = StorageAdapter(callback.clone() as Arc<dyn OrchestratorStorageCallback>);

        adapter
            .mark_pending_local_delete("convo-del", Some("aabb"))
            .await
            .expect("mark_pending_local_delete must forward");
        let pending = adapter.list_pending_local_deletes().await.unwrap();
        assert_eq!(
            pending,
            vec![PendingLocalDelete {
                conversation_id: "convo-del".to_string(),
                group_id_hex: Some("aabb".to_string()),
            }]
        );

        adapter
            .clear_pending_local_delete("convo-del")
            .await
            .expect("clear_pending_local_delete must forward");
        assert!(adapter
            .list_pending_local_deletes()
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn storage_adapter_declares_e7_optional_methods() {
        let callback = Arc::new(RecordingStorageCallback::default());
        let adapter = StorageAdapter(callback as Arc<dyn OrchestratorStorageCallback>);
        let declared = adapter.implemented_optional_methods();
        for method in [
            "adopt_reset_pending_target",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
            "mark_pending_local_delete",
            "clear_pending_local_delete",
            "list_pending_local_deletes",
        ] {
            assert!(
                declared.contains(&method),
                "StorageAdapter must declare {method} as implemented (WS-5.6 capabilities check)"
            );
        }
    }

    fn device_auth_signing_bridge_with_credentials(
        credentials: RecordingCredentialCallback,
    ) -> (tempfile::TempDir, Arc<OrchestratorBridge>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mls_context = MLSContext::new(
            dir.path()
                .join("device-auth-signing.sqlite")
                .to_string_lossy()
                .to_string(),
            "device-auth-signing-test-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("test MLSContext");
        let bridge = OrchestratorBridge::new(
            mls_context,
            Box::new(RecordingStorageCallback::default()),
            Box::new(WelcomeCountingApiCallback::new(
                "did:plc:alice",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(credentials),
            full_security_capabilities(),
            FFIOrchestratorConfig {
                max_devices: 5,
                target_key_package_count: 1,
                key_package_replenish_threshold: 1,
                sync_cooldown_seconds: 0,
                max_consecutive_sync_failures: 3,
                sync_pause_duration_seconds: 1,
                rejoin_cooldown_seconds: 0,
                max_rejoin_attempts: 3,
            },
        )
        .expect("bridge construction");
        (dir, bridge)
    }

    fn device_auth_signing_bridge() -> (tempfile::TempDir, Arc<OrchestratorBridge>) {
        device_auth_signing_bridge_with_credentials(RecordingCredentialCallback::default())
    }

    #[test]
    fn both_public_voice_decode_entrypoints_preserve_input_limit_errors() {
        // Deliberately exceed voice.rs's 8 MiB compressed-input ceiling. Both
        // UniFFI surfaces must preserve the fail-closed decoder result rather
        // than bypassing it or returning attacker-controlled output.
        let oversized = vec![0u8; 8 * 1024 * 1024 + 1];
        let free_function_error =
            ffi_decode_opus_to_pcm(oversized.clone()).expect_err("free function must reject");
        assert!(matches!(
            free_function_error,
            OrchestratorBridgeError::Voice { ref message }
                if message.contains("input exceeds maximum size")
        ));

        let (_dir, bridge) = device_auth_signing_bridge();
        let method_error = bridge
            .decode_opus_to_pcm(oversized)
            .expect_err("bridge method must reject");
        assert!(matches!(
            method_error,
            OrchestratorBridgeError::Voice { ref message }
                if message.contains("input exceeds maximum size")
        ));
    }

    #[test]
    fn device_auth_signing_api_accepts_only_the_challenge() {
        let _signature_only_api: fn(
            &OrchestratorBridge,
            Vec<u8>,
        ) -> Result<Vec<u8>, OrchestratorBridgeError> =
            OrchestratorBridge::sign_device_auth_challenge;
    }

    #[test]
    fn device_auth_signing_refuses_uninitialized_and_shutdown_bridges() {
        let (_dir, bridge) = device_auth_signing_bridge();
        let challenge = b"CATBIRD-DEVICE-AUTH-V1:challenge".to_vec();

        assert!(matches!(
            bridge.sign_device_auth_challenge(challenge.clone()),
            Err(OrchestratorBridgeError::NotAuthenticated)
        ));

        bridge
            .initialize("did:plc:alice".to_string())
            .expect("initialize bridge");
        bridge
            .inner
            .mls_context()
            .create_key_package(b"did:plc:alice".to_vec())
            .expect("register identity signer");
        bridge.shutdown();

        assert!(matches!(
            bridge.sign_device_auth_challenge(challenge),
            Err(OrchestratorBridgeError::NotAuthenticated)
        ));
    }

    #[test]
    fn device_auth_signing_refuses_emergency_closed_bridge_as_not_authenticated() {
        let (_dir, bridge) = device_auth_signing_bridge();
        let did = "did:plc:alice";
        bridge
            .initialize(did.to_string())
            .expect("initialize bridge");
        bridge
            .inner
            .mls_context()
            .create_key_package(did.as_bytes().to_vec())
            .expect("register identity signer");

        bridge
            .emergency_close("device auth lifecycle test".to_string())
            .expect("emergency close bridge");

        assert!(matches!(
            bridge.sign_device_auth_challenge(b"after-emergency-close".to_vec()),
            Err(OrchestratorBridgeError::NotAuthenticated)
        ));
    }

    #[test]
    fn device_auth_signing_rejects_empty_challenge() {
        let (_dir, bridge) = device_auth_signing_bridge();
        bridge
            .initialize("did:plc:alice".to_string())
            .expect("initialize bridge");

        assert!(matches!(
            bridge.sign_device_auth_challenge(Vec::new()),
            Err(OrchestratorBridgeError::InvalidInput { message })
                if message == "device authentication challenge must not be empty"
        ));
    }

    #[test]
    fn device_auth_signature_is_exact_ed25519_key_package_signature() {
        use openmls_traits::types::SignatureScheme;
        use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

        let (_dir, bridge) = device_auth_signing_bridge();
        let did = "did:plc:alice";
        bridge
            .initialize(did.to_string())
            .expect("initialize bridge");
        let key_package = bridge
            .inner
            .mls_context()
            .create_key_package(did.as_bytes().to_vec())
            .expect("create registered KeyPackage");
        let challenge = b"CATBIRD-DEVICE-AUTH-V1:challenge".to_vec();

        let signature = bridge
            .sign_device_auth_challenge(challenge.clone())
            .expect("sign device authentication challenge");

        assert_eq!(
            signature.len(),
            64,
            "Ed25519 signatures are exactly 64 bytes"
        );
        let provider = openmls_libcrux_crypto::Provider::default();
        provider
            .crypto()
            .verify_signature(
                SignatureScheme::ED25519,
                &challenge,
                &key_package.signature_public_key,
                &signature,
            )
            .expect("signature must verify under the KeyPackage public key");

        let mut mutated = challenge;
        mutated[0] ^= 1;
        assert!(
            provider
                .crypto()
                .verify_signature(
                    SignatureScheme::ED25519,
                    &mutated,
                    &key_package.signature_public_key,
                    &signature,
                )
                .is_err(),
            "one-byte challenge mutation must invalidate the signature"
        );
    }

    #[test]
    fn device_auth_signing_restores_the_durable_registered_signer_after_database_recreation() {
        use openmls_traits::types::SignatureScheme;
        use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

        let did = "did:plc:alice";
        let original_dir = tempfile::tempdir().expect("original tempdir");
        let original_context = MLSContext::new(
            original_dir
                .path()
                .join("original.sqlite")
                .to_string_lossy()
                .to_string(),
            "original-device-auth-key".to_string(),
            Box::new(RecordingKeychain::default()),
        )
        .expect("original MLSContext");
        let registered_key_package = original_context
            .create_key_package(did.as_bytes().to_vec())
            .expect("registered KeyPackage");
        let durable_signer = original_context
            .export_identity_key(did.to_string())
            .expect("export durable signer for simulated credential store");

        let credentials = RecordingCredentialCallback::default();
        credentials
            .signing_keys
            .lock()
            .expect("credential signing-key lock")
            .insert(did.to_string(), durable_signer);
        let (_recreated_dir, bridge) = device_auth_signing_bridge_with_credentials(credentials);
        bridge
            .initialize(did.to_string())
            .expect("initialize recreated bridge");

        let challenge = b"CATBIRD-DEVICE-AUTH-V1:recreated-database".to_vec();
        let signature = bridge
            .sign_device_auth_challenge(challenge.clone())
            .expect("restore and use durable registered signer");

        let provider = openmls_libcrux_crypto::Provider::default();
        provider
            .crypto()
            .verify_signature(
                SignatureScheme::ED25519,
                &challenge,
                &registered_key_package.signature_public_key,
                &signature,
            )
            .expect("signature must use the pre-recreation registered public key");
    }

    #[test]
    fn device_auth_signing_refuses_a_drifted_local_signer_when_durable_adoption_fails() {
        let did = "did:plc:alice";
        let credentials = RecordingCredentialCallback::default();
        credentials
            .signing_keys
            .lock()
            .expect("credential signing-key lock")
            .insert(
                did.to_string(),
                b"not-a-serialized-signature-keypair".to_vec(),
            );
        let (_dir, bridge) = device_auth_signing_bridge_with_credentials(credentials);
        bridge
            .initialize(did.to_string())
            .expect("initialize bridge");
        bridge
            .inner
            .mls_context()
            .create_key_package(did.as_bytes().to_vec())
            .expect("create drifted local signer");

        assert!(matches!(
            bridge.sign_device_auth_challenge(
                b"CATBIRD-DEVICE-AUTH-V1:reject-drifted-signer".to_vec()
            ),
            Err(OrchestratorBridgeError::Mls { message })
                if message.contains("durable registered signer could not be reconciled")
        ));
    }

    #[test]
    fn device_auth_signing_discards_a_signature_if_the_initialized_user_changes() {
        use std::sync::mpsc;

        let (_dir, bridge) = device_auth_signing_bridge();
        let alice = "did:plc:alice";
        let bob = "did:plc:bob";
        bridge
            .initialize(alice.to_string())
            .expect("initialize Alice");
        bridge
            .inner
            .mls_context()
            .create_key_package(alice.as_bytes().to_vec())
            .expect("register Alice signer");

        let (signing_entered_tx, signing_entered_rx) = mpsc::channel();
        let (release_signing_tx, release_signing_rx) = mpsc::channel();
        let signing_bridge = Arc::clone(&bridge);
        let signer = std::thread::spawn(move || {
            signing_bridge.sign_device_auth_challenge_with_hook(
                b"CATBIRD-DEVICE-AUTH-V1:user-change-race".to_vec(),
                || {
                    signing_entered_tx
                        .send(())
                        .expect("announce signing critical section");
                    release_signing_rx
                        .recv()
                        .expect("release signing critical section");
                },
            )
        });
        signing_entered_rx
            .recv()
            .expect("signing must capture Alice lifecycle");

        bridge
            .initialize(bob.to_string())
            .expect("change initialized user to Bob");
        release_signing_tx
            .send(())
            .expect("release Alice signing operation");

        assert!(matches!(
            signer.join().expect("signer thread"),
            Err(OrchestratorBridgeError::NotAuthenticated)
        ));
    }

    #[test]
    fn device_auth_signing_serializes_terminal_shutdown() {
        use std::sync::mpsc;

        let (_dir, bridge) = device_auth_signing_bridge();
        let did = "did:plc:alice";
        bridge
            .initialize(did.to_string())
            .expect("initialize bridge");
        bridge
            .inner
            .mls_context()
            .create_key_package(did.as_bytes().to_vec())
            .expect("register identity signer");

        let (signing_entered_tx, signing_entered_rx) = mpsc::channel();
        let (release_signing_tx, release_signing_rx) = mpsc::channel();
        let signing_bridge = Arc::clone(&bridge);
        let signer = std::thread::spawn(move || {
            signing_bridge.sign_device_auth_challenge_with_hook(
                b"CATBIRD-DEVICE-AUTH-V1:race".to_vec(),
                || {
                    signing_entered_tx
                        .send(())
                        .expect("announce signing critical section");
                    release_signing_rx
                        .recv()
                        .expect("release signing critical section");
                },
            )
        });
        signing_entered_rx
            .recv()
            .expect("signing must enter critical section");

        let (shutdown_attempting_tx, shutdown_attempting_rx) = mpsc::channel();
        let (allow_shutdown_lock_tx, allow_shutdown_lock_rx) = mpsc::channel();
        let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel();
        let shutdown_bridge = Arc::clone(&bridge);
        let shutdown = std::thread::spawn(move || {
            shutdown_bridge.shutdown_with_hook(|| {
                shutdown_attempting_tx
                    .send(())
                    .expect("announce shutdown lock attempt");
                allow_shutdown_lock_rx
                    .recv()
                    .expect("allow shutdown lock attempt");
            });
            shutdown_complete_tx
                .send(())
                .expect("announce completed shutdown");
        });

        shutdown_attempting_rx
            .recv()
            .expect("shutdown must reach the lifecycle transition");
        allow_shutdown_lock_tx
            .send(())
            .expect("allow shutdown to attempt lifecycle lock");
        assert!(
            shutdown_complete_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "terminal shutdown must wait while signing owns the lifecycle transition"
        );
        release_signing_tx
            .send(())
            .expect("release signing operation");
        let signature = signer
            .join()
            .expect("signer thread")
            .expect("sign before shutdown transition");
        assert_eq!(signature.len(), 64);
        shutdown_complete_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("shutdown completes after signing releases transition");
        shutdown.join().expect("shutdown thread");

        assert!(matches!(
            bridge.sign_device_auth_challenge(b"after-shutdown".to_vec()),
            Err(OrchestratorBridgeError::NotAuthenticated)
        ));
    }
}
