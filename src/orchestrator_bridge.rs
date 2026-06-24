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
    OrchestratorConfig, OrchestratorError, PendingLocalDelete, PersistedRecoveryBackoff,
    PersistedRecoveryState, ProcessExternalCommitResult, ResetRecordOutcome, SendMessageResponse,
    SyncCursor,
};

use crate::api::MLSContext;
use crate::engine::{EngineLifecycle, MlsEngine};

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
    /// The Rust trait (`MLSStorageBackend::mark_reset_pending`) provides a
    /// no-op default; platforms that haven't adopted the payload may keep the
    /// generated callback stub empty and the behavior is unchanged.
    fn mark_reset_pending(
        &self,
        conversation_id: String,
        new_group_id_hex: String,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<(), OrchestratorBridgeError>;

    /// Clear any persisted `RESET_PENDING` payload after the conversation has
    /// successfully adopted the new group.
    fn clear_reset_pending(&self, conversation_id: String) -> Result<(), OrchestratorBridgeError>;

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

    /// Fetch encrypted envelopes for a conversation.
    ///
    /// `message_type` / `from_epoch` / `to_epoch` mirror the
    /// `blue.catbird.mlsChat.getMessages` lexicon params. Pass-through to the
    /// server URL — platform implementations should forward them untouched.
    /// `from_epoch` and `to_epoch` are inclusive epoch bounds; supplying them
    /// (especially with `message_type = Some("commit")`) keeps epoch catch-up
    /// from being stranded on groups with more than 50 lifetime commits.
    fn get_messages(
        &self,
        convo_id: String,
        cursor: Option<String>,
        limit: u32,
        message_type: Option<String>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
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

    /// Fetch a pending Welcome message for a conversation.
    ///
    /// Platform impls should call the `blue.catbird.mlsChat.getGroupState`
    /// lexicon with `include: "welcome"` and return the raw Welcome bytes.
    ///
    /// If no Welcome is available for this device (consumed, expired, or
    /// never issued), return `OrchestratorBridgeError::ServerError` with
    /// status 404 (or 410 for an explicitly expired Welcome). The
    /// orchestrator uses the status code to distinguish "Welcome gone,
    /// fall back to External Commit" from "transport error".
    fn get_welcome(&self, convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError>;

    /// Submit an External Commit to join/rejoin a conversation.
    ///
    /// Platform impls should POST to `blue.catbird.mlsChat.commitGroupChange`
    /// with `action = "externalCommit"`, the commit bytes, optional
    /// post-commit GroupInfo, and the base64-encoded MLS confirmation tag
    /// from the new local group state. Return the server's new epoch and
    /// `rejoinedAt` timestamp.
    ///
    /// On 409 (epoch race), return `ServerError { status: 409 }` — the
    /// orchestrator treats this as a retryable failure without burning a
    /// recovery attempt slot. On 429, return `ServerError { status: 429 }`
    /// so the orchestrator can treat it as rate-limited (not a real failure).
    fn process_external_commit(
        &self,
        convo_id: String,
        commit_data: Vec<u8>,
        group_info: Option<Vec<u8>>,
        confirmation_tag: Option<String>,
    ) -> Result<FFIProcessExternalCommitResult, OrchestratorBridgeError>;

    /// Report that recovery has been exhausted for a conversation.
    ///
    /// Called by the orchestrator's `RecoveryTracker` when a conversation has
    /// hit `MAX_REJOIN_ATTEMPTS` external-commit failures (S1.1 of the §8
    /// recovery pyramid). The platform impl should POST to
    /// `blue.catbird.mlsChat.reportRecoveryFailure` so the server can
    /// accumulate quorum reports and trigger an automatic group reset (S2)
    /// per ADR-002 §6.
    ///
    /// `failure_type` is one of `"external_commit_exhausted"`,
    /// `"remote_data_error"`, or future variants.
    ///
    /// `epoch_authenticator` is the hex-encoded local epoch authenticator
    /// (RFC 9420 §8.7) when present — binds the report to a specific epoch
    /// so stale clients can't forge quorum votes. `None` is accepted by
    /// pre-A7 servers; once A7 ships, servers MAY require it.
    ///
    /// `failure_mode` (ADR-008 D1, spec §8.6.1): one of `"local_state_loss"`
    /// or `"group_state_unrecoverable"`. Mode A reports SHOULD NOT count
    /// toward server-side quorum auto-reset (clients should self-heal
    /// instead); Mode B reports indicate the group itself is unrecoverable
    /// and SHOULD count. Optional during interim deployment.
    ///
    /// Errors should be returned (not swallowed); the orchestrator logs but
    /// does not retry, since the local state is already terminal.
    fn report_recovery_failure(
        &self,
        convo_id: String,
        failure_type: String,
        epoch_authenticator: Option<String>,
        failure_mode: Option<String>,
    ) -> Result<(), OrchestratorBridgeError>;
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
    fn get_authorized_device_keys(
        &self,
        user_did: String,
    ) -> Result<Option<Vec<Vec<u8>>>, OrchestratorBridgeError>;
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
pub struct FFIProcessExternalCommitResult {
    pub epoch: u64,
    pub rejoined_at: String,
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

fn project_conversation_recovery_state(
    state: Option<&ConversationState>,
) -> FFIConversationRecoveryState {
    match state {
        None | Some(ConversationState::Active) => FFIConversationRecoveryState::Healthy,
        Some(ConversationState::Initializing) => FFIConversationRecoveryState::Recovering,
        Some(ConversationState::ForkDetected) => FFIConversationRecoveryState::EpochBehind,
        Some(ConversationState::NeedsRejoin) => FFIConversationRecoveryState::NeedsRejoin,
        Some(ConversationState::ResetPending { .. }) => FFIConversationRecoveryState::ResetPending,
        Some(ConversationState::Quarantined { .. }) | Some(ConversationState::Failed) => {
            FFIConversationRecoveryState::UnrecoverableLocal
        }
    }
}

async fn project_conversation_recovery_state_for(
    inner: &ConcreteOrchestrator,
    conversation_id: &str,
) -> FFIConversationRecoveryState {
    let state = inner
        .conversation_states()
        .lock()
        .await
        .get(conversation_id)
        .cloned();
    let projected = project_conversation_recovery_state(state.as_ref());

    if projected != FFIConversationRecoveryState::Healthy {
        return projected;
    }

    let group_id = inner
        .group_states()
        .lock()
        .await
        .values()
        .find(|group| group.conversation_id == conversation_id)
        .map(|group| group.group_id.clone());

    let Some(group_id) = group_id else {
        return projected;
    };
    let Ok(group_id_bytes) = hex::decode(&group_id) else {
        return projected;
    };

    match inner.mls_context().get_epoch(group_id_bytes) {
        Ok(_) => projected,
        Err(_) => FFIConversationRecoveryState::GroupMissing,
    }
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
struct CredentialAdapter(Arc<dyn OrchestratorCredentialCallback>);

// -- Conversion helpers --

fn convo_view_to_ffi(cv: &ConversationView) -> FFIConversationView {
    FFIConversationView {
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
    }
}

fn ffi_to_convo_view(ffi: &FFIConversationView) -> ConversationView {
    ConversationView {
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
    match e {
        OrchestratorBridgeError::Storage { message } => OrchestratorError::Storage(message),
        OrchestratorBridgeError::Api { message } => OrchestratorError::Api(message),
        OrchestratorBridgeError::Credential { message } => OrchestratorError::Credential(message),
        OrchestratorBridgeError::NotAuthenticated => OrchestratorError::NotAuthenticated,
        OrchestratorBridgeError::ShuttingDown => OrchestratorError::ShuttingDown,
        OrchestratorBridgeError::ServerError { status, body } => {
            OrchestratorError::ServerError { status, body }
        }
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
        // The UniFFI bridge carries only the state *tag* across the boundary.
        // For the `ResetPending` variant the full payload (new_group_id,
        // reset_generation, notified_at_ms) is forwarded separately via
        // `mark_reset_pending`; `persist_reset_pending_state` in `recovery.rs`
        // is the call site that invokes both in sequence.
        self.0
            .set_conversation_state(conversation_id.to_string(), state.tag().to_string())
            .map_err(bridge_err)
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

    async fn clear_reset_pending(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .clear_reset_pending(conversation_id.to_string())
            .map_err(bridge_err)
    }

    // WS-5.6 capabilities declaration: the bridge forwards these optional
    // methods to the platform callback; everything else still rides the
    // default no-ops (warned at orchestrator init).
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "mark_reset_pending",
            "clear_reset_pending",
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

    async fn get_welcome(&self, convo_id: &str) -> crate::orchestrator::Result<Vec<u8>> {
        self.0.get_welcome(convo_id.to_string()).map_err(bridge_err)
    }

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
        confirmation_tag: Option<&str>,
    ) -> crate::orchestrator::Result<ProcessExternalCommitResult> {
        let result = self
            .0
            .process_external_commit(
                convo_id.to_string(),
                commit_data.to_vec(),
                group_info.map(|b| b.to_vec()),
                confirmation_tag.map(|s| s.to_string()),
            )
            .map_err(bridge_err)?;
        Ok(ProcessExternalCommitResult {
            epoch: result.epoch,
            rejoined_at: result.rejoined_at,
            receipt: None,
        })
    }

    async fn report_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .report_recovery_failure(
                convo_id.to_string(),
                failure_type.to_string(),
                epoch_authenticator.map(|s| s.to_string()),
                failure_mode.map(|s| s.to_string()),
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

        let storage = Arc::new(StorageAdapter(Arc::from(storage)));
        let api_client = Arc::new(APIAdapter(Arc::from(api_client)));
        let credentials = Arc::new(CredentialAdapter(Arc::from(credentials)));
        let engine = Arc::new(MlsEngine::new(
            mls_context,
            storage,
            api_client,
            credentials,
            Arc::new(EngineLifecycle::default()),
            orch_config,
        ));
        let inner = engine.orchestrator();

        Arc::new(Self { inner, engine })
    }

    /// Initialize the orchestrator for a user DID.
    pub fn initialize(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.initialize(&user_did))?;
        Ok(())
    }

    pub fn initialize_engine(&self, user_did: String) -> Result<(), OrchestratorBridgeError> {
        self.engine.initialize_user(&user_did)?;
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

    /// Atomically swap members in a single commit.
    pub fn swap_members(
        &self,
        group_id: String,
        remove_dids: Vec<String>,
        add_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.swap_members(
            &group_id,
            &remove_dids,
            &add_dids,
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
    /// clears per-conversation recovery trackers, rebinds the group id, and
    /// flags `needs_rejoin`. The deferred-recovery loop driven by
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

// ═══════════════════════════════════════════════════════════════════════════
// Bridge unit tests (WS-5 FIX-4): the E7 persistence + WS-5.2 escalation
// surface must actually cross the UniFFI adapter layer, not ride the trait
// default no-ops.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
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
        fn mark_reset_pending(
            &self,
            _conversation_id: String,
            _new_group_id_hex: String,
            _reset_generation: i32,
            _notified_at_ms: i64,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
        fn clear_reset_pending(
            &self,
            _conversation_id: String,
        ) -> Result<(), OrchestratorBridgeError> {
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
            self.backoff.lock().unwrap().remove(&conversation_id);
            Ok(())
        }
        fn set_last_global_rejoin_attempt_at(
            &self,
            at_ms: i64,
        ) -> Result<(), OrchestratorBridgeError> {
            *self.last_global_ms.lock().unwrap() = Some(at_ms);
            Ok(())
        }
        fn mark_pending_local_delete(
            &self,
            conversation_id: String,
            group_id_hex: Option<String>,
        ) -> Result<(), OrchestratorBridgeError> {
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
    }

    impl WelcomeCountingApiCallback {
        fn new(current_did: &str, welcome_calls: Arc<AtomicUsize>) -> Self {
            Self {
                current_did: current_did.to_string(),
                welcome_calls,
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

        fn create_conversation(
            &self,
            _group_id: String,
            _initial_members: Option<Vec<String>>,
            _metadata_name: Option<String>,
            _metadata_description: Option<String>,
            _commit_data: Option<Vec<u8>>,
            _welcome_data: Option<Vec<u8>>,
        ) -> Result<FFICreateConversationResult, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::Api {
                message: "not used by bridge joinOrRejoin test".to_string(),
            })
        }

        fn leave_conversation(&self, _convo_id: String) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }

        fn add_members(
            &self,
            _convo_id: String,
            _member_dids: Vec<String>,
            _commit_data: Vec<u8>,
            _welcome_data: Option<Vec<u8>>,
        ) -> Result<FFIAddMembersResult, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::Api {
                message: "not used by bridge joinOrRejoin test".to_string(),
            })
        }

        fn remove_members(
            &self,
            _convo_id: String,
            _member_dids: Vec<String>,
            _commit_data: Vec<u8>,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }

        fn send_message(
            &self,
            _convo_id: String,
            _ciphertext: Vec<u8>,
            _epoch: u64,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
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

        fn publish_key_package(
            &self,
            _key_package: Vec<u8>,
            _cipher_suite: String,
            _expires_at: String,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }

        fn get_key_packages(
            &self,
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

        fn register_device(
            &self,
            _device_uuid: String,
            _device_name: String,
            _mls_did: String,
            _signature_key: Vec<u8>,
            _key_packages: Vec<Vec<u8>>,
        ) -> Result<FFIDeviceInfo, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::Api {
                message: "not used by bridge joinOrRejoin test".to_string(),
            })
        }

        fn list_devices(&self) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError> {
            Ok(vec![])
        }

        fn remove_device(&self, _device_id: String) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }

        fn publish_group_info(
            &self,
            _convo_id: String,
            _group_info: Vec<u8>,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }

        fn get_group_info(&self, _convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::ServerError {
                status: 503,
                body: "bridge joinOrRejoin test stopped at GroupInfo".to_string(),
            })
        }

        fn get_welcome(&self, _convo_id: String) -> Result<Vec<u8>, OrchestratorBridgeError> {
            self.welcome_calls.fetch_add(1, Ordering::SeqCst);
            Err(OrchestratorBridgeError::ServerError {
                status: 503,
                body: "bridge joinOrRejoin test Welcome probe".to_string(),
            })
        }

        fn process_external_commit(
            &self,
            _convo_id: String,
            _commit_data: Vec<u8>,
            _group_info: Option<Vec<u8>>,
            _confirmation_tag: Option<String>,
        ) -> Result<FFIProcessExternalCommitResult, OrchestratorBridgeError> {
            Err(OrchestratorBridgeError::Api {
                message: "not used by bridge joinOrRejoin test".to_string(),
            })
        }

        fn report_recovery_failure(
            &self,
            _convo_id: String,
            _failure_type: String,
            _epoch_authenticator: Option<String>,
            _failure_mode: Option<String>,
        ) -> Result<(), OrchestratorBridgeError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingCredentialCallback {
        signing_keys: Mutex<HashMap<String, Vec<u8>>>,
        mls_dids: Mutex<HashMap<String, String>>,
        device_uuids: Mutex<HashMap<String, String>>,
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
            Ok(None)
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
                "did:plc:alice",
                welcome_calls.clone(),
            )),
            Box::new(RecordingCredentialCallback::default()),
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

        bridge
            .initialize("did:plc:alice".to_string())
            .expect("bridge initialize");
        let result = bridge.join_or_rejoin("convo-bridge-probe".to_string());

        assert!(result.is_err(), "stubbed GroupInfo should stop recovery");
        assert_eq!(
            welcome_calls.load(Ordering::SeqCst),
            1,
            "OrchestratorBridge.joinOrRejoin must call MLSOrchestrator::join_or_rejoin, whose first step probes Welcome"
        );
    }

    #[test]
    fn conversation_recovery_projection_matches_swift_vocabulary() {
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
}
