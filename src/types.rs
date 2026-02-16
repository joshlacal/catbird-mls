// UniFFI Record types (structs passed across FFI)

#[derive(uniffi::Record)]
pub struct KeyPackageData {
    pub data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct GroupCreationResult {
    pub group_id: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct AddMembersResult {
    pub commit_data: Vec<u8>,
    pub welcome_data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub padded_size: u32,
}

#[derive(uniffi::Record)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub epoch: u64,
    pub sequence_number: u64,
    pub sender_credential: CredentialData,
}

#[derive(uniffi::Record)]
pub struct ExternalCommitResult {
    pub commit_data: Vec<u8>,
    pub group_id: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct KeyPackageResult {
    pub key_package_data: Vec<u8>,
    pub hash_ref: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct WelcomeResult {
    pub group_id: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct ExportedSecret {
    pub secret: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct CommitResult {
    pub new_epoch: u64,
}

#[derive(uniffi::Record, Clone)]
pub struct CredentialData {
    pub credential_type: String,
    pub identity: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct MemberCredential {
    pub credential: CredentialData,
    pub signature_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct StagedWelcomeInfo {
    pub group_id: Vec<u8>,
    pub sender_credential: CredentialData,
    pub member_credentials: Vec<MemberCredential>,
    pub staged_welcome_id: String,
}

#[derive(uniffi::Record)]
pub struct StagedCommitInfo {
    pub group_id: Vec<u8>,
    pub sender_credential: CredentialData,
    pub added_members: Vec<MemberCredential>,
    pub removed_members: Vec<MemberCredential>,
    pub staged_commit_id: String,
}

#[derive(uniffi::Record)]
pub struct UpdateProposalInfo {
    pub leaf_index: u32,
    pub old_credential: CredentialData,
    pub new_credential: CredentialData,
}

#[derive(uniffi::Record)]
pub struct GroupMemberDebugInfo {
    pub leaf_index: u32,
    pub credential_identity: Vec<u8>,
    pub credential_type: String,
}

#[derive(uniffi::Record)]
pub struct GroupDebugInfo {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub total_members: u32,
    pub members: Vec<GroupMemberDebugInfo>,
}

// Proposal inspection types

#[derive(uniffi::Record)]
pub struct ProposalRef {
    pub data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct AddProposalInfo {
    pub credential: CredentialData,
    pub key_package_ref: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct RemoveProposalInfo {
    pub removed_index: u32,
}

#[derive(uniffi::Enum)]
pub enum ProposalInfo {
    Add { info: AddProposalInfo },
    Remove { info: RemoveProposalInfo },
    Update { info: UpdateProposalInfo },
}

#[derive(uniffi::Enum)]
pub enum ProcessedContent {
    ApplicationMessage {
        plaintext: Vec<u8>,
        sender: CredentialData,
    },
    Proposal {
        proposal: ProposalInfo,
        proposal_ref: ProposalRef,
    },
    StagedCommit {
        new_epoch: u64,
    },
}

#[derive(uniffi::Record)]
pub struct ProcessCommitResult {
    pub new_epoch: u64,
    pub update_proposals: Vec<UpdateProposalInfo>,
    pub add_proposals: Vec<AddProposalInfo>,
    pub remove_proposals: Vec<RemoveProposalInfo>,
}

#[derive(uniffi::Record, Clone)]
pub struct GroupConfig {
    pub max_past_epochs: u32,
    pub out_of_order_tolerance: u32,
    pub maximum_forward_distance: u32,
    /// Maximum allowed lifetime for leaf nodes in seconds.
    /// Set to 0 to disable lifetime validation.
    /// Recommended: 86400 * 90 (90 days)
    pub max_leaf_lifetime_seconds: u64,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            max_past_epochs: 5, // Retain 5 past epochs to handle network delays and message reordering
            out_of_order_tolerance: 10,
            maximum_forward_distance: 2000,
            max_leaf_lifetime_seconds: 86400 * 90, // 90 days
        }
    }
}

// Logger callback trait for Swift OSLog integration
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait MLSLogger: Send + Sync {
    /// Log a message from Rust to Swift's OSLog
    /// - level: "debug", "info", "warning", "error"
    /// - message: The log message
    async fn log(&self, level: String, message: String);
}

// Epoch secret storage callback trait for Swift encrypted storage
// Uses async callback interface for native Swift async/await integration
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait EpochSecretStorage: Send + Sync {
    /// Store epoch secret for a conversation
    /// - conversation_id: Hex-encoded conversation/group ID
    /// - epoch: Epoch number
    /// - secret_data: Serialized epoch secret material
    /// Returns true if stored successfully
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool;

    /// Retrieve epoch secret for a conversation
    /// - conversation_id: Hex-encoded conversation/group ID
    /// - epoch: Epoch number
    /// Returns serialized epoch secret material if found
    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>>;

    /// Delete epoch secret (called during retention cleanup)
    /// - conversation_id: Hex-encoded conversation/group ID
    /// - epoch: Epoch number
    /// Returns true if deleted successfully
    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool;

    /// Delete epoch secrets older than a cutoff epoch
    /// - conversation_id: Hex-encoded conversation/group ID
    /// - cutoff_epoch: Epoch number (exclusive) - delete all epochs < cutoff_epoch
    /// Returns number of deleted secrets
    async fn delete_epochs_before(&self, conversation_id: String, cutoff_epoch: u64) -> u32;
}

/// Result type for proposal creation operations
/// Contains the proposal message to send and a reference for tracking
#[derive(uniffi::Record)]
pub struct ProposeResult {
    /// MlsMessageOut to send to server (serialized proposal)
    pub proposal_message: Vec<u8>,
    /// ProposalRef for local tracking (serialized reference)
    pub proposal_ref: Vec<u8>,
}

// Validation framework types for client-side MLS hardening

/// Operation type for credential validation context
#[derive(uniffi::Enum, Clone)]
pub enum OperationType {
    Join,
    Add,
    Update,
    Remove,
    Decrypt,
}

/// Validation context passed to CredentialValidator
#[derive(uniffi::Record, Clone)]
pub struct ValidationContext {
    pub conversation_id: String,
    pub operation_type: OperationType,
    pub current_epoch: u64,
}

/// Tree hash data for epoch state verification
#[derive(uniffi::Record)]
pub struct TreeHashData {
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
}

/// Credential validator callback trait for Swift-side policy enforcement
/// Allows the client to validate credentials before accepting group state changes
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait CredentialValidator: Send + Sync {
    /// Validate a credential in the context of a specific operation
    /// Returns true if the credential is valid and the operation should proceed
    /// Returns false to reject the credential and abort the operation
    async fn validate_credential(
        &self,
        credential: CredentialData,
        context: ValidationContext,
    ) -> bool;
}

/// Callback for authorizing external join proposals
///
/// Implement this to define your application's authorization policy
/// for external commits (outsiders requesting to join a group).
#[uniffi::export(callback_interface)]
pub trait ExternalJoinAuthorizer: Send + Sync {
    /// Authorize an external join request.
    ///
    /// # Arguments
    /// * `group_id` - Group being joined
    /// * `requester_credential` - Credential of the requester
    /// * `requester_signature_key` - Public signature key of requester
    ///
    /// # Returns
    /// true to allow the join, false to reject
    fn authorize_external_join(
        &self,
        group_id: Vec<u8>,
        requester_credential: CredentialData,
        requester_signature_key: Vec<u8>,
    ) -> bool;
}

#[derive(uniffi::Record)]
pub struct PendingProposalDetail {
    /// Unique reference for this proposal
    pub proposal_ref: Vec<u8>,
    /// Type: "add", "remove", "update", "psk", "reinit", "external_init", "group_context_extensions"
    pub proposal_type: String,
    /// For Add: the identity being added
    pub add_identity: Option<Vec<u8>>,
    /// For Remove: the leaf index being removed
    pub remove_leaf_index: Option<u32>,
    /// For Update: the identity updating their key
    pub update_identity: Option<Vec<u8>>,
    /// Sender of the proposal
    pub sender_identity: Option<Vec<u8>>,
    /// Sender leaf index
    pub sender_leaf_index: Option<u32>,
}
