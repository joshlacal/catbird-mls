use super::error::Result;

/// Result of creating an MLS group locally.
#[derive(Debug, Clone)]
pub struct CryptoGroupCreationResult {
    pub group_id: Vec<u8>,
}

/// Result of adding members (commit + welcome).
#[derive(Debug, Clone)]
pub struct CryptoAddMembersResult {
    pub commit_data: Vec<u8>,
    pub welcome_data: Vec<u8>,
}

/// Result of encrypting a message.
#[derive(Debug, Clone)]
pub struct CryptoEncryptResult {
    pub ciphertext: Vec<u8>,
}

/// Sender credential from a decrypted message.
#[derive(Debug, Clone)]
pub struct CryptoCredentialData {
    pub credential_type: String,
    pub identity: Vec<u8>,
}

/// Result of decrypting a message.
#[derive(Debug, Clone)]
pub struct CryptoDecryptResult {
    pub plaintext: Vec<u8>,
    pub epoch: u64,
    pub sequence_number: u64,
    pub sender_credential: CryptoCredentialData,
}

/// Result of creating a key package.
#[derive(Debug, Clone)]
pub struct CryptoKeyPackageResult {
    pub key_package_data: Vec<u8>,
    pub hash_ref: Vec<u8>,
    pub signature_public_key: Vec<u8>,
}

/// Result of an external commit (rejoin).
#[derive(Debug, Clone)]
pub struct CryptoExternalCommitResult {
    pub commit_data: Vec<u8>,
    pub group_id: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
}

/// Key package data for adding members.
#[derive(Debug, Clone)]
pub struct CryptoKeyPackageData {
    pub data: Vec<u8>,
}

/// MLS group configuration.
#[derive(Debug, Clone)]
pub struct CryptoGroupConfig {
    pub max_past_epochs: u32,
    pub out_of_order_tolerance: u32,
    pub maximum_forward_distance: u32,
    pub max_leaf_lifetime_seconds: u64,
}

impl Default for CryptoGroupConfig {
    fn default() -> Self {
        Self {
            max_past_epochs: 5,
            out_of_order_tolerance: 10,
            maximum_forward_distance: 2000,
            max_leaf_lifetime_seconds: 86400 * 90,
        }
    }
}

/// Platform-agnostic MLS cryptographic operations.
///
/// Implemented by the FFI layer (wrapping openmls) on each platform.
/// All methods are synchronous since the underlying crypto is CPU-bound.
pub trait MLSCryptoProvider: Send + Sync {
    /// Create a new MLS group.
    fn create_group(
        &self,
        identity: Vec<u8>,
        config: Option<CryptoGroupConfig>,
    ) -> Result<CryptoGroupCreationResult>;

    /// Get the current epoch for a group.
    fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64>;

    /// Get the TLS-serialized confirmation tag for a group.
    fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>>;

    /// Process a Welcome message to join a group.
    fn process_welcome(
        &self,
        welcome_data: Vec<u8>,
        identity: Vec<u8>,
        config: Option<CryptoGroupConfig>,
    ) -> Result<CryptoGroupCreationResult>;

    /// Add members to a group (produces commit + welcome).
    fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<CryptoKeyPackageData>,
    ) -> Result<CryptoAddMembersResult>;

    /// Remove members from a group (produces commit data).
    fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>>;

    /// Merge a pending commit (after server confirms).
    fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64>;

    /// Encrypt a message for a group.
    fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<CryptoEncryptResult>;

    /// Decrypt a message from a group.
    fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<CryptoDecryptResult>;

    /// Export GroupInfo for external joins.
    fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity: Vec<u8>,
    ) -> Result<Vec<u8>>;

    /// Create an External Commit to rejoin a group.
    fn create_external_commit(
        &self,
        group_info: Vec<u8>,
        identity: Vec<u8>,
    ) -> Result<CryptoExternalCommitResult>;

    /// Discard a pending external join.
    fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<()>;

    /// Delete a group from local state.
    fn delete_group(&self, group_id: Vec<u8>) -> Result<()>;

    /// Create a key package for the given identity.
    fn create_key_package(
        &self,
        identity: Vec<u8>,
    ) -> Result<CryptoKeyPackageResult>;
}
