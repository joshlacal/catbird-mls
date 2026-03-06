use crate::error::MLSError;
use crate::types::*;

/// Conditional bounds for MlsCryptoContext.
#[cfg(not(target_arch = "wasm32"))]
pub trait MlsCryptoContextBounds: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MlsCryptoContextBounds for T {}

#[cfg(target_arch = "wasm32")]
pub trait MlsCryptoContextBounds {}
#[cfg(target_arch = "wasm32")]
impl<T> MlsCryptoContextBounds for T {}

/// Platform-agnostic MLS cryptographic operations.
///
/// Implemented by:
/// - `MLSContext` (native, via rusqlite/openmls_sqlite_storage)
/// - `WasmMLSContext` (browser, via sqlite-wasm-rs/OPFS)
///
/// All methods are synchronous since the underlying crypto is CPU-bound.
pub trait MlsCryptoContext: MlsCryptoContextBounds {
    fn create_key_package(&self, identity: Vec<u8>) -> Result<KeyPackageResult, MLSError>;

    fn create_group(
        &self,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError>;

    fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError>;

    fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError>;

    fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError>;

    fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError>;

    fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError>;

    fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError>;

    fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError>;

    fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError>;

    fn create_external_commit(
        &self,
        group_info: Vec<u8>,
        identity: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError>;

    fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<(), MLSError>;

    fn delete_group(&self, group_id: Vec<u8>) -> Result<(), MLSError>;

    /// Read encrypted group metadata from MLS group context extensions.
    /// Returns JSON bytes of the metadata, or empty vec if none set.
    fn get_group_metadata(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;

    /// Update group metadata by proposing + committing a GroupContextExtensions change.
    /// Returns the commit message bytes that must be sent to the server.
    fn update_group_metadata(
        &self,
        group_id: Vec<u8>,
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError>;

    fn process_welcome(
        &self,
        welcome_data: Vec<u8>,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError>;
}
