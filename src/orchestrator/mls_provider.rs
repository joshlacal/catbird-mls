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

    /// Atomically swap members in a single commit: remove old and add new.
    fn swap_members(
        &self,
        group_id: Vec<u8>,
        remove_identities: Vec<Vec<u8>>,
        add_key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        let _ = (group_id, remove_identities, add_key_packages);
        Err(MLSError::Internal(
            "swap_members not supported on this platform".to_string(),
        ))
    }

    fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError>;

    fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError>;

    fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError>;

    fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;

    /// Return the RFC 9420 §8.7 `epoch_authenticator` for the group's current
    /// epoch. Platforms bind quorum-reset reports (§8.6) to this value so a
    /// stale client can't forge votes for an epoch it never observed.
    ///
    /// Default returns `OperationNotSupported` so existing platforms continue
    /// to compile until they wire up the OpenMLS exposure.
    fn epoch_authenticator(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "epoch_authenticator not available on this platform".to_string(),
        })
    }

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

    /// Merge an incoming `StagedCommit` that was previously staged by
    /// `decrypt_message` (task #33 receiver-side three-phase commit).
    ///
    /// Returns the new (post-merge) epoch. Called by the orchestrator's
    /// HTTP-sync path after it has validated a commit against recovery
    /// policy and is ready to advance the local MLS epoch.
    ///
    /// Default no-op returns `target_epoch` unchanged — platforms that do
    /// not stage incoming commits (e.g. auto-merge implementations) can
    /// safely inherit this and still satisfy the orchestrator contract.
    fn merge_incoming_commit(
        &self,
        _group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<u64, MLSError> {
        Ok(target_epoch)
    }

    /// Discard an incoming `StagedCommit` that was previously staged by
    /// `decrypt_message` without advancing the local epoch.
    ///
    /// Called by the orchestrator when recovery policy decides the staged
    /// commit should not be applied (e.g. a fork/reset is being initiated).
    ///
    /// Default no-op for platforms that do not stage incoming commits.
    fn discard_incoming_commit(
        &self,
        _group_id: Vec<u8>,
        _target_epoch: u64,
    ) -> Result<(), MLSError> {
        Ok(())
    }

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

    /// Clean up epoch secrets older than the retention window for a group.
    ///
    /// After every epoch advance, call this to delete secrets beyond the
    /// retention window, enforcing forward secrecy and bounding storage.
    /// Default no-op for platforms that don't manage epoch secrets at
    /// the crypto context layer.
    fn cleanup_epoch_secrets(
        &self,
        _group_id: Vec<u8>,
        _current_epoch: u64,
        _retention_epochs: u64,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    /// Attempt fork resolution by removing and re-adding members.
    /// Default returns OperationNotSupported.
    fn recover_fork_by_readding(
        &self,
        _group_id: Vec<u8>,
        _key_packages: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "fork-resolution feature not available".to_string(),
        })
    }

    /// Export a secret using the Puncturable PRF tree (forward-secure within epoch).
    ///
    /// Falls back to `export_secret` with a deterministic label derived from the
    /// component ID when the group lacks an `application_export_tree`.
    /// Default implementation always falls back (platforms override for PPRF).
    fn safe_export_secret(
        &self,
        _group_id: Vec<u8>,
        _component_id: u16,
    ) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "safe_export_secret not available on this platform".to_string(),
        })
    }

    /// Export a secret from the pending commit's Puncturable PRF tree.
    ///
    /// Default implementation returns OperationNotSupported.
    fn safe_export_secret_from_pending(
        &self,
        _group_id: Vec<u8>,
        _component_id: u16,
    ) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "safe_export_secret_from_pending not available on this platform".to_string(),
        })
    }

    /// Propose self-removal from a group.
    fn propose_self_remove(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;

    /// Commit all pending proposals for a group and return the commit bytes.
    fn commit_pending_proposals(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;
}
