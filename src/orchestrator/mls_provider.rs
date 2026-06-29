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

    fn create_last_resort_key_package(
        &self,
        _identity: Vec<u8>,
    ) -> Result<KeyPackageResult, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "last-resort key package generation not available on this platform".to_string(),
        })
    }

    /// Export this identity's full signing keypair (serialized) so the platform
    /// can persist it durably (keychain/keystore) and reuse it across
    /// reinstalls. Reusing one durable signer prevents signing-key churn that
    /// strands previously-published key packages on the server (recipients
    /// would otherwise hit `NoMatchingKeyPackage`).
    ///
    /// Default: `OperationNotSupported`. Native `MLSContext` wires this to
    /// `MLSContext::export_identity_key`; platforms whose crypto context is a
    /// UniFFI callback can implement it later — the orchestrator degrades
    /// gracefully (falls back to storing the public key only).
    fn export_identity_key(&self, _identity: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "export_identity_key not available on this platform".to_string(),
        })
    }

    /// Import a previously-exported full signing keypair into local crypto
    /// storage and register it as this identity's signer, so subsequent key
    /// packages (and device registration) are signed with the durable key
    /// rather than a freshly-minted one.
    ///
    /// Default: `OperationNotSupported` (orchestrator treats failure as
    /// warn-only and mints a fresh signer, preserving legacy behavior).
    fn import_identity_key(&self, _identity: Vec<u8>, _key_data: Vec<u8>) -> Result<(), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "import_identity_key not available on this platform".to_string(),
        })
    }

    fn set_suspended(&self, _value: bool) {}

    fn interrupt_storage(&self) -> usize {
        0
    }

    fn flush_and_prepare_close(&self) -> Result<(), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "flush_and_prepare_close not available on this platform".to_string(),
        })
    }

    fn storage_lifecycle_status(&self) -> StorageLifecycleStatus {
        StorageLifecycleStatus {
            state: StorageLifecycleState::Open,
            interruptible_contexts: 0,
            is_busy: false,
            busy_contexts: 0,
            last_operation_label: None,
        }
    }

    fn create_group(
        &self,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError>;

    /// Create a new MLS group at a **predetermined** group_id (RFC 9420 §11
    /// `MlsGroup::new_with_group_id`). Used by the first-responder bootstrap
    /// path (spec §8.5 / Phase 1) where every member needs to land on the
    /// same `groupId` published by the server's `groupResetEvent`. Random
    /// group_id (the default `create_group` path) cannot satisfy that
    /// contract — different bootstrap candidates would produce different
    /// local groups.
    ///
    /// `group_id` is the raw bytes of the target MLS group identifier
    /// (NOT hex-encoded). Callers that have a hex string from the
    /// `groupResetEvent.newGroupId` must `hex::decode` before calling.
    ///
    /// Default returns `OperationNotSupported` so existing platforms
    /// (Swift/Kotlin UniFFI callback impls) continue to compile until they
    /// wire up the OpenMLS exposure. Native `MLSContext` and the WASM
    /// crypto context implement this directly.
    fn create_group_with_id(
        &self,
        identity: Vec<u8>,
        group_id: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        let _ = (identity, group_id, config);
        Err(MLSError::OperationNotSupported {
            reason: "create_group_with_id not available on this platform".to_string(),
        })
    }

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

    /// Return the MLS credential identities (`Vec<u8>` each) of every current
    /// member of the group. Used by the Welcome-reissue responder to locate a
    /// recipient's stale leaf so it can be swapped out in a single commit.
    ///
    /// Default returns `OperationNotSupported` so existing platforms continue
    /// to compile until they wire up member enumeration.
    fn group_member_identities(&self, group_id: Vec<u8>) -> Result<Vec<Vec<u8>>, MLSError> {
        let _ = group_id;
        Err(MLSError::OperationNotSupported {
            reason: "group_member_identities not available on this platform".to_string(),
        })
    }

    fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError>;

    fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError>;

    fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError>;

    /// Return true when the MLS group exists in local crypto storage.
    ///
    /// Defaulting to `get_epoch` keeps existing platform implementors
    /// source-compatible while still giving the orchestrator a portable
    /// existence probe for reset-event self-echo guards.
    fn group_exists(&self, group_id: Vec<u8>) -> bool {
        self.get_epoch(group_id).is_ok()
    }

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

    /// Update group metadata by proposing + committing a GroupContextExtensions
    /// change. Returns the commit message bytes that must be sent to the server.
    ///
    /// Used by `CommitKind::UpdateMetadata` stage_commit dispatch (iOS
    /// three-phase rename path). The `metadata_json` carries a legacy
    /// `GroupMetadataPayload` for compat but its contents are NOT written
    /// into the MLS group context — title / description / avatar live in
    /// encrypted `GroupMetadataV1` blobs (see `update_group_metadata_encrypted`).
    fn update_group_metadata(
        &self,
        group_id: Vec<u8>,
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError>;

    /// Atomic encrypted metadata update (Phase A.2).
    ///
    /// Stages a GroupContextExtensions commit, derives the post-commit
    /// metadata key from the staged commit's exporter, and encrypts a
    /// fresh `GroupMetadataV1` payload. Returns the commit bytes, the
    /// encrypted blob, the blob locator, the new metadata version, and
    /// the FINAL `MetadataReference` JSON for the caller's local cache.
    ///
    /// Default impl returns `Err(NotImplemented)` so any backend that
    /// hasn't wired the encrypted path surfaces the missing impl.
    fn update_group_metadata_encrypted(
        &self,
        group_id: Vec<u8>,
        title: Option<String>,
        description: Option<String>,
        avatar_blob_locator: Option<String>,
        avatar_content_type: Option<String>,
    ) -> Result<crate::types::UpdateGroupMetadataResultFfi, MLSError> {
        let _ = (
            group_id,
            title,
            description,
            avatar_blob_locator,
            avatar_content_type,
        );
        Err(MLSError::Internal(
            "MlsCryptoContext::update_group_metadata_encrypted is not implemented for this backend"
                .into(),
        ))
    }

    /// Return the current epoch's metadata key + `MetadataReference` for a
    /// group, so the orchestrator can fetch and decrypt the encrypted
    /// `GroupMetadataV1` blob and surface the group name/description to
    /// newly-joined members (who can't derive a past epoch's exporter and so
    /// never cached the plaintext). `metadata_reference_json` is `None` when
    /// the group has no metadata set yet.
    ///
    /// Default returns `Ok(None)` so backends that haven't wired the encrypted
    /// metadata path degrade gracefully (no name shown) instead of erroring on
    /// every join. The native `MLSContext` implements this directly.
    fn get_current_metadata(
        &self,
        group_id: Vec<u8>,
    ) -> Result<Option<crate::types::CurrentMetadataInfo>, MLSError> {
        let _ = group_id;
        Ok(None)
    }

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
