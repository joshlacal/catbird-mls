use crate::error::MLSError;
use crate::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnEchoProof {
    pub canonical_entry_sha256: [u8; 32],
    pub accepted_request_sha256: [u8; 32],
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub server_entry_id: String,
    pub mls_epoch: u64,
    pub aad_sha256: [u8; 32],
    pub ciphertext_sha256: [u8; 32],
}

impl OwnEchoProof {
    pub const PROOF_DOMAIN: &'static [u8] = b"CATBIRD-CLEAN-OWN-ECHO-PROOF-V1\0";

    pub fn compute_canonical_entry_sha256(
        conversation_id: &str,
        group_id: &[u8],
        server_entry_id: &str,
        mls_epoch: u64,
        aad_sha256: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(Self::PROOF_DOMAIN);
        hasher.update((conversation_id.len() as u32).to_be_bytes());
        hasher.update(conversation_id.as_bytes());
        hasher.update((group_id.len() as u32).to_be_bytes());
        hasher.update(group_id);
        hasher.update((server_entry_id.len() as u32).to_be_bytes());
        hasher.update(server_entry_id.as_bytes());
        hasher.update(mls_epoch.to_be_bytes());
        hasher.update(aad_sha256);
        hasher.update(ciphertext_sha256);
        hasher.finalize().into()
    }

    pub fn new(
        accepted_request_sha256: [u8; 32],
        conversation_id: String,
        group_id: Vec<u8>,
        server_entry_id: String,
        mls_epoch: u64,
        aad_sha256: [u8; 32],
        ciphertext_sha256: [u8; 32],
    ) -> Self {
        let canonical_entry_sha256 = Self::compute_canonical_entry_sha256(
            &conversation_id,
            &group_id,
            &server_entry_id,
            mls_epoch,
            &aad_sha256,
            &ciphertext_sha256,
        );
        Self {
            canonical_entry_sha256,
            accepted_request_sha256,
            conversation_id,
            group_id,
            server_entry_id,
            mls_epoch,
            aad_sha256,
            ciphertext_sha256,
        }
    }
}

#[derive(Debug)]
pub enum MlsDecryptOutcome {
    Message(DecryptResult),
    OwnPrivateMessage {
        epoch: u64,
        aad_sha256: [u8; 32],
        ciphertext_sha256: [u8; 32],
    },
    OwnPendingCommit,
}

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

    /// Return the active Ed25519 public key for an enrolled MLS identity.
    fn identity_public_key(&self, _identity: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "identity_public_key not available on this platform".to_string(),
        })
    }

    /// Sign a Rust-canonical mutation transcript with this identity's
    /// non-exporting Ed25519 signer.
    fn sign_with_identity_key(
        &self,
        _identity: Vec<u8>,
        _payload: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "identity signing not available on this platform".to_string(),
        })
    }

    /// Return the hex-encoded key-package refs the client currently holds a
    /// private key for (i.e. the live local bundle set). Used to drain
    /// server-side orphans via `syncKeyPackages`: any KP the server still lists
    /// as available but that is NOT in this set has had its private key lost
    /// locally (consumed by a join, storage reset, reinstall) and would fail a
    /// recipient with `NoMatchingKeyPackage` if served — the server deletes
    /// those.
    ///
    /// Default returns empty; callers MUST treat an empty result as "unknown"
    /// and skip the sync, never as "I hold nothing" (that would wipe the
    /// server pool). The native `MLSContext` implements this.
    fn list_key_package_hashes(&self) -> Result<Vec<String>, MLSError> {
        Ok(Vec::new())
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
    fn add_members_with_aad(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
        aad: Option<Vec<u8>>,
    ) -> Result<AddMembersResult, MLSError> {
        let _ = &aad;
        self.add_members(group_id, key_packages)
    }

    /// Add members AND re-seal the group metadata at the post-add epoch so the
    /// newly-added members can decrypt the group name/description. The returned
    /// `AddMembersResult` carries `metadata_blob_locator` / `metadata_blob_ciphertext`
    /// / `metadata_version`, which the caller MUST upload via
    /// `MLSAPIClient::put_group_metadata_blob`.
    ///
    /// Default impl drops the metadata and behaves exactly like `add_members`
    /// (for platforms without encrypted-metadata support); the native
    /// `MLSContext` overrides it.
    fn add_members_with_metadata(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<AddMembersResult, MLSError> {
        let _ = (&title, &description);
        self.add_members(group_id, key_packages)
    }

    fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError>;

    fn remove_members_with_aad(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
        aad: Option<Vec<u8>>,
    ) -> Result<RemoveMembersResult, MLSError> {
        let _ = &aad;
        let commit_data = self.remove_members(group_id, member_identities)?;
        Ok(RemoveMembersResult {
            commit_data,
            next_confirmation_tag: None,
            next_group_context_hash: None,
        })
    }

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

    /// Enumerate every locally persisted MLS group id.
    ///
    /// Destructive recovery uses this to re-associate persisted group-state
    /// bindings after a process restart, when the orchestrator's in-memory
    /// cache is empty. Backends that cannot enumerate must fail closed rather
    /// than let local-delete reconciliation clear the only discoverability
    /// mapping for unidentified epoch secrets.
    fn list_local_group_ids(&self) -> Result<Vec<Vec<u8>>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "local MLS group enumeration not available on this platform".to_string(),
        })
    }

    fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;

    fn get_group_context_hash(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "get_group_context_hash not available on this platform".to_string(),
        })
    }

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
    fn decrypt_message_outcome(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<MlsDecryptOutcome, MLSError> {
        self.decrypt_message(group_id, ciphertext)
            .map(MlsDecryptOutcome::Message)
    }

    /// Make all MLS storage mutations performed by the current operation
    /// durable before the orchestrator publishes a matching epoch projection
    /// or advances a delivery-service cursor.
    ///
    /// Incoming commit merge can mutate the in-memory/OpenMLS group before a
    /// database flush reports failure. A redelivery then observes
    /// `WrongEpoch`; without an explicit durability retry, treating that as a
    /// duplicate could acknowledge a commit whose MLS state is not durable.
    /// Backends must therefore implement this as a real storage durability
    /// barrier. The fail-closed default prevents an unwired backend from
    /// silently weakening ordered commit processing.
    fn ensure_storage_durable(&self) -> Result<(), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "MLS storage durability barrier not available on this platform".to_string(),
        })
    }

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

    /// Publish a previously decrypted standalone proposal into the OpenMLS
    /// proposal store after application-level sender authorization succeeds.
    fn accept_incoming_proposal(
        &self,
        _group_id: Vec<u8>,
        _proposal_ref: Vec<u8>,
    ) -> Result<(), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "staged incoming proposal acceptance is unavailable".to_string(),
        })
    }

    /// Discard a previously decrypted standalone proposal after sender
    /// authorization fails or the caller abandons processing.
    fn discard_incoming_proposal(
        &self,
        _group_id: Vec<u8>,
        _proposal_ref: Vec<u8>,
    ) -> Result<(), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "staged incoming proposal discard is unavailable".to_string(),
        })
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

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    fn stage_app_data_update_for_test(
        &self,
        group_id: Vec<u8>,
        component_id: u16,
        data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        let _ = (group_id, component_id, data);
        Err(MLSError::Internal("not implemented".into()))
    }

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
        aad: Option<Vec<u8>>,
    ) -> Result<crate::types::UpdateGroupMetadataResultFfi, MLSError> {
        let _ = (
            group_id,
            title,
            description,
            avatar_blob_locator,
            avatar_content_type,
            aad,
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
    /// Export the canonical metadata encryption key (MEK) for an epoch.
    fn export_metadata_key(&self, _group_id: Vec<u8>, _epoch: u64) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "export_metadata_key not available on this platform".to_string(),
        })
    }
    /// Export the canonical metadata encryption key (MEK) from a pending staged commit.
    fn export_metadata_key_from_pending(
        &self,
        _group_id: Vec<u8>,
        _target_epoch: u64,
    ) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "export_metadata_key_from_pending not available on this platform".to_string(),
        })
    }

    /// Propose self-removal from a group.
    fn propose_self_remove(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;

    /// Commit all pending proposals for a group and return the commit bytes.
    fn commit_pending_proposals(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError>;

    /// Store a proven own-message echo proof inside the encrypted MLS database.
    fn store_own_echo_proof(&self, _proof: &OwnEchoProof) -> Result<(), MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "store_own_echo_proof not available on this platform".to_string(),
        })
    }

    /// Query non-destructively for an exact own-message echo proof.
    fn has_own_echo_proof(
        &self,
        _conversation_id: &str,
        _group_id: &[u8],
        _server_entry_id: &str,
        _mls_epoch: u64,
        _aad_sha256: &[u8; 32],
        _ciphertext_sha256: &[u8; 32],
    ) -> Result<bool, MLSError> {
        Ok(false)
    }
}
