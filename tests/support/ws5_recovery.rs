//! Shared fault-injection fixtures for recovery persistence tests.

/// Event observer that records WS-5.2 recovery-storage escalations.
#[derive(Default)]
pub(crate) struct RecordingObserver {
    pub(crate) storage_failures: std::sync::Mutex<Vec<(String, String, String)>>,
}

impl catbird_mls::orchestrator::event_observer::OrchestratorEventObserver for RecordingObserver {
    fn on_recovery_storage_write_failed(&self, convo_id: &str, operation: &str, error: &str) {
        self.storage_failures.lock().unwrap().push((
            convo_id.to_string(),
            operation.to_string(),
            error.to_string(),
        ));
    }
}

/// Crypto context whose decrypt always fails with a peer-bad class error
/// (InvalidCommit). The production `MLSContext` flattens OpenMLS process
/// failures to `DecryptionFailed`, so the Layer-3 peer-bad classifier can't
/// be tripped through real crypto in-process; this mock drives the
/// quarantine-entry path directly through `process_incoming`.
pub(crate) struct FailingCrypto {
    peer_bad: bool,
}

impl FailingCrypto {
    pub(crate) fn peer_bad() -> Self {
        Self { peer_bad: true }
    }

    pub(crate) fn self_bad() -> Self {
        Self { peer_bad: false }
    }
}

impl catbird_mls::orchestrator::MlsCryptoContext for FailingCrypto {
    fn create_key_package(
        &self,
        _identity: Vec<u8>,
    ) -> Result<catbird_mls::KeyPackageResult, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn create_group(
        &self,
        _identity: Vec<u8>,
        _config: Option<catbird_mls::GroupConfig>,
    ) -> Result<catbird_mls::GroupCreationResult, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn add_members(
        &self,
        _group_id: Vec<u8>,
        _key_packages: Vec<catbird_mls::KeyPackageData>,
    ) -> Result<catbird_mls::AddMembersResult, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn remove_members(
        &self,
        _group_id: Vec<u8>,
        _member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn merge_pending_commit(&self, _group_id: Vec<u8>) -> Result<u64, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn clear_pending_commit(&self, _group_id: Vec<u8>) -> Result<(), catbird_mls::MLSError> {
        Ok(())
    }
    fn get_epoch(&self, _group_id: Vec<u8>) -> Result<u64, catbird_mls::MLSError> {
        Ok(1)
    }
    fn get_confirmation_tag(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Ok(vec![0x24_u8; 32])
    }
    fn export_group_info(
        &self,
        _group_id: Vec<u8>,
        _signer_identity: Vec<u8>,
    ) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn encrypt_message(
        &self,
        _group_id: Vec<u8>,
        _plaintext: Vec<u8>,
    ) -> Result<catbird_mls::EncryptResult, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn decrypt_message(
        &self,
        _group_id: Vec<u8>,
        _ciphertext: Vec<u8>,
    ) -> Result<catbird_mls::DecryptResult, catbird_mls::MLSError> {
        if self.peer_bad {
            Err(catbird_mls::MLSError::InvalidCommit)
        } else {
            Err(catbird_mls::MLSError::Internal(
                "self-bad decrypt failure".into(),
            ))
        }
    }
    fn create_external_commit(
        &self,
        _group_info: Vec<u8>,
        _identity: Vec<u8>,
    ) -> Result<catbird_mls::ExternalCommitResult, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn discard_pending_external_join(
        &self,
        _group_id: Vec<u8>,
    ) -> Result<(), catbird_mls::MLSError> {
        Ok(())
    }
    fn delete_group(&self, _group_id: Vec<u8>) -> Result<(), catbird_mls::MLSError> {
        Ok(())
    }
    fn update_group_metadata(
        &self,
        _group_id: Vec<u8>,
        _metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn process_welcome(
        &self,
        _welcome_data: Vec<u8>,
        _identity: Vec<u8>,
        _config: Option<catbird_mls::GroupConfig>,
    ) -> Result<catbird_mls::WelcomeResult, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn propose_self_remove(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn commit_pending_proposals(
        &self,
        _group_id: Vec<u8>,
    ) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
    }
    fn get_group_context_hash(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Ok(vec![0x23_u8; 32])
    }
    fn identity_public_key(&self, _identity: Vec<u8>) -> Result<Vec<u8>, catbird_mls::MLSError> {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32]);
        Ok(signer.verifying_key().to_bytes().to_vec())
    }

    fn sign_with_identity_key(
        &self,
        _identity: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, catbird_mls::MLSError> {
        use ed25519_dalek::Signer;
        let signer = ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32]);
        Ok(signer.sign(&payload).to_bytes().to_vec())
    }
}
pub(crate) async fn configure_test_signing_authority(
    credentials: &impl catbird_mls::orchestrator::CredentialStore,
    did: &str,
) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32]);
    let signer = openmls_basic_credential::SignatureKeyPair::from_raw(
        openmls::prelude::SignatureScheme::ED25519,
        signing_key.to_bytes().to_vec(),
        signing_key.verifying_key().to_bytes().to_vec(),
    );
    credentials
        .store_signing_key(
            did,
            &serde_json::to_vec(&signer).expect("serialize deterministic test signer"),
        )
        .await
        .expect("store deterministic test signer");
}
