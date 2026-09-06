//! Security regressions for durable inbound-message processing.

#![allow(dead_code)]

mod e2e_harness;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use catbird_mls::orchestrator::mls_provider::{MlsDecryptOutcome, OwnEchoProof};
use catbird_mls::orchestrator::{
    ConversationState, GroupState, MLSAPIClient, MLSMessagePayload, MLSOrchestrator,
    MLSStorageBackend, Message, MlsCryptoContext, OrchestratorConfig, ReactionAction,
};
use e2e_harness::mock_api_client::MockDeliveryService;
use e2e_harness::mock_credentials::MockCredentials;
use e2e_harness::mock_storage::MockStorage;
use e2e_harness::TestWorld;
use sha2::{Digest, Sha256};
struct ControlledCommitCrypto {
    decrypt_calls: AtomicUsize,
    discard_calls: AtomicUsize,
    cleanup_calls: AtomicUsize,
    durability_calls: AtomicUsize,
    pending_commit: AtomicBool,
    crypto_epoch: AtomicU64,
    merge_succeeds: bool,
    discard_succeeds: bool,
    durability_succeeds: bool,
    wrong_epoch_on_decrypt: bool,
    external_join_rejection_on_decrypt: bool,
    group_not_found_on_decrypt: bool,
    secret_reuse_on_decrypt: bool,
    own_private_message_on_decrypt: bool,
    own_pending_commit_on_decrypt: bool,
    custom_own_private_epoch: Option<u64>,
    custom_own_private_aad_sha256: Option<[u8; 32]>,
    custom_own_private_ciphertext_sha256: Option<[u8; 32]>,
    application_plaintext: Option<Vec<u8>>,
    application_then_secret_reuse: bool,
    first_decrypt_delay: Option<Duration>,
    first_decrypt_entered: AtomicBool,
    proof_storage: Mutex<HashMap<[u8; 32], OwnEchoProof>>,
    fail_store_proof: AtomicBool,
    fail_lookup_proof: AtomicBool,
}

impl ControlledCommitCrypto {
    fn configured(
        merge_succeeds: bool,
        discard_succeeds: bool,
        durability_succeeds: bool,
        crypto_epoch: u64,
        wrong_epoch_on_decrypt: bool,
    ) -> Self {
        Self {
            decrypt_calls: AtomicUsize::new(0),
            discard_calls: AtomicUsize::new(0),
            cleanup_calls: AtomicUsize::new(0),
            durability_calls: AtomicUsize::new(0),
            pending_commit: AtomicBool::new(false),
            crypto_epoch: AtomicU64::new(crypto_epoch),
            merge_succeeds,
            discard_succeeds,
            durability_succeeds,
            wrong_epoch_on_decrypt,
            external_join_rejection_on_decrypt: false,
            group_not_found_on_decrypt: false,
            secret_reuse_on_decrypt: false,
            own_private_message_on_decrypt: false,
            own_pending_commit_on_decrypt: false,
            custom_own_private_epoch: None,
            custom_own_private_aad_sha256: None,
            custom_own_private_ciphertext_sha256: None,
            application_plaintext: None,
            application_then_secret_reuse: false,
            first_decrypt_delay: None,
            first_decrypt_entered: AtomicBool::new(false),
            proof_storage: Mutex::new(HashMap::new()),
            fail_store_proof: AtomicBool::new(false),
            fail_lookup_proof: AtomicBool::new(false),
        }
    }
    fn merge_fails() -> Self {
        Self::configured(false, true, true, 1, false)
    }

    fn merge_succeeds() -> Self {
        Self::configured(true, true, true, 1, false)
    }

    fn discard_fails() -> Self {
        Self::configured(false, false, true, 1, false)
    }

    fn wrong_epoch_repair(durability_succeeds: bool) -> Self {
        Self::configured(false, true, durability_succeeds, 7, true)
    }

    fn rejects_external_join_proposal() -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.external_join_rejection_on_decrypt = true;
        crypto
    }

    fn group_not_found() -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.group_not_found_on_decrypt = true;
        crypto
    }

    fn secret_reuse() -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.secret_reuse_on_decrypt = true;
        crypto
    }

    fn own_private_message() -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.own_private_message_on_decrypt = true;
        crypto
    }

    fn own_pending_commit() -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.own_pending_commit_on_decrypt = true;
        crypto
    }

    fn application_then_secret_reuse(first_decrypt_delay: Duration) -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.application_plaintext = Some(
            serde_json::to_vec(&MLSMessagePayload::text("serialized inbound"))
                .expect("serialize test application payload"),
        );
        crypto.application_then_secret_reuse = true;
        crypto.first_decrypt_delay = Some(first_decrypt_delay);
        crypto
    }

    fn non_displayable_application(durability_succeeds: bool) -> Self {
        let mut crypto = Self::configured(false, true, durability_succeeds, 1, false);
        crypto.application_plaintext = Some(
            serde_json::to_vec(&MLSMessagePayload::reaction(
                "target-message",
                "test-reaction",
                ReactionAction::Add,
            ))
            .expect("serialize test control payload"),
        );
        crypto
    }
}

impl MlsCryptoContext for ControlledCommitCrypto {
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
        Ok(self.crypto_epoch.load(Ordering::SeqCst))
    }

    fn get_confirmation_tag(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, catbird_mls::MLSError> {
        Err(catbird_mls::MLSError::Internal("unused in test".into()))
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
        let decrypt_index = self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        if self.external_join_rejection_on_decrypt {
            return Err(catbird_mls::MLSError::external_join_proposal_authorization_required());
        }
        if self.group_not_found_on_decrypt {
            return Err(catbird_mls::MLSError::group_not_found(
                "injected missing local group",
            ));
        }
        if self.wrong_epoch_on_decrypt {
            return Err(catbird_mls::MLSError::OpenMLS(
                "ValidationError(WrongEpoch)".to_string(),
            ));
        }
        if self.secret_reuse_on_decrypt || (self.application_then_secret_reuse && decrypt_index > 0)
        {
            return Err(catbird_mls::MLSError::OpenMLS(
                "ValidationError(UnableToDecrypt(SecretTreeError(SecretReuseError)))".to_string(),
            ));
        }
        if let Some(plaintext) = self.application_plaintext.as_ref() {
            self.first_decrypt_entered.store(true, Ordering::SeqCst);
            if let Some(delay) = self.first_decrypt_delay {
                std::thread::sleep(delay);
            }
            return Ok(catbird_mls::DecryptResult {
                plaintext: plaintext.clone(),
                epoch: 1,
                sequence_number: 1,
                sender_credential: catbird_mls::CredentialData {
                    credential_type: "basic".to_string(),
                    identity: b"did:plc:alice".to_vec(),
                },
                content_type: catbird_mls::DecryptContentType::Application,
                proposal_ref: None,
            });
        }
        self.pending_commit.store(true, Ordering::SeqCst);
        Ok(catbird_mls::DecryptResult {
            plaintext: Vec::new(),
            epoch: 7,
            sequence_number: 1,
            sender_credential: catbird_mls::CredentialData {
                credential_type: "basic".to_string(),
                identity: b"did:plc:alice".to_vec(),
            },
            content_type: catbird_mls::DecryptContentType::Commit,
            proposal_ref: None,
        })
    }

    fn decrypt_message_outcome(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<MlsDecryptOutcome, catbird_mls::MLSError> {
        if self.own_private_message_on_decrypt {
            let epoch = self
                .custom_own_private_epoch
                .unwrap_or_else(|| self.crypto_epoch.load(Ordering::SeqCst));
            let aad_sha256 = self
                .custom_own_private_aad_sha256
                .unwrap_or_else(|| Sha256::digest(b"").into());
            let ciphertext_sha256 = self
                .custom_own_private_ciphertext_sha256
                .unwrap_or_else(|| Sha256::digest(&ciphertext).into());
            return Ok(MlsDecryptOutcome::OwnPrivateMessage {
                epoch,
                aad_sha256,
                ciphertext_sha256,
            });
        }
        if self.own_pending_commit_on_decrypt {
            return Ok(MlsDecryptOutcome::OwnPendingCommit);
        }
        self.decrypt_message(group_id, ciphertext)
            .map(MlsDecryptOutcome::Message)
    }

    fn store_own_echo_proof(&self, proof: &OwnEchoProof) -> Result<(), catbird_mls::MLSError> {
        if self.fail_store_proof.load(Ordering::SeqCst) {
            return Err(catbird_mls::MLSError::StorageFailed);
        }
        self.proof_storage
            .lock()
            .unwrap()
            .insert(proof.canonical_entry_sha256, proof.clone());
        Ok(())
    }

    fn has_own_echo_proof(
        &self,
        conversation_id: &str,
        group_id: &[u8],
        server_entry_id: &str,
        mls_epoch: u64,
        aad_sha256: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
    ) -> Result<bool, catbird_mls::MLSError> {
        if self.fail_lookup_proof.load(Ordering::SeqCst) {
            return Err(catbird_mls::MLSError::StorageFailed);
        }
        let canonical_entry_sha256 = OwnEchoProof::compute_canonical_entry_sha256(
            conversation_id,
            group_id,
            server_entry_id,
            mls_epoch,
            aad_sha256,
            ciphertext_sha256,
        );
        let guard = self.proof_storage.lock().unwrap();
        if let Some(proof) = guard.get(&canonical_entry_sha256) {
            let matches = proof.conversation_id == conversation_id
                && proof.group_id == group_id
                && proof.server_entry_id == server_entry_id
                && proof.mls_epoch == mls_epoch
                && proof.aad_sha256 == *aad_sha256
                && proof.ciphertext_sha256 == *ciphertext_sha256;
            Ok(matches)
        } else {
            Ok(false)
        }
    }

    fn merge_incoming_commit(
        &self,
        _group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<u64, catbird_mls::MLSError> {
        self.pending_commit.store(false, Ordering::SeqCst);
        if self.merge_succeeds {
            self.crypto_epoch.store(target_epoch, Ordering::SeqCst);
            Ok(target_epoch)
        } else {
            Err(catbird_mls::MLSError::Internal(
                "injected merge rejection".into(),
            ))
        }
    }

    fn ensure_storage_durable(&self) -> Result<(), catbird_mls::MLSError> {
        self.durability_calls.fetch_add(1, Ordering::SeqCst);
        if self.durability_succeeds {
            Ok(())
        } else {
            Err(catbird_mls::MLSError::StorageFailed)
        }
    }

    fn discard_incoming_commit(
        &self,
        _group_id: Vec<u8>,
        _target_epoch: u64,
    ) -> Result<(), catbird_mls::MLSError> {
        self.discard_calls.fetch_add(1, Ordering::SeqCst);
        if self.discard_succeeds {
            self.pending_commit.store(false, Ordering::SeqCst);
            Ok(())
        } else {
            Err(catbird_mls::MLSError::Internal(
                "injected staged-commit cleanup failure".into(),
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

    fn cleanup_epoch_secrets(
        &self,
        _group_id: Vec<u8>,
        _current_epoch: u64,
        _retention_epochs: u64,
    ) -> Result<(), catbird_mls::MLSError> {
        self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
}

#[tokio::test(flavor = "multi_thread")]
async fn external_join_authorization_rejection_does_not_advance_fork_or_rejoin_state() {
    let did = "did:plc:alice";
    let conversation_id = "ee11ee22ee33ee44ee55ee66ee77ee88";
    let group_id = conversation_id;
    let storage = MockStorage::new();
    let crypto = Arc::new(ControlledCommitCrypto::rejects_external_join_proposal());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(MockDeliveryService::new(did).clone_as(did)),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");
    let initial_state = GroupState {
        group_id: group_id.to_string(),
        conversation_id: conversation_id.to_string(),
        epoch: 1,
        members: vec![did.to_string()],
    };
    storage
        .set_group_state(&initial_state)
        .await
        .expect("persist initial group state");
    orchestrator
        .group_states()
        .lock()
        .await
        .insert(group_id.to_string(), initial_state);
    orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(conversation_id.to_string(), ConversationState::Active);

    for index in 0..3 {
        let error = orchestrator
            .process_incoming(&catbird_mls::orchestrator::IncomingEnvelope {
                conversation_id: conversation_id.to_string(),
                sender_did: "did:plc:outsider".to_string(),
                ciphertext: format!("external-proposal-{index}").into_bytes(),
                timestamp: chrono::Utc::now(),
                server_message_id: Some(format!("external-proposal-{index}")),
                server_epoch: Some(1),
                server_sequence: None,
            })
            .await
            .expect_err("unauthorized ExternalJoinProposal must fail closed");
        assert!(matches!(
            error,
            catbird_mls::orchestrator::OrchestratorError::Mls(
                catbird_mls::MLSError::InsufficientPermissions { ref operation }
            ) if operation == "external_join_proposal"
        ));
    }

    assert_eq!(crypto.decrypt_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        orchestrator
            .conversation_states()
            .lock()
            .await
            .get(conversation_id),
        Some(&ConversationState::Active)
    );
    assert!(!storage.has_rejoin_flag(conversation_id));
    assert!(storage
        .get_state_transitions(conversation_id)
        .iter()
        .all(|transition| !matches!(
            transition.to,
            ConversationState::ForkDetected { .. } | ConversationState::NeedsRejoin
        )));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_conversation_mapping_aborts_the_page_cursor() {
    let did = "did:plc:alice";
    let conversation_id = "aa11aa22aa33aa44aa55aa66aa77aa88";
    let storage = MockStorage::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let crypto = Arc::new(ControlledCommitCrypto::merge_succeeds());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage),
        Arc::new(api.clone()),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    api.create_conversation(conversation_id, None, None, None, None)
        .await
        .expect("create server-only conversation");
    api.send_message_with_id(conversation_id, b"ordered-frame", 1, "missing-map")
        .await
        .expect("seed ordered frame");

    let error = orchestrator
        .fetch_messages(conversation_id, None, 10, None, None, None)
        .await
        .expect_err("unknown mapping must abort instead of returning the page cursor");
    assert!(matches!(
        error,
        catbird_mls::orchestrator::OrchestratorError::NotJoined { ref convo_id }
            if convo_id == conversation_id
    ));
    assert_eq!(crypto.decrypt_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_local_group_aborts_the_page_cursor() {
    let did = "did:plc:alice";
    let conversation_id = "bb11bb22bb33bb44bb55bb66bb77bb88";
    let group_id = conversation_id;
    let storage = MockStorage::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let crypto = Arc::new(ControlledCommitCrypto::group_not_found());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(api.clone()),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    api.create_conversation(conversation_id, None, None, None, None)
        .await
        .expect("create mock conversation");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");
    let initial_state = GroupState {
        group_id: group_id.to_string(),
        conversation_id: conversation_id.to_string(),
        epoch: 1,
        members: vec![did.to_string()],
    };
    storage
        .set_group_state(&initial_state)
        .await
        .expect("persist initial group state");
    orchestrator
        .group_states()
        .lock()
        .await
        .insert(group_id.to_string(), initial_state);
    api.send_message_with_id(conversation_id, b"ordered-frame", 1, "missing-group")
        .await
        .expect("seed ordered frame");

    let error = orchestrator
        .fetch_messages(conversation_id, None, 10, None, None, None)
        .await
        .expect_err("missing local group must abort instead of returning the page cursor");
    assert!(matches!(
        error,
        catbird_mls::orchestrator::OrchestratorError::NotJoined { ref convo_id }
            if convo_id == conversation_id
    ));
    assert_eq!(crypto.decrypt_calls.load(Ordering::SeqCst), 1);
}

type MessagingTestOrchestrator =
    MLSOrchestrator<MockStorage, MockDeliveryService, MockCredentials, ControlledCommitCrypto>;

struct WrongEpochRepairFixture {
    orchestrator: MessagingTestOrchestrator,
    storage: MockStorage,
    api: MockDeliveryService,
    crypto: Arc<ControlledCommitCrypto>,
    conversation_id: String,
}

async fn controlled_inbound_fixture(
    conversation_id: &str,
    crypto: Arc<ControlledCommitCrypto>,
) -> WrongEpochRepairFixture {
    controlled_inbound_fixture_with_group(conversation_id, conversation_id, crypto).await
}

async fn controlled_inbound_fixture_with_group(
    conversation_id: &str,
    group_id: &str,
    crypto: Arc<ControlledCommitCrypto>,
) -> WrongEpochRepairFixture {
    let did = "did:plc:alice";
    let storage = MockStorage::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(api.clone()),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    api.create_conversation(group_id, None, None, None, None)
        .await
        .expect("create mock conversation");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");

    let initial_state = GroupState {
        group_id: group_id.to_string(),
        conversation_id: conversation_id.to_string(),
        epoch: 1,
        members: vec![did.to_string()],
    };
    storage
        .set_group_state(&initial_state)
        .await
        .expect("persist initial group state");
    orchestrator
        .group_states()
        .lock()
        .await
        .insert(group_id.to_string(), initial_state);

    orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(conversation_id.to_string(), ConversationState::Active);

    WrongEpochRepairFixture {
        orchestrator,
        storage,
        api,
        crypto,
        conversation_id: conversation_id.to_string(),
    }
}

async fn wrong_epoch_repair_fixture(
    conversation_id: &str,
    durability_succeeds: bool,
) -> WrongEpochRepairFixture {
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::wrong_epoch_repair(
            durability_succeeds,
        )),
    )
    .await;

    fixture
        .api
        .send_message_with_id(conversation_id, b"commit-one", 7, "commit-1")
        .await
        .expect("seed first commit envelope");
    fixture
        .api
        .send_message_with_id(conversation_id, b"commit-two", 8, "commit-2")
        .await
        .expect("seed second commit envelope");

    fixture
}

fn test_envelope(
    conversation_id: &str,
    message_id: &str,
) -> catbird_mls::orchestrator::IncomingEnvelope {
    catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: conversation_id.to_string(),
        sender_did: "did:plc:alice".to_string(),
        ciphertext: format!("ciphertext-{message_id}").into_bytes(),
        timestamp: chrono::Utc::now(),
        server_message_id: Some(message_id.to_string()),
        server_epoch: Some(1),
        server_sequence: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_delivery_is_serialized_through_message_durability() {
    let conversation_id = "9192939495969798999a9b9c9d9e9fa0";
    let message_id = "overlapping-application";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::application_then_secret_reuse(
            Duration::from_millis(150),
        )),
    )
    .await;
    let orchestrator = Arc::new(fixture.orchestrator);
    let envelope = test_envelope(conversation_id, message_id);

    let first = {
        let orchestrator = Arc::clone(&orchestrator);
        let envelope = envelope.clone();
        tokio::spawn(async move { orchestrator.process_incoming(&envelope).await })
    };
    while !fixture.crypto.first_decrypt_entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    let second = {
        let orchestrator = Arc::clone(&orchestrator);
        let envelope = envelope.clone();
        tokio::spawn(async move { orchestrator.process_incoming(&envelope).await })
    };

    let first = tokio::time::timeout(Duration::from_secs(2), first)
        .await
        .expect("first delivery must not deadlock")
        .expect("first delivery task")
        .expect("first delivery succeeds");
    let second = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("second delivery must not deadlock")
        .expect("second delivery task")
        .expect("serialized redelivery succeeds through durable dedup");

    assert!(first.is_some(), "one delivery must materialize the message");
    assert!(
        second.is_none(),
        "the redelivery must deduplicate after storage"
    );
    assert_eq!(
        fixture.crypto.decrypt_calls.load(Ordering::SeqCst),
        1,
        "the second pipeline must wait for the first storage barrier before deduplication"
    );
    assert!(fixture.storage.message_exists(message_id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_reuse_without_durable_envelope_evidence_fails_closed_without_rejoin() {
    let conversation_id = "8182838485868788898a8b8c8d8e8f90";
    let message_id = "unproven-secret-reuse";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::secret_reuse()),
    )
    .await;
    fixture
        .api
        .send_message_with_id(conversation_id, b"secret-reuse", 1, message_id)
        .await
        .expect("seed server envelope");
    fixture
        .storage
        .store_message(&Message {
            id: message_id.to_string(),
            conversation_id: "different-stable-conversation".to_string(),
            sender_did: "did:plc:alice".to_string(),
            text: "unrelated durable row".to_string(),
            timestamp: chrono::Utc::now(),
            epoch: 1,
            sequence_number: 1,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .expect("seed colliding durable ID in another conversation");

    for _ in 0..3 {
        let error = fixture
            .orchestrator
            .fetch_messages(conversation_id, None, 1, None, None, None)
            .await
            .expect_err("unproven SecretReuse must withhold the page cursor");
        assert!(error
            .to_string()
            .contains("SecretReuse without durable envelope evidence"));
    }

    assert_eq!(fixture.crypto.decrypt_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(conversation_id),
        Some(&ConversationState::Active),
        "SecretReuse proof failure is not evidence of a fork"
    );
    assert!(!fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_missing_proof_withholds_cursor_and_marks_rejoin() {
    let conversation_id = "7172737475767778797a7b7c7d7e7f80";
    let message_id = "unproven-own-echo";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    fixture
        .api
        .send_message_with_id(conversation_id, b"own-echo", 1, message_id)
        .await
        .expect("seed server envelope");
    fixture
        .api
        .send_message_with_id(conversation_id, b"later-frame", 1, "later-frame")
        .await
        .expect("seed continuation frame");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("own-message error without durable outbox proof must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_exact_durable_proof_advances_cursor_and_retains_proof() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f70";
    let message_id = "durable-own-echo";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    let group_bytes = hex::decode(conversation_id).unwrap_or_default();
    let ciphertext = b"exact-ciphertext";
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"").into();
    let ct_hash: [u8; 32] = Sha256::digest(ciphertext).into();

    let proof = OwnEchoProof::new(
        req_hash,
        conversation_id.to_string(),
        group_bytes.clone(),
        message_id.to_string(),
        1,
        aad_hash,
        ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();

    fixture
        .api
        .send_message_with_id(conversation_id, ciphertext, 1, message_id)
        .await
        .expect("seed server envelope");

    fixture
        .api
        .send_message_with_id(conversation_id, b"continuation", 1, "durable-own-echo-next")
        .await
        .expect("seed continuation frame");

    let (messages, cursor) = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect("durably proven own echo may advance the cursor");
    assert!(messages.is_empty());
    assert_eq!(cursor.as_deref(), Some("1"));

    // Proof must be retained after acceptance
    assert!(fixture
        .crypto
        .has_own_echo_proof(
            conversation_id,
            &group_bytes,
            message_id,
            1,
            &aad_hash,
            &ct_hash,
        )
        .expect("proof must remain queryable"));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_entry_id_collision_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f71";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    let group_bytes = hex::decode(conversation_id).unwrap_or_default();
    let ciphertext = b"ciphertext-payload";
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"").into();
    let ct_hash: [u8; 32] = Sha256::digest(ciphertext).into();

    // Store proof for entry-1
    let proof = OwnEchoProof::new(
        req_hash,
        conversation_id.to_string(),
        group_bytes.clone(),
        "entry-1".to_string(),
        1,
        aad_hash,
        ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();

    // Inbound envelope arrives with entry-2
    fixture
        .api
        .send_message_with_id(conversation_id, ciphertext, 1, "entry-2")
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("entry-id collision must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));

    // Proof for entry-1 is still intact
    assert!(fixture
        .crypto
        .has_own_echo_proof(
            conversation_id,
            &group_bytes,
            "entry-1",
            1,
            &aad_hash,
            &ct_hash,
        )
        .unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_conversation_mismatch_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f72";
    let message_id = "mismatch-convo-msg";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    let group_bytes = hex::decode(conversation_id).unwrap_or_default();
    let ciphertext = b"ciphertext-payload";
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"").into();
    let ct_hash: [u8; 32] = Sha256::digest(ciphertext).into();

    // Store proof for a different conversation
    let proof = OwnEchoProof::new(
        req_hash,
        "different-conversation-id".to_string(),
        group_bytes,
        message_id.to_string(),
        1,
        aad_hash,
        ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();

    fixture
        .api
        .send_message_with_id(conversation_id, ciphertext, 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("conversation mismatch must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_group_or_epoch_mismatch_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f73";
    let message_id = "mismatch-group-epoch-msg";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    let ciphertext = b"ciphertext-payload";
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"").into();
    let ct_hash: [u8; 32] = Sha256::digest(ciphertext).into();

    // Proof with wrong group ID
    let proof = OwnEchoProof::new(
        req_hash,
        conversation_id.to_string(),
        b"wrong-group-id".to_vec(),
        message_id.to_string(),
        1,
        aad_hash,
        ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();

    fixture
        .api
        .send_message_with_id(conversation_id, ciphertext, 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("group mismatch must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_ciphertext_mutation_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f74";
    let message_id = "ciphertext-mutation-msg";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    let group_bytes = hex::decode(conversation_id).unwrap_or_default();
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"").into();
    let original_ct_hash: [u8; 32] = Sha256::digest(b"original-ciphertext").into();

    let proof = OwnEchoProof::new(
        req_hash,
        conversation_id.to_string(),
        group_bytes,
        message_id.to_string(),
        1,
        aad_hash,
        original_ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();

    // Send mutated ciphertext
    fixture
        .api
        .send_message_with_id(conversation_id, b"mutated-ciphertext", 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("ciphertext mutation must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_aad_mutation_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f75";
    let message_id = "aad-mutation-msg";
    let mut crypto = ControlledCommitCrypto::own_private_message();
    crypto.custom_own_private_aad_sha256 = Some(Sha256::digest(b"mutated-aad").into());
    let fixture = controlled_inbound_fixture(conversation_id, Arc::new(crypto)).await;
    let group_bytes = hex::decode(conversation_id).unwrap_or_default();
    let ciphertext = b"ciphertext-payload";
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"expected-aad").into();
    let ct_hash: [u8; 32] = Sha256::digest(ciphertext).into();

    let proof = OwnEchoProof::new(
        req_hash,
        conversation_id.to_string(),
        group_bytes,
        message_id.to_string(),
        1,
        aad_hash,
        ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();

    fixture
        .api
        .send_message_with_id(conversation_id, ciphertext, 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("aad mutation must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[test]
fn canonical_entry_digest_vector_proof_every_field_changes_digest() {
    let convo = "convo-1";
    let group = b"group-1";
    let entry = "entry-1";
    let epoch = 10u64;
    let aad = [1u8; 32];
    let ct = [2u8; 32];

    let base_digest =
        OwnEchoProof::compute_canonical_entry_sha256(convo, group, entry, epoch, &aad, &ct);

    // Mutate conversation
    let d1 =
        OwnEchoProof::compute_canonical_entry_sha256("convo-2", group, entry, epoch, &aad, &ct);
    assert_ne!(base_digest, d1, "conversation change must alter digest");

    // Mutate group
    let d2 =
        OwnEchoProof::compute_canonical_entry_sha256(convo, b"group-2", entry, epoch, &aad, &ct);
    assert_ne!(base_digest, d2, "group change must alter digest");

    // Mutate entry
    let d3 =
        OwnEchoProof::compute_canonical_entry_sha256(convo, group, "entry-2", epoch, &aad, &ct);
    assert_ne!(base_digest, d3, "entry change must alter digest");

    // Mutate epoch
    let d4 = OwnEchoProof::compute_canonical_entry_sha256(convo, group, entry, 11u64, &aad, &ct);
    assert_ne!(base_digest, d4, "epoch change must alter digest");

    // Mutate aad
    let mut mutated_aad = aad;
    mutated_aad[0] ^= 0xff;
    let d5 =
        OwnEchoProof::compute_canonical_entry_sha256(convo, group, entry, epoch, &mutated_aad, &ct);
    assert_ne!(base_digest, d5, "aad change must alter digest");

    // Mutate ciphertext
    let mut mutated_ct = ct;
    mutated_ct[0] ^= 0xff;
    let d6 =
        OwnEchoProof::compute_canonical_entry_sha256(convo, group, entry, epoch, &aad, &mutated_ct);
    assert_ne!(base_digest, d6, "ciphertext change must alter digest");
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_storage_lookup_failure_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f76";
    let message_id = "storage-failure-msg";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_private_message()),
    )
    .await;
    let group_bytes = hex::decode(conversation_id).unwrap_or_default();
    let ciphertext = b"ciphertext-payload";
    let req_hash: [u8; 32] = Sha256::digest(b"test-request").into();
    let aad_hash: [u8; 32] = Sha256::digest(b"").into();
    let ct_hash: [u8; 32] = Sha256::digest(ciphertext).into();

    let proof = OwnEchoProof::new(
        req_hash,
        conversation_id.to_string(),
        group_bytes,
        message_id.to_string(),
        1,
        aad_hash,
        ct_hash,
    );
    fixture.crypto.store_own_echo_proof(&proof).unwrap();
    fixture
        .crypto
        .fail_lookup_proof
        .store(true, Ordering::SeqCst);

    fixture
        .api
        .send_message_with_id(conversation_id, ciphertext, 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("storage lookup failure must withhold cursor");
    assert!(matches!(
        error,
        catbird_mls::orchestrator::error::OrchestratorError::Mls(
            catbird_mls::MLSError::StorageFailed
        )
    ));
    assert!(!fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn own_pending_commit_untracked_restarted_withholds_cursor() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f77";
    let message_id = "untracked-commit-msg";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_pending_commit()),
    )
    .await;

    fixture
        .api
        .send_message_with_id(conversation_id, b"commit-ciphertext", 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("untracked OwnPendingCommit outcome must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own pending commit outcome"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn bare_own_commits_hash_without_expectation_withholds_cursor_and_marks_rejoin() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f78";
    let message_id = "bare-own-commit";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::own_pending_commit()),
    )
    .await;

    let commit_hash = Sha256::digest(b"commit-ciphertext").to_vec();
    fixture
        .orchestrator
        .own_commits()
        .lock()
        .await
        .insert(commit_hash.clone(), web_time::Instant::now());

    fixture
        .api
        .send_message_with_id(conversation_id, b"commit-ciphertext", 1, message_id)
        .await
        .expect("seed server envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("bare tracked commit without expectation must fail closed");
    assert!(error
        .to_string()
        .contains("unverified bare own commit hash without expectation"));
    assert!(fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn response_lost_or_unrecorded_proof_withholds_cursor() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("response-lost-cursor-withholding", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;
    let group_bytes = hex::decode(group_id).unwrap();

    // Alice encrypts an application message directly (simulating send where response was lost before proof storage)
    let enc = alice
        .orchestrator
        .mls_context()
        .encrypt_message(group_bytes.clone(), b"lost response payload".to_vec())
        .expect("encrypt application message");

    // Seed server with the message envelope
    world
        .api_service
        .send_message_with_id(
            &convo.conversation_id,
            &enc.ciphertext,
            0,
            "server-entry-lost-ack",
        )
        .await
        .expect("seed server envelope");

    // Because no durable proof was recorded, receiving this own private message echo must withhold cursor
    let error = alice
        .orchestrator
        .fetch_messages(group_id, None, 10, None, None, None)
        .await
        .expect_err("lost response / missing proof must withhold cursor on own message echo");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
    assert!(!alice.storage.has_rejoin_flag(group_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn proof_store_failure_withholds_cursor() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("proof-store-failure-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;
    let group_bytes = hex::decode(group_id).unwrap();

    let enc = alice
        .orchestrator
        .mls_context()
        .encrypt_message(group_bytes.clone(), b"unproven payload".to_vec())
        .expect("encrypt application message");
    world
        .api_service
        .send_message_with_id(
            &convo.conversation_id,
            &enc.ciphertext,
            0,
            "unproven-server-entry",
        )
        .await
        .expect("seed server envelope");

    let error = alice
        .orchestrator
        .fetch_messages(group_id, None, 10, None, None, None)
        .await
        .expect_err("missing proof must withhold cursor");
    assert!(error
        .to_string()
        .contains("unverified own-private message outcome"));
}

#[tokio::test(flavor = "multi_thread")]
async fn post_set_aad_failure_restores_aad_and_echo_matches_exact_proof() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("aad-restore-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;
    let group_bytes = hex::decode(group_id).unwrap();
    // Force a failure in add_members_with_aad with non-empty AAD (using an invalid key package)
    let bad_kp = catbird_mls::KeyPackageData {
        data: b"invalid key package bytes".to_vec(),
    };
    let add_res = alice.orchestrator.mls_context().add_members_with_aad(
        group_bytes.clone(),
        vec![bad_kp],
        Some(b"custom-aad".to_vec()),
    );
    assert!(
        add_res.is_err(),
        "add_members_with_aad with invalid key package must fail"
    );
    // Now Alice sends an application message. The group AAD must have been restored to empty,
    // so the proof's empty AAD matches the encryption and the subsequent echo.
    let sent = alice
        .orchestrator
        .send_message(group_id, "hello with restored AAD")
        .await
        .expect("send_message must succeed after restored AAD");

    // Fetch messages: Alice's own message echoes back and must be skipped cleanly via exact proof
    let (fetched, _cursor) = alice
        .orchestrator
        .fetch_messages(group_id, None, 10, None, None, None)
        .await
        .expect("fetch_messages must match proof and skip echo");
    assert!(fetched.is_empty(), "own message echo must be skipped");
}

#[tokio::test(flavor = "multi_thread")]
async fn own_private_message_survives_restart_and_redelivery() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("restart-redelivery-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = &convo.group_id;

    let sent = alice
        .orchestrator
        .send_message(group_id, "restart message")
        .await
        .expect("send_message failed");
    assert_ne!(sent.id, "restart message");
    let parsed_server_uuid =
        uuid::Uuid::parse_str(&sent.id).expect("server entryId must be UUIDv4");
    assert_eq!(parsed_server_uuid.get_version_num(), 4);

    // Clear in-memory caches to simulate app restart
    alice.orchestrator.own_commits().lock().await.clear();
    alice.orchestrator.pending_messages().lock().await.clear();

    // First fetch: message echoes back, skipped via durable proof in SQLCipher
    let (fetched1, _cursor1) = alice
        .orchestrator
        .fetch_messages(group_id, None, 100, None, None, None)
        .await
        .expect("fetch_messages failed on restart");
    assert!(
        fetched1.is_empty(),
        "own message echo should be skipped after restart"
    );

    // Second fetch (redelivery): message echoes back again, skipped via retained proof
    let (fetched2, _cursor2) = alice
        .orchestrator
        .fetch_messages(group_id, None, 100, None, None, None)
        .await
        .expect("fetch_messages failed on redelivery");
    assert!(
        fetched2.is_empty(),
        "own message echo should be skipped on redelivery"
    );

    // Verify local storage still has the original sent message
    let all_msgs = alice.storage.get_conversation_messages(group_id);
    assert_eq!(all_msgs.len(), 1);
    assert_eq!(all_msgs[0].text, "restart message");
}

#[tokio::test(flavor = "multi_thread")]
async fn message_store_failure_then_secret_reuse_never_returns_a_cursor() {
    let conversation_id = "5152535455565758595a5b5c5d5e5f60";
    let message_id = "store-failure-redelivery";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::application_then_secret_reuse(
            Duration::ZERO,
        )),
    )
    .await;
    fixture
        .api
        .send_message_with_id(conversation_id, b"application", 1, message_id)
        .await
        .expect("seed server envelope");
    fixture.storage.fail_next_store_message();

    let first_error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("message storage failure must withhold the page cursor");
    assert!(first_error
        .to_string()
        .contains("injected store_message failure"));

    let redelivery_error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("SecretReuse after failed storage must still withhold the cursor");
    assert!(redelivery_error
        .to_string()
        .contains("SecretReuse without durable envelope evidence"));
    assert!(!fixture.storage.message_exists(message_id).await.unwrap());
    assert!(!fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn non_displayable_application_requires_crypto_durability_before_cursor_return() {
    let conversation_id = "4142434445464748494a4b4c4d4e4f50";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::non_displayable_application(false)),
    )
    .await;
    fixture
        .api
        .send_message_with_id(conversation_id, b"control", 1, "control-message")
        .await
        .expect("seed server control envelope");

    let error = fixture
        .orchestrator
        .fetch_messages(conversation_id, None, 1, None, None, None)
        .await
        .expect_err("non-displayable payload must not bypass crypto durability");
    assert!(error.to_string().contains("Storage operation failed"));
    assert_eq!(fixture.crypto.durability_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_epoch_durability_retry_failure_withholds_projection_and_cursor() {
    let fixture = wrong_epoch_repair_fixture("aaaabbbbccccddddeeeeffff00001111", false).await;
    let (_, server_cursor) = fixture
        .api
        .get_messages(
            &fixture.conversation_id,
            None,
            1,
            Some("commit"),
            None,
            None,
        )
        .await
        .expect("inspect mock server page");
    assert_eq!(server_cursor.as_deref(), Some("1"));

    let error = fixture
        .orchestrator
        .fetch_messages(
            &fixture.conversation_id,
            None,
            1,
            Some("commit"),
            None,
            None,
        )
        .await
        .expect_err("failed crypto durability retry must abort the page cursor");
    assert!(error.to_string().contains("Storage operation failed"));
    assert_eq!(fixture.crypto.durability_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.crypto.cleanup_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .orchestrator
            .group_states()
            .lock()
            .await
            .get(&fixture.conversation_id)
            .expect("cached state remains present")
            .epoch,
        1
    );
    assert_eq!(
        fixture
            .storage
            .get_group_state(&fixture.conversation_id)
            .await
            .expect("read persisted state")
            .expect("persisted state remains present")
            .epoch,
        1
    );
    assert!(fixture.storage.has_rejoin_flag(&fixture.conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_epoch_equal_projection_still_requires_crypto_durability() {
    let fixture = wrong_epoch_repair_fixture("a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4", false).await;
    let mut projected = fixture
        .storage
        .get_group_state(&fixture.conversation_id)
        .await
        .expect("read persisted state")
        .expect("persisted state remains present");
    projected.epoch = 7;
    fixture
        .storage
        .set_group_state(&projected)
        .await
        .expect("seed projection advanced by a later application message");
    fixture
        .orchestrator
        .group_states()
        .lock()
        .await
        .get_mut(&fixture.conversation_id)
        .expect("cached state remains present")
        .epoch = 7;

    let error = fixture
        .orchestrator
        .fetch_messages(
            &fixture.conversation_id,
            None,
            1,
            Some("commit"),
            None,
            None,
        )
        .await
        .expect_err("epoch equality must not bypass a failed crypto durability retry");
    assert!(error.to_string().contains("Storage operation failed"));
    assert_eq!(fixture.crypto.durability_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.crypto.cleanup_calls.load(Ordering::SeqCst), 0);
    assert!(fixture.storage.has_rejoin_flag(&fixture.conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_epoch_projection_write_failure_withholds_cache_cleanup_and_cursor() {
    let fixture = wrong_epoch_repair_fixture("11110000ffffeeeeddddccccbbbbaaaa", true).await;
    fixture.storage.fail_next_set_group_state();

    let error = fixture
        .orchestrator
        .fetch_messages(
            &fixture.conversation_id,
            None,
            1,
            Some("commit"),
            None,
            None,
        )
        .await
        .expect_err("failed projection write must abort the page cursor");
    assert!(error
        .to_string()
        .contains("injected set_group_state failure"));
    assert_eq!(fixture.crypto.durability_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.crypto.cleanup_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .orchestrator
            .group_states()
            .lock()
            .await
            .get(&fixture.conversation_id)
            .expect("cached state remains present")
            .epoch,
        1
    );
    assert_eq!(
        fixture
            .storage
            .get_group_state(&fixture.conversation_id)
            .await
            .expect("read persisted state")
            .expect("persisted state remains present")
            .epoch,
        1
    );
    assert!(fixture.storage.has_rejoin_flag(&fixture.conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_epoch_redelivery_repairs_durable_projection_before_cursor_return() {
    let fixture = wrong_epoch_repair_fixture("1234567890abcdef1234567890abcdef", true).await;

    let (messages, cursor) = fixture
        .orchestrator
        .fetch_messages(
            &fixture.conversation_id,
            None,
            1,
            Some("commit"),
            None,
            None,
        )
        .await
        .expect("durable retry and projection repair should allow cursor return");
    assert!(messages.is_empty());
    assert_eq!(cursor.as_deref(), Some("1"));
    assert_eq!(fixture.crypto.durability_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.crypto.cleanup_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .orchestrator
            .group_states()
            .lock()
            .await
            .get(&fixture.conversation_id)
            .expect("cached state remains present")
            .epoch,
        7
    );
    assert_eq!(
        fixture
            .storage
            .get_group_state(&fixture.conversation_id)
            .await
            .expect("read persisted state")
            .expect("persisted state remains present")
            .epoch,
        7
    );
    assert!(!fixture.storage.has_rejoin_flag(&fixture.conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn merge_failure_prevents_epoch_pruning_and_page_cursor_return() {
    let did = "did:plc:alice";
    let conversation_id = "00112233445566778899aabbccddeeff";
    let group_id = conversation_id;

    let storage = MockStorage::new();
    let credentials = MockCredentials::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let crypto = Arc::new(ControlledCommitCrypto::merge_fails());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(api.clone()),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    api.create_conversation(group_id, None, None, None, None)
        .await
        .expect("create mock conversation");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");

    let initial_state = GroupState {
        group_id: group_id.to_string(),
        conversation_id: conversation_id.to_string(),
        epoch: 1,
        members: vec![did.to_string()],
    };
    storage
        .set_group_state(&initial_state)
        .await
        .expect("persist initial group state");
    orchestrator
        .group_states()
        .lock()
        .await
        .insert(group_id.to_string(), initial_state);

    api.send_message_with_id(conversation_id, b"commit-one", 7, "commit-1")
        .await
        .expect("seed first commit envelope");
    api.send_message_with_id(conversation_id, b"commit-two", 8, "commit-2")
        .await
        .expect("seed second commit envelope");

    let (_, server_cursor) = api
        .get_messages(conversation_id, None, 1, Some("commit"), None, None)
        .await
        .expect("inspect mock server page");
    assert_eq!(server_cursor.as_deref(), Some("1"));

    let error = orchestrator
        .fetch_messages(conversation_id, None, 1, Some("commit"), None, None)
        .await
        .expect_err("merge failure must abort the page instead of returning its cursor");
    assert!(error.to_string().contains("injected merge rejection"));

    assert_eq!(crypto.decrypt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        orchestrator
            .group_states()
            .lock()
            .await
            .get(group_id)
            .expect("cached group state remains present")
            .epoch,
        1,
        "failed merge must not advance the cached epoch"
    );
    assert_eq!(
        storage
            .get_group_state(group_id)
            .await
            .expect("read persisted group state")
            .expect("persisted group state remains present")
            .epoch,
        1,
        "failed merge must not persist the staged target epoch"
    );
    assert_eq!(
        crypto.cleanup_calls.load(Ordering::SeqCst),
        0,
        "failed merge must not prune epoch secrets"
    );
    assert!(
        storage.has_rejoin_flag(conversation_id),
        "failed merge must still durably mark the conversation for rejoin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn epoch_persistence_failure_prevents_cache_pruning_and_page_cursor_return() {
    let did = "did:plc:alice";
    let conversation_id = "ffeeddccbbaa99887766554433221100";
    let group_id = conversation_id;

    let storage = MockStorage::new();
    let credentials = MockCredentials::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let crypto = Arc::new(ControlledCommitCrypto::merge_succeeds());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(api.clone()),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    api.create_conversation(group_id, None, None, None, None)
        .await
        .expect("create mock conversation");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");

    let initial_state = GroupState {
        group_id: group_id.to_string(),
        conversation_id: conversation_id.to_string(),
        epoch: 1,
        members: vec![did.to_string()],
    };
    storage
        .set_group_state(&initial_state)
        .await
        .expect("persist initial group state");
    orchestrator
        .group_states()
        .lock()
        .await
        .insert(group_id.to_string(), initial_state);

    api.send_message_with_id(conversation_id, b"commit-one", 7, "commit-1")
        .await
        .expect("seed first commit envelope");
    api.send_message_with_id(conversation_id, b"commit-two", 8, "commit-2")
        .await
        .expect("seed second commit envelope");

    let (_, server_cursor) = api
        .get_messages(conversation_id, None, 1, Some("commit"), None, None)
        .await
        .expect("inspect mock server page");
    assert_eq!(server_cursor.as_deref(), Some("1"));

    storage.fail_next_set_group_state();
    let error = orchestrator
        .fetch_messages(conversation_id, None, 1, Some("commit"), None, None)
        .await
        .expect_err("epoch persistence failure must abort the page cursor");
    assert!(error
        .to_string()
        .contains("injected set_group_state failure"));

    assert_eq!(crypto.decrypt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        orchestrator
            .group_states()
            .lock()
            .await
            .get(group_id)
            .expect("cached group state remains present")
            .epoch,
        1,
        "failed persistence must not publish the epoch to the cache"
    );
    assert_eq!(
        storage
            .get_group_state(group_id)
            .await
            .expect("read persisted group state")
            .expect("persisted group state remains present")
            .epoch,
        1,
        "failed persistence must leave the durable epoch unchanged"
    );
    assert_eq!(
        crypto.cleanup_calls.load(Ordering::SeqCst),
        0,
        "failed persistence must not prune epoch secrets"
    );
    assert!(
        storage.has_rejoin_flag(conversation_id),
        "failed persistence must durably mark the conversation for rejoin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_rejection_attempts_staged_commit_cleanup_and_surfaces_failure() {
    let did = "did:plc:alice";
    let conversation_id = "102132435465768798a9bacbdcedfe0f";
    let group_id = conversation_id;

    let storage = MockStorage::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let crypto = Arc::new(ControlledCommitCrypto::discard_fails());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(api),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");
    orchestrator.group_states().lock().await.insert(
        group_id.to_string(),
        GroupState {
            group_id: group_id.to_string(),
            conversation_id: conversation_id.to_string(),
            epoch: 1,
            members: vec![did.to_string()],
        },
    );

    let error = orchestrator
        .process_incoming(&catbird_mls::orchestrator::IncomingEnvelope {
            conversation_id: conversation_id.to_string(),
            sender_did: "did:plc:mallory".to_string(),
            ciphertext: b"staged-commit".to_vec(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("credential-substitution".to_string()),
            server_epoch: Some(7),
            server_sequence: None,
        })
        .await
        .expect_err("credential mismatch and cleanup failure must fail closed");

    assert!(error
        .to_string()
        .contains("injected staged-commit cleanup failure"));
    assert_eq!(crypto.decrypt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        crypto.discard_calls.load(Ordering::SeqCst),
        1,
        "credential rejection must attempt to clear the staged commit"
    );
    assert!(
        crypto.pending_commit.load(Ordering::SeqCst),
        "a surfaced cleanup failure must not pretend the staged commit was removed"
    );
    assert!(
        storage.has_rejoin_flag(conversation_id),
        "staged-commit cleanup failure must durably route the conversation to recovery"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_rejection_leaves_no_staged_commit_residue_when_cleanup_succeeds() {
    let did = "did:plc:alice";
    let conversation_id = "0ffedcba98765432100123456789abcd";
    let group_id = conversation_id;

    let storage = MockStorage::new();
    let crypto = Arc::new(ControlledCommitCrypto::merge_fails());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(MockDeliveryService::new(did).clone_as(did)),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping");

    let error = orchestrator
        .process_incoming(&catbird_mls::orchestrator::IncomingEnvelope {
            conversation_id: conversation_id.to_string(),
            sender_did: "did:plc:mallory".to_string(),
            ciphertext: b"staged-commit".to_vec(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("credential-substitution".to_string()),
            server_epoch: Some(7),
            server_sequence: None,
        })
        .await
        .expect_err("credential mismatch must fail closed");

    assert!(error.to_string().contains("credential binding rejected"));
    assert_eq!(crypto.discard_calls.load(Ordering::SeqCst), 1);
    assert!(
        !crypto.pending_commit.load(Ordering::SeqCst),
        "successful credential-rejection cleanup must remove the staged commit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_group_projection_fails_before_pruning_or_cursor_return() {
    let did = "did:plc:alice";
    let conversation_id = "0123456789abcdeffedcba9876543210";
    let group_id = conversation_id;

    let storage = MockStorage::new();
    let api = MockDeliveryService::new(did).clone_as(did);
    let crypto = Arc::new(ControlledCommitCrypto::merge_succeeds());
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&crypto),
        Arc::new(storage.clone()),
        Arc::new(api.clone()),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(did).await.expect("initialize");
    api.create_conversation(group_id, None, None, None, None)
        .await
        .expect("create mock conversation");
    storage
        .ensure_conversation_exists(did, conversation_id, group_id)
        .await
        .expect("seed stable conversation mapping without group projection");
    api.send_message_with_id(conversation_id, b"commit-one", 7, "commit-1")
        .await
        .expect("seed first commit envelope");
    api.send_message_with_id(conversation_id, b"commit-two", 8, "commit-2")
        .await
        .expect("seed second commit envelope");

    let (_, server_cursor) = api
        .get_messages(conversation_id, None, 1, Some("commit"), None, None)
        .await
        .expect("inspect mock server page");
    assert_eq!(server_cursor.as_deref(), Some("1"));

    let error = orchestrator
        .fetch_messages(conversation_id, None, 1, Some("commit"), None, None)
        .await
        .expect_err("missing durable group projection must abort the page cursor");
    assert!(error.to_string().contains("Group not found"));
    assert_eq!(crypto.cleanup_calls.load(Ordering::SeqCst), 0);
    assert!(storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn send_message_response_validation_rejects_noncanonical_shapes_and_mutations() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("response-validation-group", None, None)
        .await
        .expect("create_group");
    let group_id = &convo.group_id;

    // Helper to get the submitted signedRequest from a baseline send
    // Do a successful send first so we capture a real signedRequest shape
    alice
        .orchestrator
        .send_message(group_id, "seed message")
        .await
        .expect("seed send");
    let last_req = world
        .api_service
        .submitted_prepared_requests()
        .last()
        .cloned()
        .expect("last request");
    let wire: serde_json::Value =
        serde_json::from_slice(last_req.body.as_deref().unwrap()).unwrap();
    let valid_signed_request = wire.get("signedRequest").unwrap().clone();

    // 1. Top-level response without "entry" wrapper
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "conversationId": &convo.conversation_id,
            "entryId": uuid::Uuid::new_v4().to_string(),
            "receivedAt": "2026-08-27T00:00:00.000Z",
            "seq": 1,
            "signedRequest": valid_signed_request
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg1")
        .await
        .expect_err("top-level response without entry wrapper must be rejected");
    assert!(err
        .to_string()
        .contains("send_message response must contain only 'entry'"));

    // 2. Extra field in entry object
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": &convo.conversation_id,
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "2026-08-27T00:00:00.000Z",
                "seq": 1,
                "signedRequest": valid_signed_request,
                "unexpectedExtraField": "malicious"
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg2")
        .await
        .expect_err("entry with extra fields must be rejected");
    assert!(err
        .to_string()
        .contains("send_message response entry must have exactly 5 fields"));

    // 3. Mutated signature in returned signedRequest
    // Capture the latest valid signedRequest for msg3
    let mut bad_sig_request = valid_signed_request.clone();
    bad_sig_request["signature"] =
        serde_json::json!("bXV0YXRlZHNpZ25hdHVyZW11dGF0ZWRzaWduYXR1cmVtdXRhdGVkc2lnbmF0dXJlMQ==");
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": &convo.conversation_id,
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "2026-08-27T00:00:00.000Z",
                "seq": 1,
                "signedRequest": bad_sig_request
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg3")
        .await
        .expect_err("mutated signature in signedRequest must be rejected");
    assert!(err
        .to_string()
        .contains("signedRequest does not match submitted signedRequest"));

    // 4. Mutated actorDid in returned signedRequest
    let mut bad_actor_request = valid_signed_request.clone();
    bad_actor_request["body"]["actorDid"] = serde_json::json!("did:plc:mallory");
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": &convo.conversation_id,
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "2026-08-27T00:00:00.000Z",
                "seq": 1,
                "signedRequest": bad_actor_request
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg4")
        .await
        .expect_err("mutated actorDid in signedRequest must be rejected");
    assert!(err
        .to_string()
        .contains("signedRequest does not match submitted signedRequest"));

    // 5. Mismatched outer conversationId in entry
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": "00000000-0000-0000-0000-000000000000",
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "2026-08-27T00:00:00.000Z",
                "seq": 1,
                "signedRequest": valid_signed_request
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg5")
        .await
        .expect_err("mismatched outer conversationId must be rejected");
    assert!(err.to_string().contains("conversationId mismatch"));

    // 6. Invalid receivedAt timestamp
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": &convo.conversation_id,
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "not-a-timestamp",
                "seq": 1,
                "signedRequest": valid_signed_request
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg6")
        .await
        .expect_err("invalid receivedAt must be rejected");
    assert!(err
        .to_string()
        .contains("receivedAt is not a valid RFC3339 timestamp"));

    // 7. Sequence zero and exceeding MAX_SAFE_INTEGER
    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": &convo.conversation_id,
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "2026-08-27T00:00:00.000Z",
                "seq": 0,
                "signedRequest": valid_signed_request
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg7")
        .await
        .expect_err("seq zero must be rejected");
    assert!(err
        .to_string()
        .contains("seq must be in range 1..=9007199254740991"));

    world.api_service.set_next_send_custom_response(
        200,
        serde_json::json!({
            "entry": {
                "conversationId": &convo.conversation_id,
                "entryId": uuid::Uuid::new_v4().to_string(),
                "receivedAt": "2026-08-27T00:00:00.000Z",
                "seq": 9_007_199_254_740_992u64,
                "signedRequest": valid_signed_request
            }
        }),
    );
    let err = alice
        .orchestrator
        .send_message(group_id, "msg8")
        .await
        .expect_err("seq > MAX_SAFE_INTEGER must be rejected");
    assert!(err
        .to_string()
        .contains("seq must be in range 1..=9007199254740991"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_incoming_sequence_survives_durable_store_and_duplicate_delivery() {
    let fixture = controlled_inbound_fixture_with_group(
        "8d85cf39-997f-4861-a45e-a71f944db857",
        "9192939495969798999a9b9c9d9e9fa09192939495969798999a9b9c9d9e9fa0",
        Arc::new(ControlledCommitCrypto::application_then_secret_reuse(Duration::ZERO)),
    ).await;
    let mut envelope = test_envelope(&fixture.conversation_id, "e94874a0-86ab-49f4-8355-35a5d972b607");
    envelope.server_sequence = Some(271);
    envelope.timestamp = "2026-09-05T04:52:13.456Z".parse().unwrap();
    let message = fixture.orchestrator.process_incoming(&envelope).await.unwrap().unwrap();
    assert_eq!(message.sequence_number, 271, "server sequence must replace the process-local crypto counter");
    assert_eq!(message.timestamp, envelope.timestamp);
    assert_eq!(message.epoch, 1);
    let before = fixture.storage.get_messages(&fixture.conversation_id, 10, None).await.unwrap();
    assert!(fixture.orchestrator.process_incoming(&envelope).await.unwrap().is_none());
    let mut unproven_metadata = envelope.clone();
    unproven_metadata.server_sequence = Some(999);
    unproven_metadata.timestamp = "2026-09-05T05:52:13.456Z".parse().unwrap();
    assert!(fixture.orchestrator.process_incoming(&unproven_metadata).await.unwrap().is_none());
    let after = fixture.storage.get_messages(&fixture.conversation_id, 10, None).await.unwrap();
    assert_eq!(serde_json::to_value(&before).unwrap(), serde_json::to_value(&after).unwrap());
    assert_eq!(fixture.crypto.decrypt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_invalid_id_is_rejected_before_decrypt_but_legacy_ids_remain_accepted() {
    let fixture = controlled_inbound_fixture_with_group(
        "8d85cf39-997f-4861-a45e-a71f944db857",
        "9192939495969798999a9b9c9d9e9fa09192939495969798999a9b9c9d9e9fa0",
        Arc::new(ControlledCommitCrypto::application_then_secret_reuse(Duration::ZERO)),
    ).await;
    let mut envelope = test_envelope(&fixture.conversation_id, "membership-left:e94874a0-86ab-49f4-8355-35a5d972b607:e94874a0-86ab-49f4-8355-35a5d972b607");
    envelope.server_sequence = Some(271);
    assert!(fixture.orchestrator.process_incoming_message(&envelope).await.is_err());
    assert_eq!(fixture.crypto.decrypt_calls.load(Ordering::SeqCst), 0);
    assert!(fixture.storage.get_messages(&fixture.conversation_id, 10, None).await.unwrap().is_empty());
    envelope.server_sequence = None;
    envelope.server_message_id = Some("arbitrary-legacy-id".into());
    assert!(fixture.orchestrator.process_incoming(&envelope).await.unwrap().is_some());
    assert_eq!(fixture.crypto.decrypt_calls.load(Ordering::SeqCst), 1);
}
