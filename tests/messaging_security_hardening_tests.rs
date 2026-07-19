//! Security regressions for durable inbound-message processing.

#![allow(dead_code)]

mod e2e_harness;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use catbird_mls::orchestrator::{
    ConversationState, GroupState, MLSAPIClient, MLSMessagePayload, MLSOrchestrator,
    MLSStorageBackend, Message, MlsCryptoContext, OrchestratorConfig, ReactionAction,
};
use e2e_harness::mock_api_client::MockDeliveryService;
use e2e_harness::mock_credentials::MockCredentials;
use e2e_harness::mock_storage::MockStorage;

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
    cannot_decrypt_own_message_on_decrypt: bool,
    application_plaintext: Option<Vec<u8>>,
    application_then_secret_reuse: bool,
    first_decrypt_delay: Option<Duration>,
    first_decrypt_entered: AtomicBool,
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
            cannot_decrypt_own_message_on_decrypt: false,
            application_plaintext: None,
            application_then_secret_reuse: false,
            first_decrypt_delay: None,
            first_decrypt_entered: AtomicBool::new(false),
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

    fn cannot_decrypt_own_message() -> Self {
        let mut crypto = Self::configured(false, true, true, 1, false);
        crypto.cannot_decrypt_own_message_on_decrypt = true;
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
        if self.cannot_decrypt_own_message_on_decrypt {
            return Err(catbird_mls::MLSError::OpenMLS(
                "ValidationError(CannotDecryptOwnMessage)".to_string(),
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
    let did = "did:plc:alice";
    let group_id = conversation_id;
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
async fn own_message_decrypt_error_requires_durable_server_id_evidence() {
    let conversation_id = "7172737475767778797a7b7c7d7e7f80";
    let message_id = "unproven-own-echo";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::cannot_decrypt_own_message()),
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
        .contains("CannotDecryptOwnMessage without durable outbox evidence"));
    assert!(!fixture.storage.has_rejoin_flag(conversation_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_pending_server_id_authorizes_own_echo_skip() {
    let conversation_id = "6162636465666768696a6b6c6d6e6f70";
    let message_id = "durable-own-echo";
    let fixture = controlled_inbound_fixture(
        conversation_id,
        Arc::new(ControlledCommitCrypto::cannot_decrypt_own_message()),
    )
    .await;
    fixture
        .storage
        .store_pending_message(conversation_id, message_id)
        .await
        .expect("seed durable outbox evidence");
    fixture
        .api
        .send_message_with_id(conversation_id, b"own-echo", 1, message_id)
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
    assert!(!fixture
        .storage
        .remove_pending_message(message_id)
        .await
        .expect("inspect consumed pending proof"));
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
