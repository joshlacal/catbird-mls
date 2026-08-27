#![allow(dead_code)]

mod e2e_harness;

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use async_trait::async_trait;
use catbird_mls::orchestrator::error::{OrchestratorError, Result as OrchestratorResult};
use catbird_mls::orchestrator::{
    ConversationState, GroupState, IncomingEnvelope, MLSAPIClient, MLSOrchestrator,
    MLSStorageBackend, MlsCryptoContext, OrchestratorConfig,
};
use catbird_mls::{
    AddMembersResult, DecryptResult, EncryptResult, ExternalCommitResult, GroupConfig,
    GroupCreationResult, KeyPackageData, KeyPackageResult, MLSContext, MLSError, WelcomeResult,
};
use chrono::Utc;
use e2e_harness::mock_api_client::MockDeliveryService;
use e2e_harness::mock_credentials::MockCredentials;
use e2e_harness::mock_storage::MockStorage;
use e2e_harness::{TestClient, TestWorld};
use openmls::prelude::{MlsMessageIn, Welcome};
use tls_codec::Deserialize;

#[derive(Debug, Clone)]
struct CommitSubmission {
    convo_id: String,
    commit_data: Vec<u8>,
    action: String,
    confirmation_tag: Option<String>,
}

#[derive(Clone)]
struct RecordingCommitApi {
    inner: MockDeliveryService,
    submissions: Arc<Mutex<Vec<CommitSubmission>>>,
    recovery_reports: Arc<Mutex<Vec<(String, Option<String>)>>>,
    fail_commits: bool,
}

impl RecordingCommitApi {
    fn new(inner: MockDeliveryService, fail_commits: bool) -> Self {
        Self {
            inner,
            submissions: Arc::new(Mutex::new(Vec::new())),
            recovery_reports: Arc::new(Mutex::new(Vec::new())),
            fail_commits,
        }
    }

    fn submissions(&self) -> Vec<CommitSubmission> {
        self.submissions.lock().unwrap().clone()
    }

    fn recovery_reports(&self) -> Vec<(String, Option<String>)> {
        self.recovery_reports.lock().unwrap().clone()
    }
}

#[async_trait]
impl MLSAPIClient for RecordingCommitApi {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.inner.is_authenticated_as(did).await
    }

    async fn current_did(&self) -> Option<String> {
        self.inner.current_did().await
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> OrchestratorResult<catbird_mls::orchestrator::ConversationListPage> {
        self.inner.get_conversations(limit, cursor).await
    }

    async fn submit_prepared_request(
        &self,
        request: catbird_mls::orchestrator::canonical_transport::PreparedRequest,
    ) -> OrchestratorResult<catbird_mls::orchestrator::canonical_transport::GatewayResponse> {
        if self.fail_commits
            && request.operation
                == catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition
        {
            return Err(OrchestratorError::Api(
                "injected commit failure".to_string(),
            ));
        }
        if request.operation
            == catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestReset
        {
            if let Some(ref b) = request.body {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(b) {
                    let body_obj = v.get("signedRequest").and_then(|s| s.get("body")).or_else(|| v.get("body")).unwrap_or(&v);
                    let prior = body_obj.get("prior");
                    let convo_id = prior
                        .and_then(|p| p.get("conversationId"))
                        .or_else(|| body_obj.get("conversationId"))
                        .and_then(|c| c.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let auth = prior
                        .and_then(|p| p.get("groupContextHash"))
                        .and_then(|g| g.as_str().or_else(|| g.get("$bytes").and_then(|b| b.as_str())))
                        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
                        .map(|bytes| hex::encode(bytes));
                    self.recovery_reports.lock().unwrap().push((convo_id, auth));
                }
            }
        }
        self.inner.submit_prepared_request(request).await
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> OrchestratorResult<(
        Vec<catbird_mls::orchestrator::IncomingEnvelope>,
        Option<String>,
    )> {
        self.inner
            .get_messages(convo_id, cursor, limit, message_type, from_epoch, to_epoch)
            .await
    }

    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        dids: &[String],
    ) -> OrchestratorResult<Vec<catbird_mls::orchestrator::KeyPackageRef>> {
        self.inner.get_key_packages(actor_device_id, dids).await
    }

    async fn get_key_package_stats(
        &self,
    ) -> OrchestratorResult<catbird_mls::orchestrator::KeyPackageStats> {
        self.inner.get_key_package_stats().await
    }

    async fn sync_key_packages(
        &self,
        local_hashes: &[String],
        device_id: &str,
    ) -> OrchestratorResult<catbird_mls::orchestrator::KeyPackageSyncResult> {
        self.inner.sync_key_packages(local_hashes, device_id).await
    }

    async fn list_devices(
        &self,
        actor_device_id: &str,
    ) -> OrchestratorResult<Vec<catbird_mls::orchestrator::DeviceInfo>> {
        self.inner.list_devices(actor_device_id).await
    }

    async fn get_group_info(&self, convo_id: &str) -> OrchestratorResult<Vec<u8>> {
        self.inner.get_group_info(convo_id).await
    }

    async fn get_welcome(&self, convo_id: &str) -> OrchestratorResult<Vec<u8>> {
        self.inner.get_welcome(convo_id).await
    }
}

struct UnsupportedForkCrypto;

fn unsupported<T>() -> Result<T, MLSError> {
    Err(MLSError::OperationNotSupported {
        reason: "test crypto does not support this operation".to_string(),
    })
}

impl MlsCryptoContext for UnsupportedForkCrypto {
    fn create_key_package(&self, _identity: Vec<u8>) -> Result<KeyPackageResult, MLSError> {
        unsupported()
    }

    fn create_group(
        &self,
        _identity: Vec<u8>,
        _config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        unsupported()
    }

    fn add_members(
        &self,
        _group_id: Vec<u8>,
        _key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        unsupported()
    }

    fn remove_members(
        &self,
        _group_id: Vec<u8>,
        _member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        unsupported()
    }

    fn merge_pending_commit(&self, _group_id: Vec<u8>) -> Result<u64, MLSError> {
        unsupported()
    }

    fn clear_pending_commit(&self, _group_id: Vec<u8>) -> Result<(), MLSError> {
        Ok(())
    }

    fn get_epoch(&self, _group_id: Vec<u8>) -> Result<u64, MLSError> {
        Ok(7)
    }

    fn get_confirmation_tag(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        unsupported()
    }

    fn export_group_info(
        &self,
        _group_id: Vec<u8>,
        _signer_identity: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        unsupported()
    }

    fn encrypt_message(
        &self,
        _group_id: Vec<u8>,
        _plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        unsupported()
    }

    fn decrypt_message(
        &self,
        _group_id: Vec<u8>,
        _ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        Err(MLSError::DecryptionFailed)
    }

    fn create_external_commit(
        &self,
        _group_info: Vec<u8>,
        _identity: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        unsupported()
    }

    fn discard_pending_external_join(&self, _group_id: Vec<u8>) -> Result<(), MLSError> {
        Ok(())
    }

    fn delete_group(&self, _group_id: Vec<u8>) -> Result<(), MLSError> {
        Ok(())
    }

    fn update_group_metadata(
        &self,
        _group_id: Vec<u8>,
        _metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        unsupported()
    }

    fn process_welcome(
        &self,
        _welcome_data: Vec<u8>,
        _identity: Vec<u8>,
        _config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError> {
        unsupported()
    }

    fn propose_self_remove(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        unsupported()
    }

    fn commit_pending_proposals(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        unsupported()
    }
}

async fn setup_alice_bob_group(label: &str) -> (TestWorld, String) {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let group_id = world
        .client("Alice")
        .orchestrator
        .create_group(label, Some(&[bob_did]), None)
        .await
        .expect("Alice create_group with Bob should succeed")
        .group_id;

    (world, group_id)
}

fn epoch_for(client: &TestClient, group_id: &str) -> u64 {
    client
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(group_id).expect("valid group id hex"))
        .expect("get_epoch should succeed")
}

async fn build_recording_orchestrator(
    source: &TestClient,
    api: RecordingCommitApi,
    group_id: &str,
) -> MLSOrchestrator<MockStorage, RecordingCommitApi, MockCredentials, MLSContext> {
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(source.orchestrator.mls_context()),
        Arc::new(source.storage.clone()),
        Arc::new(api),
        Arc::new(source.credentials.clone()),
        OrchestratorConfig::default(),
    );

    orchestrator.initialize(&source.did).await.unwrap();
    source
        .storage
        .set_conversation_state(group_id, ConversationState::Active)
        .await
        .unwrap();

    let source_group_state = {
        source
            .orchestrator
            .group_states()
            .lock()
            .await
            .get(group_id)
            .cloned()
            .expect("source group state should exist")
    };
    let source_conversation = {
        source
            .orchestrator
            .conversations()
            .lock()
            .await
            .values()
            .find(|conversation| conversation.group_id == group_id)
            .cloned()
            .expect("source conversation mapping should exist")
    };

    orchestrator
        .group_states()
        .lock()
        .await
        .insert(group_id.to_string(), source_group_state);
    orchestrator.conversations().lock().await.insert(
        source_conversation.conversation_id.clone(),
        source_conversation.clone(),
    );
    orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(group_id.to_string(), ConversationState::Active);
    orchestrator.conversation_states().lock().await.insert(
        source_conversation.conversation_id.clone(),
        ConversationState::Active,
    );

    orchestrator
}

async fn trigger_fork_detection<A>(
    orchestrator: &MLSOrchestrator<MockStorage, A, MockCredentials, MLSContext>,
    group_id: &str,
    sender_did: &str,
) where
    A: MLSAPIClient + 'static,
{
    for i in 0..2 {
        let envelope = IncomingEnvelope {
            conversation_id: group_id.to_string(),
            sender_did: sender_did.to_string(),
            ciphertext: format!("not-an-mls-message-{i}").into_bytes(),
            timestamp: Utc::now(),
            server_message_id: Some(format!("bad-fork-frame-{i}")),
            server_epoch: None,
        };
        let result = orchestrator.process_incoming(&envelope).await;
        assert!(
            result.is_err(),
            "invalid ciphertext should drive decrypt failure"
        );
    }
}

#[cfg(feature = "fork-resolution")]
#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_stages_server_submit_ready_commit_without_merging_first() {
    let (world, group_id) = setup_alice_bob_group("fork-direct-staging").await;
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let source_epoch = epoch_for(alice, &group_id);

    let key_packages = alice
        .orchestrator
        .api_client()
        .get_key_packages("00000000-0000-4000-8000-000000000001", &[alice.did.clone(), bob_did])
        .await
        .expect("key packages should be available");
    assert!(
        key_packages.len() >= 2,
        "test intentionally supplies own and peer key packages"
    );

    let (commit, welcome) = MlsCryptoContext::recover_fork_by_readding(
        alice.orchestrator.mls_context().as_ref(),
        hex::decode(&group_id).expect("valid group id hex"),
        key_packages
            .into_iter()
            .map(|kp| kp.key_package_data)
            .collect(),
    )
    .expect("recover_fork_by_readding should stage a commit");

    assert!(
        !commit.is_empty(),
        "commit bytes must be server-submit-ready"
    );
    MlsMessageIn::tls_deserialize_exact(&commit[..])
        .expect("commit must be a valid MLS wire message");
    let welcome = welcome.expect("readding Bob should produce a Welcome");
    assert!(!welcome.is_empty(), "Welcome bytes must not be empty");
    Welcome::tls_deserialize_exact(&welcome[..]).expect("Welcome must be valid MLS Welcome data");

    assert_eq!(
        epoch_for(alice, &group_id),
        source_epoch,
        "recover_fork_by_readding must stage only; local epoch changes after ACK merge"
    );

    let merged_epoch = alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(hex::decode(&group_id).expect("valid group id hex"))
        .expect("explicit ACK merge should succeed");
    assert_eq!(merged_epoch.new_epoch, source_epoch + 1);
}

#[cfg(feature = "fork-resolution")]
#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_orchestrator_submits_then_merges_and_clears_state() {
    let (world, group_id) = setup_alice_bob_group("fork-orchestrator-success").await;
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let source_epoch = epoch_for(alice, &group_id);

    let api = RecordingCommitApi::new(world.api_service.clone_as(&alice.did), false);
    let api_probe = api.clone();
    let orchestrator = build_recording_orchestrator(alice, api, &group_id).await;

    trigger_fork_detection(&orchestrator, &group_id, &bob_did).await;

    let submissions = api_probe.submissions();
    assert_eq!(submissions.len(), 1, "fork recovery should submit once");
    let submitted = &submissions[0];
    assert_eq!(submitted.convo_id, group_id);
    assert_eq!(submitted.action, "forkReadd");
    assert!(
        submitted
            .confirmation_tag
            .as_deref()
            .is_some_and(|tag| !tag.is_empty()),
        "commit submission should include confirmation tag"
    );
    MlsMessageIn::tls_deserialize_exact(&submitted.commit_data[..])
        .expect("submitted commit must be valid MLS wire data");

    assert_eq!(
        epoch_for(alice, &group_id),
        source_epoch + 1,
        "orchestrator should merge locally only after commit_group_change ACK"
    );
    assert_eq!(
        orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&group_id),
        Some(&ConversationState::Active),
        "successful fork readd should clear ForkDetected state"
    );
}

#[cfg(feature = "fork-resolution")]
#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_resolves_rotated_stable_conversation_to_active_group() {
    let (world, group_id) = setup_alice_bob_group("fork-rotated-stable").await;
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let stable_conversation_id = format!("convo-{group_id}");

    world
        .delivery_service()
        .rekey_conversation_for_test(&group_id, &stable_conversation_id);
    alice
        .storage
        .ensure_conversation_exists(&alice.did, &stable_conversation_id, &group_id)
        .await
        .expect("migrate stable conversation storage row");
    alice
        .storage
        .set_conversation_state(&stable_conversation_id, ConversationState::Active)
        .await
        .expect("persist migrated stable conversation as Active");
    alice
        .storage
        .delete_conversations(&alice.did, &[&group_id])
        .await
        .expect("retire superseded stable-conversation projection");
    {
        let mut conversations = alice.orchestrator.conversations().lock().await;
        if let Some(mut migrated) = conversations.remove(&group_id) {
            migrated.conversation_id = stable_conversation_id.clone();
            conversations.insert(stable_conversation_id.clone(), migrated);
        }
    }
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh rotated stable conversation mapping");
    let source_epoch = epoch_for(alice, &group_id);

    let api = RecordingCommitApi::new(world.api_service.clone_as(&alice.did), false);
    let api_probe = api.clone();
    let orchestrator = build_recording_orchestrator(alice, api, &group_id).await;
    {
        let mut states = orchestrator.group_states().lock().await;
        let current = states.remove(&group_id).expect("current group state");
        states.insert(stable_conversation_id.clone(), current);
    }

    trigger_fork_detection(&orchestrator, &stable_conversation_id, &bob_did).await;

    let submissions = api_probe.submissions();
    assert_eq!(submissions.len(), 1, "fork recovery should submit once");
    assert_eq!(submissions[0].convo_id, stable_conversation_id);
    assert_eq!(submissions[0].action, "forkReadd");
    assert_eq!(
        orchestrator
            .mls_context()
            .get_epoch(hex::decode(&group_id).expect("active group id"))
            .expect("active group epoch"),
        source_epoch + 1,
        "fork repair must merge against the active mutable group"
    );
    {
        let states = orchestrator.group_states().lock().await;
        assert!(!states.contains_key(&stable_conversation_id));
        let current = states
            .get(&group_id)
            .expect("normalized active group state");
        assert_eq!(current.epoch, source_epoch + 1);
        assert_eq!(current.conversation_id, stable_conversation_id);
    }
    assert_eq!(
        orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&stable_conversation_id),
        Some(&ConversationState::Active)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_vote_authenticator_ignores_stale_legacy_group_state() {
    let (world, group_id) = setup_alice_bob_group("recovery-vote-active").await;
    let alice = world.client("Alice");
    let unrelated = alice
        .orchestrator
        .create_group("recovery-vote-unrelated", None, None)
        .await
        .expect("create unrelated group");
    let stable_conversation_id = uuid::Uuid::new_v4().to_string();
    world
        .delivery_service()
        .rekey_conversation_for_test(&group_id, &stable_conversation_id);
    alice
        .storage
        .ensure_conversation_exists(&alice.did, &stable_conversation_id, &group_id)
        .await
        .expect("persist authorized stable-conversation migration");
    alice
        .storage
        .set_conversation_state(&stable_conversation_id, ConversationState::Active)
        .await
        .expect("persist migrated stable conversation as Active");
    alice
        .storage
        .delete_conversations(&alice.did, &[&group_id])
        .await
        .expect("retire superseded stable-conversation projection");
    {
        let mut conversations = alice.orchestrator.conversations().lock().await;
        if let Some(mut migrated) = conversations.remove(&group_id) {
            migrated.conversation_id = stable_conversation_id.clone();
            conversations.insert(stable_conversation_id.clone(), migrated);
        }
    }
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh rotated mapping");

    let api = RecordingCommitApi::new(world.api_service.clone_as(&alice.did), false);
    let api_probe = api.clone();
    let orchestrator = build_recording_orchestrator(alice, api, &group_id).await;
    orchestrator.group_states().lock().await.insert(
        stable_conversation_id.clone(),
        GroupState {
            group_id: unrelated.group_id.clone(),
            conversation_id: stable_conversation_id.clone(),
            epoch: unrelated.epoch,
            members: vec![alice.did.clone()],
        },
    );
    let expected_authenticator = hex::encode(
        orchestrator
            .mls_context()
            .get_group_context_hash(hex::decode(&group_id).expect("active group id"))
            .expect("active epoch authenticator"),
    );

    orchestrator
        .user_confirmed_manual_reset(&stable_conversation_id)
        .await
        .expect("manual reset report");

    assert_eq!(
        api_probe.recovery_reports(),
        vec![(stable_conversation_id, Some(expected_authenticator))]
    );
}

#[cfg(feature = "fork-resolution")]
#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_does_not_merge_and_falls_to_rejoin_when_submit_fails() {
    let (world, group_id) = setup_alice_bob_group("fork-orchestrator-failure").await;
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let source_epoch = epoch_for(alice, &group_id);

    let api = RecordingCommitApi::new(world.api_service.clone_as(&alice.did), true);
    let api_probe = api.clone();
    let orchestrator = build_recording_orchestrator(alice, api, &group_id).await;

    trigger_fork_detection(&orchestrator, &group_id, &bob_did).await;

    let submissions = api_probe.submissions();
    assert_eq!(submissions.len(), 1, "fork recovery should submit once");
    MlsMessageIn::tls_deserialize_exact(&submissions[0].commit_data[..])
        .expect("failed submission still must be valid MLS wire data");
    assert_eq!(
        epoch_for(alice, &group_id),
        source_epoch,
        "failed server submit must not merge the pending fork commit"
    );
    assert_eq!(
        orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&group_id),
        Some(&ConversationState::NeedsRejoin),
        "server submit failure should fall back to NeedsRejoin"
    );
    assert!(
        alice.storage.has_rejoin_flag(&group_id),
        "NeedsRejoin fallback should be persisted"
    );
    let merge_attempt = alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(hex::decode(&group_id).expect("valid group id hex"))
        .expect("merge without pending commit should be a no-op");
    assert_eq!(
        merge_attempt.new_epoch, source_epoch,
        "failed submit should clear the staged pending commit before any later merge"
    );
    assert_eq!(epoch_for(alice, &group_id), source_epoch);
}

#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_falls_back_to_needs_rejoin_when_crypto_unsupported() {
    let user_did = "did:plc:alice";
    let group_id = hex::encode([0x41_u8; 32]);
    let storage = Arc::new(MockStorage::new());
    storage
        .ensure_conversation_exists(user_did, &group_id, &group_id)
        .await
        .unwrap();
    storage
        .set_conversation_state(&group_id, ConversationState::Active)
        .await
        .unwrap();

    let orchestrator = MLSOrchestrator::new(
        Arc::new(UnsupportedForkCrypto),
        Arc::clone(&storage),
        Arc::new(MockDeliveryService::new(user_did)),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(user_did).await.unwrap();
    orchestrator.group_states().lock().await.insert(
        group_id.clone(),
        GroupState {
            group_id: group_id.clone(),
            conversation_id: group_id.clone(),
            epoch: 7,
            members: vec!["did:plc:bob".to_string()],
        },
    );
    orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(group_id.clone(), ConversationState::Active);

    for i in 0..2 {
        let envelope = IncomingEnvelope {
            conversation_id: group_id.clone(),
            sender_did: "did:plc:bob".to_string(),
            ciphertext: format!("unsupported-fork-{i}").into_bytes(),
            timestamp: Utc::now(),
            server_message_id: Some(format!("unsupported-fork-{i}")),
            server_epoch: None,
        };
        let result = orchestrator.process_incoming(&envelope).await;
        assert!(result.is_err(), "fake crypto always fails decryption");
    }
    assert_eq!(
        orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&group_id),
        Some(&ConversationState::NeedsRejoin),
        "unsupported crypto falls back from fork readd to NeedsRejoin"
    );
}
