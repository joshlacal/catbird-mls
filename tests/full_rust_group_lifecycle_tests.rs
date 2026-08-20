#![allow(dead_code)]

mod e2e_harness;
#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use catbird_mls::orchestrator::{MLSAPIClient, MLSStorageBackend, OrchestratorConfig};
use catbird_mls::{
    CreateConversationRequest, EngineLifecycle, GroupMutationResult, KeychainAccess, LeaveResult,
    MLSContext, MLSError, MlsEngine,
};
use e2e_harness::mock_api_client::MockDeliveryService;
use e2e_harness::mock_credentials::MockCredentials;
use e2e_harness::mock_storage::MockStorage;
use e2e_harness::TestWorld;

struct InMemoryKeychain {
    store: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryKeychain {
    fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl KeychainAccess for InMemoryKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.store.lock().unwrap().get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.store.lock().unwrap().insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.store.lock().unwrap().remove(&key);
        Ok(())
    }
}

struct GroupLifecycleFixture {
    engine: MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext>,
    storage: Arc<MockStorage>,
    api: Arc<MockDeliveryService>,
    _temp_dir: tempfile::TempDir,
}

impl GroupLifecycleFixture {
    async fn with_one_recipient_key_package() -> Self {
        let mut world = TestWorld::new();
        world.add_client("Bob").await;
        let bob_did = world
            .register_device("Bob")
            .await
            .expect("register bob device");

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("mls.db");
        let context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "test-key".to_string(),
            Box::new(InMemoryKeychain::new()),
        )
        .expect("MLSContext");
        epoch_secret_test_support::install(&context);
        let storage = Arc::new(MockStorage::new());
        let api = Arc::new(world.delivery_service().clone_as("did:plc:alice"));
        let credentials = Arc::new(MockCredentials::new());
        world.install_authorized_device_keys(&credentials, &bob_did);
        let config = OrchestratorConfig::default();

        let engine = MlsEngine::new(
            context,
            Arc::clone(&storage),
            Arc::clone(&api),
            credentials,
            Arc::new(EngineLifecycle::default()),
            config,
        );
        engine
            .initialize_user("did:plc:alice")
            .expect("engine initialize");

        Self {
            engine,
            storage,
            api,
            _temp_dir: temp_dir,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn add_remove_resolve_stable_conversation_id_to_current_group_id() {
    let fixture = GroupLifecycleFixture::with_one_recipient_key_package().await;

    let created = fixture
        .engine
        .create_conversation(CreateConversationRequest {
            name: "rotated".into(),
            member_dids: vec![],
            description: None,
        })
        .expect("create conversation");
    let original_group_id = created.conversation.group_id.clone();
    let stable_convo_id = "00000000-0000-4000-8000-000000000001";

    fixture
        .api
        .rekey_conversation_for_test(&created.conversation.conversation_id, stable_convo_id);
    fixture
        .storage
        .ensure_conversation_exists("did:plc:alice", stable_convo_id, &original_group_id)
        .await
        .expect("seed stable conversation mapping");

    let added: GroupMutationResult = fixture
        .engine
        .add_members(stable_convo_id, &["did:plc:bob".into()])
        .expect("add members through stable conversation id");
    assert_eq!(added.conversation.conversation_id, stable_convo_id);
    assert_eq!(added.conversation.group_id, original_group_id);
    assert!(added
        .conversation
        .members
        .iter()
        .any(|member| member.did == "did:plc:bob"));

    let removed: GroupMutationResult = fixture
        .engine
        .remove_members(stable_convo_id, &["did:plc:bob".into()])
        .expect("remove members through stable conversation id");
    assert_eq!(removed.conversation.conversation_id, stable_convo_id);
    assert_eq!(removed.conversation.group_id, original_group_id);
    assert!(!removed
        .conversation
        .members
        .iter()
        .any(|member| member.did == "did:plc:bob"));
    assert!(
        fixture.api.get_group_info(stable_convo_id).await.is_ok(),
        "post-mutation GroupInfo must stay published under the stable conversation id"
    );
    assert!(
        fixture
            .api
            .get_group_info(&original_group_id)
            .await
            .is_err(),
        "post-mutation GroupInfo must not be republished under the raw MLS group id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_conversation_publishes_group_info_and_confirms_commit_atomically() {
    let fixture = GroupLifecycleFixture::with_one_recipient_key_package().await;

    let result = fixture
        .engine
        .create_conversation(CreateConversationRequest {
            name: "test".into(),
            member_dids: vec!["did:plc:bob".into()],
            description: None,
        })
        .expect("create conversation");

    assert_eq!(result.conversation.epoch, 0);
    assert_eq!(
        fixture
            .api
            .conversation_epoch(&result.conversation.conversation_id),
        Some(0)
    );
    let group_info = fixture
        .api
        .get_group_info(&result.conversation.conversation_id)
        .await
        .expect("group info published");
    assert!(!group_info.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn add_remove_and_leave_return_updated_snapshots() {
    let fixture = GroupLifecycleFixture::with_one_recipient_key_package().await;

    let created = fixture
        .engine
        .create_conversation(CreateConversationRequest {
            name: "test".into(),
            member_dids: vec![],
            description: None,
        })
        .expect("create conversation");
    let convo_id = created.conversation.conversation_id.clone();

    let added: GroupMutationResult = fixture
        .engine
        .add_members(&convo_id, &["did:plc:bob".into()])
        .expect("add members");
    assert!(added.conversation.epoch > created.conversation.epoch);
    assert!(added
        .conversation
        .members
        .iter()
        .any(|member| member.did == "did:plc:bob"));

    let removed: GroupMutationResult = fixture
        .engine
        .remove_members(&convo_id, &["did:plc:bob".into()])
        .expect("remove members");
    assert!(removed.conversation.epoch > added.conversation.epoch);
    assert!(!removed
        .conversation
        .members
        .iter()
        .any(|member| member.did == "did:plc:bob"));

    let left: LeaveResult = fixture
        .engine
        .leave_conversation(&convo_id)
        .expect("leave conversation");
    assert_eq!(left.conversation_id, convo_id);
    assert!(left.group_id.is_some());
    assert_eq!(
        fixture.api.members_of(&left.conversation_id),
        Vec::<String>::new()
    );
}
