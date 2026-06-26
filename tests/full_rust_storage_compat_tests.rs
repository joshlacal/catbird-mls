#![allow(dead_code)]

#[path = "mock_api_client.rs"]
mod mock_api_client;
#[path = "mock_credentials.rs"]
mod mock_credentials;
#[path = "mock_storage.rs"]
mod mock_storage;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use catbird_mls::orchestrator::{ConversationRecoveryState, OrchestratorConfig};
use catbird_mls::{
    CreateConversationRequest, EngineLifecycle, KeychainAccess, MLSContext, MLSError, MlsEngine,
    StorageLifecycleState,
};

use mock_api_client::MockDeliveryService;
use mock_credentials::MockCredentials;
use mock_storage::{MockStorage, StorageProjectionCounts};

#[derive(Clone, Default)]
struct SharedKeychain {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[async_trait::async_trait]
impl KeychainAccess for SharedKeychain {
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

struct StorageCompatFixture {
    did: &'static str,
    db_path: String,
    keychain: SharedKeychain,
    storage: Arc<MockStorage>,
    api: Arc<MockDeliveryService>,
    credentials: Arc<MockCredentials>,
    _temp_dir: tempfile::TempDir,
}

impl StorageCompatFixture {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("mls.db").to_string_lossy().to_string();
        Self {
            did: "did:plc:alice",
            db_path,
            keychain: SharedKeychain::default(),
            storage: Arc::new(MockStorage::new()),
            api: Arc::new(MockDeliveryService::new("did:plc:alice")),
            credentials: Arc::new(MockCredentials::new()),
            _temp_dir: temp_dir,
        }
    }

    fn context(&self) -> Arc<MLSContext> {
        MLSContext::new(
            self.db_path.clone(),
            "test-key".to_string(),
            Box::new(self.keychain.clone()),
        )
        .expect("MLSContext")
    }

    fn engine(&self) -> MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext> {
        MlsEngine::new(
            self.context(),
            Arc::clone(&self.storage),
            Arc::clone(&self.api),
            Arc::clone(&self.credentials),
            Arc::new(EngineLifecycle::default()),
            OrchestratorConfig::default(),
        )
    }
}

#[test]
fn openmls_sqlite_state_round_trips_under_rust_engine_storage() {
    let fixture = StorageCompatFixture::new();
    let (conversation_id, group_id, epoch_before_close) = {
        let engine = fixture.engine();
        engine.initialize_user(fixture.did).expect("initialize");
        let created = engine
            .create_conversation(CreateConversationRequest {
                name: "storage-owned-by-rust".into(),
                member_dids: vec![],
                description: None,
            })
            .expect("create conversation");

        let ready = engine
            .ensure_conversation_ready(&created.conversation.conversation_id)
            .expect("created group should be ready");
        assert_eq!(ready.recovery_state, ConversationRecoveryState::Healthy);
        let epoch_before_close = ready.epoch.expect("created OpenMLS epoch");

        let projection_counts = fixture.storage.storage_projection_counts();
        assert_eq!(
            projection_counts,
            StorageProjectionCounts {
                conversations: 1,
                group_states: 1,
                messages: 0,
            },
            "platform storage should only receive app projection rows, not OpenMLS crypto rows"
        );

        engine
            .emergency_close("storage compatibility restart")
            .expect("close first engine");

        (
            created.conversation.conversation_id,
            created.conversation.group_id,
            epoch_before_close,
        )
    };

    let reopened = fixture.engine();
    reopened
        .initialize_user(fixture.did)
        .expect("initialize reopened engine");

    let ready = reopened
        .ensure_conversation_ready(&conversation_id)
        .expect("reopened group should be ready");
    assert_eq!(ready.recovery_state, ConversationRecoveryState::Healthy);
    assert_eq!(
        ready.epoch,
        Some(epoch_before_close),
        "OpenMLS epoch should be loaded from the Rust-owned SQLite database"
    );
    assert_eq!(
        fixture.storage.storage_projection_counts(),
        StorageProjectionCounts {
            conversations: 1,
            group_states: 1,
            messages: 0,
        },
        "reopening the Rust context must not synthesize OpenMLS rows through platform storage"
    );
    assert!(
        !group_id.is_empty(),
        "conversation projection keeps only the stable app-facing group id"
    );
}

#[test]
fn storage_lifecycle_status_reports_suspend_interrupt_and_close() {
    let fixture = StorageCompatFixture::new();
    let engine = fixture.engine();

    engine.initialize_user(fixture.did).expect("initialize");
    let initial = engine.storage_lifecycle_status();
    assert_eq!(initial.state, StorageLifecycleState::Open);
    assert_eq!(initial.last_operation_label.as_deref(), Some("initialized"));
    assert_eq!(initial.interruptible_contexts, 2);

    let interrupted = engine
        .interrupt_storage("unit-test interrupt")
        .expect("interrupt storage");
    assert_eq!(interrupted, 2);
    let after_interrupt = engine.storage_lifecycle_status();
    assert_eq!(after_interrupt.state, StorageLifecycleState::Open);
    assert_eq!(
        after_interrupt.last_operation_label.as_deref(),
        Some("interrupt: unit-test interrupt")
    );

    engine
        .prepare_for_suspend("unit-test suspend", Duration::from_millis(250))
        .expect("prepare suspend");
    let suspended = engine.storage_lifecycle_status();
    assert_eq!(suspended.state, StorageLifecycleState::Suspended);
    assert_eq!(
        suspended.last_operation_label.as_deref(),
        Some("prepare_for_suspend: unit-test suspend")
    );

    engine
        .emergency_close("unit-test close")
        .expect("emergency close");
    let closed = engine.storage_lifecycle_status();
    assert_eq!(closed.state, StorageLifecycleState::Closed);
    assert_eq!(
        closed.last_operation_label.as_deref(),
        Some("emergency_close: unit-test close")
    );
}
