#![allow(dead_code)]

#[path = "mock_api_client.rs"]
mod mock_api_client;
#[path = "mock_credentials.rs"]
mod mock_credentials;
#[path = "mock_storage.rs"]
mod mock_storage;

use std::collections::HashMap;
use std::sync::Arc;

use catbird_mls::orchestrator::{ConversationState, MLSStorageBackend, OrchestratorConfig};
use catbird_mls::{EngineLifecycle, KeychainAccess, MLSContext, MLSError, MlsEngine};

use mock_api_client::MockDeliveryService;
use mock_credentials::MockCredentials;
use mock_storage::MockStorage;

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

#[async_trait::async_trait]
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

struct StartupReconcileFixture {
    did: &'static str,
    context: Arc<MLSContext>,
    storage: Arc<MockStorage>,
    engine: MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext>,
    _temp_dir: tempfile::TempDir,
}

impl StartupReconcileFixture {
    fn new() -> Self {
        let did = "did:plc:test";
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("mls.db");

        let context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "test-key".to_string(),
            Box::new(InMemoryKeychain::new()),
        )
        .expect("MLSContext");
        let storage = Arc::new(MockStorage::new());
        let api = Arc::new(MockDeliveryService::new(did));
        let credentials = Arc::new(MockCredentials::new());
        let engine = MlsEngine::new(
            Arc::clone(&context),
            Arc::clone(&storage),
            api,
            credentials,
            Arc::new(EngineLifecycle::default()),
            OrchestratorConfig::default(),
        );

        Self {
            did,
            context,
            storage,
            engine,
            _temp_dir: temp_dir,
        }
    }

    async fn persist_local_group(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Vec<u8> {
        let created = self
            .context
            .create_group(self.did.as_bytes().to_vec(), None)
            .expect("create_group");
        let group_id_hex = hex::encode(&created.group_id);
        self.storage
            .ensure_conversation_exists(self.did, conversation_id, &group_id_hex)
            .await
            .expect("ensure_conversation_exists");
        self.storage
            .set_conversation_state(conversation_id, state)
            .await
            .expect("set_conversation_state");
        created.group_id
    }

    async fn persist_missing_group(
        &self,
        conversation_id: &str,
        state: ConversationState,
        group_id_hex: &str,
    ) {
        self.storage
            .ensure_conversation_exists(self.did, conversation_id, group_id_hex)
            .await
            .expect("ensure_conversation_exists");
        self.storage
            .set_conversation_state(conversation_id, state)
            .await
            .expect("set_conversation_state");
    }
}

fn random_group_id_hex() -> String {
    format!("{:032x}", uuid::Uuid::new_v4().as_u128())
}

#[tokio::test(flavor = "multi_thread")]
async fn initialize_fails_closed_on_malformed_persisted_security_state() {
    let fixture = StartupReconcileFixture::new();
    fixture
        .persist_missing_group(
            "convo-malformed",
            ConversationState::Active,
            &random_group_id_hex(),
        )
        .await;
    fixture.storage.fail_next_get_conversation_state();

    let error = fixture
        .engine
        .initialize_user(fixture.did)
        .expect_err("malformed reset/quarantine state must abort initialization");

    assert!(
        error
            .to_string()
            .contains("malformed persisted reset/quarantine sidecar"),
        "initialization must expose the malformed security state: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_reconcile_marks_missing_groups_for_rejoin_without_deleting_healthy_groups() {
    let fixture = StartupReconcileFixture::new();
    let healthy_group_id = fixture
        .persist_local_group("convo-healthy", ConversationState::Active)
        .await;
    fixture
        .persist_missing_group(
            "convo-missing",
            ConversationState::Active,
            &random_group_id_hex(),
        )
        .await;

    fixture
        .engine
        .initialize_user(fixture.did)
        .expect("initialize_user");

    let report = fixture
        .engine
        .startup_reconcile()
        .expect("startup_reconcile");

    assert_eq!(report.scanned, 2);
    assert_eq!(report.healthy, 1);
    assert_eq!(report.needs_rejoin, 1);
    assert_eq!(report.reset_pending, 0);
    assert_eq!(report.unrecoverable_local, 0);

    assert!(
        fixture.storage.has_rejoin_flag("convo-missing"),
        "missing local group must be flagged for deferred recovery"
    );
    assert_eq!(
        fixture.storage.get_current_state("convo-missing"),
        Some(ConversationState::NeedsRejoin),
        "missing local group should project into NeedsRejoin state"
    );
    assert!(
        fixture.context.get_epoch(healthy_group_id).is_ok(),
        "startup reconcile must not delete unrelated healthy local groups"
    );
    assert!(
        !fixture.storage.has_rejoin_flag("convo-healthy"),
        "healthy local group must stay unflagged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_reconcile_preserves_reset_pending_and_unrecoverable_states_in_report() {
    let fixture = StartupReconcileFixture::new();
    fixture
        .persist_missing_group(
            "convo-reset",
            ConversationState::Active,
            &random_group_id_hex(),
        )
        .await;
    fixture
        .storage
        .mark_reset_pending("convo-reset", &random_group_id_hex(), 7, 1_717_000_000_000)
        .await
        .expect("mark_reset_pending");
    fixture
        .persist_missing_group(
            "convo-failed",
            ConversationState::Failed,
            &random_group_id_hex(),
        )
        .await;

    fixture
        .engine
        .initialize_user(fixture.did)
        .expect("initialize_user");

    let report = fixture
        .engine
        .startup_reconcile()
        .expect("startup_reconcile");

    assert_eq!(report.scanned, 2);
    assert_eq!(report.healthy, 0);
    assert_eq!(report.needs_rejoin, 0);
    assert_eq!(report.reset_pending, 1);
    assert_eq!(report.unrecoverable_local, 1);

    let persisted_reset = fixture
        .storage
        .get_persisted_reset_pending("convo-reset")
        .expect("reset_pending payload should survive startup reconcile");
    assert_eq!(persisted_reset.reset_generation, 7);
    assert_eq!(persisted_reset.notified_at_ms, 1_717_000_000_000);
    assert!(
        !fixture.storage.has_rejoin_flag("convo-failed"),
        "unrecoverable conversations must not be re-flagged as needs_rejoin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_reconcile_does_not_mark_rejoin_when_local_epoch_probe_returns_context_closed() {
    let fixture = StartupReconcileFixture::new();
    fixture
        .persist_local_group("convo-context-closed", ConversationState::Active)
        .await;

    fixture
        .engine
        .initialize_user(fixture.did)
        .expect("initialize_user");
    fixture
        .context
        .flush_and_prepare_close()
        .expect("flush_and_prepare_close");

    let report = fixture
        .engine
        .startup_reconcile()
        .expect("startup_reconcile");

    assert_eq!(report.scanned, 1);
    assert_eq!(report.healthy, 0);
    assert_eq!(report.needs_rejoin, 0);
    assert_eq!(report.reset_pending, 0);
    assert_eq!(report.unrecoverable_local, 0);
    assert!(
        !fixture.storage.has_rejoin_flag("convo-context-closed"),
        "context lifecycle errors must not be reclassified as missing local groups"
    );
    assert_eq!(
        fixture.storage.get_current_state("convo-context-closed"),
        Some(ConversationState::Active),
        "startup reconcile must preserve the existing persisted state on context errors"
    );
}
