#![allow(dead_code)]

mod e2e_harness;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use catbird_mls::engine::{EngineLifecycle, MlsEngine};
use catbird_mls::orchestrator::{
    MLSOrchestrator, MLSStorageBackend, OrchestratorConfig, PersistedRecoveryBackoff,
};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use e2e_harness::mock_api_client::MockDeliveryService;
use e2e_harness::mock_credentials::MockCredentials;
use e2e_harness::mock_storage::MockStorage;

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

struct InMemoryKeychain {
    store: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl InMemoryKeychain {
    fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl KeychainAccess for InMemoryKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        let map = self.store.lock().unwrap();
        Ok(map.get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        let mut map = self.store.lock().unwrap();
        map.insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        let mut map = self.store.lock().unwrap();
        map.remove(&key);
        Ok(())
    }
}

type TestOrchestrator =
    MLSOrchestrator<MockStorage, MockDeliveryService, MockCredentials, MLSContext>;
type TestEngine = MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext>;

struct TestClientHarness {
    did: String,
    storage: Arc<MockStorage>,
    api: Arc<MockDeliveryService>,
    credentials: Arc<MockCredentials>,
    orchestrator: TestOrchestrator,
    engine: TestEngine,
    _temp_dir: PathBuf,
}

impl TestClientHarness {
    async fn new(name: &str, shared_server: &MockDeliveryService) -> Self {
        let did = format!("did:plc:{name}");
        let seq = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!(
            "catbird_mls_full_rust_recovery_{}_{}_{}_{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            seq,
        ));
        std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");
        let db_path = temp_dir.join("mls.db");

        let context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            format!("test-key-{name}"),
            Box::new(InMemoryKeychain::new()),
        )
        .expect("failed to create MLSContext");
        let storage = Arc::new(MockStorage::new());
        let credentials = Arc::new(MockCredentials::new());
        let api = Arc::new(shared_server.clone_as(&did));
        let config = OrchestratorConfig::default();

        let orchestrator = MLSOrchestrator::new(
            Arc::clone(&context),
            Arc::clone(&storage),
            Arc::clone(&api),
            Arc::clone(&credentials),
            config.clone(),
        );
        let engine = MlsEngine::new(
            context,
            Arc::clone(&storage),
            Arc::clone(&api),
            Arc::clone(&credentials),
            Arc::new(EngineLifecycle::default()),
            config,
        );

        Self {
            did,
            storage,
            api,
            credentials,
            orchestrator,
            engine,
            _temp_dir: temp_dir,
        }
    }

    async fn initialize(&self) {
        self.orchestrator
            .initialize(&self.did)
            .await
            .expect("orchestrator initialize failed");
        self.engine
            .initialize_user(&self.did)
            .expect("engine initialize_user failed");
        self.orchestrator
            .ensure_device_registered()
            .await
            .expect("ensure_device_registered failed");
    }
}

impl Drop for TestClientHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._temp_dir);
    }
}

struct RecoverySchedulerFixture {
    convo_id: String,
    alice: TestClientHarness,
}

impl RecoverySchedulerFixture {
    async fn with_missing_local_group_and_available_welcome() -> Self {
        let shared_server = MockDeliveryService::new("did:plc:bootstrap");
        let alice = TestClientHarness::new("alice", &shared_server).await;
        let bob = TestClientHarness::new("bob", &shared_server).await;

        alice.initialize().await;
        bob.initialize().await;

        let convo = bob
            .orchestrator
            .create_group(
                "Deferred recovery fixture",
                Some(&[alice.did.clone()]),
                None,
            )
            .await
            .expect("create_group failed");

        alice
            .storage
            .ensure_conversation_exists(&alice.did, &convo.conversation_id, &convo.group_id)
            .await
            .expect("ensure_conversation_exists failed");
        alice
            .storage
            .mark_needs_rejoin(&convo.conversation_id)
            .await
            .expect("mark_needs_rejoin failed");

        Self {
            convo_id: convo.conversation_id,
            alice,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deferred_recovery_uses_welcome_first_and_avoids_external_commit() {
    let fixture = RecoverySchedulerFixture::with_missing_local_group_and_available_welcome().await;

    let report = fixture
        .alice
        .engine
        .run_deferred_recovery("test")
        .expect("run_deferred_recovery should succeed");

    assert_eq!(report.attempted, 1);
    assert_eq!(report.recovered, 1);
    assert_eq!(
        fixture.alice.api.welcome_fetch_count(&fixture.convo_id),
        1,
        "deferred recovery must fetch Welcome before considering External Commit"
    );
    assert_eq!(
        fixture.alice.api.external_commit_count(&fixture.convo_id),
        0,
        "deferred recovery must not fall back to External Commit when Welcome succeeds"
    );
    assert!(
        !fixture.alice.storage.has_rejoin_flag(&fixture.convo_id),
        "successful Rust-owned deferred recovery should clear the persisted rejoin flag"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_wipe_local_group_preserves_conversation_and_marks_rejoin() {
    let shared_server = MockDeliveryService::new("did:plc:bootstrap");
    let alice = TestClientHarness::new("alice-debug-wipe", &shared_server).await;
    alice.initialize().await;

    let created = alice
        .engine
        .create_conversation(catbird_mls::CreateConversationRequest {
            name: "Debug wipe fixture".to_string(),
            member_dids: vec![],
            description: None,
        })
        .expect("create conversation");
    let conversation_id = created.conversation.conversation_id.clone();
    let group_id = created.conversation.group_id.clone();
    let group_id_bytes = hex::decode(&group_id).expect("group id should be hex");

    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id_bytes.clone())
            .is_ok(),
        "created fixture should have local OpenMLS group state before debug wipe"
    );

    let result = alice
        .engine
        .debug_wipe_local_group_for_recovery(&conversation_id)
        .expect("debug wipe should succeed");

    assert_eq!(result.conversation_id, conversation_id);
    assert_eq!(result.group_id, Some(group_id.clone()));
    assert!(
        result.deleted_local_group,
        "debug wipe should report that local OpenMLS group state was removed"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &conversation_id)
            .await
            .unwrap()
            .is_some(),
        "debug wipe must preserve the conversation projection so recovery can still find it"
    );
    assert!(
        alice.storage.has_rejoin_flag(&conversation_id),
        "debug wipe must mark needs_rejoin so Rust deferred recovery owns the repair"
    );
    assert!(
        matches!(
            alice.orchestrator.mls_context().get_epoch(group_id_bytes),
            Err(MLSError::GroupNotFound { .. })
        ),
        "debug wipe must delete local OpenMLS group state through Rust"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deferred_recovery_respects_success_cooldown() {
    let fixture = RecoverySchedulerFixture::with_missing_local_group_and_available_welcome().await;

    let first = fixture
        .alice
        .engine
        .run_deferred_recovery("initial-pass")
        .expect("initial deferred recovery should succeed");
    assert_eq!(first.recovered, 1);

    fixture
        .alice
        .storage
        .mark_needs_rejoin(&fixture.convo_id)
        .await
        .expect("mark_needs_rejoin should re-arm the queue for the cooldown test");

    let second = fixture
        .alice
        .engine
        .run_deferred_recovery("cooldown-pass")
        .expect("cooldown-gated deferred recovery should still return a report");

    assert_eq!(second.attempted, 0);
    assert_eq!(second.skipped, 1);
    assert_eq!(
        fixture.alice.api.welcome_fetch_count(&fixture.convo_id),
        1,
        "success cooldown must skip the second pass before another Welcome fetch"
    );
    assert_eq!(
        fixture.alice.api.external_commit_count(&fixture.convo_id),
        0,
        "success cooldown must skip the second pass before any External Commit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deferred_recovery_honors_hydrated_max_attempt_lockout() {
    let shared_server = MockDeliveryService::new("did:plc:bootstrap");
    let alice = TestClientHarness::new("alice-lockout", &shared_server).await;
    alice
        .storage
        .ensure_conversation_exists(
            &alice.did,
            "convo-locked-out",
            "00112233445566778899aabbccddeeff",
        )
        .await
        .expect("ensure_conversation_exists failed");
    alice
        .storage
        .mark_needs_rejoin("convo-locked-out")
        .await
        .expect("mark_needs_rejoin failed");

    let now_ms = chrono::Utc::now().timestamp_millis();
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "convo-locked-out".to_string(),
            failed_rejoin_count: OrchestratorConfig::default().max_rejoin_attempts,
            last_attempt_at_ms: now_ms,
            quarantined_until_ms: Some(
                now_ms
                    + catbird_mls::orchestrator::constants::RECOVERY_BACKOFF_TTL.as_millis() as i64,
            ),
        });

    alice.initialize().await;

    let report = alice
        .engine
        .run_deferred_recovery("hydrated-lockout")
        .expect("lockout-gated deferred recovery should return a report");

    assert_eq!(report.attempted, 0);
    assert_eq!(report.skipped, 1);
    assert_eq!(
        alice.api.welcome_fetch_count("convo-locked-out"),
        0,
        "hydrated lockout must skip before any Welcome fetch"
    );
    assert_eq!(
        alice.api.external_commit_count("convo-locked-out"),
        0,
        "hydrated lockout must skip before any External Commit"
    );
}
