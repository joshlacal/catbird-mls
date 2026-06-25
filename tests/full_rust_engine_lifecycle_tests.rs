#![allow(dead_code)]

#[path = "mock_api_client.rs"]
mod mock_api_client;
#[path = "mock_credentials.rs"]
mod mock_credentials;
#[path = "mock_storage.rs"]
mod mock_storage;

use std::collections::HashMap;
use std::sync::Arc;

use catbird_mls::orchestrator::OrchestratorConfig;
use catbird_mls::{
    EngineLifecycle, KeychainAccess, MLSContext, MLSError, MlsEngine, ShutdownReason,
};

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

struct FullRustEngineFixture {
    engine: MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext>,
    _temp_dir: tempfile::TempDir,
}

impl FullRustEngineFixture {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("mls.db");

        let context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            "test-key".to_string(),
            Box::new(InMemoryKeychain::new()),
        )
        .expect("MLSContext");

        let engine = MlsEngine::new(
            context,
            Arc::new(MockStorage::new()),
            Arc::new(MockDeliveryService::new("did:plc:test")),
            Arc::new(MockCredentials::new()),
            Arc::new(EngineLifecycle::default()),
            OrchestratorConfig::default(),
        );

        Self {
            engine,
            _temp_dir: temp_dir,
        }
    }

    fn engine(&self) -> &MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext> {
        &self.engine
    }
}

#[test]
fn engine_initialize_and_shutdown_are_idempotent() {
    let fixture = FullRustEngineFixture::new();
    let engine = fixture.engine();

    engine.initialize_user("did:plc:test").expect("initialize");
    engine
        .initialize_user("did:plc:test")
        .expect("second initialize is no-op");
    engine
        .shutdown(ShutdownReason::AppSuspend)
        .expect("shutdown");
    engine
        .shutdown(ShutdownReason::AppSuspend)
        .expect("second shutdown is no-op");
}

#[test]
fn engine_sync_tracks_lifecycle_transitions() {
    let fixture = FullRustEngineFixture::new();
    let engine = fixture.engine();

    let before_init = engine.sync(false).expect("sync before init");
    assert_eq!(
        before_init.performed_sync, false,
        "sync should be a no-op before initialization"
    );

    engine.initialize_user("did:plc:test").expect("initialize");
    let after_init = engine.sync(false).expect("sync after init");
    assert_eq!(
        after_init.performed_sync, true,
        "sync should run once the engine is initialized"
    );

    engine
        .shutdown(ShutdownReason::AppSuspend)
        .expect("shutdown to suspended");
    let after_suspend = engine.sync(false).expect("sync after suspend");
    assert_eq!(
        after_suspend.performed_sync, false,
        "sync should be skipped while suspended"
    );
}

#[test]
fn engine_reinitializes_after_mixed_shutdown_reasons() {
    let fixture = FullRustEngineFixture::new();
    let engine = fixture.engine();

    engine.initialize_user("did:plc:test").expect("initialize");
    engine
        .shutdown(ShutdownReason::AppSuspend)
        .expect("suspend shutdown");
    engine
        .initialize_user("did:plc:test")
        .expect("reinitialize after suspend");
    engine
        .shutdown(ShutdownReason::ProcessExit)
        .expect("process exit shutdown");
    engine
        .initialize_user("did:plc:test")
        .expect("reinitialize after process exit");

    let sync_result = engine.sync(true).expect("full sync after mixed shutdowns");
    assert_eq!(
        sync_result,
        catbird_mls::EngineSyncResult {
            full_sync: true,
            performed_sync: true,
        }
    );
}

#[test]
fn prepare_for_suspend_blocks_new_work_and_interrupts_storage() {
    let fixture = FullRustEngineFixture::new();
    let engine = fixture.engine();

    engine.initialize_user("did:plc:test").expect("initialize");
    let result = engine
        .prepare_for_suspend("unit-test", std::time::Duration::from_millis(250))
        .expect("prepare for suspend");

    assert_eq!(
        result.accepting_new_work, false,
        "engine should reject new work once suspension starts"
    );
    assert!(
        result.interrupted_contexts >= 1,
        "suspension should interrupt at least one SQLCipher context"
    );
    assert!(
        engine.is_suspended(),
        "engine should report suspended state"
    );

    let sync_while_suspended = engine.sync(false).expect("sync while suspended");
    assert_eq!(
        sync_while_suspended.performed_sync, false,
        "post-suspend work must stay gated until resume"
    );
}

#[test]
fn resume_from_suspend_restores_initialized_phase_without_replaying_startup() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("mls.db");
    let context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        "test-key".to_string(),
        Box::new(InMemoryKeychain::new()),
    )
    .expect("MLSContext");
    let storage = Arc::new(MockStorage::new());
    let api = Arc::new(MockDeliveryService::new("did:plc:test"));
    let credentials = Arc::new(MockCredentials::new());
    let engine = MlsEngine::new(
        context,
        Arc::clone(&storage),
        api,
        credentials,
        Arc::new(EngineLifecycle::default()),
        OrchestratorConfig::default(),
    );

    engine.initialize_user("did:plc:test").expect("initialize");
    let startup_probes_before_suspend = storage.startup_probe_counts();

    engine
        .prepare_for_suspend("unit-test", std::time::Duration::from_millis(250))
        .expect("prepare for suspend");
    engine
        .resume_from_suspend("unit-test")
        .expect("resume from suspend");

    assert_eq!(
        storage.startup_probe_counts(),
        startup_probes_before_suspend,
        "resume must not rerun initialize-time hydration or recovery probes"
    );

    let sync_after_resume = engine.sync(false).expect("sync after resume");
    assert_eq!(
        sync_after_resume.performed_sync, true,
        "resume should restore initialized engine state"
    );
}

#[test]
fn emergency_close_requires_fresh_initialize_before_resume() {
    let fixture = FullRustEngineFixture::new();
    let engine = fixture.engine();

    engine.initialize_user("did:plc:test").expect("initialize");
    engine
        .emergency_close("unit-test")
        .expect("emergency close");

    let resume_error = engine
        .resume_from_suspend("unit-test")
        .expect_err("resume should fail after emergency close");
    assert!(
        matches!(
            resume_error,
            catbird_mls::orchestrator::OrchestratorError::NotAuthenticated
        ),
        "expected NotAuthenticated after emergency close, got {resume_error:?}"
    );

    let sync_after_emergency_close = engine.sync(false).expect("sync after emergency close");
    assert_eq!(
        sync_after_emergency_close.performed_sync, false,
        "shutdown engine must keep work gated until a fresh initialize"
    );
}
