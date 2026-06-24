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
