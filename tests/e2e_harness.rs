//! E2E test harness for multi-client MLS orchestrator testing.
//!
//! Wires together multiple `MLSOrchestrator` instances with shared mock backends,
//! simulating multiple clients communicating through a shared delivery service.

#![allow(dead_code)]

#[path = "mock_api_client.rs"]
pub mod mock_api_client;
#[path = "mock_credentials.rs"]
pub mod mock_credentials;
#[path = "mock_storage.rs"]
pub mod mock_storage;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use catbird_mls::orchestrator::{MLSOrchestrator, OrchestratorConfig};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};

/// Global counter to ensure unique temp dirs across concurrent tests.
static GLOBAL_COUNTER: AtomicU32 = AtomicU32::new(0);

use mock_api_client::MockDeliveryService;
use mock_credentials::MockCredentials;
use mock_storage::MockStorage;

// ---------------------------------------------------------------------------
// In-memory keychain for tests (no iOS Keychain available)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// TestClient — a simulated MLS client
// ---------------------------------------------------------------------------

/// A simulated MLS client with its own orchestrator, context, storage, and credentials.
pub struct TestClient {
    pub name: String,
    pub did: String,
    pub orchestrator: MLSOrchestrator<MockStorage, MockDeliveryService, MockCredentials>,
    pub storage: MockStorage,
    pub credentials: MockCredentials,
    /// Temp directory holding this client's MLS database; cleaned up on drop.
    pub _temp_dir: std::path::PathBuf,
}

impl Drop for TestClient {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._temp_dir);
    }
}

// ---------------------------------------------------------------------------
// TestWorld — manages multiple clients sharing a mock server
// ---------------------------------------------------------------------------

/// The test world — manages multiple clients sharing a mock delivery service.
pub struct TestWorld {
    pub api_service: MockDeliveryService,
    pub clients: HashMap<String, TestClient>,
}

impl TestWorld {
    /// Create a new test world with a shared mock delivery service.
    pub fn new() -> Self {
        // Bootstrap with a placeholder DID; each client gets its own view via clone_as.
        let api_service = MockDeliveryService::new("did:plc:bootstrap");
        Self {
            api_service,
            clients: HashMap::new(),
        }
    }

    /// Add a new client (creates orchestrator, storage, credentials, and MLS context).
    pub async fn add_client(&mut self, name: &str) -> &TestClient {
        let did = format!("did:plc:{}", name.to_lowercase());
        let seq = GLOBAL_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Per-client temp directory for SQLite storage
        let temp_dir = std::env::temp_dir().join(format!(
            "catbird_mls_e2e_{}_{}_{}_{}",
            name.to_lowercase(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            seq,
        ));
        std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

        let db_path = temp_dir.join("mls.db");

        // Each client gets its own keychain, storage, and credentials
        let keychain = Box::new(InMemoryKeychain::new());
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            format!("test-key-{}", name),
            keychain,
        )
        .expect("failed to create MLSContext");

        let storage = MockStorage::new();
        let credentials = MockCredentials::new();

        // All clients share the same backing delivery service, authenticated as their own DID
        let api_client = self.api_service.clone_as(&did);

        let orchestrator = MLSOrchestrator::new(
            mls_context,
            Arc::new(storage.clone()),
            Arc::new(api_client),
            Arc::new(credentials.clone()),
            OrchestratorConfig::default(),
        );

        let client = TestClient {
            name: name.to_string(),
            did,
            orchestrator,
            storage,
            credentials,
            _temp_dir: temp_dir,
        };

        self.clients.insert(name.to_string(), client);
        self.clients.get(name).unwrap()
    }

    /// Get a client by name.
    pub fn client(&self, name: &str) -> &TestClient {
        self.clients
            .get(name)
            .unwrap_or_else(|| panic!("no client named '{}'", name))
    }

    /// Register a client's device (initializes the orchestrator and calls ensure_device_registered).
    pub async fn register_device(
        &self,
        name: &str,
    ) -> catbird_mls::orchestrator::error::Result<String> {
        let client = self.client(name);
        client.orchestrator.initialize(&client.did).await?;
        client.orchestrator.ensure_device_registered().await
    }

    /// Access the shared delivery service for introspection.
    pub fn delivery_service(&self) -> &MockDeliveryService {
        &self.api_service
    }
}

// ---------------------------------------------------------------------------
// Smoke tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smoke_test_two_clients() {
    let mut world = TestWorld::new();

    world.add_client("Alice").await;
    world.add_client("Bob").await;

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    assert_eq!(alice.did, "did:plc:alice");
    assert_eq!(bob.did, "did:plc:bob");

    // Verify per-client isolation: storages are independent
    assert_eq!(alice.storage.conversation_count(), 0);
    assert_eq!(bob.storage.conversation_count(), 0);
}

#[tokio::test]
async fn smoke_test_initialize_clients() {
    let mut world = TestWorld::new();

    world.add_client("Alice").await;
    world.add_client("Bob").await;

    // Initialize orchestrators
    let alice = world.client("Alice");
    alice
        .orchestrator
        .initialize(&alice.did)
        .await
        .expect("Alice init failed");

    let bob = world.client("Bob");
    bob.orchestrator
        .initialize(&bob.did)
        .await
        .expect("Bob init failed");
}
