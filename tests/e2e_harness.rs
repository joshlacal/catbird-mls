//! E2E test harness for multi-client MLS orchestrator testing.
//!
//! Wires together multiple `MLSOrchestrator` instances with shared mock backends,
//! simulating multiple clients communicating through a shared delivery service.

#![allow(dead_code)]

#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;
#[path = "mock_api_client.rs"]
pub mod mock_api_client;
#[path = "mock_credentials.rs"]
pub mod mock_credentials;
#[path = "mock_storage.rs"]
pub mod mock_storage;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

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
#[derive(Clone, Default)]
pub struct InMemoryKeychain {
    pub store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryKeychain {
    pub fn new() -> Self {
        Self {
            store: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
    pub orchestrator:
        MLSOrchestrator<MockStorage, MockDeliveryService, MockCredentials, MLSContext>,
    pub storage: MockStorage,
    pub credentials: MockCredentials,
    pub keychain: InMemoryKeychain,
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
    /// Test-only DID authority populated exclusively during explicit fixture
    /// device registration. Validation never learns from a later DS response,
    /// so substitution/revocation tests cannot become self-authorizing.
    authorized_device_keys: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
}

impl Default for TestWorld {
    fn default() -> Self {
        Self::new()
    }
}

impl TestWorld {
    /// Create a new test world with a shared mock delivery service.
    pub fn new() -> Self {
        // Bootstrap with a placeholder DID; each client gets its own view via clone_as.
        let api_service = MockDeliveryService::new("did:plc:bootstrap");
        Self {
            api_service,
            clients: HashMap::new(),
            authorized_device_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a new client (creates orchestrator, storage, credentials, and MLS context).
    pub async fn add_client(&mut self, name: &str) -> &TestClient {
        let did = format!("did:plc:{}", name.to_lowercase());
        self.add_client_with_did(name, &did).await
    }

    /// Add a new client with an explicit DID (e.g. secondary device for an existing user).
    pub async fn add_client_with_did(&mut self, name: &str, did: &str) -> &TestClient {
        let did = did.to_string();
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
        let keychain = InMemoryKeychain::new();
        let mls_context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            format!("test-key-{}", name),
            Box::new(keychain.clone()),
        )
        .expect("failed to create MLSContext");
        epoch_secret_test_support::install(&mls_context);

        let storage = MockStorage::new();
        let credentials = MockCredentials::new();
        for (root_did, keys) in self.authorized_device_keys.lock().unwrap().iter() {
            credentials.set_authorized_device_keys(root_did, keys.clone());
        }

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
            keychain,
            _temp_dir: temp_dir,
        };

        self.clients.insert(name.to_string(), client);
        self.clients.get(name).unwrap()
    }

    /// Reopen the same native encrypted SQLite database and app projection
    /// with a fresh orchestrator; retain account/device credentials and keys.
    pub async fn restart_client(&mut self, name: &str) {
        let client = self.clients.get_mut(name).expect("client to restart");
        client.orchestrator.shutdown().await;
        client
            .orchestrator
            .mls_context()
            .flush_and_prepare_close()
            .expect("close native database");
        let native = MLSContext::new(
            client
                ._temp_dir
                .join("mls.db")
                .to_string_lossy()
                .to_string(),
            format!("test-key-{name}"),
            Box::new(client.keychain.clone()),
        )
        .expect("reopen native encrypted database");
        epoch_secret_test_support::install(&native);
        client.orchestrator = MLSOrchestrator::new(
            native,
            Arc::new(client.storage.clone()),
            Arc::new(self.api_service.clone_as(&client.did)),
            Arc::new(client.credentials.clone()),
            OrchestratorConfig::default(),
        );
        client
            .orchestrator
            .initialize(&client.did)
            .await
            .expect("initialize reopened orchestrator");
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
        let scoped_did = client.orchestrator.ensure_device_registered().await?;
        let signing_key = client
            .orchestrator
            .mls_context()
            .create_key_package(scoped_did.as_bytes().to_vec())?
            .signature_public_key;
        let mut pkgs = Vec::new();
        for _ in 0..10 {
            let kp = client
                .orchestrator
                .mls_context()
                .create_key_package(scoped_did.as_bytes().to_vec())?;
            pkgs.push(kp.key_package_data);
        }
        let device_id = scoped_did
            .split('#')
            .nth(1)
            .unwrap_or(&scoped_did)
            .to_string();
        client
            .orchestrator
            .api_client()
            .publish_key_packages(
                &pkgs,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "",
                Some(&device_id),
            )
            .await?;

        let account_keys = {
            let mut authority = self.authorized_device_keys.lock().unwrap();
            authority.insert(scoped_did.clone(), vec![signing_key.clone()]);
            let account_keys = authority.entry(client.did.clone()).or_default();
            if !account_keys.contains(&signing_key) {
                account_keys.push(signing_key.clone());
            }
            account_keys.clone()
        };
        for fixture_client in self.clients.values() {
            fixture_client
                .credentials
                .set_authorized_device_keys(&scoped_did, vec![signing_key.clone()]);
            fixture_client
                .credentials
                .set_authorized_device_keys(&client.did, account_keys.clone());
        }

        Ok(client.did.clone())
    }

    /// Seed an independent test credential store from authority established by
    /// explicit fixture registration, never from a package being validated.
    pub fn install_authorized_device_keys(&self, credentials: &MockCredentials, root_did: &str) {
        let keys = self
            .authorized_device_keys
            .lock()
            .unwrap()
            .get(root_did)
            .cloned()
            .unwrap_or_else(|| panic!("no registered test authority for {root_did}"));
        credentials.set_authorized_device_keys(root_did, keys);
    }

    /// `name`'s own signed `requestLeafRecovery` of `kind` in `cid`, bound to the current
    /// coordinate, with `package` reserved: the view mls-ds presents (seed it with
    /// `MockDeliveryService::add_pending_leaf_recovery_request`).
    pub async fn signed_leaf_recovery_view(
        &self,
        name: &str,
        cid: &str,
        kind: &str,
        package: &catbird_mls::KeyPackageResult,
    ) -> serde_json::Value {
        use catbird_mls::client::chat_wire;
        use catbird_mls::orchestrator::canonical_transport::{
            derive_key_id, CanonicalOperation, CleanChatSigningContext,
        };
        use catbird_mls::orchestrator::CredentialStore as _;
        let client = self.client(name);
        let device = client.orchestrator.require_actor_device_id().await.unwrap();
        let auth_generation = client
            .credentials
            .get_auth_generation(&client.did)
            .await
            .unwrap()
            .unwrap();
        let key = client
            .orchestrator
            .mls_context()
            .identity_public_key(format!("{}#{device}", client.did))
            .unwrap();
        let request_id = uuid::Uuid::new_v4().to_string();
        let prior = self.api_service.lifecycle_state(cid).unwrap()["coordinates"].clone();
        let body = chat_wire::leaf_recovery_request_body(
            &request_id,
            &client.did,
            &device,
            &derive_key_id(&key),
            auth_generation,
            &prior,
            kind,
            &chat_wire::now_rfc3339_millis(),
        )
        .unwrap();
        let prepared = client
            .orchestrator
            .prepare_clean_chat_signed_request(
                CleanChatSigningContext {
                    actor_did: client.did.clone(),
                    device_id: device.clone(),
                    auth_generation: Some(auth_generation),
                },
                CanonicalOperation::RequestLeafRecovery,
                serde_json::to_vec(&body).unwrap(),
            )
            .await
            .unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&prepared.body.unwrap()).unwrap();
        use base64::Engine as _;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        serde_json::json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryView",
            "conversationId": cid, "recoveryRequestId": request_id,
            "requesterDid": client.did, "requesterDeviceId": device,
            "recoveryKind": kind, "status": "open", "boundCoordinate": prior,
            "reservation": {
                "keyPackageRef": b64(&package.hash_ref),
                "keyPackage": {"bytes": b64(&package.key_package_data)},
            },
            "signedRequest": wire["signedRequest"],
        })
    }

    /// Admit `joiner_did`'s open leaf recovery in `cid` the way a native fulfiller holding a
    /// verified roster does. The legacy orchestrator refuses it (without a roster a DID with no
    /// leaf is never entitled); a native `CatbirdMlsClient` admits it. Here `fulfiller`'s MLS
    /// context builds the Add of the reserved KeyPackage and its Welcome locally and signs the
    /// `leafRecoveryFulfillmentBody`; the mock DS accepts it as it accepts any submitted
    /// fulfillment (state, entry, Welcome); the fulfiller then merges its Commit. Returns the DS
    /// answer `{coordinates, entry, welcomes}`.
    pub async fn admit_as_native_fulfiller(
        &self,
        fulfiller: &str,
        joiner_did: &str,
        cid: &str,
    ) -> serde_json::Value {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use catbird_mls::orchestrator::canonical_transport::{
            canonical_commit_aad_bytes, derive_key_id, CanonicalOperation, CleanChatSigningContext,
        };
        use catbird_mls::orchestrator::{
            CredentialStore as _, MLSAPIClient as _, MLSStorageBackend as _, MlsCryptoContext,
        };
        use sha2::{Digest as _, Sha256};
        let bytes = |value: &serde_json::Value| {
            STANDARD
                .decode(value.as_str().or_else(|| value["$bytes"].as_str()).unwrap())
                .unwrap()
        };
        let client = self.client(fulfiller);
        let orchestrator = &client.orchestrator;
        let context: &MLSContext = orchestrator.mls_context();
        let device = orchestrator.require_actor_device_id().await.unwrap();
        let auth_generation = client
            .credentials
            .get_auth_generation(&client.did)
            .await
            .unwrap()
            .unwrap();
        let view = self
            .api_service
            .open_leaf_recovery_for_test(cid, joiner_did)
            .expect("the joiner's open leaf recovery");
        let state = self.api_service.lifecycle_state(cid).unwrap();
        let prior = state["coordinates"].clone();
        let group_id = bytes(&prior["groupId"]);
        let generation = prior["generation"].as_i64().unwrap();
        let prior_epoch = prior["epoch"].as_u64().unwrap();
        let snapshot = &state["metadataSnapshot"];
        let version = snapshot["metadataVersion"].as_u64().unwrap();
        let metadata_key = |epoch| -> [u8; 32] {
            MlsCryptoContext::export_metadata_key(context, group_id.clone(), epoch)
                .unwrap()
                .try_into()
                .unwrap()
        };
        let metadata = catbird_mls::metadata::decrypt_metadata_snapshot(
            &metadata_key(prior_epoch),
            &group_id,
            prior_epoch,
            version,
            &bytes(&snapshot["nonce"]).try_into().unwrap(),
            &bytes(&snapshot["ciphertext"]),
        )
        .unwrap();

        let convo_uuid = STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes());
        let transition_id = uuid::Uuid::new_v4();
        let mut aad_prior = prior.clone();
        aad_prior["conversationId"] = serde_json::json!(convo_uuid);
        let aad = serde_json::json!({
            "conversationId": convo_uuid, "generation": generation, "protocolVersion": "1",
            "transitionId": STANDARD.encode(transition_id.as_bytes()), "prior": aad_prior,
        });
        let added = MlsCryptoContext::add_members_with_aad(
            context,
            group_id.clone(),
            vec![catbird_mls::KeyPackageData {
                data: bytes(&view["reservation"]["keyPackage"]["bytes"]),
            }],
            Some(canonical_commit_aad_bytes(&aad).unwrap()),
        )
        .unwrap();
        let epoch = MlsCryptoContext::merge_pending_commit(context, group_id.clone()).unwrap();
        let tag = MlsCryptoContext::get_confirmation_tag(context, group_id.clone()).unwrap();
        let hash = MlsCryptoContext::get_group_context_hash(context, group_id.clone()).unwrap();
        let nonce: [u8; 12] = rand::random();
        let ciphertext = catbird_mls::metadata::encrypt_metadata_snapshot_with_nonce(
            &metadata_key(epoch),
            &group_id,
            epoch,
            version,
            &nonce,
            &metadata,
        )
        .unwrap();
        let next = serde_json::json!({
            "conversationId": cid, "groupId": {"$bytes": STANDARD.encode(&group_id)},
            "epoch": epoch, "generation": generation,
            "stateVersion": prior["stateVersion"].as_u64().unwrap() + 1,
            "groupContextHash": {"$bytes": STANDARD.encode(&hash)},
            "confirmationTag": {"$bytes": STANDARD.encode(&tag)}, "lifecycle": "active",
        });
        let mut metadata_snapshot = serde_json::json!({
            "coordinate": {
                "conversationId": convo_uuid, "generation": generation,
                "groupId": {"$bytes": STANDARD.encode(&group_id)}, "epoch": epoch,
                "groupContextHash": {"$bytes": STANDARD.encode(&hash)},
                "confirmationTag": {"$bytes": STANDARD.encode(&tag)},
            },
            "originTransitionId": snapshot["originTransitionId"],
            "metadataVersion": version,
            "nonce": {"$bytes": STANDARD.encode(nonce)},
            "ciphertext": {"$bytes": STANDARD.encode(&ciphertext)},
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "authorProof": snapshot["authorProof"],
        });
        if let Some(binding) = snapshot.get("avatarBinding") {
            metadata_snapshot["avatarBinding"] = binding.clone();
        }
        let request_id = &view["recoveryRequestId"];
        let joiner_device = &view["requesterDeviceId"];
        let key_package_ref = &view["reservation"]["keyPackageRef"];
        let welcome = &added.welcome_data;
        let public_key = MlsCryptoContext::identity_public_key(
            context,
            format!("{}#{device}", client.did).into_bytes(),
        )
        .unwrap();
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
            "transitionId": transition_id.to_string(), "recoveryRequestId": request_id,
            "actorDid": client.did, "actorDeviceId": device,
            "keyId": derive_key_id(&public_key), "authGeneration": auth_generation,
            "prior": prior, "next": next, "aad": aad,
            "manifest": {
                "participantChanges": [],
                "leafChanges": [{
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery", "userDid": joiner_did,
                    "deviceId": joiner_device, "recoveryRequestId": request_id,
                    "keyPackageRef": key_package_ref,
                }],
                "leafRecoveryRequestId": request_id,
                "welcomeBundle": {
                    "welcomeId": uuid::Uuid::new_v4().to_string(), "framing": "mlsMessage",
                    "contentType": "welcome", "opaqueWelcome": {"$bytes": STANDARD.encode(welcome)},
                    "sha256": STANDARD.encode(Sha256::digest(welcome)),
                    "deliveries": [{
                        "recipientDid": joiner_did, "recipientDeviceId": joiner_device,
                        "provenance": {"recoveryRequestId": request_id, "keyPackageRef": key_package_ref},
                    }],
                },
            },
            "commit": {
                "framing": "mlsMessage", "contentType": "publicMessageCommit",
                "bytes": {"$bytes": STANDARD.encode(&added.commit_data)},
                "sha256": STANDARD.encode(Sha256::digest(&added.commit_data)),
            },
            "metadataSnapshot": metadata_snapshot,
            "idempotencyKey": transition_id.to_string(),
            "signedAt": catbird_mls::client::chat_wire::now_rfc3339_millis(),
        });
        let prepared = orchestrator
            .prepare_clean_chat_signed_request(
                CleanChatSigningContext {
                    actor_did: client.did.clone(),
                    device_id: device.clone(),
                    auth_generation: Some(auth_generation),
                },
                CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body).unwrap(),
            )
            .await
            .unwrap();
        let response = orchestrator
            .api_client()
            .submit_prepared_request(prepared)
            .await
            .unwrap();
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        // Land the accepted transition as the orchestrator lands its own: projection from the
        // merged tree, cached view at the new epoch, and (test-utils) the Commit echo's fence.
        let gid = hex::encode(&group_id);
        let mut projection = client.storage.get_group_state(&gid).await.unwrap().unwrap();
        projection.epoch = epoch;
        projection.members = MlsCryptoContext::group_member_identities(context, group_id.clone())
            .unwrap()
            .into_iter()
            .map(|identity| String::from_utf8(identity).unwrap())
            .collect();
        client.storage.set_group_state(&projection).await.unwrap();
        orchestrator
            .group_states()
            .lock()
            .await
            .insert(gid, projection);
        if let Some(conversation) = orchestrator.conversations().lock().await.get_mut(cid) {
            conversation.epoch = epoch;
        }
        #[cfg(feature = "test-utils")]
        orchestrator
            .track_own_commit_for_test(
                Sha256::digest(&added.commit_data).to_vec(),
                cid,
                &hex::encode(&group_id),
                epoch,
            )
            .await;
        serde_json::from_slice(&response.body).unwrap()
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
