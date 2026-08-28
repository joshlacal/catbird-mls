use async_trait::async_trait;
use catbird_mls::{
    EpochSecretStorage, GroupConfig, KeyPackageData, KeychainAccess, MLSContext, MLSError,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct TestKeychain {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            values: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.values.lock().unwrap().get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.values.lock().unwrap().insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.values.lock().unwrap().remove(&key);
        Ok(())
    }
}

struct BooleanEpochSecretStorage {
    store_result: bool,
}

#[async_trait]
impl EpochSecretStorage for BooleanEpochSecretStorage {
    async fn store_epoch_secret(
        &self,
        _conversation_id: String,
        _epoch: u64,
        _secret_data: Vec<u8>,
    ) -> bool {
        self.store_result
    }

    async fn get_epoch_secret(&self, _conversation_id: String, _epoch: u64) -> Option<Vec<u8>> {
        None
    }

    async fn delete_epoch_secret(&self, _conversation_id: String, _epoch: u64) -> bool {
        true
    }

    async fn delete_epochs_before(&self, _conversation_id: String, _cutoff_epoch: u64) -> u32 {
        0
    }
}

#[derive(Default)]
struct TrackingEpochSecretState {
    secrets: Mutex<HashMap<(String, u64), Vec<u8>>>,
    delete_calls: AtomicUsize,
}

struct TrackingEpochSecretStorage {
    state: Arc<TrackingEpochSecretState>,
}

#[async_trait]
impl EpochSecretStorage for TrackingEpochSecretStorage {
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool {
        self.state
            .secrets
            .lock()
            .unwrap()
            .insert((conversation_id, epoch), secret_data);
        true
    }

    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>> {
        self.state
            .secrets
            .lock()
            .unwrap()
            .get(&(conversation_id, epoch))
            .cloned()
    }

    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool {
        self.state.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.state
            .secrets
            .lock()
            .unwrap()
            .remove(&(conversation_id, epoch));
        true
    }

    async fn delete_epochs_before(&self, _conversation_id: String, _cutoff_epoch: u64) -> u32 {
        0
    }
}

fn make_context_with_keychain(
    path: &std::path::Path,
    store_result: bool,
    keychain: TestKeychain,
) -> Arc<MLSContext> {
    let context = MLSContext::new(
        path.to_string_lossy().to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(keychain),
    )
    .unwrap();
    context
        .set_epoch_secret_storage(Box::new(BooleanEpochSecretStorage { store_result }))
        .unwrap();
    context
}

fn make_context(path: &std::path::Path, store_result: bool) -> Arc<MLSContext> {
    make_context_with_keychain(path, store_result, TestKeychain::new())
}

fn make_tracking_context(
    path: &std::path::Path,
) -> (Arc<MLSContext>, Arc<TrackingEpochSecretState>) {
    let context = MLSContext::new(
        path.to_string_lossy().to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(TestKeychain::new()),
    )
    .unwrap();
    let state = Arc::new(TrackingEpochSecretState::default());
    context
        .set_epoch_secret_storage(Box::new(TrackingEpochSecretStorage {
            state: Arc::clone(&state),
        }))
        .unwrap();
    (context, state)
}

fn derive_cipher_salt_hex(encryption_key: &str) -> String {
    let digest = Sha256::digest(encryption_key.as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn open_manifest_connection(path: &std::path::Path, encryption_key: &str) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(path).expect("open test database");
    connection
        .pragma_update(None, "cipher_memory_security", "OFF")
        .unwrap();
    connection
        .pragma_update(None, "key", encryption_key)
        .unwrap();
    connection
        .pragma_update(None, "cipher_plaintext_header_size", 32)
        .unwrap();
    connection
        .pragma_update(
            None,
            "cipher_salt",
            format!("x'{}'", derive_cipher_salt_hex(encryption_key)),
        )
        .unwrap();
    connection
}

#[test]
fn welcome_storage_rejection_rolls_back_joined_group_durably() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice_path = alice_dir.path().join("alice.db");
    let bob_path = bob_dir.path().join("bob.db");

    let alice = make_context(&alice_path, true);
    let bob_keychain = TestKeychain::new();
    let bob = make_context_with_keychain(&bob_path, false, bob_keychain.clone());

    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(GroupConfig::default()))
        .unwrap();
    let bob_key_package = bob.create_key_package(b"did:plc:bob".to_vec()).unwrap();
    let add = alice
        .add_members(
            created.group_id.clone(),
            vec![KeyPackageData {
                data: bob_key_package.key_package_data,
            }],
        )
        .unwrap();
    alice
        .merge_pending_commit(created.group_id.clone())
        .unwrap();

    let error = match bob.process_welcome(
        add.welcome_data,
        b"did:plc:bob".to_vec(),
        Some(GroupConfig::default()),
    ) {
        Ok(_) => panic!("Welcome adoption must fail when epoch-secret persistence is rejected"),
        Err(error) => error,
    };

    assert!(matches!(error, MLSError::StorageFailed));
    assert!(
        !bob.group_exists(created.group_id.clone()),
        "failed Welcome adoption must not publish a live group"
    );

    drop(bob);
    let reopened = make_context_with_keychain(&bob_path, true, bob_keychain);
    assert!(
        !reopened.group_exists(created.group_id),
        "failed Welcome adoption must not survive a database reopen"
    );
}

#[test]
fn post_export_welcome_failure_deletes_the_exact_epoch_secret() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice_path = alice_dir.path().join("alice.db");
    let bob_path = bob_dir.path().join("bob.db");
    let encryption_key = "test-key-1234567890123456";

    let alice = make_context(&alice_path, true);
    let (bob, epoch_state) = make_tracking_context(&bob_path);
    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(GroupConfig::default()))
        .unwrap();
    let bob_key_package = bob.create_key_package(b"did:plc:bob".to_vec()).unwrap();
    let add = alice
        .add_members(
            created.group_id.clone(),
            vec![KeyPackageData {
                data: bob_key_package.key_package_data,
            }],
        )
        .unwrap();
    alice
        .merge_pending_commit(created.group_id.clone())
        .unwrap();

    let failure_connection = open_manifest_connection(&bob_path, encryption_key);
    failure_connection
        .execute_batch(
            "CREATE TRIGGER fail_nonempty_group_manifest_write
             BEFORE INSERT ON mls_manifests
             WHEN NEW.key = 'group_ids' AND NEW.value <> '[]'
             BEGIN
                 SELECT RAISE(FAIL, 'injected group_ids manifest failure');
             END;",
        )
        .expect("install post-export failure trigger");

    match bob.process_welcome(
        add.welcome_data,
        b"did:plc:bob".to_vec(),
        Some(GroupConfig::default()),
    ) {
        Ok(_) => panic!("post-export manifest failure must reject Welcome adoption"),
        Err(_) => {}
    }

    assert_eq!(epoch_state.delete_calls.load(Ordering::SeqCst), 1);
    assert!(
        epoch_state.secrets.lock().unwrap().is_empty(),
        "failed Welcome adoption must not orphan an externally stored epoch secret"
    );
    assert!(!bob.group_exists(created.group_id));
}
