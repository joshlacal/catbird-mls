#![allow(dead_code)]

#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;
#[path = "mock_api_client.rs"]
mod mock_api_client;
#[path = "mock_credentials.rs"]
mod mock_credentials;
#[path = "mock_storage.rs"]
mod mock_storage;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use catbird_mls::orchestrator::{
    ConversationRecoveryState, ConversationState, GroupState, JoinMethod, MLSStorageBackend,
    OrchestratorConfig,
};
use catbird_mls::{
    CreateConversationRequest, EngineLifecycle, GroupConfig, KeyPackageData, KeychainAccess,
    MLSContext, MLSError, MlsEngine, StorageLifecycleState,
};
use mock_api_client::MockDeliveryService;
use mock_credentials::MockCredentials;
use mock_storage::{MockStorage, StorageProjectionCounts};
use openmls_basic_credential::{SignatureKeyPair, StorageId};
use sha2::{Digest, Sha256};

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
    did: String,
    db_path: String,
    encryption_key: String,
    keychain: SharedKeychain,
    storage: Arc<MockStorage>,
    api: Arc<MockDeliveryService>,
    credentials: Arc<MockCredentials>,
    _temp_dir: tempfile::TempDir,
}

#[derive(Clone, serde::Deserialize)]
struct ExistingFixtureState {
    did: String,
    conversation_id: String,
    group_id_hex: String,
    epoch: u64,
    encryption_key: String,
}

impl StorageCompatFixture {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("mls.db").to_string_lossy().to_string();
        Self {
            did: "did:plc:alice".to_string(),
            db_path,
            encryption_key: "test-key".to_string(),
            keychain: SharedKeychain::default(),
            storage: Arc::new(MockStorage::new()),
            api: Arc::new(MockDeliveryService::new("did:plc:alice")),
            credentials: Arc::new(MockCredentials::new()),
            _temp_dir: temp_dir,
        }
    }

    fn load_preexisting_openmls_fixture() -> (Self, ExistingFixtureState) {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let existing: ExistingFixtureState = serde_json::from_slice(
            &fs::read(fixture_dir.join("openmls_preexisting_metadata.json"))
                .expect("read preexisting fixture metadata"),
        )
        .expect("decode preexisting fixture metadata");
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("mls.db");
        fs::copy(fixture_dir.join("openmls_preexisting.sqlite"), &db_path)
            .expect("copy preexisting OpenMLS SQLite fixture");

        (
            Self {
                did: existing.did.clone(),
                db_path: db_path.to_string_lossy().to_string(),
                encryption_key: existing.encryption_key.clone(),
                keychain: SharedKeychain::default(),
                storage: Arc::new(MockStorage::new()),
                api: Arc::new(MockDeliveryService::new("did:plc:alice")),
                credentials: Arc::new(MockCredentials::new()),
                _temp_dir: temp_dir,
            },
            existing,
        )
    }

    fn context_without_epoch_secret_storage(&self) -> Arc<MLSContext> {
        MLSContext::new(
            self.db_path.clone(),
            self.encryption_key.clone(),
            Box::new(self.keychain.clone()),
        )
        .expect("MLSContext")
    }

    fn context(&self) -> Arc<MLSContext> {
        let context = self.context_without_epoch_secret_storage();
        epoch_secret_test_support::install(&context);
        context
    }

    fn engine(&self) -> MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext> {
        self.engine_with_context(self.context())
    }

    fn engine_with_context(
        &self,
        context: Arc<MLSContext>,
    ) -> MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext> {
        MlsEngine::new(
            context,
            Arc::clone(&self.storage),
            Arc::clone(&self.api),
            Arc::clone(&self.credentials),
            Arc::new(EngineLifecycle::default()),
            OrchestratorConfig::default(),
        )
    }

    fn load_fixture_projection_rows(&self, existing: &ExistingFixtureState) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture runtime");

        runtime
            .block_on(self.storage.ensure_conversation_exists(
                &existing.did,
                &existing.conversation_id,
                &existing.group_id_hex,
            ))
            .expect("seed conversation projection");
        runtime
            .block_on(self.storage.update_join_info(
                &existing.conversation_id,
                &existing.did,
                JoinMethod::Creator,
                existing.epoch,
            ))
            .expect("seed join info");
        runtime
            .block_on(
                self.storage
                    .set_conversation_state(&existing.conversation_id, ConversationState::Active),
            )
            .expect("seed conversation state");
        runtime
            .block_on(self.storage.set_group_state(&GroupState {
                group_id: existing.group_id_hex.clone(),
                conversation_id: existing.conversation_id.clone(),
                epoch: existing.epoch,
                members: vec![existing.did.clone()],
            }))
            .expect("seed group state");
    }
}

#[test]
fn existing_openmls_sqlite_state_without_tier0_signer_fails_closed() {
    let (fixture, existing) = StorageCompatFixture::load_preexisting_openmls_fixture();
    fixture.load_fixture_projection_rows(&existing);

    assert_eq!(
        fixture.storage.storage_projection_counts(),
        StorageProjectionCounts {
            conversations: 1,
            group_states: 1,
            messages: 0,
        },
        "fixture builder should only seed Swift-owned projection rows"
    );

    // This historical file fixture intentionally has no Keychain sidecar.
    // Its signer manifest therefore names a Tier-0 key that is not available.
    // Loading it as Healthy would retain readable group state while silently
    // making every authenticated epoch-changing operation impossible.
    let error = match MLSContext::new(
        fixture.db_path.clone(),
        fixture.encryption_key.clone(),
        Box::new(fixture.keychain.clone()),
    ) {
        Ok(_) => panic!("missing Tier-0 signer must not initialize as healthy"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        MLSError::StorageFailed | MLSError::InvalidInput { .. }
    ));
    assert_eq!(
        fixture.storage.storage_projection_counts(),
        StorageProjectionCounts {
            conversations: 1,
            group_states: 1,
            messages: 0,
        },
        "rejecting incomplete Rust-owned storage must not mutate platform projections"
    );
    assert!(
        fixture.storage.has_group_state(&existing.group_id_hex),
        "Swift-owned projection rows must remain intact for explicit recovery"
    );
}

#[test]
fn legacy_noncanonical_keychain_signer_fails_closed_without_mutation() {
    let fixture = StorageCompatFixture::new();
    let (_group_id, signer_data) = {
        let context = fixture.context();
        let created = context
            .create_group(fixture.did.as_bytes().to_vec(), None)
            .expect("create group with canonical signer");
        let signer_data = context
            .export_identity_key(fixture.did.clone())
            .expect("export test signer");
        context
            .flush_and_prepare_close()
            .expect("close before keychain migration fixture rewrite");
        (created.group_id, signer_data)
    };

    let signer: SignatureKeyPair =
        serde_json::from_slice(&signer_data).expect("decode test signer");
    let canonical_key = format!(
        "sig_key_{}",
        hex::encode(serde_json::to_vec(&signer.id()).expect("encode canonical signer id"))
    );
    let legacy_key = format!(
        "sig_key_{}",
        hex::encode(
            serde_json::to_vec(&StorageId::from(signer.public().to_vec()))
                .expect("encode legacy signer id")
        )
    );
    assert_ne!(canonical_key, legacy_key);

    {
        let mut keychain = fixture.keychain.store.lock().unwrap();
        let key_data = keychain
            .remove(&canonical_key)
            .expect("canonical signer must exist before migration fixture rewrite");
        keychain.insert(legacy_key.clone(), key_data);
    }

    let before_hash = Sha256::digest(&std::fs::read(&fixture.db_path).unwrap());

    let error = match MLSContext::new(
        fixture.db_path.clone(),
        fixture.encryption_key.clone(),
        Box::new(fixture.keychain.clone()),
    ) {
        Ok(_) => panic!("legacy non-canonical signer without canonical slot must fail closed"),
        Err(e) => e,
    };
    assert!(matches!(
        error,
        MLSError::StorageFailed | MLSError::InvalidInput { .. }
    ));

    let after_hash = Sha256::digest(&std::fs::read(&fixture.db_path).unwrap());
    assert_eq!(
        before_hash, after_hash,
        "database file must remain unchanged on fail-closed reopen"
    );
}

#[test]
fn openmls_sqlite_state_round_trips_under_rust_engine_storage() {
    let fixture = StorageCompatFixture::new();
    let (conversation_id, group_id, epoch_before_close) = {
        let engine = fixture.engine();
        engine.initialize_user(&fixture.did).expect("initialize");
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

    let before_reopen_hash = Sha256::digest(&std::fs::read(&fixture.db_path).unwrap());
    let before_reopen_mtime = std::fs::metadata(&fixture.db_path)
        .unwrap()
        .modified()
        .unwrap();
    let reopened_context = fixture.context();
    assert_eq!(
        reopened_context
            .get_epoch(hex::decode(&group_id).expect("group id hex"))
            .expect("load persisted group epoch"),
        epoch_before_close
    );
    reopened_context
        .flush_and_prepare_close()
        .expect("close read-only reopened context");
    drop(reopened_context);
    let after_reopen_hash = Sha256::digest(&std::fs::read(&fixture.db_path).unwrap());
    let after_reopen_mtime = std::fs::metadata(&fixture.db_path)
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        before_reopen_hash, after_reopen_hash,
        "successful persisted-group context reopen must not mutate the database"
    );
    assert_eq!(
        before_reopen_mtime, after_reopen_mtime,
        "successful persisted-group context reopen must not update the database mtime"
    );

    let reopened = fixture.engine();
    reopened
        .initialize_user(&fixture.did)
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
fn configured_group_reopens_after_add_members_without_mutation() {
    let alice_fixture = StorageCompatFixture::new();
    let bob_fixture = StorageCompatFixture::new();
    let alice = alice_fixture.context();
    let bob = bob_fixture.context();
    let config = GroupConfig {
        max_past_epochs: 2,
        out_of_order_tolerance: 7,
        maximum_forward_distance: 321,
        ..GroupConfig::default()
    };
    let group_id = alice
        .create_group(b"did:plc:alice".to_vec(), Some(config))
        .expect("create configured group")
        .group_id;
    let bob_key_package = bob
        .create_key_package(b"did:plc:bob".to_vec())
        .expect("create Bob key package");
    alice
        .add_members(
            group_id.clone(),
            vec![KeyPackageData {
                data: bob_key_package.key_package_data,
            }],
        )
        .expect("add Bob");
    alice
        .merge_pending_commit(group_id.clone())
        .expect("merge add-members commit");
    let expected_epoch = alice.get_epoch(group_id.clone()).expect("read epoch");
    alice
        .flush_and_prepare_close()
        .expect("close configured group");
    drop(alice);
    bob.flush_and_prepare_close().expect("close Bob context");
    drop(bob);

    let before_reopen_hash =
        Sha256::digest(std::fs::read(&alice_fixture.db_path).expect("read database"));
    let before_reopen_mtime = std::fs::metadata(&alice_fixture.db_path)
        .expect("database metadata")
        .modified()
        .expect("database mtime");
    let reopened = alice_fixture.context();
    assert_eq!(
        reopened
            .get_epoch(group_id)
            .expect("load configured group after add-members"),
        expected_epoch
    );
    reopened
        .flush_and_prepare_close()
        .expect("close reopened configured group");
    drop(reopened);

    assert_eq!(
        before_reopen_hash,
        Sha256::digest(std::fs::read(&alice_fixture.db_path).expect("read reopened database")),
        "successful configured-group reopen must not mutate the database"
    );
    assert_eq!(
        before_reopen_mtime,
        std::fs::metadata(&alice_fixture.db_path)
            .expect("reopened database metadata")
            .modified()
            .expect("reopened database mtime"),
        "successful configured-group reopen must not update the database mtime"
    );
}

#[test]
fn storage_lifecycle_status_reports_busy_interrupt_suspend_and_close() {
    let fixture = StorageCompatFixture::new();
    let context = fixture.context_without_epoch_secret_storage();
    let engine = fixture.engine_with_context(Arc::clone(&context));

    engine.initialize_user(&fixture.did).expect("initialize");
    let initial = engine.storage_lifecycle_status();
    assert_eq!(initial.state, StorageLifecycleState::Open);
    assert!(!initial.is_busy);
    assert_eq!(initial.busy_contexts, 0);
    assert_eq!(initial.last_operation_label.as_deref(), Some("initialized"));
    assert_eq!(initial.interruptible_contexts, 2);

    epoch_secret_test_support::install(&context);
    let created = engine
        .create_conversation(CreateConversationRequest {
            name: "operation-labels".into(),
            member_dids: vec![],
            description: None,
        })
        .expect("create conversation");
    let group_id = hex::decode(&created.conversation.group_id).expect("group id hex");
    let ciphertext = context
        .encrypt_message(group_id.clone(), b"hello from rust".to_vec())
        .expect("encrypt fixture message")
        .ciphertext;
    let after_encrypt = engine.storage_lifecycle_status();
    assert_eq!(
        after_encrypt.last_operation_label.as_deref(),
        Some("encrypt_message"),
        "engine status should preserve the storage registry label for host-facing lifecycle status"
    );
    let decrypt_result = context.decrypt_message(group_id, ciphertext);
    assert!(
        decrypt_result.is_err(),
        "single-context fixture is only exercising the storage label path here"
    );
    let after_decrypt = engine.storage_lifecycle_status();
    assert_eq!(
        after_decrypt.last_operation_label.as_deref(),
        Some("decrypt_message"),
        "engine status should keep the latest storage operation label visible to Swift hosts"
    );

    let busy_context = Arc::clone(&context);
    let busy_started = Arc::new(AtomicBool::new(false));
    let busy_started_signal = Arc::clone(&busy_started);
    let busy_worker = thread::spawn(move || {
        busy_context
            .debug_hold_storage_lock_for_test(busy_started_signal, Duration::from_millis(200))
            .expect("hold storage lock");
    });
    for _ in 0..20 {
        if busy_started.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let busy = (0..20)
        .map(|_| {
            let status = context.storage_lifecycle_status();
            if status.is_busy {
                return Some(status);
            }
            thread::sleep(Duration::from_millis(10));
            None
        })
        .find_map(|status| status)
        .expect("status should eventually observe the Rust storage registry busy signal");
    assert_eq!(busy.state, StorageLifecycleState::Open);
    assert!(
        busy.is_busy,
        "status should reflect an in-flight Rust storage operation"
    );
    assert!(
        busy.busy_contexts >= 1,
        "busy count should rise while the Rust storage mutex is held"
    );

    busy_worker.join().expect("busy worker");
    let after_busy = engine.storage_lifecycle_status();
    assert!(!after_busy.is_busy);
    assert_eq!(after_busy.busy_contexts, 0);

    let interrupted = engine
        .interrupt_storage("unit-test interrupt")
        .expect("interrupt storage");
    assert_eq!(interrupted, 2);
    let after_interrupt = engine.storage_lifecycle_status();
    assert_eq!(after_interrupt.state, StorageLifecycleState::Open);
    assert!(!after_interrupt.is_busy);
    assert_eq!(after_interrupt.busy_contexts, 0);
    assert_eq!(
        after_interrupt.last_operation_label.as_deref(),
        Some("interrupt")
    );

    engine
        .prepare_for_suspend("unit-test suspend", Duration::from_millis(250))
        .expect("prepare suspend");
    let suspended = engine.storage_lifecycle_status();
    assert_eq!(suspended.state, StorageLifecycleState::Suspended);
    assert!(!suspended.is_busy);
    assert_eq!(suspended.busy_contexts, 0);
    assert_eq!(suspended.last_operation_label.as_deref(), Some("interrupt"));

    engine
        .emergency_close("unit-test close")
        .expect("emergency close");
    let closed = engine.storage_lifecycle_status();
    assert_eq!(closed.state, StorageLifecycleState::Closed);
    assert!(!closed.is_busy);
    assert_eq!(closed.busy_contexts, 0);
    assert_eq!(
        closed.last_operation_label.as_deref(),
        Some("flush_and_prepare_close")
    );
}
#[test]
fn sqlite_storage_provider_sqlcipher_encryption_verified() {
    use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
    use rusqlite::Connection;

    #[derive(Default)]
    struct TestJsonCodec;

    impl Codec for TestJsonCodec {
        type Error = serde_json::Error;

        fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
            serde_json::to_vec(value)
        }

        fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
            serde_json::from_slice(slice)
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("encrypted_storage_proof.db");

    let conn = Connection::open(&db_path).expect("open connection");
    conn.pragma_update(None, "cipher_memory_security", "OFF")
        .expect("cipher_memory_security");
    conn.pragma_update(None, "key", "test-sqlcipher-key-9876543210")
        .expect("set pragma key");

    let cipher_version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .expect("query cipher_version");
    assert!(
        !cipher_version.is_empty(),
        "PRAGMA cipher_version must return non-empty version string from SQLCipher"
    );

    let mut provider = SqliteStorageProvider::<TestJsonCodec, Connection>::new(conn);
    provider.run_migrations().expect("run migrations");

    drop(provider);

    let raw_bytes = std::fs::read(&db_path).expect("read db file");
    assert!(
        raw_bytes.len() >= 16,
        "database file must have at least 16 bytes"
    );
    assert!(
        !raw_bytes.starts_with(b"SQLite format 3\0"),
        "raw database header must be encrypted ciphertext, NOT plaintext SQLite format 3"
    );
}

fn derive_test_cipher_salt_hex(encryption_key: &str) -> String {
    let digest = Sha256::digest(encryption_key.as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn open_test_connection(path: &std::path::Path, encryption_key: &str) -> rusqlite::Connection {
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
            format!("x'{}'", derive_test_cipher_salt_hex(encryption_key)),
        )
        .unwrap();
    connection
        .pragma_update(None, "cipher_page_size", 4096)
        .unwrap();
    connection.pragma_update(None, "kdf_iter", 256000).unwrap();
    connection
        .pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")
        .unwrap();
    connection
        .pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")
        .unwrap();
    connection
}

#[test]
fn reopen_existing_db_validates_schema_and_rejects_missing_table_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_table_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // 2. Corrupt by dropping a mandatory OpenMLS V5 table.
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("DROP TABLE vc_operation_trees", [])
            .expect("drop table");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must fail validation and NOT touch the file
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening database with missing table must fail validation");
    assert!(
        err.to_string().contains("missing")
            || err.to_string().contains("table")
            || err.to_string().contains("Required table")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "file hash must remain unchanged on validation error"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "file mtime must remain unchanged on validation error"
    );
}

#[test]
fn reopen_existing_db_rejects_unexpected_or_malformed_schema_objects_without_mutation() {
    let mutations = [
        "CREATE TABLE unexpected_table (value TEXT)",
        "CREATE INDEX unexpected_index ON mls_manifests(value)",
        "CREATE VIEW unexpected_view AS SELECT key FROM mls_manifests",
        "CREATE TRIGGER unexpected_trigger AFTER INSERT ON mls_manifests BEGIN SELECT 1; END",
        "DROP INDEX vc_retained_key_package_material_epoch_id;
         CREATE INDEX vc_retained_key_package_material_epoch_id
         ON vc_retained_key_package_material(provider_version)",
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_master
         SET sql = replace(sql, '''application_export_tree''', '''legacy_removed''')
         WHERE name = 'openmls_group_data';
         PRAGMA writable_schema = OFF",
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_master
         SET sql = replace(sql, 'value TEXT NOT NULL', 'value TEXT NOT NULL DEFAULT ''x''')
         WHERE name = 'mls_manifests';
         PRAGMA writable_schema = OFF",
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_master
         SET sql = replace(sql, 'value TEXT NOT NULL', 'value TEXT NOT NULL REFERENCES mls_manifests(key)')
         WHERE name = 'mls_manifests';
         PRAGMA writable_schema = OFF",
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_master
         SET sql = replace(sql, 'PRIMARY KEY AUTOINCREMENT', 'PRIMARY KEY')
         WHERE name = 'openmls_own_leaf_nodes';
         PRAGMA writable_schema = OFF",
    ];

    for (case, mutation) in mutations.into_iter().enumerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join(format!("schema-object-{case}.db"));
        let key = "test-encryption-key-for-validation";
        let keychain = SharedKeychain::default();
        let context = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            key.to_string(),
            Box::new(keychain.clone()),
        )
        .expect("create initial valid database");
        drop(context);

        open_test_connection(&db_path, key)
            .execute_batch(mutation)
            .expect("apply schema mutation");
        let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
        let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

        MLSContext::new(
            db_path.to_string_lossy().to_string(),
            key.to_string(),
            Box::new(keychain),
        )
        .err()
        .expect("unexpected or malformed schema object must fail validation");
        assert_eq!(
            before_hash,
            Sha256::digest(&std::fs::read(&db_path).unwrap()),
            "failed schema validation must not mutate case {case}"
        );
        assert_eq!(
            before_mtime,
            std::fs::metadata(&db_path).unwrap().modified().unwrap(),
            "failed schema validation must not update mtime for case {case}"
        );
    }
}

#[test]
fn reopen_existing_db_rejects_old_or_future_refinery_version_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_refinery_version_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // 2. Corrupt refinery versions by inserting future version 7
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("INSERT INTO openmls_sqlite_storage_migrations (version, name, applied_on, checksum) VALUES (7, 'future_migration', '2099-01-01', '0')", []).expect("insert future migration");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must fail validation and NOT touch the file
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening database with future refinery version must fail validation");
    assert!(err
        .to_string()
        .contains("Refinery schema versions mismatch"));

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "file hash must remain unchanged on validation error"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "file mtime must remain unchanged on validation error"
    );
}

#[test]
fn reopen_existing_db_rejects_corrupt_bundle_row_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_bundle_corrupt_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // 2. Corrupt by inserting an invalid bundle row
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("INSERT INTO mls_key_package_bundles (hash_ref, bundle_b64, created_at) VALUES ('aabbcc', 'not-valid-base64!', 12345)", []).expect("insert corrupt bundle");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must fail validation and NOT touch the file
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening database with corrupt bundle row must fail validation");
    assert!(err.to_string().contains("Corrupt") || err.to_string().contains("bundle"));

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "file hash must remain unchanged on validation error"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "file mtime must remain unchanged on validation error"
    );
}

#[test]
fn reopen_existing_db_rejects_missing_or_malformed_openmls_column_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_malformed_column_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // 2. Corrupt openmls_encryption_keys table by recreating it without the required 'value' column
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("DROP TABLE openmls_encryption_keys", [])
            .expect("drop table");
        conn.execute("CREATE TABLE openmls_encryption_keys (provider_version INTEGER NOT NULL, public_key BLOB PRIMARY KEY)", []).expect("create table without key_pair col");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must fail validation and NOT touch the file
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening database with malformed column descriptor must fail validation");
    assert!(
        err.to_string().contains("openmls_encryption_keys")
            && (err.to_string().contains("schema mismatch")
                || err.to_string().contains("Required column"))
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "file hash must remain unchanged on validation error"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "file mtime must remain unchanged on validation error"
    );
}

#[test]
fn reopen_existing_db_rejects_stale_pending_external_join_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_stale_join_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // 2. Corrupt by inserting a stale pending_external_join for a non-existent group
    {
        let conn = open_test_connection(&db_path, key);
        let stale_join_json = serde_json::json!({
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff": {
                "group_id": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "signer_public_key": vec![0x42; 32],
                "created_at": 12345
            }
        });
        conn.execute("INSERT OR REPLACE INTO mls_manifests (key, value) VALUES ('pending_external_joins', ?1)", [stale_join_json.to_string()]).expect("insert stale join");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must fail validation and NOT touch the file
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening database with stale pending join must fail validation");
    assert!(
        err.to_string().contains("Stale pending_external_join")
            || err.to_string().contains("pending_external_joins")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "file hash must remain unchanged on validation error"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "file mtime must remain unchanged on validation error"
    );
}

#[test]
fn reopen_existing_db_succeeds_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_clean_reopen_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 2. Reopen valid database
    let reopened = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("reopen valid existing database");
    drop(reopened);

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "valid reopen without writes must leave file hash unchanged"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "valid reopen without writes must leave file mtime unchanged"
    );
}

#[test]
fn reopen_existing_db_rejects_bundle_drift_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("existing_bundle_drift_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create a valid initial database and publish a key package bundle
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    let _kp = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create key package");
    ctx.flush_and_prepare_close().expect("flush and close");
    // 2. Introduce drift: delete row from openmls_key_packages while keeping it in mls_key_package_bundles
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("DELETE FROM openmls_key_packages", [])
            .expect("delete key package");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must detect drift and fail closed without touching the file
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening database with key package drift must fail validation");
    assert!(
        err.to_string()
            .contains("missing from openmls_key_packages")
            || err.to_string().contains("drift")
            || err.to_string().contains("Key package drift")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed drift validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed drift validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_succeeds_after_public_delete_with_parity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("delete_parity_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create DB and publish 2 key packages
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    let kp1 = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp1");
    let kp2 = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp2");

    let deleted = ctx
        .delete_key_package_bundles(vec![kp1.hash_ref.clone()])
        .expect("delete bundle");
    assert_eq!(deleted, 1);
    ctx.flush_and_prepare_close().expect("close");

    // 2. Reopen must pass validation with exact 1-to-1 parity
    let reopened = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("reopen after delete must succeed with exact parity");

    let deleted_second = reopened
        .delete_key_package_bundles(vec![kp2.hash_ref])
        .expect("delete second bundle");
    assert_eq!(deleted_second, 1);
    let deleted_absent = reopened
        .delete_key_package_bundles(vec![kp1.hash_ref])
        .expect("delete absent bundle");
    assert_eq!(deleted_absent, 0);
}

#[test]
fn reopen_existing_db_succeeds_after_prune_with_parity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("prune_parity_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create DB and publish 2 key packages
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    let kp1 = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp1");
    let kp2 = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp2");
    ctx.flush_and_prepare_close().expect("flush and close");

    // 2. Backdate kp1 row past 90 days
    {
        let conn = open_test_connection(&db_path, key);
        let backdated = 1000i64;
        conn.execute(
            "UPDATE mls_key_package_bundles SET created_at = ?1 WHERE hash_ref = ?2",
            rusqlite::params![backdated, hex::encode(&kp1.hash_ref)],
        )
        .expect("backdate");
    }

    // 3. Reopen fresh: on fresh create / reconcile path it prunes and synchronizes
    let reopened = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("reopen valid existing database");

    let deleted_expired = reopened
        .delete_key_package_bundles(vec![kp1.hash_ref.clone()])
        .expect("delete already-pruned bundle");
    assert_eq!(deleted_expired, 0);
    let deleted_second = reopened
        .delete_key_package_bundles(vec![kp2.hash_ref])
        .expect("delete second bundle");
    assert_eq!(deleted_second, 1);
    let deleted_absent = reopened
        .delete_key_package_bundles(vec![kp1.hash_ref])
        .expect("delete absent bundle");
    assert_eq!(deleted_absent, 0);
}
#[test]
fn reopen_existing_db_rejects_non_empty_openmls_signature_keys_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sig_keys_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    // 1. Create DB
    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // 2. Corrupt by inserting row into openmls_signature_keys
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute(
            "INSERT INTO openmls_signature_keys (provider_version, public_key, signature_key) VALUES (1, X'01020304', X'05060708')",
            [],
        )
        .expect("insert into openmls_signature_keys");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    // 3. Reopen must fail validation
    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopening with non-empty openmls_signature_keys must fail validation");
    assert!(err
        .to_string()
        .contains("openmls_signature_keys must be empty on preflight"));

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed signature_keys validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed signature_keys validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_relabeled_bundle_hash_ref_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("relabel_bundle_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    let kp = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp");
    ctx.flush_and_prepare_close().expect("close");

    // Corrupt hash_ref in mls_key_package_bundles
    {
        let conn = open_test_connection(&db_path, key);
        let fake_hash = vec![0x99u8; kp.hash_ref.len()];
        conn.execute(
            "UPDATE mls_key_package_bundles SET hash_ref = ?1 WHERE hash_ref = ?2",
            rusqlite::params![hex::encode(&fake_hash), hex::encode(&kp.hash_ref)],
        )
        .expect("relabel hash_ref");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with relabeled hash_ref must fail validation");
    assert!(err
        .to_string()
        .contains("does not match computed key package ref"));

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed relabel validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed relabel validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_duplicate_manifest_group_id_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("dup_group_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // Insert duplicate group_id into manifest
    {
        let conn = open_test_connection(&db_path, key);
        let dup_json =
            serde_json::to_string(&vec!["01020304".to_string(), "01020304".to_string()]).unwrap();
        conn.execute(
            "INSERT INTO mls_manifests (key, value) VALUES ('group_ids', ?1)",
            [&dup_json],
        )
        .expect("insert duplicate group_ids");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with duplicate group_id in manifest must fail validation");
    assert!(err.to_string().contains("Duplicate group_id"));

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed duplicate group validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed duplicate group validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_extra_unmanifested_group_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("extra_group_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    epoch_secret_test_support::install(&ctx);
    let _res = ctx
        .create_group("did:plc:alice#device-1".as_bytes().to_vec(), None)
        .expect("create group");
    ctx.flush_and_prepare_close().expect("close");

    // Remove group_id from manifest (simulating crash before persist_group_id)
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("DELETE FROM mls_manifests WHERE key = 'group_ids'", [])
            .expect("clear group_ids manifest");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with unmanifested DB group must fail validation");
    assert!(
        err.to_string()
            .contains("Manifest group_ids mismatch with openmls_group_data")
            || err.to_string().contains("unmanifested")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed unmanifested DB group validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed unmanifested DB group validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_tampered_page_without_modifying_file_or_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("tampered_page_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    let _kp = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp");
    ctx.flush_and_prepare_close().expect("close");

    // Tamper with bytes in the middle of the database file
    let mut file_bytes = std::fs::read(&db_path).unwrap();
    let tamper_offset = file_bytes.len() / 2;
    for b in &mut file_bytes[tamper_offset..tamper_offset + 16] {
        *b ^= 0xFF;
    }
    std::fs::write(&db_path, &file_bytes).unwrap();

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with tampered page must fail integrity check");
    assert!(
        err.to_string().contains("integrity_check") || err.to_string().contains("Failed to open")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed integrity check must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed integrity check must not update mtime"
    );

    // Verify no WAL or SHM sidecar file was created
    let wal_path = db_path.with_extension("db-wal");
    let shm_path = db_path.with_extension("db-shm");
    assert!(
        !wal_path.exists(),
        "no wal sidecar should be created on failed preflight"
    );
    assert!(
        !shm_path.exists(),
        "no shm sidecar should be created on failed preflight"
    );
}

#[test]
fn reopen_existing_db_rejects_corrupt_nonempty_group_data_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("corrupt_group_data_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    epoch_secret_test_support::install(&ctx);
    let res = ctx
        .create_group("did:plc:alice#device-1".as_bytes().to_vec(), None)
        .expect("create group");
    ctx.flush_and_prepare_close().expect("close");

    // Corrupt group_data BLOB to valid non-empty JSON that fails MlsGroup::load
    {
        let conn = open_test_connection(&db_path, key);
        let corrupt_json = b"{\"invalid\": \"group_state\"}";
        let group_id_json =
            serde_json::to_vec(&openmls::prelude::GroupId::from_slice(&res.group_id)).unwrap();
        conn.execute(
            "UPDATE openmls_group_data SET group_data = ?1 WHERE group_id = ?2",
            rusqlite::params![corrupt_json.as_slice(), group_id_json],
        )
        .expect("update group_data");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with corrupt group_data must fail validation");
    assert!(
        err.to_string().contains("MlsGroup::load failed") || err.to_string().contains("Corrupt")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed group_data validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed group_data validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_swapped_valid_signer_keypair_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("swapped_signer_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    let _kp = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("create kp");
    ctx.flush_and_prepare_close().expect("close");

    // Read manifested signer pk
    let conn = open_test_connection(&db_path, key);
    let signers_json: String = conn
        .query_row(
            "SELECT value FROM mls_manifests WHERE key = 'signers'",
            [],
            |r| r.get(0),
        )
        .expect("read signers manifest");
    let signers_map: std::collections::HashMap<String, String> =
        serde_json::from_str(&signers_json).unwrap();
    let (_, hex_pk) = signers_map.into_iter().next().unwrap();

    let diff_pair =
        openmls_basic_credential::SignatureKeyPair::new(openmls::prelude::SignatureScheme::ED25519)
            .expect("create diff key pair");

    // Overwrite keychain entry with diff_pair at the exact stored slot
    let key_to_overwrite = keychain
        .store
        .lock()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    let diff_pair_json = serde_json::to_vec(&diff_pair).unwrap();
    keychain
        .store
        .lock()
        .unwrap()
        .insert(key_to_overwrite, diff_pair_json);
    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with swapped signer keypair must fail validation");
    assert!(
        err.to_string().contains("public key mismatch")
            || err.to_string().contains("SignatureKeyPair")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed swapped signer validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed swapped signer validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_missing_signers_manifest_with_groups_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("missing_signers_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    epoch_secret_test_support::install(&ctx);
    let _res = ctx
        .create_group("did:plc:alice#device-1".as_bytes().to_vec(), None)
        .expect("create group");
    ctx.flush_and_prepare_close().expect("close");

    // Delete signers manifest row
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("DELETE FROM mls_manifests WHERE key = 'signers'", [])
            .expect("delete signers manifest");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with groups but missing signers manifest must fail validation");
    assert!(
        err.to_string().contains("own leaf credential not bound")
            || err.to_string().contains("signers")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed signers validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed signers validation must not update mtime"
    );
}

#[test]
fn reopen_existing_db_rejects_on_conflict_replace_ddl_without_modifying_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("on_conflict_ddl_test.db");
    let key = "test-encryption-key-for-validation";
    let keychain = SharedKeychain::default();

    let ctx = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("create initial valid database");
    drop(ctx);

    // Modify schema with PRAGMA writable_schema to add ON CONFLICT REPLACE
    {
        let conn = open_test_connection(&db_path, key);
        conn.execute("PRAGMA writable_schema = ON", [])
            .expect("enable writable_schema");
        conn.execute(
            "UPDATE sqlite_master SET sql = 'CREATE TABLE mls_manifests (key TEXT PRIMARY KEY ON CONFLICT REPLACE, value TEXT NOT NULL)' WHERE name = 'mls_manifests'",
            [],
        )
        .expect("update DDL with ON CONFLICT REPLACE");
    }

    let before_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let before_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();

    let err = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.to_string(),
        Box::new(keychain.clone()),
    )
    .err()
    .expect("reopen with ON CONFLICT REPLACE DDL must fail validation");
    assert!(
        err.to_string().contains("unsupported DDL constraints")
            || err.to_string().contains("conflict resolution")
    );

    let after_hash = Sha256::digest(&std::fs::read(&db_path).unwrap());
    let after_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
    assert_eq!(
        before_hash, after_hash,
        "failed DDL validation must not mutate file"
    );
    assert_eq!(
        before_mtime, after_mtime,
        "failed DDL validation must not update mtime"
    );
}
