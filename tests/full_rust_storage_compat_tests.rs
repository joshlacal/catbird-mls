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
    CreateConversationRequest, EngineLifecycle, KeychainAccess, MLSContext, MLSError, MlsEngine,
    StorageLifecycleState,
};
use openmls_basic_credential::{SignatureKeyPair, StorageId};

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
    assert!(matches!(error, MLSError::StorageFailed));
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
fn legacy_noncanonical_keychain_signer_is_migrated_and_verified() {
    let fixture = StorageCompatFixture::new();
    let (group_id, signer_data) = {
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

    let reopened = fixture.context();
    assert_eq!(
        reopened.get_epoch(group_id).expect("load migrated group"),
        0
    );
    let keychain = fixture.keychain.store.lock().unwrap();
    assert!(keychain.contains_key(&canonical_key));
    assert!(!keychain.contains_key(&legacy_key));
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
