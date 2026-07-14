#![allow(dead_code)]

#[path = "mock_api_client.rs"]
mod mock_api_client;
#[path = "mock_credentials.rs"]
mod mock_credentials;
#[path = "mock_storage.rs"]
mod mock_storage;

use std::collections::HashMap;
use std::sync::Arc;

use catbird_mls::orchestrator::{
    ConversationState, MLSOrchestrator, MLSStorageBackend, OrchestratorConfig, OrchestratorError,
};
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
            .set_conversation_state(conversation_id, state.clone())
            .await
            .expect("set_conversation_state");
        if let ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            notified_at_ms,
        } = state
        {
            self.storage
                .mark_reset_pending(
                    conversation_id,
                    &new_group_id,
                    reset_generation,
                    notified_at_ms,
                )
                .await
                .expect("mark_reset_pending");
        }
        created.group_id
    }

    async fn persist_hex_addressable_local_group(&self, state: ConversationState) -> String {
        let created = self
            .context
            .create_group(self.did.as_bytes().to_vec(), None)
            .expect("create_group");
        let group_id_hex = hex::encode(&created.group_id);
        self.storage
            .ensure_conversation_exists(self.did, &group_id_hex, &group_id_hex)
            .await
            .expect("ensure_conversation_exists");
        self.storage
            .set_conversation_state(&group_id_hex, state.clone())
            .await
            .expect("set_conversation_state");
        if let ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            notified_at_ms,
        } = state
        {
            self.storage
                .mark_reset_pending(
                    &group_id_hex,
                    &new_group_id,
                    reset_generation,
                    notified_at_ms,
                )
                .await
                .expect("mark_reset_pending");
        }
        group_id_hex
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
async fn malformed_reset_or_quarantine_state_keeps_restarted_orchestrator_unavailable() {
    for persisted_state in [
        ConversationState::ResetPending {
            new_group_id: random_group_id_hex(),
            reset_generation: 7,
            notified_at_ms: 1_717_000_000_000,
        },
        ConversationState::Quarantined {
            reason: catbird_mls::orchestrator::QuarantineReason::PeerBadCommit,
            since_ms: 1_717_000_000_000,
        },
    ] {
        let fixture = StartupReconcileFixture::new();
        fixture
            .persist_local_group("convo-malformed", persisted_state)
            .await;
        fixture
            .storage
            .mark_conversation_state_malformed("convo-malformed");

        let restarted = MLSOrchestrator::new(
            Arc::clone(&fixture.context),
            Arc::clone(&fixture.storage),
            Arc::new(MockDeliveryService::new(fixture.did)),
            Arc::new(MockCredentials::new()),
            OrchestratorConfig::default(),
        );

        restarted
            .initialize(fixture.did)
            .await
            .expect_err("malformed security state must abort restart initialization");

        let readiness = restarted.ensure_conversation_ready("convo-malformed").await;
        assert!(
            matches!(
                readiness,
                Err(OrchestratorError::NotAuthenticated | OrchestratorError::ShuttingDown)
            ),
            "failed initialization must leave the orchestrator unavailable, got {readiness:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_hydration_attempted_resume_cannot_send_surviving_local_group() {
    let fixture = StartupReconcileFixture::new();
    let conversation_id = fixture
        .persist_hex_addressable_local_group(ConversationState::ResetPending {
            new_group_id: random_group_id_hex(),
            reset_generation: 11,
            notified_at_ms: 1_717_000_000_000,
        })
        .await;
    fixture
        .storage
        .fail_next_get_conversation_state_for(&conversation_id);
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&fixture.context),
        Arc::clone(&fixture.storage),
        Arc::new(MockDeliveryService::new(fixture.did)),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    orchestrator
        .initialize(fixture.did)
        .await
        .expect_err("malformed hydration must fail initialization");
    assert!(matches!(
        orchestrator.resume_after_suspend(fixture.did).await,
        Err(OrchestratorError::ShuttingDown)
    ));

    let send = orchestrator
        .send_message(&conversation_id, "must remain blocked")
        .await;
    assert!(
        matches!(
            send,
            Err(OrchestratorError::NotAuthenticated | OrchestratorError::ShuttingDown)
        ),
        "attempted resume after malformed hydration must not expose send authority: {send:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_rejects_uninitialized_and_terminal_shutdown_phases() {
    let fixture = StartupReconcileFixture::new();
    let orchestrator = MLSOrchestrator::new(
        Arc::clone(&fixture.context),
        Arc::clone(&fixture.storage),
        Arc::new(MockDeliveryService::new(fixture.did)),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    );

    assert!(matches!(
        orchestrator.resume_after_suspend(fixture.did).await,
        Err(OrchestratorError::InvalidInput(_))
    ));

    orchestrator
        .initialize(fixture.did)
        .await
        .expect("initialize before terminal shutdown");
    orchestrator.shutdown().await;
    assert!(matches!(
        orchestrator.resume_after_suspend(fixture.did).await,
        Err(OrchestratorError::ShuttingDown)
    ));
}

async fn blocked_malformed_initialize(
    fixture: &StartupReconcileFixture,
) -> (
    Arc<MLSOrchestrator<MockStorage, MockDeliveryService, MockCredentials, MLSContext>>,
    mock_storage::ConversationStateReadBarrier,
    tokio::task::JoinHandle<Result<(), OrchestratorError>>,
) {
    fixture
        .persist_local_group(
            "convo-malformed-race",
            ConversationState::ResetPending {
                new_group_id: random_group_id_hex(),
                reset_generation: 9,
                notified_at_ms: 1_717_000_000_000,
            },
        )
        .await;
    fixture
        .persist_local_group("convo-healthy-race", ConversationState::Active)
        .await;
    fixture
        .storage
        .fail_next_get_conversation_state_for("convo-malformed-race");
    let barrier = fixture
        .storage
        .pause_next_conversation_state_read("convo-malformed-race");
    let orchestrator = Arc::new(MLSOrchestrator::new(
        Arc::clone(&fixture.context),
        Arc::clone(&fixture.storage),
        Arc::new(MockDeliveryService::new(fixture.did)),
        Arc::new(MockCredentials::new()),
        OrchestratorConfig::default(),
    ));
    let initializing = {
        let orchestrator = Arc::clone(&orchestrator);
        let did = fixture.did.to_string();
        tokio::spawn(async move { orchestrator.initialize(&did).await })
    };
    barrier.wait_until_entered().await;
    (orchestrator, barrier, initializing)
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_initialize_cannot_revoke_racing_successful_retry() {
    let fixture = StartupReconcileFixture::new();
    let (orchestrator, barrier, first_initialize) = blocked_malformed_initialize(&fixture).await;
    let retry = {
        let orchestrator = Arc::clone(&orchestrator);
        let did = fixture.did.to_string();
        tokio::spawn(async move { orchestrator.initialize(&did).await })
    };
    tokio::task::yield_now().await;
    assert!(
        !retry.is_finished(),
        "retry must wait for lifecycle ownership"
    );

    barrier.release();
    first_initialize
        .await
        .expect("first initialize task")
        .expect_err("first initialize must observe malformed state");
    retry
        .await
        .expect("retry initialize task")
        .expect("retry initialize must become the lifecycle owner");

    let readiness = orchestrator
        .ensure_conversation_ready("convo-healthy-race")
        .await
        .expect("successful retry must leave an operational orchestrator");
    assert!(
        readiness.send_allowed,
        "retry must publish a ready lifecycle"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_initialize_cannot_revoke_racing_resume() {
    let fixture = StartupReconcileFixture::new();
    let (orchestrator, barrier, initializing) = blocked_malformed_initialize(&fixture).await;
    let resume = {
        let orchestrator = Arc::clone(&orchestrator);
        let did = fixture.did.to_string();
        tokio::spawn(async move { orchestrator.resume_after_suspend(&did).await })
    };
    tokio::task::yield_now().await;
    assert!(
        !resume.is_finished(),
        "resume must wait for lifecycle ownership"
    );

    barrier.release();
    initializing
        .await
        .expect("initialize task")
        .expect_err("initialize must observe malformed state");
    assert!(matches!(
        resume.await.expect("resume task"),
        Err(OrchestratorError::ShuttingDown)
    ));

    let malformed_readiness = orchestrator
        .ensure_conversation_ready("convo-malformed-race")
        .await;
    assert!(
        matches!(
            malformed_readiness,
            Err(OrchestratorError::NotAuthenticated | OrchestratorError::ShuttingDown)
        ),
        "racing resume must not reopen a failed initializer: {malformed_readiness:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_initialize_and_racing_shutdown_end_atomically_shutdown() {
    let fixture = StartupReconcileFixture::new();
    let (orchestrator, barrier, initializing) = blocked_malformed_initialize(&fixture).await;
    let shutdown = {
        let orchestrator = Arc::clone(&orchestrator);
        tokio::spawn(async move { orchestrator.shutdown().await })
    };
    tokio::task::yield_now().await;
    assert!(
        !shutdown.is_finished(),
        "shutdown must wait for lifecycle ownership"
    );

    barrier.release();
    initializing
        .await
        .expect("initialize task")
        .expect_err("initialize must observe malformed state");
    shutdown.await.expect("shutdown task");

    assert!(matches!(
        orchestrator
            .ensure_conversation_ready("convo-malformed-race")
            .await,
        Err(OrchestratorError::ShuttingDown)
    ));
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
