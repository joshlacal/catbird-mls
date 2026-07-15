#![allow(dead_code)]

mod e2e_harness;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use catbird_mls::orchestrator::{
    ConversationRecoveryState, EngineEvent, IncomingEnvelope, MLSAPIClient, MLSMessagePayload,
    MLSOrchestrator, OrchestratorConfig, OrchestratorError,
};
use catbird_mls::{
    CreateConversationRequest, EngineLifecycle, KeychainAccess, MLSContext, MLSError, MlsEngine,
};
use e2e_harness::mock_api_client::MockDeliveryService;
use e2e_harness::mock_credentials::MockCredentials;
use e2e_harness::mock_storage::MockStorage;
use e2e_harness::TestWorld;

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

#[async_trait]
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

struct FullRustMessagingFixture {
    engine: MlsEngine<MockStorage, MockDeliveryService, MockCredentials, MLSContext>,
    orchestrator: MLSOrchestrator<MockStorage, MockDeliveryService, MockCredentials, MLSContext>,
    api: Arc<MockDeliveryService>,
    _temp_dir: tempfile::TempDir,
}

impl FullRustMessagingFixture {
    async fn new(did: &str) -> Self {
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
        let config = OrchestratorConfig::default();

        let orchestrator = MLSOrchestrator::new(
            Arc::clone(&context),
            Arc::clone(&storage),
            Arc::clone(&api),
            Arc::clone(&credentials),
            config.clone(),
        );
        orchestrator
            .initialize(did)
            .await
            .expect("orchestrator initialize");

        let engine = MlsEngine::new(
            context,
            storage,
            Arc::clone(&api),
            credentials,
            Arc::new(EngineLifecycle::default()),
            config,
        );
        engine.initialize_user(did).expect("engine initialize");

        Self {
            engine,
            orchestrator,
            api,
            _temp_dir: temp_dir,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn send_payload_returns_message_inserted_event() {
    let fixture = FullRustMessagingFixture::new("did:plc:alice").await;
    let convo = fixture
        .orchestrator
        .create_group("Pipeline", None, None)
        .await
        .expect("create_group failed");

    let payload_json =
        serde_json::to_string(&MLSMessagePayload::text("hello from rust")).expect("payload json");

    let result = fixture
        .engine
        .send_payload(&convo.conversation_id, &payload_json)
        .expect("engine send_payload");

    assert_eq!(result.message.conversation_id, convo.conversation_id);
    assert!(result.events.iter().any(|event| matches!(
        event,
        EngineEvent::MessageInserted { convo_id, .. } if convo_id == &convo.conversation_id
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn process_server_event_records_reset_pending_and_emits_recovery_event() {
    let fixture = FullRustMessagingFixture::new("did:plc:alice").await;
    let convo = fixture
        .orchestrator
        .create_group("Reset me", None, None)
        .await
        .expect("create_group failed");

    let event_json = serde_json::json!({
        "type": "groupReset",
        "convoId": convo.conversation_id,
        "newGroupId": "00112233445566778899aabbccddeeff",
        "resetGeneration": 1
    })
    .to_string();

    let events = fixture
        .engine
        .process_server_event(&event_json)
        .expect("process_server_event");

    assert!(events.iter().any(|event| matches!(
        event,
        EngineEvent::RecoveryStateChanged { convo_id, state }
            if convo_id == &convo.conversation_id && *state == ConversationRecoveryState::ResetPending
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        EngineEvent::NeedsUiRefresh { convo_id } if convo_id == &convo.conversation_id
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn send_after_suspend_rejects_durable_reset_pending_existing_target() {
    let fixture = FullRustMessagingFixture::new("did:plc:alice").await;
    let predecessor = fixture
        .engine
        .create_conversation(CreateConversationRequest {
            name: "Reset predecessor".into(),
            member_dids: vec![],
            description: None,
        })
        .expect("create predecessor conversation")
        .conversation;
    let target = fixture
        .engine
        .create_conversation(CreateConversationRequest {
            name: "Materialized reset target".into(),
            member_dids: vec![],
            description: None,
        })
        .expect("create reset target conversation")
        .conversation;
    let reset_generation = 73;
    let event_json = serde_json::json!({
        "type": "groupReset",
        "convoId": predecessor.conversation_id,
        "newGroupId": target.group_id,
        "resetGeneration": reset_generation,
    })
    .to_string();
    fixture
        .engine
        .process_server_event(&event_json)
        .expect("persist ResetPending");
    fixture
        .engine
        .prepare_for_suspend("reset-send-gate", std::time::Duration::from_millis(250))
        .expect("prepare for suspend");
    fixture
        .engine
        .resume_from_suspend("reset-send-gate")
        .expect("resume from suspend");

    let sends_before = fixture.api.message_count(&predecessor.conversation_id);
    let payload_json =
        serde_json::to_string(&MLSMessagePayload::text("must not send")).expect("payload json");
    let error = fixture
        .engine
        .send_payload(&predecessor.conversation_id, &payload_json)
        .expect_err("durable ResetPending must reject direct send");

    assert!(matches!(
        error,
        OrchestratorError::ResetCompletionNotCommitted {
            ref convo_id,
            reset_generation: generation,
            ..
        } if convo_id == &predecessor.conversation_id && generation == reset_generation
    ));
    assert_eq!(
        fixture.api.message_count(&predecessor.conversation_id),
        sends_before,
        "reset-gated send must not reach the delivery service"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn process_incoming_message_catches_up_missing_commits_before_decrypting() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Carol").await;
    let _alice_did = world
        .register_device("Alice")
        .await
        .expect("register alice");
    let bob_did = world.register_device("Bob").await.expect("register bob");
    let carol_did = world
        .register_device("Carol")
        .await
        .expect("register carol");

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("Epoch catch-up", Some(&[bob_did.clone()]), None)
        .await
        .expect("create_group failed");

    bob.orchestrator
        .ensure_conversation_ready(&convo.conversation_id)
        .await
        .expect("bob welcome join");

    alice
        .orchestrator
        .add_members(&convo.conversation_id, &[carol_did])
        .await
        .expect("add carol");

    let payload_json =
        serde_json::to_string(&MLSMessagePayload::text("after commit")).expect("payload json");
    let sent = alice
        .orchestrator
        .send_payload_json(&convo.conversation_id, &payload_json)
        .await
        .expect("alice send");

    let api = world.delivery_service().clone_as("did:plc:bob");
    let envelopes =
        MLSAPIClient::get_messages(&api, &convo.conversation_id, None, 20, None, None, None)
            .await
            .expect("get messages")
            .0;
    let envelope = envelopes
        .into_iter()
        .find(|candidate| candidate.server_message_id.as_deref() == Some(sent.id.as_str()))
        .expect("sent envelope");

    let result = bob
        .orchestrator
        .process_incoming_message(&IncomingEnvelope {
            server_epoch: Some(sent.epoch),
            ..envelope
        })
        .await
        .expect("process incoming");

    let message = result
        .message
        .expect("message should decrypt after catch-up");
    assert_eq!(message.id, sent.id);
    assert!(result.events.iter().any(|event| matches!(
        event,
        EngineEvent::MessageInserted { message_id, convo_id }
            if message_id == &sent.id && convo_id == &convo.conversation_id
    )));
}
