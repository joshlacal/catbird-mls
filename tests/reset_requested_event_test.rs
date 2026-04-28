//! Tests for `record_reset_requested` — the Phase 2.5 indirect-flow entry
//! point that handles `resetRequestedEvent` SSE events from `mls-ds`.
//!
//! Phase 2.5 plan: `docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 1.
//!
//! Scenarios covered:
//! 1. Idempotency — same `request_event_id` (and same `reset_generation`)
//!    arriving twice produces a single persisted RESET_PENDING row and a
//!    single `mark_reset_pending` storage call.
//! 2. None group_id path — when the server passes
//!    `expected_new_mls_group_id: None` (the canonical Phase 2.5 indirect
//!    flow), the orchestrator mints a fresh client-side group_id and
//!    persists it into RESET_PENDING. The deferred-recovery loop's first-
//!    responder bootstrap branch then picks it up. We verify the state
//!    here without driving the bootstrap network call (that path is
//!    covered by integration tests that mock the API layer).
//! 3. Some group_id path — admin/legacy direct flow where the server
//!    pre-determines the target id; orchestrator uses it verbatim. State
//!    matches what `record_group_reset` produces.
//! 4. Survives orchestrator restart — RESET_PENDING payload persisted via
//!    `mark_reset_pending` rehydrates after a fresh `MLSOrchestrator`
//!    initializes against the same storage.

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    ConversationState, MLSOrchestrator, MLSStorageBackend, OrchestratorConfig,
};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use std::sync::Arc;

use e2e_harness::TestWorld;

// ---------------------------------------------------------------------------
// 1. Idempotency: duplicate event collapses to single persisted row.
// ---------------------------------------------------------------------------

/// Two `record_reset_requested` calls with the same conversation +
/// reset_generation must produce exactly one persisted RESET_PENDING row.
/// The mock counts `mark_reset_pending` invocations: a second call MUST NOT
/// hit storage again, and the persisted `new_group_id` MUST be unchanged
/// from the first call (no oscillation as random ids would otherwise
/// produce).
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_idempotent_on_same_generation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    // Set up a baseline conversation so reset has somewhere to land.
    let convo = alice
        .orchestrator
        .create_group("Idempotency Test", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // First arrival of the event.
    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            17,
            "quorumVote",
            "req-quorum:convo123:vote789",
            None,
        )
        .await
        .expect("first record_reset_requested failed");

    let first_payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("first call must persist RESET_PENDING via mark_reset_pending");
    assert_eq!(first_payload.reset_generation, 17);
    assert!(
        !first_payload.new_group_id_hex.is_empty(),
        "first call must mint a non-empty client-side new_group_id when None passed"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        1,
        "first call should produce exactly one storage write"
    );
    let first_new_group_id = first_payload.new_group_id_hex.clone();

    // Same event arrives again (SSE reconnect / event_stream replay).
    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            17,
            "quorumVote",
            "req-quorum:convo123:vote789",
            None,
        )
        .await
        .expect("idempotent second record_reset_requested failed");

    let second_payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("idempotent path must keep RESET_PENDING persisted");
    assert_eq!(
        second_payload.new_group_id_hex, first_new_group_id,
        "idempotent path must not mint a new group_id (would oscillate state)"
    );
    assert_eq!(
        second_payload.reset_generation, 17,
        "reset_generation must match the duplicate event"
    );
    assert_eq!(
        alice.storage.mark_reset_pending_call_count(&convo_id),
        1,
        "idempotent second call must NOT issue another mark_reset_pending storage write"
    );
}

// ---------------------------------------------------------------------------
// 2. None group_id path: client mints a fresh candidate.
// ---------------------------------------------------------------------------

/// When `expected_new_mls_group_id` is `None` (the canonical Phase 2.5
/// indirect-trigger shape — quorum, sweep, inline-409, inline-404), the
/// orchestrator mints a fresh client-side UUIDv4-style group_id, transitions
/// to `RESET_PENDING { new_group_id, .. }`, and flips `needs_rejoin` so the
/// deferred-recovery loop's first-responder bootstrap branch picks it up.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_with_none_mints_local_group_id() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("None Path", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            42,
            "inlineGroupInfo404",
            "req-inline-404:convo123:5:1234",
            None,
        )
        .await
        .expect("record_reset_requested(None) failed");

    let payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("None path must persist RESET_PENDING with a minted group_id");
    assert_eq!(
        payload.new_group_id_hex.len(),
        32,
        "minted group_id must be a 32-hex-char UUIDv4-style id (got {} chars)",
        payload.new_group_id_hex.len()
    );
    assert!(
        hex::decode(&payload.new_group_id_hex).is_ok(),
        "minted group_id must decode as valid hex"
    );
    assert_eq!(payload.reset_generation, 42);

    // Conversation state should have flipped to RESET_PENDING with the same
    // new_group_id.
    let state = alice
        .storage
        .get_current_state(&convo_id)
        .expect("conversation must have a state row");
    match state {
        ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        } => {
            assert_eq!(new_group_id, payload.new_group_id_hex);
            assert_eq!(reset_generation, 42);
        }
        other => panic!("expected ResetPending, got {other:?}"),
    }

    // needs_rejoin flag should be set so the deferred-recovery loop
    // picks the conversation up.
    assert!(
        alice.storage.has_rejoin_flag(&convo_id),
        "needs_rejoin flag must be set so deferred-recovery loop picks up the conversation"
    );
}

// ---------------------------------------------------------------------------
// 3. Some group_id path: admin / legacy-equivalent target id.
// ---------------------------------------------------------------------------

/// When `expected_new_mls_group_id: Some(g)` is passed (admin path or legacy
/// direct flow), the orchestrator targets `g` directly. State matches what
/// `record_group_reset(convo, hex::decode(g), gen)` produces — verifies the
/// new sibling function does not regress the legacy behavior.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_with_some_uses_server_group_id() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Some Path", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let admin_supplied = format!("{:032x}", uuid::Uuid::new_v4().as_u128());

    alice
        .orchestrator
        .record_reset_requested(
            &convo_id,
            "crypto-session-prior",
            8,
            "adminRequest",
            "req-admin:convo123:abc",
            Some(admin_supplied.clone()),
        )
        .await
        .expect("record_reset_requested(Some) failed");

    let payload = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("Some path must persist RESET_PENDING with the server-supplied id");
    assert_eq!(
        payload.new_group_id_hex, admin_supplied,
        "Some path must use the server-supplied id verbatim, not mint a new one"
    );
    assert_eq!(payload.reset_generation, 8);

    let state = alice
        .storage
        .get_current_state(&convo_id)
        .expect("conversation must have a state row");
    match state {
        ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        } => {
            assert_eq!(new_group_id, admin_supplied);
            assert_eq!(reset_generation, 8);
        }
        other => panic!("expected ResetPending, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Survives orchestrator restart: rehydration drives recovery on resume.
// ---------------------------------------------------------------------------

/// `record_reset_requested` arriving before an orchestrator restart must
/// survive the restart. The mock storage's `mark_reset_pending` row is
/// preserved across the simulated restart, and a fresh orchestrator built
/// against the same storage must rehydrate `ConversationState::ResetPending`
/// in its in-memory `conversation_states` map during `initialize`.
#[tokio::test(flavor = "multi_thread")]
async fn test_record_reset_requested_survives_orchestrator_restart() {
    // We can't easily reuse the `TestWorld` add_client flow for restart since
    // it owns the orchestrator. Build a single client manually so we can
    // tear down the orchestrator while keeping storage + mls_context backing
    // dirs alive, then construct a fresh orchestrator pointing at the same
    // storage.

    use e2e_harness::mock_api_client::MockDeliveryService;
    use e2e_harness::mock_credentials::MockCredentials;
    use e2e_harness::mock_storage::MockStorage;

    struct InMemoryKeychain {
        store: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl KeychainAccess for InMemoryKeychain {
        async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(self.store.lock().unwrap().get(&key).cloned())
        }
        async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
            self.store.lock().unwrap().insert(key, value);
            Ok(())
        }
        async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
            self.store.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    let did = "did:plc:restartalice".to_string();
    let temp_dir = std::env::temp_dir().join(format!(
        "catbird_mls_restart_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");
    let db_path = temp_dir.join("mls.db");
    let key = format!("test-key-{}", uuid::Uuid::new_v4());

    let storage = MockStorage::new();
    let credentials = MockCredentials::new();
    let api_service = MockDeliveryService::new(&did);

    let convo_id = "convo-survives-restart";
    let admin_supplied = format!("{:032x}", uuid::Uuid::new_v4().as_u128());

    // ---- Phase 1: write RESET_PENDING via the real orchestrator API ----
    {
        let keychain = Box::new(InMemoryKeychain {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
        let mls_context =
            MLSContext::new(db_path.to_string_lossy().to_string(), key.clone(), keychain)
                .expect("failed to create MLSContext (phase 1)");

        let api_client = api_service.clone_as(&did);
        let orchestrator = MLSOrchestrator::new(
            mls_context,
            Arc::new(storage.clone()),
            Arc::new(api_client),
            Arc::new(credentials.clone()),
            OrchestratorConfig::default(),
        );

        orchestrator
            .initialize(&did)
            .await
            .expect("phase-1 initialize failed");

        // Seed a conversation row so the orchestrator's group_states + storage
        // know about it.
        storage
            .ensure_conversation_exists(&did, convo_id, convo_id)
            .await
            .expect("ensure_conversation_exists failed");

        orchestrator
            .record_reset_requested(
                convo_id,
                "crypto-session-prior",
                99,
                "systemSweep",
                "req-sweep:convo:tick42",
                Some(admin_supplied.clone()),
            )
            .await
            .expect("record_reset_requested failed in phase 1");

        // Sanity: verify the persisted row is there.
        let persisted = storage
            .get_persisted_reset_pending(convo_id)
            .expect("RESET_PENDING must be persisted before restart");
        assert_eq!(persisted.new_group_id_hex, admin_supplied);
        assert_eq!(persisted.reset_generation, 99);

        // Drop the orchestrator + mls_context so the SQLCipher DB is closed
        // cleanly (mimics process restart).
        orchestrator.shutdown().await;
    }

    // ---- Phase 2: fresh orchestrator against the same storage ----
    let storage_phase2 = storage.clone();

    let keychain2 = Box::new(InMemoryKeychain {
        store: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let mls_context2 = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        key.clone(),
        keychain2,
    )
    .expect("failed to create MLSContext (phase 2)");

    let api_client2 = api_service.clone_as(&did);
    let orchestrator2 = MLSOrchestrator::new(
        mls_context2,
        Arc::new(storage_phase2.clone()),
        Arc::new(api_client2),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );

    orchestrator2
        .initialize(&did)
        .await
        .expect("phase-2 initialize failed");

    // The storage's mark_reset_pending row should still be there (Mock
    // backing it is shared via Arc<Mutex>; in production this would be the
    // platform DB).
    let post_restart = storage_phase2
        .get_persisted_reset_pending(convo_id)
        .expect("RESET_PENDING payload must survive restart");
    assert_eq!(post_restart.new_group_id_hex, admin_supplied);
    assert_eq!(post_restart.reset_generation, 99);

    // Verify the fresh orchestrator can read RESET_PENDING via its own
    // public surface — `reset_pending_payload` is `pub(crate)` so we read
    // through `get_conversation_state` on the storage trait, which is the
    // same fallback path the recovery loop uses (recovery.rs:1559).
    let rehydrated = storage_phase2
        .get_conversation_state(convo_id)
        .await
        .expect("get_conversation_state must succeed");
    match rehydrated {
        Some(ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        }) => {
            assert_eq!(new_group_id, admin_supplied);
            assert_eq!(reset_generation, 99);
        }
        other => panic!("expected post-restart storage to rehydrate ResetPending, got {other:?}"),
    }

    // Cleanup: shutdown + temp dir.
    orchestrator2.shutdown().await;
    let _ = std::fs::remove_dir_all(&temp_dir);
}
