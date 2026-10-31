//! Recovery persistence contracts requiring access to the private quarantine exit.
//! Public manual reset first performs authenticated server reset coordination;
//! these cases isolate the durable quarantine/backoff writes themselves.

use std::sync::Arc;

use crate::orchestrator::{
    constants, CredentialStore, IncomingEnvelope, MLSOrchestrator, MLSStorageBackend,
    OrchestratorConfig, PersistedRecoveryBackoff, QuarantineExitReason,
};
use crate::recovery_e2e_harness as e2e_harness;
#[path = "../../tests/support/ws5_recovery.rs"]
mod ws5_recovery_support;
use ws5_recovery_support::{configure_test_signing_authority, FailingCrypto, RecordingObserver};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// FIX-3: entering quarantine drops the in-memory failed_rejoins entry; the
/// persisted backoff row must be dropped too, or restart hydration within
/// the 24h TTL re-imports a maxed-out lockout for a conversation whose
/// quarantine already exited (ghost gate).
#[tokio::test(flavor = "multi_thread")]
async fn quarantine_entry_clears_persisted_backoff_no_ghost_lockout() {
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let convo_id = "00000000-0000-4000-8000-0000000000d1".to_string();
    let group_id = "d1".repeat(32);
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let credentials = e2e_harness::mock_credentials::MockCredentials::new();
    let ds = e2e_harness::mock_api_client::MockDeliveryService::new(did);

    let orchestrator = MLSOrchestrator::new(
        Arc::new(FailingCrypto::peer_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    credentials
        .store_device_uuid(did, "00000000-0000-4000-8000-000000000001")
        .await
        .unwrap();
    credentials
        .store_mls_did(did, &format!("{did}#00000000-0000-4000-8000-000000000001"))
        .await
        .unwrap();
    configure_test_signing_authority(&credentials, did).await;
    storage
        .ensure_conversation_exists(did, &convo_id, &group_id)
        .await
        .expect("seed explicit conversation-to-group mapping");
    // Maxed-out persisted row, as accumulated rejoin failures would write it.
    storage.seed_recovery_backoff(PersistedRecoveryBackoff {
        conversation_id: convo_id.clone(),
        failed_rejoin_count: 3,
        last_attempt_at_ms: now_ms(),
        quarantined_until_ms: Some(now_ms() + constants::RECOVERY_BACKOFF_TTL.as_millis() as i64),
    });

    // Drive Layer-3 quarantine entry: three distinct peer-bad frames trip
    // RepeatedFramingFailures.
    let mut frame_errors = Vec::new();
    for i in 0..3 {
        let envelope = IncomingEnvelope {
            canonical_entry_json: None,
            conversation_id: convo_id.clone(),
            sender_did: "did:plc:mallory".to_string(),
            ciphertext: format!("peer-bad-frame-{i}").into_bytes(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some(format!("00000000-0000-4000-8000-{:012x}", i + 1)),
            server_epoch: None,
            server_sequence: None,
        };
        if let Err(error) = orchestrator.process_incoming(&envelope).await {
            frame_errors.push(error.to_string());
        }
    }
    assert!(
        orchestrator
            .get_conversation_quarantine_state(&convo_id)
            .await
            .is_some(),
        "three peer-bad frames must enter Layer-3 quarantine (test precondition): {frame_errors:?}"
    );

    assert!(
        storage.get_persisted_recovery_backoff(&convo_id).is_none(),
        "FIX-3 REGRESSION: enter_quarantine left the persisted maxed-out \
         backoff row behind"
    );

    // Exercise the internal persistence transition after a confirmed reset,
    // then hydrate a fresh orchestrator over the same mock storage.
    orchestrator
        .exit_quarantine(&convo_id, QuarantineExitReason::UserConfirmedReset)
        .await;
    assert!(orchestrator
        .get_conversation_quarantine_state(&convo_id)
        .await
        .is_none());

    let restarted = MLSOrchestrator::new(
        Arc::new(FailingCrypto::peer_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );
    restarted.initialize(did).await.expect("re-initialize");
    {
        let tracker = restarted.recovery_tracker().lock().await;
        assert!(
            !tracker.is_maxed_out(&convo_id),
            "FIX-3 REGRESSION: restart re-imported a ghost maxed-out lockout \
             for a conversation that already exited quarantine"
        );
        assert_eq!(tracker.failed_attempts(&convo_id), 0);
        assert!(!tracker.should_skip(&convo_id));
    }
}

/// R-2 (E7 follow-up): quarantine state persists are recovery-critical —
/// `enter_quarantine` / `exit_quarantine` write failures must escalate
/// through `report_recovery_storage_failure` (event observer + error_log),
/// not warn-only tracing. A dropped enter-side write silently loses the
/// quarantine across restart; a dropped exit-side write resurrects it. The
/// backoff-row clear right next to them already escalates (FIX-3 in
/// 771e6e4); this pins the same policy for the four sibling writes.
#[tokio::test(flavor = "multi_thread")]
async fn failing_quarantine_persists_escalate() {
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let convo_id = "00000000-0000-4000-8000-0000000000d3".to_string();
    let group_id = "d3".repeat(32);
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let credentials = e2e_harness::mock_credentials::MockCredentials::new();
    let ds = e2e_harness::mock_api_client::MockDeliveryService::new(did);

    let orchestrator = MLSOrchestrator::new(
        Arc::new(FailingCrypto::peer_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    credentials
        .store_device_uuid(did, "00000000-0000-4000-8000-000000000001")
        .await
        .unwrap();
    credentials
        .store_mls_did(did, &format!("{did}#00000000-0000-4000-8000-000000000001"))
        .await
        .unwrap();
    configure_test_signing_authority(&credentials, did).await;
    storage
        .ensure_conversation_exists(did, &convo_id, &group_id)
        .await
        .expect("seed explicit conversation-to-group mapping");
    let observer = Arc::new(RecordingObserver::default());
    orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let frame = |i: usize| IncomingEnvelope {
        canonical_entry_json: None,
        conversation_id: convo_id.clone(),
        sender_did: "did:plc:mallory".to_string(),
        ciphertext: format!("peer-bad-frame-{i}").into_bytes(),
        timestamp: chrono::Utc::now(),
        server_message_id: Some(format!("00000000-0000-4000-8002-{:012x}", i + 1)),
        server_epoch: None,
        server_sequence: None,
    };

    // Two peer-bad frames arm Layer 3; inject the enter-side persist
    // failures only for the third (quarantine-tripping) frame so the
    // one-shot flags are consumed by enter_quarantine itself.
    for i in 0..2 {
        let _ = orchestrator.process_incoming(&frame(i)).await;
    }
    storage.fail_next_set_conversation_state();
    storage.fail_next_mark_quarantined();
    let _ = orchestrator.process_incoming(&frame(2)).await;

    assert!(
        orchestrator
            .get_conversation_quarantine_state(&convo_id)
            .await
            .is_some(),
        "three peer-bad frames must enter Layer-3 quarantine (test precondition)"
    );
    {
        let escalations = observer.storage_failures.lock().unwrap().clone();
        assert!(
            escalations
                .iter()
                .any(|(cid, op, _)| cid == &convo_id && op == "set_conversation_state:quarantined"),
            "R-2 REGRESSION: failing Quarantined state persist must escalate, got {escalations:?}"
        );
        assert!(
            escalations
                .iter()
                .any(|(cid, op, _)| cid == &convo_id && op == "mark_quarantined"),
            "R-2 REGRESSION: failing mark_quarantined must escalate, got {escalations:?}"
        );
    }

    // Exit side: both persists fail — must escalate, not warn.
    storage.fail_next_set_conversation_state();
    storage.fail_next_clear_quarantine();
    orchestrator
        .exit_quarantine(&convo_id, QuarantineExitReason::UserConfirmedReset)
        .await;

    let escalations = observer.storage_failures.lock().unwrap().clone();
    assert!(
        escalations.iter().any(|(cid, op, _)| cid == &convo_id
            && op == "set_conversation_state:active_quarantine_exit"),
        "R-2 REGRESSION: failing Active state persist on quarantine exit must escalate, got {escalations:?}"
    );
    assert!(
        escalations
            .iter()
            .any(|(cid, op, _)| cid == &convo_id && op == "clear_quarantine"),
        "R-2 REGRESSION: failing clear_quarantine must escalate, got {escalations:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn f03_sequencer_equivocation_receipts_survive_reset_pending_ingestion() {
    use crate::orchestrator::types::SequencerReceipt;

    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let convo_id = "00000000-0000-4000-8000-0000000000f3".to_string();
    let group_id = "aa".repeat(32);
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let credentials = e2e_harness::mock_credentials::MockCredentials::new();
    let ds = e2e_harness::mock_api_client::MockDeliveryService::new(did);

    let orchestrator = MLSOrchestrator::new(
        Arc::new(FailingCrypto::peer_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    storage
        .ensure_conversation_exists(did, &convo_id, &group_id)
        .await
        .expect("seed conversation");

    let receipt = SequencerReceipt {
        convo_id: convo_id.clone(),
        epoch: 7,
        sequencer_term: 1,
        commit_hash: vec![0xDE; 32],
        sequencer_did: "did:web:sequencer.example".to_string(),
        issued_at: 1_730_000_000,
        signature: vec![0xAB; 64],
    };
    storage
        .store_sequencer_receipt(&receipt)
        .await
        .expect("store sequencer receipt");

    orchestrator
        .record_group_reset(&convo_id, vec![0xBB; 32], 2)
        .await
        .expect("record_group_reset");

    let stored = storage
        .get_sequencer_receipts(&convo_id, None)
        .await
        .expect("get_sequencer_receipts");
    assert_eq!(
        stored.len(),
        1,
        "F-03: unverified server reset hint must NOT wipe stored sequencer equivocation receipts"
    );
    assert_eq!(stored[0].commit_hash, receipt.commit_hash);
}

#[tokio::test(flavor = "multi_thread")]
async fn f03_peer_poison_quarantine_survives_unverified_server_reset() {
    use crate::orchestrator::types::ConversationState;

    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let convo_id = "00000000-0000-4000-8000-0000000000f4".to_string();
    let group_id = "cc".repeat(32);
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let credentials = e2e_harness::mock_credentials::MockCredentials::new();
    let ds = e2e_harness::mock_api_client::MockDeliveryService::new(did);

    let orchestrator = MLSOrchestrator::new(
        Arc::new(FailingCrypto::peer_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials.clone()),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    credentials
        .store_device_uuid(did, "00000000-0000-4000-8000-000000000001")
        .await
        .unwrap();
    credentials
        .store_mls_did(did, &format!("{did}#00000000-0000-4000-8000-000000000001"))
        .await
        .unwrap();
    configure_test_signing_authority(&credentials, did).await;
    storage
        .ensure_conversation_exists(did, &convo_id, &group_id)
        .await
        .expect("seed conversation");

    // Trip PeerBadCommit quarantine with 3 frames from the same peer.
    for i in 0..3 {
        let envelope = IncomingEnvelope {
            canonical_entry_json: None,
            conversation_id: convo_id.clone(),
            sender_did: "did:plc:mallory11111111111111111".to_string(),
            ciphertext: format!("poison-commit-{i}").into_bytes(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some(format!("00000000-0000-4000-8005-{:012x}", i + 1)),
            server_epoch: None,
            server_sequence: None,
        };
        let _ = orchestrator.process_incoming(&envelope).await;
    }
    assert!(
        orchestrator
            .get_conversation_quarantine_state(&convo_id)
            .await
            .is_some(),
        "test precondition: conversation must be quarantined"
    );
    assert!(
        storage.get_persisted_quarantine(&convo_id).is_some(),
        "test precondition: persisted quarantine must exist"
    );

    // An unverified server reset arrives while the conversation is quarantined.
    orchestrator
        .record_group_reset(&convo_id, vec![0x55; 32], 3)
        .await
        .expect("unverified server reset should not hard-error event stream");

    assert!(
        orchestrator
            .get_conversation_quarantine_state(&convo_id)
            .await
            .is_some(),
        "F-03: unverified server reset must NOT clear in-memory peer-poison quarantine"
    );
    assert!(
        storage.get_persisted_quarantine(&convo_id).is_some(),
        "F-03: unverified server reset must NOT clear persisted peer-poison quarantine"
    );
    assert!(
        matches!(
            storage.get_conversation_state(&convo_id).await.unwrap(),
            Some(ConversationState::Quarantined { .. })
        ),
        "F-03: durable ConversationState::Quarantined must survive unverified server reset across restarts"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn f03_passive_recover_leaf_or_reset_does_not_auto_reset_on_zero_leaf_state() {
    use crate::orchestrator::canonical_transport::CanonicalOperation;
    use e2e_harness::TestWorld;

    let mut world = TestWorld::new();
    let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    world.add_client_with_did("Alice", alice_did).await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let created = alice
        .orchestrator
        .create_group("f03-zero-leaf", None, None)
        .await
        .expect("create group");
    let convo_id = created.conversation_id.clone();

    world.add_client_with_did("AliceDev2", alice_did).await;
    world.register_device("AliceDev2").await.unwrap();
    world
        .delivery_service()
        .set_bootstrap_reset_group_success(true);
    // Untrusted server reports an empty `leaves: []` (`leafCount == 0`) array.
    world
        .delivery_service()
        .set_conversation_leaves_for_test(&convo_id, vec![]);

    let dev2 = world.client("AliceDev2");
    dev2.storage
        .ensure_conversation_exists(alice_did, &convo_id, &created.group_id)
        .await
        .unwrap();

    // 1. Passive background rejoin (`join_or_rejoin` -> `recover_leaf_or_reset`)
    //    must NEVER autonomously sign a reset on zero-leaf state.
    let _ = dev2.orchestrator.join_or_rejoin(&convo_id).await;
    let reset_requests = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::RequestReset)
        .count();
    assert_eq!(
        reset_requests, 0,
        "F-03: passive recovery must not auto-sign RequestReset on zero-leaf state"
    );
    assert_eq!(
        world
            .delivery_service()
            .bootstrap_reset_group_call_count(&convo_id),
        0,
        "F-03: passive recovery must not activate a reset group on zero-leaf state"
    );

    // 2. Even `accept_conversation` must NOT treat an empty `leaves: []` array
    //    as proof that nobody else can add us.
    let _ = dev2.orchestrator.accept_conversation(&convo_id).await;
    let reset_requests_after_accept = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::RequestReset)
        .count();
    assert_eq!(
        reset_requests_after_accept, 0,
        "F-03: zero-leaf `leaves: []` must never vacuously satisfy nobody_else_can_add"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn f15_clear_needs_rejoin_retains_flag_when_durable_group_state_mismatches_crypto() {
    use crate::orchestrator::types::{ConversationState, GroupState};
    use e2e_harness::TestWorld;

    let mut world = TestWorld::new();
    let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    world.add_client_with_did("Alice", alice_did).await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let created = alice
        .orchestrator
        .create_group("f15-durable-mismatch", None, None)
        .await
        .expect("create group");
    let convo_id = created.conversation_id.clone();

    // Mark conversation NeedsRejoin and make durable GroupState.epoch diverge from crypto epoch (0).
    alice
        .storage
        .set_conversation_state(&convo_id, ConversationState::NeedsRejoin)
        .await
        .unwrap();
    alice.storage.mark_needs_rejoin(&convo_id).await.unwrap();
    alice
        .storage
        .set_group_state(&GroupState {
            group_id: created.group_id.clone(),
            conversation_id: convo_id.clone(),
            epoch: 99,
            members: vec![alice_did.to_string()],
        })
        .await
        .unwrap();

    let cleared = alice
        .orchestrator
        .clear_needs_rejoin_if_locally_healthy(&convo_id)
        .await;
    assert!(
        !cleared,
        "F-15: clear_needs_rejoin_if_locally_healthy must return false when durable GroupState mismatches crypto epoch"
    );
    assert!(
        alice.storage.has_rejoin_flag(&convo_id),
        "F-15: durable needs_rejoin flag must remain set on GroupState mismatch"
    );
    assert_eq!(
        alice
            .storage
            .get_conversation_state(&convo_id)
            .await
            .unwrap(),
        Some(ConversationState::NeedsRejoin)
    );
}
