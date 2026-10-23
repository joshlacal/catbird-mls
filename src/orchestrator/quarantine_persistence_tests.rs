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
