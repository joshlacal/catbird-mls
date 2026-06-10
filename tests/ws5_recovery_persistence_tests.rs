//! WS-5 (2026-06-09 MLS stack improvement plan) regression tests.
//!
//! Pins three invariants:
//!
//! - **S1 / WS-5.1**: the deprecated `handle_group_reset` no longer performs
//!   an inline `join_or_rejoin` (no External Commit, no epoch advance) — it
//!   only records deferred-recovery state.
//! - **E7 / WS-5.4**: RecoveryTracker backoff/quarantine state is persisted
//!   write-through and hydrated on orchestrator init, with a 24 h TTL, so
//!   restart cannot reset rejoin backoff (the epoch re-inflation vector).
//! - **WS-5.3**: `force_delete_local` is crash-safe — a persisted intent row
//!   drives a startup reconcile sweep that finishes interrupted deletes.

#![allow(dead_code)]

mod e2e_harness;

use std::sync::Arc;

use catbird_mls::orchestrator::recovery::RecoveryTracker;
use catbird_mls::orchestrator::{
    constants, MLSOrchestrator, MLSStorageBackend, OrchestratorConfig, PendingLocalDelete,
    PersistedRecoveryBackoff, PersistedRecoveryState,
};
use e2e_harness::TestWorld;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Build a "restarted" orchestrator over the SAME mock storage / DS /
/// credentials as `world`'s client, with a fresh MLS context (fresh process,
/// same platform database). Mirrors what an app restart looks like to the
/// orchestrator core.
async fn restart_orchestrator(
    world: &TestWorld,
    name: &str,
) -> (
    MLSOrchestrator<
        e2e_harness::mock_storage::MockStorage,
        e2e_harness::mock_api_client::MockDeliveryService,
        e2e_harness::mock_credentials::MockCredentials,
        catbird_mls::MLSContext,
    >,
    std::path::PathBuf,
) {
    let client = world.client(name);
    let temp_dir = std::env::temp_dir().join(format!(
        "catbird_mls_ws5_restart_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");
    let db_path = temp_dir.join("mls.db");

    struct NoopKeychain;
    #[async_trait::async_trait]
    impl catbird_mls::KeychainAccess for NoopKeychain {
        async fn read(&self, _key: String) -> Result<Option<Vec<u8>>, catbird_mls::MLSError> {
            Ok(None)
        }
        async fn write(&self, _key: String, _value: Vec<u8>) -> Result<(), catbird_mls::MLSError> {
            Ok(())
        }
        async fn delete(&self, _key: String) -> Result<(), catbird_mls::MLSError> {
            Ok(())
        }
    }

    let mls_context = catbird_mls::MLSContext::new(
        db_path.to_string_lossy().to_string(),
        format!("restart-key-{name}"),
        Box::new(NoopKeychain),
    )
    .expect("failed to create restart MLSContext");

    let orchestrator = MLSOrchestrator::new(
        mls_context,
        Arc::new(client.storage.clone()),
        Arc::new(world.delivery_service().clone_as(&client.did)),
        Arc::new(client.credentials.clone()),
        OrchestratorConfig::default(),
    );
    orchestrator
        .initialize(&client.did)
        .await
        .expect("restart initialize failed");
    (orchestrator, temp_dir)
}

// ───────────────────────────────────────────────────────────────────────────
// WS-5.1 — handle_group_reset defers instead of committing inline
// ───────────────────────────────────────────────────────────────────────────

/// The deprecated `handle_group_reset` must not perform an External Commit or
/// advance the server epoch; it only records deferred-recovery state
/// (RESET_PENDING + needs_rejoin) exactly like `record_group_reset`.
#[tokio::test(flavor = "multi_thread")]
async fn handle_group_reset_records_deferred_state_without_external_commit() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.1 deferral", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let server_epoch_before = world
        .delivery_service()
        .conversation_epoch(&convo_id)
        .expect("conversation should exist on mock DS");

    let new_group_id =
        hex::decode("aabbccddeeff00112233445566778899").expect("fixture must be valid hex");
    #[allow(deprecated)]
    alice
        .orchestrator
        .handle_group_reset(&convo_id, new_group_id, 1)
        .await
        .expect("handle_group_reset should succeed as a pure record operation");

    // No External Commit was sent and the server epoch did not move.
    assert_eq!(
        world.delivery_service().external_commit_count(&convo_id),
        0,
        "S1 REGRESSION: deprecated handle_group_reset performed an inline External Commit"
    );
    assert_eq!(
        world.delivery_service().conversation_epoch(&convo_id),
        Some(server_epoch_before),
        "S1 REGRESSION: handle_group_reset advanced the server epoch"
    );

    // Deferred-recovery state was recorded.
    assert!(
        alice.storage.has_rejoin_flag(&convo_id),
        "handle_group_reset must flag needs_rejoin for the deferred-recovery loop"
    );
    let persisted = alice
        .storage
        .get_persisted_reset_pending(&convo_id)
        .expect("handle_group_reset must persist the RESET_PENDING payload");
    assert_eq!(
        persisted.new_group_id_hex,
        "aabbccddeeff00112233445566778899"
    );
    assert_eq!(persisted.reset_generation, 1);
}

// ───────────────────────────────────────────────────────────────────────────
// WS-5.4 — RecoveryTracker persistence across restart (invariant E7)
// ───────────────────────────────────────────────────────────────────────────

/// A failed rejoin attempt must write through to storage (per-convo entry +
/// global timestamp), and a re-created orchestrator on the same storage must
/// hydrate it: cooldown/global gates stay armed across restart.
#[tokio::test(flavor = "multi_thread")]
async fn rejoin_backoff_survives_orchestrator_restart() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.4 restart", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Drive a real failed rejoin: the mock DS has no published GroupInfo for
    // forced rejoin after we drop it, so force_rejoin fails and records a
    // failure. (get_group_info is published by create_group, so inject a
    // failure for the next call.)
    world.delivery_service().fail_next_get_group_info();
    let err = alice.orchestrator.force_rejoin(&convo_id).await;
    assert!(err.is_err(), "force_rejoin should fail via injected error");

    // Write-through happened.
    let entry = alice
        .storage
        .get_persisted_recovery_backoff(&convo_id)
        .expect("failed rejoin must persist a backoff entry (WS-5.4 write-through)");
    assert_eq!(entry.failed_rejoin_count, 1);
    assert!(entry.quarantined_until_ms.is_none());
    let drift = (now_ms() - entry.last_attempt_at_ms).abs();
    assert!(
        drift < 10_000,
        "last_attempt_at_ms should be ~now (drift {drift}ms)"
    );
    assert!(
        alice
            .storage
            .get_persisted_last_global_rejoin_at_ms()
            .is_some(),
        "global last-rejoin-attempt timestamp must persist"
    );

    // "Restart": new orchestrator over the same storage.
    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    {
        let tracker = restarted.recovery_tracker().lock().await;
        assert_eq!(
            tracker.failed_attempts(&convo_id),
            1,
            "E7 REGRESSION: restart erased the persisted failure count"
        );
        assert!(
            tracker.cooldown_remaining(&convo_id).is_some(),
            "E7 REGRESSION: per-convo rejoin cooldown not honored after restart"
        );
        assert!(
            tracker.should_skip(&convo_id),
            "rejoin gate must stay closed across restart"
        );
        assert!(
            tracker.should_skip("some-other-convo"),
            "global MIN_REJOIN_INTERVAL must stay armed across restart"
        );
    }
    let _ = std::fs::remove_dir_all(temp_dir);
}

/// Successful rejoin clears the conversation's persisted entry (E7 rule).
/// Exercised via the server-reset path, which must also clear the entry —
/// both call sites share the same storage write.
#[tokio::test(flavor = "multi_thread")]
async fn server_reset_clears_persisted_backoff_entry() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.4 clear", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    world.delivery_service().fail_next_get_group_info();
    let _ = alice.orchestrator.force_rejoin(&convo_id).await;
    assert!(alice
        .storage
        .get_persisted_recovery_backoff(&convo_id)
        .is_some());

    let new_group_id =
        hex::decode("00112233445566778899aabbccddeeff").expect("fixture must be valid hex");
    alice
        .orchestrator
        .record_group_reset(&convo_id, new_group_id, 1)
        .await
        .expect("record_group_reset failed");

    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff(&convo_id)
            .is_none(),
        "server reset is a fresh start — persisted backoff entry must be cleared"
    );
}

/// TTL expiry: persisted entries older than RECOVERY_BACKOFF_TTL are ignored
/// on hydration.
#[tokio::test(flavor = "multi_thread")]
async fn persisted_backoff_older_than_ttl_is_ignored_on_hydration() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let stale_ms = now_ms() - constants::RECOVERY_BACKOFF_TTL.as_millis() as i64 - 60_000;
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "stale-convo".to_string(),
            failed_rejoin_count: 3,
            last_attempt_at_ms: stale_ms,
            quarantined_until_ms: Some(
                stale_ms + constants::RECOVERY_BACKOFF_TTL.as_millis() as i64,
            ),
        });

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    {
        let tracker = restarted.recovery_tracker().lock().await;
        assert_eq!(
            tracker.failed_attempts("stale-convo"),
            0,
            "entries past the 24h TTL must be ignored on hydration"
        );
        assert!(!tracker.should_skip("stale-convo"));
    }
    let _ = std::fs::remove_dir_all(temp_dir);
}

/// A maxed-out conversation with a still-active quarantined_until keeps its
/// maxed-out gate after restart; an expired lockout is honored (count clamps
/// below max — never extended).
#[tokio::test(flavor = "multi_thread")]
async fn quarantine_lockout_honored_but_never_extended_on_hydration() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");

    let max = OrchestratorConfig::default().max_rejoin_attempts;

    // Active lockout: last attempt 1h ago, quarantined for 24h from then.
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "locked-convo".to_string(),
            failed_rejoin_count: max,
            last_attempt_at_ms: now_ms() - 3_600_000,
            quarantined_until_ms: Some(now_ms() + 23 * 3_600_000),
        });
    // Expired lockout: last attempt 2h ago (within TTL), lockout ended 1h ago.
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "released-convo".to_string(),
            failed_rejoin_count: max,
            last_attempt_at_ms: now_ms() - 2 * 3_600_000,
            quarantined_until_ms: Some(now_ms() - 3_600_000),
        });

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    {
        let tracker = restarted.recovery_tracker().lock().await;
        assert!(
            tracker.is_maxed_out("locked-convo"),
            "active quarantined_until must keep the maxed-out gate closed"
        );
        assert!(tracker.should_skip("locked-convo"));

        assert!(
            !tracker.is_maxed_out("released-convo"),
            "expired quarantined_until must not be extended by hydration"
        );
        assert_eq!(
            tracker.failed_attempts("released-convo"),
            max - 1,
            "expired lockout clamps the count just below max (one attempt re-opens)"
        );
        // 2h elapsed > 10m max backoff for (max-1) attempts → no cooldown left.
        assert!(
            tracker.cooldown_remaining("released-convo").is_none(),
            "hydration must honor already-elapsed cooldown, not restart it"
        );
    }
    let _ = std::fs::remove_dir_all(temp_dir);
}

/// Pure-tracker hydration unit checks for the E7 edge cases that don't need a
/// full orchestrator: zero-count entries and remaining-cooldown math.
#[test]
fn tracker_hydration_honors_remaining_cooldown() {
    let mut tracker = RecoveryTracker::new(3);
    let now = now_ms();
    let state = PersistedRecoveryState {
        entries: vec![
            PersistedRecoveryBackoff {
                conversation_id: "fresh-failure".into(),
                failed_rejoin_count: 1,
                // 10s ago: attempt-1 backoff is 30s → ~20s remaining.
                last_attempt_at_ms: now - 10_000,
                quarantined_until_ms: None,
            },
            PersistedRecoveryBackoff {
                conversation_id: "zero-count".into(),
                failed_rejoin_count: 0,
                last_attempt_at_ms: now,
                quarantined_until_ms: None,
            },
        ],
        last_global_rejoin_attempt_at_ms: Some(now - 10_000),
    };
    tracker.hydrate_from_persisted(&state, now);

    let remaining = tracker
        .cooldown_remaining("fresh-failure")
        .expect("cooldown must be honored");
    assert!(
        remaining <= std::time::Duration::from_secs(21),
        "hydration must not extend cooldown beyond the true remainder (got {remaining:?})"
    );
    assert!(remaining >= std::time::Duration::from_secs(15));

    assert_eq!(tracker.failed_attempts("zero-count"), 0);

    // Global gate: 10s elapsed of 30s MIN_REJOIN_INTERVAL → still armed.
    assert!(tracker.should_skip("any-other-convo"));
}

// ───────────────────────────────────────────────────────────────────────────
// WS-5.3 — crash-safe force_delete_local
// ───────────────────────────────────────────────────────────────────────────

/// A pending local-delete intent left behind by a crash is finished by the
/// startup reconcile sweep: storage rows removed, intent cleared.
#[tokio::test(flavor = "multi_thread")]
async fn startup_sweep_finishes_interrupted_local_delete() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.3 sweep", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Simulate a crash mid-delete: intent persisted, deletes never ran.
    alice.storage.seed_pending_local_delete(PendingLocalDelete {
        conversation_id: convo_id.clone(),
        group_id_hex: Some(convo.group_id.clone()),
    });
    assert!(
        alice.storage.has_group_state(&convo.group_id) || alice.storage.conversation_count() > 0
    );

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    let _ = &restarted;

    assert_eq!(
        alice.storage.pending_local_delete_count(),
        0,
        "reconcile sweep must clear the completed intent"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &convo_id)
            .await
            .unwrap()
            .is_none(),
        "reconcile sweep must finish the interrupted conversation delete"
    );
    assert!(
        !alice.storage.has_group_state(&convo.group_id),
        "reconcile sweep must finish the interrupted group-state delete"
    );
    let _ = std::fs::remove_dir_all(temp_dir);
}

/// Normal force_delete_local path: intent is written and then cleared, so a
/// healthy run leaves no pending rows behind.
#[tokio::test(flavor = "multi_thread")]
async fn force_delete_local_clears_its_intent() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.3 intent", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Reach force_delete_local through the public leave path is overkill;
    // drive it via sync's stale-conversation cleanup by deleting the convo
    // on the DS and syncing.
    world
        .delivery_service()
        .remove_conversation_for_test(&convo_id);
    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("sync should succeed");

    assert_eq!(
        alice.storage.pending_local_delete_count(),
        0,
        "force_delete_local must clear its intent after completing"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &convo_id)
            .await
            .unwrap()
            .is_none(),
        "stale conversation should be locally deleted by sync"
    );
}
