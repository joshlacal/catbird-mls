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
//!
//! Private-operation write-failure cases live in the native library test
//! modules `local_delete_persistence_tests` and `quarantine_persistence_tests`;
//! the public/startup replay cases remain here.

#![allow(dead_code)]

mod e2e_harness;
#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use std::sync::Arc;

use catbird_mls::orchestrator::recovery::RecoveryTracker;
use catbird_mls::orchestrator::{
    constants, ConversationState, CredentialStore, IncomingEnvelope, MLSOrchestrator,
    MLSStorageBackend, OrchestratorConfig, OrchestratorError, PendingLocalDelete,
    PersistedRecoveryBackoff, PersistedRecoveryState, ResetRecordOutcome,
};
use e2e_harness::TestWorld;
#[path = "support/ws5_recovery.rs"]
mod ws5_recovery_support;
use ws5_recovery_support::{FailingCrypto, RecordingObserver};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn encode_local_delete_authority_v2(owner_user_did: &str, group_id: &str, epoch: u64) -> String {
    let payload = serde_json::json!({
        "owner_user_did": owner_user_did,
        "groups": [{
            "group_id_hex": group_id,
            "epoch": epoch,
        }],
        "group_state_keys": [group_id],
        "conversation": {
            "group_id": group_id,
            "epoch": epoch,
        },
        "reset": null,
    });
    let mut encoded = b"CBLD\x02".to_vec();
    encoded.extend(serde_json::to_vec(&payload).expect("encode v2 delete authority fixture"));
    hex::encode(encoded)
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
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let temp_path = temp_dir.into_path();
    let db_path = temp_path.join("mls.db");

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
    epoch_secret_test_support::install(&mls_context);

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
    (orchestrator, temp_path)
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

/// A partial write must commit the stricter per-conversation backoff before
/// the shorter global stamp. If the global write then fails, restart must
/// still hydrate the escalating 2m/10m/24h gate instead of permitting one
/// attempt every global-minimum interval.
#[tokio::test(flavor = "multi_thread")]
async fn partial_global_write_failure_preserves_per_conversation_backoff_on_restart() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WS-5.4 partial write", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    alice.storage.fail_next_set_last_global_rejoin_attempt_at();
    world.delivery_service().fail_next_get_group_info();
    let error = alice
        .orchestrator
        .force_rejoin(&convo_id)
        .await
        .expect_err("the injected global persistence failure must propagate");
    assert!(error.to_string().contains("global recovery timestamp"));

    let persisted = alice
        .storage
        .get_persisted_recovery_backoff(&convo_id)
        .expect("the stricter per-conversation row must commit before the global stamp");
    assert_eq!(persisted.failed_rejoin_count, 1);
    assert!(
        alice
            .storage
            .get_persisted_last_global_rejoin_at_ms()
            .is_none(),
        "test precondition: injected global write must not commit"
    );

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    let tracker = restarted.recovery_tracker().lock().await;
    assert_eq!(tracker.failed_attempts(&convo_id), 1);
    assert!(
        tracker.cooldown_remaining(&convo_id).is_some(),
        "restart must retain the stricter per-conversation cooldown after partial write"
    );
    drop(tracker);
    drop(temp_dir);
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
    // R-1 (Swift twin parity): the TTL-rejected entry must also be DELETED
    // from storage, not just ignored — a kept row would resurrect if the
    // wall clock later regressed.
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff("stale-convo")
            .is_none(),
        "R-1 REGRESSION: TTL-rejected backoff row survived hydration"
    );
    let _ = std::fs::remove_dir_all(temp_dir);
}

/// R-1: hydration deletes every persisted row it rejects (TTL-expired AND
/// future-dated) while keeping valid rows intact. Without the delete, the
/// future-dated drop (FIX-8) re-logs its warning on every restart because
/// the row survives, and an expired row can resurrect on clock regression.
#[tokio::test(flavor = "multi_thread")]
async fn hydration_deletes_rejected_rows_and_keeps_valid_rows() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");

    let ttl_ms = constants::RECOVERY_BACKOFF_TTL.as_millis() as i64;
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "expired-convo".to_string(),
            failed_rejoin_count: 2,
            last_attempt_at_ms: now_ms() - ttl_ms - 60_000,
            quarantined_until_ms: None,
        });
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "future-convo".to_string(),
            failed_rejoin_count: 3,
            // Written "one hour from now": the wall clock stepped backwards.
            last_attempt_at_ms: now_ms() + 3_600_000,
            quarantined_until_ms: Some(now_ms() + 25 * 3_600_000),
        });
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: "valid-convo".to_string(),
            failed_rejoin_count: 1,
            last_attempt_at_ms: now_ms() - 10_000,
            quarantined_until_ms: None,
        });

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    {
        let tracker = restarted.recovery_tracker().lock().await;
        assert_eq!(tracker.failed_attempts("expired-convo"), 0);
        assert_eq!(tracker.failed_attempts("future-convo"), 0);
        assert_eq!(
            tracker.failed_attempts("valid-convo"),
            1,
            "valid entry must hydrate normally"
        );
    }
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff("expired-convo")
            .is_none(),
        "R-1 REGRESSION: TTL-rejected row survived hydration"
    );
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff("future-convo")
            .is_none(),
        "R-1 REGRESSION: future-dated row survived hydration — its drop \
         warning would repeat on every restart"
    );
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff("valid-convo")
            .is_some(),
        "hydration must not delete rows it accepted"
    );
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
    let rejected = tracker.hydrate_from_persisted(&state, now);
    assert_eq!(
        rejected,
        vec!["zero-count".to_string()],
        "zero-count entries carry no state and must be rejected for deletion"
    );

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
        group_id_hex: Some(encode_local_delete_authority_v2(
            &alice.did,
            &convo.group_id,
            convo.epoch,
        )),
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

#[tokio::test(flavor = "multi_thread")]
async fn legacy_delete_replays_without_conversation_row_and_removes_group_state() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("legacy row already gone", None, None)
        .await
        .expect("create group");

    alice.storage.seed_pending_local_delete(PendingLocalDelete {
        conversation_id: convo.conversation_id.clone(),
        group_id_hex: Some(convo.group_id.clone()),
    });
    alice
        .storage
        .delete_conversations(&alice.did, &[&convo.conversation_id])
        .await
        .expect("simulate conversation row deleted before crash");
    assert!(alice.storage.has_group_state(&convo.group_id));

    let (_restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        !alice.storage.has_group_state(&convo.group_id),
        "legacy captured group id must remain cleanup authority after its conversation row is gone"
    );
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_delete_treats_absent_mls_group_id_as_group_state_key() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("legacy MLS group already gone", None, None)
        .await
        .expect("create group");

    alice.storage.seed_pending_local_delete(PendingLocalDelete {
        conversation_id: convo.conversation_id.clone(),
        group_id_hex: Some(convo.group_id.clone()),
    });
    alice
        .orchestrator
        .mls_context()
        .delete_group(hex::decode(&convo.group_id).expect("group id"))
        .expect("simulate MLS group deleted before crash");
    alice
        .storage
        .delete_conversations(&alice.did, &[&convo.conversation_id])
        .await
        .expect("simulate conversation row deleted before crash");
    assert!(alice.storage.has_group_state(&convo.group_id));

    let (_restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        !alice.storage.has_group_state(&convo.group_id),
        "GroupNotFound replay must still delete the legacy group-id-keyed state row"
    );
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_orphan_without_mapping_clears_stale_recovery_rows() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("legacy orphan recovery", None, None)
        .await
        .expect("create group");
    let conversation_id = convo.conversation_id.clone();

    alice.storage.seed_pending_local_delete(PendingLocalDelete {
        conversation_id: conversation_id.clone(),
        group_id_hex: Some(convo.group_id.clone()),
    });
    alice
        .storage
        .delete_conversations(&alice.did, &[&conversation_id])
        .await
        .expect("simulate mapping deleted before crash");
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: conversation_id.clone(),
            failed_rejoin_count: 3,
            last_attempt_at_ms: now_ms(),
            quarantined_until_ms: Some(now_ms() + 60_000),
        });
    alice
        .storage
        .mark_needs_rejoin(&conversation_id)
        .await
        .expect("seed rejoin");
    // Seed reset authority before quarantine: under ruling 2a the authority
    // commit is itself a quarantine exit, so seeding in the other order would
    // clear the row this test needs. The resulting both-set row is the legacy
    // artifact whose survival across restart is what is under test here.
    alice
        .storage
        .mark_reset_pending(&conversation_id, &hex::encode(vec![0x7a; 32]), 11, now_ms())
        .await
        .expect("seed reset");
    alice
        .storage
        .mark_quarantined(&conversation_id, "legacy-orphan", now_ms())
        .await
        .expect("seed quarantine");
    let rejoin_flag_before_restart = alice.storage.has_rejoin_flag(&conversation_id);

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;

    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff(&conversation_id)
            .is_some(),
        "unfenced legacy authority must not clear a newer recovery lifecycle"
    );
    assert!(
        alice
            .storage
            .get_persisted_quarantine(&conversation_id)
            .is_some(),
        "unfenced legacy authority must not clear quarantine"
    );
    assert_eq!(
        alice.storage.has_rejoin_flag(&conversation_id),
        rejoin_flag_before_restart,
        "legacy orphan cleanup must not rewrite the current conversation state"
    );
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .is_some(),
        "unfenced legacy authority must not clear reset-generation state"
    );
    assert_eq!(
        restarted
            .recovery_tracker()
            .lock()
            .await
            .failed_attempts(&conversation_id),
        3,
        "preserved recovery state must hydrate after legacy orphan cleanup"
    );
    let _ = std::fs::remove_dir_all(temp_dir);
}

// ───────────────────────────────────────────────────────────────────────────
// WS-5 review fixes (2026-06-10)
// ───────────────────────────────────────────────────────────────────────────

/// FIX-1: clearing a STALE needs_rejoin flag (local group already caught up)
/// is pure housekeeping — it must NOT arm the global rejoin gate, must NOT
/// record a per-convo "successful rejoin", and must NOT persist a
/// global-attempt stamp. A rejoin on another conversation immediately after
/// must be permitted.
#[tokio::test(flavor = "multi_thread")]
async fn stale_rejoin_flag_clear_does_not_arm_global_gate() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("FIX-1 stale flag", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Align the server listing epoch with the local group epoch so the flag
    // below is genuinely STALE (the local group is fully caught up).
    let local_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&convo.group_id).unwrap())
        .expect("local group must exist");
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&convo_id, local_epoch);

    // Flag needs_rejoin even though the local group is fully caught up —
    // exactly the stale-flag situation the sync housekeeping branch handles.
    alice
        .storage
        .mark_needs_rejoin(&convo_id)
        .await
        .expect("mark_needs_rejoin failed");
    assert!(alice.storage.has_rejoin_flag(&convo_id));

    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("sync should succeed");

    assert!(
        !alice.storage.has_rejoin_flag(&convo_id),
        "stale needs_rejoin flag must be cleared by the sync housekeeping branch"
    );
    {
        let tracker = alice.orchestrator.recovery_tracker().lock().await;
        assert!(
            !tracker.should_skip("some-other-convo"),
            "FIX-1 REGRESSION: stale-flag housekeeping armed the global \
             MIN_REJOIN_INTERVAL gate — re-armed every 5s sync pass it never opens"
        );
        assert!(
            tracker.success_cooldown_remaining(&convo_id).is_none(),
            "stale-flag housekeeping must not record a per-convo successful rejoin"
        );
    }
    assert!(
        alice
            .storage
            .get_persisted_last_global_rejoin_at_ms()
            .is_none(),
        "FIX-1 REGRESSION: stale-flag housekeeping persisted a global-attempt \
         stamp — the spurious gate would survive restart"
    );
}

/// FIX-1: when the flag-clear write itself fails, the failure must escalate
/// through the observer (operation = clear_rejoin_flag) and the tracker
/// housekeeping must be skipped for that pass (clearing tracker state while
/// the flag persists would loop every sync pass).
#[tokio::test(flavor = "multi_thread")]
async fn failing_clear_rejoin_flag_escalates_and_skips_tracker_clear() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("FIX-1 escalation", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    // Seed real failure-tracking state via an injected failed rejoin.
    world.delivery_service().fail_next_get_group_info();
    let _ = alice.orchestrator.force_rejoin(&convo_id).await;
    assert_eq!(
        alice
            .orchestrator
            .recovery_tracker()
            .lock()
            .await
            .failed_attempts(&convo_id),
        1
    );
    assert!(alice
        .storage
        .get_persisted_recovery_backoff(&convo_id)
        .is_some());

    // Stale flag + failing clear (server listing epoch aligned with local so
    // the stale-housekeeping branch fires).
    let local_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&convo.group_id).unwrap())
        .expect("local group must exist");
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&convo_id, local_epoch);
    alice.storage.mark_needs_rejoin(&convo_id).await.unwrap();
    alice.storage.fail_next_clear_rejoin_flag();

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("sync should succeed");

    let escalations = observer.storage_failures.lock().unwrap().clone();
    assert!(
        escalations
            .iter()
            .any(|(cid, op, _)| cid == &convo_id && op == "clear_rejoin_flag"),
        "failing clear_rejoin_flag must escalate via the observer, got {escalations:?}"
    );
    assert_eq!(
        alice
            .orchestrator
            .recovery_tracker()
            .lock()
            .await
            .failed_attempts(&convo_id),
        1,
        "tracker clear must be SKIPPED when the flag-clear write failed"
    );
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff(&convo_id)
            .is_some(),
        "persisted backoff row must survive when the flag-clear write failed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quarantine_entry_projection_serializes_with_reset_authority() {
    let did = "did:plc:alice";
    let convo_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let credentials = e2e_harness::mock_credentials::MockCredentials::new();
    let ds = e2e_harness::mock_api_client::MockDeliveryService::new(did);
    let orchestrator = MLSOrchestrator::new(
        Arc::new(FailingCrypto::peer_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    storage
        .ensure_conversation_exists(did, &convo_id, &convo_id)
        .await
        .expect("seed conversation");

    for i in 0..2 {
        let _ = orchestrator
            .process_incoming(&IncomingEnvelope {
                canonical_entry_json: None,
                conversation_id: convo_id.clone(),
                sender_did: "did:plc:mallory".to_string(),
                ciphertext: format!("entry-race-{i}").into_bytes(),
                timestamp: chrono::Utc::now(),
                server_message_id: Some(format!("entry-race-{i}")),
                server_epoch: None,
                server_sequence: None,
            })
            .await;
    }
    let state_barrier = storage.pause_next_conversation_state_write_any(&convo_id);
    let third_frame = IncomingEnvelope {
        canonical_entry_json: None,
        conversation_id: convo_id.clone(),
        sender_did: "did:plc:mallory".to_string(),
        ciphertext: b"entry-race-2".to_vec(),
        timestamp: chrono::Utc::now(),
        server_message_id: Some("entry-race-2".to_string()),
        server_epoch: None,
        server_sequence: None,
    };
    let enter = orchestrator.process_incoming(&third_frame);
    let reset = async {
        state_barrier.wait_until_entered().await;
        let mut recording =
            Box::pin(orchestrator.record_group_reset_with_outcome(&convo_id, vec![0x7c; 16], 20));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut recording)
                .await
                .is_err(),
            "reset must wait while quarantine entry owns the transition gate"
        );
        state_barrier.release();
        recording.await
    };
    let (_, reset_result) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(enter, reset)
    })
    .await
    .expect("quarantine entry race timed out");
    assert_eq!(
        reset_result.expect("record reset"),
        ResetRecordOutcome::Recorded
    );
    assert_eq!(
        storage
            .get_persisted_reset_pending(&convo_id)
            .expect("reset remains authoritative")
            .reset_generation,
        20
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quarantine_exit_projection_serializes_with_reset_authority() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use catbird_mls::orchestrator::{GroupState, MlsCryptoContext, QuarantineReason};
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
        ("Charlie", "did:plc:cccccccccccccccccccccccc"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let charlie = world.client("Charlie");
    let created = alice
        .orchestrator
        .create_group(
            "quarantine exit race",
            Some(&[bob.did.clone(), charlie.did.clone()]),
            None,
        )
        .await
        .unwrap();
    let convo_id = created.conversation_id;
    let group = hex::decode(created.group_id).unwrap();
    let identity =
        |client: &e2e_harness::TestClient, device: String| format!("{}#{device}", client.did);
    let bob_identity = identity(
        bob,
        bob.orchestrator.require_actor_device_id().await.unwrap(),
    );
    let charlie_identity = identity(
        charlie,
        charlie
            .orchestrator
            .require_actor_device_id()
            .await
            .unwrap(),
    );
    let mut packages = Vec::new();
    for (client, scoped) in [(bob, &bob_identity), (charlie, &charlie_identity)] {
        packages.push(catbird_mls::KeyPackageData {
            data: client
                .orchestrator
                .mls_context()
                .create_key_package(scoped.as_bytes().to_vec())
                .unwrap()
                .key_package_data,
        });
    }
    let added = alice
        .orchestrator
        .mls_context()
        .add_members(group.clone(), packages)
        .unwrap();
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group.clone())
        .unwrap();
    bob.orchestrator
        .mls_context()
        .process_welcome(added.welcome_data, bob_identity.into_bytes(), None)
        .unwrap();
    let projection = GroupState {
        conversation_id: convo_id.clone(),
        group_id: hex::encode(&group),
        epoch: 1,
        members: alice
            .orchestrator
            .mls_context()
            .group_member_identities(group.clone())
            .unwrap()
            .into_iter()
            .map(|id| String::from_utf8(id).unwrap())
            .collect(),
    };
    alice.storage.set_group_state(&projection).await.unwrap();
    alice.storage.set_epoch_pair_for_test(&convo_id, 1, 1);
    let since = now_ms();
    alice
        .storage
        .mark_quarantined(
            &convo_id,
            QuarantineReason::RepeatedFramingFailures.tag(),
            since,
        )
        .await
        .unwrap();
    alice
        .storage
        .set_conversation_state(
            &convo_id,
            ConversationState::Quarantined {
                reason: QuarantineReason::RepeatedFramingFailures,
                since_ms: since,
            },
        )
        .await
        .unwrap();
    // Entry is covered separately above. Rehydrate real crypto plus durable
    // quarantine so this race isolates the reachable healthy-peer exit path.
    world.restart_client("Alice").await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let orchestrator = &alice.orchestrator;
    let storage = &alice.storage;
    assert!(orchestrator
        .get_conversation_quarantine_state(&convo_id)
        .await
        .is_some());
    let aad = serde_json::json!({
        "conversationId":STANDARD.encode(uuid::Uuid::parse_str(&convo_id).unwrap().as_bytes()),
        "generation":0,"protocolVersion":"1","transitionId":STANDARD.encode(uuid::Uuid::new_v4().as_bytes()),
        "prior":{"conversationId":STANDARD.encode(uuid::Uuid::parse_str(&convo_id).unwrap().as_bytes()),
            "generation":0,"stateVersion":1,"epoch":1,"lifecycle":"active","groupId":STANDARD.encode(&group),
            "confirmationTag":STANDARD.encode(bob.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),
            "groupContextHash":STANDARD.encode(bob.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap())},
    });
    let commit = bob
        .orchestrator
        .mls_context()
        .remove_members_with_aad(
            group.clone(),
            vec![charlie_identity.into_bytes()],
            Some(catbird_mls::orchestrator::canonical_commit_aad_bytes(&aad).unwrap()),
        )
        .unwrap()
        .commit_data;
    bob.orchestrator
        .mls_context()
        .merge_pending_commit(group.clone())
        .unwrap();
    let envelope = IncomingEnvelope {
        canonical_entry_json: None,
        conversation_id: convo_id.clone(),
        sender_did: bob.did.clone(),
        ciphertext: commit,
        timestamp: chrono::Utc::now(),
        server_message_id: Some(uuid::Uuid::new_v4().to_string()),
        server_epoch: Some(2),
        server_sequence: Some(2),
    };
    let state_barrier =
        storage.pause_next_conversation_state_write(&convo_id, ConversationState::Active);
    let exit = orchestrator.process_incoming(&envelope);
    let reset = async {
        state_barrier.wait_until_entered().await;
        let mut recording =
            Box::pin(orchestrator.record_group_reset_with_outcome(&convo_id, vec![0x7d; 32], 21));
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), &mut recording).await.is_err(),
            "reset must wait while the durable healthy-peer quarantine exit owns the transition gate");
        assert_eq!(
            orchestrator.mls_context().get_epoch(group.clone()).unwrap(),
            2,
            "the healthy peer Commit is already native-durable while exit owns the gate"
        );
        assert_eq!(
            storage
                .get_group_state(&hex::encode(&group))
                .await
                .unwrap()
                .unwrap()
                .epoch,
            2,
            "the app epoch projection precedes quarantine exit"
        );
        state_barrier.release();
        recording.await
    };
    let (exit_result, reset_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(exit, reset)
        })
        .await
        .expect("quarantine exit race timed out");
    exit_result.expect("process durable healthy peer Commit and exit quarantine");
    assert_eq!(
        reset_result.expect("record reset"),
        ResetRecordOutcome::Recorded
    );
    assert_eq!(
        storage
            .get_persisted_reset_pending(&convo_id)
            .expect("reset remains authoritative")
            .reset_generation,
        21
    );
    assert!(matches!(
        storage.get_conversation_state(&convo_id).await.unwrap(),
        Some(ConversationState::ResetPending {
            reset_generation: 21,
            ..
        })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn decrypt_failure_projection_preserves_reset_authority() {
    let did = "did:plc:alice";
    let convo_id = "cccccccccccccccccccccccccccccccc".to_string();
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let credentials = e2e_harness::mock_credentials::MockCredentials::new();
    let ds = e2e_harness::mock_api_client::MockDeliveryService::new(did);
    let orchestrator = MLSOrchestrator::new(
        Arc::new(FailingCrypto::self_bad()),
        Arc::new(storage.clone()),
        Arc::new(ds.clone_as(did)),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(did).await.expect("initialize");
    storage
        .ensure_conversation_exists(did, &convo_id, &convo_id)
        .await
        .expect("seed conversation");
    orchestrator
        .record_group_reset(&convo_id, vec![0x7e; 16], 22)
        .await
        .expect("record reset");

    for i in 0..3 {
        let _ = orchestrator
            .process_incoming(&IncomingEnvelope {
                canonical_entry_json: None,
                conversation_id: convo_id.clone(),
                sender_did: "did:plc:mallory".to_string(),
                ciphertext: format!("self-bad-{i}").into_bytes(),
                timestamp: chrono::Utc::now(),
                server_message_id: Some(format!("self-bad-{i}")),
                server_epoch: None,
                server_sequence: None,
            })
            .await;
    }

    assert!(matches!(
        orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&convo_id),
        Some(ConversationState::ResetPending {
            reset_generation: 22,
            ..
        })
    ));
    assert!(storage.has_rejoin_flag(&convo_id));
}

/// Ruling 2a (2026-08-15): a server reset is a quarantine exit, and the exit
/// belongs to the `mark_reset_pending` authority commit rather than to the
/// separate `clear_quarantine` call issued after it. The Android lane found
/// that the old warn-only backstop minted the both-set row on its own — no
/// crash required, just a failed clear — and such a row rehydrates quarantined
/// forever because the replayed reset event dedupes on generation before
/// reaching the clear again. Fail that separate call and the conversation must
/// still land ResetPending with no persisted quarantine residue.
#[tokio::test(flavor = "multi_thread")]
async fn server_reset_exits_quarantine_even_when_the_backstop_clear_fails() {
    let did = "did:plc:alice";
    let convo_id = "deadbeefdeadbeefdeadbeefdeadbeef".to_string();
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
        .ensure_conversation_exists(did, &convo_id, &convo_id)
        .await
        .expect("seed explicit conversation-to-group mapping");

    let observer = Arc::new(RecordingObserver::default());
    orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    // Three peer-bad frames trip Layer-3 quarantine, arming both the in-memory
    // tracker and the persisted row.
    for i in 0..3 {
        let envelope = IncomingEnvelope {
            canonical_entry_json: None,
            conversation_id: convo_id.clone(),
            sender_did: "did:plc:mallory".to_string(),
            ciphertext: format!("peer-bad-frame-{i}").into_bytes(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some(format!("bad-frame-{i}")),
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
        "three peer-bad frames must enter Layer-3 quarantine (test precondition)"
    );
    assert!(
        storage.get_persisted_quarantine(&convo_id).is_some(),
        "quarantine entry must have persisted a row (test precondition)"
    );

    // The exact minting path: the authority commit lands, the separate
    // backstop clear fails.
    storage.fail_next_clear_quarantine();
    let new_group_id = vec![0x5a; 32];
    orchestrator
        .record_group_reset(&convo_id, new_group_id.clone(), 9)
        .await
        .expect("record_group_reset failed");

    assert!(
        storage.get_persisted_quarantine(&convo_id).is_none(),
        "RULING 2a REGRESSION: a failed backstop clear minted a row that is \
         both reset-pending and quarantined"
    );
    assert!(
        orchestrator
            .get_conversation_quarantine_state(&convo_id)
            .await
            .is_none(),
        "server reset must exit quarantine in memory too"
    );
    match storage
        .get_conversation_state(&convo_id)
        .await
        .expect("read durable state")
    {
        Some(ConversationState::ResetPending {
            new_group_id: target,
            reset_generation,
            ..
        }) => {
            assert_eq!(target, hex::encode(&new_group_id));
            assert_eq!(reset_generation, 9);
        }
        other => panic!("expected durable ResetPending, got {other:?}"),
    }

    // The backstop still escalates rather than warning, so a pre-amendment
    // backend that leaves residue is visible instead of silent.
    let escalations = observer.storage_failures.lock().unwrap().clone();
    assert!(
        escalations
            .iter()
            .any(|(cid, op, _)| cid == &convo_id && op == "clear_quarantine"),
        "failing backstop clear_quarantine must escalate, got {escalations:?}"
    );
}

/// FIX-8: entries future-dated by a backward wall-clock step are invalid
/// persisted state — they must be dropped on hydration (TTL gate can't fire
/// on negative elapsed, and honoring them would restart the full cooldown
/// every boot / pin quarantine far past 24h of real time). Same policy for
/// the global stamp.
#[test]
fn future_dated_persisted_state_dropped_on_hydration() {
    let mut tracker = RecoveryTracker::new(3);
    let now = now_ms();
    let state = PersistedRecoveryState {
        entries: vec![PersistedRecoveryBackoff {
            conversation_id: "future-convo".into(),
            failed_rejoin_count: 3,
            // Written "one hour from now": the wall clock stepped backwards.
            last_attempt_at_ms: now + 3_600_000,
            quarantined_until_ms: Some(now + 25 * 3_600_000),
        }],
        last_global_rejoin_attempt_at_ms: Some(now + 3_600_000),
    };
    let rejected = tracker.hydrate_from_persisted(&state, now);
    assert_eq!(
        rejected,
        vec!["future-convo".to_string()],
        "future-dated entry must be reported rejected so the caller deletes \
         the row (otherwise the drop warning repeats every restart)"
    );

    assert_eq!(
        tracker.failed_attempts("future-convo"),
        0,
        "FIX-8 REGRESSION: future-dated backoff entry must be dropped"
    );
    assert!(!tracker.is_maxed_out("future-convo"));
    assert!(
        !tracker.should_skip("future-convo"),
        "future-dated entry must not gate"
    );
    assert!(
        !tracker.should_skip("any-other-convo"),
        "FIX-8 REGRESSION: future-dated global stamp must be dropped, not \
         honored as an armed MIN_REJOIN_INTERVAL gate"
    );
}

/// FIX-9 (tracker level): a maxed-out lockout that lapses while the process
/// is running stops gating at runtime — is_maxed_out/should_skip open the
/// moment the lockout lapses, and expire_lapsed_lockout clamps the count to
/// max-1 so exactly one fresh attempt re-opens. Exercises the clamp the
/// hydration-only path could never reach for self-written entries (their
/// lockout expiry coincides with the 24h TTL drop).
#[tokio::test]
async fn runtime_lockout_expiry_reopens_one_attempt() {
    let max = 3;
    let mut tracker = RecoveryTracker::new(max);
    let now = now_ms();
    // Hydrate a maxed entry whose lockout lapses 200ms from now (a
    // long-running process awaiting expiry, compressed for the test).
    let rejected = tracker.hydrate_from_persisted(
        &PersistedRecoveryState {
            entries: vec![PersistedRecoveryBackoff {
                conversation_id: "locked".into(),
                failed_rejoin_count: max,
                last_attempt_at_ms: now - 3_600_000,
                quarantined_until_ms: Some(now + 200),
            }],
            last_global_rejoin_attempt_at_ms: None,
        },
        now,
    );
    assert!(
        rejected.is_empty(),
        "an active lockout within TTL is valid state — must not be rejected"
    );

    assert!(
        tracker.is_maxed_out("locked"),
        "lockout active: gate closed"
    );
    assert!(tracker.should_skip("locked"));
    assert!(
        tracker.expire_lapsed_lockout("locked").is_none(),
        "no clamp while the lockout is active"
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(
        !tracker.is_maxed_out("locked"),
        "FIX-9 REGRESSION: lapsed lockout still gates at runtime — a \
         long-running process would be locked out for its whole lifetime"
    );
    assert!(
        tracker.cooldown_remaining("locked").is_none(),
        "post-lockout entry behaves as max-1 attempts with a long-elapsed \
         cooldown"
    );
    assert!(!tracker.should_skip("locked"));

    let (clamped, last_attempt_at_ms) = tracker
        .expire_lapsed_lockout("locked")
        .expect("lapsed lockout must clamp");
    assert_eq!(clamped, max - 1, "exactly one fresh attempt re-opens");
    let drift = (now_ms() - 3_600_000 - last_attempt_at_ms).abs();
    assert!(
        drift < 10_000,
        "clamp must report the original last-attempt time for the persisted \
         row (drift {drift}ms)"
    );
    assert_eq!(tracker.failed_attempts("locked"), max - 1);
    assert!(
        tracker.expire_lapsed_lockout("locked").is_none(),
        "clamp is one-shot"
    );
}

/// FIX-9 (orchestrator level): the rejoin gate itself honors runtime expiry —
/// a force_rejoin during the lockout is suppressed with max-attempts, and the
/// same call after the lockout lapses proceeds to a real attempt (failing
/// with the injected server error instead of the gate error).
#[tokio::test(flavor = "multi_thread")]
async fn rejoin_gate_reopens_after_runtime_lockout_expiry() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("FIX-9 gate reopen", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    let max = OrchestratorConfig::default().max_rejoin_attempts;
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: convo_id.clone(),
            failed_rejoin_count: max,
            last_attempt_at_ms: now_ms() - 3_600_000,
            quarantined_until_ms: Some(now_ms() + 2_000),
        });

    let (restarted, temp_dir) = restart_orchestrator(&world, "Alice").await;

    // Lockout still active: suppressed by the maxed-out gate.
    let err = restarted
        .force_rejoin(&convo_id)
        .await
        .expect_err("rejoin must be suppressed during the lockout");
    assert!(
        err.to_string().contains("max attempts"),
        "expected max-attempts suppression, got: {err}"
    );

    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;

    // Lockout lapsed: the gate clamps to max-1 and lets one attempt through,
    // which then fails with the injected server error (not the gate).
    world.delivery_service().fail_next_get_group_info();
    let err = restarted
        .force_rejoin(&convo_id)
        .await
        .expect_err("attempt should fail via injected server error");
    assert!(
        !err.to_string().contains("max attempts"),
        "FIX-9 REGRESSION: gate still closed after the lockout lapsed: {err}"
    );
    let _ = std::fs::remove_dir_all(temp_dir);
}
