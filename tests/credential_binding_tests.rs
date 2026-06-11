//! WS-3 stage 1 integration tests: warn-only credential binding (ADR-009 D3)
//! and sequencer equivocation detection (ADR-009 D8 / backlog E3).
//!
//! Uses the TestWorld/TestClient harness plus two mock extensions:
//!   - `MockDeliveryService::redirect_key_packages_for_test` — serve another
//!     user's key package for a requested DID (malicious-DS simulation);
//!   - `MockDeliveryService::issue_external_commit_receipts_for_test` — return
//!     `SequencerReceipt`s from `process_external_commit`.
//!
//! Stage-1 contract under test: mismatches/equivocations are LOGGED and
//! ESCALATED via `OrchestratorEventObserver`, and the operation still
//! succeeds (warn-and-allow; no enforcement).

#![allow(dead_code)]

mod e2e_harness;

use std::sync::{Arc, Mutex};

use catbird_mls::orchestrator::event_observer::OrchestratorEventObserver;
use catbird_mls::orchestrator::{IncomingEnvelope, MLSStorageBackend, SequencerReceipt};
use e2e_harness::TestWorld;

// ---------------------------------------------------------------------------
// Recording observer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CredentialWarning {
    convo_id: String,
    operation: String,
    expected_did: String,
    claimed_identity: String,
    reason: String,
}

#[derive(Debug, Clone)]
struct EquivocationEvent {
    convo_id: String,
    epoch: i32,
    stored_commit_hash_hex: String,
    new_commit_hash_hex: String,
    sequencer_did: String,
}

/// Test observer recording WS-3 escalations.
#[derive(Default)]
struct RecordingObserver {
    credential_warnings: Mutex<Vec<CredentialWarning>>,
    equivocations: Mutex<Vec<EquivocationEvent>>,
}

impl RecordingObserver {
    fn credential_warnings(&self) -> Vec<CredentialWarning> {
        self.credential_warnings.lock().unwrap().clone()
    }

    fn equivocations(&self) -> Vec<EquivocationEvent> {
        self.equivocations.lock().unwrap().clone()
    }
}

impl OrchestratorEventObserver for RecordingObserver {
    fn on_credential_binding_warning(
        &self,
        convo_id: &str,
        operation: &str,
        expected_did: &str,
        claimed_identity: &str,
        reason: &str,
    ) {
        self.credential_warnings
            .lock()
            .unwrap()
            .push(CredentialWarning {
                convo_id: convo_id.to_string(),
                operation: operation.to_string(),
                expected_did: expected_did.to_string(),
                claimed_identity: claimed_identity.to_string(),
                reason: reason.to_string(),
            });
    }

    fn on_sequencer_equivocation(
        &self,
        convo_id: &str,
        epoch: i32,
        stored_commit_hash_hex: &str,
        new_commit_hash_hex: &str,
        sequencer_did: &str,
    ) {
        self.equivocations.lock().unwrap().push(EquivocationEvent {
            convo_id: convo_id.to_string(),
            epoch,
            stored_commit_hash_hex: stored_commit_hash_hex.to_string(),
            new_commit_hash_hex: new_commit_hash_hex.to_string(),
            sequencer_did: sequencer_did.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// (a) Matching credential → no warning
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn matching_credential_produces_no_warning() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("cred-bind-clean", None, None)
        .await
        .expect("create_group failed");

    alice
        .orchestrator
        .add_members(&convo.group_id, &[bob_did])
        .await
        .expect("add_members with genuine key package failed");

    assert!(
        observer.credential_warnings().is_empty(),
        "matching credential must not produce binding warnings, got: {:?}",
        observer.credential_warnings()
    );
}

// ---------------------------------------------------------------------------
// (b) Mismatched DID in fetched key package → warn + escalate, op succeeds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_key_package_warns_and_operation_succeeds() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Mallory").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();
    world.register_device("Mallory").await.unwrap();

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("cred-bind-forged", None, None)
        .await
        .expect("create_group failed");

    // Malicious DS: requests for Bob's key packages get Mallory's instead,
    // still labeled as Bob's.
    world
        .delivery_service()
        .redirect_key_packages_for_test(&bob_did, &mallory_did);

    // Warn-and-allow: the add must still succeed (Mallory's package is a
    // structurally valid MLS key package).
    world
        .client("Alice")
        .orchestrator
        .add_members(&convo.group_id, &[bob_did.clone()])
        .await
        .expect("stage-1 warn-and-allow: add_members must still succeed on mismatch");

    let warnings = observer.credential_warnings();
    assert!(
        !warnings.is_empty(),
        "expected a credential-binding warning for the substituted key package"
    );
    let w = warnings
        .iter()
        .find(|w| w.expected_did == bob_did)
        .unwrap_or_else(|| panic!("no warning for expected DID {bob_did}, got {warnings:?}"));
    assert_eq!(w.operation, "fetch");
    assert_eq!(w.claimed_identity, mallory_did);
    assert!(
        w.reason.contains("does not match"),
        "reason should describe the DID mismatch, got: {}",
        w.reason
    );
    assert_eq!(w.convo_id, convo.group_id);
}

// ---------------------------------------------------------------------------
// (b2) Fork-readd fetch path: substituted key package → warn + escalate
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_key_package_fetch_warns_on_mismatch() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Mallory").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();
    let mallory_did = world.register_device("Mallory").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    // Create the group WITH Bob so `group_states` carries members for the
    // fork-readd key-package fetch.
    let convo = alice
        .orchestrator
        .create_group("fork-readd-cred-bind", Some(&[bob_did.clone()]), None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();
    assert!(
        observer.credential_warnings().is_empty(),
        "clean create_group must not produce binding warnings, got: {:?}",
        observer.credential_warnings()
    );

    // Malicious DS: from now on, fetches of Bob's key packages serve
    // Mallory's package, still labeled as Bob's.
    world
        .delivery_service()
        .redirect_key_packages_for_test(&bob_did, &mallory_did);

    // Drive the automated fork-readd path: FORK_DETECTION_THRESHOLD (2)
    // consecutive decrypt failures on an Active conversation trigger
    // `attempt_fork_readd`, which fetches member key packages and consumes
    // them in a forkReadd commit. Stage-1 contract: the fetch is verified
    // and the mismatch warns; recovery behavior is unchanged.
    for i in 0..2 {
        let envelope = IncomingEnvelope {
            conversation_id: group_id.clone(),
            sender_did: bob_did.clone(),
            ciphertext: format!("not-an-mls-message-{i}").into_bytes(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some(format!("fork-readd-bad-frame-{i}")),
        };
        let result = world
            .client("Alice")
            .orchestrator
            .process_incoming(&envelope)
            .await;
        assert!(
            result.is_err(),
            "invalid ciphertext should drive decrypt failure"
        );
    }

    let warnings = observer.credential_warnings();
    let w = warnings
        .iter()
        .find(|w| w.expected_did == bob_did)
        .unwrap_or_else(|| {
            panic!(
                "fork-readd fetch must run credential verification; \
                 no warning for expected DID {bob_did}, got {warnings:?}"
            )
        });
    assert_eq!(w.operation, "fetch");
    assert_eq!(w.claimed_identity, mallory_did);
    assert!(
        w.reason.contains("does not match"),
        "reason should describe the DID mismatch, got: {}",
        w.reason
    );
    assert_eq!(w.convo_id, group_id);
}

// ---------------------------------------------------------------------------
// (c) Equivocating receipts → detection fires, recovery still proceeds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn equivocating_receipts_fire_detection_and_recovery_proceeds() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("equivocation-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();

    // Sequencer starts issuing receipts for External Commits.
    world
        .delivery_service()
        .issue_external_commit_receipts_for_test(true);

    // The mock assigns epoch = current + 1 to the next External Commit.
    let next_epoch = world
        .delivery_service()
        .conversation_epoch(&group_id)
        .expect("mock should know the conversation epoch") as i32
        + 1;

    // Pre-store a receipt claiming a DIFFERENT commit was sequenced at that
    // same (conversation, epoch) — the equivocation evidence.
    let conflicting = SequencerReceipt {
        convo_id: group_id.clone(),
        epoch: next_epoch,
        commit_hash: vec![0xAA; 32],
        sequencer_did: "did:web:sequencer.test".to_string(),
        issued_at: chrono::Utc::now().timestamp(),
        signature: vec![],
    };
    alice
        .storage
        .store_sequencer_receipt(&conflicting)
        .await
        .expect("pre-store conflicting receipt");

    // Drive the External-Commit recovery path. Stage-1 contract: detection
    // fires, recovery still succeeds.
    alice
        .orchestrator
        .force_rejoin(&group_id)
        .await
        .expect("stage-1 detection-only: force_rejoin must still succeed");

    let events = observer.equivocations();
    assert_eq!(
        events.len(),
        1,
        "expected exactly one equivocation event, got: {events:?}"
    );
    let ev = &events[0];
    assert_eq!(ev.convo_id, group_id);
    assert_eq!(ev.epoch, next_epoch);
    assert_eq!(ev.stored_commit_hash_hex, hex::encode(vec![0xAA; 32]));
    assert_ne!(
        ev.new_commit_hash_hex, ev.stored_commit_hash_hex,
        "the two conflicting hashes must differ"
    );
    assert_eq!(ev.sequencer_did, "did:web:sequencer.test");
}

// ---------------------------------------------------------------------------
// (d) Non-equivocating receipt sequence → silent
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn non_equivocating_receipts_are_silent() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("receipt-clean-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();

    world
        .delivery_service()
        .issue_external_commit_receipts_for_test(true);

    let next_epoch = world
        .delivery_service()
        .conversation_epoch(&group_id)
        .expect("mock should know the conversation epoch") as i32
        + 1;

    // A prior receipt at a DIFFERENT epoch is not equivocation, even with a
    // different commit hash.
    let unrelated = SequencerReceipt {
        convo_id: group_id.clone(),
        epoch: next_epoch + 10,
        commit_hash: vec![0xBB; 32],
        sequencer_did: "did:web:sequencer.test".to_string(),
        issued_at: chrono::Utc::now().timestamp(),
        signature: vec![],
    };
    alice
        .storage
        .store_sequencer_receipt(&unrelated)
        .await
        .expect("pre-store unrelated receipt");

    alice
        .orchestrator
        .force_rejoin(&group_id)
        .await
        .expect("force_rejoin failed");

    assert!(
        observer.equivocations().is_empty(),
        "non-equivocating receipts must not fire detection, got: {:?}",
        observer.equivocations()
    );
    assert!(
        observer.credential_warnings().is_empty(),
        "no credential warnings expected in this flow"
    );

    // The genuinely sequenced receipt was still stored alongside the
    // unrelated one.
    let stored = alice
        .storage
        .get_sequencer_receipts(&group_id, None)
        .await
        .expect("get_sequencer_receipts");
    assert_eq!(stored.len(), 2, "expected pre-stored + new receipt");
    assert!(
        stored
            .iter()
            .any(|r| r.epoch == next_epoch && r.commit_hash != vec![0xBB; 32]),
        "the sequencer-issued receipt for the External Commit must be stored"
    );
}
