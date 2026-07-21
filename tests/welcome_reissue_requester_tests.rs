//! Regression tests for the Welcome-reissue REQUESTER path.
//!
//! Bug recap (2026-07-22, prod convo da03101e…):
//!   1. A receiver's Welcome was sealed to a key package whose private key
//!      the device no longer held (server-side key packages outlived a local
//!      storage wipe) — `process_welcome` fails with `NoMatchingKeyPackage`.
//!   2. `decide_welcome_recovery` correctly chose `RequestReissue`, but
//!      `ApiClient::request_welcome_reissue` failed (the default impl —
//!      the iOS FFI callback historically lacked the method entirely).
//!   3. The failure propagated via `?` BEFORE the attempt was recorded, so
//!      every sync tick re-entered the reissue arm with attempt_count == 0:
//!      an unbounded ~5s retry loop that never backed off and never
//!      escalated to External Commit. Observed live: the same dead Welcome
//!      fetched every ~5s for 8+ minutes.
//!
//! Fix: record the reissue attempt REGARDLESS of the request outcome, so the
//! backoff ladder keeps moving and attempts eventually exhaust into
//! `ExternalCommitWithHistoryGap`.
//!
//! The mock delivery service intentionally does NOT implement
//! `request_welcome_reissue` (it inherits the failing trait default), which
//! reproduces the exact pre-wiring platform state.

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::MLSStorageBackend;
use e2e_harness::TestWorld;

#[tokio::test(flavor = "multi_thread")]
async fn failed_reissue_request_records_attempt_and_backs_off() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Carol").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();
    world.register_device("Carol").await.unwrap();

    let carol_did = world.client("Carol").did.clone();
    let bob_did = world.client("Bob").did.clone();

    // Alice creates a group with Carol; the DS stores a Welcome sealed to
    // Carol's key package.
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group(
            "reissue-requester",
            Some(std::slice::from_ref(&carol_did)),
            None,
        )
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();
    let group_id = convo.group_id.clone();

    // Orphaned-KP wedge: Bob can fetch a Welcome for this convo, but it is
    // sealed to Carol's key material — his `process_welcome` must fail with
    // `NoMatchingKeyPackage`.
    world
        .delivery_service()
        .copy_welcome_for_test(&convo_id, &carol_did, &bob_did);

    let bob = world.client("Bob");
    bob.storage
        .ensure_conversation_exists(&bob.did, &convo_id, &group_id)
        .await
        .expect("test conversation should be persisted");

    // Attempt 1: decision = RequestReissue; the request itself fails (mock
    // inherits the "not implemented" default). The attempt must STILL be
    // recorded so the loop is bounded.
    let err = bob
        .orchestrator
        .join_or_rejoin(&convo_id)
        .await
        .expect_err("NoMatchingKeyPackage with failing reissue backend must not join");
    let msg = format!("{err}");
    assert!(
        msg.contains("Welcome reissue request failed"),
        "failed reissue request must surface through the recovery route; got {msg}"
    );

    let attempts = bob
        .storage
        .get_welcome_reissue_attempt_log(&convo_id)
        .await
        .expect("attempt log readable");
    assert_eq!(
        attempts.attempt_count(),
        1,
        "a failed reissue request must consume an attempt slot (pre-fix: 0, infinite loop)"
    );

    // Attempt 2 (immediately): the backoff window must suppress a new
    // reissue request — this is the assertion that kills the ~5s tight loop.
    world
        .delivery_service()
        .copy_welcome_for_test(&convo_id, &carol_did, &bob_did);
    let err2 = bob
        .orchestrator
        .join_or_rejoin(&convo_id)
        .await
        .expect_err("second attempt inside the backoff window must not join");
    let msg2 = format!("{err2}");
    assert!(
        msg2.contains("reissue suppressed"),
        "second attempt inside the backoff window must be suppressed, not retried; got {msg2}"
    );
    let attempts2 = bob
        .storage
        .get_welcome_reissue_attempt_log(&convo_id)
        .await
        .expect("attempt log readable");
    assert_eq!(
        attempts2.attempt_count(),
        1,
        "suppressed retry must not burn another attempt slot"
    );
}
