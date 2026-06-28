//! Integration tests for the rustFull Welcome-reissue responder (W3 #1).
//!
//! Exercises `MLSOrchestrator::respond_to_welcome_reissue` via the `TestWorld`
//! harness. The responder mirrors `swap_members` (remove the recipient's stale
//! leaf + re-add with a fresh key package in one atomic commit) and threads the
//! reissue `request_id` as the server `addMembers` idempotency key.
//!
//! Asserts:
//!   1. The responder advances the admin's local epoch by exactly 1 — a
//!      SwapMembers commit, NOT an external commit.
//!   2. The reissue `request_id` reaches the delivery service as the
//!      `add_members_with_idempotency` idempotency key.
//!   3. A repeat call with the same `request_id` is a safe no-op: the server
//!      replays the answered request idempotently and the responder's epoch
//!      fence discards the duplicate, so the local epoch does NOT advance again.

#![allow(dead_code)]

mod e2e_harness;

use e2e_harness::TestWorld;

fn epoch_for_group(client: &e2e_harness::TestClient, group_id: &str) -> u64 {
    let bytes = hex::decode(group_id).expect("valid hex group id");
    client
        .orchestrator
        .mls_context()
        .get_epoch(bytes)
        .expect("get_epoch")
}

#[tokio::test(flavor = "multi_thread")]
async fn responds_with_swap_and_idempotency_key() {
    let mut world = TestWorld::new();
    world.add_client("Admin").await;
    world.add_client("Recipient").await;

    world.register_device("Admin").await.unwrap();
    world.register_device("Recipient").await.unwrap();

    let recipient_did = world.client("Recipient").did.clone();

    let admin = world.client("Admin");
    let convo = admin
        .orchestrator
        .create_group(
            "reissue-responder",
            Some(std::slice::from_ref(&recipient_did)),
            None,
        )
        .await
        .expect("create_group failed");

    let convo_id = convo.conversation_id.clone();
    let group_id = convo.group_id.clone();

    // Recipient is a current member; capture the admin's local epoch.
    let epoch_before = epoch_for_group(admin, &group_id);

    // Pass a device-qualified DID to exercise the `#`-split. Production leaf
    // credential identities are device-qualified (`did:...#device`), so the
    // responder must reduce both the request DID and each leaf identity to the
    // bare user DID before matching. The harness mints bare leaf identities, so
    // a device-qualified request DID still has to match a bare leaf.
    let recipient_device_did = format!("{recipient_did}#device-stale");
    let request_id = "reissue-req-123";

    admin
        .orchestrator
        .respond_to_welcome_reissue(&convo_id, &recipient_device_did, request_id)
        .await
        .expect("responder succeeds");

    // (1) Local epoch advanced by exactly 1 (SwapMembers — single commit).
    let epoch_after = epoch_for_group(admin, &group_id);
    assert_eq!(
        epoch_after,
        epoch_before + 1,
        "responder must advance the local epoch by exactly 1 ({epoch_before} -> {epoch_after})"
    );

    // No external commit was used — the whole point of the swap-based responder.
    assert_eq!(
        world.delivery_service().external_commit_count(&convo_id),
        0,
        "responder must NOT use an external commit (epoch inflation guard)"
    );

    // (2) request_id forwarded as the addMembers idempotency key.
    let keys = world.delivery_service().add_members_idempotency_keys();
    assert!(
        keys.contains(&request_id.to_string()),
        "request_id must be forwarded as the addMembers idempotency key; saw {keys:?}"
    );

    // (3) Repeat call with the same request_id is a safe no-op: the server
    // replays the answered request idempotently (no server-epoch advance) and
    // the responder's epoch fence discards the staged commit → no double
    // local-epoch advance.
    let admin = world.client("Admin");
    admin
        .orchestrator
        .respond_to_welcome_reissue(&convo_id, &recipient_device_did, request_id)
        .await
        .expect("repeat responder call succeeds");

    let epoch_after_repeat = epoch_for_group(admin, &group_id);
    assert_eq!(
        epoch_after_repeat, epoch_after,
        "a repeat reissue response with the same request_id must not advance the epoch again \
         ({epoch_after} -> {epoch_after_repeat})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_conversation_is_unfulfillable() {
    let mut world = TestWorld::new();
    world.add_client("Admin").await;
    world.register_device("Admin").await.unwrap();

    let admin = world.client("Admin");

    // A convo this device has no local MLS state for must surface a typed
    // RecoveryFailed (not a raw crypto error) so the Swift layer classifies it
    // as "unfulfillable here" and stops retrying.
    let err = admin
        .orchestrator
        .respond_to_welcome_reissue("did:plc:nonexistent-convo", "did:plc:someone", "req-x")
        .await
        .expect_err("unknown conversation must error");

    use catbird_mls::orchestrator::error::OrchestratorError;
    match err {
        OrchestratorError::RecoveryFailed(msg) => {
            assert!(
                msg.contains("not present in local MLS group state"),
                "expected unfulfillable-here message, got: {msg}"
            );
        }
        other => panic!("expected RecoveryFailed, got {other:?}"),
    }
}
