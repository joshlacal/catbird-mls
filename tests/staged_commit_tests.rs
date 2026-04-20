//! Integration tests for the sender-side three-phase commit API (task #44).
//!
//! Exercises `MLSOrchestrator::{stage_commit, confirm_commit, discard_pending}`
//! directly via the `TestWorld` harness. Confirms:
//!   1. `stage_commit` + `confirm_commit` advances the local epoch.
//!   2. `stage_commit` + `discard_pending` leaves the epoch unchanged.
//!   3. A second `confirm_commit` with the same handle returns `InvalidInput`.
//!   4. `confirm_commit` with a mismatched `server_epoch` returns
//!      `EpochMismatch` and leaves the pending commit recoverable.
//!   5. `discard_pending` after `confirm_commit` returns `InvalidInput`
//!      (handle is stale).

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::error::OrchestratorError;
use catbird_mls::orchestrator::types::{CommitKind, CommitPlan};
use e2e_harness::TestWorld;

/// Drive `stage_commit` on Alice's side for a fresh add-members operation.
/// Returns the plan that `confirm_commit` / `discard_pending` consumes.
async fn stage_add_members(
    alice_orch: &impl AliceOrchestratorAccess,
    group_id: &str,
    target_dids: &[String],
) -> CommitPlan {
    // Fetch key packages via the mock server the same way the wrapper does.
    let key_packages = alice_orch.fetch_key_packages(target_dids).await;
    let kp_data: Vec<catbird_mls::KeyPackageData> = key_packages
        .into_iter()
        .map(|data| catbird_mls::KeyPackageData { data })
        .collect();

    alice_orch
        .stage_commit_add(group_id, target_dids.to_vec(), kp_data)
        .await
        .expect("stage_commit failed")
}

/// Small trait to keep the test helpers legible; implemented on `&TestClient`
/// via a closure-like pattern (can't use generics at call-site without making
/// the tests very verbose).
trait AliceOrchestratorAccess {
    async fn fetch_key_packages(&self, dids: &[String]) -> Vec<Vec<u8>>;
    async fn stage_commit_add(
        &self,
        group_id: &str,
        member_dids: Vec<String>,
        kp_data: Vec<catbird_mls::KeyPackageData>,
    ) -> Result<CommitPlan, OrchestratorError>;
}

impl AliceOrchestratorAccess for &e2e_harness::TestClient {
    async fn fetch_key_packages(&self, dids: &[String]) -> Vec<Vec<u8>> {
        use catbird_mls::orchestrator::MLSAPIClient;
        let kps = self
            .orchestrator
            .api_client()
            .get_key_packages(dids)
            .await
            .expect("mock get_key_packages should succeed");
        kps.into_iter().map(|k| k.key_package_data).collect()
    }

    async fn stage_commit_add(
        &self,
        group_id: &str,
        member_dids: Vec<String>,
        kp_data: Vec<catbird_mls::KeyPackageData>,
    ) -> Result<CommitPlan, OrchestratorError> {
        self.orchestrator
            .stage_commit(
                group_id,
                CommitKind::AddMembers {
                    member_dids,
                    key_packages: kp_data,
                },
            )
            .await
    }
}

fn epoch_for_group(client: &e2e_harness::TestClient, group_id: &str) -> u64 {
    let bytes = hex::decode(group_id).expect("valid hex group id");
    client
        .orchestrator
        .mls_context()
        .get_epoch(bytes)
        .expect("get_epoch")
}

// ---------------------------------------------------------------------------
// 1. stage_commit + confirm_commit advances the local epoch
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_stage_then_confirm_advances_epoch() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let convo = alice
        .orchestrator
        .create_group("stage-then-confirm", None, None)
        .await
        .expect("create_group failed");

    let group_id = convo.group_id.clone();
    let epoch_before = epoch_for_group(alice, &group_id);

    let plan = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;
    assert_eq!(
        plan.source_epoch, epoch_before,
        "plan must capture current epoch"
    );
    assert_eq!(
        plan.target_epoch,
        epoch_before + 1,
        "MLS commits always advance by +1"
    );

    // Staging alone must not advance the epoch.
    let epoch_after_stage = epoch_for_group(alice, &group_id);
    assert_eq!(
        epoch_after_stage, epoch_before,
        "stage_commit must not advance the epoch"
    );

    // Ship the commit to the mock DS. The wrapper-style code would do this;
    // we call the mock API directly here to keep the test focused on the
    // sender-side three-phase API.
    use catbird_mls::orchestrator::MLSAPIClient;
    let server_result = alice
        .orchestrator
        .api_client()
        .add_members(
            &group_id,
            &[bob.did.clone()],
            &plan.commit_bytes,
            plan.welcome_bytes.as_deref(),
        )
        .await
        .expect("server add_members should succeed");
    assert!(server_result.success);

    // Confirm with skip-fence (mock server returns non-zero new_epoch that
    // doesn't necessarily match our target; the fence is exercised in the
    // dedicated test below).
    let confirmed = alice
        .orchestrator
        .confirm_commit(plan.handle, 0)
        .await
        .expect("confirm_commit must succeed");

    let epoch_after_confirm = epoch_for_group(alice, &group_id);
    assert!(
        epoch_after_confirm > epoch_before,
        "confirm_commit must advance the local epoch ({} -> {})",
        epoch_before,
        epoch_after_confirm
    );
    assert_eq!(
        confirmed.new_epoch, epoch_after_confirm,
        "ConfirmedCommit.new_epoch must match MLS-reported epoch"
    );
}

// ---------------------------------------------------------------------------
// 2. stage_commit + discard_pending leaves the epoch unchanged
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_stage_then_discard_no_epoch_change() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let convo = alice
        .orchestrator
        .create_group("stage-then-discard", None, None)
        .await
        .expect("create_group failed");

    let group_id = convo.group_id.clone();
    let epoch_before = epoch_for_group(alice, &group_id);

    let plan = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;

    alice
        .orchestrator
        .discard_pending(plan.handle)
        .await
        .expect("discard_pending must succeed");

    let epoch_after = epoch_for_group(alice, &group_id);
    assert_eq!(
        epoch_after, epoch_before,
        "discard_pending must leave the epoch untouched"
    );

    // And the pending map must be empty — a second stage for the same
    // group should succeed.
    let plan2 = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;
    // Clean up so the test doesn't leave OpenMLS pending state leaking.
    alice
        .orchestrator
        .discard_pending(plan2.handle)
        .await
        .expect("second discard_pending must succeed");
}

// ---------------------------------------------------------------------------
// 3. Double-confirm errors cleanly (handle nonce check)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_double_confirm_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let convo = alice
        .orchestrator
        .create_group("double-confirm", None, None)
        .await
        .unwrap();
    let group_id = convo.group_id.clone();

    let plan = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;
    let handle = plan.handle.clone();

    // Ship the commit first.
    use catbird_mls::orchestrator::MLSAPIClient;
    alice
        .orchestrator
        .api_client()
        .add_members(
            &group_id,
            &[bob.did.clone()],
            &plan.commit_bytes,
            plan.welcome_bytes.as_deref(),
        )
        .await
        .unwrap();

    // First confirm succeeds.
    alice
        .orchestrator
        .confirm_commit(handle.clone(), 0)
        .await
        .expect("first confirm must succeed");

    // Second confirm with the same handle must fail with InvalidInput.
    let err = alice
        .orchestrator
        .confirm_commit(handle, 0)
        .await
        .expect_err("second confirm must error");

    match err {
        OrchestratorError::InvalidInput(msg) => {
            assert!(
                msg.contains("already confirmed") || msg.contains("nonce mismatch"),
                "expected already-confirmed error, got: {}",
                msg
            );
        }
        other => panic!("expected InvalidInput, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. confirm_commit with mismatched server_epoch errors and preserves handle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_confirm_wrong_server_epoch_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let convo = alice
        .orchestrator
        .create_group("wrong-epoch-fence", None, None)
        .await
        .unwrap();
    let group_id = convo.group_id.clone();
    let epoch_before = epoch_for_group(alice, &group_id);

    let plan = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;
    let handle = plan.handle.clone();
    let bogus_server_epoch = plan.target_epoch.wrapping_add(42);

    let err = alice
        .orchestrator
        .confirm_commit(handle.clone(), bogus_server_epoch)
        .await
        .expect_err("confirm with wrong server epoch must error");

    match err {
        OrchestratorError::EpochMismatch { local, remote } => {
            assert_eq!(local, plan.target_epoch);
            assert_eq!(remote, bogus_server_epoch);
        }
        other => panic!("expected EpochMismatch, got {:?}", other),
    }

    // Epoch must NOT have advanced.
    let epoch_after_err = epoch_for_group(alice, &group_id);
    assert_eq!(
        epoch_after_err, epoch_before,
        "failed confirm must not advance epoch"
    );

    // Handle should still be valid — discard_pending must succeed so we can
    // clean up the MLS pending-commit slot.
    alice
        .orchestrator
        .discard_pending(handle)
        .await
        .expect("handle should still be valid after fence rejection");
}

// ---------------------------------------------------------------------------
// 5. discard_pending after confirm_commit returns InvalidInput
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_discard_after_confirm_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let convo = alice
        .orchestrator
        .create_group("discard-after-confirm", None, None)
        .await
        .unwrap();
    let group_id = convo.group_id.clone();

    let plan = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;
    let handle = plan.handle.clone();

    use catbird_mls::orchestrator::MLSAPIClient;
    alice
        .orchestrator
        .api_client()
        .add_members(
            &group_id,
            &[bob.did.clone()],
            &plan.commit_bytes,
            plan.welcome_bytes.as_deref(),
        )
        .await
        .unwrap();

    alice
        .orchestrator
        .confirm_commit(handle.clone(), 0)
        .await
        .expect("confirm must succeed");

    let err = alice
        .orchestrator
        .discard_pending(handle)
        .await
        .expect_err("discard after confirm must error");

    match err {
        OrchestratorError::InvalidInput(_) => {}
        other => panic!("expected InvalidInput, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 6. Staging while a commit is already pending is rejected
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_stage_while_pending_errors() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let convo = alice
        .orchestrator
        .create_group("stage-while-pending", None, None)
        .await
        .unwrap();
    let group_id = convo.group_id.clone();

    let plan1 = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;

    // Try to stage a second commit while the first is still pending.
    let err = alice
        .orchestrator
        .stage_commit(
            &group_id,
            CommitKind::RemoveMembers {
                member_dids: vec![bob.did.clone()],
            },
        )
        .await
        .expect_err("second stage must fail while the first is pending");

    match err {
        OrchestratorError::InvalidInput(msg) => {
            assert!(
                msg.contains("already exists") || msg.contains("pending"),
                "expected already-pending error, got: {}",
                msg
            );
        }
        other => panic!("expected InvalidInput, got {:?}", other),
    }

    // Clean up.
    alice
        .orchestrator
        .discard_pending(plan1.handle)
        .await
        .unwrap();
}
