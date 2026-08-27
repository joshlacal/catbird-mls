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
//!   6. Projection persistence failure withholds confirmation, preserves the
//!      last durable/cache projection, and marks the conversation for rejoin.

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::credential_binding::{
    extract_key_package_binding, extract_key_package_identity,
};
use catbird_mls::orchestrator::error::OrchestratorError;
use catbird_mls::orchestrator::types::{CommitKind, CommitPlan, IncomingEnvelope};
use catbird_mls::orchestrator::{
    MLSAPIClient, MLSStorageBackend, MlsCryptoContext, MlsDecryptOutcome,
};
use catbird_mls::DecryptContentType;
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
            .get_key_packages("00000000-0000-4000-8000-000000000001", dids)
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
            &convo.conversation_id,
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

#[tokio::test(flavor = "multi_thread")]
async fn own_commit_echo_requires_durable_local_confirmation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("own-echo-durable-fence", None, None)
        .await
        .expect("create group");
    let plan = stage_add_members(&alice, &convo.group_id, &[bob.did.clone()]).await;
    let tracked_before = alice.orchestrator.own_commits().lock().await.len();

    let error = alice
        .orchestrator
        .process_incoming(&IncomingEnvelope {
            conversation_id: convo.conversation_id.clone(),
            sender_did: alice.did.clone(),
            ciphertext: plan.commit_bytes.clone(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("accepted-response-lost".to_string()),
            server_epoch: Some(plan.target_epoch),
        })
        .await
        .expect_err("an unconfirmed own commit must withhold success/cursor advancement");

    assert!(error.to_string().contains("before durable confirmation"));
    assert_eq!(
        alice.orchestrator.own_commits().lock().await.len(),
        tracked_before,
        "failed proof must retain the hash for a retry"
    );
    assert!(
        alice.storage.has_rejoin_flag(&convo.conversation_id),
        "ambiguous server acceptance must enter durable recovery"
    );

    alice
        .orchestrator
        .discard_pending(plan.handle)
        .await
        .expect("test cleanup");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_confirm_projection_failure_withholds_success_and_cache_advance() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;

    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("confirm-projection-failure", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();
    let epoch_before = epoch_for_group(alice, &group_id);
    let plan = stage_add_members(&alice, &group_id, &[bob.did.clone()]).await;

    use catbird_mls::orchestrator::MLSAPIClient;
    alice
        .orchestrator
        .api_client()
        .add_members(
            &convo.conversation_id,
            &[bob.did.clone()],
            &plan.commit_bytes,
            plan.welcome_bytes.as_deref(),
        )
        .await
        .expect("server add_members should succeed");

    alice.storage.fail_next_set_group_state();
    let error = alice
        .orchestrator
        .confirm_commit(plan.handle, 0)
        .await
        .expect_err("projection failure must withhold confirmation");
    assert!(matches!(error, OrchestratorError::Storage(_)));
    assert!(
        epoch_for_group(alice, &group_id) > epoch_before,
        "the test must exercise a post-merge projection failure"
    );

    let cached = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .values()
        .find(|state| state.group_id == group_id)
        .cloned()
        .expect("pre-merge cache projection must remain available");
    assert_eq!(cached.epoch, epoch_before);
    assert!(!cached.members.contains(&bob.did));

    let persisted = alice
        .storage
        .get_group_state(&group_id)
        .await
        .expect("read persisted group state")
        .expect("pre-merge persisted group state must remain available");
    assert_eq!(persisted.epoch, epoch_before);
    assert!(!persisted.members.contains(&bob.did));
    assert!(
        alice
            .storage
            .needs_rejoin(&convo.conversation_id)
            .await
            .expect("read durable needs-rejoin flag"),
        "post-merge projection failure must route the conversation to recovery"
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
            &convo.conversation_id,
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
            &convo.conversation_id,
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

// ---------------------------------------------------------------------------
// Structural outbound DID binding
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn staged_add_rejects_empty_authority_but_pure_remove_swap_remains_valid() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("empty-add-authority", None, None)
        .await
        .expect("create group");
    let bob_kp = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .create_key_package(bob_did.as_bytes().to_vec())
        .expect("bob kp");
    let group_id_bytes = hex::decode(&convo.group_id).unwrap();
    let _ = alice
        .orchestrator
        .mls_context()
        .add_members(
            group_id_bytes.clone(),
            vec![catbird_mls::KeyPackageData {
                data: bob_kp.key_package_data,
            }],
        )
        .expect("add bob");
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group_id_bytes)
        .expect("merge bob");
    let error = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::AddMembers {
                member_dids: vec![],
                key_packages: vec![],
            },
        )
        .await
        .expect_err("an Add operation needs non-empty authority");
    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert!(error.to_string().contains("empty"));

    let pure_remove = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::SwapMembers {
                remove_dids: vec![bob_did],
                add_dids: vec![],
                add_key_packages: vec![],
            },
        )
        .await
        .expect("an empty add-side must remain valid for a pure-removal Swap");
    alice
        .orchestrator
        .discard_pending(pure_remove.handle)
        .await
        .expect("discard pure-remove compatibility commit");
}

#[tokio::test(flavor = "multi_thread")]
async fn key_package_extractor_rejects_mls_message_with_welcome_body() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();
    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("wrong body", None, None)
        .await
        .expect("create group");
    let plan = stage_add_members(&alice, &convo.conversation_id, &[bob_did]).await;
    let welcome = plan
        .welcome_bytes
        .as_deref()
        .expect("Add plan carries a Welcome message");
    assert!(
        extract_key_package_identity(welcome).is_err(),
        "a valid MLS message with a non-KeyPackage body must reject"
    );
    alice
        .orchestrator
        .discard_pending(plan.handle)
        .await
        .expect("discard staged add");
}

async fn raw_key_package(
    client: &e2e_harness::TestClient,
    did: &str,
) -> catbird_mls::KeyPackageData {
    use catbird_mls::orchestrator::MLSAPIClient;
    let mut packages = client
        .orchestrator
        .api_client()
        .get_key_packages("00000000-0000-4000-8000-000000000001", &[did.to_string()])
        .await
        .expect("fetch key package");
    assert_eq!(
        packages.len(),
        1,
        "test fixture expects one package per DID"
    );
    catbird_mls::KeyPackageData {
        data: packages.remove(0).key_package_data,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_add_rejects_non_exact_key_package_batches_atomically() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory", "Eve"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();
    let eve_did = world.client("Eve").did.clone();
    let bob_kp = raw_key_package(alice, &bob_did).await;
    let mallory_kp = raw_key_package(alice, &mallory_did).await;
    let eve_kp = raw_key_package(alice, &eve_did).await;
    let mut trailing_bob_kp = bob_kp.clone();
    trailing_bob_kp.data.extend_from_slice(&[0xde, 0xad]);

    let cases = vec![
        (
            "substituted",
            vec![bob_did.clone()],
            vec![mallory_kp.clone()],
        ),
        (
            "appended",
            vec![bob_did.clone()],
            vec![bob_kp.clone(), mallory_kp.clone()],
        ),
        (
            "missing",
            vec![bob_did.clone(), mallory_did.clone()],
            vec![bob_kp.clone()],
        ),
        (
            "malformed",
            vec![bob_did.clone()],
            vec![catbird_mls::KeyPackageData {
                data: vec![0xde, 0xad, 0xbe, 0xef],
            }],
        ),
        (
            "trailing bytes",
            vec![bob_did.clone()],
            vec![trailing_bob_kp],
        ),
        (
            "mismatched batch",
            vec![bob_did.clone(), mallory_did.clone()],
            vec![bob_kp.clone(), eve_kp],
        ),
    ];

    for (case, expected_dids, key_packages) in cases {
        let convo = alice
            .orchestrator
            .create_group(&format!("binding-{case}"), None, None)
            .await
            .expect("create group");
        let group_bytes = hex::decode(&convo.group_id).unwrap();
        let epoch_before = alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .unwrap();
        let own_commits_before = alice.orchestrator.own_commits().lock().await.len();

        let result = alice
            .orchestrator
            .stage_commit(
                &convo.group_id,
                CommitKind::AddMembers {
                    member_dids: expected_dids,
                    key_packages,
                },
            )
            .await;
        let error = match result {
            Ok(_) => panic!("{case} batch must reject"),
            Err(error) => error,
        };
        assert!(
            matches!(error, OrchestratorError::InvalidInput(_)),
            "{case} must fail as InvalidInput, got {error:?}"
        );
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(group_bytes)
                .unwrap(),
            epoch_before,
            "{case} rejection must not change epoch"
        );
        assert_eq!(
            alice.orchestrator.own_commits().lock().await.len(),
            own_commits_before,
            "{case} rejection must not create own-commit tracking"
        );

        let valid = alice
            .orchestrator
            .stage_commit(
                &convo.group_id,
                CommitKind::AddMembers {
                    member_dids: vec![bob_did.clone()],
                    key_packages: vec![bob_kp.clone()],
                },
            )
            .await
            .unwrap_or_else(|error| {
                panic!("{case} rejection must leave no pending commit: {error}")
            });
        assert!(
            valid.welcome_bytes.is_some(),
            "{case} rejection must not consume the package or suppress the valid retry Welcome"
        );
        alice
            .orchestrator
            .discard_pending(valid.handle)
            .await
            .expect("discard validation commit");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_swap_mismatch_does_neither_removal_nor_addition() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory", "Eve"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();
    let eve_did = world.client("Eve").did.clone();
    let bob_kp = raw_key_package(alice, &bob_did).await;
    let mallory_kp = raw_key_package(alice, &mallory_did).await;
    let eve_kp = raw_key_package(alice, &eve_did).await;
    let mut trailing_mallory_kp = mallory_kp.clone();
    trailing_mallory_kp.data.push(0xff);
    let cases = vec![
        ("substituted", vec![mallory_did.clone()], vec![bob_kp]),
        (
            "appended",
            vec![mallory_did.clone()],
            vec![mallory_kp.clone(), eve_kp.clone()],
        ),
        (
            "missing",
            vec![mallory_did.clone(), eve_did],
            vec![mallory_kp.clone()],
        ),
        (
            "malformed",
            vec![mallory_did.clone()],
            vec![catbird_mls::KeyPackageData {
                data: vec![0xde, 0xad, 0xbe, 0xef],
            }],
        ),
        (
            "trailing bytes",
            vec![mallory_did.clone()],
            vec![trailing_mallory_kp],
        ),
    ];

    for (case, add_dids, add_key_packages) in cases {
        let convo = alice
            .orchestrator
            .create_group(&format!("binding-swap-{case}"), None, None)
            .await
            .expect("create group");
        let bob_kp = world
            .client("Bob")
            .orchestrator
            .mls_context()
            .create_key_package(bob_did.as_bytes().to_vec())
            .expect("bob kp");
        let group_bytes = hex::decode(&convo.group_id).unwrap();
        let _ = alice
            .orchestrator
            .mls_context()
            .add_members(
                group_bytes.clone(),
                vec![catbird_mls::KeyPackageData {
                    data: bob_kp.key_package_data,
                }],
            )
            .expect("add bob");
        alice
            .orchestrator
            .mls_context()
            .merge_pending_commit(group_bytes.clone())
            .expect("merge bob");
        let group_bytes = hex::decode(&convo.group_id).unwrap();
        let members_before = alice
            .orchestrator
            .mls_context()
            .group_member_identities(group_bytes.clone())
            .expect("members before");
        let epoch_before = alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .unwrap();
        let own_commits_before = alice.orchestrator.own_commits().lock().await.len();

        let error = alice
            .orchestrator
            .stage_commit(
                &convo.group_id,
                CommitKind::SwapMembers {
                    remove_dids: vec![bob_did.clone()],
                    add_dids,
                    add_key_packages,
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, OrchestratorError::InvalidInput(_)),
            "{case} must reject as InvalidInput: {error}"
        );
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .group_member_identities(group_bytes.clone())
                .expect("members after"),
            members_before,
            "{case} failed swap must neither remove nor add"
        );
        assert_eq!(
            alice
                .orchestrator
                .mls_context()
                .get_epoch(group_bytes)
                .unwrap(),
            epoch_before,
            "{case} failed swap must preserve epoch"
        );
        assert_eq!(
            alice.orchestrator.own_commits().lock().await.len(),
            own_commits_before,
            "{case} rejection must not create own-commit tracking"
        );

        let valid = alice
            .orchestrator
            .stage_commit(
                &convo.group_id,
                CommitKind::SwapMembers {
                    remove_dids: vec![bob_did.clone()],
                    add_dids: vec![mallory_did.clone()],
                    add_key_packages: vec![mallory_kp.clone()],
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{case} valid retry failed: {error}"));
        assert!(valid.welcome_bytes.is_some());
        alice
            .orchestrator
            .discard_pending(valid.handle)
            .await
            .expect("discard valid retry");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_add_fails_closed_when_authorized_device_resolution_errors() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    world
        .delivery_service()
        .set_next_create_conversation_id("aaaaaaaa-0001-4000-8000-000000000001");
    let convo = alice
        .orchestrator
        .create_group("binding-resolver-error", None, None)
        .await
        .expect("create group");
    let group_bytes = hex::decode(&convo.group_id).unwrap();
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    let own_commits_before = alice.orchestrator.own_commits().lock().await.len();
    let bob_kp = raw_key_package(alice, &bob_did).await;

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&bob_did, true);
    let error = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::AddMembers {
                member_dids: vec![bob_did.clone()],
                key_packages: vec![bob_kp.clone()],
            },
        )
        .await
        .expect_err("resolver infrastructure failure must fail closed");
    assert!(matches!(error, OrchestratorError::Credential(_)));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes)
            .unwrap(),
        epoch_before,
        "resolver rejection must preserve the epoch"
    );
    assert_eq!(
        alice.orchestrator.own_commits().lock().await.len(),
        own_commits_before,
        "resolver rejection must not record an own commit"
    );

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&bob_did, false);
    let valid = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::AddMembers {
                member_dids: vec![bob_did],
                key_packages: vec![bob_kp],
            },
        )
        .await
        .expect("the exact same package must remain usable after rejection");
    assert!(
        valid.welcome_bytes.is_some(),
        "valid retry must still produce its Welcome"
    );
    alice
        .orchestrator
        .discard_pending(valid.handle)
        .await
        .expect("discard valid retry");
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_add_enforces_authorized_device_keys_when_resolver_is_available() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    world
        .delivery_service()
        .set_next_create_conversation_id("aaaaaaaa-0002-4000-8000-000000000002");
    let convo = alice
        .orchestrator
        .create_group("binding-resolved-device-key", None, None)
        .await
        .expect("create group");
    let bob_kp = raw_key_package(alice, &bob_did).await;
    let binding = extract_key_package_binding(&bob_kp.data).expect("extract Bob binding");

    alice
        .credentials
        .set_authorized_device_keys(&bob_did, vec![]);
    alice.orchestrator.invalidate_device_key_cache().await;
    let error = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::AddMembers {
                member_dids: vec![bob_did.clone()],
                key_packages: vec![bob_kp.clone()],
            },
        )
        .await
        .expect_err("resolved zero-key authority must reject Bob's package");
    assert!(matches!(error, OrchestratorError::InvalidInput(_)));

    alice
        .credentials
        .set_authorized_device_keys(&bob_did, vec![binding.signature_key]);
    alice.orchestrator.invalidate_device_key_cache().await;
    let valid = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::AddMembers {
                member_dids: vec![bob_did],
                key_packages: vec![bob_kp],
            },
        )
        .await
        .expect("authorized package must remain compatible");
    alice
        .orchestrator
        .discard_pending(valid.handle)
        .await
        .expect("discard valid staged add");
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_swap_fails_closed_when_authorized_device_resolution_errors() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();
    let convo = alice
        .orchestrator
        .create_group("binding-swap-resolver-error", None, None)
        .await
        .expect("create group");
    let bob_kp = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .create_key_package(bob_did.as_bytes().to_vec())
        .expect("bob kp");
    let group_bytes = hex::decode(&convo.group_id).unwrap();
    let _ = alice
        .orchestrator
        .mls_context()
        .add_members(
            group_bytes.clone(),
            vec![catbird_mls::KeyPackageData {
                data: bob_kp.key_package_data,
            }],
        )
        .expect("add bob");
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group_bytes.clone())
        .expect("merge bob");
    let group_bytes = hex::decode(&convo.group_id).unwrap();
    let members_before = alice
        .orchestrator
        .mls_context()
        .group_member_identities(group_bytes.clone())
        .expect("members before");
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    let own_commits_before = alice.orchestrator.own_commits().lock().await.len();
    let mallory_kp = raw_key_package(alice, &mallory_did).await;

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&mallory_did, true);
    let error = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::SwapMembers {
                remove_dids: vec![bob_did.clone()],
                add_dids: vec![mallory_did.clone()],
                add_key_packages: vec![mallory_kp.clone()],
            },
        )
        .await
        .expect_err("Swap resolver failure must fail before either mutation");
    assert!(matches!(error, OrchestratorError::Credential(_)));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .group_member_identities(group_bytes.clone())
            .expect("members after"),
        members_before
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes)
            .unwrap(),
        epoch_before
    );
    assert_eq!(
        alice.orchestrator.own_commits().lock().await.len(),
        own_commits_before,
        "resolver rejection must not record an own commit"
    );

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&mallory_did, false);
    let valid = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::SwapMembers {
                remove_dids: vec![bob_did],
                add_dids: vec![mallory_did],
                add_key_packages: vec![mallory_kp],
            },
        )
        .await
        .expect("the exact same Swap package must remain usable after rejection");
    assert!(
        valid.welcome_bytes.is_some(),
        "valid Swap retry must still produce its Welcome"
    );
    alice
        .orchestrator
        .discard_pending(valid.handle)
        .await
        .expect("discard valid Swap retry");
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_swap_rejects_exact_did_batch_before_device_resolution() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();
    let convo = alice
        .orchestrator
        .create_group("binding-before-resolution", None, None)
        .await
        .expect("create group");
    let mallory_kp = raw_key_package(alice, &mallory_did).await;

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&mallory_did, true);
    let error = alice
        .orchestrator
        .stage_commit(
            &convo.conversation_id,
            CommitKind::SwapMembers {
                remove_dids: vec![],
                add_dids: vec![bob_did],
                add_key_packages: vec![mallory_kp],
            },
        )
        .await
        .expect_err("a substituted DID root must fail before resolver activity");

    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert_eq!(
        alice.credentials.device_key_lookup_count(&mallory_did),
        0,
        "an attacker-controlled credential root must not be resolved or cached"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolver_success_unaccepted_appdata_commit_withholds_merge_and_cursor_advance() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("unaccepted-appdata-fence", None, None)
        .await
        .expect("create group");
    let group_id = convo.group_id.clone();
    let group_bytes = hex::decode(&group_id).unwrap();

    // Alice adds Bob to the group using stage_add_members + confirm_commit
    let add_plan = stage_add_members(&alice, &group_id, &[bob_did.clone()]).await;
    let server_result = alice
        .orchestrator
        .api_client()
        .add_members(
            &convo.conversation_id,
            &[bob_did.clone()],
            &add_plan.commit_bytes,
            add_plan.welcome_bytes.as_deref(),
        )
        .await
        .expect("server add_members should succeed");
    assert!(server_result.success);

    let _confirmed_add = alice
        .orchestrator
        .confirm_commit(add_plan.handle, add_plan.target_epoch)
        .await
        .expect("confirm add_members commit");

    let welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&convo.conversation_id)
        .await
        .expect("bob get_welcome");
    bob.orchestrator
        .join_group(&welcome)
        .await
        .expect("bob join_group");

    let alice_epoch_baseline = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    let bob_epoch_baseline = bob
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    assert_eq!(alice_epoch_baseline, bob_epoch_baseline);
    assert_eq!(alice_epoch_baseline, 1);
    // Alice stages a genuine AppData Update commit (component 0x8001)
    let expected_metadata_1 = b"{\"version\":1,\"locator\":\"metadata-loc-1\",\"hash\":\"\"}".to_vec();
    let plan = alice
        .orchestrator
        .stage_app_data_update_commit_for_test(
            &group_id,
            0x8001,
            Some(expected_metadata_1.clone()),
        )
        .await
        .expect("stage update metadata");
    assert_eq!(plan.source_epoch, 1);
    assert_eq!(plan.target_epoch, 2);

    // -----------------------------------------------------------------------
    // Phase 1: Real AppData resolver execution on a peer context (Bob)
    // -----------------------------------------------------------------------
    // Bob receives Alice's genuine 0x8001 AppData commit ciphertext.
    // Decrypt runs real crypto: OpenMLS returns UnresolvedAppDataCommit, updater
    // applies component 0x8001 update, and resolve_app_data_commit returns StagedCommit.
    let bob_decrypt = bob
        .orchestrator
        .mls_context()
        .decrypt_message_outcome(group_bytes.clone(), plan.commit_bytes.clone())
        .expect("Bob decrypt_message_outcome should resolve AppData commit via real crypto");

    match bob_decrypt {
        MlsDecryptOutcome::Message(decrypted) => {
            assert_eq!(decrypted.content_type, DecryptContentType::Commit);
            assert_eq!(decrypted.epoch, plan.target_epoch);
        }
        other => panic!("expected DecryptContentType::Commit, got {:?}", other),
    }

    // AppData component 0x8001 must remain UNMERGED on Bob before explicit merge
    let bob_metadata_before_merge = bob
        .orchestrator
        .mls_context()
        .get_current_metadata(group_bytes.clone())
        .unwrap()
        .and_then(|m| m.metadata_reference_json);
    assert_eq!(
        bob_metadata_before_merge, None,
        "Bob's 0x8001 AppData dictionary component must remain unmerged before explicit merge"
    );

    let bob_epoch_after_decrypt = bob
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    assert_eq!(
        bob_epoch_after_decrypt, bob_epoch_baseline,
        "AppData commit resolution must stage without auto-merging into local group"
    );

    // Explicit merge advances Bob's epoch to the target epoch
    let bob_merged_epoch = bob
        .orchestrator
        .mls_context()
        .merge_incoming_commit(group_bytes.clone(), plan.target_epoch)
        .expect("explicit merge staged commit on Bob");
    assert_eq!(bob_merged_epoch, plan.target_epoch);
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .unwrap(),
        plan.target_epoch
    );

    let bob_metadata_after_merge = bob
        .orchestrator
        .mls_context()
        .get_current_metadata(group_bytes.clone())
        .unwrap()
        .and_then(|m| m.metadata_reference_json)
        .expect("Bob must have 0x8001 metadata reference after merge");
    assert_eq!(
        bob_metadata_after_merge, expected_metadata_1,
        "Bob's 0x8001 AppData component must reflect merged value"
    );

    // -----------------------------------------------------------------------
    // Phase 2: Own pending commit with volatile tracking cleared (model restart)
    // -----------------------------------------------------------------------
    // Clear Alice's volatile tracking map so `is_own_commit` is false and real crypto runs
    alice.orchestrator.own_commits().lock().await.clear();
    let restart_error = alice
        .orchestrator
        .process_incoming(&IncomingEnvelope {
            conversation_id: convo.conversation_id.clone(),
            sender_did: alice.did.clone(),
            ciphertext: plan.commit_bytes.clone(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("restarted-unconfirmed-appdata-commit".to_string()),
            server_epoch: Some(plan.target_epoch),
        })
        .await
        .expect_err("unconfirmed OwnPendingCommit after restart must withhold cursor advance");

    assert!(
        restart_error
            .to_string()
            .contains("unverified own pending commit outcome"),
        "error must be from real decrypt OwnPendingCommit outcome, got: {}",
        restart_error
    );

    // Group epoch must NOT have merged or advanced in Alice's group
    let alice_epoch_after_restart_echo = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    assert_eq!(
        alice_epoch_after_restart_echo, alice_epoch_baseline,
        "unaccepted OwnPendingCommit must never merge into the local MLS group"
    );

    // Durably confirm the staged commit on Alice (simulating server ACK)
    let confirmed = alice
        .orchestrator
        .confirm_commit(plan.handle, plan.target_epoch)
        .await
        .expect("confirm staged commit");
    assert_eq!(confirmed.new_epoch, plan.target_epoch);
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .unwrap(),
        plan.target_epoch
    );

    // -----------------------------------------------------------------------
    // Phase 3: Exercise volatile tracking fence on a second AppData commit
    // -----------------------------------------------------------------------
    let expected_metadata_2 = b"{\"version\":2,\"locator\":\"metadata-loc-2\",\"hash\":\"\"}".to_vec();
    let plan2 = alice
        .orchestrator
        .stage_app_data_update_commit_for_test(
            &group_id,
            0x8001,
            Some(expected_metadata_2.clone()),
        )
        .await
        .expect("stage second update metadata");
    assert_eq!(plan2.source_epoch, 2);
    assert_eq!(plan2.target_epoch, 3);

    // 3a. A commit envelope arrives BEFORE durable confirmation while volatile tracking is active:
    let tracking_error = alice
        .orchestrator
        .process_incoming(&IncomingEnvelope {
            conversation_id: convo.conversation_id.clone(),
            sender_did: alice.did.clone(),
            ciphertext: plan2.commit_bytes.clone(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("tracked-unconfirmed-commit".to_string()),
            server_epoch: Some(plan2.target_epoch),
        })
        .await
        .expect_err("tracked unconfirmed commit must withhold cursor advance");

    assert!(
        tracking_error
            .to_string()
            .contains("before durable confirmation"),
        "error must be from the volatile tracking fence, got: {}",
        tracking_error
    );

    // Group epoch must NOT have merged or advanced
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .unwrap(),
        plan.target_epoch,
        "unaccepted commit must not merge into local group"
    );

    // 3b. Durably confirm the second staged commit
    let confirmed2 = alice
        .orchestrator
        .confirm_commit(plan2.handle, plan2.target_epoch)
        .await
        .expect("confirm second staged commit");
    assert_eq!(confirmed2.new_epoch, plan2.target_epoch);

    // 3c. Process the commit envelope again — now passes the accepted fence and advances cursor
    let result = alice
        .orchestrator
        .process_incoming(&IncomingEnvelope {
            conversation_id: convo.conversation_id.clone(),
            sender_did: alice.did.clone(),
            ciphertext: plan2.commit_bytes.clone(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("tracked-accepted-commit".to_string()),
            server_epoch: Some(plan2.target_epoch),
        })
        .await
        .expect("durably confirmed commit echo must be skipped cleanly");
    assert!(result.is_none(), "echo must produce no decrypted message");

    let final_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .unwrap();
    assert_eq!(final_epoch, plan2.target_epoch);

    // Bob processes and merges second AppData commit
    let bob_decrypt2 = bob
        .orchestrator
        .mls_context()
        .decrypt_message_outcome(group_bytes.clone(), plan2.commit_bytes.clone())
        .expect("Bob decrypt second AppData commit");
    match bob_decrypt2 {
        MlsDecryptOutcome::Message(decrypted) => {
            assert_eq!(decrypted.content_type, DecryptContentType::Commit);
            assert_eq!(decrypted.epoch, plan2.target_epoch);
        }
        other => panic!("expected DecryptContentType::Commit, got {:?}", other),
    }
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_current_metadata(group_bytes.clone())
            .unwrap()
            .and_then(|m| m.metadata_reference_json)
            .unwrap(),
        expected_metadata_1,
        "Bob's metadata before merging second commit must still be expected_metadata_1"
    );
    bob.orchestrator
        .mls_context()
        .merge_incoming_commit(group_bytes.clone(), plan2.target_epoch)
        .expect("Bob merge second AppData commit");
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .unwrap(),
        plan2.target_epoch
    );
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_current_metadata(group_bytes.clone())
            .unwrap()
            .and_then(|m| m.metadata_reference_json)
            .unwrap(),
        expected_metadata_2,
        "Bob's metadata after merging second commit must be expected_metadata_2"
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn test_stage_commit_mismatched_identity_withholds_cursor() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo1 = alice
        .orchestrator
        .create_group("mismatched-identity-1", None, None)
        .await
        .expect("create group 1");
    let convo2 = alice
        .orchestrator
        .create_group("mismatched-identity-2", None, None)
        .await
        .expect("create group 2");

    // Alice stages a commit on group 1
    let plan = stage_add_members(&alice, &convo1.group_id, &[bob.did.clone()]).await;

    // An envelope arrives claiming to be for convo2 but containing convo1's commit
    let error = alice
        .orchestrator
        .process_incoming(&IncomingEnvelope {
            conversation_id: convo2.conversation_id.clone(),
            sender_did: alice.did.clone(),
            ciphertext: plan.commit_bytes.clone(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some("mismatched-convo-commit".to_string()),
            server_epoch: Some(plan.target_epoch),
        })
        .await
        .expect_err("mismatched identity expectation must withhold cursor");

    assert!(error
        .to_string()
        .contains("self-commit expectation identity mismatch"));

    alice
        .orchestrator
        .discard_pending(plan.handle)
        .await
        .expect("cleanup staged commit");
}
