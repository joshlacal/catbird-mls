//! Regression test for the "silent epoch merge" hypothesis behind production
//! epoch-inflation bug (see CLAUDE.md + production logs on convo
//! `4b8f5349db56aa35a02c59e96b6ad404`, April 2026).
//!
//! Production symptom:
//!   server newEpoch: 2809
//!   joinByExternalCommit Success
//!   External Commit joined at epoch 2676   ← local epoch DID NOT advance
//!
//! This test exercises `MLSContext::create_external_commit` (the FFI entry
//! point iOS actually hits) and asserts that `get_epoch` immediately afterwards
//! returns the *post-join* epoch, NOT the GroupInfo-source epoch.
//!
//! Scenarios:
//! 1. Fresh joiner (no prior state) — baseline.
//! 2. Rejoiner (group_id already present at a stale epoch, simulating the
//!    production "lost sync" case: Bob was a member at epoch 5, misses commits,
//!    uses External Commit to rejoin while Alice is at epoch 10).

use async_trait::async_trait;
use catbird_mls::{GroupConfig, KeyPackageData, KeychainAccess, MLSContext, MLSError};
use std::collections::HashMap;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// In-memory keychain stub (copied from group_metadata_e2e_test.rs — tests
// elsewhere share the same pattern).
// ---------------------------------------------------------------------------

struct TestKeychain {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.store.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.store.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.store.lock().unwrap().remove(&key);
        Ok(())
    }
}

fn new_ctx(dir: &tempfile::TempDir) -> std::sync::Arc<MLSContext> {
    let db = dir.path().join("mls.db");
    MLSContext::new(
        db.to_str().unwrap().to_string(),
        "test-encryption-key!".to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("MLSContext::new failed")
}

/// Helper: push Alice's epoch forward by N self-commits (adds a throwaway
/// key-package and then removes it). Returns Alice's final epoch.
fn advance_alice_by_adding_and_removing(
    alice: &MLSContext,
    _alice_id: &[u8],
    group_id: &[u8],
    throwaway_ctx: &MLSContext,
    throwaway_id: &[u8],
) -> u64 {
    // Create a dummy key package on a sacrificial context.
    let kp = throwaway_ctx
        .create_key_package(throwaway_id.to_vec())
        .expect("throwaway create_key_package failed");
    let add_res = alice
        .add_members(
            group_id.to_vec(),
            vec![KeyPackageData {
                data: kp.key_package_data,
            }],
        )
        .expect("alice add_members failed");
    let _ = alice
        .merge_pending_commit(group_id.to_vec())
        .expect("alice merge_pending_commit after add failed");
    // Drop the throwaway — we don't need them to process the welcome;
    // Alice just needs epochs to tick forward.
    let _ = add_res;

    // Remove the throwaway to bump another epoch. Use remove_members if
    // available by signer public key; if not, just rely on the single add
    // for a modest epoch advance.
    alice
        .get_epoch(group_id.to_vec())
        .expect("alice get_epoch after add failed")
    // NOTE: we deliberately stop at one add; epoch 1 is enough to discriminate
    // a silent no-op (epoch == 0) from a real advance (epoch >= 2).
    // The symptom the test reproduces is "local epoch < server epoch", which
    // we'll check against the exported GroupInfo's epoch directly.
}

#[test]
fn external_commit_advances_local_epoch_past_group_info_epoch() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    // Sacrificial "carol" context we use only to mint KeyPackages for Alice to
    // add so we can push Alice's epoch past 1.
    let carol_dir = tempfile::tempdir().unwrap();

    let alice_ctx = new_ctx(&alice_dir);
    let bob_ctx = new_ctx(&bob_dir);
    let carol_ctx = new_ctx(&carol_dir);

    let alice_id = b"did:plc:alice";
    let bob_id = b"did:plc:bob";
    let carol_id = b"did:plc:carol";

    // 1. Alice creates a group.
    let create_res = alice_ctx
        .create_group(alice_id.to_vec(), Some(GroupConfig::default()))
        .expect("alice create_group failed");
    let group_id = create_res.group_id;
    let alice_epoch_after_create = alice_ctx.get_epoch(group_id.clone()).unwrap();
    assert_eq!(
        alice_epoch_after_create, 0,
        "fresh group should start at epoch 0 (sanity)"
    );

    // 2. Advance Alice's epoch to at least 1 by adding a throwaway member.
    let alice_epoch_post_add =
        advance_alice_by_adding_and_removing(&alice_ctx, alice_id, &group_id, &carol_ctx, carol_id);
    assert!(
        alice_epoch_post_add >= 1,
        "alice epoch should have advanced past 0; got {}",
        alice_epoch_post_add
    );

    // 3. Alice exports GroupInfo at her current epoch E.
    let group_info_bytes = alice_ctx
        .export_group_info(group_id.clone(), alice_id.to_vec())
        .expect("alice export_group_info failed");

    // 4. Bob uses it for External Commit. This is the exact sequence iOS runs.
    let ext_commit = bob_ctx
        .create_external_commit(group_info_bytes.clone(), bob_id.to_vec())
        .expect("bob create_external_commit failed");

    // 5. AUTHORITATIVE CHECK: Bob's local epoch, read back through the FFI
    //    (same path iOS hits via `ctx.currentEpoch(groupId)`), must be strictly
    //    GREATER than the GroupInfo source epoch. The external commit adds
    //    exactly 1 to the epoch, so we expect alice_epoch_post_add + 1.
    let bob_local_epoch = bob_ctx
        .get_epoch(ext_commit.group_id.clone())
        .expect("bob get_epoch after external commit failed");
    assert_eq!(
        bob_local_epoch,
        alice_epoch_post_add + 1,
        "After External Commit, Bob's local epoch must be source epoch + 1. \
         Source (GroupInfo) epoch={}, Bob's reported epoch={}. \
         If bob_local_epoch == source epoch, the external commit merge never \
         advanced OpenMLS's group state (silent no-op). \
         If bob_local_epoch == 0, the FFI is reading the wrong group.",
        alice_epoch_post_add,
        bob_local_epoch
    );
}

#[test]
fn external_commit_from_stale_member_advances_past_stale_epoch() {
    // Reproduce the production "rejoiner" scenario:
    //   - Bob was a member at epoch N, has local group state at epoch N
    //   - Meanwhile Alice advanced to epoch N+k
    //   - Bob's network comes back, he "loses sync", re-joins via External
    //     Commit using Alice's latest GroupInfo.
    //   - Bob's FFI `get_epoch` must now report N+k+1, NOT N.

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let carol_dir = tempfile::tempdir().unwrap();
    let dave_dir = tempfile::tempdir().unwrap();

    let alice_ctx = new_ctx(&alice_dir);
    let bob_ctx = new_ctx(&bob_dir);
    let carol_ctx = new_ctx(&carol_dir);
    let dave_ctx = new_ctx(&dave_dir);

    let alice_id: &[u8] = b"did:plc:alice";
    let bob_id: &[u8] = b"did:plc:bob";
    let carol_id: &[u8] = b"did:plc:carol";
    let dave_id: &[u8] = b"did:plc:dave";

    // Alice creates group at epoch 0.
    let create_res = alice_ctx
        .create_group(alice_id.to_vec(), Some(GroupConfig::default()))
        .expect("alice create_group failed");
    let group_id = create_res.group_id;

    // Alice adds Bob via Welcome — Bob now has the group at epoch 1.
    let bob_kp = bob_ctx
        .create_key_package(bob_id.to_vec())
        .expect("bob create_key_package failed");
    let add_bob = alice_ctx
        .add_members(
            group_id.clone(),
            vec![KeyPackageData {
                data: bob_kp.key_package_data,
            }],
        )
        .expect("alice add_members(bob) failed");
    let _ = alice_ctx
        .merge_pending_commit(group_id.clone())
        .expect("alice merge after add bob failed");

    // Bob processes the Welcome so he has real local state for this group_id.
    let welcome_res = bob_ctx
        .process_welcome(
            add_bob.welcome_data,
            bob_id.to_vec(),
            Some(GroupConfig::default()),
        )
        .expect("bob process_welcome failed");
    assert_eq!(welcome_res.group_id, group_id);
    let bob_epoch_after_welcome = bob_ctx.get_epoch(group_id.clone()).unwrap();
    assert_eq!(
        bob_epoch_after_welcome, 1,
        "bob should be at epoch 1 after welcome"
    );

    // Alice advances further without Bob (simulate Bob offline).
    for (dummy_ctx, dummy_id) in [(&carol_ctx, carol_id), (&dave_ctx, dave_id)] {
        let kp = dummy_ctx
            .create_key_package(dummy_id.to_vec())
            .expect("dummy create_key_package failed");
        let _ = alice_ctx
            .add_members(
                group_id.clone(),
                vec![KeyPackageData {
                    data: kp.key_package_data,
                }],
            )
            .expect("alice add_members(dummy) failed");
        let _ = alice_ctx
            .merge_pending_commit(group_id.clone())
            .expect("alice merge after add dummy failed");
    }
    let alice_final_epoch = alice_ctx.get_epoch(group_id.clone()).unwrap();
    assert!(
        alice_final_epoch >= 3,
        "alice should be at epoch >= 3; got {}",
        alice_final_epoch
    );

    // Bob's local state is still at epoch 1 — he's "behind" just like a
    // production client after missing commits.
    let bob_epoch_before_rejoin = bob_ctx.get_epoch(group_id.clone()).unwrap();
    assert_eq!(
        bob_epoch_before_rejoin, 1,
        "bob should still be stuck at epoch 1 (stale)"
    );

    // Alice exports GroupInfo at her current epoch.
    let fresh_group_info = alice_ctx
        .export_group_info(group_id.clone(), alice_id.to_vec())
        .expect("alice export_group_info failed");

    // Bob does an External Commit using the fresh GroupInfo.
    let ext_commit = bob_ctx
        .create_external_commit(fresh_group_info, bob_id.to_vec())
        .expect("bob create_external_commit (rejoin) failed");
    assert_eq!(
        ext_commit.group_id, group_id,
        "external commit should target same group_id"
    );

    // THE PRODUCTION REGRESSION CHECK:
    // Before the fix, Bob's get_epoch would return 1 (stale) instead of
    // alice_final_epoch + 1. Verify the FFI reports the POST-JOIN epoch.
    let bob_epoch_after_rejoin = bob_ctx.get_epoch(group_id.clone()).unwrap();
    assert_eq!(
        bob_epoch_after_rejoin,
        alice_final_epoch + 1,
        "After External Commit rejoin, Bob's local epoch must be \
         alice_final_epoch + 1 ({}+1 = {}), got {}. \
         If this equals {} (alice's source epoch), the merge was silent: \
         `create_external_commit` replaced the in-memory group but the \
         post-merge group is still at the source epoch. \
         If this equals 1 (bob's pre-rejoin stale epoch), the new external \
         commit didn't replace Bob's existing group state.",
        alice_final_epoch,
        alice_final_epoch + 1,
        bob_epoch_after_rejoin,
        alice_final_epoch,
    );
}
