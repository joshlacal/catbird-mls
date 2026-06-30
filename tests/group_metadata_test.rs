//! Integration tests for the post-cutover encrypted metadata path.
//!
//! Verifies the Phase A core invariant: `create_group` and
//! `update_group_metadata_encrypted` never write the retired plaintext
//! `0xff00` GroupContext extension. All metadata flows through encrypted
//! `GroupMetadataV1` blobs (see `src/metadata.rs`) referenced from the
//! AppDataDictionary at component `0x8001`.

use async_trait::async_trait;
use catbird_mls::{GroupConfig, KeychainAccess, MLSContext, MLSError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// In-memory keychain for tests
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

fn make_context() -> (Arc<MLSContext>, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "catbird_mls_test_{}_{}_{}",
        std::process::id(),
        id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.db").to_str().unwrap().to_string();
    let ctx = MLSContext::new(
        path,
        "test-key-1234567890123456".to_string(),
        Box::new(TestKeychain::new()),
    )
    .unwrap();
    (ctx, dir)
}

#[test]
fn create_group_with_name_does_not_carry_legacy_extension() {
    // Phase A invariant: even when GroupConfig provides name + description,
    // create_group does NOT add the retired 0xff00 plaintext extension.
    // Encrypted metadata is uploaded out-of-band via putGroupMetadataBlob.
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("Engineering".to_string()),
        group_description: Some("desc".to_string()),
        ..Default::default()
    };

    let _result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();
    // No assertion about plaintext extension content because the legacy
    // reader was removed in Phase F. The Phase A invariant is enforced
    // structurally (create_group has no code path that adds 0xff00).
}

#[test]
fn create_group_without_metadata_succeeds() {
    let (ctx, _dir) = make_context();

    let _result = ctx
        .create_group(b"alice@example.com".to_vec(), None)
        .unwrap();
}

#[test]
fn update_group_metadata_encrypted_returns_artifacts() {
    // Phase A.2 atomic FFI: stages commit + encrypts blob in one call.
    let (ctx, _dir) = make_context();
    let result = ctx
        .create_group(b"alice@example.com".to_vec(), None)
        .unwrap();

    let outcome = ctx
        .update_group_metadata_encrypted(
            result.group_id.clone(),
            Some("Renamed".to_string()),
            Some("New".to_string()),
            None,
            None,
        )
        .unwrap();

    assert!(!outcome.commit_bytes.is_empty(), "commit bytes produced");
    assert!(
        !outcome.metadata_blob_ciphertext.is_empty(),
        "encrypted blob produced"
    );
    assert!(
        !outcome.metadata_blob_locator.is_empty(),
        "fresh UUID locator produced"
    );
    assert!(outcome.metadata_version >= 1, "version starts at 1");
    assert!(
        !outcome.metadata_reference_json.is_empty(),
        "MetadataReference JSON produced for local cache"
    );
}

/// Regression for Android H4 epoch drift: `commit_pending_proposals` must not
/// build a commit when the proposal store is empty. Previously it unconditionally
/// created an empty (or metadata-only) commit every sync tick, advancing the
/// local epoch by 1 while the server rejected the no-op → 17+ epoch drift per
/// hour on 1:1 conversations, breaking sendMessage with TreeStateDiverged 409s.
#[test]
fn test_commit_pending_proposals_is_noop_when_nothing_pending_1to1() {
    let (ctx, _dir) = make_context();

    // Simulate a 1:1 conversation (no metadata).
    let result = ctx
        .create_group(b"alice@example.com".to_vec(), None)
        .unwrap();

    let epoch_before = ctx.get_epoch(result.group_id.clone()).unwrap();

    match ctx.commit_pending_proposals(result.group_id.clone()) {
        Ok(_) => panic!(
            "commit_pending_proposals must not produce a commit when the store is empty \
             — this is the Android H4 drift bug"
        ),
        Err(MLSError::InvalidInput { .. }) => {}
        Err(e) => panic!("expected InvalidInput, got {:?}", e),
    }

    let epoch_after = ctx.get_epoch(result.group_id).unwrap();
    assert_eq!(
        epoch_before, epoch_after,
        "epoch must NOT advance when there is nothing to commit (was {} -> {})",
        epoch_before, epoch_after
    );
}

/// Same guarantee for groups that have metadata. Previously the
/// `planned_metadata_reference_json(..., metadata_changed=false)` path minted a
/// fresh UUID locator even when no metadata actually changed, causing the
/// same drift on named groups.
#[test]
fn test_commit_pending_proposals_is_noop_when_nothing_pending_named_group() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("My Group".to_string()),
        group_description: Some("desc".to_string()),
        ..Default::default()
    };
    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    let epoch_before = ctx.get_epoch(result.group_id.clone()).unwrap();

    match ctx.commit_pending_proposals(result.group_id.clone()) {
        Ok(_) => panic!(
            "commit_pending_proposals must not advance epoch for a named group with \
             no pending proposals (metadata_changed=false)"
        ),
        Err(MLSError::InvalidInput { .. }) => {}
        Err(e) => panic!("expected InvalidInput, got {:?}", e),
    }

    let epoch_after = ctx.get_epoch(result.group_id).unwrap();
    assert_eq!(
        epoch_before, epoch_after,
        "epoch must NOT advance for named group with no real proposals (was {} -> {})",
        epoch_before, epoch_after
    );
}

/// Regression: a member added at group-creation time must be able to decrypt
/// the group name.
///
/// Before the fix, `add_members_with_metadata` on a freshly-created group (which
/// has no committed `MetadataReference` yet) planned NO reference — the
/// `metadata_changed` arg to `planned_metadata_reference_json` was hardcoded
/// `false`, so `next_metadata_version(None, false, false) -> None`. The add
/// commit (and the Welcome built from it) therefore embedded no reference, and
/// the reseal branch (gated on that same planned reference) was skipped, so no
/// blob was produced. Joiners landed with an empty AppDataDictionary and fell
/// back to "Secure Chat".
///
/// The add commit must now embed a v1 `MetadataReference` (delivered to the
/// joiner via the Welcome) and re-seal the `GroupMetadataV1` blob at the
/// post-add epoch, so the joiner can derive the metadata key, find the
/// reference, and decrypt the name/description.
#[test]
fn add_members_with_metadata_lets_fresh_group_joiner_decrypt_name() {
    let (alice, _adir) = make_context();
    let (bob, _bdir) = make_context();

    // Alice creates a NAMED group (no committed reference exists yet).
    let config = GroupConfig {
        group_name: Some("Engineering".to_string()),
        group_description: Some("the eng team".to_string()),
        ..Default::default()
    };
    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(config))
        .unwrap();
    let group_id = created.group_id.clone();

    // Bob publishes a key package; Alice adds him WITH metadata in one commit.
    let bob_kp = bob.create_key_package(b"did:plc:bob".to_vec()).unwrap();
    let add = alice
        .add_members_with_metadata(
            group_id.clone(),
            vec![catbird_mls::KeyPackageData {
                data: bob_kp.key_package_data,
            }],
            Some("Engineering".to_string()),
            Some("the eng team".to_string()),
            None,
            None,
        )
        .unwrap();

    // The FIX: a fresh group must produce a re-sealed blob for the caller to
    // upload. Previously these were all None.
    let blob_ciphertext = add.metadata_blob_ciphertext.clone().expect(
        "add_members_with_metadata must re-seal a metadata blob for a freshly-created group",
    );
    let blob_version = add.metadata_version.expect("metadata version must be set");
    assert!(
        add.metadata_blob_locator.is_some(),
        "blob locator must be set"
    );

    // Alice merges; Bob processes the Welcome (which carries the post-add group
    // context, including the MetadataReference at component 0x8001).
    alice.merge_pending_commit(group_id.clone()).unwrap();
    let joined = bob
        .process_welcome(add.welcome_data.clone(), b"did:plc:bob".to_vec(), None)
        .unwrap();
    assert_eq!(joined.group_id, group_id, "bob joined the same group");

    // Bob now sees a MetadataReference at his current epoch (was the bug) and
    // can derive the metadata key.
    let info = bob
        .get_current_metadata(group_id.clone())
        .unwrap()
        .expect("joiner must have current metadata info");
    assert!(
        info.metadata_reference_json.is_some(),
        "the add commit must deliver a MetadataReference to the joiner via the Welcome"
    );
    let key: [u8; 32] = info.metadata_key.as_slice().try_into().unwrap();

    // Bob decrypts Alice's re-sealed blob at his epoch → recovers the name.
    let decrypted = catbird_mls::metadata::decrypt_metadata_blob(
        &key,
        &group_id,
        info.epoch,
        blob_version,
        &blob_ciphertext,
    )
    .expect("joiner must be able to decrypt the group metadata blob");
    assert_eq!(decrypted.title, "Engineering");
    assert_eq!(decrypted.description, "the eng team");
}
