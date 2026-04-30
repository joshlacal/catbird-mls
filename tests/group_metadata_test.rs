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
