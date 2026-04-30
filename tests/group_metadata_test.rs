//! Integration test for group context extension metadata

use async_trait::async_trait;
use catbird_mls::group_metadata::GroupMetadata;
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

// MLS metadata cutover (Phase A): plaintext 0xff00 GroupContext extension is
// retired. `create_group` no longer writes a plaintext extension when
// `group_name` / `group_description` are set; `update_group_metadata` no
// longer writes one either, and prunes any leftover entry from groups
// created by older builds. Title / description / avatar live exclusively in
// encrypted `GroupMetadataV1` blobs; the MLS group context only carries an
// opaque `MetadataReference` at AppDataDictionary component 0x8001 (see
// `src/metadata.rs` and its dedicated tests).

#[test]
fn create_group_with_name_does_not_write_plaintext_0xff00() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("Engineering".to_string()),
        group_description: Some("desc".to_string()),
        ..Default::default()
    };

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    // The plaintext 0xff00 reader must observe nothing: encrypted-only
    // path is authoritative now.
    let meta_bytes = ctx.get_group_metadata(result.group_id).unwrap();
    assert!(
        meta_bytes.is_empty(),
        "create_group must not write plaintext 0xff00 extension; got {} bytes",
        meta_bytes.len()
    );
}

#[test]
fn test_create_group_without_metadata() {
    let (ctx, _dir) = make_context();

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), None)
        .unwrap();

    let meta_bytes = ctx.get_group_metadata(result.group_id).unwrap();
    assert!(meta_bytes.is_empty(), "No metadata should be present");
}

#[test]
fn update_group_metadata_produces_commit_without_plaintext() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("Original".to_string()),
        ..Default::default()
    };
    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    // The `metadata` parameter is retained for source-compat with existing
    // callers, but its title/description are intentionally not written
    // into the MLS group context. The commit must still be produced — it
    // advances the AppDataDictionary `MetadataReference` so joiners pick
    // up the new encrypted blob locator.
    let payload = GroupMetadata::new(
        Some("Renamed".to_string()),
        Some("New".to_string()),
    );
    let commit_bytes = ctx
        .update_group_metadata(result.group_id.clone(), payload.to_extension_bytes().unwrap())
        .unwrap();
    assert!(!commit_bytes.is_empty(), "commit bytes should be produced");

    // Pre-merge: still no plaintext.
    let pre = ctx.get_group_metadata(result.group_id.clone()).unwrap();
    assert!(pre.is_empty(), "pre-merge plaintext 0xff00 must be absent");

    // Post-merge: still no plaintext.
    ctx.merge_pending_commit(result.group_id.clone()).unwrap();
    let post = ctx.get_group_metadata(result.group_id).unwrap();
    assert!(post.is_empty(), "post-merge plaintext 0xff00 must be absent");
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
