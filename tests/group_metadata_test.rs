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

#[test]
fn test_create_group_with_metadata() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("My Group".to_string()),
        group_description: Some("A test group".to_string()),
        ..Default::default()
    };

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    // get_group_metadata returns JSON bytes via the FFI layer.
    // At creation, metadata is plaintext; the MEK-based reader
    // handles the plaintext fallback transparently.
    let meta_bytes = ctx.get_group_metadata(result.group_id.clone()).unwrap();
    assert!(!meta_bytes.is_empty(), "Metadata should be present");

    let meta = GroupMetadata::from_extension_bytes(&meta_bytes).unwrap();
    assert_eq!(meta.name.as_deref(), Some("My Group"));
    assert_eq!(meta.description.as_deref(), Some("A test group"));
    assert!(meta.avatar_hash.is_none());
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
fn test_update_group_metadata_produces_commit() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("Original".to_string()),
        ..Default::default()
    };

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    let new_meta = GroupMetadata::new(
        Some("Renamed Group".to_string()),
        Some("New description".to_string()),
    );
    let commit_bytes = ctx
        .update_group_metadata(
            result.group_id.clone(),
            new_meta.to_extension_bytes().unwrap(),
        )
        .unwrap();
    assert!(!commit_bytes.is_empty(), "Commit bytes should be produced");

    // Before merge, the group is still at the old epoch with plaintext metadata
    // from creation (the pending commit hasn't been applied yet).
    let meta_bytes = ctx.get_group_metadata(result.group_id.clone()).unwrap();
    assert!(!meta_bytes.is_empty(), "Original metadata should still be readable before merge");
    let meta = GroupMetadata::from_extension_bytes(&meta_bytes).unwrap();
    assert_eq!(meta.name.as_deref(), Some("Original"));
}

#[test]
fn test_update_group_metadata_readable_after_merge() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("Original".to_string()),
        ..Default::default()
    };

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    let new_meta = GroupMetadata::new(
        Some("Renamed Group".to_string()),
        Some("New description".to_string()),
    );
    let _commit_bytes = ctx
        .update_group_metadata(
            result.group_id.clone(),
            new_meta.to_extension_bytes().unwrap(),
        )
        .unwrap();

    // Merge the pending commit (simulating server ACK)
    ctx.merge_pending_commit(result.group_id.clone()).unwrap();

    // After merge the epoch has advanced, but the metadata was encrypted
    // with the stable per-group MEK, so it remains readable.
    let meta_bytes = ctx.get_group_metadata(result.group_id).unwrap();
    assert!(!meta_bytes.is_empty(), "Metadata should be readable after epoch advance");

    let meta = GroupMetadata::from_extension_bytes(&meta_bytes).unwrap();
    assert_eq!(meta.name.as_deref(), Some("Renamed Group"));
    assert_eq!(meta.description.as_deref(), Some("New description"));
}
