//! Integration test for `MLSContext::create_group_with_id` (spec §8.5
//! first-responder bootstrap).
//!
//! Asserts that creating a group at a predetermined `group_id` produces an
//! `MlsGroup` whose `group_id()` matches the bytes the caller supplied bit-
//! for-bit. This is the load-bearing invariant for first-responder bootstrap:
//! every candidate creates an MLS group at the SAME id so the race winner's
//! Welcome message can be deserialized by every recipient — if `group_id`
//! drifted, race losers would be holding orphan local groups against the
//! winner's published Welcome.

use async_trait::async_trait;
use catbird_mls::{GroupConfig, KeychainAccess, MLSContext, MLSError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
        "catbird_mls_create_group_with_id_test_{}_{}_{}",
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
fn create_group_with_id_uses_predetermined_bytes() {
    let (ctx, _dir) = make_context();

    // 32 bytes — the size of a hex-decoded `groupResetEvent.newGroupId`
    // (server emits a SHA-256-style identifier for the post-reset group).
    let predetermined = vec![
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18,
    ];

    let result = ctx
        .create_group_with_id(
            b"alice@example.com".to_vec(),
            predetermined.clone(),
            Some(GroupConfig::default()),
        )
        .expect("create_group_with_id should succeed");

    assert_eq!(
        result.group_id, predetermined,
        "MLSContext::create_group_with_id MUST return a group whose id matches the caller's bytes verbatim — race-loss recipients would otherwise reject the winner's Welcome"
    );

    // Sanity: the FFI epoch lookup is keyed on the same group_id we supplied.
    let epoch = ctx
        .get_epoch(predetermined)
        .expect("get_epoch should succeed for newly-created group");
    assert_eq!(epoch, 0, "newly-created group should be at epoch 0");
}

#[test]
fn create_group_without_id_still_uses_random_openmls_default() {
    // Backward-compat: existing `create_group(identity, config)` callers must
    // keep getting OpenMLS-generated random group_ids. Regression guard for
    // the create_group_internal refactor that routes both paths through one
    // implementation.
    let (ctx, _dir) = make_context();

    let result_a = ctx
        .create_group(b"alice@example.com".to_vec(), Some(GroupConfig::default()))
        .expect("create_group should succeed");
    let result_b = ctx
        .create_group(b"bob@example.com".to_vec(), Some(GroupConfig::default()))
        .expect("create_group should succeed");

    assert_ne!(
        result_a.group_id, result_b.group_id,
        "two separate create_group calls must produce different random ids"
    );
    assert!(
        !result_a.group_id.is_empty(),
        "OpenMLS should always pick a non-empty random id"
    );
}

#[test]
fn create_group_with_id_two_calls_at_same_id_are_rejected_by_storage() {
    // Sanity check: OpenMLS storage can't hold two groups at the same id in
    // the same MLSContext. This isn't the production race-loss path (the
    // server's createConvo returns 409 ConvoAlreadyExists BEFORE we'd hit
    // local storage on subsequent attempts), but it documents that local
    // storage is also collision-safe — race losers should always
    // `delete_group(predetermined)` after seeing the 409, never assume the
    // local entry was magically cleaned up.
    let (ctx, _dir) = make_context();

    let predetermined = vec![0xff; 32];

    let first = ctx.create_group_with_id(
        b"alice@example.com".to_vec(),
        predetermined.clone(),
        Some(GroupConfig::default()),
    );
    assert!(first.is_ok(), "first create_group_with_id should succeed");

    let second = ctx.create_group_with_id(
        b"alice@example.com".to_vec(),
        predetermined.clone(),
        Some(GroupConfig::default()),
    );
    assert!(
        second.is_err(),
        "second create_group_with_id at the same id MUST fail (local storage collision); race losers must delete_group before retrying"
    );
}
