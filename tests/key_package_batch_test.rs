//! Integration tests for `MLSContext::create_key_packages` — the batched
//! key package creation path added for 0xdead10cc prevention.
//!
//! The batch must: produce `count` distinct, persisted bundles with a SINGLE
//! persistence pass; survive a context reopen (per-row storage + startup
//! load); and respect the suspension flag (refuse to start while suspended,
//! resume normally after the flag clears).

use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use openmls::prelude::{DeserializeBytes, KeyPackageIn, ProtocolVersion};
use openmls_traits::OpenMlsProvider;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct TestKeychain {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
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

fn make_db_path() -> (String, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "catbird_mls_key_package_batch_test_{}_{}_{}",
        std::process::id(),
        id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    (dir.join("test.db").to_str().unwrap().to_string(), dir)
}

fn open_context_with_keychain(path: &str, keychain: TestKeychain) -> Arc<MLSContext> {
    MLSContext::new(
        path.to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(keychain),
    )
    .unwrap()
}

fn open_context(path: &str) -> Arc<MLSContext> {
    open_context_with_keychain(path, TestKeychain::new())
}

const IDENTITY: &[u8] = b"did:plc:batchtest#device-1";

#[test]
fn batch_creates_count_distinct_persisted_bundles() {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    let results = ctx
        .create_key_packages(IDENTITY.to_vec(), 5)
        .expect("batch creation should succeed");

    assert_eq!(results.len(), 5, "batch must return one result per package");

    let mut hash_refs: Vec<Vec<u8>> = results.iter().map(|r| r.hash_ref.clone()).collect();
    hash_refs.sort();
    hash_refs.dedup();
    assert_eq!(hash_refs.len(), 5, "every key package must be distinct");

    // The whole batch reuses ONE persistent identity signer.
    let first_pk = &results[0].signature_public_key;
    for r in &results {
        assert_eq!(
            &r.signature_public_key, first_pk,
            "all packages in a batch must share the persistent identity signer"
        );
    }

    let count = ctx.get_key_package_bundle_count().unwrap();
    assert_eq!(count, 5, "all bundles must be cached after the batch");
}

#[test]
fn batch_bundles_survive_context_reopen() {
    let (path, _dir) = make_db_path();
    let keychain = TestKeychain::new();
    let ctx = open_context_with_keychain(&path, keychain.clone());

    let results = ctx.create_key_packages(IDENTITY.to_vec(), 3).unwrap();
    assert_eq!(results.len(), 3);

    ctx.flush_and_prepare_close()
        .expect("graceful close should succeed");
    drop(ctx);

    // Reopen: bundles must load from per-row storage into the cache.
    let reopened = open_context_with_keychain(&path, keychain);
    let count = reopened.get_key_package_bundle_count().unwrap();
    assert_eq!(
        count, 3,
        "bundles persisted by the batch must survive a context reopen"
    );

    // And the specific hash_refs must still be resolvable for Welcome processing.
    for r in &results {
        assert!(
            reopened
                .debug_check_key_package_hash(hex::encode(&r.hash_ref))
                .unwrap_or(false),
            "bundle {} must be loadable after reopen",
            hex::encode(&r.hash_ref)
        );
    }
}

#[test]
fn suspended_context_refuses_batch_then_recovers() {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    ctx.set_suspended(true);
    match ctx.create_key_packages(IDENTITY.to_vec(), 2) {
        Ok(_) => panic!("batch must refuse to start while suspension is in progress"),
        Err(err) => assert!(
            matches!(err, MLSError::ContextClosed),
            "suspension bail-out must surface as ContextClosed, got {:?}",
            err
        ),
    }

    // Nothing should have been persisted.
    assert_eq!(ctx.get_key_package_bundle_count().unwrap(), 0);

    // Clearing the flag restores normal operation (BGTask start path).
    ctx.set_suspended(false);
    let results = ctx.create_key_packages(IDENTITY.to_vec(), 2).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn single_create_delegates_to_batch() {
    // Backward-compat: `create_key_package` (count=1 path) must keep working
    // for the orchestrator and existing platform callers.
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    let result = ctx.create_key_package(IDENTITY.to_vec()).unwrap();
    assert!(!result.key_package_data.is_empty());
    assert!(!result.hash_ref.is_empty());
    assert_eq!(ctx.get_key_package_bundle_count().unwrap(), 1);
}

#[test]
fn oversized_local_batch_is_rejected_before_allocation_or_generation() {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    let error = match ctx.create_key_packages(IDENTITY.to_vec(), 101) {
        Ok(_) => panic!("local KeyPackage batches above the fixed ceiling must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, MLSError::InvalidInput { .. }));
    assert_eq!(ctx.get_key_package_bundle_count().unwrap(), 0);
}

#[test]
fn direct_add_rejects_key_package_size_limits_before_tls_parsing() {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    let oversized_package = catbird_mls::KeyPackageData {
        data: vec![0_u8; 1024 * 1024 + 1],
    };
    let error = match ctx.add_members(vec![0xAA; 32], vec![oversized_package]) {
        Ok(_) => {
            panic!("a package above the fixed ceiling must fail before group lookup or parsing")
        }
        Err(error) => error,
    };
    assert!(matches!(error, MLSError::InvalidInput { .. }));

    let oversized_swap_package = catbird_mls::KeyPackageData {
        data: vec![0_u8; 1024 * 1024 + 1],
    };
    let error = match ctx.swap_members(
        vec![0xAA; 32],
        vec![b"did:plc:old-member".to_vec()],
        vec![oversized_swap_package],
    ) {
        Ok(_) => panic!("raw swap must apply the same pre-parse package ceiling as raw add"),
        Err(error) => error,
    };
    assert!(matches!(error, MLSError::InvalidInput { .. }));

    let aggregate_batch = (0..11)
        .map(|_| catbird_mls::KeyPackageData {
            data: vec![0_u8; 1024 * 1024],
        })
        .collect();
    let error = match ctx.add_members(vec![0xAA; 32], aggregate_batch) {
        Ok(_) => panic!("an aggregate batch above ten MiB must fail before TLS parsing"),
        Err(error) => error,
    };
    assert!(matches!(error, MLSError::InvalidInput { .. }));
}

#[test]
fn direct_stage_rejects_key_package_count_before_group_lookup_or_conversion() {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    let error = match ctx.stage_commit(
        "not-a-group-id".to_string(),
        catbird_mls::orchestrator_bridge::FFICommitKind::SwapMembers {
            remove_dids: Vec::new(),
            add_dids: (0..101).map(|i| format!("did:plc:member{i}")).collect(),
            add_key_packages: vec![Vec::new(); 101],
        },
        IDENTITY.to_vec(),
    ) {
        Ok(_) => panic!("the 101-package batch must be rejected before invalid group lookup"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("101 packages"),
        "unexpected error: {message}"
    );
    assert!(
        !message.contains("Invalid hex group ID"),
        "batch limits must run before group decoding"
    );
}

#[test]
fn last_resort_create_marks_package_and_persists_bundle() {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);

    let result = ctx
        .create_last_resort_key_package(IDENTITY.to_vec())
        .expect("last-resort key package creation should succeed");
    assert!(!result.key_package_data.is_empty());
    assert!(!result.hash_ref.is_empty());
    assert_eq!(ctx.get_key_package_bundle_count().unwrap(), 1);

    let (kp_in, remaining) = if let Ok((msg, remaining)) =
        openmls::prelude::MlsMessageIn::tls_deserialize_bytes(&result.key_package_data)
    {
        match msg.extract() {
            openmls::prelude::MlsMessageBodyIn::KeyPackage(kp) => (kp, remaining),
            _ => panic!("expected KeyPackage message"),
        }
    } else {
        KeyPackageIn::tls_deserialize_bytes(&result.key_package_data)
            .expect("generated key package should deserialize")
    };
    assert!(
        remaining.is_empty(),
        "KeyPackage serialization should not leave trailing bytes"
    );

    use openmls_traits::OpenMlsProvider;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .expect("generated key package should validate");
    assert!(
        !kp.leaf_node().signature_key().as_slice().is_empty(),
        "generated package must be valid"
    );
}
