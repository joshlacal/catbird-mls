use async_trait::async_trait;
use catbird_mls::{
    mls_classify_key_package_binding, mls_classify_peer_bad_error, FfiKeyPackageBindingStatus,
    FfiMlsErrorKind, KeychainAccess, MLSContext, MLSError,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

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

fn make_db_path() -> (String, std::path::PathBuf) {
    let sequence = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "catbird_mls_ffi_bridge_classifier_test_{}_{}_{}",
        std::process::id(),
        sequence,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    (dir.join("test.db").to_str().unwrap().to_string(), dir)
}

fn open_context(path: &str) -> Arc<MLSContext> {
    MLSContext::new(
        path.to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(TestKeychain::new()),
    )
    .unwrap()
}

fn alice_key_package() -> (Vec<u8>, Vec<u8>) {
    let (path, _dir) = make_db_path();
    let ctx = open_context(&path);
    let result = ctx
        .create_key_package(b"did:plc:alice#device-1".to_vec())
        .expect("key package creation should succeed");
    (result.key_package_data, result.signature_public_key)
}

#[test]
fn key_package_binding_classifier_accepts_matching_identity_and_signing_key() {
    let (key_package, signature_key) = alice_key_package();

    let classification = mls_classify_key_package_binding(
        "did:plc:alice".to_string(),
        key_package,
        Some(vec![signature_key]),
    );

    assert_eq!(classification.status, FfiKeyPackageBindingStatus::Verified);
    assert!(classification.identity_matches);
    assert_eq!(classification.signing_key_matches, Some(true));
    assert_eq!(
        classification.claimed_identity.as_deref(),
        Some("did:plc:alice#device-1")
    );
}

#[test]
fn key_package_binding_classifier_rejects_case_distinct_did_root() {
    let (key_package, signature_key) = alice_key_package();

    let classification = mls_classify_key_package_binding(
        "did:plc:Alice".to_string(),
        key_package,
        Some(vec![signature_key]),
    );

    assert_eq!(
        classification.status,
        FfiKeyPackageBindingStatus::IdentityMismatch
    );
    assert!(!classification.identity_matches);
    assert_eq!(classification.signing_key_matches, Some(true));
    assert_eq!(
        classification.claimed_root_did.as_deref(),
        Some("did:plc:alice")
    );
}

#[test]
fn key_package_binding_classifier_reports_identity_mismatch_before_key_mismatch() {
    let (key_package, signature_key) = alice_key_package();

    let classification = mls_classify_key_package_binding(
        "did:plc:bob".to_string(),
        key_package,
        Some(vec![signature_key]),
    );

    assert_eq!(
        classification.status,
        FfiKeyPackageBindingStatus::IdentityMismatch
    );
    assert!(!classification.identity_matches);
    assert_eq!(classification.signing_key_matches, Some(true));
    assert!(classification
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("does not match expected DID"));
}

#[test]
fn key_package_binding_classifier_reports_signing_key_mismatch() {
    let (key_package, _signature_key) = alice_key_package();

    let classification = mls_classify_key_package_binding(
        "did:plc:alice".to_string(),
        key_package,
        Some(vec![vec![0x42; 32]]),
    );

    assert_eq!(
        classification.status,
        FfiKeyPackageBindingStatus::SigningKeyMismatch
    );
    assert!(classification.identity_matches);
    assert_eq!(classification.signing_key_matches, Some(false));
}

#[test]
fn key_package_binding_classifier_reports_unavailable_signing_key_resolution() {
    let (key_package, _signature_key) = alice_key_package();

    let classification =
        mls_classify_key_package_binding("did:plc:alice".to_string(), key_package, None);

    assert_eq!(
        classification.status,
        FfiKeyPackageBindingStatus::SigningKeyUnavailable
    );
    assert!(classification.identity_matches);
    assert_eq!(classification.signing_key_matches, None);
}

#[test]
fn peer_bad_error_classifier_matches_orchestrator_epoch_gate() {
    let peer_bad =
        mls_classify_peer_bad_error(FfiMlsErrorKind::InvalidCommit, "".to_string(), Some(7), 7);
    assert!(peer_bad.peer_bad);
    assert!(peer_bad.quarantine_trigger_eligible);
    assert!(!peer_bad.wrong_epoch);

    let catching_up =
        mls_classify_peer_bad_error(FfiMlsErrorKind::InvalidCommit, "".to_string(), Some(6), 7);
    assert!(!catching_up.peer_bad);
    assert!(!catching_up.quarantine_trigger_eligible);

    let wrong_epoch = mls_classify_peer_bad_error(
        FfiMlsErrorKind::OpenMls,
        "ValidationError(WrongEpoch)".to_string(),
        Some(7),
        7,
    );
    assert!(!wrong_epoch.peer_bad);
    assert!(wrong_epoch.wrong_epoch);

    let flattened = mls_classify_peer_bad_error(
        FfiMlsErrorKind::DecryptionFailed,
        "Decryption failed".to_string(),
        Some(7),
        7,
    );
    assert!(!flattened.peer_bad);
}
