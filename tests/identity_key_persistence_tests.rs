//! Regression coverage for imported identity signer custody.
//!
//! An imported `SignatureKeyPair` must be stored under the same scheme-qualified
//! identifier used by `SignatureKeyPair::read`.  Otherwise a cold start drops
//! the manifest entry and mints a different signer for the identity.

use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct TestKeychain {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            values: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.values.lock().unwrap().get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.values.lock().unwrap().insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.values.lock().unwrap().remove(&key);
        Ok(())
    }
}

#[test]
fn imported_identity_key_survives_context_restart_without_key_rotation() {
    let identity = "did:plc:imported-signer#device-1";
    let source_dir = tempfile::tempdir().expect("source tempdir");
    let source_path = source_dir.path().join("mls.db");
    let source = MLSContext::new(
        source_path.to_string_lossy().to_string(),
        "test-key".to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("source context");
    let original = source
        .create_key_package(identity.as_bytes().to_vec())
        .expect("create source key package");
    let exported = source
        .export_identity_key(identity.to_string())
        .expect("export identity key");
    drop(source);

    let imported_dir = tempfile::tempdir().expect("imported tempdir");
    let imported_path = imported_dir.path().join("mls.db");
    let keychain = TestKeychain::new();
    let imported = MLSContext::new(
        imported_path.to_string_lossy().to_string(),
        "test-key".to_string(),
        Box::new(keychain.clone()),
    )
    .expect("import context");
    imported
        .import_identity_key(identity.to_string(), exported)
        .expect("import identity key");
    drop(imported);

    let reopened = MLSContext::new(
        imported_path.to_string_lossy().to_string(),
        "test-key".to_string(),
        Box::new(keychain),
    )
    .expect("reopened context");
    let after_restart = reopened
        .create_key_package(identity.as_bytes().to_vec())
        .expect("reuse imported signer after restart");

    assert_eq!(
        after_restart.signature_public_key, original.signature_public_key,
        "restart must reuse the imported signer instead of minting a new key"
    );
}
