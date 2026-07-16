use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

struct TestKeychain {
    values: Mutex<HashMap<String, Vec<u8>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            values: Mutex::new(HashMap::new()),
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

fn derive_cipher_salt_hex(encryption_key: &str) -> String {
    let digest = Sha256::digest(encryption_key.as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn open_manifest_connection(path: &std::path::Path, encryption_key: &str) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(path).expect("open test database");
    connection
        .pragma_update(None, "cipher_memory_security", "OFF")
        .unwrap();
    connection
        .pragma_update(None, "key", encryption_key)
        .unwrap();
    connection
        .pragma_update(None, "cipher_plaintext_header_size", 32)
        .unwrap();
    connection
        .pragma_update(
            None,
            "cipher_salt",
            format!("x'{}'", derive_cipher_salt_hex(encryption_key)),
        )
        .unwrap();
    connection
}

#[test]
fn delete_group_preserves_live_group_and_reports_manifest_write_failure() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database_path = directory.path().join("mls.db");
    let encryption_key = "delete-fail-closed-test-key";
    let context = MLSContext::new(
        database_path.to_string_lossy().to_string(),
        encryption_key.to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("context");
    let created = context
        .create_group(b"did:plc:delete-test".to_vec(), None)
        .expect("create group");

    let failure_connection = open_manifest_connection(&database_path, encryption_key);
    failure_connection
        .execute_batch(
            "CREATE TRIGGER fail_group_manifest_write
             BEFORE INSERT ON mls_manifests
             WHEN NEW.key = 'group_ids'
             BEGIN
                 SELECT RAISE(FAIL, 'injected group_ids manifest failure');
             END;",
        )
        .expect("install failure trigger");

    let deletion = context.delete_group(created.group_id.clone());

    assert!(
        deletion.is_err(),
        "durable deletion failure must not be reported as success"
    );
    assert!(
        context.group_exists(created.group_id.clone()),
        "the live group must remain available so a durable-delete retry is possible"
    );

    failure_connection
        .execute_batch("DROP TRIGGER fail_group_manifest_write;")
        .expect("remove failure trigger");
    context
        .delete_group(created.group_id.clone())
        .expect("retry after a partial durable delete must finish idempotently");
    assert!(!context.group_exists(created.group_id));
}
