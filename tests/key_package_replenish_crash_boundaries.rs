//! Fault injection tests for MLS key package replenish crash boundaries.
//!
//! Simulates crashes at storage write boundaries without mocking underlying logic:
//! 1. Crash after OpenMLS writes to `openmls_key_packages`, before bundle write to `mls_key_package_bundles`
//!    (unmanifested OpenMLS orphan causing "Key package drift detected").
//! 2. Crash after OpenMLS deletes from `openmls_key_packages` during Welcome consumption,
//!    before bundle deletion from `mls_key_package_bundles` (stale bundle).
//! 3. Crash during replenish with active replenish journal in `Started` phase.
//!
//! Verifies that startup reconciles, unmanifested orphans are safely quarantined into
//! `mls_manifests` (never lost, never resurrected, never published), and `MLSContext::new` succeeds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use sha2::{Digest, Sha256};

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

const TEST_KEY: &str = "test-key-1234567890123456";
const IDENTITY: &[u8] = b"did:plc:testuser#device-1";

fn make_db_path() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mls.db").to_str().unwrap().to_string();
    (db_path, dir)
}

fn open_raw_sqlite(path: &str, encryption_key: &str) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "cipher_memory_security", "OFF")
        .unwrap();
    conn.pragma_update(None, "key", encryption_key).unwrap();
    conn.pragma_update(None, "cipher_plaintext_header_size", 32)
        .unwrap();
    let salt = hex::encode(&Sha256::digest(encryption_key.as_bytes())[..16]);
    conn.pragma_update(None, "cipher_salt", format!("x'{salt}'"))
        .unwrap();
    conn.pragma_update(None, "cipher_page_size", 4096).unwrap();
    conn.pragma_update(None, "kdf_iter", 256000).unwrap();
    conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")
        .unwrap();
    conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")
        .unwrap();
    conn
}

#[test]
fn test_crash_boundary_unmanifested_openmls_orphan_reconciles_on_startup() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

    // 1. Clean startup and create 3 key packages. Both tables have 3 entries.
    {
        let ctx = MLSContext::new(
            db_path.clone(),
            TEST_KEY.to_string(),
            Box::new(keychain.clone()),
        )
        .expect("initial MLSContext::new must succeed");

        let kps = ctx
            .create_key_packages(IDENTITY.to_vec(), 3)
            .expect("create 3 key packages");
        assert_eq!(kps.len(), 3);
    }

    // 2. Fault injection at storage seam:
    // Simulate crash after OpenMLS writes to `openmls_key_packages` but before `mls_key_package_bundles` is written.
    let orphan_ref = hex::decode("deadbeef0102030405060708deadbeef").unwrap();
    let orphan_kp_bytes = hex::decode("cafe0102030405060708cafe01020304").unwrap();
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);

        // Checkpoint WAL first so raw connection sees all tables cleanly.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();

        let initial_kp_count: i64 = conn
            .query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
            .unwrap();
        let initial_bundle_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM mls_key_package_bundles",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(initial_kp_count, 3);
        assert_eq!(initial_bundle_count, 3);

        // Inject the orphan directly into openmls_key_packages.
        conn.execute(
            "INSERT INTO openmls_key_packages (provider_version, key_package_ref, key_package) VALUES (?1, ?2, ?3)",
            rusqlite::params![1i64, orphan_ref, orphan_kp_bytes],
        )
        .expect("inject orphan row");

        let drifted_kp_count: i64 = conn
            .query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(drifted_kp_count, 4);

        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // 3. Reopen MLSContext:
    // PRE-FIX: Panics/errors with "Key package drift detected: 3 manifested bundles vs 4 OpenMLS key packages"
    // POST-FIX: Startup reconciles the orphan, quarantines it into `mls_manifests`, and opens cleanly!
    let reopen_result = MLSContext::new(
        db_path.clone(),
        TEST_KEY.to_string(),
        Box::new(keychain.clone()),
    );
    assert!(
        reopen_result.is_ok(),
        "MLSContext::new must reconcile drift and succeed, got: {:?}",
        reopen_result.err()
    );

    // 4. Verify post-reconcile invariants:
    // - openmls_key_packages count is 3
    // - mls_key_package_bundles count is 3
    // - The orphan was quarantined in mls_manifests
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        let final_kp_count: i64 = conn
            .query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
            .unwrap();
        let final_bundle_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM mls_key_package_bundles",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            final_kp_count, 3,
            "openmls_key_packages should have 3 rows after quarantine"
        );
        assert_eq!(
            final_bundle_count, 3,
            "mls_key_package_bundles should have 3 rows"
        );

        // Verify orphan exists in quarantine
        let quarantined_row: Option<String> = conn
            .query_row(
                "SELECT value FROM mls_manifests WHERE key LIKE 'quarantined_key_package:openmls_orphan:%'",
                [],
                |r| r.get(0),
            )
            .ok();
        assert!(
            quarantined_row.is_some(),
            "Quarantined orphan record must exist in mls_manifests"
        );
        let record_str = quarantined_row.unwrap();
        assert!(
            record_str.contains("deadbeef"),
            "Quarantine record must reference the orphaned key package"
        );
    }
}

#[test]
fn test_crash_boundary_stale_manifested_bundle_reconciles_on_startup() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

    // 1. Clean startup and create 3 key packages.
    {
        let ctx = MLSContext::new(
            db_path.clone(),
            TEST_KEY.to_string(),
            Box::new(keychain.clone()),
        )
        .expect("initial MLSContext::new must succeed");

        let kps = ctx
            .create_key_packages(IDENTITY.to_vec(), 3)
            .expect("create 3 key packages");
        assert_eq!(kps.len(), 3);
    }

    // 2. Fault injection at storage seam:
    // Simulate crash after OpenMLS deletes from `openmls_key_packages` during Welcome consumption,
    // before bundle deletion from `mls_key_package_bundles`.
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();

        // Delete ONE row from openmls_key_packages to create reverse drift (3 bundles vs 2 OpenMLS packages).
        let first_ref: Vec<u8> = conn
            .query_row(
                "SELECT key_package_ref FROM openmls_key_packages LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "DELETE FROM openmls_key_packages WHERE key_package_ref = ?1",
            [&first_ref],
        )
        .unwrap();

        let kp_count: i64 = conn
            .query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
            .unwrap();
        let bundle_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM mls_key_package_bundles",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kp_count, 2);
        assert_eq!(bundle_count, 3);

        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // 3. Reopen MLSContext:
    // PRE-FIX: Fails with "Manifested key package bundle ... missing from openmls_key_packages"
    // POST-FIX: Quarantines the stale manifested bundle and opens cleanly!
    let reopen_result = MLSContext::new(
        db_path.clone(),
        TEST_KEY.to_string(),
        Box::new(keychain.clone()),
    );
    assert!(
        reopen_result.is_ok(),
        "MLSContext::new must reconcile stale bundle and succeed, got: {:?}",
        reopen_result.err()
    );

    // 4. Verify post-reconcile counts match:
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        let final_kp_count: i64 = conn
            .query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
            .unwrap();
        let final_bundle_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM mls_key_package_bundles",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(final_kp_count, 2);
        assert_eq!(final_bundle_count, 2);
    }
}

#[test]
fn test_crash_boundary_replenish_journal_aborted_generation() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

    // 1. Clean startup and create 2 key packages.
    {
        let ctx = MLSContext::new(
            db_path.clone(),
            TEST_KEY.to_string(),
            Box::new(keychain.clone()),
        )
        .expect("initial MLSContext::new must succeed");

        let kps = ctx
            .create_key_packages(IDENTITY.to_vec(), 2)
            .expect("create 2 key packages");
        assert_eq!(kps.len(), 2);
    }

    // 2. Fault injection at storage seam:
    // Simulate a crash during replenish where an intent was recorded in mls_manifests,
    // OpenMLS wrote an orphan key package, and the app was killed before the bundle was manifested.
    let orphan_ref = hex::decode("feedbeef0102030405060708feedbeef").unwrap();
    let orphan_kp_bytes = hex::decode("babe0102030405060708babe01020304").unwrap();
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();

        // Record replenish intent in Started phase
        let intent_json = serde_json::json!({
            "operation_id": "test-replenish-op-1",
            "needed": 5,
            "identity": "did:plc:testuser#device-1",
            "phase": "Started",
            "staged_hash_refs": [],
            "created_at": 1000000u64,
        })
        .to_string();
        conn.execute(
            "INSERT OR REPLACE INTO mls_manifests (key, value) VALUES ('key_package_replenish_journal', ?1)",
            [&intent_json],
        )
        .unwrap();

        // Inject orphan package into openmls_key_packages
        conn.execute(
            "INSERT INTO openmls_key_packages (provider_version, key_package_ref, key_package) VALUES (1, ?1, ?2)",
            rusqlite::params![orphan_ref, orphan_kp_bytes],
        )
        .unwrap();

        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // 3. Reopen MLSContext:
    // PRE-FIX: Fails with drift.
    // POST-FIX: Quarantines orphan, clears incomplete journal, opens cleanly!
    let reopen_result = MLSContext::new(
        db_path.clone(),
        TEST_KEY.to_string(),
        Box::new(keychain.clone()),
    );
    assert!(
        reopen_result.is_ok(),
        "MLSContext::new must reconcile aborted replenish and succeed, got: {:?}",
        reopen_result.err()
    );

    // 4. Verify post-reconcile state:
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        let final_kp_count: i64 = conn
            .query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
            .unwrap();
        let final_bundle_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM mls_key_package_bundles",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(final_kp_count, 2);
        assert_eq!(final_bundle_count, 2);

        // Journal should be cleared
        let journal_row: Option<String> = conn
            .query_row(
                "SELECT value FROM mls_manifests WHERE key = 'key_package_replenish_journal'",
                [],
                |r| r.get(0),
            )
            .ok();
        assert!(journal_row.is_none(), "Incomplete replenish journal must be cleared after reconciliation");
    }
}
