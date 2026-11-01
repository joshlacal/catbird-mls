//! Fault injection tests for MLS key package replenish crash boundaries.
//!
//! Simulates crashes at storage write boundaries without mocking underlying logic:
//! 1. Crash after OpenMLS writes to `openmls_kv` (`scope = 'KeyPackage'`), before bundle write to
//!    `pending_ops` (`op_kind = 'kp_bundle'`) (unmanifested OpenMLS orphan).
//! 2. Crash after OpenMLS deletes from `openmls_kv` (`scope = 'KeyPackage'`) during Welcome consumption,
//!    before bundle deletion from `pending_ops` (stale bundle).
//! 3. Crash during replenish with active replenish journal in `Started` phase.
//!
//! Verifies that startup reconciles, unmanifested orphans are safely quarantined into
//! `account_meta` (never lost, never resurrected, never published), and `MLSContext::new` succeeds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use catbird_mls::storage::{
    derive_db_key_32_from_str, derive_sqlcipher_96hex_key_spec, SCOPE_KEY_PACKAGE,
};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};

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
    let key_32 = derive_db_key_32_from_str(encryption_key);
    let key_spec = derive_sqlcipher_96hex_key_spec(&key_32);
    conn.execute_batch(&format!(
        "PRAGMA cipher_memory_security = OFF;\n\
         PRAGMA key = \"{key_spec}\";\n\
         PRAGMA cipher_plaintext_header_size = 32;\n\
         PRAGMA journal_mode = WAL;"
    ))
    .unwrap();
    conn
}

fn count_openmls_kps(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT count(*) FROM openmls_kv WHERE version = 1 AND scope = ?1",
        [SCOPE_KEY_PACKAGE],
        |r| r.get(0),
    )
    .unwrap()
}

fn count_kp_bundles(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT count(*) FROM pending_ops WHERE op_kind = 'kp_bundle'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn test_crash_boundary_unmanifested_openmls_orphan_reconciles_on_startup() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

    // 1. Clean startup and create 3 key packages. Both stores have 3 entries.
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
    // Simulate crash after OpenMLS writes to `openmls_kv` (`KeyPackage`) before `pending_ops` (`kp_bundle`).
    let orphan_ref = hex::decode("deadbeef0102030405060708deadbeef").unwrap();
    let orphan_kp_bytes = hex::decode("cafe0102030405060708cafe01020304").unwrap();
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();

        assert_eq!(count_openmls_kps(&conn), 3);
        assert_eq!(count_kp_bundles(&conn), 3);

        conn.execute(
            "INSERT INTO openmls_kv (version, scope, key_bytes, value_bytes) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![1i64, SCOPE_KEY_PACKAGE, orphan_ref, orphan_kp_bytes],
        )
        .expect("inject orphan row");

        assert_eq!(count_openmls_kps(&conn), 4);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // 3. Reopen MLSContext: reconciles orphan into `account_meta` and opens cleanly.
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
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        assert_eq!(
            count_openmls_kps(&conn),
            3,
            "openmls_kv KeyPackage scope should have 3 rows after quarantine"
        );
        assert_eq!(
            count_kp_bundles(&conn),
            3,
            "pending_ops kp_bundle should have 3 rows"
        );

        let quarantined_row: Option<String> = conn
            .query_row(
                "SELECT value_json FROM account_meta WHERE key LIKE 'quarantined_key_package:openmls_orphan:%'",
                [],
                |r| r.get(0),
            )
            .ok();
        assert!(
            quarantined_row.is_some(),
            "Quarantined orphan record must exist in account_meta"
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

    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();

        let first_ref: Vec<u8> = conn
            .query_row(
                "SELECT key_bytes FROM openmls_kv WHERE version = 1 AND scope = ?1 LIMIT 1",
                [SCOPE_KEY_PACKAGE],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "DELETE FROM openmls_kv WHERE version = 1 AND scope = ?1 AND key_bytes = ?2",
            rusqlite::params![SCOPE_KEY_PACKAGE, first_ref],
        )
        .unwrap();

        assert_eq!(count_openmls_kps(&conn), 2);
        assert_eq!(count_kp_bundles(&conn), 3);

        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

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

    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        assert_eq!(count_openmls_kps(&conn), 2);
        assert_eq!(count_kp_bundles(&conn), 2);
    }
}

#[test]
fn test_crash_boundary_replenish_journal_aborted_generation() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

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

    let orphan_ref = hex::decode("feedbeef0102030405060708feedbeef").unwrap();
    let orphan_kp_bytes = hex::decode("babe0102030405060708babe01020304").unwrap();
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();

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
            "INSERT OR REPLACE INTO account_meta (key, value_json, updated_at_ms) VALUES ('key_package_replenish_journal', ?1, 0)",
            [&intent_json],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO openmls_kv (version, scope, key_bytes, value_bytes) VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![SCOPE_KEY_PACKAGE, orphan_ref, orphan_kp_bytes],
        )
        .unwrap();

        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

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

    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        assert_eq!(count_openmls_kps(&conn), 2);
        assert_eq!(count_kp_bundles(&conn), 2);

        let journal_row: Option<String> = conn
            .query_row(
                "SELECT value_json FROM account_meta WHERE key = 'key_package_replenish_journal'",
                [],
                |r| r.get(0),
            )
            .ok();
        assert!(
            journal_row.is_none(),
            "Incomplete replenish journal must be cleared after reconciliation"
        );
    }
}

#[test]
fn test_multi_process_race_context_b_does_not_quarantine_in_flight_package_of_context_a() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

    let ctx_a = MLSContext::new(
        db_path.clone(),
        TEST_KEY.to_string(),
        Box::new(keychain.clone()),
    )
    .expect("context A init");

    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let intent_json = serde_json::json!({
            "operation_id": "multi-proc-race-op-1",
            "needed": 1,
            "identity": "did:plc:testuser#device-1",
            "phase": "Started",
            "owner_pid": 1u32,
            "staged_hash_refs": [],
            "created_at": now,
        })
        .to_string();
        conn.execute(
            "INSERT OR REPLACE INTO account_meta (key, value_json, updated_at_ms) VALUES ('key_package_replenish_journal', ?1, 0)",
            [&intent_json],
        )
        .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    let db_path_clone = db_path.clone();
    let keychain_clone = keychain.clone();

    catbird_mls::set_post_build_key_package_hook(Some(move || {
        let ctx_b = MLSContext::new(
            db_path_clone.clone(),
            TEST_KEY.to_string(),
            Box::new(keychain_clone.clone()),
        );
        assert!(
            ctx_b.is_ok(),
            "Context B must open cleanly without failing on Context A's in-flight drift: {:?}",
            ctx_b.err()
        );

        let conn = open_raw_sqlite(&db_path_clone, TEST_KEY);
        let quarantined_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM account_meta WHERE key LIKE 'quarantined_key_package:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            quarantined_count, 0,
            "Context B must NOT quarantine Context A's in-flight key package while live journal is active"
        );
    }));

    let kps = ctx_a
        .create_key_packages(IDENTITY.to_vec(), 1)
        .expect("context A create key package");
    assert_eq!(kps.len(), 1);

    catbird_mls::set_post_build_key_package_hook::<fn()>(None);

    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        let quarantined_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM account_meta WHERE key LIKE 'quarantined_key_package:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(
            count_openmls_kps(&conn),
            1,
            "openmls_kv KeyPackage must have 1 row"
        );
        assert_eq!(
            count_kp_bundles(&conn),
            1,
            "pending_ops kp_bundle must have 1 row"
        );
        assert_eq!(quarantined_count, 0, "Quarantined count must be 0");
    }
}

#[test]
fn test_extension_process_tolerates_drift_without_destructive_reconciliation() {
    let (db_path, _dir) = make_db_path();
    let keychain = TestKeychain::new();

    {
        let ctx = MLSContext::new(
            db_path.clone(),
            TEST_KEY.to_string(),
            Box::new(keychain.clone()),
        )
        .unwrap();
        ctx.create_key_packages(IDENTITY.to_vec(), 2).unwrap();
    }

    let orphan_ref = hex::decode("deadbeef0102030405060708deadbeef").unwrap();
    let orphan_kp_bytes = hex::decode("cafe0102030405060708cafe01020304").unwrap();
    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        conn.execute(
            "INSERT INTO openmls_kv (version, scope, key_bytes, value_bytes) VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![SCOPE_KEY_PACKAGE, orphan_ref, orphan_kp_bytes],
        )
        .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    catbird_mls::set_simulate_extension_process_for_test(true);
    let ext_ctx = MLSContext::new(
        db_path.clone(),
        TEST_KEY.to_string(),
        Box::new(keychain.clone()),
    );
    catbird_mls::set_simulate_extension_process_for_test(false);

    assert!(ext_ctx.is_ok(), "Extension process must open without error");

    {
        let conn = open_raw_sqlite(&db_path, TEST_KEY);
        let quarantined_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM account_meta WHERE key LIKE 'quarantined_key_package:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count_openmls_kps(&conn),
            3,
            "Extension process must not delete orphan from openmls_kv"
        );
        assert_eq!(
            quarantined_count, 0,
            "Extension process must not quarantine orphan"
        );
    }
}
