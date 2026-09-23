//! Canonical subscription ticket and event frame processing.
//!
//! Provides:
//! - Exact authenticated inventory sync under one inventory session -> `AppliedInventoryFence`
//! - Subscription ticket preparation via `blue.catbird.chat.getSubscriptionTicket`
//! - Event frame decode, CAS cursor persistence, and message/state dispatch

use crate::error::MLSError;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_value_read(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
    id: &str,
) -> Result<Option<Vec<u8>>, MLSError> {
    use rusqlite::OptionalExtension;
    checked_namespace(namespace)?;
    checked_id(id)?;
    let key = format!("direct_request_value_v2:{namespace}:{id}");
    storage
        .welcome_ack_connection()
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| MLSError::StorageFailed)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_value_cas(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
    id: &str,
    expected: Option<&[u8]>,
    next: &[u8],
) -> Result<bool, MLSError> {
    use rusqlite::OptionalExtension;
    checked_namespace(namespace)?;
    checked_id(id)?;
    if next.is_empty() || next.len() > 16 * 1024 * 1024 {
        return Err(MLSError::invalid_input("Request value exceeds storage bound"));
    }
    let key = format!("direct_request_value_v2:{namespace}:{id}");
    let tx = storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(|_| MLSError::StorageFailed)?;
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| MLSError::StorageFailed)?;
    if old.as_deref() != expected {
        return Ok(false);
    }
    tx.execute(
        "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES(?1,?2)",
        rusqlite::params![key, next],
    )
    .map_err(|_| MLSError::StorageFailed)?;
    tx.commit().map_err(|_| MLSError::StorageFailed)?;
    storage.flush_database()?;
    Ok(true)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_values_list(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
) -> Result<Vec<Vec<u8>>, MLSError> {
    checked_namespace(namespace)?;
    let pattern = format!("direct_request_value_v2:{namespace}:%");
    let mut query = storage
        .welcome_ack_connection()
        .prepare("SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key LIKE ?1 ORDER BY key")
        .map_err(|_| MLSError::StorageFailed)?;
    let rows = query
        .query_map([&pattern], |r| r.get::<_, Vec<u8>>(0))
        .map_err(|_| MLSError::StorageFailed)?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|_| MLSError::StorageFailed)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_values_total_bytes(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
) -> Result<u64, MLSError> {
    checked_namespace(namespace)?;
    let pattern = format!("direct_request_value_v2:{namespace}:%");
    let total: i64 = storage
        .welcome_ack_connection()
        .query_row(
            "SELECT COALESCE(SUM(length(value)),0) FROM mls_manifests WHERE key LIKE ?1",
            [&pattern],
            |r| r.get(0),
        )
        .map_err(|_| MLSError::StorageFailed)?;
    Ok(total.max(0) as u64)
}

pub(crate) fn checked_id(id: &str) -> Result<(), MLSError> {
    if id.is_empty() || id.len() > 512 {
        return Err(MLSError::invalid_input("Invalid request value identifier"));
    }
    Ok(())
}

pub(crate) fn checked_namespace(namespace: &str) -> Result<(), MLSError> {
    if namespace.is_empty() || namespace.len() > 128 {
        return Err(MLSError::invalid_input("Invalid request value namespace"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::mls_provider::MlsCryptoContext;

    struct NoopKeychain;
    #[async_trait::async_trait]
    impl crate::KeychainAccess for NoopKeychain {
        async fn read(&self, _key: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        async fn write(&self, _key: String, _data: Vec<u8>) -> Result<(), MLSError> {
            Ok(())
        }
        async fn delete(&self, _key: String) -> Result<(), MLSError> {
            Ok(())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn request_value_cas_and_bounds_work_as_expected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("request_val_test.db").to_string_lossy().to_string();
        let context = crate::MLSContext::new(
            db_path,
            "test-key-1234567890123456".to_string(),
            Box::new(NoopKeychain),
        )
        .unwrap();

        let ns = "testNamespace";
        let id1 = "id-1";
        let id2 = "id-2";

        assert_eq!(context.read_request_value(ns, id1).unwrap(), None);

        // Insert id1
        let val1 = b"first value payload";
        assert!(context.compare_exchange_request_value(ns, id1, None, val1).unwrap());
        assert_eq!(context.read_request_value(ns, id1).unwrap().as_deref(), Some(val1.as_slice()));

        // CAS with wrong expected fails
        assert!(!context.compare_exchange_request_value(ns, id1, Some(b"wrong"), b"new val").unwrap());
        assert_eq!(context.read_request_value(ns, id1).unwrap().as_deref(), Some(val1.as_slice()));

        // CAS with right expected updates
        let val1_updated = b"second value payload";
        assert!(context.compare_exchange_request_value(ns, id1, Some(val1), val1_updated).unwrap());
        assert_eq!(context.read_request_value(ns, id1).unwrap().as_deref(), Some(val1_updated.as_slice()));

        // Insert id2
        let val2 = b"third payload";
        assert!(context.compare_exchange_request_value(ns, id2, None, val2).unwrap());

        // List
        let list = context.list_request_values(ns).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], val1_updated);
        assert_eq!(list[1], val2);

        // Total bytes
        let total = context.request_values_total_bytes(ns).unwrap();
        assert_eq!(total, (val1_updated.len() + val2.len()) as u64);

        // Bounds check
        assert!(checked_id("").is_err());
        assert!(checked_id(&"x".repeat(513)).is_err());
        assert!(checked_namespace("").is_err());
        assert!(checked_namespace(&"x".repeat(129)).is_err());
    }
}
