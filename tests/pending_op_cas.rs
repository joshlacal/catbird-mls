use catbird_mls::storage::{MlsAccountDb, OpenMode};

#[test]
fn pending_operation_compare_exchange_preserves_the_owner_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let db =
        MlsAccountDb::open_native(dir.path().join("cas.db"), &[19; 32], OpenMode::App).unwrap();

    db.write_tx(|tx| {
        assert!(tx.compare_exchange_pending_op(
            "direct_request_creation",
            "peer",
            None,
            "first",
            1
        )?);
        assert!(!tx.compare_exchange_pending_op(
            "direct_request_creation",
            "peer",
            None,
            "second",
            2
        )?);
        assert!(!tx.compare_exchange_pending_op(
            "direct_request_creation",
            "peer",
            Some("stale"),
            "second",
            2,
        )?);
        assert_eq!(
            tx.get_pending_op("direct_request_creation", "peer")?
                .as_deref(),
            Some("first")
        );
        assert!(tx.compare_exchange_pending_op(
            "direct_request_creation",
            "peer",
            Some("first"),
            "second",
            2,
        )?);
        assert!(!tx.delete_pending_op_if_payload("direct_request_creation", "peer", "first",)?);
        assert!(tx.delete_pending_op_if_payload("direct_request_creation", "peer", "second",)?);
        Ok(())
    })
    .unwrap();
}
