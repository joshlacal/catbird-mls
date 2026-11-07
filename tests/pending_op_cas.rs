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

/// The orchestrator's `sendCounter` reservation is durable and shares the live client's
/// `account_meta` key, so both send paths sign one strictly increasing sequence.
#[tokio::test]
async fn send_counter_reservation_is_durable_and_shared_with_the_live_client() {
    use catbird_mls::client::chat_wire;
    use catbird_mls::orchestrator::MLSStorageBackend;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("counter.db");
    let cid = "00000000-0000-4000-8000-000000000c01";
    {
        let db = MlsAccountDb::open_native(path.clone(), &[19; 32], OpenMode::App).unwrap();
        assert_eq!(db.reserve_send_counter(cid).await.unwrap(), 1);
        assert_eq!(db.reserve_send_counter(cid).await.unwrap(), 2);
        db.write_tx(|tx| tx.put_account_meta(&chat_wire::send_counter_key(cid), "7", 0))
            .unwrap();
    }
    let db = MlsAccountDb::open_native(path, &[19; 32], OpenMode::App).unwrap();
    assert_eq!(db.reserve_send_counter(cid).await.unwrap(), 8);
    assert_eq!(
        db.reserve_send_counter("00000000-0000-4000-8000-000000000c02")
            .await
            .unwrap(),
        1
    );
}
