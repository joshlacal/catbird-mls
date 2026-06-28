//! Regression: the orchestrator must scope every key-package publish to the
//! SERVER-MINTED device id returned by `registerDevice`.
//!
//! The delivery service mints its own `device_id` on registration and ignores
//! the client-supplied UUID. A publish that carries no device id — or the wrong
//! (client-generated) UUID — fails `resolve_device_scope`, so the server cannot
//! bind the package to the device signature key and rejects it (403), stranding
//! the device with only the single key package bundled into `registerDevice`.
//! Rust owns the device identity, so it must persist the minted id and forward
//! it across the `MLSAPIClient::publish_key_package` edge.

mod e2e_harness;
mod mock_api_client;
mod mock_credentials;
mod mock_storage;

use e2e_harness::TestWorld;

#[tokio::test(flavor = "multi_thread")]
async fn publish_key_package_carries_server_minted_device_id() {
    let mut world = TestWorld::new();
    world.add_client("alice").await;
    world
        .register_device("alice")
        .await
        .expect("device registration should succeed");

    let did = world.client("alice").did.clone();

    // Ground truth: the id the *server* minted at registration. The client UUID
    // sent to registerDevice is discarded server-side, so publishes must use
    // this value — not whatever UUID the client happened to generate.
    let minted_id = world
        .delivery_service()
        .latest_registered_device_id(&did)
        .expect("registration must mint a server device id");

    let published = world.delivery_service().published_device_ids(&did);

    assert!(
        !published.is_empty(),
        "ensure_device_registered must publish initial key packages"
    );
    assert!(
        published
            .iter()
            .all(|d| d.as_deref() == Some(minted_id.as_str())),
        "every key-package publish must carry the server-minted device id \
         {minted_id:?}, but captured device ids were {published:?}"
    );
}
