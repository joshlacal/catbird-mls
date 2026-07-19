//! Regression coverage for uncorroborated delivery-service roster omissions.
//!
//! A paginated `get_conversations` response is transport-authenticated data,
//! not MLS-authenticated removal evidence. Sync must therefore preserve the
//! local ratchet tree and durable conversation when the DS temporarily omits
//! an otherwise-live conversation.

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{MLSAPIClient, MLSStorageBackend};
use chrono::{Duration, Utc};
use e2e_harness::TestWorld;

#[tokio::test(flavor = "multi_thread")]
async fn complete_second_page_is_seen_before_omission_preflight() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");

    let alice = world.client("Alice");
    let target = alice
        .orchestrator
        .create_group("second-page target", None, None)
        .await
        .expect("create target");

    // Sync requests pages of 100. Insert 100 cheap server-only fixtures and
    // sort the real local conversation last. A single-page implementation
    // would misclassify `target` as omitted and fail the new preflight.
    for index in 0_u64..100 {
        world
            .api_service
            .create_conversation(&format!("{index:064x}"), None, None, None, None)
            .await
            .expect("create pagination fixture");
    }
    world
        .delivery_service()
        .set_conversation_created_at_for_test(
            &target.conversation_id,
            Utc::now() + Duration::days(1),
        );

    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("sync must traverse the second page before checking omissions");

    assert!(alice
        .storage
        .get_conversation(&alice.did, &target.conversation_id)
        .await
        .expect("read target")
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_server_listing_omission_preserves_local_state_and_continues_sync() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register Alice");

    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("omission must not delete", None, None)
        .await
        .expect("create group");
    let conversation_id = conversation.conversation_id.clone();
    let group_id = hex::decode(&conversation.group_id).expect("group id");

    world
        .delivery_service()
        .set_conversation_hidden_from_list(&conversation_id, true);

    // A server listing omission must not abort the sync: aborting would let one
    // omitted row deny sync for every other conversation (a DoS). The sync
    // completes; the security guarantee is that the local state asserted below is
    // preserved, never deleted, without authenticated MLS removal evidence.
    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("an uncorroborated server omission must not fail the sync; local state is preserved and sync continues");

    assert!(
        alice
            .orchestrator
            .mls_context()
            .group_exists(group_id.clone()),
        "a DS listing omission must not erase the local MLS ratchet tree"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &conversation_id)
            .await
            .expect("read durable conversation")
            .is_some(),
        "a DS listing omission must not erase the durable conversation"
    );
    assert!(
        alice
            .orchestrator
            .conversations()
            .lock()
            .await
            .contains_key(&conversation_id),
        "a DS listing omission must not erase the in-memory conversation"
    );
    assert_eq!(
        alice.storage.pending_local_delete_count(),
        0,
        "sync must not even arm destructive cleanup from a server omission"
    );

    // The omission is transient: once the complete page is visible again,
    // normal sync succeeds with the exact same local state.
    world
        .delivery_service()
        .set_conversation_hidden_from_list(&conversation_id, false);
    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("sync should recover when the complete listing returns");

    assert!(alice.orchestrator.mls_context().group_exists(group_id));
    assert!(alice
        .storage
        .get_conversation(&alice.did, &conversation_id)
        .await
        .expect("read preserved conversation after recovery")
        .is_some());
}
