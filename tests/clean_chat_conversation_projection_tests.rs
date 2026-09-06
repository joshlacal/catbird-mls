//! Native sync must not round-trip a stale platform roster back into the UI.
#![allow(dead_code)]
mod e2e_harness;

use catbird_mls::orchestrator::{
    ConversationMetadata, ConversationState, ConversationView, MLSStorageBackend, MemberRole,
    MemberView,
};
use e2e_harness::TestWorld;

const CID: &str = "11111111-1111-4111-8111-111111111111";
const GROUP: &str = "000102030405060708090a0b0c0d0e0f";

async fn stale_platform_projection() -> TestWorld {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let alice = world.client("Alice");
    alice.orchestrator.initialize(&alice.did).await.unwrap();
    alice
        .storage
        .ensure_conversation_exists(&alice.did, CID, GROUP)
        .await
        .unwrap();
    alice
        .storage
        .set_conversation_state(CID, ConversationState::Active)
        .await
        .unwrap();
    let mut current = alice
        .storage
        .get_conversation(&alice.did, CID)
        .await
        .unwrap()
        .unwrap();
    current.epoch = 4;
    current.members = vec![
        MemberView {
            did: alice.did.clone(),
            role: MemberRole::Member,
        },
        MemberView {
            did: "did:plc:bob".into(),
            role: MemberRole::Admin,
        },
        MemberView {
            did: "did:plc:carol".into(),
            role: MemberRole::Member,
        },
    ];
    current.metadata = Some(ConversationMetadata {
        name: Some("Known encrypted title".into()),
        description: None,
        avatar_url: None,
    });
    alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .insert(CID.into(), current);
    world
}

fn encoded(view: &ConversationView) -> serde_json::Value {
    serde_json::to_value(view).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn current_native_roster_roles_epoch_and_title_reach_the_host_without_writes() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    let before = alice
        .storage
        .get_conversation(&alice.did, CID)
        .await
        .unwrap()
        .unwrap();
    let rows = alice
        .orchestrator
        .conversation_display_snapshot(&alice.did)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].epoch, 4);
    assert_eq!(
        rows[0].members.len(),
        3,
        "people are copied from canonical participants, not counted from device leaves"
    );
    assert_eq!(rows[0].members[0].role, MemberRole::Member);
    assert_eq!(rows[0].members[1].role, MemberRole::Admin);
    assert_eq!(
        rows[0].metadata.as_ref().unwrap().name.as_deref(),
        Some("Known encrypted title")
    );
    assert_eq!(
        encoded(
            &alice
                .storage
                .get_conversation(&alice.did, CID)
                .await
                .unwrap()
                .unwrap()
        ),
        encoded(&before)
    );
    assert_eq!(
        alice.storage.get_conversation_state(CID).await.unwrap(),
        Some(ConversationState::Active)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_and_reset_state_preserve_durable_projection_over_stale_active_cache() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    let durable = alice
        .storage
        .get_conversation(&alice.did, CID)
        .await
        .unwrap()
        .unwrap();
    for state in [
        ConversationState::DeviceRemoved,
        ConversationState::Closed,
        ConversationState::ResetPending {
            new_group_id: "2222".into(),
            reset_generation: 1,
            notified_at_ms: 1,
        },
    ] {
        if let ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            notified_at_ms,
        } = &state
        {
            alice
                .storage
                .mark_reset_pending(CID, new_group_id, *reset_generation, *notified_at_ms)
                .await
                .unwrap();
        } else {
            alice
                .storage
                .set_conversation_state(CID, state.clone())
                .await
                .unwrap();
        }
        let rows = alice
            .orchestrator
            .conversation_display_snapshot(&alice.did)
            .await
            .unwrap();
        assert_eq!(encoded(&rows[0]), encoded(&durable));
        assert_eq!(
            alice.storage.get_conversation_state(CID).await.unwrap(),
            Some(state)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_runtime_and_different_group_keep_durable_rows_without_resurrecting_deleted_rows() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    let durable = alice
        .storage
        .get_conversation(&alice.did, CID)
        .await
        .unwrap()
        .unwrap();
    alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get_mut(CID)
        .unwrap()
        .group_id = "2222".into();
    assert_eq!(
        encoded(
            &alice
                .orchestrator
                .conversation_display_snapshot(&alice.did)
                .await
                .unwrap()[0]
        ),
        encoded(&durable)
    );
    alice.orchestrator.conversations().lock().await.clear();
    assert_eq!(
        encoded(
            &alice
                .orchestrator
                .conversation_display_snapshot(&alice.did)
                .await
                .unwrap()[0]
        ),
        encoded(&durable)
    );
    alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .insert(CID.into(), durable);
    alice
        .storage
        .delete_conversations(&alice.did, &[CID])
        .await
        .unwrap();
    assert!(alice
        .orchestrator
        .conversation_display_snapshot(&alice.did)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_account_shutdown_and_storage_failure_never_fall_back_to_runtime_data() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    let reads = alice.storage.startup_probe_counts().list_conversations;
    assert!(alice
        .orchestrator
        .conversation_display_snapshot("did:plc:other")
        .await
        .is_err());
    assert_eq!(
        alice.storage.startup_probe_counts().list_conversations,
        reads
    );
    alice.storage.fail_next_list_conversations();
    assert!(alice
        .orchestrator
        .conversation_display_snapshot(&alice.did)
        .await
        .is_err());
    alice.storage.fail_next_get_conversation_state();
    assert!(alice
        .orchestrator
        .conversation_display_snapshot(&alice.did)
        .await
        .is_err());
    alice.orchestrator.shutdown().await;
    assert!(alice
        .orchestrator
        .conversation_display_snapshot(&alice.did)
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn older_runtime_epoch_cannot_overwrite_a_newer_durable_projection() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    alice.storage.set_epoch_pair_for_test(CID, 8, 1);
    let durable = alice
        .storage
        .get_conversation(&alice.did, CID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        encoded(
            &alice
                .orchestrator
                .conversation_display_snapshot(&alice.did)
                .await
                .unwrap()[0]
        ),
        encoded(&durable)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_terminal_state_also_blocks_a_stale_active_overlay() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    let durable = alice
        .storage
        .get_conversation(&alice.did, CID)
        .await
        .unwrap()
        .unwrap();
    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(CID.into(), ConversationState::DeviceRemoved);
    assert_eq!(
        encoded(
            &alice
                .orchestrator
                .conversation_display_snapshot(&alice.did)
                .await
                .unwrap()[0]
        ),
        encoded(&durable)
    );
    assert_eq!(
        alice.storage.get_conversation_state(CID).await.unwrap(),
        Some(ConversationState::Active)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn account_lifecycle_cannot_change_during_an_in_flight_snapshot_read() {
    let world = stale_platform_projection().await;
    let alice = world.client("Alice");
    let barrier = alice.storage.pause_next_conversation_state_read(CID);
    let (projection, ()) = tokio::join!(
        alice.orchestrator.conversation_display_snapshot(&alice.did),
        async {
            barrier.wait_until_entered().await;
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(30),
                    alice.orchestrator.shutdown(),
                )
                .await
                .is_err(),
                "shutdown must wait for the account-scoped read to finish"
            );
            barrier.release();
        }
    );
    assert_eq!(projection.unwrap()[0].epoch, 4);
    alice.orchestrator.shutdown().await;
    assert!(alice
        .orchestrator
        .conversation_display_snapshot(&alice.did)
        .await
        .is_err());
}
