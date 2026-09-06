//! A verified signed close disables the retained history without deleting keys.
#![allow(dead_code)]
mod e2e_harness;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    ConversationState, GroupState, MLSStorageBackend, MlsCryptoContext,
};
use catbird_mls::KeyPackageData;
use e2e_harness::TestWorld;
use serde_json::json;

async fn closed_pair() -> (TestWorld, String, Vec<u8>) {
    closed_pair_with_closing_device(false).await
}

async fn closed_pair_with_closing_device(new_device: bool) -> (TestWorld, String, Vec<u8>) {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let created = alice
        .orchestrator
        .create_group("", Some(&[bob.did.clone()]), None)
        .await
        .unwrap();
    let cid = created.conversation_id;
    let group = hex::decode(&created.group_id).unwrap();
    let identity = format!(
        "{}#{}",
        bob.did,
        bob.orchestrator.require_actor_device_id().await.unwrap()
    );
    let package = bob
        .orchestrator
        .mls_context()
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let added = alice
        .orchestrator
        .mls_context()
        .add_members(
            group.clone(),
            vec![KeyPackageData {
                data: package.key_package_data,
            }],
        )
        .unwrap();
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group.clone())
        .unwrap();
    bob.orchestrator
        .mls_context()
        .process_welcome(added.welcome_data, identity.into_bytes(), None)
        .unwrap();
    let mut view = alice
        .storage
        .get_conversation(&alice.did, &cid)
        .await
        .unwrap()
        .unwrap();
    view.epoch = 1;
    bob.storage
        .ensure_conversation_exists(&bob.did, &cid, &created.group_id)
        .await
        .unwrap();
    let projection = GroupState {
        conversation_id: cid.clone(),
        group_id: created.group_id.clone(),
        epoch: 1,
        members: alice
            .orchestrator
            .mls_context()
            .group_member_identities(group.clone())
            .unwrap()
            .into_iter()
            .map(|i| String::from_utf8(i).unwrap())
            .collect(),
    };
    bob.storage.set_group_state(&projection).await.unwrap();
    alice.storage.set_group_state(&projection).await.unwrap();
    let state = json!({"conversationKind":"direct","coordinates":{"conversationId":cid,"groupId":STANDARD.encode(&group),"generation":0,"epoch":1,"stateVersion":8,"lifecycle":"active","confirmationTag":STANDARD.encode(alice.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),"groupContextHash":STANDARD.encode(alice.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap())},"participants":[{"userDid":alice.did,"role":"admin","status":"active","leafCount":1},{"userDid":bob.did,"role":"admin","status":"active","leafCount":1}],"leaves":[],"metadataSnapshot":{"metadataVersion":1}});
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state);
    if new_device {
        world
            .add_client_with_did("Alice2", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
            .await;
        world.register_device("Alice2").await.unwrap();
        world
            .client("Alice2")
            .orchestrator
            .leave_conversation(&cid)
            .await
            .unwrap();
    } else {
        alice.orchestrator.leave_conversation(&cid).await.unwrap();
    }
    // The real leave facade allocates the outer entry independently of the
    // signed transition. Keep the original signed bytes and terminal sequence.
    let mut entries = world.delivery_service().terminal_entries_for_test();
    let close = entries
        .iter_mut()
        .find(|entry| entry["$type"] == "blue.catbird.chat.defs#conversationCloseEntry")
        .unwrap();
    close["entryId"] = json!(uuid::Uuid::new_v4().to_string());
    assert_ne!(
        close["entryId"],
        close["signedRequest"]["body"]["transitionId"]
    );
    world
        .delivery_service()
        .set_terminal_entries_for_test(entries);
    (world, cid, group)
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_signed_close_preserves_history_and_disables_sends_across_restart() {
    let (mut world, cid, group) = closed_pair().await;
    let bob = world.client("Bob");
    assert!(bob
        .orchestrator
        .reconcile_terminal_conversation(&cid)
        .await
        .unwrap());
    assert_eq!(
        bob.storage.get_conversation_state(&cid).await.unwrap(),
        Some(ConversationState::Closed)
    );
    assert!(bob
        .storage
        .get_conversation(&bob.did, &cid)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    assert!(
        !bob.orchestrator
            .ensure_conversation_ready(&cid)
            .await
            .unwrap()
            .send_allowed
    );
    assert!(bob
        .orchestrator
        .reconcile_terminal_conversation(&cid)
        .await
        .unwrap());
    world.restart_client("Bob").await;
    let bob = world.client("Bob");
    bob.orchestrator.startup_reconcile().await.unwrap();
    assert!(
        !bob.orchestrator
            .ensure_conversation_ready(&cid)
            .await
            .unwrap()
            .send_allowed
    );
    assert!(bob.orchestrator.join_or_rejoin(&cid).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn close_tombstone_without_valid_signed_row_never_changes_membership() {
    let (world, cid, group) = closed_pair().await;
    let mut entries = world.delivery_service().terminal_entries_for_test();
    let close = entries
        .iter_mut()
        .find(|e| e["$type"] == "blue.catbird.chat.defs#conversationCloseEntry")
        .unwrap();
    close["signedRequest"]["signature"] = json!(STANDARD.encode([0; 64]));
    world
        .delivery_service()
        .set_terminal_entries_for_test(entries);
    let bob = world.client("Bob");
    assert!(bob
        .orchestrator
        .reconcile_terminal_conversation(&cid)
        .await
        .is_err());
    assert_ne!(
        bob.storage.get_conversation_state(&cid).await.unwrap(),
        Some(ConversationState::Closed)
    );
    assert_eq!(bob.orchestrator.mls_context().get_epoch(group).unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_close_rejects_malformed_outer_identity_and_variant() {
    let (world, cid, group) = closed_pair().await;
    let original = world.delivery_service().terminal_entries_for_test();
    for (field, value) in [
        ("entryId", json!("not-a-uuid")),
        ("entryId", json!(uuid::Uuid::nil().to_string())),
        ("$type", json!("blue.catbird.chat.defs#commitEntry")),
        ("seq", json!(0)),
    ] {
        let mut entries = original.clone();
        let close = entries
            .iter_mut()
            .find(|entry| entry["$type"] == "blue.catbird.chat.defs#conversationCloseEntry")
            .unwrap();
        close[field] = value;
        world
            .delivery_service()
            .set_terminal_entries_for_test(entries);
        let bob = world.client("Bob");
        assert!(
            !bob.orchestrator
                .reconcile_terminal_conversation(&cid)
                .await
                .unwrap_or(false),
            "malformed {field} must never authorize a terminal projection"
        );
        assert_ne!(
            bob.storage.get_conversation_state(&cid).await.unwrap(),
            Some(ConversationState::Closed)
        );
        assert_eq!(
            bob.orchestrator
                .mls_context()
                .get_epoch(group.clone())
                .unwrap(),
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn delayed_own_closed_event_acknowledges_only_exact_fresh_terminal_sequence() {
    let (world, cid, _) = closed_pair().await;
    let alice = world.client("Alice");
    assert!(alice
        .storage
        .get_conversation(&alice.did, &cid)
        .await
        .unwrap()
        .is_none());
    assert!(alice
        .orchestrator
        .reconcile_terminal_conversation_hint(&cid, 20, true)
        .await
        .unwrap());
    assert!(!alice
        .orchestrator
        .reconcile_terminal_conversation_hint(&cid, 19, true)
        .await
        .unwrap());
    assert!(!alice
        .orchestrator
        .reconcile_terminal_conversation_hint(&cid, 20, false)
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_accepts_account_close_from_authorized_device_without_group_leaf() {
    let (world, cid, group) = closed_pair_with_closing_device(true).await;
    let bob = world.client("Bob");
    assert!(bob
        .orchestrator
        .reconcile_terminal_conversation(&cid)
        .await
        .unwrap());
    assert_eq!(
        bob.storage.get_conversation_state(&cid).await.unwrap(),
        Some(ConversationState::Closed)
    );
    assert_eq!(bob.orchestrator.mls_context().get_epoch(group).unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn active_inventory_successor_does_not_acknowledge_or_project_old_close() {
    let (world, cid, group) = closed_pair().await;
    let active = json!({"state":{"coordinates":{"conversationId":cid,"groupId":STANDARD.encode(&group),"lifecycle":"active"}}});
    world
        .delivery_service()
        .set_terminal_inventory_extra_items_for_test(vec![active]);
    let bob = world.client("Bob");
    assert!(!bob
        .orchestrator
        .reconcile_terminal_conversation(&cid)
        .await
        .unwrap());
    assert_ne!(
        bob.storage.get_conversation_state(&cid).await.unwrap(),
        Some(ConversationState::Closed)
    );
    let alice = world.client("Alice");
    assert!(!alice
        .orchestrator
        .reconcile_terminal_conversation_hint(&cid, 20, true)
        .await
        .unwrap());
}
