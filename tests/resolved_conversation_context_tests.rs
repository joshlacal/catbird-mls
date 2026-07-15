#![allow(dead_code)]

mod e2e_harness;

use std::sync::Arc;

use catbird_mls::orchestrator::{
    ConversationState, ConversationView, CredentialStore, GroupState, IncomingEnvelope,
    MLSAPIClient, MLSOrchestrator, MLSStorageBackend, MemberRole, MemberView, MlsCryptoContext,
    OrchestratorConfig, PersistedRecoveryBackoff,
};
use catbird_mls::{GroupConfig, KeychainAccess, MLSContext, MLSError};
use chrono::Utc;
use e2e_harness::TestWorld;
use sha2::{Digest, Sha256};

const STABLE_CONVERSATION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[tokio::test(flavor = "multi_thread")]
async fn failed_create_rolls_back_the_unmapped_local_mls_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let before = alice
        .orchestrator
        .mls_context()
        .list_local_group_ids()
        .expect("enumerate groups before failed create");

    world.delivery_service().fail_next_create();
    assert!(alice
        .orchestrator
        .create_group("must roll back", None, None)
        .await
        .is_err());

    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .expect("enumerate groups after failed create"),
        before,
        "create rollback must not orphan an MLS group before stable mapping exists"
    );
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        alice
            .orchestrator
            .groups_being_created()
            .lock()
            .await
            .is_empty(),
        "create protection must also be balanced on failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_post_create_projection_rolls_back_stable_row_cache_and_raw_mls_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let stable_id = "stable-create-projection-failure";
    let local_groups_before = alice
        .orchestrator
        .mls_context()
        .list_local_group_ids()
        .expect("enumerate groups before create");
    let storage_rows_before = alice.storage.conversation_count();
    world
        .delivery_service()
        .set_next_create_conversation_id(stable_id);
    alice.storage.fail_next_set_group_state();

    assert!(alice
        .orchestrator
        .create_group("post-create rollback", None, None)
        .await
        .is_err());

    let server_page = world
        .delivery_service()
        .clone_as(&alice.did)
        .get_conversations(100, None)
        .await
        .expect("read accepted server conversation");
    let accepted = server_page
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == stable_id)
        .expect("createConvo accepted stable conversation");
    assert_ne!(accepted.group_id, stable_id);
    assert_eq!(
        alice.storage.conversation_count(),
        storage_rows_before,
        "rollback must delete the half-created stable storage row"
    );
    assert!(alice
        .storage
        .get_conversation(&alice.did, stable_id)
        .await
        .expect("read stable storage row")
        .is_none());
    assert!(
        !alice
            .orchestrator
            .conversations()
            .lock()
            .await
            .contains_key(stable_id),
        "rollback must evict the stable conversation cache"
    );
    assert!(
        !alice.storage.has_group_state(&accepted.group_id),
        "rollback must delete the raw-group GroupState projection"
    );
    assert!(
        !alice
            .orchestrator
            .group_states()
            .lock()
            .await
            .contains_key(&accepted.group_id),
        "rollback must evict the raw-group GroupState cache"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .expect("enumerate groups after create"),
        local_groups_before,
        "rollback must delete the raw MLS secrets"
    );
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_group_info_export_removes_stable_projection_and_raw_aliases() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let stable_id = "stable-create-export-failure";
    let local_groups_before = alice
        .orchestrator
        .mls_context()
        .list_local_group_ids()
        .unwrap();
    let storage_rows_before = alice.storage.conversation_count();
    world
        .delivery_service()
        .set_next_create_conversation_id(stable_id);
    let group_state_gate = alice.storage.pause_next_group_state_write();

    let mut create = Box::pin(
        alice
            .orchestrator
            .create_group("export rollback", None, None),
    );
    tokio::select! {
        _ = group_state_gate.wait_until_entered() => {}
        result = &mut create => panic!("create completed before group-state barrier: {result:?}"),
    }
    let accepted = world
        .delivery_service()
        .clone_as(&alice.did)
        .get_conversations(100, None)
        .await
        .expect("read accepted server conversation")
        .conversations
        .into_iter()
        .find(|conversation| conversation.conversation_id == stable_id)
        .expect("createConvo accepted stable conversation");
    assert_ne!(accepted.group_id, stable_id);
    alice
        .orchestrator
        .mls_context()
        .delete_group(hex::decode(&accepted.group_id).expect("raw group id"))
        .expect("inject missing group before export");
    group_state_gate.release();
    assert!(
        create.await.is_err(),
        "missing MLS group must fail GroupInfo export"
    );

    assert_eq!(alice.storage.conversation_count(), storage_rows_before);
    assert!(alice
        .storage
        .get_conversation(&alice.did, stable_id)
        .await
        .unwrap()
        .is_none());
    assert!(!alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .contains_key(stable_id));
    assert!(!alice.storage.has_group_state(&accepted.group_id));
    assert!(!alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .contains_key(&accepted.group_id));
    let states = alice.orchestrator.conversation_states().lock().await;
    assert!(!states.contains_key(stable_id));
    assert!(!states.contains_key(&accepted.group_id));
    drop(states);
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_local_group_ids()
            .unwrap(),
        local_groups_before
    );
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_during_create_protects_distinct_stable_and_group_ids() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let stable_id = "stable-create-visibility-gap";
    world
        .delivery_service()
        .set_next_create_conversation_id(stable_id);
    world
        .delivery_service()
        .set_conversation_hidden_from_list(stable_id, true);
    let publish_gate = world.delivery_service().pause_next_publish_group_info();
    let list_gate = world.delivery_service().pause_next_get_conversations();

    let create = alice
        .orchestrator
        .create_group("stable id create race", None, None);
    let sync_while_create_is_protected = async {
        publish_gate.wait_until_reached().await;
        let mut sync = Box::pin(alice.orchestrator.sync_with_server(true));
        tokio::select! {
            _ = list_gate.wait_until_reached() => {}
            result = &mut sync => panic!("sync completed before stale listing snapshot: {result:?}"),
        }
        // Complete create after sync captured the stale server listing but
        // before sync snapshots local creation state: the generation fence
        // must suppress deletion even though the RAII guard is now gone.
        publish_gate.release();
        let guard = alice.orchestrator.groups_being_created().lock().await;
        assert!(guard.is_empty(), "create must finish and drop its guard");
        drop(guard);
        list_gate.release();
        sync.await
    };
    let (created, synced) = tokio::join!(create, sync_while_create_is_protected);
    synced.expect("concurrent sync");
    let created = created.expect("create survives concurrent sync");

    assert_eq!(created.conversation_id, stable_id);
    assert_ne!(created.conversation_id, created.group_id);
    assert!(
        alice
            .orchestrator
            .mls_context()
            .group_exists(hex::decode(&created.group_id).expect("group id")),
        "sync must not force-delete the mutable MLS group while its distinct stable id is mid-create"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, stable_id)
            .await
            .expect("read stable conversation")
            .is_some(),
        "sync must preserve the new stable-id mapping throughout creation"
    );
    assert!(
        alice
            .orchestrator
            .groups_being_created()
            .lock()
            .await
            .is_empty(),
        "create protection must be balanced on successful exit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_create_releases_creation_protection() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let stable_id = "stable-create-cancelled";
    world
        .delivery_service()
        .set_next_create_conversation_id(stable_id);
    let publish_gate = world.delivery_service().pause_next_publish_group_info();

    let mut create = Box::pin(
        alice
            .orchestrator
            .create_group("cancelled create", None, None),
    );
    tokio::select! {
        _ = publish_gate.wait_until_reached() => {}
        result = &mut create => panic!("create completed before cancellation point: {result:?}"),
    }
    drop(create);

    assert!(
        alice
            .orchestrator
            .groups_being_created()
            .lock()
            .await
            .is_empty(),
        "dropping an in-flight create future must release its creation guard"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn distinct_stable_create_publishes_group_info_for_stable_recovery_route() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let stable_id = "stable-create-group-info-route";
    world
        .delivery_service()
        .set_next_create_conversation_id(stable_id);

    let created = alice
        .orchestrator
        .create_group("stable recovery route", None, None)
        .await
        .expect("create distinct stable conversation");
    assert_eq!(created.conversation_id, stable_id);
    assert_ne!(created.conversation_id, created.group_id);

    world
        .delivery_service()
        .get_group_info(stable_id)
        .await
        .expect("GroupInfo must be published under stable conversation id");
    assert!(
        world
            .delivery_service()
            .get_group_info(&created.group_id)
            .await
            .is_err(),
        "mutable MLS group id must not become the delivery-service GroupInfo route"
    );

    alice
        .orchestrator
        .force_rejoin(stable_id)
        .await
        .expect("recovery must fetch the newly published GroupInfo by stable id");
    assert!(
        world
            .delivery_service()
            .get_group_info_call_count(stable_id)
            >= 2,
        "direct verification and recovery must both route GroupInfo by stable id"
    );
}

async fn registered_two_client_world() -> TestWorld {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    world.register_device("Bob").await.expect("register bob");
    world
}

#[tokio::test(flavor = "multi_thread")]
async fn send_uses_resolved_group_id_but_routes_by_stable_conversation_id() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");

    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("rotated send", None, None)
        .await
        .expect("create group");
    let group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh stable conversation mapping");
    let stable_message_count_before_send = world
        .delivery_service()
        .message_count(STABLE_CONVERSATION_ID);

    let sent = alice
        .orchestrator
        .send_message(STABLE_CONVERSATION_ID, "after rotation")
        .await
        .expect("send via stable conversation id");

    assert_eq!(sent.conversation_id, STABLE_CONVERSATION_ID);
    assert_eq!(
        world
            .delivery_service()
            .message_count(STABLE_CONVERSATION_ID),
        stable_message_count_before_send + 1,
        "delivery-service routing must retain the stable conversation id"
    );
    assert_eq!(
        world.delivery_service().message_count(&group_id),
        0,
        "the mutable MLS group id must not replace the server conversation id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authoritative_conversation_mapping_wins_over_stale_legacy_group_state() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    world.register_device("Bob").await.expect("register bob");

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let conversation = alice
        .orchestrator
        .create_group("stale legacy resolver", None, None)
        .await
        .expect("create group");
    let active_group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh authoritative conversation mapping");

    alice.orchestrator.group_states().lock().await.insert(
        STABLE_CONVERSATION_ID.to_string(),
        GroupState {
            group_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            conversation_id: STABLE_CONVERSATION_ID.to_string(),
            epoch: 99,
            members: vec![alice.did.clone()],
        },
    );
    let stable_message_count_before_send = world
        .delivery_service()
        .message_count(STABLE_CONVERSATION_ID);

    let sent = alice
        .orchestrator
        .send_message(STABLE_CONVERSATION_ID, "authoritative mapping")
        .await
        .expect("stale legacy group state must not override active mapping");

    assert_eq!(sent.conversation_id, STABLE_CONVERSATION_ID);
    assert_eq!(
        world
            .delivery_service()
            .message_count(STABLE_CONVERSATION_ID),
        stable_message_count_before_send + 1
    );
    assert_eq!(world.delivery_service().message_count(&active_group_id), 0);

    alice
        .orchestrator
        .add_members(STABLE_CONVERSATION_ID, std::slice::from_ref(&bob_did))
        .await
        .expect("stale legacy state must not redirect staged group mutation");
    let active = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(&active_group_id)
        .cloned()
        .expect("active group state");
    assert!(active.members.contains(&bob_did));
}

#[tokio::test(flavor = "multi_thread")]
async fn force_rejoin_deletes_locally_present_group_when_server_mapping_has_advanced() {
    let world = registered_two_client_world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");

    let old = alice
        .orchestrator
        .create_group("force rejoin old local group", None, None)
        .await
        .expect("create old local group");
    let old_group_id = old.group_id.clone();
    let old_group_bytes = hex::decode(&old_group_id).expect("old group id");
    world
        .delivery_service()
        .rekey_conversation_for_test(&old.conversation_id, STABLE_CONVERSATION_ID);
    let stable_view = world
        .delivery_service()
        .clone_as(&alice.did)
        .get_conversations(10, None)
        .await
        .expect("fetch stable server mapping")
        .conversations
        .into_iter()
        .find(|view| view.conversation_id == STABLE_CONVERSATION_ID)
        .expect("stable server conversation");
    alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .insert(STABLE_CONVERSATION_ID.to_string(), stable_view);
    alice
        .storage
        .ensure_conversation_exists(&alice.did, STABLE_CONVERSATION_ID, &old_group_id)
        .await
        .expect("persist stable conversation mapping");

    // The server has already advanced its projected mapping to G2. G2 is also
    // locally materialized, but its group-state cache binding is absent; the
    // cleanup set must still include it alongside every explicitly C-bound
    // predecessor.
    let absent_server_group_id = "22".repeat(32);
    let authoritative_group_bytes = hex::decode(&absent_server_group_id).expect("G2 group id");
    world
        .delivery_service()
        .set_conversation_group_id_for_test(STABLE_CONVERSATION_ID, &absent_server_group_id);
    {
        let mut conversations = alice.orchestrator.conversations().lock().await;
        let live = conversations
            .get_mut(STABLE_CONVERSATION_ID)
            .expect("live stable conversation");
        live.group_id = absent_server_group_id.clone();
    }
    alice
        .storage
        .set_conversation_group_id_for_test(STABLE_CONVERSATION_ID, &absent_server_group_id);
    let mls_did = alice
        .credentials
        .get_mls_did(&alice.did)
        .await
        .expect("read Alice MLS DID")
        .expect("registered Alice MLS DID");
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.clone().into_bytes(),
            authoritative_group_bytes.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize authoritative G2 without a cache binding");
    let old_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(old_group_bytes.clone())
        .expect("G1 remains in MLSContext");
    alice.orchestrator.group_states().lock().await.insert(
        old_group_id.clone(),
        GroupState {
            group_id: old_group_id.clone(),
            conversation_id: STABLE_CONVERSATION_ID.to_string(),
            epoch: old_epoch,
            members: vec![alice.did.clone()],
        },
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(old_group_bytes.clone()));
    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(authoritative_group_bytes.clone()));
    assert!(alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .values()
        .any(|state| state.conversation_id == STABLE_CONVERSATION_ID
            && state.group_id == old_group_id));

    // A second, older cache candidate is also materialized for C. Its larger
    // (synthetic) epoch proves epochs from distinct MLS groups cannot choose a
    // single cleanup winner: both pre-rejoin groups must be removed.
    let extra_old_group_bytes = vec![0x19; 32];
    let extra_old_group_id = hex::encode(&extra_old_group_bytes);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.into_bytes(),
            extra_old_group_bytes.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize second old group");
    alice.orchestrator.group_states().lock().await.insert(
        extra_old_group_id.clone(),
        GroupState {
            group_id: extra_old_group_id,
            conversation_id: STABLE_CONVERSATION_ID.to_string(),
            epoch: old_epoch + 100,
            members: vec![alice.did.clone()],
        },
    );

    // Supply GroupInfo for a distinct G3 that is not present in Alice's local
    // context. A successful force rejoin should replace G1 with this target.
    let target = bob
        .orchestrator
        .create_group("force rejoin target", None, None)
        .await
        .expect("create remote target group");
    let target_group_bytes = hex::decode(&target.group_id).expect("target group id");
    let target_group_info = world
        .delivery_service()
        .clone_as(&bob.did)
        .get_group_info(&target.conversation_id)
        .await
        .expect("fetch remote target GroupInfo");
    world
        .delivery_service()
        .clone_as(&alice.did)
        .publish_group_info(STABLE_CONVERSATION_ID, &target_group_info)
        .await
        .expect("publish target GroupInfo under stable conversation");
    assert!(!alice
        .orchestrator
        .mls_context()
        .group_exists(target_group_bytes.clone()));

    alice
        .orchestrator
        .force_rejoin(STABLE_CONVERSATION_ID)
        .await
        .expect("force rejoin succeeds");

    assert!(
        !alice
            .orchestrator
            .mls_context()
            .group_exists(old_group_bytes),
        "successful force rejoin must delete locally bound G1, not absent authoritative G2"
    );
    assert!(
        !alice
            .orchestrator
            .mls_context()
            .group_exists(extra_old_group_bytes),
        "successful force rejoin must delete every materialized group bound to C"
    );
    assert!(
        !alice
            .orchestrator
            .mls_context()
            .group_exists(authoritative_group_bytes),
        "successful force rejoin must also delete a distinct materialized authoritative group"
    );
    assert!(
        alice
            .orchestrator
            .mls_context()
            .group_exists(target_group_bytes),
        "successful force rejoin must preserve the newly joined GroupInfo target"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_local_delete_removes_every_materialized_predecessor_and_target() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");

    let conversation = alice
        .orchestrator
        .create_group("reset-pending local delete", None, None)
        .await
        .expect("create predecessor group");
    let conversation_id = conversation.conversation_id.clone();
    let predecessor_group_id = conversation.group_id.clone();
    let predecessor_group = hex::decode(&predecessor_group_id).expect("predecessor group id");
    let mls_did = alice
        .credentials
        .get_mls_did(&alice.did)
        .await
        .expect("read Alice MLS DID")
        .expect("registered Alice MLS DID");

    // Simulate an additional locally materialized predecessor left by an
    // interrupted earlier transition. Its explicit stable-conversation
    // binding is the only durable discovery path for its epoch secrets.
    let older_predecessor = vec![0x31; 32];
    let older_predecessor_id = hex::encode(&older_predecessor);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.clone().into_bytes(),
            older_predecessor.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize older predecessor");
    alice.orchestrator.group_states().lock().await.insert(
        older_predecessor_id.clone(),
        GroupState {
            group_id: older_predecessor_id,
            conversation_id: conversation_id.clone(),
            epoch: 0,
            members: vec![alice.did.clone()],
        },
    );

    // Reproduce the crash window after the atomic reset authority commit but
    // before record_group_reset deleted the old local groups. The durable
    // conversation mapping still names the predecessor while reset authority
    // names a distinct, already materialized target.
    let reset_target = vec![0x32; 32];
    let reset_target_id = hex::encode(&reset_target);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.into_bytes(),
            reset_target.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize reset target");
    alice
        .storage
        .mark_reset_pending(&conversation_id, &reset_target_id, 7, 1_700_000_000_000)
        .await
        .expect("commit reset authority");

    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(predecessor_group.clone()));
    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(older_predecessor.clone()));
    assert!(alice
        .orchestrator
        .mls_context()
        .group_exists(reset_target.clone()));

    world
        .delivery_service()
        .remove_conversation_for_test(&conversation_id);
    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("stale conversation cleanup must remain retryable");

    for (label, group_id) in [
        ("mapped predecessor", predecessor_group),
        ("older bound predecessor", older_predecessor),
        ("reset target", reset_target),
    ] {
        assert!(
            !alice.orchestrator.mls_context().group_exists(group_id),
            "local delete must remove {label} before dropping reset authority"
        );
    }
    assert!(
        alice
            .storage
            .get_persisted_reset_pending(&conversation_id)
            .is_none(),
        "successful cleanup may clear reset authority only after all local groups are gone"
    );
    assert!(
        alice
            .storage
            .get_conversation(&alice.did, &conversation_id)
            .await
            .expect("read durable conversation")
            .is_none(),
        "successful cleanup removes the durable conversation mapping"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_delete_rediscovers_all_persisted_predecessors_after_intent_crash() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("restart-safe predecessor delete", None, None)
        .await
        .expect("create mapped predecessor");
    let conversation_id = conversation.conversation_id.clone();
    let mapped_predecessor = hex::decode(&conversation.group_id).expect("mapped predecessor");
    let mls_did = alice
        .credentials
        .get_mls_did(&alice.did)
        .await
        .expect("read MLS DID")
        .expect("registered MLS DID");

    let extra_predecessor = vec![0x41; 32];
    let extra_predecessor_id = hex::encode(&extra_predecessor);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.clone().into_bytes(),
            extra_predecessor.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize extra predecessor");
    let extra_state = GroupState {
        group_id: extra_predecessor_id.clone(),
        conversation_id: conversation_id.clone(),
        epoch: 0,
        members: vec![alice.did.clone()],
    };
    alice
        .storage
        .set_group_state(&extra_state)
        .await
        .expect("persist extra predecessor binding");
    alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .insert(extra_predecessor_id.clone(), extra_state);

    let reset_target = vec![0x42; 32];
    let reset_target_id = hex::encode(&reset_target);
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.into_bytes(),
            reset_target.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize reset target");
    alice
        .storage
        .mark_reset_pending(&conversation_id, &reset_target_id, 9, 1_700_000_000_000)
        .await
        .expect("commit reset authority");
    // Force the exact reset clear CAS to lose its race after all local MLS
    // groups were deleted. This preserves the pending intent, reset authority,
    // durable conversation mapping, and group-state rows at the crash point.
    // The retry intent must therefore carry the complete cleanup set even
    // though the reopened MLS manifest no longer enumerates those groups.
    alice
        .storage
        .force_next_clear_reset_pending_for_delete_false();
    world
        .delivery_service()
        .remove_conversation_for_test(&conversation_id);
    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("first local-delete pass remains retryable");
    assert_eq!(alice.storage.pending_local_delete_count(), 1);
    assert!(alice.storage.has_group_state(&extra_predecessor_id));
    for group_id in [&mapped_predecessor, &extra_predecessor, &reset_target] {
        assert!(!alice
            .orchestrator
            .mls_context()
            .group_exists(group_id.clone()));
    }

    // Crash before group-state/conversation cleanup. A fresh process has no
    // in-memory group-state cache and the groups are already absent from its
    // MLS manifest, so only the durable intent can name every stale key.
    alice
        .orchestrator
        .mls_context()
        .flush_and_prepare_close()
        .expect("close pre-crash MLS context");

    struct NoopKeychain;
    #[async_trait::async_trait]
    impl KeychainAccess for NoopKeychain {
        async fn read(&self, _key: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        async fn write(&self, _key: String, _value: Vec<u8>) -> Result<(), MLSError> {
            Ok(())
        }
        async fn delete(&self, _key: String) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let restarted_context = MLSContext::new(
        alice._temp_dir.join("mls.db").to_string_lossy().to_string(),
        "test-key-Alice".to_string(),
        Box::new(NoopKeychain),
    )
    .expect("reopen persisted MLS context");
    let restarted = MLSOrchestrator::new(
        restarted_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(&alice.did)),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );
    restarted
        .initialize(&alice.did)
        .await
        .expect("startup delete reconcile");

    for (label, group_id) in [
        ("mapped predecessor", mapped_predecessor),
        ("persisted extra predecessor", extra_predecessor),
        ("reset target", reset_target),
    ] {
        assert!(
            !restarted.mls_context().group_exists(group_id),
            "startup reconcile must delete {label} before clearing its intent"
        );
    }
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
    assert!(
        !alice.storage.has_group_state(&extra_predecessor_id),
        "startup retry must remove stale predecessor group-state rows named only by the durable intent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_local_delete_from_alice_never_replays_in_bob_lifecycle() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("tenant-bound pending delete", None, None)
        .await
        .expect("create Alice group");
    let conversation_id = conversation.conversation_id.clone();
    let target = vec![0x51; 32];
    let target_id = hex::encode(&target);
    alice
        .storage
        .mark_reset_pending(&conversation_id, &target_id, 11, 1_700_000_000_000)
        .await
        .expect("commit Alice reset authority");
    alice
        .storage
        .force_next_clear_reset_pending_for_delete_false();
    world
        .delivery_service()
        .remove_conversation_for_test(&conversation_id);
    alice
        .orchestrator
        .sync_with_server(true)
        .await
        .expect("leave Alice delete pending");
    assert_eq!(alice.storage.pending_local_delete_count(), 1);

    struct NoopKeychain;
    #[async_trait::async_trait]
    impl KeychainAccess for NoopKeychain {
        async fn read(&self, _key: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        async fn write(&self, _key: String, _value: Vec<u8>) -> Result<(), MLSError> {
            Ok(())
        }
        async fn delete(&self, _key: String) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let bob_dir = tempfile::tempdir().expect("Bob tempdir");
    let bob_context = MLSContext::new(
        bob_dir.path().join("mls.db").to_string_lossy().to_string(),
        "bob-tenant-delete-key".into(),
        Box::new(NoopKeychain),
    )
    .expect("Bob MLS context");
    bob_context
        .create_group_with_id(
            b"did:plc:bob".to_vec(),
            target.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize Bob group at colliding bytes");
    let bob_orchestrator = MLSOrchestrator::new(
        bob_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as("did:plc:bob")),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );
    bob_orchestrator
        .initialize("did:plc:bob")
        .await
        .expect("Bob initialization must leave Alice cleanup pending");

    assert!(
        bob_orchestrator.mls_context().group_exists(target),
        "Alice's pending delete must never remove Bob's group at colliding bytes"
    );
    assert_eq!(
        alice.storage.pending_local_delete_count(),
        1,
        "tenant mismatch must keep Alice's intent for an Alice lifecycle"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unbound_legacy_delete_preserves_bob_with_same_conversation_id() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let alice_convo = alice
        .orchestrator
        .create_group("Alice legacy orphan", None, None)
        .await
        .expect("create Alice group");
    let conversation_id = alice_convo.conversation_id.clone();
    alice
        .storage
        .delete_conversations(&alice.did, &[&conversation_id])
        .await
        .expect("remove Alice conversation row");

    struct BobKeychain;
    #[async_trait::async_trait]
    impl KeychainAccess for BobKeychain {
        async fn read(&self, _key: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        async fn write(&self, _key: String, _value: Vec<u8>) -> Result<(), MLSError> {
            Ok(())
        }
        async fn delete(&self, _key: String) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let bob_did = "did:plc:bob";
    let bob_group = vec![0xb0; 32];
    let bob_group_id = hex::encode(&bob_group);
    let bob_reset_target = hex::encode(vec![0xb1; 32]);
    let bob_dir = tempfile::tempdir().expect("Bob tempdir");
    let bob_context = MLSContext::new(
        bob_dir.path().join("mls.db").to_string_lossy().to_string(),
        "bob-legacy-tenant-key".into(),
        Box::new(BobKeychain),
    )
    .expect("Bob MLS context");
    bob_context
        .create_group_with_id(
            bob_did.as_bytes().to_vec(),
            bob_group.clone(),
            Some(GroupConfig::default()),
        )
        .expect("materialize Bob group");
    alice
        .storage
        .ensure_conversation_exists(bob_did, &conversation_id, &bob_group_id)
        .await
        .expect("persist Bob conversation with colliding stable id");
    alice
        .storage
        .set_group_state(&GroupState {
            group_id: bob_group_id.clone(),
            conversation_id: conversation_id.clone(),
            epoch: 0,
            members: vec![bob_did.to_string()],
        })
        .await
        .expect("persist Bob group state");
    alice
        .storage
        .mark_reset_pending(&conversation_id, &bob_reset_target, 17, 1_700_000_000_000)
        .await
        .expect("persist Bob reset authority");
    let recovery_now = chrono::Utc::now().timestamp_millis();
    alice
        .storage
        .seed_recovery_backoff(PersistedRecoveryBackoff {
            conversation_id: conversation_id.clone(),
            failed_rejoin_count: 2,
            last_attempt_at_ms: recovery_now,
            quarantined_until_ms: Some(recovery_now + 60_000),
        });
    alice
        .storage
        .mark_quarantined(&conversation_id, "bob-current", recovery_now)
        .await
        .expect("persist Bob quarantine");
    alice
        .storage
        .mark_needs_rejoin(&conversation_id)
        .await
        .expect("persist Bob rejoin flag");
    alice
        .storage
        .seed_pending_local_delete(catbird_mls::orchestrator::PendingLocalDelete {
            conversation_id: conversation_id.clone(),
            group_id_hex: Some(alice_convo.group_id.clone()),
        });

    let bob_orchestrator = MLSOrchestrator::new(
        bob_context,
        Arc::new(alice.storage.clone()),
        Arc::new(world.delivery_service().clone_as(bob_did)),
        Arc::new(alice.credentials.clone()),
        OrchestratorConfig::default(),
    );
    bob_orchestrator.conversations().lock().await.insert(
        conversation_id.clone(),
        ConversationView {
            group_id: bob_group_id.clone(),
            conversation_id: conversation_id.clone(),
            epoch: 0,
            members: vec![MemberView {
                did: bob_did.to_string(),
                role: MemberRole::Admin,
            }],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
        },
    );
    bob_orchestrator.group_states().lock().await.insert(
        bob_group_id.clone(),
        GroupState {
            group_id: bob_group_id.clone(),
            conversation_id: conversation_id.clone(),
            epoch: 0,
            members: vec![bob_did.to_string()],
        },
    );
    bob_orchestrator.conversation_states().lock().await.insert(
        conversation_id.clone(),
        ConversationState::ResetPending {
            new_group_id: bob_reset_target.clone(),
            reset_generation: 17,
            notified_at_ms: 1_700_000_000_000,
        },
    );
    bob_orchestrator
        .initialize(bob_did)
        .await
        .expect("Bob initialize");

    assert!(bob_orchestrator.mls_context().group_exists(bob_group));
    assert!(alice.storage.has_group_state(&bob_group_id));
    assert!(alice
        .storage
        .get_conversation(bob_did, &conversation_id)
        .await
        .expect("read Bob conversation")
        .is_some());
    assert!(matches!(
        alice
            .storage
            .get_conversation_state(&conversation_id)
            .await
            .expect("read Bob reset state"),
        Some(ConversationState::ResetPending { .. })
    ));
    assert!(
        alice
            .storage
            .get_persisted_recovery_backoff(&conversation_id)
            .is_some(),
        "mismatched legacy group cleanup must preserve current-tenant recovery backoff"
    );
    assert!(
        alice
            .storage
            .get_persisted_quarantine(&conversation_id)
            .is_some(),
        "mismatched legacy group cleanup must preserve current-tenant quarantine"
    );
    assert!(alice.storage.has_rejoin_flag(&conversation_id));
    assert_eq!(
        bob_orchestrator
            .conversations()
            .lock()
            .await
            .get(&conversation_id)
            .map(|view| view.group_id.as_str()),
        Some(bob_group_id.as_str()),
        "mismatched legacy cleanup must preserve the current stable-id cache"
    );
    assert!(bob_orchestrator
        .group_states()
        .lock()
        .await
        .contains_key(&bob_group_id));
    assert!(matches!(
        bob_orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&conversation_id),
        Some(ConversationState::ResetPending { .. })
    ));
    assert_eq!(alice.storage.pending_local_delete_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_target_blocks_send_across_live_and_durable_conversation_views() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("reset authority", None, None)
        .await
        .expect("create old group");
    let conversation_id = conversation.conversation_id.clone();
    let old_group_id = conversation.group_id.clone();
    let new_group_bytes = vec![0x42; 32];
    let new_group_id = hex::encode(&new_group_bytes);

    alice
        .orchestrator
        .record_group_reset(&conversation_id, new_group_bytes.clone(), 7)
        .await
        .expect("persist reset target");

    let cached = alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&conversation_id)
        .cloned()
        .expect("live authoritative conversation view");
    assert_eq!(cached.group_id, new_group_id);
    assert_ne!(cached.group_id, old_group_id);

    let mls_did = alice
        .credentials
        .get_mls_did(&alice.did)
        .await
        .expect("read MLS DID")
        .expect("registered MLS DID");
    alice
        .orchestrator
        .mls_context()
        .create_group_with_id(
            mls_did.into_bytes(),
            new_group_bytes,
            Some(GroupConfig::default()),
        )
        .expect("make reset target locally available");

    let before = world.delivery_service().message_count(&conversation_id);
    let live_error = alice
        .orchestrator
        .send_message(&conversation_id, "live reset target")
        .await
        .expect_err("live ResetPending authority must block send until completion");
    assert!(matches!(
        live_error,
        catbird_mls::orchestrator::error::OrchestratorError::ResetCompletionNotCommitted {
            ref convo_id,
            reset_generation: 7,
            ..
        } if convo_id == &conversation_id
    ));
    assert_eq!(
        world.delivery_service().message_count(&conversation_id),
        before
    );

    let durable = alice
        .storage
        .get_conversation(&alice.did, &conversation_id)
        .await
        .expect("read durable conversation")
        .expect("durable conversation row");
    assert_eq!(
        durable.group_id, old_group_id,
        "regression fixture must retain the independently persisted stale view"
    );
    alice.orchestrator.conversations().lock().await.clear();
    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .clear();

    let durable_error = alice
        .orchestrator
        .send_message(&conversation_id, "durable reset target")
        .await
        .expect_err("durable ResetPending authority must block send after cache loss");
    assert!(matches!(
        durable_error,
        catbird_mls::orchestrator::error::OrchestratorError::ResetCompletionNotCommitted {
            ref convo_id,
            reset_generation: 7,
            ..
        } if convo_id == &conversation_id
    ));
    assert_eq!(
        world.delivery_service().message_count(&conversation_id),
        before
    );
    assert_eq!(world.delivery_service().message_count(&new_group_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_persistence_failure_keeps_old_authority_and_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("failed reset persistence", None, None)
        .await
        .expect("create old group");
    let old_group_bytes = hex::decode(&conversation.group_id).expect("old group id");
    let new_group_bytes = vec![0x24; 32];
    let new_group_id = hex::encode(&new_group_bytes);
    alice.storage.fail_next_mark_reset_pending();

    let result = alice
        .orchestrator
        .record_group_reset(&conversation.conversation_id, new_group_bytes, 8)
        .await;
    assert!(
        result.is_err(),
        "security state persistence must fail closed"
    );

    let cached = alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&conversation.conversation_id)
        .cloned()
        .expect("old conversation mapping remains");
    assert_eq!(cached.group_id, conversation.group_id);
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(old_group_bytes)
            .is_ok(),
        "old group must not be deleted after a failed reset transition"
    );
    assert!(!alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .contains_key(&new_group_id));
    assert!(alice
        .storage
        .get_persisted_reset_pending(&conversation.conversation_id)
        .is_none());
    assert!(!matches!(
        alice
            .storage
            .get_current_state(&conversation.conversation_id),
        Some(catbird_mls::orchestrator::ConversationState::ResetPending { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_payload_failure_never_publishes_new_authority() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("failed reset payload", None, None)
        .await
        .expect("create old group");
    let old_group_bytes = hex::decode(&conversation.group_id).expect("old group id");
    let new_group_id = hex::encode(vec![0x66; 32]);
    alice.storage.fail_next_mark_reset_pending();

    let result = alice
        .orchestrator
        .record_group_reset(&conversation.conversation_id, vec![0x66; 32], 9)
        .await;
    assert!(result.is_err());
    assert!(alice
        .orchestrator
        .mls_context()
        .get_epoch(old_group_bytes)
        .is_ok());
    assert!(alice
        .storage
        .get_persisted_reset_pending(&conversation.conversation_id)
        .is_none());
    assert!(!alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .contains_key(&new_group_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn same_generation_replay_resumes_strict_predecessor_cleanup() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("resume committed reset", None, None)
        .await
        .expect("create predecessor");
    let old_group = hex::decode(&conversation.group_id).expect("valid predecessor id");
    let target = vec![0x67; 32];
    let target_hex = hex::encode(&target);
    alice
        .storage
        .mark_reset_pending(
            &conversation.conversation_id,
            &target_hex,
            9,
            Utc::now().timestamp_millis(),
        )
        .await
        .expect("simulate publication committed before cleanup");
    alice.orchestrator.group_states().lock().await.clear();

    let outcome = alice
        .orchestrator
        .record_group_reset_with_outcome(&conversation.conversation_id, target.clone(), 9)
        .await
        .expect("same-generation replay must resume side effects");

    assert_eq!(
        outcome,
        catbird_mls::orchestrator::ResetRecordOutcome::StaleOrDuplicate
    );
    assert!(
        !alice.orchestrator.mls_context().group_exists(old_group),
        "replay must finish strict predecessor cleanup"
    );
    assert!(alice.storage.has_rejoin_flag(&conversation.conversation_id));
    assert!(alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .values()
        .any(
            |state| state.conversation_id == conversation.conversation_id
                && state.group_id == target_hex
        ));
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_authority_read_failure_preserves_old_group() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("failed authority read", None, None)
        .await
        .expect("create old group");
    let old_group_bytes = hex::decode(&conversation.group_id).expect("old group id");
    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .clear();
    alice
        .storage
        .mark_conversation_state_malformed(&conversation.conversation_id);

    let result = alice
        .orchestrator
        .record_group_reset(&conversation.conversation_id, vec![0x77; 32], 10)
        .await;
    assert!(
        result.is_err(),
        "authority read errors must not be discarded"
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .get_epoch(old_group_bytes)
        .is_ok());
    assert!(alice
        .storage
        .get_persisted_reset_pending(&conversation.conversation_id)
        .is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn incomplete_reset_tag_fails_closed_before_payload_commit_point() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("reset commit seam", None, None)
        .await
        .expect("create old group");
    let before = world
        .delivery_service()
        .message_count(&conversation.conversation_id);
    alice
        .storage
        .set_conversation_state(
            &conversation.conversation_id,
            catbird_mls::orchestrator::ConversationState::ResetPending {
                new_group_id: hex::encode(vec![0x88; 32]),
                reset_generation: 11,
                notified_at_ms: 1,
            },
        )
        .await
        .expect("write pre-commit reset tag");
    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .clear();

    assert!(alice
        .storage
        .get_conversation_state(&conversation.conversation_id)
        .await
        .is_err());
    let result = alice
        .orchestrator
        .send_message(&conversation.conversation_id, "must not cross reset seam")
        .await;
    assert!(
        result.is_err(),
        "incomplete reset transition must block send"
    );
    assert_eq!(
        world
            .delivery_service()
            .message_count(&conversation.conversation_id),
        before
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&conversation.group_id).expect("old group id"))
        .is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_clear_is_bound_to_the_exact_committed_generation() {
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let conversation_id = "generation-bound-clear";
    storage
        .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
        .await
        .expect("conversation row");
    storage.set_epoch_pair_for_test(conversation_id, 741, 742);
    storage
        .set_conversation_state(
            conversation_id,
            catbird_mls::orchestrator::ConversationState::ResetPending {
                new_group_id: "group-gen-2".to_string(),
                reset_generation: 2,
                notified_at_ms: 2,
            },
        )
        .await
        .expect("reset intent tag");
    storage
        .mark_reset_pending(conversation_id, "group-gen-2", 2, 2)
        .await
        .expect("commit generation 2");

    assert!(!storage
        .complete_reset_pending(conversation_id, 1, "group-gen-2", 901)
        .await
        .expect("stale generation clear is a no-op"));
    assert_eq!(
        storage
            .get_persisted_reset_pending(conversation_id)
            .expect("generation 2 must survive stale clear")
            .reset_generation,
        2
    );

    assert!(!storage
        .complete_reset_pending(conversation_id, 2, "wrong-target", 902)
        .await
        .expect("target mismatch is a no-op"));
    assert!(storage
        .get_persisted_reset_pending(conversation_id)
        .is_some());
    assert_eq!(
        storage
            .get_conversation("did:plc:alice", conversation_id)
            .await
            .unwrap()
            .unwrap()
            .epoch,
        741,
        "mismatched completion must not publish the supplied landed epoch"
    );
    assert_eq!(storage.join_epoch_for_test(conversation_id), Some(742));

    assert!(storage
        .complete_reset_pending(conversation_id, 2, "group-gen-2", 3)
        .await
        .expect("exact generation clear"));
    assert!(storage
        .get_persisted_reset_pending(conversation_id)
        .is_none());
    let completed = storage
        .get_conversation("did:plc:alice", conversation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.group_id, "group-gen-2");
    assert_eq!(completed.epoch, 3);
    assert_eq!(storage.join_epoch_for_test(conversation_id), Some(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_completion_requires_the_stable_conversation_row() {
    let storage = e2e_harness::mock_storage::MockStorage::new();
    let conversation_id = "missing-row-completion";
    storage
        .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
        .await
        .expect("conversation row");
    storage
        .set_conversation_state(
            conversation_id,
            ConversationState::ResetPending {
                new_group_id: "winner-group".to_string(),
                reset_generation: 9,
                notified_at_ms: 9,
            },
        )
        .await
        .expect("reset tag");
    storage
        .mark_reset_pending(conversation_id, "winner-group", 9, 9)
        .await
        .expect("reset payload");
    storage.remove_conversation_record_for_test(conversation_id);

    assert!(!storage
        .complete_reset_pending(conversation_id, 9, "winner-group", 3)
        .await
        .expect("missing stable row is a CAS mismatch"));
    let pending = storage
        .get_persisted_reset_pending(conversation_id)
        .expect("failed completion preserves reset authority");
    assert_eq!(pending.reset_generation, 9);
    assert_eq!(pending.new_group_id_hex, "winner-group");
}

#[tokio::test(flavor = "multi_thread")]
async fn leave_via_self_remove_uses_active_group_for_rotated_stable_conversation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("rotated self remove", None, None)
        .await
        .expect("create group");
    let group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh rotated mapping");

    alice
        .orchestrator
        .leave_via_self_remove(STABLE_CONVERSATION_ID)
        .await
        .expect("self-remove must use active mutable group");

    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(group_id).expect("active group id"))
            .is_err(),
        "successful leave must delete the active local group"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_self_remove_proposals_uses_active_group_for_rotated_stable_conversation() {
    let world = registered_two_client_world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let bob_did = bob.did.clone();
    let conversation = alice
        .orchestrator
        .create_group(
            "rotated self remove commit",
            Some(std::slice::from_ref(&bob_did)),
            None,
        )
        .await
        .expect("create group");
    let group_id = conversation.group_id.clone();
    let bob_api = world.delivery_service().clone_as(&bob.did);
    let welcome = bob_api
        .get_welcome(&conversation.conversation_id)
        .await
        .expect("bob welcome");
    bob.orchestrator
        .join_group(&welcome)
        .await
        .expect("bob join");

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh rotated mapping");
    bob.orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh bob rotated mapping");
    let group_id_bytes = hex::decode(&group_id).expect("active group id");
    let proposal = bob
        .orchestrator
        .mls_context()
        .propose_self_remove(group_id_bytes.clone())
        .expect("bob self-remove proposal");
    alice
        .orchestrator
        .process_incoming_message(&IncomingEnvelope {
            conversation_id: STABLE_CONVERSATION_ID.to_string(),
            sender_did: bob.did.clone(),
            ciphertext: proposal,
            timestamp: Utc::now(),
            server_message_id: Some("rotated-self-remove-proposal".to_string()),
            server_epoch: None,
        })
        .await
        .expect("alice processes self-remove proposal");

    alice
        .orchestrator
        .commit_self_remove_proposals(STABLE_CONVERSATION_ID)
        .await
        .expect("self-remove commit must use active mutable group");

    let current_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes)
        .expect("active group remains addressable");
    let cached = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(&group_id)
        .cloned()
        .expect("active group-keyed cache state");
    assert_eq!(cached.conversation_id, STABLE_CONVERSATION_ID);
    assert_eq!(cached.epoch, current_epoch);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_hex_identifier_cannot_be_treated_as_an_authoritative_group_mapping() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    world.register_device("Bob").await.expect("register bob");
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let conversation = alice
        .orchestrator
        .create_group("unbound hex identifier", None, None)
        .await
        .expect("create group");
    let hex_identifier = conversation.group_id.clone();

    alice.orchestrator.conversations().lock().await.clear();
    alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .remove(&hex_identifier);
    alice
        .storage
        .delete_conversations(&alice.did, &[&hex_identifier])
        .await
        .expect("remove authoritative mapping");

    let result = alice
        .orchestrator
        .add_members(&hex_identifier, std::slice::from_ref(&bob_did))
        .await;
    assert!(
        matches!(
            result,
            Err(catbird_mls::orchestrator::error::OrchestratorError::ConversationNotFound(_))
                | Err(catbird_mls::orchestrator::error::OrchestratorError::NotJoined { .. })
        ),
        "unbound hex input must fail before any MLS mutation: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_confirm_normalizes_exact_legacy_state_to_active_group_key() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    world.register_device("Bob").await.expect("register bob");
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let conversation = alice
        .orchestrator
        .create_group("legacy staged confirm", None, None)
        .await
        .expect("create group");
    let group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh stable mapping");
    {
        let mut states = alice.orchestrator.group_states().lock().await;
        let current = states.remove(&group_id).expect("current group state");
        states.insert(STABLE_CONVERSATION_ID.to_string(), current);
    }

    alice
        .orchestrator
        .add_members(STABLE_CONVERSATION_ID, std::slice::from_ref(&bob_did))
        .await
        .expect("confirm staged commit from exact legacy state");

    let states = alice.orchestrator.group_states().lock().await;
    assert!(!states.contains_key(STABLE_CONVERSATION_ID));
    let current = states
        .get(&group_id)
        .expect("normalized active group state");
    assert!(current.members.contains(&bob_did));
    assert_eq!(current.conversation_id, STABLE_CONVERSATION_ID);
}

#[tokio::test(flavor = "multi_thread")]
async fn readiness_uses_authoritative_mapping_instead_of_stale_group_state_scan() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let conversation = alice
        .orchestrator
        .create_group("authoritative readiness", None, None)
        .await
        .expect("create group");
    let group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    // The server-only rekey helper does not migrate the app projection. Model
    // that production migration explicitly so this test isolates resolved
    // group mapping rather than a genuinely durable Initializing state.
    alice
        .storage
        .ensure_conversation_exists(&alice.did, STABLE_CONVERSATION_ID, &group_id)
        .await
        .expect("migrate stable conversation storage row");
    alice
        .storage
        .set_conversation_state(STABLE_CONVERSATION_ID, ConversationState::Active)
        .await
        .expect("persist migrated stable conversation as Active");
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh stable mapping");
    {
        let mut states = alice.orchestrator.group_states().lock().await;
        states.remove(&group_id);
        states.insert(
            STABLE_CONVERSATION_ID.to_string(),
            GroupState {
                group_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                conversation_id: STABLE_CONVERSATION_ID.to_string(),
                epoch: 99,
                members: vec![alice.did.clone()],
            },
        );
    }

    let ready = alice
        .orchestrator
        .ensure_conversation_ready(STABLE_CONVERSATION_ID)
        .await
        .expect("readiness projection");
    assert_eq!(
        ready.recovery_state,
        catbird_mls::orchestrator::ConversationRecoveryState::Healthy
    );
    assert!(ready.send_allowed);
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_uses_resolved_group_id_but_stores_under_stable_conversation_id() {
    let world = registered_two_client_world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let bob_did = bob.did.clone();

    let conversation = alice
        .orchestrator
        .create_group("rotated receive", Some(&[bob_did]), None)
        .await
        .expect("create group with bob");
    let group_id = conversation.group_id.clone();

    let bob_api = world.delivery_service().clone_as(&bob.did);
    let welcome = bob_api
        .get_welcome(&conversation.conversation_id)
        .await
        .expect("bob welcome");
    bob.orchestrator
        .join_group(&welcome)
        .await
        .expect("bob initial join");

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh alice mapping");
    bob.orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh bob mapping");

    let sent = alice
        .orchestrator
        .send_message(STABLE_CONVERSATION_ID, "after rotation")
        .await
        .expect("send through resolved context");

    let envelope = bob_api
        .get_messages(STABLE_CONVERSATION_ID, None, 20, None, None, None)
        .await
        .expect("fetch envelope")
        .0
        .into_iter()
        .find(|message| message.server_message_id.as_deref() == Some(sent.id.as_str()))
        .expect("post-reset envelope");

    let received = bob
        .orchestrator
        .process_incoming_message(&envelope)
        .await
        .expect("process incoming")
        .message
        .expect("decrypted message");

    assert_eq!(received.text, "after rotation");
    assert_eq!(received.conversation_id, STABLE_CONVERSATION_ID);
    assert_eq!(
        bob.storage
            .get_conversation_messages(STABLE_CONVERSATION_ID)
            .len(),
        2,
        "history boundary and received message must share stable storage identity"
    );
    assert!(
        bob.storage.get_conversation_messages(&group_id).is_empty(),
        "received application messages must not be stored under mutable group id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn welcome_join_persists_history_under_stable_conversation_id() {
    let world = registered_two_client_world().await;
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let bob_did = bob.did.clone();

    let conversation = alice
        .orchestrator
        .create_group("rotated welcome", Some(&[bob_did]), None)
        .await
        .expect("create group with bob");
    let group_id = conversation.group_id.clone();
    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);

    let bob_api = world.delivery_service().clone_as(&bob.did);
    let welcome = bob_api
        .get_welcome(STABLE_CONVERSATION_ID)
        .await
        .expect("welcome under stable conversation id");
    let joined = bob
        .orchestrator
        .join_group(&welcome)
        .await
        .expect("join rotated conversation");

    assert_eq!(joined.conversation_id, STABLE_CONVERSATION_ID);
    assert_eq!(joined.group_id, group_id);
    let persisted = bob
        .storage
        .get_conversation(&bob.did, STABLE_CONVERSATION_ID)
        .await
        .expect("read persisted conversation")
        .expect("stable conversation record");
    assert_eq!(persisted.group_id, group_id);
    let markers = bob
        .storage
        .get_conversation_messages(STABLE_CONVERSATION_ID);
    assert_eq!(markers.len(), 1, "Welcome must create one history marker");
    assert_eq!(markers[0].conversation_id, STABLE_CONVERSATION_ID);
    assert!(
        bob.storage.get_conversation_messages(&group_id).is_empty(),
        "Welcome must not split history under the mutable group id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_conversation_fails_closed_before_consuming_own_commit_state() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world
        .register_device("Alice")
        .await
        .expect("register alice");
    let alice = world.client("Alice");
    let ciphertext = b"attacker-selected ciphertext".to_vec();
    let commit_hash = Sha256::digest(&ciphertext).to_vec();
    alice
        .orchestrator
        .own_commits()
        .lock()
        .await
        .insert(commit_hash.clone(), web_time::Instant::now());

    let result = alice
        .orchestrator
        .process_incoming_message(&IncomingEnvelope {
            conversation_id: STABLE_CONVERSATION_ID.to_string(),
            sender_did: "did:plc:attacker".to_string(),
            ciphertext,
            timestamp: Utc::now(),
            server_message_id: None,
            server_epoch: None,
        })
        .await
        .expect("unknown conversation is ignored");

    assert!(result.message.is_none());
    assert!(
        alice
            .orchestrator
            .own_commits()
            .lock()
            .await
            .contains_key(&commit_hash),
        "unresolved conversation input must not mutate self-commit replay state"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn epoch_cleanup_keeps_crypto_group_and_storage_conversation_id_separate() {
    let world = registered_two_client_world().await;
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let conversation = alice
        .orchestrator
        .create_group("rotated cleanup", None, None)
        .await
        .expect("create group");
    let group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh stable conversation mapping");

    for _ in 0..3 {
        alice
            .orchestrator
            .add_members(STABLE_CONVERSATION_ID, std::slice::from_ref(&bob_did))
            .await
            .expect("advance epoch by adding bob");
        alice
            .orchestrator
            .remove_members(STABLE_CONVERSATION_ID, std::slice::from_ref(&bob_did))
            .await
            .expect("advance epoch by removing bob");
    }

    let cleanup_calls = alice.storage.epoch_cleanup_calls();
    assert!(
        !cleanup_calls.is_empty(),
        "epoch must exceed retention window"
    );
    assert!(
        cleanup_calls
            .iter()
            .all(|(conversation_id, _)| conversation_id == STABLE_CONVERSATION_ID),
        "platform epoch storage must be pruned by stable conversation id"
    );
    assert!(
        cleanup_calls
            .iter()
            .all(|(conversation_id, _)| conversation_id != &group_id),
        "mutable MLS group id must remain confined to crypto cleanup"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn swap_members_uses_resolved_group_after_server_accepts_stable_conversation_route() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Charlie"] {
        world.add_client(name).await;
        world.register_device(name).await.expect("register device");
    }
    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let charlie_did = world.client("Charlie").did.clone();
    let conversation = alice
        .orchestrator
        .create_group("rotated swap", Some(std::slice::from_ref(&bob_did)), None)
        .await
        .expect("create group with bob");
    let group_id = conversation.group_id.clone();

    world
        .delivery_service()
        .rekey_conversation_for_test(&conversation.conversation_id, STABLE_CONVERSATION_ID);
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("refresh stable conversation mapping");

    alice
        .orchestrator
        .swap_members(
            STABLE_CONVERSATION_ID,
            std::slice::from_ref(&bob_did),
            std::slice::from_ref(&charlie_did),
        )
        .await
        .expect("swap through stable conversation id");

    let state = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(&group_id)
        .cloned()
        .expect("current group state");
    assert!(!state.members.contains(&bob_did));
    assert!(state.members.contains(&charlie_did));
    assert_eq!(state.conversation_id, STABLE_CONVERSATION_ID);
}
