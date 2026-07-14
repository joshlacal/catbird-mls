#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    CredentialStore, GroupState, IncomingEnvelope, MLSAPIClient, MLSStorageBackend,
};
use catbird_mls::GroupConfig;
use chrono::Utc;
use e2e_harness::TestWorld;
use sha2::{Digest, Sha256};

const STABLE_CONVERSATION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

    // The server has already advanced its projected mapping to G2, but this
    // client has no G2. Its group-state cache and MLSContext still contain G1.
    let absent_server_group_id = "22".repeat(32);
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
    assert!(!alice
        .orchestrator
        .mls_context()
        .group_exists(hex::decode(&absent_server_group_id).expect("G2 group id")));
    assert!(alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .values()
        .any(|state| state.conversation_id == STABLE_CONVERSATION_ID
            && state.group_id == old_group_id));

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
        alice
            .orchestrator
            .mls_context()
            .group_exists(target_group_bytes),
        "successful force rejoin must preserve the newly joined GroupInfo target"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_pending_target_overrides_stale_live_and_durable_conversation_views() {
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
    alice
        .orchestrator
        .send_message(&conversation_id, "live reset target")
        .await
        .expect("live resolver must select reset target");
    assert_eq!(
        world.delivery_service().message_count(&conversation_id),
        before + 1
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

    alice
        .orchestrator
        .send_message(&conversation_id, "durable reset target")
        .await
        .expect("persisted ResetPending target must override stale durable view");
    assert_eq!(
        world.delivery_service().message_count(&conversation_id),
        before + 2
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
    alice.storage.fail_next_set_conversation_state();

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

    storage
        .clear_reset_pending(conversation_id, Some(1))
        .await
        .expect("stale generation clear is a no-op");
    assert_eq!(
        storage
            .get_persisted_reset_pending(conversation_id)
            .expect("generation 2 must survive stale clear")
            .reset_generation,
        2
    );

    storage
        .clear_reset_pending(conversation_id, None)
        .await
        .expect("rollback clear cannot erase committed state");
    assert!(storage
        .get_persisted_reset_pending(conversation_id)
        .is_some());

    storage
        .clear_reset_pending(conversation_id, Some(2))
        .await
        .expect("exact generation clear");
    assert!(storage
        .get_persisted_reset_pending(conversation_id)
        .is_none());
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
