#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{IncomingEnvelope, MLSAPIClient, MLSStorageBackend};
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
