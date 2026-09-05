//! A delayed but valid Welcome must catch up before restoring a removed device.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation, ConversationState, MLSStorageBackend, MlsCryptoContext,
};
use catbird_mls::KeyPackageData;
use chrono::{SecondsFormat, TimeZone, Utc};
use e2e_harness::TestWorld;
use openmls::prelude::{
    tls_codec::DeserializeBytes as _, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion,
};
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

async fn delayed_welcome(advance: bool) -> (TestWorld, String, Vec<u8>, Vec<u8>) {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world
        .add_client_with_did("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await;
    world
        .add_client_with_did("Charlie", "did:plc:cccccccccccccccccccccccc")
        .await;
    for name in ["Alice", "Bob", "Charlie"] {
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    let created = alice
        .orchestrator
        .create_group(
            "Leave test",
            Some(&[
                "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
                "did:plc:cccccccccccccccccccccccc".into(),
            ]),
            None,
        )
        .await
        .unwrap();
    let cid = created.conversation_id;
    let group = hex::decode(created.group_id).unwrap();
    let mut bob_package = None;
    let mut bob_welcome = None;
    for name in ["Charlie", "Bob"] {
        let client = world.client(name);
        let identity = format!(
            "{}#{}",
            client.did,
            client.orchestrator.require_actor_device_id().await.unwrap()
        );
        let package = client
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
                    data: package.key_package_data.clone(),
                }],
            )
            .unwrap();
        alice
            .orchestrator
            .mls_context()
            .merge_pending_commit(group.clone())
            .unwrap();
        if name == "Charlie" {
            client
                .orchestrator
                .mls_context()
                .process_welcome(added.welcome_data, identity.into_bytes(), None)
                .unwrap();
        } else {
            world
                .client("Charlie")
                .orchestrator
                .mls_context()
                .process_commit(group.clone(), added.commit_data)
                .unwrap();
            bob_package = Some(package);
            bob_welcome = Some(added.welcome_data);
        }
    }
    let package = bob_package.unwrap();
    let welcome = bob_welcome.unwrap();
    let provider = openmls_libcrux_crypto::Provider::new().unwrap();
    let MlsMessageBodyIn::KeyPackage(key_package) =
        MlsMessageIn::tls_deserialize_exact_bytes(&package.key_package_data)
            .unwrap()
            .extract()
    else {
        panic!("native artifact must be a KeyPackage message");
    };
    let key_package = key_package
        .validate(provider.crypto(), ProtocolVersion::default())
        .unwrap();
    assert_eq!(
        key_package.hash_ref(provider.crypto()).unwrap().as_slice(),
        package.hash_ref
    );
    let expires_at = Utc
        .timestamp_opt(key_package.life_time().not_after() as i64, 0)
        .single()
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut projection = alice
        .storage
        .get_group_state(&hex::encode(&group))
        .await
        .unwrap()
        .unwrap();
    projection.epoch = 2;
    projection.members = alice
        .orchestrator
        .mls_context()
        .group_member_identities(group.clone())
        .unwrap()
        .into_iter()
        .map(|id| String::from_utf8(id).unwrap())
        .collect();
    alice.storage.set_group_state(&projection).await.unwrap();
    for name in ["Bob", "Charlie"] {
        let client = world.client(name);
        client
            .storage
            .ensure_conversation_exists(&client.did, &cid, &hex::encode(&group))
            .await
            .unwrap();
        client.storage.set_group_state(&projection).await.unwrap();
    }
    let requests = world.delivery_service().submitted_prepared_requests();
    let create = requests
        .iter()
        .find(|r| r.operation == CanonicalOperation::CreateConversation)
        .unwrap();
    let create: Value = serde_json::from_slice(create.body.as_deref().unwrap()).unwrap();
    let mut snapshot = create["signedRequest"]["body"]["metadataSnapshot"].clone();
    let coords = json!({"conversationId":cid,"groupId":STANDARD.encode(&group),"generation":3,"stateVersion":17,"epoch":2,"lifecycle":"active","confirmationTag":STANDARD.encode(alice.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),"groupContextHash":STANDARD.encode(alice.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap())});
    let metadata = catbird_mls::metadata::GroupMetadataV1 {
        version: 1,
        title: "Leave test".into(),
        description: "Keep this title encrypted".into(),
        avatar_blob_locator: None,
        avatar_content_type: None,
    };
    let key: [u8; 32] = alice
        .orchestrator
        .mls_context()
        .export_metadata_key(group.clone(), 2)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = [7; 12];
    let cipher = catbird_mls::metadata::encrypt_metadata_snapshot_with_nonce(
        &key, &group, 2, 1, &nonce, &metadata,
    )
    .unwrap();
    snapshot["coordinate"] = json!({"conversationId":STANDARD.encode(uuid::Uuid::parse_str(&cid).unwrap().as_bytes()),"generation":3,"epoch":2,"groupId":coords["groupId"],"confirmationTag":coords["confirmationTag"],"groupContextHash":coords["groupContextHash"]});
    snapshot["nonce"] = json!(STANDARD.encode(nonce));
    snapshot["ciphertext"] = json!(STANDARD.encode(&cipher));
    snapshot["ciphertextSize"] = json!(cipher.len());
    snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&cipher)));
    let mut leaves = Vec::new();
    for name in ["Alice", "Charlie", "Bob"] {
        let c = world.client(name);
        leaves.push(json!({"userDid":c.did,"deviceId":c.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":leaves.len(),"deviceStatus":"active"}));
    }
    let state = json!({"conversationKind":"group","snapshotSeq":17,"coordinates":coords,"leaves":leaves,"participants":[{"userDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","role":"admin","status":"active","leafCount":1},{"userDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","role":"member","status":"active","leafCount":1},{"userDid":"did:plc:cccccccccccccccccccccccc","role":"member","status":"active","leafCount":1}],"metadataSnapshot":snapshot});
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state.clone());
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&cid, 2);
    world
        .client("Bob")
        .storage
        .set_conversation_state(&cid, ConversationState::DeviceRemoved)
        .await
        .unwrap();
    world
        .client("Bob")
        .storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "saved-before-welcome".into(),
            conversation_id: cid.clone(),
            sender_did: world.client("Bob").did.clone(),
            text: "Keep my saved history".into(),
            timestamp: chrono::Utc::now(),
            epoch: 0,
            sequence_number: 0,
            is_own: true,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    world.delivery_service().set_welcome_delivery_for_test(json!({
        "welcomeId":uuid::Uuid::new_v4().to_string(), "conversationId":cid, "transitionSeq":17,
        "coordinates":coords, "status":"pending", "opaqueWelcome":STANDARD.encode(&welcome),
        "sha256":STANDARD.encode(Sha256::digest(&welcome)),
        "recipientDid":world.client("Bob").did,
        "recipientDeviceId":world.client("Bob").orchestrator.require_actor_device_id().await.unwrap(),
        "provenance":{"recoveryRequestId":uuid::Uuid::new_v4().to_string(), "keyPackageRef":STANDARD.encode(&package.hash_ref)},
        "expiresAt":expires_at,
    }));
    if advance {
        world
            .client("Charlie")
            .orchestrator
            .leave_conversation(&cid)
            .await
            .unwrap();
        assert!(world
            .client("Alice")
            .orchestrator
            .fulfill_pending_group_leave(&cid)
            .await
            .unwrap());
    }
    (world, cid, group, welcome)
}

async fn assert_usable(world: &TestWorld, cid: &str, group: &[u8], epoch: u64) {
    let bob = world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(group.to_vec())
            .unwrap(),
        epoch
    );
    assert_eq!(
        bob.storage.get_conversation_state(cid).await.unwrap(),
        Some(ConversationState::Active)
    );
    assert!(!bob.storage.needs_rejoin(cid).await.unwrap());
    assert!(bob
        .storage
        .message_exists("saved-before-welcome")
        .await
        .unwrap());
    let ciphertext = world
        .client("Alice")
        .orchestrator
        .mls_context()
        .encrypt_message(group.to_vec(), b"Messages after delayed Welcome".to_vec())
        .unwrap()
        .ciphertext;
    let message = bob
        .orchestrator
        .mls_context()
        .decrypt_message(group.to_vec(), ciphertext)
        .unwrap();
    assert_eq!(message.plaintext, b"Messages after delayed Welcome");
}

fn assert_no_membership_mutation(world: &TestWorld, since: usize) {
    assert!(
        !world.delivery_service().submitted_prepared_requests()[since..]
            .iter()
            .any(|request| {
                matches!(
                    request.operation,
                    CanonicalOperation::RequestLeafRecovery
                        | CanonicalOperation::RequestReset
                        | CanonicalOperation::ActivateReset
                        | CanonicalOperation::SubmitTransition
                        | CanonicalOperation::AcceptConversation
                )
            }),
        "adopting an authorized Welcome must not create another membership transition"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn current_welcome_restores_removed_device_and_is_idempotent() {
    let (world, cid, group, welcome) = delayed_welcome(false).await;
    let baseline = world.delivery_service().submitted_prepared_requests().len();
    let bob = world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .join_or_rejoin_from_available_welcome(&cid, welcome.clone())
            .await
            .unwrap(),
        2
    );
    assert_usable(&world, &cid, &group, 2).await;
    assert_eq!(
        bob.orchestrator
            .join_or_rejoin_from_available_welcome(&cid, welcome)
            .await
            .unwrap(),
        2,
        "retry must reuse the verified joined group after its KeyPackage was consumed"
    );
    assert_no_membership_mutation(&world, baseline);
}

#[tokio::test(flavor = "multi_thread")]
async fn delayed_welcome_catches_up_before_restoring_removed_device() {
    let (world, cid, group, welcome) = delayed_welcome(true).await;
    let baseline = world.delivery_service().submitted_prepared_requests().len();
    let bob = world.client("Bob");
    assert!(bob
        .orchestrator
        .mls_context()
        .get_epoch(group.clone())
        .is_err());
    assert_eq!(
        bob.orchestrator
            .join_or_rejoin_from_available_welcome(&cid, welcome)
            .await
            .unwrap(),
        3
    );
    assert_usable(&world, &cid, &group, 3).await;
    assert_no_membership_mutation(&world, baseline);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_welcome_catchup_preserves_terminal_state_and_reuses_native_join_on_retry() {
    let (mut world, cid, group, welcome) = delayed_welcome(true).await;
    let baseline = world.delivery_service().submitted_prepared_requests().len();
    world.delivery_service().fail_next_get_entries();
    let bob = world.client("Bob");
    let error = bob
        .orchestrator
        .join_or_rejoin_from_available_welcome(&cid, welcome.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected unavailable entry proof"),
        "original read error lost: {error}"
    );
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        2,
        "verified Welcome state must survive a transient catch-up failure"
    );
    assert_eq!(
        bob.storage.get_conversation_state(&cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved),
        "the device remains unsendable until it catches up to the authorized coordinate"
    );
    world.restart_client("Bob").await;
    assert_eq!(
        world
            .client("Bob")
            .orchestrator
            .join_or_rejoin_from_available_welcome(&cid, welcome)
            .await
            .unwrap(),
        3,
        "restart must resume from native state instead of consuming the same Welcome again"
    );
    assert_usable(&world, &cid, &group, 3).await;
    assert_no_membership_mutation(&world, baseline);
}
