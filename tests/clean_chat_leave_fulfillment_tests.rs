//! Real OpenMLS multi-device removal through the signed v2 leave lifecycle.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation, MLSStorageBackend, MlsCryptoContext,
};
use catbird_mls::{KeyPackageData, ProcessedContent};
use e2e_harness::TestWorld;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

async fn setup() -> (TestWorld, String, Vec<u8>, Value) {
    setup_with_inventory_padding(0).await
}

async fn setup_with_inventory_padding(padding: usize) -> (TestWorld, String, Vec<u8>, Value) {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world
        .add_client_with_did("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await;
    world
        .add_client_with_did("Bob2", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
        .await;
    world
        .add_client_with_did("Charlie", "did:plc:cccccccccccccccccccccccc")
        .await;
    for name in ["Alice", "Bob", "Bob2", "Charlie"] {
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    for _ in 0..padding {
        world
            .delivery_service()
            .set_next_create_conversation_id(&uuid::Uuid::new_v4().to_string());
        alice
            .orchestrator
            .api_client()
            .create_conversation(
                &hex::encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes())),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }
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
    let mut packages = Vec::new();
    for name in ["Bob", "Bob2", "Charlie"] {
        let c = world.client(name);
        let identity = format!(
            "{}#{}",
            c.did,
            c.orchestrator.require_actor_device_id().await.unwrap()
        );
        packages.push(KeyPackageData {
            data: c
                .orchestrator
                .mls_context()
                .create_key_package(identity.as_bytes().to_vec())
                .unwrap()
                .key_package_data,
        });
    }
    let added = alice
        .orchestrator
        .mls_context()
        .add_members(group.clone(), packages)
        .unwrap();
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group.clone())
        .unwrap();
    for name in ["Bob", "Bob2", "Charlie"] {
        let c = world.client(name);
        let identity = format!(
            "{}#{}",
            c.did,
            c.orchestrator.require_actor_device_id().await.unwrap()
        );
        c.orchestrator
            .mls_context()
            .process_welcome(
                added.welcome_data.clone(),
                identity.as_bytes().to_vec(),
                None,
            )
            .unwrap();
    }
    let mut projection = alice
        .storage
        .get_group_state(&hex::encode(&group))
        .await
        .unwrap()
        .unwrap();
    projection.epoch = 1;
    projection.members = alice
        .orchestrator
        .mls_context()
        .group_member_identities(group.clone())
        .unwrap()
        .into_iter()
        .map(|id| String::from_utf8(id).unwrap())
        .collect();
    alice.storage.set_group_state(&projection).await.unwrap();
    for name in ["Bob", "Bob2", "Charlie"] {
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
    let coords = json!({"conversationId":cid,"groupId":STANDARD.encode(&group),"generation":3,"stateVersion":17,"epoch":1,"lifecycle":"active","confirmationTag":STANDARD.encode(alice.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),"groupContextHash":STANDARD.encode(alice.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap())});
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
        .export_metadata_key(group.clone(), 1)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = [7; 12];
    let cipher = catbird_mls::metadata::encrypt_metadata_snapshot_with_nonce(
        &key, &group, 1, 1, &nonce, &metadata,
    )
    .unwrap();
    snapshot["coordinate"] = json!({"conversationId":STANDARD.encode(uuid::Uuid::parse_str(&cid).unwrap().as_bytes()),"generation":3,"epoch":1,"groupId":coords["groupId"],"confirmationTag":coords["confirmationTag"],"groupContextHash":coords["groupContextHash"]});
    snapshot["nonce"] = json!(STANDARD.encode(nonce));
    snapshot["ciphertext"] = json!(STANDARD.encode(&cipher));
    snapshot["ciphertextSize"] = json!(cipher.len());
    snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&cipher)));
    let mut leaves = Vec::new();
    for name in ["Alice", "Bob", "Bob2", "Charlie"] {
        let c = world.client(name);
        leaves.push(json!({"userDid":c.did,"deviceId":c.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":leaves.len(),"deviceStatus":"active"}));
    }
    let state = json!({"conversationKind":"group","snapshotSeq":17,"coordinates":coords,"leaves":leaves,"participants":[{"userDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","role":"admin","status":"active","leafCount":1},{"userDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","role":"member","status":"active","leafCount":2},{"userDid":"did:plc:cccccccccccccccccccccccc","role":"member","status":"active","leafCount":1}],"metadataSnapshot":snapshot});
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state.clone());
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&cid, 1);
    world
        .client("Bob")
        .orchestrator
        .leave_conversation(&cid)
        .await
        .unwrap();
    (world, cid, group, state)
}

fn fulfillment(world: &TestWorld) -> Value {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .filter_map(|r| serde_json::from_slice::<Value>(r.body.as_deref()?).ok())
        .map(|v| v["signedRequest"]["body"].clone())
        .find(|v| v["$type"] == "blue.catbird.chat.defs#leaveCommitFulfillmentBody")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn leave_removes_both_devices_preserves_generation_and_converges_remaining_member() {
    let (world, cid, group, state) = setup().await;
    assert!(
        !world
            .client("Bob2")
            .orchestrator
            .fulfill_pending_group_leave(&cid)
            .await
            .unwrap(),
        "a sibling device cannot fulfill its own account leave"
    );
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .fulfill_pending_group_leaves()
            .await
            .unwrap(),
        1
    );
    let body = fulfillment(&world);
    assert_eq!(body["prior"], state["coordinates"]);
    for coordinate in [
        &body["next"],
        &body["aad"],
        &body["metadataSnapshot"]["coordinate"],
    ] {
        assert_eq!(coordinate["generation"], 3);
    }
    assert_eq!(body["next"]["stateVersion"], 18);
    assert_eq!(body["next"]["epoch"], 2);
    assert_eq!(body["manifest"]["leafChanges"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["metadataSnapshot"]["authorProof"],
        state["metadataSnapshot"]["authorProof"]
    );
    assert_eq!(body["metadataSnapshot"]["metadataVersion"], 1);
    let commit = STANDARD
        .decode(body["commit"]["bytes"].as_str().unwrap())
        .unwrap();
    let alice = world.client("Alice");
    let own_echo = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: cid.clone(),
        sender_did: alice.did.clone(),
        ciphertext: commit.clone(),
        timestamp: chrono::Utc::now(),
        server_epoch: Some(1),
        server_sequence: None,
        server_message_id: body["transitionId"].as_str().map(str::to_owned),
    };
    assert!(alice
        .orchestrator
        .process_incoming(&own_echo)
        .await
        .unwrap()
        .is_none());
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
    let charlie = world.client("Charlie");
    assert!(matches!(
        charlie
            .orchestrator
            .mls_context()
            .process_message(group.clone(), commit.clone())
            .unwrap(),
        ProcessedContent::StagedCommit { new_epoch: 2, .. }
    ));
    charlie
        .orchestrator
        .mls_context()
        .merge_incoming_commit(group.clone(), 2)
        .unwrap();
    let alice = world.client("Alice");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_confirmation_tag(group.clone())
            .unwrap(),
        charlie
            .orchestrator
            .mls_context()
            .get_confirmation_tag(group.clone())
            .unwrap()
    );
    for name in ["Alice", "Charlie"] {
        let c = world.client(name);
        let identities = c
            .orchestrator
            .mls_context()
            .group_member_identities(group.clone())
            .unwrap();
        assert_eq!(identities.len(), 2);
        assert!(identities.iter().all(
            |id| !String::from_utf8_lossy(id).starts_with("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb#")
        ));
    }
    let key: [u8; 32] = charlie
        .orchestrator
        .mls_context()
        .export_metadata_key(group.clone(), 2)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = STANDARD
        .decode(body["metadataSnapshot"]["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let cipher = STANDARD
        .decode(body["metadataSnapshot"]["ciphertext"].as_str().unwrap())
        .unwrap();
    let metadata =
        catbird_mls::metadata::decrypt_metadata_snapshot(&key, &group, 2, 1, &nonce, &cipher)
            .unwrap();
    assert_eq!(metadata.title, "Leave test");
    let bob_key: [u8; 32] = world
        .client("Bob")
        .orchestrator
        .mls_context()
        .export_metadata_key(group.clone(), 1)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(catbird_mls::metadata::decrypt_metadata_snapshot(
        &bob_key, &group, 2, 1, &nonce, &cipher
    )
    .is_err());
    let application = alice
        .orchestrator
        .mls_context()
        .encrypt_message(group.clone(), b"Still chatting after Bob left".to_vec())
        .unwrap();
    assert!(matches!(
        charlie.orchestrator.mls_context().process_message(group.clone(), application.ciphertext.clone()).unwrap(),
        ProcessedContent::ApplicationMessage { plaintext, .. } if plaintext == b"Still chatting after Bob left"
    ));
    for name in ["Bob", "Bob2"] {
        assert!(world
            .client(name)
            .orchestrator
            .mls_context()
            .process_message(group.clone(), application.ciphertext.clone())
            .is_err());
    }
    assert_eq!(
        alice
            .storage
            .get_group_state(&hex::encode(&group))
            .await
            .unwrap()
            .unwrap()
            .epoch,
        2
    );
    assert_eq!(
        alice
            .orchestrator
            .fulfill_pending_group_leaves()
            .await
            .unwrap(),
        0,
        "terminal request never repeats"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn generic_forbidden_preserves_pending_until_proven_expired_then_fresh_retry_succeeds() {
    let (world, cid, group, _) = setup().await;
    let alice = world.client("Alice");
    let group_hex = hex::encode(&group);
    alice
        .storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "history-before-uncertain-leave".into(),
            conversation_id: cid.clone(),
            sender_did: alice.did.clone(),
            text: "Keep history through an uncertain leave".into(),
            timestamp: chrono::Utc::now(),
            epoch: 1,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    world.delivery_service().set_leave_fulfillment_responses(
        3,
        403,
        json!({"error":"NotAuthorized"}),
    );
    assert!(alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .is_err());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .group_member_identities(group.clone())
            .unwrap()
            .len(),
        4
    );
    let pending = alice
        .orchestrator
        .mls_context()
        .get_prepared_control(&group_hex)
        .unwrap()
        .expect("generic 403 cannot prove that an internal transport retry was never accepted");
    assert!(alice
        .orchestrator
        .mls_context()
        .export_metadata_key_from_pending(group.clone(), 2)
        .is_ok());
    assert!(alice
        .storage
        .message_exists("history-before-uncertain-leave")
        .await
        .unwrap());
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());

    // This response is emitted only after exact operation arbitration. With a
    // fresh unchanged coordinate it proves this signed operation never landed,
    // while its original durable leave consent is still current and unexpired.
    world.delivery_service().set_leave_fulfillment_responses(
        1,
        400,
        json!({"error":"SignedOperationExpired"}),
    );
    let error = alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("terminal unaccepted control"),
        "{error}"
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .get_prepared_control(&group_hex)
        .unwrap()
        .is_none());
    assert!(alice
        .orchestrator
        .mls_context()
        .export_metadata_key_from_pending(group.clone(), 2)
        .is_err());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    assert!(alice
        .storage
        .message_exists("history-before-uncertain-leave")
        .await
        .unwrap());
    assert!(alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    assert_eq!(
        alice.orchestrator.mls_context().get_epoch(group).unwrap(),
        2
    );
    assert!(alice
        .storage
        .message_exists("history-before-uncertain-leave")
        .await
        .unwrap());
    let bodies: Vec<_> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|request| request.operation == CanonicalOperation::SubmitTransition)
        .map(|request| request.body.unwrap())
        .collect();
    assert_eq!(bodies.len(), 5);
    assert!(bodies[..4].iter().all(|body| body == &pending.request_body));
    assert_ne!(
        bodies[4], pending.request_body,
        "fresh signing is allowed only after retained nonacceptance proof"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_consent_and_last_admin_are_never_fulfilled() {
    let (world, cid, group, mut state) = setup().await;
    state["coordinates"]["stateVersion"] = json!(18);
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state.clone());
    let alice = world.client("Alice");
    assert!(!alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    state["coordinates"]["stateVersion"] = json!(17);
    state["participants"][0]["role"] = json!("member");
    state["participants"][1]["role"] = json!("admin");
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state);
    assert!(!alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    assert_eq!(
        alice.orchestrator.mls_context().get_epoch(group).unwrap(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_success_ack_preserves_pending_removal_for_reconciliation() {
    let (world, cid, group, _) = setup().await;
    world.delivery_service().set_leave_fulfillment_responses(
        3,
        200,
        json!({"result":{"applied":true}}),
    );
    let alice = world.client("Alice");
    assert!(alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .is_err());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    assert!(
        alice
            .orchestrator
            .mls_context()
            .export_metadata_key_from_pending(group, 2)
            .is_ok(),
        "unknown outcome must retain pending MLS state"
    );
    assert!(
        !alice.storage.needs_rejoin(&cid).await.unwrap(),
        "unknown pending Commit must not trigger blind replacement recovery"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn discovers_pending_leave_after_first_inventory_page() {
    let (world, cid, group, _) = setup_with_inventory_padding(100).await;
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .fulfill_pending_group_leaves()
            .await
            .unwrap(),
        1
    );
    assert_eq!(fulfillment(&world)["prior"]["conversationId"], cid);
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(group)
            .unwrap(),
        2
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_leave_with_lost_response_retries_identically_then_processes_own_echo() {
    let (world, cid, group, _) = setup().await;
    world
        .delivery_service()
        .lose_next_leave_fulfillment_response();
    let alice = world.client("Alice");
    assert!(alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    let sent: Vec<_> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .collect();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].body, sent[1].body,
        "retry must preserve raw signed request bytes"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        2
    );
    let body = fulfillment(&world);
    let envelope = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: cid.clone(),
        sender_did: alice.did.clone(),
        ciphertext: STANDARD
            .decode(body["commit"]["bytes"].as_str().unwrap())
            .unwrap(),
        timestamp: chrono::Utc::now(),
        server_epoch: Some(1),
        server_sequence: None,
        server_message_id: body["transitionId"].as_str().map(str::to_owned),
    };
    assert!(alice
        .orchestrator
        .process_incoming(&envelope)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        alice.orchestrator.mls_context().get_epoch(group).unwrap(),
        2
    );
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_lost_ack_retries_journaled_request_without_discarding_pending_commit() {
    let (world, cid, group, _) = setup().await;
    world.delivery_service().lose_leave_fulfillment_responses(2);
    let alice = world.client("Alice");
    assert!(alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    assert_eq!(
        alice.orchestrator.mls_context().get_epoch(group).unwrap(),
        2
    );
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn requester_devices_consume_authenticated_removal_and_preserve_history() {
    let (world, cid, group, _) = setup().await;
    assert!(world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    let body = fulfillment(&world);
    let ciphertext = STANDARD
        .decode(body["commit"]["bytes"].as_str().unwrap())
        .unwrap();
    for name in ["Bob", "Bob2"] {
        let client = world.client(name);
        client
            .storage
            .store_message(&catbird_mls::orchestrator::Message {
                id: "saved-before-leave".into(),
                conversation_id: cid.clone(),
                sender_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
                text: "Keep this earlier conversation".into(),
                timestamp: chrono::Utc::now(),
                epoch: 1,
                sequence_number: 1,
                is_own: false,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .unwrap();
        let envelope = catbird_mls::orchestrator::IncomingEnvelope {
            conversation_id: cid.clone(),
            sender_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ciphertext: ciphertext.clone(),
            timestamp: chrono::Utc::now(),
            server_epoch: Some(1),
            server_sequence: None,
            server_message_id: body["transitionId"].as_str().map(str::to_owned),
        };
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.orchestrator.process_incoming(&envelope)
        )
        .await
        .expect("removed-device consumption must not deadlock")
        .unwrap()
        .is_none());
        assert_eq!(
            serde_json::to_value(
                client
                    .storage
                    .get_conversation_state(&cid)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            json!("DeviceRemoved")
        );
        assert_eq!(
            serde_json::to_value(
                client
                    .orchestrator
                    .conversation_states()
                    .lock()
                    .await
                    .get(&cid)
                    .unwrap()
            )
            .unwrap(),
            json!("DeviceRemoved")
        );
        assert!(
            client
                .storage
                .get_conversation(&client.did, &cid)
                .await
                .unwrap()
                .is_some(),
            "device removal preserves conversation history"
        );
        assert_eq!(
            client
                .storage
                .get_group_state(&hex::encode(&group))
                .await
                .unwrap()
                .unwrap()
                .epoch,
            1,
            "removed device must never fabricate a successor projection"
        );
        assert_eq!(
            client.storage.get_messages(&cid, 10, None).await.unwrap()[0].text,
            "Keep this earlier conversation"
        );
        assert!(!client.storage.needs_rejoin(&cid).await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_leave_replays_exact_journal_after_native_database_restart() {
    let (mut world, cid, group, _) = setup().await;
    world.delivery_service().lose_leave_fulfillment_responses(3);
    world.delivery_service().fail_next_get_entries();
    assert!(world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .is_err());
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    assert!(world
        .client("Alice")
        .orchestrator
        .mls_context()
        .export_metadata_key_from_pending(group.clone(), 2)
        .is_ok());
    world.restart_client("Alice").await;
    world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap();
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        2
    );
    let sent: Vec<_> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .collect();
    assert_eq!(sent.len(), 4);
    assert!(
        sent.iter().all(|request| request.body == sent[0].body),
        "restart must retransmit original raw signed body"
    );
    assert_eq!(
        world
            .client("Alice")
            .storage
            .get_group_state(&hex::encode(&group))
            .await
            .unwrap()
            .unwrap()
            .epoch,
        2
    );
    assert!(!world
        .client("Alice")
        .storage
        .needs_rejoin(&cid)
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn requester_removal_receipt_retries_projection_after_failure_and_native_restart() {
    let (mut world, cid, group, _) = setup().await;
    assert!(world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    let body = fulfillment(&world);
    let ciphertext = STANDARD
        .decode(body["commit"]["bytes"].as_str().unwrap())
        .unwrap();
    let envelope = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: cid.clone(),
        sender_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        ciphertext: ciphertext.clone(),
        timestamp: chrono::Utc::now(),
        server_epoch: Some(1),
        server_sequence: None,
        server_message_id: body["transitionId"].as_str().map(str::to_owned),
    };
    let bob = world.client("Bob");
    bob.storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "saved-before-leave".into(),
            conversation_id: cid.clone(),
            sender_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            text: "History survives retry and restart".into(),
            timestamp: chrono::Utc::now(),
            epoch: 1,
            sequence_number: 1,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    bob.storage.fail_next_set_conversation_state();
    assert!(bob.orchestrator.process_incoming(&envelope).await.is_err());
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .verified_incoming_removal(group.clone(), ciphertext.clone())
            .unwrap(),
        Some(2),
        "native removal must be durable before app projection"
    );
    world.restart_client("Bob").await;
    let bob = world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .verified_incoming_removal(group.clone(), ciphertext.clone())
            .unwrap(),
        Some(2)
    );
    let mut different = envelope.clone();
    if let Some(byte) = different.ciphertext.last_mut() {
        *byte ^= 1;
    }
    different.server_message_id = Some(uuid::Uuid::new_v4().to_string());
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .verified_incoming_removal(group.clone(), different.ciphertext.clone())
            .unwrap(),
        None
    );
    assert!(
        bob.orchestrator.process_incoming(&different).await.is_err(),
        "different ciphertext cannot reuse the removal receipt"
    );
    assert!(bob
        .orchestrator
        .process_incoming(&envelope)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        serde_json::to_value(
            bob.storage
                .get_conversation_state(&cid)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        json!("DeviceRemoved")
    );
    assert_eq!(
        bob.storage
            .get_group_state(&hex::encode(&group))
            .await
            .unwrap()
            .unwrap()
            .epoch,
        1
    );
    assert_eq!(
        bob.storage.get_messages(&cid, 10, None).await.unwrap()[0].text,
        "History survives retry and restart"
    );
    assert!(!bob.storage.needs_rejoin(&cid).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_inventory_finishes_leave_once_and_never_reenrolls_removed_devices() {
    let (world, cid, group, _) = setup().await;
    assert!(world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    for name in ["Bob", "Bob2"] {
        let client = world.client(name);
        assert!(client
            .orchestrator
            .reconcile_terminal_conversation(&cid)
            .await
            .unwrap());
        assert!(client
            .orchestrator
            .reconcile_terminal_conversation(&cid)
            .await
            .unwrap());
        let messages = client.storage.get_messages(&cid, 10, None).await.unwrap();
        assert_eq!(
            messages
                .iter()
                .filter(|m| m.text == "You left this conversation.")
                .count(),
            1,
            "repeated inventory must not duplicate the leave marker"
        );
        assert!(messages.iter().any(|m| m
            .payload_json
            .as_deref()
            .is_some_and(|json| json.contains("membership.left"))));
        assert_eq!(
            serde_json::to_value(
                client
                    .storage
                    .get_conversation_state(&cid)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            json!("DeviceRemoved")
        );
        let count_recovery = || {
            world
                .delivery_service()
                .submitted_prepared_requests()
                .iter()
                .filter(|request| {
                    matches!(
                        request.operation,
                        CanonicalOperation::RequestLeafRecovery
                            | CanonicalOperation::RequestReset
                            | CanonicalOperation::ActivateReset
                    )
                })
                .count()
        };
        let before = count_recovery();
        client.orchestrator.startup_reconcile().await.unwrap();
        client
            .orchestrator
            .run_deferred_recovery("removed-device regression")
            .await
            .unwrap();
        assert!(
            !client
                .orchestrator
                .ensure_conversation_ready(&cid)
                .await
                .unwrap()
                .send_allowed
        );
        assert!(client
            .orchestrator
            .send_message(&cid, "This must stay unsent")
            .await
            .is_err());
        assert_eq!(
            count_recovery(),
            before,
            "startup and readiness must not reenroll a device after account leave"
        );
        assert!(client
            .storage
            .get_conversation(&client.did, &cid)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            client
                .storage
                .get_group_state(&hex::encode(&group))
                .await
                .unwrap()
                .unwrap()
                .epoch,
            1
        );
        assert!(!client.storage.needs_rejoin(&cid).await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn losing_fulfiller_proves_competing_commit_after_restart_then_catches_up() {
    let (mut world, cid, group, _) = setup().await;
    world.delivery_service().set_leave_fulfillment_responses(
        3,
        503,
        json!({"error":"TemporarilyUnavailable"}),
    );
    assert!(world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .is_err());
    assert!(world
        .client("Alice")
        .orchestrator
        .mls_context()
        .get_prepared_control(&hex::encode(&group))
        .unwrap()
        .is_some());
    assert!(world
        .client("Charlie")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap());
    world.restart_client("Alice").await;
    if let Err(error) = world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
    {
        assert!(error.to_string().contains("superseded"), "{error}");
    }
    let alice = world.client("Alice");
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_prepared_control(&hex::encode(&group))
            .unwrap()
            .is_none(),
        "fresh contiguous entry proof must resolve losing pending operation"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    let winner = world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .filter_map(|r| serde_json::from_slice::<Value>(r.body.as_deref()?).ok())
        .map(|v| v["signedRequest"]["body"].clone())
        .find(|v| v["actorDid"] == "did:plc:cccccccccccccccccccccccc")
        .unwrap();
    let envelope = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: cid.clone(),
        sender_did: "did:plc:cccccccccccccccccccccccc".into(),
        ciphertext: STANDARD
            .decode(winner["commit"]["bytes"].as_str().unwrap())
            .unwrap(),
        timestamp: chrono::Utc::now(),
        server_epoch: Some(1),
        server_sequence: None,
        server_message_id: winner["transitionId"].as_str().map(str::to_owned),
    };
    assert!(alice
        .orchestrator
        .process_incoming(&envelope)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        2
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_confirmation_tag(group.clone())
            .unwrap(),
        world
            .client("Charlie")
            .orchestrator
            .mls_context()
            .get_confirmation_tag(group)
            .unwrap()
    );
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn resumed_expired_leave_at_unchanged_coordinate_safely_clears_pending() {
    let (mut world, cid, group, _) = setup().await;
    let group_hex = hex::encode(&group);
    world
        .delivery_service()
        .fail_leave_fulfillment_submissions(3);
    assert!(world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .is_err());
    assert!(world
        .client("Alice")
        .orchestrator
        .mls_context()
        .get_prepared_control(&group_hex)
        .unwrap()
        .is_some());
    world.restart_client("Alice").await;
    world.delivery_service().set_leave_fulfillment_responses(
        1,
        409,
        json!({"error":"LeaveRequestExpired"}),
    );
    let alice = world.client("Alice");
    let error = alice
        .orchestrator
        .fulfill_pending_group_leave(&cid)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("terminal unaccepted control"),
        "{error}"
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .get_prepared_control(&group_hex)
        .unwrap()
        .is_none());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        1
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .group_member_identities(group.clone())
            .unwrap()
            .len(),
        4
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .export_metadata_key_from_pending(group.clone(), 2)
        .is_err());
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
    let bodies: Vec<_> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|request| request.operation == CanonicalOperation::SubmitTransition)
        .map(|request| request.body.unwrap())
        .collect();
    assert_eq!(bodies.len(), 4);
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "restart must replay byte-identical signed operation before discarding"
    );
}
