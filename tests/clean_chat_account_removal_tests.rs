//! Real OpenMLS account moderation: remove every device, then remove account policy.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    canonical_transport::{CanonicalOperation, PreparedRequest},
    MLSAPIClient, MLSStorageBackend, MlsCryptoContext,
};
use catbird_mls::{KeyPackageData, ProcessedContent};
use e2e_harness::TestWorld;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BOB_DID: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

async fn setup() -> (TestWorld, String, Vec<u8>, Value) {
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
    let created = alice
        .orchestrator
        .create_group(
            "Account removal test",
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
        title: "Account removal test".into(),
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
    for name in ["Bob", "Bob2"] {
        let client = world.client(name);
        client
            .storage
            .store_message(&catbird_mls::orchestrator::Message {
                id: "history-before-account-removal".into(),
                conversation_id: cid.clone(),
                sender_did: client.did.clone(),
                text: "History survives account removal".into(),
                timestamp: chrono::Utc::now(),
                epoch: 1,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .unwrap();
    }
    (world, cid, group, state)
}

fn transition_requests(world: &TestWorld, kind: &str) -> Vec<PreparedRequest> {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|request| request.operation == CanonicalOperation::SubmitTransition)
        .filter(|request| {
            serde_json::from_slice::<Value>(request.body.as_deref().unwrap()).unwrap()
                ["signedRequest"]["body"]["$type"]
                == kind
        })
        .collect()
}

fn removal_body(world: &TestWorld) -> Value {
    let requests = transition_requests(world, "blue.catbird.chat.defs#commitTransitionBody");
    serde_json::from_slice::<Value>(requests[0].body.as_deref().unwrap()).unwrap()["signedRequest"]
        ["body"]
        .clone()
}

async fn current_state(world: &TestWorld, cid: &str) -> Value {
    let alice = world.client("Alice");
    let device = alice.orchestrator.require_actor_device_id().await.unwrap();
    let reply = alice.orchestrator.api_client().submit_prepared_request(PreparedRequest {
        operation: CanonicalOperation::GetConversationState,
        method: "GET".into(),
        path: format!("/xrpc/blue.catbird.chat.getConversationState?conversationId={cid}&actorDeviceId={device}"),
        body: None,
    }).await.unwrap();
    assert_eq!(reply.status, 200);
    serde_json::from_slice::<Value>(&reply.body).unwrap()["state"].clone()
}

fn recovery_request_count(world: &TestWorld) -> usize {
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
}

async fn assert_remaining_members_converge(world: &TestWorld, cid: &str, group: &[u8]) {
    let body = removal_body(world);
    let envelope = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: cid.into(),
        sender_did: world.client("Alice").did.clone(),
        ciphertext: STANDARD
            .decode(body["commit"]["bytes"].as_str().unwrap())
            .unwrap(),
        timestamp: chrono::Utc::now(),
        server_epoch: Some(1),
        server_sequence: None,
        server_message_id: body["transitionId"].as_str().map(str::to_owned),
    };
    for name in ["Alice", "Charlie"] {
        let client = world.client(name);
        assert!(client
            .orchestrator
            .process_incoming(&envelope)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            client
                .orchestrator
                .mls_context()
                .get_epoch(group.to_vec())
                .unwrap(),
            2
        );
        let identities = client
            .orchestrator
            .mls_context()
            .group_member_identities(group.to_vec())
            .unwrap();
        assert_eq!(identities.len(), 2);
        assert!(identities
            .iter()
            .all(|identity| !String::from_utf8_lossy(identity).starts_with(BOB_DID)));
        assert!(!client.storage.needs_rejoin(cid).await.unwrap());
    }
    let alice = world.client("Alice");
    let charlie = world.client("Charlie");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_confirmation_tag(group.to_vec())
            .unwrap(),
        charlie
            .orchestrator
            .mls_context()
            .get_confirmation_tag(group.to_vec())
            .unwrap()
    );
    let application = alice
        .orchestrator
        .mls_context()
        .encrypt_message(group.to_vec(), b"Remaining members keep chatting".to_vec())
        .unwrap();
    assert!(
        matches!(charlie.orchestrator.mls_context().process_message(group.to_vec(), application.ciphertext.clone()).unwrap(),
        ProcessedContent::ApplicationMessage { plaintext, .. } if plaintext == b"Remaining members keep chatting")
    );
    for name in ["Bob", "Bob2"] {
        assert!(world
            .client(name)
            .orchestrator
            .mls_context()
            .process_message(group.to_vec(), application.ciphertext.clone())
            .is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn account_removal_revokes_all_devices_and_preserves_removed_device_history() {
    let (world, cid, group, before) = setup().await;
    world
        .client("Alice")
        .orchestrator
        .remove_accounts(&cid, &[BOB_DID.into()])
        .await
        .unwrap();
    let after = current_state(&world, &cid).await;
    assert!(!after["participants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|participant| participant["userDid"] == BOB_DID));
    assert!(!after["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .any(|leaf| leaf["userDid"] == BOB_DID));
    assert_eq!(after["coordinates"]["generation"], 3);
    assert_eq!(after["coordinates"]["stateVersion"], 19);
    assert_eq!(after["coordinates"]["epoch"], 2);
    let body = removal_body(&world);
    assert_eq!(body["prior"], before["coordinates"]);
    assert_eq!(body["manifest"]["participantChanges"], json!([]));
    assert_eq!(body["manifest"]["leafChanges"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["metadataSnapshot"]["authorProof"],
        before["metadataSnapshot"]["authorProof"]
    );
    assert_eq!(
        transition_requests(&world, "blue.catbird.chat.defs#commitTransitionBody").len(),
        1
    );
    assert_eq!(
        transition_requests(&world, "blue.catbird.chat.defs#policyTransitionBody").len(),
        1
    );
    assert_remaining_members_converge(&world, &cid, &group).await;
    for name in ["Bob", "Bob2"] {
        let client = world.client(name);
        assert!(client
            .orchestrator
            .reconcile_terminal_conversation(&cid)
            .await
            .unwrap());
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
        let prior = recovery_request_count(&world);
        client.orchestrator.startup_reconcile().await.unwrap();
        client
            .orchestrator
            .run_deferred_recovery("account removal regression")
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
            .send_message(&cid, "Do not reenroll a removed account")
            .await
            .is_err());
        assert_eq!(recovery_request_count(&world), prior);
        assert!(client
            .storage
            .message_exists("history-before-account-removal")
            .await
            .unwrap());
        assert_eq!(
            client.storage.get_messages(&cid, 10, None).await.unwrap()[0].text,
            "History survives account removal"
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
async fn partial_policy_failure_is_truthful_and_retry_removes_account_without_second_commit() {
    let (world, cid, group, _) = setup().await;
    assert!(
        world
            .client("Alice")
            .orchestrator
            .conversations()
            .lock()
            .await
            .get(&cid)
            .unwrap()
            .members
            .iter()
            .any(|member| member.did == BOB_DID),
        "fixture starts with Bob's account in the local roster"
    );
    world.delivery_service().fail_next_policy_removal();
    let alice = world.client("Alice");
    let error = alice
        .orchestrator
        .remove_accounts(&cid, &[BOB_DID.into()])
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("conversation_member_removal_pending:"),
        "{error}"
    );
    let intermediate = current_state(&world, &cid).await;
    let target = intermediate["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["userDid"] == BOB_DID)
        .unwrap();
    assert_eq!(target["status"], "active");
    assert_eq!(target["leafCount"], 0);
    assert!(
        alice
            .orchestrator
            .conversations()
            .lock()
            .await
            .get(&cid)
            .unwrap()
            .members
            .iter()
            .any(|member| member.did == BOB_DID),
        "local account roster must remain truthful until policy succeeds"
    );
    assert!(!intermediate["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .any(|leaf| leaf["userDid"] == BOB_DID));
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
            .group_member_identities(group.clone())
            .unwrap()
            .len(),
        2
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .get_prepared_control(&hex::encode(&group))
        .unwrap()
        .is_none());
    assert_eq!(
        transition_requests(&world, "blue.catbird.chat.defs#commitTransitionBody").len(),
        1
    );
    alice
        .orchestrator
        .remove_accounts(&cid, &[BOB_DID.into()])
        .await
        .unwrap();
    let after = current_state(&world, &cid).await;
    assert!(
        !alice
            .orchestrator
            .conversations()
            .lock()
            .await
            .get(&cid)
            .unwrap()
            .members
            .iter()
            .any(|member| member.did == BOB_DID),
        "confirmed account removal must update the local roster"
    );

    assert!(!after["participants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["userDid"] == BOB_DID));
    assert_eq!(
        transition_requests(&world, "blue.catbird.chat.defs#commitTransitionBody").len(),
        1
    );
    assert_eq!(
        transition_requests(&world, "blue.catbird.chat.defs#policyTransitionBody").len(),
        2
    );
    assert_eq!(
        alice.orchestrator.mls_context().get_epoch(group).unwrap(),
        2
    );
    for name in ["Bob", "Bob2"] {
        assert!(world
            .client(name)
            .storage
            .message_exists("history-before-account-removal")
            .await
            .unwrap());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_account_removal_with_lost_response_replays_identical_commit_before_policy() {
    let (world, cid, group, _) = setup().await;
    world
        .delivery_service()
        .lose_next_account_removal_response();
    let alice = world.client("Alice");
    alice
        .orchestrator
        .remove_accounts(&cid, &[BOB_DID.into()])
        .await
        .unwrap();
    let commits = transition_requests(&world, "blue.catbird.chat.defs#commitTransitionBody");
    assert_eq!(commits.len(), 2);
    assert_eq!(
        commits[0].body, commits[1].body,
        "lost ACK replay preserves the complete signed request bytes"
    );
    assert_eq!(
        transition_requests(&world, "blue.catbird.chat.defs#policyTransitionBody").len(),
        1
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group.clone())
            .unwrap(),
        2
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .get_prepared_control(&hex::encode(&group))
        .unwrap()
        .is_none());
    assert!(!current_state(&world, &cid).await["participants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["userDid"] == BOB_DID));
    assert_remaining_members_converge(&world, &cid, &group).await;
}
