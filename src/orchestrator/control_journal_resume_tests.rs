//! Offline resume must restore journal fences before the runtime becomes Ready.
use crate::orchestrator::{
    canonical_transport::CanonicalOperation, CommitKind, IncomingEnvelope, MLSOrchestrator,
    MLSStorageBackend, MlsCryptoContext, OrchestratorConfig,
};
use crate::recovery_e2e_harness::TestWorld;
use crate::KeyPackageData;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

async fn journal_fixture(ambiguous: bool) -> (TestWorld, String, Vec<u8>) {
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
    let mut packages = Vec::new();
    for name in ["Bob", "Charlie"] {
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
    for name in ["Bob", "Charlie"] {
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
    let coords = json!({"conversationId":cid,"groupId":STANDARD.encode(&group),"generation":3,"stateVersion":17,"epoch":1,"lifecycle":"active","confirmationTag":STANDARD.encode(alice.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),"groupContextHash":STANDARD.encode(alice.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap())});
    let metadata = crate::metadata::GroupMetadataV1 {
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
    let cipher = crate::metadata::encrypt_metadata_snapshot_with_nonce(
        &key, &group, 1, 1, &nonce, &metadata,
    )
    .unwrap();
    snapshot["coordinate"] = json!({"conversationId":STANDARD.encode(uuid::Uuid::parse_str(&cid).unwrap().as_bytes()),"generation":3,"epoch":1,"groupId":coords["groupId"],"confirmationTag":coords["confirmationTag"],"groupContextHash":coords["groupContextHash"]});
    snapshot["nonce"] = json!(STANDARD.encode(nonce));
    snapshot["ciphertext"] = json!(STANDARD.encode(&cipher));
    snapshot["ciphertextSize"] = json!(cipher.len());
    snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&cipher)));
    let mut leaves = Vec::new();
    for name in ["Alice", "Bob", "Charlie"] {
        let c = world.client(name);
        leaves.push(json!({"userDid":c.did,"deviceId":c.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":leaves.len(),"deviceStatus":"active"}));
    }
    let state = json!({"conversationKind":"group","snapshotSeq":17,"coordinates":coords,"leaves":leaves,"participants":[{"userDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","role":"admin","status":"active","leafCount":1},{"userDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","role":"member","status":"active","leafCount":1},{"userDid":"did:plc:cccccccccccccccccccccccc","role":"member","status":"active","leafCount":1}],"metadataSnapshot":snapshot});
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state.clone());
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&cid, 1);
    world
        .client("Charlie")
        .orchestrator
        .leave_conversation(&cid)
        .await
        .unwrap();
    if ambiguous {
        world.delivery_service().lose_leave_fulfillment_responses(3);
        world.delivery_service().fail_next_get_entries();
        assert!(world
            .client("Alice")
            .orchestrator
            .fulfill_pending_group_leave(&cid)
            .await
            .is_err());
    } else {
        assert!(world
            .client("Alice")
            .orchestrator
            .fulfill_pending_group_leave(&cid)
            .await
            .unwrap());
    }
    (world, cid, group)
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_control_reconciles_by_signed_transition_with_independent_entry_id() {
    let (world, cid, group) = journal_fixture(true).await;
    let alice = world.client("Alice");
    let group_hex = hex::encode(&group);
    let pending = alice
        .orchestrator
        .mls_context()
        .get_prepared_control(&group_hex)
        .unwrap()
        .unwrap();
    let mut entries = world.delivery_service().terminal_entries_for_test();
    let accepted = entries
        .iter_mut()
        .find(|entry| entry["signedRequest"]["body"]["transitionId"] == pending.transition_id)
        .unwrap();
    let entry_id = uuid::Uuid::new_v4().to_string();
    accepted["entryId"] = json!(entry_id);
    let exact_signed = accepted["signedRequest"].clone();
    world
        .delivery_service()
        .set_terminal_entries_for_test(entries);
    world.delivery_service().set_leave_fulfillment_responses(
        3,
        503,
        json!({"error":"Unavailable"}),
    );
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
        .orchestrator
        .mls_context()
        .get_prepared_control(&group_hex)
        .unwrap()
        .is_none());
    let completed = alice
        .orchestrator
        .mls_context()
        .list_prepared_controls()
        .unwrap()
        .into_iter()
        .find(|record| record.transition_id == pending.transition_id)
        .unwrap();
    assert!(completed.completed);
    let proof: Value = serde_json::from_slice(completed.confirmed_entry.as_ref().unwrap()).unwrap();
    assert_eq!(proof["entryId"], entry_id);
    assert_eq!(proof["signedRequest"], exact_signed);
    assert_eq!(completed.request_body, pending.request_body);
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
}

async fn verify_resume(reattach: bool, ambiguous: bool) {
    let (world, cid, group) = journal_fixture(ambiguous).await;
    let alice = world.client("Alice");
    let group_hex = hex::encode(&group);
    let original = alice
        .orchestrator
        .mls_context()
        .list_prepared_controls()
        .unwrap()
        .into_iter()
        .find(|record| record.conversation_id == cid)
        .unwrap();
    assert_eq!(original.completed, !ambiguous);
    let calls_before = world.delivery_service().submitted_prepared_requests().len();
    alice.orchestrator.suspend().await.unwrap();
    assert!(alice
        .orchestrator
        .pending_staged_commits()
        .lock()
        .await
        .is_empty());
    assert!(alice.orchestrator.own_commits().lock().await.is_empty());
    let replacement = if reattach {
        let replacement = MLSOrchestrator::new(
            alice.orchestrator.mls_context().clone(),
            Arc::new(alice.storage.clone()),
            Arc::new(world.delivery_service().clone_as(&alice.did)),
            Arc::new(alice.credentials.clone()),
            OrchestratorConfig::default(),
        );
        replacement
            .reattach_after_suspend(&alice.did)
            .await
            .unwrap();
        Some(replacement)
    } else {
        alice
            .orchestrator
            .resume_after_suspend(&alice.did)
            .await
            .unwrap();
        None
    };
    let restored = replacement.as_ref().unwrap_or(&alice.orchestrator);
    assert_eq!(
        world.delivery_service().submitted_prepared_requests().len(),
        calls_before,
        "offline resume must hydrate authority without transmitting a mutation"
    );

    if ambiguous {
        assert!(
            restored
                .pending_staged_commits()
                .lock()
                .await
                .contains_key(&group_hex),
            "the retained ambiguous operation must block a replacement before Ready"
        );
        assert_eq!(
            restored
                .mls_context()
                .get_prepared_control(&group_hex)
                .unwrap()
                .unwrap()
                .request_body,
            original.request_body
        );
        let error = restored
            .stage_commit(
                &cid,
                CommitKind::RemoveMembers {
                    member_dids: vec![world.client("Bob").did.clone()],
                },
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("staged commit already exists"),
            "missing journal blocker: {error}"
        );
        assert!(restored
            .mls_context()
            .export_metadata_key_from_pending(group.clone(), 2)
            .is_ok());
        assert_eq!(
            world.delivery_service().submitted_prepared_requests().len(),
            calls_before
        );
        let request: Value = serde_json::from_slice(&original.request_body).unwrap();
        let ciphertext = STANDARD
            .decode(
                request["signedRequest"]["body"]["commit"]["bytes"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let echo = IncomingEnvelope {
            conversation_id: cid.clone(),
            sender_did: alice.did.clone(),
            ciphertext,
            timestamp: chrono::Utc::now(),
            server_message_id: Some(original.transition_id.clone()),
            server_epoch: Some(1),
            server_sequence: None,
        };
        // The stream can resume before a sync/replay task. While the server's
        // acceptance remains unconfirmed, defer its echo without labelling
        // healthy pending crypto as a lost or divergent group.
        world.delivery_service().lose_leave_fulfillment_responses(3);
        world.delivery_service().fail_next_get_entries();
        assert!(restored.process_incoming(&echo).await.is_err());
        assert!(
            !alice.storage.needs_rejoin(&cid).await.unwrap(),
            "an unconfirmed own Commit must not enter membership recovery"
        );
        assert_eq!(restored.mls_context().get_epoch(group.clone()).unwrap(), 1);
        assert!(restored
            .mls_context()
            .export_metadata_key_from_pending(group.clone(), 2)
            .is_ok());
        assert_eq!(
            restored
                .mls_context()
                .get_prepared_control(&group_hex)
                .unwrap()
                .unwrap()
                .request_body,
            original.request_body
        );
        // A later delivery resolves the exact journal before it reaches the
        // ordinary MLS decryption path; no explicit replay API is called.
        restored.process_incoming(&echo).await.unwrap();
        let requests = world.delivery_service().submitted_prepared_requests();
        let replay = requests
            .iter()
            .rev()
            .find(|request| request.operation == CanonicalOperation::SubmitTransition)
            .unwrap();
        assert_eq!(replay.body.as_ref().unwrap(), &original.request_body);
        assert!(restored
            .mls_context()
            .get_prepared_control(&group_hex)
            .unwrap()
            .is_none());
        assert!(!restored
            .own_commits()
            .lock()
            .await
            .contains_key(&original.commit_sha256));
        assert_eq!(restored.mls_context().get_epoch(group).unwrap(), 2);
        assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
        return;
    }

    assert!(
        restored
            .own_commits()
            .lock()
            .await
            .contains_key(&original.commit_sha256),
        "completed exact Commit proof must be present before an inbound echo"
    );
    assert!(restored
        .own_commit_expectations()
        .lock()
        .await
        .contains_key(&original.commit_sha256));
    let request: Value = serde_json::from_slice(&original.request_body).unwrap();
    let ciphertext = STANDARD
        .decode(
            request["signedRequest"]["body"]["commit"]["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    restored
        .process_incoming(&IncomingEnvelope {
            conversation_id: cid.clone(),
            sender_did: alice.did.clone(),
            ciphertext,
            timestamp: chrono::Utc::now(),
            server_message_id: Some(original.transition_id.clone()),
            server_epoch: Some(1),
            server_sequence: None,
        })
        .await
        .unwrap();
    assert!(
        !restored
            .own_commits()
            .lock()
            .await
            .contains_key(&original.commit_sha256),
        "the verified echo consumes the restored proof rather than entering crypto recovery"
    );
    assert_eq!(restored.mls_context().get_epoch(group).unwrap(), 2);
    assert!(!alice.storage.needs_rejoin(&cid).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_resume_restores_ambiguous_control_blocker_and_exact_replay() {
    verify_resume(false, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_reattach_restores_ambiguous_control_blocker_and_exact_replay() {
    verify_resume(true, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_resume_restores_completed_own_commit_proof() {
    verify_resume(false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_reattach_restores_completed_own_commit_proof() {
    verify_resume(true, false).await;
}
