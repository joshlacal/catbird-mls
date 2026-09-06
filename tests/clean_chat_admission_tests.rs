//! Canonical pending consent survives inventory, startup, and cryptographic recovery.
#![allow(dead_code)]
mod e2e_harness;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_atproto::blue_catbird::chat::ConversationState as CanonicalState;
use catbird_mls::orchestrator::{
    canonical_transport::{
        decode_conversation_state, encode_conversation_state, CanonicalOperation,
        CleanChatSigningContext, PreparedRequest,
    },
    ConversationState, ConversationView, CredentialStore, GroupState, MLSAPIClient,
    MLSStorageBackend, MlsCryptoContext,
};
use e2e_harness::TestWorld;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct RetainedEpochSecrets(Arc<Mutex<HashMap<(String, u64), Vec<u8>>>>);

#[async_trait::async_trait]
impl catbird_mls::EpochSecretStorage for RetainedEpochSecrets {
    async fn store_epoch_secret(&self, group: String, epoch: u64, secret: Vec<u8>) -> bool {
        self.0.lock().unwrap().insert((group, epoch), secret);
        true
    }
    async fn get_epoch_secret(&self, group: String, epoch: u64) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(&(group, epoch)).cloned()
    }
    async fn delete_epoch_secret(&self, group: String, epoch: u64) -> bool {
        self.0.lock().unwrap().remove(&(group, epoch));
        true
    }
    async fn delete_epochs_before(&self, group: String, cutoff: u64) -> u32 {
        let mut secrets = self.0.lock().unwrap();
        let before = secrets.len();
        secrets.retain(|(key, epoch), _| key != &group || *epoch >= cutoff);
        (before - secrets.len()) as u32
    }
}

impl RetainedEpochSecrets {
    fn install(&self, fixture: &AdmissionFixture) {
        fixture
            .world
            .client("Bob")
            .orchestrator
            .mls_context()
            .set_epoch_secret_storage(Box::new(self.clone()))
            .unwrap();
    }
    fn secret(&self, group: &[u8], epoch: u64) -> Vec<u8> {
        self.0
            .lock()
            .unwrap()
            .get(&(hex::encode(group), epoch))
            .cloned()
            .expect("successful real Welcome must persist the historical epoch secret")
    }
    async fn reopen_bob(&self, fixture: &mut AdmissionFixture) {
        fixture.world.restart_client("Bob").await;
        self.install(fixture);
    }
}

const ALICE: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
const CHARLIE: &str = "did:plc:cccccccccccccccccccccccc";

struct AdmissionFixture {
    world: TestWorld,
    cid: String,
    group: Vec<u8>,
    state: CanonicalState,
    view: ConversationView,
}

fn typed_state(value: Value) -> CanonicalState {
    decode_conversation_state(&serde_json::to_vec(&value).unwrap())
        .expect("the complete canonical server DTO must validate through the production codec")
}

fn with_state(view: &ConversationView, state: Option<&CanonicalState>) -> ConversationView {
    let mut value = serde_json::to_value(view).unwrap();
    value["canonicalState"] = serde_json::to_value(state).unwrap();
    serde_json::from_value(value).unwrap()
}

fn server_state(state: &CanonicalState) -> Value {
    // The shared mock's strict signed-CAS comparisons use base64 wire values.
    // Decode/encode still validates the complete schema before this conversion.
    fn bare_bytes(value: &mut Value) {
        match value {
            Value::Object(fields)
                if fields.len() == 1 && fields.get("$bytes").is_some_and(Value::is_string) =>
            {
                *value = fields.remove("$bytes").unwrap();
            }
            Value::Object(fields) => fields.values_mut().for_each(bare_bytes),
            Value::Array(items) => items.iter_mut().for_each(bare_bytes),
            _ => {}
        }
    }
    let mut value = serde_json::from_slice(&encode_conversation_state(state).unwrap()).unwrap();
    bare_bytes(&mut value);
    value
}

async fn pending_fixture() -> AdmissionFixture {
    pending_fixture_for_kind(false).await
}

async fn pending_fixture_for_kind(group_chat: bool) -> AdmissionFixture {
    let mut world = TestWorld::new();
    let mut clients = vec![("Alice", ALICE), ("Bob", BOB)];
    if group_chat {
        clients.push(("Charlie", CHARLIE));
    }
    for (name, did) in clients {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    let members = if group_chat {
        vec![BOB.into(), CHARLIE.into()]
    } else {
        vec![BOB.into()]
    };
    let created = alice
        .orchestrator
        .create_group("Pending consent", Some(&members), None)
        .await
        .unwrap();
    let cid = created.conversation_id.clone();
    let group = hex::decode(&created.group_id).unwrap();
    let create = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .find(|r| r.operation == CanonicalOperation::CreateConversation)
        .unwrap();
    let wrapper: Value = serde_json::from_slice(create.body.as_ref().unwrap()).unwrap();
    let body = &wrapper["signedRequest"]["body"];
    let mut participants = body["manifest"]["participants"].clone();
    for participant in participants.as_array_mut().unwrap() {
        participant["leafCount"] = json!(if participant["status"] == "active" {
            1
        } else {
            0
        });
    }
    let state = typed_state(json!({
        "cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "conversationKind":body["conversationKind"], "coordinates":body["next"],
        "metadataSnapshot":body["metadataSnapshot"], "snapshotSeq":1,
        "participants":participants,
        "leaves":[{"userDid":ALICE,"deviceId":body["actorDeviceId"],"deviceStatus":"active","leafOrigin":"genesis","keyId":body["keyId"]}]
    }));
    let view = with_state(&created, Some(&state));
    world
        .delivery_service()
        .set_conversation_view_for_test(&cid, view.clone());
    // The point-read fixture is independent from the legacy list projection.
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, server_state(&state));
    let bob = world.client("Bob");
    bob.storage
        .ensure_conversation_exists(BOB, &cid, &created.group_id)
        .await
        .unwrap();
    bob.storage
        .set_conversation_view_for_test(&cid, view.clone());
    assert!(bob
        .orchestrator
        .mls_context()
        .get_epoch(group.clone())
        .is_err());
    AdmissionFixture {
        world,
        cid,
        group,
        state,
        view,
    }
}

fn assert_no_membership_work(f: &AdmissionFixture, start: usize) {
    for request in &f.world.delivery_service().submitted_prepared_requests()[start..] {
        assert!(
            !matches!(
                request.operation,
                CanonicalOperation::AcceptConversation
                    | CanonicalOperation::RequestLeafRecovery
                    | CanonicalOperation::RequestReset
                    | CanonicalOperation::ActivateReset
                    | CanonicalOperation::SubmitTransition
                    | CanonicalOperation::SendMessage
            ),
            "pending consent must not trigger {:?}",
            request.operation
        );
    }
}

async fn raw_state(f: &AdmissionFixture, name: &str) -> Value {
    let client = f.world.client(name);
    let response = client
        .orchestrator
        .api_client()
        .submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversationState,
            path: format!(
                "/xrpc/blue.catbird.chat.getConversationState?conversationId={}&actorDeviceId={}",
                f.cid,
                client.orchestrator.require_actor_device_id().await.unwrap()
            ),
            method: "GET".into(),
            body: None,
        })
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    serde_json::from_slice(&response.body).unwrap()
}

fn policy_view(f: &AdmissionFixture, state: &CanonicalState) -> ConversationView {
    let mut view = f.view.clone();
    view.epoch = state.coordinates.epoch as u64;
    view.members = state
        .participants
        .iter()
        .map(|p| catbird_mls::orchestrator::MemberView {
            did: p.user_did.to_string(),
            role: if p.role.as_str() == "admin" {
                catbird_mls::orchestrator::MemberRole::Admin
            } else {
                catbird_mls::orchestrator::MemberRole::Member
            },
        })
        .collect();
    with_state(&view, Some(state))
}

fn publish_complete_state(f: &AdmissionFixture, state: &CanonicalState) {
    let raw = server_state(state);
    let api = f.world.delivery_service();
    api.set_lifecycle_state_for_test(&f.cid, raw.clone());
    api.set_conversation_participants_for_test(
        &f.cid,
        raw["participants"].as_array().unwrap().clone(),
    );
    api.set_conversation_leaves_for_test(&f.cid, raw["leaves"].as_array().unwrap().clone());
    api.update_conversation_metadata_snapshot_for_test(&f.cid, raw["metadataSnapshot"].clone());
    api.set_conversation_view_for_test(&f.cid, policy_view(f, state));
}

async fn fulfill_bob_and_adopt_welcome(f: &AdmissionFixture) -> CanonicalState {
    let (next, welcome) = fulfill_bob_recovery(f).await;
    adopt_bob_welcome(f, &next, &welcome).await;
    next
}

async fn fulfill_bob_recovery(f: &AdmissionFixture) -> (CanonicalState, Value) {
    let prior_response = raw_state(f, "Alice").await;
    let prior = typed_state(prior_response["state"].clone());
    let request = prior_response["pendingLeafRecoveryRequests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|request| request["requesterDid"] == BOB && request["status"] == "open")
        .unwrap()
        .clone();
    let result = f
        .world
        .client("Alice")
        .orchestrator
        .fulfill_leaf_recovery(&f.cid)
        .await
        .unwrap();
    let body = &result["entry"]["signedRequest"]["body"];
    assert_eq!(
        body["manifest"]["leafRecoveryRequestId"],
        request["recoveryRequestId"]
    );
    let mut next = server_state(&prior);
    next["coordinates"] = body["next"].clone();
    next["snapshotSeq"] = result["entry"]["seq"].clone();
    next["metadataSnapshot"] = body["metadataSnapshot"].clone();
    // The generic mock omits full leaf-view fields. Derive only the accepted
    // successor from its signed manifest and exact reserved package binding.
    let leaves = next["leaves"].as_array_mut().unwrap();
    for change in body["manifest"]["leafChanges"].as_array().unwrap() {
        leaves.retain(|leaf| {
            !(leaf["userDid"] == change["userDid"] && leaf["deviceId"] == change["deviceId"])
        });
        if change["$type"] == "blue.catbird.chat.defs#addLeafByRecovery" {
            assert_eq!(change["userDid"], request["requesterDid"]);
            assert_eq!(change["deviceId"], request["requesterDeviceId"]);
            assert_eq!(
                change["keyPackageRef"],
                request["reservation"]["keyPackageRef"]
            );
            leaves.push(json!({"userDid":change["userDid"],"deviceId":change["deviceId"],"deviceStatus":"active",
                "keyId":request["reservation"]["requesterKeyId"],"leafOrigin":"keyPackage","joinKeyPackageRef":change["keyPackageRef"]}));
        } else {
            assert_eq!(change["$type"], "blue.catbird.chat.defs#removeLeaf");
        }
    }
    let leaves = next["leaves"].as_array().unwrap().clone();
    for participant in next["participants"].as_array_mut().unwrap() {
        participant["leafCount"] = json!(leaves
            .iter()
            .filter(|leaf| leaf["userDid"] == participant["userDid"])
            .count());
    }
    let next = typed_state(next);
    publish_complete_state(f, &next);
    (next, result["welcomes"][0].clone())
}

async fn adopt_bob_welcome(f: &AdmissionFixture, next: &CanonicalState, welcome: &Value) {
    assert_eq!(welcome["recipientDid"], BOB);
    let bytes = STANDARD
        .decode(welcome["opaqueWelcome"].as_str().unwrap())
        .unwrap();
    let joined = f
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&f.cid, bytes)
        .await
        .unwrap();
    assert_eq!(joined, next.coordinates.epoch as u64);
    assert!(f
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
        .iter()
        .any(|record| record.projection_completed));
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_host_group_without_policy_cannot_bypass_retained_pending_consent() {
    let mut f = pending_fixture().await;
    f.world
        .client("Bob")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    let forged = hex::encode([91; 32]);
    let mut unknown = with_state(&f.view, None);
    unknown.group_id = forged.clone();
    unknown.epoch = 99;
    f.world
        .client("Bob")
        .storage
        .set_conversation_group_id_for_test(&f.cid, &forged);
    f.world
        .client("Bob")
        .storage
        .set_conversation_view_for_test(&f.cid, unknown.clone());
    f.world
        .delivery_service()
        .set_conversation_group_id_for_test(&f.cid, &forged);
    f.world
        .delivery_service()
        .set_conversation_view_for_test(&f.cid, unknown.clone());
    f.world
        .client("Bob")
        .orchestrator
        .conversations()
        .lock()
        .await
        .insert(f.cid.clone(), unknown);
    // An unrelated active group with the same claimed mapping still has no
    // Welcome receipt binding it to this conversation or its admission.
    let bob = f.world.client("Bob");
    let identity = format!(
        "{BOB}#{}",
        bob.orchestrator.require_actor_device_id().await.unwrap()
    );
    bob.orchestrator
        .mls_context()
        .create_group_with_id(identity.into_bytes(), vec![91; 32], None)
        .unwrap();
    bob.orchestrator
        .mls_context()
        .self_update(vec![91; 32])
        .unwrap();
    bob.orchestrator
        .mls_context()
        .merge_pending_commit(vec![91; 32])
        .unwrap();
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(vec![91; 32])
            .unwrap(),
        1
    );
    assert!(bob
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
        .is_empty());
    f.world.restart_client("Bob").await;
    let start = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    let bob = f.world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .startup_reconcile()
            .await
            .unwrap()
            .needs_rejoin,
        0
    );
    f.world.delivery_service().fail_next_get_messages();
    bob.orchestrator.sync_with_server(true).await.unwrap();
    assert!(
        !bob.orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
    assert!(bob
        .orchestrator
        .send_message(&f.cid, "Unverified mapping is not consent")
        .await
        .is_err());
    assert_no_membership_work(&f, start);
    assert!(bob
        .orchestrator
        .api_client()
        .get_messages(&f.cid, None, 1, None, None, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("injected get_messages failure"));
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_conversation_policy(BOB, &f.cid)
            .unwrap(),
        Some(f.state.clone())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_departure_reopens_as_pending_only_after_new_invitation_then_verified_welcome(
) {
    let mut f = pending_fixture_for_kind(true).await;
    let epoch_secrets = RetainedEpochSecrets::default();
    epoch_secrets.install(&f);
    publish_complete_state(&f, &f.state);
    f.world
        .client("Bob")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    f.world
        .client("Bob")
        .orchestrator
        .accept_conversation(&f.cid)
        .await
        .unwrap();
    let accepted = typed_state(raw_state(&f, "Alice").await["state"].clone());
    publish_complete_state(&f, &accepted);
    let active = fulfill_bob_and_adopt_welcome(&f).await;
    let bob = f.world.client("Bob");
    assert!(
        bob.orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
    bob.storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "history-through-reinvitation".into(),
            conversation_id: f.cid.clone(),
            sender_did: ALICE.into(),
            text: "Preserve this conversation through leaving and returning".into(),
            timestamp: chrono::Utc::now(),
            epoch: active.coordinates.epoch as u64,
            sequence_number: 3,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    let history_key = epoch_secrets.secret(&f.group, active.coordinates.epoch as u64);
    assert!(bob
        .orchestrator
        .mls_context()
        .get_conversation_departure(BOB, &f.cid)
        .unwrap()
        .is_none());
    assert!(matches!(
        bob.orchestrator.leave_conversation(&f.cid).await.unwrap(),
        catbird_mls::orchestrator::lifecycle::LeaveOutcome::Pending { .. }
    ));
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&f.cid)
        .await
        .unwrap());
    let departed = typed_state(raw_state(&f, "Alice").await["state"].clone());
    assert!(!departed
        .participants
        .iter()
        .any(|p| p.user_did.as_str() == BOB));

    // Keep the list snapshot stale while the point read is current. This
    // actual invitation must bind the accepted departure coordinate.
    f.world
        .client("Alice")
        .orchestrator
        .add_members(&f.cid, &[BOB.into()])
        .await
        .unwrap();
    let reinvited = typed_state(raw_state(&f, "Alice").await["state"].clone());
    let removal = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .filter(|request| request.operation == CanonicalOperation::SubmitTransition)
        .filter_map(|request| serde_json::from_slice::<Value>(request.body.as_deref()?).ok())
        .map(|wrapper| wrapper["signedRequest"]["body"].clone())
        .find(|body| body["$type"] == "blue.catbird.chat.defs#leaveCommitFulfillmentBody")
        .unwrap();
    let envelope = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: f.cid.clone(),
        sender_did: ALICE.into(),
        ciphertext: STANDARD
            .decode(removal["commit"]["bytes"].as_str().unwrap())
            .unwrap(),
        timestamp: chrono::Utc::now(),
        server_epoch: removal["prior"]["epoch"].as_u64(),
        server_sequence: None,
        server_message_id: removal["transitionId"].as_str().map(str::to_owned),
    };
    assert!(bob
        .orchestrator
        .process_incoming(&envelope)
        .await
        .unwrap()
        .is_none());
    assert!(
        bob.orchestrator
            .mls_context()
            .get_conversation_departure(BOB, &f.cid)
            .unwrap()
            .is_none(),
        "raw MLS removal proves its context, not a canonical state version"
    );
    epoch_secrets.reopen_bob(&mut f).await;
    let bob = f.world.client("Bob");
    let target_epoch = bob
        .orchestrator
        .mls_context()
        .verified_incoming_removal(f.group.clone(), envelope.ciphertext.clone())
        .unwrap()
        .expect("the genuine removal receipt must survive native database reopen");
    assert_eq!(target_epoch, departed.coordinates.epoch as u64);

    let mut old_view = policy_view(&f, &f.state);
    old_view.epoch = departed.coordinates.epoch as u64;
    bob.storage.set_conversation_view_for_test(&f.cid, old_view);
    let display = bob
        .orchestrator
        .conversation_display_snapshot(BOB)
        .await
        .unwrap();
    assert!(
        display[0].canonical_state.is_none(),
        "the existing MLS removal receipt cannot establish a canonical departure coordinate"
    );
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert!(bob
        .orchestrator
        .mls_context()
        .get_conversation_departure(BOB, &f.cid)
        .unwrap()
        .is_none());
    assert!(
        bob.orchestrator
            .reconcile_terminal_conversation(&f.cid)
            .await
            .unwrap(),
        "verify the actual signed removal entry and consume its MLS Commit"
    );
    let anchor = bob
        .orchestrator
        .mls_context()
        .get_conversation_departure(BOB, &f.cid)
        .unwrap()
        .expect("authenticated terminal reconciliation must persist departure coordinate");
    assert_eq!(anchor, departed.coordinates);
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert!(!bob
        .orchestrator
        .mls_context()
        .group_is_active(f.group.clone())
        .unwrap());
    assert!(bob
        .storage
        .message_exists("history-through-reinvitation")
        .await
        .unwrap());
    epoch_secrets.reopen_bob(&mut f).await;
    let bob = f.world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_conversation_departure(BOB, &f.cid)
            .unwrap(),
        Some(anchor.clone())
    );

    // Neither the actual old invitation nor an untrusted pending projection at
    // the exact departure coordinate proves a newer invitation was issued.
    let mut equal_pending = departed.clone();
    equal_pending.participants.push(
        f.state
            .participants
            .iter()
            .find(|p| p.user_did.as_str() == BOB)
            .unwrap()
            .clone(),
    );
    for stale in [&f.state, &equal_pending] {
        let mut view = policy_view(&f, stale);
        view.epoch = view.epoch.max(anchor.epoch as u64);
        bob.storage.set_conversation_view_for_test(&f.cid, view);
        let display = bob
            .orchestrator
            .conversation_display_snapshot(BOB)
            .await
            .unwrap();
        assert!(
            display[0].canonical_state.is_none(),
            "old/equal-coordinate pending consent must stay suppressed"
        );
        assert_eq!(
            bob.storage.get_conversation_state(&f.cid).await.unwrap(),
            Some(ConversationState::DeviceRemoved)
        );
    }

    assert_eq!(reinvited.coordinates.group_id, anchor.group_id);
    assert_eq!(
        reinvited.coordinates.epoch, anchor.epoch,
        "re-invitation changes policy without changing MLS epoch"
    );
    assert_eq!(
        reinvited.coordinates.state_version,
        anchor.state_version + 1
    );
    let renewed = reinvited
        .participants
        .iter()
        .find(|p| p.user_did.as_str() == BOB)
        .unwrap();
    assert_eq!(renewed.status.as_str(), "pending");
    assert_ne!(
        renewed.invitation_provenance,
        f.state
            .participants
            .iter()
            .find(|p| p.user_did.as_str() == BOB)
            .unwrap()
            .invitation_provenance
    );
    publish_complete_state(&f, &reinvited);
    bob.orchestrator.sync_with_server(true).await.unwrap();
    let display = bob
        .orchestrator
        .conversation_display_snapshot(BOB)
        .await
        .unwrap();
    assert_eq!(display[0].canonical_state, Some(reinvited.clone()));
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert!(
        !bob.orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
    assert!(bob
        .storage
        .message_exists("history-through-reinvitation")
        .await
        .unwrap());

    bob.orchestrator.accept_conversation(&f.cid).await.unwrap();
    let accepted = typed_state(raw_state(&f, "Alice").await["state"].clone());
    publish_complete_state(&f, &accepted);
    let (restored, welcome) = fulfill_bob_recovery(&f).await;
    let old_epoch = bob
        .orchestrator
        .mls_context()
        .get_epoch(f.group.clone())
        .unwrap();
    let mut packages = bob
        .orchestrator
        .mls_context()
        .list_key_package_hashes()
        .unwrap();
    packages.sort();
    for field in ["groupContextHash", "confirmationTag"] {
        let bob = f.world.client("Bob");
        let receipts = bob
            .orchestrator
            .mls_context()
            .list_welcome_acceptances()
            .unwrap();
        let mut corrupted = welcome.clone();
        corrupted["coordinates"][field] = json!(STANDARD.encode([96; 32]));
        let delivery =
            catbird_mls::orchestrator::welcome_ack::WelcomeDelivery::from_value(corrupted).unwrap();
        let error = bob
            .orchestrator
            .mls_context()
            .process_welcome_delivery(&delivery, delivery.recipient_identity().into_bytes(), None)
            .err()
            .expect("corrupted re-admission must reject after staging");
        assert!(
            error
                .to_string()
                .contains("Welcome cryptographic coordinate mismatch"),
            "reach post-staging {field} validation, then roll back: {error}"
        );
        epoch_secrets.reopen_bob(&mut f).await;
        let bob = f.world.client("Bob");
        assert_eq!(
            bob.orchestrator
                .mls_context()
                .get_epoch(f.group.clone())
                .unwrap(),
            old_epoch
        );
        assert!(!bob
            .orchestrator
            .mls_context()
            .group_is_active(f.group.clone())
            .unwrap());
        let mut remaining_packages = bob
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap();
        remaining_packages.sort();
        assert_eq!(remaining_packages, packages);
        assert_eq!(
            bob.orchestrator
                .mls_context()
                .list_welcome_acceptances()
                .unwrap(),
            receipts
        );
        assert_eq!(
            epoch_secrets.secret(&f.group, active.coordinates.epoch as u64),
            history_key
        );
        assert!(bob
            .storage
            .message_exists("history-through-reinvitation")
            .await
            .unwrap());
        assert_eq!(
            bob.storage.get_conversation_state(&f.cid).await.unwrap(),
            Some(ConversationState::DeviceRemoved)
        );
    }
    adopt_bob_welcome(&f, &restored, &welcome).await;
    let bob = f.world.client("Bob");
    assert_eq!(restored.coordinates.epoch, anchor.epoch + 1);
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::Active)
    );
    assert!(
        bob.orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
    assert!(bob
        .orchestrator
        .mls_context()
        .group_is_active(f.group.clone())
        .unwrap());
    let application = f
        .world
        .client("Alice")
        .orchestrator
        .mls_context()
        .encrypt_message(f.group.clone(), b"Welcome back after leaving".to_vec())
        .unwrap();
    assert!(
        matches!(bob.orchestrator.mls_context().process_message(f.group.clone(), application.ciphertext).unwrap(),
        catbird_mls::ProcessedContent::ApplicationMessage { plaintext, .. }
            if plaintext == b"Welcome back after leaving")
    );
    assert!(bob
        .storage
        .message_exists("history-through-reinvitation")
        .await
        .unwrap());
    assert_eq!(
        epoch_secrets.secret(&f.group, active.coordinates.epoch as u64),
        history_key
    );
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_conversation_departure(BOB, &f.cid)
            .unwrap(),
        Some(anchor)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_reinvitation_requires_signed_departure_anchor_after_raw_removal_restart() {
    let mut f = pending_fixture_for_kind(true).await;
    let epoch_secrets = RetainedEpochSecrets::default();
    epoch_secrets.install(&f);
    publish_complete_state(&f, &f.state);
    f.world
        .client("Bob")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    f.world
        .client("Bob")
        .orchestrator
        .accept_conversation(&f.cid)
        .await
        .unwrap();
    let accepted = typed_state(raw_state(&f, "Alice").await["state"].clone());
    publish_complete_state(&f, &accepted);
    let active = fulfill_bob_and_adopt_welcome(&f).await;
    let old_key = epoch_secrets.secret(&f.group, active.coordinates.epoch as u64);
    f.world
        .client("Bob")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap();
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .fulfill_pending_group_leave(&f.cid)
        .await
        .unwrap());
    let departed = typed_state(raw_state(&f, "Alice").await["state"].clone());
    let removal = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == CanonicalOperation::SubmitTransition)
        .filter_map(|r| serde_json::from_slice::<Value>(r.body.as_deref()?).ok())
        .map(|wrapper| wrapper["signedRequest"]["body"].clone())
        .find(|body| body["$type"] == "blue.catbird.chat.defs#leaveCommitFulfillmentBody")
        .unwrap();
    let envelope = catbird_mls::orchestrator::IncomingEnvelope {
        conversation_id: f.cid.clone(),
        sender_did: ALICE.into(),
        ciphertext: STANDARD
            .decode(removal["commit"]["bytes"].as_str().unwrap())
            .unwrap(),
        timestamp: chrono::Utc::now(),
        server_epoch: removal["prior"]["epoch"].as_u64(),
        server_sequence: None,
        server_message_id: removal["transitionId"].as_str().map(str::to_owned),
    };
    f.world
        .client("Bob")
        .orchestrator
        .process_incoming(&envelope)
        .await
        .unwrap();
    epoch_secrets.reopen_bob(&mut f).await;
    f.world
        .client("Alice")
        .orchestrator
        .add_members(&f.cid, &[BOB.into()])
        .await
        .unwrap();
    let reinvited = typed_state(raw_state(&f, "Alice").await["state"].clone());
    assert_eq!(reinvited.coordinates.epoch, departed.coordinates.epoch);
    assert_eq!(
        reinvited.coordinates.state_version,
        departed.coordinates.state_version + 1
    );
    let bob = f.world.client("Bob");
    assert!(bob
        .orchestrator
        .mls_context()
        .get_conversation_departure(BOB, &f.cid)
        .unwrap()
        .is_none());
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .verified_incoming_removal(f.group.clone(), envelope.ciphertext)
            .unwrap(),
        Some(departed.coordinates.epoch as u64)
    );
    bob.storage
        .set_conversation_view_for_test(&f.cid, policy_view(&f, &reinvited));
    assert!(
        bob.orchestrator
            .conversation_display_snapshot(BOB)
            .await
            .unwrap()[0]
            .canonical_state
            .is_none(),
        "a real current invitation still requires an authenticated canonical departure anchor"
    );
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert_eq!(
        epoch_secrets.secret(&f.group, active.coordinates.epoch as u64),
        old_key
    );
    assert!(bob
        .orchestrator
        .reconcile_terminal_conversation(&f.cid)
        .await
        .unwrap());
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_conversation_departure(BOB, &f.cid)
            .unwrap(),
        Some(departed.coordinates)
    );
    assert_eq!(
        bob.orchestrator
            .conversation_display_snapshot(BOB)
            .await
            .unwrap()[0]
            .canonical_state,
        Some(reinvited)
    );
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_close_never_displays_a_pending_invitation_again() {
    let f = pending_fixture().await;
    let bob = f.world.client("Bob");
    bob.orchestrator.startup_reconcile().await.unwrap();
    assert_eq!(
        bob.orchestrator.leave_conversation(&f.cid).await.unwrap(),
        catbird_mls::orchestrator::lifecycle::LeaveOutcome::Left
    );
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::Closed)
    );
    let mut untrusted = f.state.clone();
    untrusted.coordinates.state_version += 100;
    untrusted.snapshot_seq += 100;
    bob.storage
        .set_conversation_view_for_test(&f.cid, policy_view(&f, &untrusted));
    let display = bob
        .orchestrator
        .conversation_display_snapshot(BOB)
        .await
        .unwrap();
    assert!(display[0].canonical_state.is_none());
    assert_eq!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::Closed)
    );
    assert!(
        !bob.orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_invitation_startup_preserves_consent_without_rejoin() {
    let f = pending_fixture().await;
    let start = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    let bob = f.world.client("Bob");
    let report = bob.orchestrator.startup_reconcile().await.unwrap();
    assert_eq!(
        report.needs_rejoin, 0,
        "pending invitations are not missing native membership"
    );
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_conversation_policy(BOB, &f.cid)
            .unwrap(),
        Some(f.state.clone())
    );
    assert!(
        bob.orchestrator
            .mls_context()
            .get_conversation_policy(ALICE, &f.cid)
            .unwrap()
            .is_none(),
        "policy retention must be scoped to the initialized account"
    );
    assert!(!bob.storage.needs_rejoin(&f.cid).await.unwrap());
    assert_ne!(
        bob.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::NeedsRejoin)
    );
    bob.orchestrator
        .run_deferred_recovery("pending invitation regression")
        .await
        .unwrap();
    assert!(
        !bob.orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
    assert!(bob
        .orchestrator
        .send_message(&f.cid, "Wait for explicit invitation acceptance")
        .await
        .is_err());
    let display = bob
        .orchestrator
        .conversation_display_snapshot(BOB)
        .await
        .unwrap();
    assert_eq!(display.len(), 1);
    assert_eq!(
        serde_json::to_value(&display[0]).unwrap()["canonicalState"],
        serde_json::to_value(&f.state).unwrap()
    );
    assert_no_membership_work(&f, start);
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_invitation_sync_preserves_display_without_automatic_admission_or_messages() {
    let f = pending_fixture().await;
    let start = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    let packages = f.world.delivery_service().key_package_count(BOB);
    f.world.delivery_service().fail_next_get_messages();
    let bob = f.world.client("Bob");
    bob.orchestrator.sync_with_server(true).await.unwrap();
    assert_no_membership_work(&f, start);
    assert_eq!(f.world.delivery_service().key_package_count(BOB), packages);
    assert!(!bob.storage.needs_rejoin(&f.cid).await.unwrap());
    assert!(bob
        .orchestrator
        .mls_context()
        .get_epoch(f.group.clone())
        .is_err());
    assert!(f
        .world
        .delivery_service()
        .app_message_epoch_ranges()
        .is_empty());
    let unconsumed_failure = bob
        .orchestrator
        .api_client()
        .get_messages(&f.cid, None, 1, None, None, None)
        .await
        .unwrap_err();
    assert!(
        unconsumed_failure
            .to_string()
            .contains("injected get_messages failure"),
        "pending sync must never consume the message-fetch fault"
    );
    let display = bob
        .orchestrator
        .conversation_display_snapshot(BOB)
        .await
        .unwrap();
    assert_eq!(display.len(), 1);
    assert_eq!(
        serde_json::to_value(&display[0]).unwrap()["canonicalState"],
        serde_json::to_value(&f.state).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_inventory_and_forged_view_epoch_preserve_known_pending_consent() {
    let mut f = pending_fixture().await;
    let bob = f.world.client("Bob");
    bob.orchestrator.startup_reconcile().await.unwrap();
    let start = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    for unverified_epoch in [0, 99] {
        let mut unknown = with_state(&f.view, None);
        unknown.epoch = unverified_epoch;
        f.world
            .delivery_service()
            .set_conversation_view_for_test(&f.cid, unknown);
        bob.orchestrator.sync_with_server(true).await.unwrap();
        assert_no_membership_work(&f, start);
        assert!(bob
            .orchestrator
            .mls_context()
            .get_epoch(f.group.clone())
            .is_err());
        assert!(!bob.storage.needs_rejoin(&f.cid).await.unwrap());
        let display = bob
            .orchestrator
            .conversation_display_snapshot(BOB)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&display[0]).unwrap()["canonicalState"],
            serde_json::to_value(&f.state).unwrap(),
            "an unverified view epoch of {unverified_epoch} is not admission authority"
        );
    }
    // A legacy host adapter can still omit canonicalState after reopening.
    // The encrypted native policy copy must preserve the known invitation.
    bob.storage
        .set_conversation_view_for_test(&f.cid, with_state(&f.view, None));
    f.world.restart_client("Bob").await;
    let bob = f.world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .startup_reconcile()
            .await
            .unwrap()
            .needs_rejoin,
        0
    );
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_conversation_policy(BOB, &f.cid)
            .unwrap(),
        Some(f.state.clone())
    );
    let display = bob
        .orchestrator
        .conversation_display_snapshot(BOB)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&display[0]).unwrap()["canonicalState"],
        serde_json::to_value(&f.state).unwrap()
    );
    assert_no_membership_work(&f, start);
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_acceptance_at_same_epoch_survives_stale_pending_and_unknown_inventory() {
    let f = pending_fixture().await;
    let bob = f.world.client("Bob");
    bob.orchestrator.startup_reconcile().await.unwrap();
    let accepted = bob.orchestrator.accept_conversation(&f.cid).await.unwrap();
    assert_eq!(accepted["coordinates"]["epoch"], f.state.coordinates.epoch);
    assert_eq!(
        accepted["coordinates"]["stateVersion"],
        f.state.coordinates.state_version + 1
    );
    let response = bob
        .orchestrator
        .api_client()
        .submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversationState,
            path: format!(
                "/xrpc/blue.catbird.chat.getConversationState?conversationId={}&actorDeviceId={}",
                f.cid,
                bob.orchestrator.require_actor_device_id().await.unwrap()
            ),
            method: "GET".into(),
            body: None,
        })
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let accepted_state =
        typed_state(serde_json::from_slice::<Value>(&response.body).unwrap()["state"].clone());
    assert_eq!(
        accepted_state
            .participants
            .iter()
            .find(|p| p.user_did.as_ref() == BOB)
            .unwrap()
            .status
            .to_string(),
        "active"
    );
    assert_eq!(accepted_state.coordinates.epoch, f.state.coordinates.epoch);
    assert_eq!(
        accepted_state.coordinates.state_version,
        f.state.coordinates.state_version + 1
    );
    f.world
        .delivery_service()
        .set_conversation_view_for_test(&f.cid, with_state(&f.view, Some(&accepted_state)));
    bob.orchestrator.sync_with_server(true).await.unwrap();
    for retained_view in [f.view.clone(), with_state(&f.view, None)] {
        f.world
            .delivery_service()
            .set_conversation_view_for_test(&f.cid, retained_view);
        bob.orchestrator.sync_with_server(true).await.unwrap();
        let display = bob
            .orchestrator
            .conversation_display_snapshot(BOB)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&display[0]).unwrap()["canonicalState"],
            serde_json::to_value(&accepted_state).unwrap()
        );
        assert_eq!(
            bob.orchestrator
                .mls_context()
                .get_conversation_policy(BOB, &f.cid)
                .unwrap(),
            Some(accepted_state.clone())
        );
    }
    assert_eq!(
        f.world
            .delivery_service()
            .submitted_prepared_requests()
            .iter()
            .filter(|request| request.operation == CanonicalOperation::AcceptConversation)
            .count(),
        1,
        "stale pending inventory must not repeat consent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_native_welcome_at_newer_epoch_supersedes_a_retained_pending_gate() {
    let f = pending_fixture().await;
    let alice = f.world.client("Alice");
    let bob = f.world.client("Bob");
    bob.orchestrator.startup_reconcile().await.unwrap();
    let identity = format!(
        "{BOB}#{}",
        bob.orchestrator.require_actor_device_id().await.unwrap()
    );
    // Submit actual signed consent without running the client's post-accept
    // policy refresh: this phone still holds its retained pending inventory.
    let auth_generation = bob
        .credentials
        .get_auth_generation(BOB)
        .await
        .unwrap()
        .unwrap();
    let public_key = bob
        .orchestrator
        .mls_context()
        .identity_public_key(identity.clone())
        .unwrap();
    let transition = uuid::Uuid::new_v4().to_string();
    let mut next = serde_json::to_value(&f.state.coordinates).unwrap();
    next["stateVersion"] = json!(f.state.coordinates.state_version + 1);
    let participant = f
        .state
        .participants
        .iter()
        .find(|p| p.user_did.as_ref() == BOB)
        .unwrap();
    let body = json!({
        "$type":"blue.catbird.chat.defs#participantAcceptanceBody", "signatureDomain":"CATBIRD-CHAT-ACCEPT\0",
        "actorDid":BOB,"actorDeviceId":bob.orchestrator.require_actor_device_id().await.unwrap(),
        "authGeneration":auth_generation, "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(public_key)),
        "transitionId":transition,"idempotencyKey":transition,"recoveryRequestId":uuid::Uuid::new_v4().to_string(),
        "prior":f.state.coordinates,"next":next,"invitationProvenance":participant.invitation_provenance,
        "signedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)
    });
    let prepared = bob
        .orchestrator
        .prepare_clean_chat_signed_request(
            CleanChatSigningContext {
                actor_did: BOB.into(),
                device_id: bob.orchestrator.require_actor_device_id().await.unwrap(),
                auth_generation: Some(auth_generation),
            },
            CanonicalOperation::AcceptConversation,
            serde_json::to_vec(&body).unwrap(),
        )
        .await
        .unwrap();
    let accepted = bob
        .orchestrator
        .api_client()
        .submit_prepared_request(prepared)
        .await
        .unwrap();
    assert_eq!(accepted.status, 200);
    let accepted: Value = serde_json::from_slice(&accepted.body).unwrap();
    assert_eq!(bob.orchestrator.mls_context().get_conversation_policy(BOB, &f.cid).unwrap(), Some(f.state.clone()), "direct signed consent must leave the old retained policy available for this native-proof regression");
    let reserved_package = STANDARD
        .decode(
            accepted["recovery"]["reservation"]["keyPackage"]["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let added = alice
        .orchestrator
        .mls_context()
        .add_members(
            f.group.clone(),
            vec![catbird_mls::KeyPackageData {
                data: reserved_package,
            }],
        )
        .unwrap();
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(f.group.clone())
        .unwrap();
    bob.orchestrator
        .mls_context()
        .process_welcome(added.welcome_data, identity.into_bytes(), None)
        .unwrap();
    assert!(bob
        .orchestrator
        .mls_context()
        .group_is_active(f.group.clone())
        .unwrap());
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(f.group.clone())
            .unwrap(),
        1
    );
    let projection = GroupState {
        conversation_id: f.cid.clone(),
        group_id: hex::encode(&f.group),
        epoch: 1,
        members: bob
            .orchestrator
            .mls_context()
            .group_member_identities(f.group.clone())
            .unwrap()
            .into_iter()
            .map(|bytes| String::from_utf8(bytes).unwrap())
            .collect(),
    };
    bob.storage.set_group_state(&projection).await.unwrap();
    bob.storage
        .set_conversation_state(&f.cid, ConversationState::Active)
        .await
        .unwrap();
    // Canonical inventory remains at pending epoch0; only the verified native
    // group proves this device has since received membership at epoch1.
    let start = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    let report = bob.orchestrator.startup_reconcile().await.unwrap();
    assert_eq!(report.healthy, 1);
    assert_eq!(report.needs_rejoin, 0);
    let ready = bob
        .orchestrator
        .ensure_conversation_ready(&f.cid)
        .await
        .unwrap();
    assert!(
        ready.send_allowed,
        "a real active native successor should lift the stale pending gate"
    );
    assert_no_membership_work(&f, start);
}
