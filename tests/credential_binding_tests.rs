//! WS-3 stage 1+2 integration tests: credential binding (ADR-009
//! D3/D4), sequencer equivocation detection (ADR-009 D8 / backlog E3),
//! receipt clearing across server resets (N44a), inbound envelope-sender
//! spoofing (N44b), and the authorized-device-key seam (N44c).
//!
//! Uses the TestWorld/TestClient harness plus mock extensions:
//!   - `MockDeliveryService::redirect_key_packages_for_test` — serve another
//!     user's key package for a requested DID (malicious-DS simulation);
//!   - `MockDeliveryService::issue_external_commit_receipts_for_test` — return
//!     `SequencerReceipt`s from `process_external_commit`;
//!   - `MockDeliveryService::relabel_envelope_sender_for_test` — spoof the
//!     envelope `sender_did` of a genuine MLS ciphertext (ADR-009 D4);
//!   - `MockCredentials::set_authorized_device_keys` — resolve the optional
//!     `get_authorized_device_keys` capability (ADR-009 full check).
//!
//! Observer callbacks remain as telemetry, while DID/device binding failures
//! now reject before state-changing MLS operations.

#![allow(dead_code)]

mod e2e_harness;

use std::sync::{Arc, Mutex};

use catbird_mls::orchestrator::event_observer::OrchestratorEventObserver;
use catbird_mls::orchestrator::{
    extract_key_package_binding, ConversationState, IncomingEnvelope, MLSAPIClient,
    MLSStorageBackend, MlsCryptoContext, OrchestratorError, SequencerReceipt,
};
use e2e_harness::TestWorld;

async fn replace_available_packages_with_one_wrapped(
    world: &TestWorld,
    requester_name: &str,
    publisher_name: &str,
    did: &str,
) {
    use openmls::prelude::{tls_codec::DeserializeBytes as _, tls_codec::Serialize as _, *};
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;

    let requester = world.client(requester_name);
    let mut last_package = None;
    loop {
        let fetched = requester
            .orchestrator
            .api_client()
            .get_key_packages("00000000-0000-4000-8000-000000000001", &[did.to_string()])
            .await
            .expect("drain raw key packages");
        let Some(package) = fetched.into_iter().next() else {
            break;
        };
        last_package = Some(package);
    }
    let package = last_package.expect("registered device publishes key packages");
    let package_in = if let Ok((msg, remaining)) =
        MlsMessageIn::tls_deserialize_bytes(&package.key_package_data)
    {
        if remaining.is_empty() {
            match msg.extract() {
                MlsMessageBodyIn::KeyPackage(kp) => kp,
                _ => panic!("expected KeyPackage message"),
            }
        } else {
            let (pkg, _) = KeyPackageIn::tls_deserialize_bytes(&package.key_package_data)
                .expect("decode raw published key package");
            pkg
        }
    } else {
        let (pkg, _) = KeyPackageIn::tls_deserialize_bytes(&package.key_package_data)
            .expect("decode raw published key package");
        pkg
    };
    let provider = OpenMlsRustCrypto::default();
    let validated = package_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .expect("validate published key package");
    let wrapped = MlsMessageOut::from(validated)
        .tls_serialize_detached()
        .expect("serialize wrapped key package");
    world
        .client(publisher_name)
        .orchestrator
        .api_client()
        .publish_key_package(
            &wrapped,
            &package.cipher_suite,
            "2099-01-01T00:00:00Z",
            None,
        )
        .await
        .expect("republish wrapped key package");
}

// ---------------------------------------------------------------------------
// Recording observer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CredentialWarning {
    convo_id: String,
    operation: String,
    expected_did: String,
    claimed_identity: String,
    reason: String,
}

#[derive(Debug, Clone)]
struct EquivocationEvent {
    convo_id: String,
    epoch: i32,
    stored_commit_hash_hex: String,
    new_commit_hash_hex: String,
    sequencer_did: String,
}

/// Test observer recording WS-3 escalations.
#[derive(Default)]
struct RecordingObserver {
    credential_warnings: Mutex<Vec<CredentialWarning>>,
    equivocations: Mutex<Vec<EquivocationEvent>>,
}

impl RecordingObserver {
    fn credential_warnings(&self) -> Vec<CredentialWarning> {
        self.credential_warnings.lock().unwrap().clone()
    }

    fn equivocations(&self) -> Vec<EquivocationEvent> {
        self.equivocations.lock().unwrap().clone()
    }
}

impl OrchestratorEventObserver for RecordingObserver {
    fn on_credential_binding_warning(
        &self,
        convo_id: &str,
        operation: &str,
        expected_did: &str,
        claimed_identity: &str,
        reason: &str,
    ) {
        self.credential_warnings
            .lock()
            .unwrap()
            .push(CredentialWarning {
                convo_id: convo_id.to_string(),
                operation: operation.to_string(),
                expected_did: expected_did.to_string(),
                claimed_identity: claimed_identity.to_string(),
                reason: reason.to_string(),
            });
    }

    fn on_sequencer_equivocation(
        &self,
        convo_id: &str,
        epoch: i32,
        stored_commit_hash_hex: &str,
        new_commit_hash_hex: &str,
        sequencer_did: &str,
    ) {
        self.equivocations.lock().unwrap().push(EquivocationEvent {
            convo_id: convo_id.to_string(),
            epoch,
            stored_commit_hash_hex: stored_commit_hash_hex.to_string(),
            new_commit_hash_hex: new_commit_hash_hex.to_string(),
            sequencer_did: sequencer_did.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// (a) Matching credential → no warning
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn matching_credential_produces_no_warning() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("cred-bind-clean", None, None)
        .await
        .expect("create_group failed");

    alice
        .orchestrator
        .swap_members(&convo.group_id, &[], &[bob_did])
        .await
        .expect("add_members with genuine key package failed");

    assert!(
        observer.credential_warnings().is_empty(),
        "matching credential must not produce binding warnings, got: {:?}",
        observer.credential_warnings()
    );
}

// ---------------------------------------------------------------------------
// (b) Mismatched DID in fetched key package → reject before MLS mutation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_key_package_rejects_add_without_epoch_or_pending_commit() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Mallory").await;
    world.register_device("Alice").await.unwrap();
    world.register_device("Bob").await.unwrap();
    world.register_device("Mallory").await.unwrap();

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("cred-bind-forged", None, None)
        .await
        .expect("create_group failed");

    // Malicious DS: requests for Bob's key packages get Mallory's instead,
    // still labeled as Bob's.
    world
        .delivery_service()
        .redirect_key_packages_for_test(&bob_did, &mallory_did);

    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&convo.group_id).unwrap())
        .unwrap();

    let error = world
        .client("Alice")
        .orchestrator
        .swap_members(&convo.group_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect_err("substituted raw credential root must reject the complete add");
    assert!(
        error.to_string().contains("credential") || error.to_string().contains("DID"),
        "rejection must identify credential/DID binding: {error}"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&convo.group_id).unwrap())
            .unwrap(),
        epoch_before,
        "rejected add must not advance the epoch"
    );

    // No pending commit may have been created: restoring the genuine package
    // response and retrying on the same group must stage and complete.
    world
        .delivery_service()
        .redirect_key_packages_for_test(&bob_did, &bob_did);
    world
        .client("Alice")
        .orchestrator
        .swap_members(&convo.group_id, &[], &[bob_did])
        .await
        .expect("valid retry proves the rejected add left no pending commit");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_key_package_rejects_complete_batch_before_staging() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Carol").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();
    let carol_did = world.client("Carol").did.clone();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("missing-key-package", None, None)
        .await
        .expect("create_group failed");
    let group_id = hex::decode(&convo.group_id).unwrap();
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id.clone())
        .unwrap();

    let error = alice
        .orchestrator
        .swap_members(&convo.group_id, &[], &[bob_did.clone(), carol_did])
        .await
        .expect_err("partial DS batch must reject atomically");
    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert!(error.to_string().contains("returned 1 key packages for 2"));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id.clone())
            .unwrap(),
        epoch_before
    );

    alice
        .orchestrator
        .swap_members(&convo.group_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("valid retry proves partial batch did not create a pending commit");
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_no_advance_add_rejects_without_local_roster_mutation() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("no-advance-add", None, None)
        .await
        .expect("create_group failed");
    let group_id_bytes = hex::decode(&convo.group_id).unwrap();
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes.clone())
        .unwrap();
    let members_before = alice
        .orchestrator
        .group_states()
        .lock()
        .await
        .get(&convo.group_id)
        .expect("group state")
        .members
        .clone();

    world.delivery_service().no_advance_next_add_members();
    let error = alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect_err("success without epoch advance must be rejected");
    assert!(matches!(error, OrchestratorError::EpochMismatch { .. }));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id_bytes.clone())
            .unwrap(),
        epoch_before
    );
    assert_eq!(
        alice
            .orchestrator
            .group_states()
            .lock()
            .await
            .get(&convo.group_id)
            .expect("group state after rejection")
            .members,
        members_before,
        "no-advance ACK must not append requested DIDs to local state"
    );
    assert!(alice
        .storage
        .get_group_state(&convo.group_id)
        .await
        .expect("persisted state after rejection")
        .is_some_and(|state| state.members == members_before));

    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("valid retry proves the no-advance rejection discarded pending state");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_group_keeps_invitees_pending_without_fetching_key_packages() {
    let mut world = TestWorld::new();
    const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbb";
    const MALLORY: &str = "cccccccccccccccccccccccc";
    for name in [ALICE, BOB, MALLORY] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client(ALICE);
    let bob_did = world.client(BOB).did.clone();
    let mallory_did = world.client(MALLORY).did.clone();
    world
        .delivery_service()
        .redirect_key_packages_for_test(&bob_did, &mallory_did);

    let bob_packages_before = world.delivery_service().key_package_count(&bob_did);
    let conversation = alice
        .orchestrator
        .create_group(
            "actor-only genesis",
            Some(std::slice::from_ref(&bob_did)),
            None,
        )
        .await
        .expect("pending invitee must not require a KeyPackage");

    assert_eq!(
        world.delivery_service().key_package_count(&bob_did),
        bob_packages_before,
        "createConversation must not fetch or consume an invitee KeyPackage"
    );
    assert_eq!(conversation.epoch, 0);
    assert!(conversation
        .members
        .iter()
        .any(|member| member.did == bob_did));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&conversation.group_id).expect("group id is hex"))
            .expect("read actor-only group epoch"),
        0,
        "the local MLS group must contain only the creator at epoch zero"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_swap_rejects_substitution_atomically_then_valid_retry_mutates() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();
    let convo = alice
        .orchestrator
        .create_group("public swap binding", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let group_bytes = hex::decode(&convo.group_id).unwrap();
    let members_before = alice
        .orchestrator
        .mls_context()
        .group_member_identities(group_bytes.clone())
        .expect("members before substitution");
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .expect("epoch before substitution");

    world
        .delivery_service()
        .redirect_key_packages_for_test(&mallory_did, &bob_did);
    let error = alice
        .orchestrator
        .swap_members(
            &convo.group_id,
            std::slice::from_ref(&bob_did),
            std::slice::from_ref(&mallory_did),
        )
        .await
        .expect_err("public Swap must reject a substituted raw credential root");
    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .group_member_identities(group_bytes.clone())
            .expect("members after substitution"),
        members_before,
        "wrapper rejection must perform neither removal nor addition"
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .expect("epoch after substitution"),
        epoch_before,
        "wrapper rejection must not advance the epoch"
    );

    world
        .delivery_service()
        .redirect_key_packages_for_test(&mallory_did, &mallory_did);
    alice
        .orchestrator
        .swap_members(
            &convo.group_id,
            std::slice::from_ref(&bob_did),
            std::slice::from_ref(&mallory_did),
        )
        .await
        .expect("valid retry proves the rejected wrapper call left no pending commit");
    let members_after = alice
        .orchestrator
        .mls_context()
        .group_member_identities(group_bytes.clone())
        .expect("members after valid retry");
    assert!(!members_after
        .iter()
        .any(|identity| identity.starts_with(bob_did.as_bytes())));
    assert!(members_after
        .iter()
        .any(|identity| identity.starts_with(mallory_did.as_bytes())));
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes)
            .expect("epoch after valid retry")
            > epoch_before
    );
}

async fn read_pure_removal_server_state(world: &TestWorld, cid: &str) -> serde_json::Value {
    use catbird_mls::orchestrator::canonical_transport::{CanonicalOperation, PreparedRequest};
    let alice = world.client("Alice");
    let device = alice.orchestrator.require_actor_device_id().await.unwrap();
    let response = alice.orchestrator.api_client().submit_prepared_request(PreparedRequest {
        operation:CanonicalOperation::GetConversationState,method:"GET".into(),
        path:format!("/xrpc/blue.catbird.chat.getConversationState?conversationId={cid}&actorDeviceId={device}"),body:None,
    }).await.expect("read canonical device membership");
    assert_eq!(response.status,200);
    serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["state"].clone()
}

/// The legacy raw Add wrapper predates the mock's canonical roster projection.
/// Seed that projection from the real landed MLS tree before testing Remove.
async fn seed_pure_removal_device_roster(world: &TestWorld, cid: &str, group: &str) {
    let alice = world.client("Alice");
    let leaves = alice.orchestrator.mls_context().group_member_identities(hex::decode(group).unwrap()).unwrap()
        .into_iter().enumerate().map(|(index,identity)| {
            let identity=String::from_utf8(identity).unwrap();
            let (did,device)=identity.split_once('#').expect("real fixture identity includes exact device");
            uuid::Uuid::parse_str(device).expect("real fixture device UUID");
            serde_json::json!({"userDid":did,"deviceId":device,"deviceStatus":"active","leafIndex":index})
        }).collect::<Vec<_>>();
    let page=alice.orchestrator.api_client().get_conversations(100,None).await.unwrap();
    let conversation=page.conversations.iter().find(|c|c.conversation_id==cid).unwrap();
    let participants=conversation.members.iter().map(|member| serde_json::json!({
        "userDid":member.did,"role":if member.did==alice.did {"admin"} else {"member"},"status":"active",
        "leafCount":leaves.iter().filter(|leaf|leaf["userDid"]==member.did).count()
    })).collect::<Vec<_>>();
    let mut state=read_pure_removal_server_state(world,cid).await;
    state["leaves"]=serde_json::json!(&leaves);
    state["participants"]=serde_json::json!(&participants);
    world.delivery_service().set_conversation_leaves_for_test(cid,leaves);
    world.delivery_service().set_conversation_participants_for_test(cid,participants);
    world.delivery_service().set_lifecycle_state_for_test(cid,state);
}

#[tokio::test(flavor = "multi_thread")]
async fn public_pure_remove_server_failure_discards_then_retry_succeeds() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("public pure removal failure", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    seed_pure_removal_device_roster(&world,&convo.conversation_id,&convo.group_id).await;
    alice.credentials.set_authorized_device_key_resolution_failure(&bob_did,true);
    let group_bytes = hex::decode(&convo.group_id).unwrap();
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .expect("epoch before failed server call");

    world.delivery_service().fail_next_remove_members();
    alice
        .orchestrator
        .swap_members(&convo.group_id, std::slice::from_ref(&bob_did), &[])
        .await
        .expect_err("server removal failure must reject the public pure-remove Swap");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes.clone())
            .expect("epoch after failed server call"),
        epoch_before
    );
    assert!(alice
        .orchestrator
        .mls_context()
        .group_member_identities(group_bytes.clone())
        .expect("members after failed server call")
        .iter()
        .any(|identity| identity.starts_with(bob_did.as_bytes())));
    let failed_server_page = alice
        .orchestrator
        .api_client()
        .get_conversations(100, None)
        .await
        .expect("read server projection after failed removal");
    assert!(failed_server_page
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == convo.conversation_id)
        .expect("conversation remains visible after failed removal")
        .members
        .iter()
        .any(|member| member.did == bob_did));
    let failed_state=read_pure_removal_server_state(&world,&convo.conversation_id).await;
    assert_eq!(failed_state["coordinates"]["epoch"],epoch_before);
    assert!(failed_state["leaves"].as_array().unwrap().iter().any(|leaf|leaf["userDid"]==bob_did),
        "failed removal preserves Bob's exact device on the server");

    alice
        .orchestrator
        .swap_members(&convo.group_id, std::slice::from_ref(&bob_did), &[])
        .await
        .expect("valid retry proves the failed server call discarded its pending commit");
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes)
            .expect("epoch after valid retry")
            > epoch_before
    );

    let server_page = alice
        .orchestrator
        .api_client()
        .get_conversations(100, None)
        .await
        .expect("read fake delivery-service projection after retry");
    let server_conversation = server_page
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == convo.conversation_id)
        .expect("conversation remains visible to Alice");
    assert!(server_conversation.members.iter().any(|member| member.did == bob_did),
        "device removal preserves account policy membership");
    let state=read_pure_removal_server_state(&world,&convo.conversation_id).await;
    assert!(!state["leaves"].as_array().unwrap().iter().any(|leaf|leaf["userDid"]==bob_did),
        "successful retry removes Bob's exact device from the server roster");
    assert!(state["participants"].as_array().unwrap().iter().any(|p|p["userDid"]==bob_did && p["leafCount"]==0));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrapped_key_packages_work_through_create_add_and_swap_wrappers() {
    let mut create_world = TestWorld::new();
    create_world.add_client("Alice").await;
    create_world.add_client("Bob").await;
    create_world.register_device("Alice").await.unwrap();
    let create_bob_did = create_world.register_device("Bob").await.unwrap();
    replace_available_packages_with_one_wrapped(&create_world, "Alice", "Bob", &create_bob_did)
        .await;
    create_world
        .client("Alice")
        .orchestrator
        .create_group(
            "wrapped create",
            Some(std::slice::from_ref(&create_bob_did)),
            None,
        )
        .await
        .expect("create_group accepts a wrapped KeyPackage");

    let mut add_world = TestWorld::new();
    add_world.add_client("Alice").await;
    add_world.add_client("Bob").await;
    add_world.register_device("Alice").await.unwrap();
    let add_bob_did = add_world.register_device("Bob").await.unwrap();
    let add_convo = add_world
        .client("Alice")
        .orchestrator
        .create_group("wrapped add", None, None)
        .await
        .expect("create empty group");
    replace_available_packages_with_one_wrapped(&add_world, "Alice", "Bob", &add_bob_did).await;
    add_world
        .client("Alice")
        .orchestrator
        .swap_members(
            &add_convo.conversation_id,
            &[],
            std::slice::from_ref(&add_bob_did),
        )
        .await
        .expect("add_members accepts a wrapped KeyPackage");

    let mut swap_world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory"] {
        swap_world.add_client(name).await;
        swap_world.register_device(name).await.unwrap();
    }
    let swap_alice = swap_world.client("Alice");
    let swap_bob_did = swap_world.client("Bob").did.clone();
    let swap_mallory_did = swap_world.client("Mallory").did.clone();
    let swap_convo = swap_alice
        .orchestrator
        .create_group("wrapped swap", None, None)
        .await
        .expect("create group");
    swap_alice
        .orchestrator
        .swap_members(
            &swap_convo.conversation_id,
            &[],
            std::slice::from_ref(&swap_bob_did),
        )
        .await
        .expect("add Bob");
    replace_available_packages_with_one_wrapped(&swap_world, "Alice", "Mallory", &swap_mallory_did)
        .await;
    swap_alice
        .orchestrator
        .swap_members(
            &swap_convo.conversation_id,
            std::slice::from_ref(&swap_bob_did),
            std::slice::from_ref(&swap_mallory_did),
        )
        .await
        .expect("swap_members accepts a wrapped KeyPackage");
}

#[tokio::test(flavor = "multi_thread")]
async fn public_swap_preserves_pure_removal_compatibility() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("public pure removal", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    seed_pure_removal_device_roster(&world,&convo.conversation_id,&convo.group_id).await;
    alice.credentials.set_authorized_device_key_resolution_failure(&bob_did,true);
    let group_bytes = hex::decode(&convo.group_id).unwrap();
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_bytes.clone())
        .expect("epoch before pure removal");

    alice
        .orchestrator
        .swap_members(&convo.group_id, std::slice::from_ref(&bob_did), &[])
        .await
        .expect("public Swap must support a pure-removal operation");

    let members_after = alice
        .orchestrator
        .mls_context()
        .group_member_identities(group_bytes.clone())
        .expect("members after pure removal");
    assert!(!members_after
        .iter()
        .any(|identity| std::str::from_utf8(identity).unwrap().split('#').next() == Some(bob_did.as_str())));
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_bytes)
            .expect("epoch after pure removal")
            > epoch_before
    );
    let server_page = alice
        .orchestrator
        .api_client()
        .get_conversations(100, None)
        .await
        .expect("read fake delivery-service projection");
    let server_conversation = server_page
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == convo.conversation_id)
        .expect("conversation remains visible to Alice");
    assert!(server_conversation.members.iter().any(|member| member.did == bob_did),
        "pure-removal Swap changes device leaves without removing the account");
    let state=read_pure_removal_server_state(&world,&convo.conversation_id).await;
    assert!(!state["leaves"].as_array().unwrap().iter().any(|leaf|leaf["userDid"]==bob_did),
        "pure-removal Swap removes Bob's exact device from the server roster");
    assert!(state["participants"].as_array().unwrap().iter().any(|p|p["userDid"]==bob_did && p["leafCount"]==0));
}

// ---------------------------------------------------------------------------
// (b2) Fork-readd fetch path: substituted key package → warn + escalate
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn fork_readd_key_package_fetch_warns_on_mismatch() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.add_client("Mallory").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();
    let mallory_did = world.register_device("Mallory").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;
    let convo = alice
        .orchestrator
        .create_group("fork readd mismatch", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let group_id = convo.group_id.clone();
    assert!(
        observer.credential_warnings().is_empty(),
        "clean create_group must not produce binding warnings, got: {:?}",
        observer.credential_warnings()
    );

    // Malicious DS: from now on, fetches of Bob's key packages serve
    // Mallory's package, still labeled as Bob's.
    world
        .delivery_service()
        .redirect_key_packages_for_test(&bob_did, &mallory_did);

    // Drive the automated fork-readd path: FORK_DETECTION_THRESHOLD (2)
    // consecutive decrypt failures on an Active conversation trigger
    // `attempt_fork_readd`, which fetches member key packages and consumes
    // them in a forkReadd commit. Stage-1 contract: the fetch is verified
    // and the mismatch warns; recovery behavior is unchanged.
    for i in 0..2 {
        let envelope = IncomingEnvelope {
            conversation_id: group_id.clone(),
            sender_did: bob_did.clone(),
            ciphertext: format!("not-an-mls-message-{i}").into_bytes(),
            timestamp: chrono::Utc::now(),
            server_message_id: Some(format!("fork-readd-bad-frame-{i}")),
            server_epoch: None,
            server_sequence: None,
        };
        let result = world
            .client("Alice")
            .orchestrator
            .process_incoming(&envelope)
            .await;
        assert!(
            result.is_err(),
            "invalid ciphertext should drive decrypt failure"
        );
    }

    let warnings = observer.credential_warnings();
    let w = warnings
        .iter()
        .find(|w| w.expected_did == bob_did)
        .unwrap_or_else(|| {
            panic!(
                "fork-readd fetch must run credential verification; \
                 no warning for expected DID {bob_did}, got {warnings:?}"
            )
        });
    assert_eq!(w.operation, "fetch");
    assert!(w.claimed_identity == mallory_did || w.claimed_identity.starts_with(&mallory_did));
    assert!(
        w.reason.contains("does not match"),
        "reason should describe the DID mismatch, got: {}",
        w.reason
    );
    assert!(w.convo_id == group_id || w.convo_id == convo.conversation_id);
}

// ---------------------------------------------------------------------------
// (c) Equivocating receipts → detection fires, recovery still proceeds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn equivocating_receipts_fire_detection_and_recovery_proceeds() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("equivocation-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();

    // Sequencer starts issuing receipts for External Commits.
    world
        .delivery_service()
        .issue_external_commit_receipts_for_test(true);

    // The mock assigns epoch = current + 1 to the next External Commit.
    let next_epoch = world
        .delivery_service()
        .conversation_epoch(&group_id)
        .expect("mock should know the conversation epoch") as i32
        + 1;

    // Pre-store a receipt claiming a DIFFERENT commit was sequenced at that
    // same (conversation, epoch) — the equivocation evidence.
    let conflicting = SequencerReceipt {
        convo_id: convo.conversation_id.clone(),
        epoch: next_epoch,
        sequencer_term: 0,
        commit_hash: vec![0xAA; 32],
        sequencer_did: "did:web:sequencer.test".to_string(),
        issued_at: chrono::Utc::now().timestamp(),
        signature: vec![],
    };
    alice
        .storage
        .store_sequencer_receipt(&conflicting)
        .await
        .expect("pre-store conflicting receipt");

    // Drive the External-Commit recovery path. Stage-1 contract: detection
    // fires, recovery still succeeds.
    alice
        .orchestrator
        .force_rejoin(&group_id)
        .await
        .expect("stage-1 detection-only: force_rejoin must still succeed");

    let events = observer.equivocations();
    assert_eq!(
        events.len(),
        1,
        "expected exactly one equivocation event, got: {events:?}"
    );
    let ev = &events[0];
    assert!(ev.convo_id == group_id || ev.convo_id == convo.conversation_id);
    assert_eq!(ev.epoch, next_epoch);
    assert_eq!(ev.stored_commit_hash_hex, hex::encode(vec![0xAA; 32]));
    assert_ne!(
        ev.new_commit_hash_hex, ev.stored_commit_hash_hex,
        "the two conflicting hashes must differ"
    );
    assert_eq!(ev.sequencer_did, "did:web:sequencer.test");
}

// ---------------------------------------------------------------------------
// (d) Non-equivocating receipt sequence → silent
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn non_equivocating_receipts_are_silent() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("receipt-clean-test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();

    world
        .delivery_service()
        .issue_external_commit_receipts_for_test(true);

    let next_epoch = world
        .delivery_service()
        .conversation_epoch(&group_id)
        .expect("mock should know the conversation epoch") as i32
        + 1;

    // A prior receipt at a DIFFERENT epoch is not equivocation, even with a
    // different commit hash.
    let unrelated = SequencerReceipt {
        convo_id: group_id.clone(),
        epoch: next_epoch + 10,
        sequencer_term: 0,
        commit_hash: vec![0xBB; 32],
        sequencer_did: "did:web:sequencer.test".to_string(),
        issued_at: chrono::Utc::now().timestamp(),
        signature: vec![],
    };
    alice
        .storage
        .store_sequencer_receipt(&unrelated)
        .await
        .expect("pre-store unrelated receipt");

    alice
        .orchestrator
        .force_rejoin(&group_id)
        .await
        .expect("force_rejoin failed");

    assert!(
        observer.equivocations().is_empty(),
        "non-equivocating receipts must not fire detection, got: {:?}",
        observer.equivocations()
    );
    assert!(
        observer.credential_warnings().is_empty(),
        "no credential warnings expected in this flow"
    );

    // The genuinely sequenced receipt was still stored alongside the
    // unrelated one.
    let stored = alice
        .storage
        .get_sequencer_receipts(&group_id, None)
        .await
        .expect("get_sequencer_receipts");
    assert_eq!(stored.len(), 2, "expected pre-stored + new receipt");
    assert!(
        stored
            .iter()
            .any(|r| r.epoch == next_epoch && r.commit_hash != vec![0xBB; 32]),
        "the sequencer-issued receipt for the External Commit must be stored"
    );
}

// ---------------------------------------------------------------------------
// (e) WS-3 stage 2 / N44a: server reset clears stored receipts, so receipts
//     from before the reset cannot false-positive against post-reset
//     receipts at the same epoch number. The genuine SAME-generation case
//     (no reset in between) still firing is pinned by
//     `equivocating_receipts_fire_detection_and_recovery_proceeds` above.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn reset_boundary_clears_receipts_and_post_reset_receipt_is_silent() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("reset-receipt-boundary", None, None)
        .await
        .expect("create_group failed");
    let convo_id = convo.conversation_id.clone();

    world
        .delivery_service()
        .issue_external_commit_receipts_for_test(true);

    // The mock assigns epoch = current + 1 to the next External Commit, and a
    // client-side reset ingestion does not touch the mock's epoch counter —
    // so the post-reset receipt below lands at exactly this epoch number.
    let next_epoch = world
        .delivery_service()
        .conversation_epoch(&convo_id)
        .expect("mock should know the conversation epoch") as i32
        + 1;

    // Pre-reset receipt at that same (conversation, epoch) with a DIFFERENT
    // commit hash. Without the N44a clear, the genuine post-reset receipt
    // would false-positive the equivocation check against this stale row.
    let pre_reset = SequencerReceipt {
        convo_id: convo_id.clone(),
        epoch: next_epoch,
        sequencer_term: 0,
        commit_hash: vec![0xAA; 32],
        sequencer_did: "did:web:sequencer.test".to_string(),
        issued_at: chrono::Utc::now().timestamp(),
        signature: vec![],
    };
    alice
        .storage
        .store_sequencer_receipt(&pre_reset)
        .await
        .expect("pre-store pre-reset receipt");

    // A server group reset is ingested. The reset-ingestion path
    // (`persist_reset_pending_state`) must clear the conversation's stored
    // receipts alongside its other fresh-start mirrors.
    // This receipt-boundary test deliberately reuses the mock server's only
    // cryptographically valid GroupInfo. Remove the local instance first so
    // the same-ID reset is not classified as a live self-echo. Production
    // resets normally rotate to a new group ID, but the mock cannot mint a
    // detached authoritative GroupInfo for an arbitrary replacement ID.
    let new_group_id = hex::decode(&convo.group_id).expect("created group id must be valid hex");
    alice
        .orchestrator
        .mls_context()
        .delete_group(new_group_id.clone())
        .expect("remove local group before isolated reset-boundary fixture");
    alice
        .orchestrator
        .record_group_reset(&convo_id, new_group_id.clone(), 1)
        .await
        .expect("record_group_reset failed");

    assert!(
        alice
            .storage
            .get_sequencer_receipts(&convo_id, None)
            .await
            .expect("get_sequencer_receipts after reset")
            .is_empty(),
        "ingesting a server reset must clear stored sequencer receipts for \
         the conversation (N44a) — the reset rebuilds the group, so cross-\
         boundary receipt comparison is meaningless"
    );

    // This test isolates receipt-boundary behavior from reset recovery. Model
    // the generation-bound completion CAS before deliberately using the
    // internal non-reset force_rejoin path to obtain a fresh receipt. Direct
    // force_rejoin is prohibited while ResetPending remains authoritative.
    assert!(alice
        .storage
        .complete_reset_pending(&convo_id, 1, &hex::encode(&new_group_id), 0)
        .await
        .expect("complete reset boundary for receipt test"));
    alice
        .orchestrator
        .conversation_states()
        .lock()
        .await
        .insert(convo_id.clone(), ConversationState::Active);

    // Post-reset recovery obtains a genuine sequencer receipt at the SAME
    // epoch number the pre-reset receipt occupied. It must NOT fire
    // equivocation detection.
    alice
        .orchestrator
        .force_rejoin(&convo_id)
        .await
        .expect("post-reset force_rejoin failed");

    assert!(
        observer.equivocations().is_empty(),
        "a post-reset receipt at a recycled epoch number must not fire \
         equivocation detection after the reset cleared prior receipts, \
         got: {:?}",
        observer.equivocations()
    );

    // The post-reset receipt itself is stored for future same-generation
    // comparisons.
    let stored = alice
        .storage
        .get_sequencer_receipts(&convo_id, None)
        .await
        .expect("get_sequencer_receipts after rejoin");
    assert_eq!(
        stored.len(),
        1,
        "exactly the post-reset receipt should be stored, got: {stored:?}"
    );
    assert_eq!(stored[0].epoch, next_epoch);
    assert_ne!(
        stored[0].commit_hash,
        vec![0xAA; 32],
        "the stored receipt must be the genuine post-reset one, not the \
         stale pre-reset fixture"
    );
}

// ---------------------------------------------------------------------------
// (f) WS-3 stage 2 / N44b: inbound envelope sender spoofing (ADR-009 D4)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn honest_inbound_sender_is_silent_and_message_processes() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;
    let convo = alice
        .orchestrator
        .create_group("inbound-honest", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let group_id = convo.group_id.clone();

    let bob = world.client("Bob");
    let welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&group_id)
        .await
        .expect("bob get_welcome failed");
    bob.orchestrator
        .join_group(&welcome)
        .await
        .expect("bob join_group failed");

    bob.orchestrator
        .send_message(&group_id, "hello from bob")
        .await
        .expect("bob send_message failed");

    let alice = world.client("Alice");
    let (fetched, _cursor) = alice
        .orchestrator
        .fetch_messages(&group_id, None, 100, None, None, None)
        .await
        .expect("alice fetch_messages failed");
    assert!(
        fetched.iter().any(|m| m.text == "hello from bob"),
        "honest message must be processed and returned, got: {:?}",
        fetched.iter().map(|m| m.text.clone()).collect::<Vec<_>>()
    );
    assert!(
        observer.credential_warnings().is_empty(),
        "honest traffic must not produce inbound credential warnings, got: {:?}",
        observer.credential_warnings()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spoofed_envelope_sender_is_rejected_before_message_delivery() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();
    let mallory_did = "did:plc:mallory".to_string();

    let alice = world.client("Alice");
    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let convo = alice
        .orchestrator
        .create_group("inbound-spoofed", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(&convo.conversation_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("add Bob");
    let group_id = convo.group_id.clone();

    let bob = world.client("Bob");
    let welcome = bob
        .orchestrator
        .api_client()
        .get_welcome(&group_id)
        .await
        .expect("bob get_welcome failed");
    bob.orchestrator
        .join_group(&welcome)
        .await
        .expect("bob join_group failed");

    // Bob sends a GENUINE MLS ciphertext...
    bob.orchestrator
        .send_message(&group_id, "genuine bytes, lying envelope")
        .await
        .expect("bob send_message failed");

    // ...but the malicious DS relabels the envelope's sender to Mallory.
    // Only the routing hint lies; the MLS frame is untouched and decrypts.
    world
        .delivery_service()
        .relabel_envelope_sender_for_test(&bob_did, &mallory_did);

    let alice = world.client("Alice");
    let error = alice
        .orchestrator
        .fetch_messages(&group_id, None, 100, None, None, None)
        .await
        .expect_err("spoofed envelope sender must fail application DID binding");
    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert!(error.to_string().contains("credential binding"));

    // The D4 enforcement check also remains observable through the legacy
    // warning-named observer callback.
    let warnings = observer.credential_warnings();
    let w = warnings
        .iter()
        .find(|w| w.operation == "message")
        .unwrap_or_else(|| {
            panic!("expected an inbound (operation=message) credential warning, got {warnings:?}")
        });
    assert_eq!(
        w.expected_did, mallory_did,
        "the warning's expected DID is the envelope's (spoofed) claim"
    );
    assert!(
        w.claimed_identity.starts_with(&bob_did),
        "the warning's claimed identity is the MLS credential's (genuine) \
         identity, got: {}",
        w.claimed_identity
    );
    assert!(
        w.reason.contains("does not match"),
        "reason should describe the sender mismatch, got: {}",
        w.reason
    );
    assert!(w.convo_id == group_id || w.convo_id == convo.conversation_id);
}

// ---------------------------------------------------------------------------
// (g) WS-3 stage 2 / N44c: authorized-device-key binding seam (ADR-009 full
//     check, enforced). TestWorld seeds authority only during explicit fixture
//     registration; validation never trusts keys learned from the DS response.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn device_key_mismatch_rejects_add_without_epoch_change() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    // Preserve Bob's genuine fixture-authorized key for the legitimate retry.
    let refs = alice
        .orchestrator
        .api_client()
        .get_key_packages(
            "00000000-0000-4000-8000-000000000001",
            std::slice::from_ref(&bob_did),
        )
        .await
        .expect("read Bob fixture package");
    let bob_key = extract_key_package_binding(&refs[0].key_package_data)
        .expect("decode Bob fixture package")
        .signature_key;

    // Alice's platform resolves Bob's authorized device keys — but to a set
    // that does NOT contain the signing key in Bob's published key packages
    // (e.g. a stale or revoked device record).
    alice
        .credentials
        .set_authorized_device_keys(&bob_did, vec![vec![0xEE; 32]]);

    let convo = alice
        .orchestrator
        .create_group("device-key-mismatch", None, None)
        .await
        .expect("create_group failed");

    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&convo.group_id).unwrap())
        .unwrap();
    let error = world
        .client("Alice")
        .orchestrator
        .swap_members(&convo.group_id, &[], &[bob_did.clone()])
        .await
        .expect_err("unauthorized device key must reject add_members");
    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&convo.group_id).unwrap())
            .unwrap(),
        epoch_before,
        "rejected device key must not stage or merge a commit"
    );

    let warnings = observer.credential_warnings();
    let w = warnings
        .iter()
        .find(|w| w.reason.contains("authorized device key"))
        .unwrap_or_else(|| panic!("expected a device-key binding warning, got {warnings:?}"));
    assert_eq!(w.operation, "fetch");
    assert_eq!(
        w.expected_did, bob_did,
        "device-key warnings are keyed by the credential's root DID"
    );
    assert!(
        w.claimed_identity.starts_with(&bob_did),
        "claimed identity should be Bob's credential identity, got: {}",
        w.claimed_identity
    );

    alice
        .credentials
        .set_authorized_device_keys(&bob_did, vec![bob_key]);
    alice.orchestrator.invalidate_device_key_cache().await;
    alice
        .orchestrator
        .swap_members(&convo.group_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect("valid retry proves rejection left no pending commit");
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_device_key_resolution_rejects_before_staging() {
    let mut world = TestWorld::new();
    world.add_client_with_did("Alice", "did:plc:z72i7hdynmk6r22z27h6tvur").await;
    world.add_client_with_did("Bob", "did:plc:ewvi7nxzyoun6zhxrhs64oiz").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("unsupported-device-resolution", None, None)
        .await
        .expect("create_group failed");
    let group_id = hex::decode(&convo.group_id).unwrap();
    let epoch_before = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id.clone())
        .unwrap();

    alice.credentials.clear_authorized_device_keys(&bob_did);
    alice.orchestrator.invalidate_device_key_cache().await;
    let error = alice
        .orchestrator
        .swap_members(&convo.group_id, &[], std::slice::from_ref(&bob_did))
        .await
        .expect_err("missing device resolver authority must fail closed");

    assert!(matches!(error, OrchestratorError::InvalidInput(_)));
    assert!(error.to_string().contains("unsupported"));
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(group_id)
            .unwrap(),
        epoch_before,
        "unsupported resolution must not stage or merge an MLS commit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_atomic_swap_rejects_device_mismatch_and_resolver_failure() {
    let mut world = TestWorld::new();
    for name in ["Alice", "Bob", "Mallory"] {
        world.add_client(name).await;
        world.register_device(name).await.unwrap();
    }

    let alice = world.client("Alice");
    let bob_did = world.client("Bob").did.clone();
    let mallory_did = world.client("Mallory").did.clone();
    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    let mallory_refs = alice
        .orchestrator
        .api_client()
        .get_key_packages(
            "00000000-0000-4000-8000-000000000001",
            std::slice::from_ref(&mallory_did),
        )
        .await
        .expect("read Mallory fixture package");
    let mallory_key = extract_key_package_binding(&mallory_refs[0].key_package_data)
        .expect("decode Mallory fixture package")
        .signature_key;

    alice
        .credentials
        .set_authorized_device_keys(&mallory_did, vec![vec![0xEE; 32]]);
    let mismatch_group = alice
        .orchestrator
        .create_group("mismatch swap", None, None)
        .await
        .expect("create group");
    alice
        .orchestrator
        .swap_members(
            &mismatch_group.conversation_id,
            &[],
            std::slice::from_ref(&bob_did),
        )
        .await
        .expect("add Bob");
    let mismatch_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&mismatch_group.group_id).unwrap())
        .unwrap();
    alice
        .orchestrator
        .swap_members(
            &mismatch_group.group_id,
            std::slice::from_ref(&bob_did),
            std::slice::from_ref(&mallory_did),
        )
        .await
        .expect_err("legacy group-id route must reject device-key mismatch");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&mismatch_group.group_id).unwrap())
            .unwrap(),
        mismatch_epoch
    );

    let resolver_group = alice
        .orchestrator
        .create_group("legacy swap resolver failure", None, None)
        .await
        .expect("create resolver-failure group");
    alice
        .orchestrator
        .swap_members(
            &resolver_group.conversation_id,
            &[],
            std::slice::from_ref(&bob_did),
        )
        .await
        .expect("add Bob");
    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&mallory_did, true);
    alice.orchestrator.invalidate_device_key_cache().await;
    let resolver_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(hex::decode(&resolver_group.group_id).unwrap())
        .unwrap();
    alice
        .orchestrator
        .swap_members(
            &resolver_group.group_id,
            std::slice::from_ref(&bob_did),
            std::slice::from_ref(&mallory_did),
        )
        .await
        .expect_err("legacy group-id route must reject resolver failure");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(hex::decode(&resolver_group.group_id).unwrap())
            .unwrap(),
        resolver_epoch
    );

    let warnings = observer.credential_warnings();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.reason.contains("authorized device key")),
        "device-key mismatch must remain observable: {warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.reason.contains("resolution failed")),
        "resolver failure must remain observable: {warnings:?}"
    );

    alice
        .credentials
        .set_authorized_device_key_resolution_failure(&mallory_did, false);
    alice
        .credentials
        .set_authorized_device_keys(&mallory_did, vec![mallory_key]);
    alice.orchestrator.invalidate_device_key_cache().await;
    alice
        .orchestrator
        .swap_members(
            &resolver_group.group_id,
            std::slice::from_ref(&bob_did),
            std::slice::from_ref(&mallory_did),
        )
        .await
        .expect("valid retry proves resolver rejection left no pending commit");
}

#[tokio::test(flavor = "multi_thread")]
async fn device_key_match_is_silent_and_cached_within_ttl() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.add_client("Bob").await;
    world.register_device("Alice").await.unwrap();
    let bob_did = world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");

    // Learn Bob's genuine device signing key by structurally decoding one of
    // his published key packages (same persistent signer across packages).
    let refs = alice
        .orchestrator
        .api_client()
        .get_key_packages("00000000-0000-4000-8000-000000000001", &[bob_did.clone()])
        .await
        .expect("get_key_packages failed");
    assert!(!refs.is_empty(), "Bob should have published key packages");
    let bob_key = extract_key_package_binding(&refs[0].key_package_data)
        .expect("decode Bob's key package")
        .signature_key;

    // Alice's platform resolves Bob's DID to exactly that key.
    alice
        .credentials
        .set_authorized_device_keys(&bob_did, vec![bob_key]);

    let observer = Arc::new(RecordingObserver::default());
    alice
        .orchestrator
        .set_event_observer(Some(observer.clone()))
        .await;

    // First add: resolves Bob's device keys once, key matches → silent.
    let convo1 = alice
        .orchestrator
        .create_group("device-key-match-1", None, None)
        .await
        .expect("create_group 1 failed");
    world
        .client("Alice")
        .orchestrator
        .swap_members(&convo1.group_id, &[], &[bob_did.clone()])
        .await
        .expect("add_members 1 failed");

    assert!(
        observer.credential_warnings().is_empty(),
        "matching device key must not warn, got: {:?}",
        observer.credential_warnings()
    );
    let alice = world.client("Alice");
    assert_eq!(
        alice.credentials.device_key_lookup_count(&bob_did),
        1,
        "first verification must resolve Bob's device keys exactly once"
    );

    // Second add (fresh group, fresh key-package fetch) within the ADR-009
    // D6 TTL: served from the per-DID cache — no repeat resolution.
    let convo2 = alice
        .orchestrator
        .create_group("device-key-match-2", None, None)
        .await
        .expect("create_group 2 failed");
    alice
        .orchestrator
        .swap_members(&convo2.group_id, &[], &[bob_did.clone()])
        .await
        .expect("add_members 2 failed");

    assert!(
        observer.credential_warnings().is_empty(),
        "second matching fetch must also stay silent, got: {:?}",
        observer.credential_warnings()
    );
    assert_eq!(
        alice.credentials.device_key_lookup_count(&bob_did),
        1,
        "ADR-009 D6: lookups within the TTL must be served from the cache \
         (no network in hot paths beyond the first resolution)"
    );
}
