//! Account exits retain historical keys and exact durable signed evidence.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    account_exit::AccountExitRecord,
    canonical_transport::{CanonicalOperation, PreparedRequest},
    lifecycle::LeaveOutcome,
    ConversationState, GroupState, MLSAPIClient, MLSStorageBackend, MlsCryptoContext,
};
use catbird_mls::KeyPackageData;
use e2e_harness::TestWorld;
use serde_json::{json, Value};

const ALICE: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
const CHARLIE: &str = "did:plc:cccccccccccccccccccccccc";

struct ExitFixture {
    world: TestWorld,
    cid: String,
    group: Vec<u8>,
    current: Value,
    history_key: Vec<u8>,
    close: bool,
}

async fn fixture(close: bool) -> ExitFixture {
    let mut world = TestWorld::new();
    for (name, did) in [("Alice", ALICE), ("Bob", BOB), ("Charlie", CHARLIE)] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    let members = if close {
        vec![BOB.into()]
    } else {
        vec![BOB.into(), CHARLIE.into()]
    };
    let created = alice
        .orchestrator
        .create_group("History survives exit", Some(&members), None)
        .await
        .unwrap();
    let cid = created.conversation_id;
    let group = hex::decode(created.group_id).unwrap();
    let bob = world.client("Bob");
    let bob_identity = format!(
        "{BOB}#{}",
        bob.orchestrator.require_actor_device_id().await.unwrap()
    );
    let package = bob
        .orchestrator
        .mls_context()
        .create_key_package(bob_identity.as_bytes().to_vec())
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
        .process_welcome(added.welcome_data, bob_identity.into_bytes(), None)
        .unwrap();
    let projection = GroupState {
        conversation_id: cid.clone(),
        group_id: hex::encode(&group),
        epoch: 1,
        members: alice
            .orchestrator
            .mls_context()
            .group_member_identities(group.clone())
            .unwrap()
            .into_iter()
            .map(|id| String::from_utf8(id).unwrap())
            .collect(),
    };
    alice.storage.set_group_state(&projection).await.unwrap();
    alice.storage.set_epoch_pair_for_test(&cid, 1, 1);
    alice
        .storage
        .set_conversation_state(&cid, ConversationState::Active)
        .await
        .unwrap();
    alice
        .storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "history-before-account-exit".into(),
            conversation_id: cid.clone(),
            sender_did: BOB.into(),
            text: "Keep this conversation and its keys".into(),
            timestamp: chrono::Utc::now(),
            epoch: 1,
            sequence_number: 8,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    let history_key = alice
        .orchestrator
        .mls_context()
        .export_metadata_key(group.clone(), 1)
        .unwrap();
    if !close {
        // The server has removed Alice's leaf; this offline device deliberately
        // retains epoch 1 and its history while a new invitation is pending.
        let own_identity = format!(
            "{ALICE}#{}",
            alice.orchestrator.require_actor_device_id().await.unwrap()
        );
        bob.orchestrator
            .mls_context()
            .remove_members(group.clone(), vec![own_identity.into_bytes()])
            .unwrap();
        bob.orchestrator
            .mls_context()
            .merge_pending_commit(group.clone())
            .unwrap();
    }
    let authority = if close { alice } else { bob };
    let coordinates = json!({
        "conversationId":cid, "groupId":STANDARD.encode(&group), "generation":0,
        "stateVersion":19, "epoch":if close { 1 } else { 2 }, "lifecycle":"active",
        "confirmationTag":STANDARD.encode(authority.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),
        "groupContextHash":STANDARD.encode(authority.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap()),
    });
    let participants = if close {
        json!([{"userDid":ALICE,"status":"active","role":"admin","leafCount":1},
            {"userDid":BOB,"status":"active","role":"admin","leafCount":1}])
    } else {
        json!([{"userDid":ALICE,"status":"pending","role":"member","leafCount":0},
            {"userDid":BOB,"status":"active","role":"admin","leafCount":1},
            {"userDid":CHARLIE,"status":"pending","role":"member","leafCount":0}])
    };
    let mut leaves = vec![
        json!({"userDid":BOB, "deviceId":bob.orchestrator.require_actor_device_id().await.unwrap(), "leafIndex":1,"deviceStatus":"active"}),
    ];
    if close {
        leaves.push(json!({"userDid":ALICE,"deviceId":alice.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":0,"deviceStatus":"active"}));
    }
    let current = json!({"conversationKind":if close {"direct"} else {"group"}, "snapshotSeq":19,
        "coordinates":coordinates,"participants":participants,"leaves":leaves,"metadataSnapshot":{"metadataVersion":1}});
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, current.clone());
    world
        .delivery_service()
        .set_conversation_participants_for_test(&cid, participants.as_array().unwrap().clone());
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&cid, if close { 1 } else { 2 });
    ExitFixture {
        world,
        cid,
        group,
        current,
        history_key,
        close,
    }
}

async fn fresh_leafless_direct_fixture() -> ExitFixture {
    let mut f = fixture(true).await;
    f.world.add_client_with_did("FreshAlice", ALICE).await;
    f.world.register_device("FreshAlice").await.unwrap();
    let phone = f.world.client("FreshAlice");
    // A retained conversation/history row does not give this newly registered
    // phone an MLS leaf. Alice's other real device remains an active member.
    phone
        .storage
        .ensure_conversation_exists(ALICE, &f.cid, &hex::encode(&f.group))
        .await
        .unwrap();
    phone
        .storage
        .set_conversation_state(&f.cid, ConversationState::DeviceRemoved)
        .await
        .unwrap();
    phone
        .storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "history-on-leafless-phone".into(),
            conversation_id: f.cid.clone(),
            sender_did: BOB.into(),
            text: "Retain the history on this phone".into(),
            timestamp: chrono::Utc::now(),
            epoch: 1,
            sequence_number: 8,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    assert!(phone
        .orchestrator
        .mls_context()
        .get_epoch(f.group.clone())
        .is_err());
    assert!(phone
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
        .is_empty());
    let device = phone.orchestrator.require_actor_device_id().await.unwrap();
    assert!(f.current["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .all(|leaf| leaf["deviceId"] != device));
    f
}

fn phone_exit_records(f: &ExitFixture) -> Vec<AccountExitRecord> {
    f.world
        .client("FreshAlice")
        .orchestrator
        .mls_context()
        .list_account_exits()
        .unwrap()
}

async fn assert_leafless_phone_history(f: &ExitFixture, terminal: ConversationState) {
    let phone = f.world.client("FreshAlice");
    assert_eq!(
        phone.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(terminal)
    );
    assert!(phone
        .storage
        .message_exists("history-on-leafless-phone")
        .await
        .unwrap());
    assert!(phone
        .storage
        .get_conversation(ALICE, &f.cid)
        .await
        .unwrap()
        .is_some());
    assert!(phone
        .orchestrator
        .mls_context()
        .get_epoch(f.group.clone())
        .is_err());
    assert!(phone
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
        .is_empty());
    assert_history(f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_leafless_close_completes_after_exact_not_entitled_and_reopens() {
    let mut f = fresh_leafless_direct_fixture().await;
    f.world
        .delivery_service()
        .set_account_exit_state_response_for_test(
            &f.cid,
            true,
            400,
            br#"{"error":"NotEntitled"}"#.to_vec(),
        );
    let before = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    assert_eq!(
        f.world
            .client("FreshAlice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .expect(
                "a validated accepted close must survive the exact post-exit NotEntitled response"
            ),
        LeaveOutcome::Left,
    );
    let completed = phone_exit_records(&f);
    assert_eq!(completed.len(), 1);
    assert!(completed[0].accepted_response.is_some());
    assert!(completed[0].local_completion);
    assert_eq!(
        signed_body(&completed[0])["actorDeviceId"],
        f.world
            .client("FreshAlice")
            .orchestrator
            .require_actor_device_id()
            .await
            .unwrap()
    );
    assert_eq!(requests(&f).len(), 1);
    assert_eq!(
        requests(&f)[0].body.as_ref(),
        Some(&completed[0].request_body)
    );
    assert_leafless_phone_history(&f, ConversationState::Closed).await;

    f.world.restart_client("FreshAlice").await;
    assert_eq!(phone_exit_records(&f), completed);
    f.world
        .client("FreshAlice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    assert_eq!(
        f.world
            .client("FreshAlice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap(),
        LeaveOutcome::Left
    );
    assert_eq!(phone_exit_records(&f), completed);
    assert_eq!(
        requests(&f).len(),
        1,
        "the accepted close must not be resubmitted"
    );
    assert_leafless_phone_history(&f, ConversationState::Closed).await;
    assert_eq!(
        f.world
            .client("FreshAlice")
            .storage
            .get_conversation_messages(&f.cid)
            .iter()
            .filter(|message| message.id.starts_with("conversation-closed:"))
            .count(),
        1
    );
    assert_no_recovery_mutation(&f, before);
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_not_entitled_close_retries_durable_projection_after_native_reopen() {
    let mut f = fresh_leafless_direct_fixture().await;
    f.world
        .delivery_service()
        .set_account_exit_state_response_for_test(
            &f.cid,
            true,
            400,
            br#"{"error":"NotEntitled","message":"No active account membership"}"#.to_vec(),
        );
    f.world
        .client("FreshAlice")
        .storage
        .fail_next_set_conversation_state();
    let error = f
        .world
        .client("FreshAlice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            catbird_mls::orchestrator::OrchestratorError::Storage(_)
        ),
        "exact NotEntitled must reach the injected host projection failure: {error:?}"
    );
    let pending = phone_exit_records(&f);
    assert_eq!(pending.len(), 1);
    assert!(pending[0].accepted_response.is_some());
    assert!(!pending[0].local_completion);
    assert_leafless_phone_history(&f, ConversationState::DeviceRemoved).await;
    assert_eq!(requests(&f).len(), 1);
    f.world.restart_client("FreshAlice").await;
    assert_eq!(phone_exit_records(&f), pending);
    f.world
        .client("FreshAlice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    let completed = phone_exit_records(&f);
    assert_eq!(completed.len(), 1);
    assert!(completed[0].local_completion);
    assert_eq!(completed[0].request_body, pending[0].request_body);
    assert_eq!(completed[0].accepted_response, pending[0].accepted_response);
    assert_eq!(
        requests(&f).len(),
        1,
        "restart must use the saved accepted entry, without another close"
    );
    assert_leafless_phone_history(&f, ConversationState::Closed).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_exit_rejects_responses_that_are_not_exact_not_entitled() {
    let cases: &[(&str, u16, &[u8])] = &[
        ("another error", 400, br#"{"error":"InvalidRequest"}"#),
        ("truncated JSON", 400, br#"{"error":"NotEntitled""#),
        (
            "duplicate error",
            400,
            br#"{"error":"InvalidRequest","error":"NotEntitled"}"#,
        ),
        ("numeric error", 400, br#"{"error":400}"#),
        ("nested error", 400, br#"{"error":{"error":"NotEntitled"}}"#),
        (
            "wrong message type",
            400,
            br#"{"error":"NotEntitled","message":42}"#,
        ),
        ("wrong status", 409, br#"{"error":"NotEntitled"}"#),
        ("authentication failure", 401, br#"{"error":"NotEntitled"}"#),
        ("server failure", 500, br#"{"error":"NotEntitled"}"#),
    ];
    for (name, status, body) in cases {
        let f = fixture(true).await;
        f.world
            .delivery_service()
            .set_account_exit_state_response_for_test(&f.cid, true, *status, body.to_vec());
        let error = f
            .world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap_err();
        assert!(
            matches!(error, catbird_mls::orchestrator::OrchestratorError::ServerError { status: actual, .. } if actual == *status),
            "{name}: unexpected error {error:?}"
        );
        let pending = records(&f);
        assert_eq!(pending.len(), 1, "{name}");
        assert!(
            pending[0].accepted_response.is_some(),
            "{name}: preserve the validated accepted receipt"
        );
        assert!(
            !pending[0].local_completion,
            "{name}: do not project a terminal state on another error"
        );
        assert_eq!(
            f.world
                .client("Alice")
                .storage
                .get_conversation_state(&f.cid)
                .await
                .unwrap(),
            Some(ConversationState::Active),
            "{name}"
        );
        assert!(markers(&f).is_empty(), "{name}");
        assert_history(&f).await;
        assert_eq!(requests(&f).len(), 1, "{name}");
        // A later recognized terminal response completes the already accepted
        // operation, preserving its signed bytes and without resubmission.
        f.world
            .delivery_service()
            .set_account_exit_state_response_for_test(
                &f.cid,
                true,
                403,
                br#"{"error":"AccessOutsideMembershipInterval"}"#.to_vec(),
            );
        assert_eq!(
            f.world
                .client("Alice")
                .orchestrator
                .leave_conversation(&f.cid)
                .await
                .unwrap(),
            LeaveOutcome::Left,
            "{name}"
        );
        assert_eq!(
            records(&f)[0].request_body,
            pending[0].request_body,
            "{name}"
        );
        assert_eq!(
            records(&f)[0].accepted_response,
            pending[0].accepted_response,
            "{name}"
        );
        assert_eq!(requests(&f).len(), 1, "{name}");
        assert_terminal(&f).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_active_leaf_close_completes_after_exact_access_outside_interval() {
    let mut f = fixture(true).await;
    let alice = f.world.client("Alice");
    assert!(alice
        .orchestrator
        .mls_context()
        .group_is_active(f.group.clone())
        .unwrap());
    f.world
        .delivery_service()
        .set_account_exit_state_response_for_test(
            &f.cid,
            true,
            400,
            br#"{"error":"AccessOutsideMembershipInterval"}"#.to_vec(),
        );
    assert_eq!(
        alice.orchestrator.leave_conversation(&f.cid).await.unwrap(),
        LeaveOutcome::Left
    );
    let completed = records(&f);
    assert_eq!(completed.len(), 1);
    assert!(completed[0].accepted_response.is_some());
    assert!(completed[0].local_completion);
    assert_terminal(&f).await;
    f.world.restart_client("Alice").await;
    f.world
        .client("Alice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    assert_eq!(records(&f), completed);
    assert_eq!(requests(&f).len(), 1);
    assert_terminal(&f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_zero_leaf_leave_keeps_access_outside_interval_unresolved() {
    let f = fixture(false).await;
    f.world
        .delivery_service()
        .set_account_exit_state_response_for_test(
            &f.cid,
            true,
            400,
            br#"{"error":"AccessOutsideMembershipInterval"}"#.to_vec(),
        );
    let error = f
        .world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        catbird_mls::orchestrator::OrchestratorError::ServerError { status: 400, .. }
    ));
    let pending = records(&f);
    assert_eq!(pending.len(), 1);
    assert!(pending[0].accepted_response.is_some());
    assert!(
        !pending[0].local_completion,
        "device access denial cannot prove absence of a later account re-invitation"
    );
    assert!(markers(&f).is_empty());
    assert_history(&f).await;
    assert_eq!(requests(&f).len(), 1);
    // Exact account-level absence permits completion from the same receipt.
    f.world
        .delivery_service()
        .set_account_exit_state_response_for_test(
            &f.cid,
            true,
            400,
            br#"{"error":"NotEntitled"}"#.to_vec(),
        );
    assert_eq!(
        f.world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap(),
        LeaveOutcome::Left
    );
    assert_eq!(records(&f)[0].request_body, pending[0].request_body);
    assert_eq!(
        records(&f)[0].accepted_response,
        pending[0].accepted_response
    );
    assert_eq!(requests(&f).len(), 1);
    assert_terminal(&f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn not_entitled_without_an_accepted_exit_is_not_terminal_authority() {
    let f = fresh_leafless_direct_fixture().await;
    f.world
        .delivery_service()
        .set_account_exit_state_response_for_test(
            &f.cid,
            false,
            400,
            br#"{"error":"NotEntitled"}"#.to_vec(),
        );
    let error = f
        .world
        .client("FreshAlice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        catbird_mls::orchestrator::OrchestratorError::ServerError { status: 400, .. }
    ));
    assert!(phone_exit_records(&f).is_empty());
    assert!(requests(&f).is_empty());
    assert_leafless_phone_history(&f, ConversationState::DeviceRemoved).await;
    assert!(!f
        .world
        .client("FreshAlice")
        .storage
        .get_conversation_messages(&f.cid)
        .iter()
        .any(|message| message.id.starts_with("conversation-closed:")));
}

fn requests(f: &ExitFixture) -> Vec<PreparedRequest> {
    f.world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|request| {
            matches!(
                request.operation,
                CanonicalOperation::CloseConversation | CanonicalOperation::RequestLeave
            )
        })
        .collect()
}
fn records(f: &ExitFixture) -> Vec<AccountExitRecord> {
    f.world
        .client("Alice")
        .orchestrator
        .mls_context()
        .list_account_exits()
        .unwrap()
}
fn signed_body(record: &AccountExitRecord) -> Value {
    serde_json::from_slice::<Value>(&record.request_body).unwrap()["signedRequest"]["body"].clone()
}
fn markers(f: &ExitFixture) -> Vec<String> {
    f.world
        .client("Alice")
        .storage
        .get_conversation_messages(&f.cid)
        .into_iter()
        .filter(|message| {
            message.id.starts_with("membership-left:")
                || message.id.starts_with("conversation-closed:")
        })
        .map(|message| message.id)
        .collect()
}
async fn assert_history(f: &ExitFixture) {
    let alice = f.world.client("Alice");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(f.group.clone())
            .unwrap(),
        1
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .export_metadata_key(f.group.clone(), 1)
            .unwrap(),
        f.history_key
    );
    assert!(alice
        .storage
        .get_conversation(ALICE, &f.cid)
        .await
        .unwrap()
        .is_some());
    assert!(alice
        .storage
        .message_exists("history-before-account-exit")
        .await
        .unwrap());
}
async fn assert_terminal(f: &ExitFixture) {
    assert_history(f).await;
    let alice = f.world.client("Alice");
    assert_eq!(
        alice.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(if f.close {
            ConversationState::Closed
        } else {
            ConversationState::DeviceRemoved
        })
    );
    assert!(!alice.storage.needs_rejoin(&f.cid).await.unwrap());
    assert!(
        !alice
            .orchestrator
            .ensure_conversation_ready(&f.cid)
            .await
            .unwrap()
            .send_allowed
    );
}
fn assert_no_recovery_mutation(f: &ExitFixture, after: usize) {
    for request in &f.world.delivery_service().submitted_prepared_requests()[after..] {
        assert!(
            !matches!(
                request.operation,
                CanonicalOperation::RequestReset
                    | CanonicalOperation::ActivateReset
                    | CanonicalOperation::RequestLeafRecovery
                    | CanonicalOperation::SubmitTransition
                    | CanonicalOperation::AcceptConversation
            ),
            "an exit retry must not reset or replace membership"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn close_and_zero_leaf_leave_preserve_read_only_history_and_native_keys() {
    for close in [true, false] {
        let mut f = fixture(close).await;
        let before = f
            .world
            .delivery_service()
            .submitted_prepared_requests()
            .len();
        assert_eq!(
            f.world
                .client("Alice")
                .orchestrator
                .leave_conversation(&f.cid)
                .await
                .unwrap(),
            LeaveOutcome::Left
        );
        assert_terminal(&f).await;
        let proof = records(&f);
        assert_eq!(proof.len(), 1);
        assert!(proof[0].local_completion);
        assert!(proof[0].accepted_response.is_some());
        assert_eq!(requests(&f).len(), 1);
        assert_eq!(markers(&f).len(), 1);
        assert_eq!(proof[0].request_body, requests(&f)[0].body.clone().unwrap());
        assert_ne!(
            proof[0].accepted_response.as_ref().unwrap()["result"]["entry"]["entryId"],
            signed_body(&proof[0])["transitionId"],
            "server entry IDs are independent of client transition IDs"
        );
        f.world.restart_client("Alice").await;
        f.world
            .client("Alice")
            .orchestrator
            .startup_reconcile()
            .await
            .unwrap();
        assert_eq!(
            f.world
                .client("Alice")
                .orchestrator
                .leave_conversation(&f.cid)
                .await
                .unwrap(),
            LeaveOutcome::Left
        );
        assert_eq!(records(&f), proof);
        assert_eq!(requests(&f).len(), 1);
        assert_eq!(markers(&f).len(), 1);
        assert_terminal(&f).await;
        assert_no_recovery_mutation(&f, before);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_exit_with_lost_response_reopens_and_replays_exact_signed_bytes() {
    for close in [true, false] {
        let mut f = fixture(close).await;
        let before = f
            .world
            .delivery_service()
            .submitted_prepared_requests()
            .len();
        f.world
            .delivery_service()
            .lose_next_account_exit_responses(100);
        assert!(f
            .world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .is_err());
        assert_history(&f).await;
        let pending = records(&f);
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].local_completion);
        assert!(pending[0].accepted_response.is_none());
        assert!(markers(&f).is_empty());
        f.world.restart_client("Alice").await;
        assert_eq!(records(&f), pending);
        // Another ambiguous response during startup must still preserve the
        // exact unresolved intent and block destructive recovery for this CID.
        f.world
            .client("Alice")
            .orchestrator
            .startup_reconcile()
            .await
            .unwrap();
        assert_eq!(records(&f), pending);
        assert_history(&f).await;
        assert!(markers(&f).is_empty());
        assert_no_recovery_mutation(&f, before);
        f.world
            .delivery_service()
            .lose_next_account_exit_responses(0);
        f.world
            .client("Alice")
            .orchestrator
            .startup_reconcile()
            .await
            .unwrap();
        let completed = records(&f);
        assert_eq!(completed.len(), 1);
        assert!(completed[0].local_completion);
        assert!(completed[0].accepted_response.is_some());
        assert_eq!(completed[0].request_body, pending[0].request_body);
        assert!(requests(&f).len() >= 2);
        assert!(requests(&f)
            .iter()
            .all(|request| request.body.as_ref() == Some(&pending[0].request_body)));
        assert_eq!(markers(&f).len(), 1);
        assert_terminal(&f).await;
        assert_no_recovery_mutation(&f, before);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn saved_accepted_exit_retries_host_state_or_marker_without_resubmitting() {
    for close in [true, false] {
        for fail_state in [true, false] {
            let mut f = fixture(close).await;
            if fail_state {
                f.world
                    .client("Alice")
                    .storage
                    .fail_next_set_conversation_state();
            } else {
                f.world.client("Alice").storage.fail_next_store_message();
            }
            assert!(f
                .world
                .client("Alice")
                .orchestrator
                .leave_conversation(&f.cid)
                .await
                .is_err());
            let accepted = records(&f);
            assert_eq!(accepted.len(), 1);
            assert!(accepted[0].accepted_response.is_some());
            assert!(!accepted[0].local_completion);
            assert_history(&f).await;
            assert!(markers(&f).is_empty());
            let sent = requests(&f).len();
            f.world.restart_client("Alice").await;
            f.world
                .client("Alice")
                .orchestrator
                .startup_reconcile()
                .await
                .unwrap();
            assert_terminal(&f).await;
            assert_eq!(
                requests(&f).len(),
                sent,
                "accepted proof must retry local storage without another request"
            );
            let completed = records(&f);
            assert_eq!(
                completed[0].accepted_response,
                accepted[0].accepted_response
            );
            assert!(completed[0].local_completion);
            assert_eq!(markers(&f).len(), 1);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_accepted_exit_entry_is_rejected_without_terminal_projection() {
    for close in [true, false] {
        let f = fixture(close).await;
        f.world
            .delivery_service()
            .tamper_next_account_exit_entry_for_test();
        assert!(f
            .world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .is_err());
        let pending = records(&f);
        assert_eq!(pending.len(), 1);
        assert!(pending[0].accepted_response.is_none());
        assert!(!pending[0].local_completion);
        assert!(markers(&f).is_empty());
        assert_eq!(
            f.world
                .client("Alice")
                .storage
                .get_conversation_state(&f.cid)
                .await
                .unwrap(),
            Some(ConversationState::Active)
        );
        assert_history(&f).await;
        assert_eq!(
            f.world
                .client("Alice")
                .orchestrator
                .leave_conversation(&f.cid)
                .await
                .unwrap(),
            LeaveOutcome::Left
        );
        assert_eq!(requests(&f).len(), 2);
        assert_eq!(requests(&f)[0].body, requests(&f)[1].body);
        assert_terminal(&f).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_reinvitation_requires_a_new_explicit_exit_and_retains_old_proof() {
    let f = fixture(false).await;
    f.world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap();
    let old = records(&f)[0].clone();
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation(ALICE, &f.cid)
            .await
            .unwrap()
            .unwrap()
            .epoch,
        2
    );
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation_state(&f.cid)
            .await
            .unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    // The remaining peer advances real MLS state while the departed phone
    // stays offline. A later invitation has no new Welcome for this phone.
    let bob = f.world.client("Bob");
    bob.orchestrator
        .mls_context()
        .self_update(f.group.clone())
        .unwrap();
    bob.orchestrator
        .mls_context()
        .merge_pending_commit(f.group.clone())
        .unwrap();
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(f.group.clone())
            .unwrap(),
        3
    );
    let mut reinvited = f.current.clone();
    reinvited["coordinates"]["epoch"] = json!(3);
    reinvited["coordinates"]["confirmationTag"] = json!(STANDARD.encode(
        bob.orchestrator
            .mls_context()
            .get_confirmation_tag(f.group.clone())
            .unwrap()
    ));
    reinvited["coordinates"]["groupContextHash"] = json!(STANDARD.encode(
        bob.orchestrator
            .mls_context()
            .get_group_context_hash(f.group.clone())
            .unwrap()
    ));
    reinvited["coordinates"]["stateVersion"] = json!(22);
    reinvited["snapshotSeq"] = json!(22);
    f.world
        .delivery_service()
        .set_conversation_epoch_for_test(&f.cid, 3);
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
        .is_empty());
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, reinvited);
    assert_eq!(
        f.world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap(),
        LeaveOutcome::Left
    );
    let all = records(&f);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], old);
    assert_eq!(
        all[1].replaces_operation.as_deref(),
        signed_body(&old)["transitionId"].as_str()
    );
    assert_eq!(signed_body(&all[1])["prior"]["stateVersion"], 22);
    assert_eq!(signed_body(&all[1])["prior"]["epoch"], 3);
    assert_eq!(signed_body(&all[1])["next"]["epoch"], 3);
    assert_ne!(all[1].request_body, old.request_body);
    assert_eq!(requests(&f).len(), 2);
    assert_eq!(markers(&f).len(), 2);
    assert_terminal(&f).await;
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation(ALICE, &f.cid)
            .await
            .unwrap()
            .unwrap()
            .epoch,
        3,
        "the new accepted departure advances the durable removed tuple without a Welcome"
    );
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
        .is_empty());
    let route = catbird_mls::orchestrator::canonical_transport::canonical_route(
        CanonicalOperation::GetConversationState,
    );
    let device = f
        .world
        .client("Bob")
        .orchestrator
        .require_actor_device_id()
        .await
        .unwrap();
    let response = f
        .world
        .delivery_service()
        .clone_as(BOB)
        .submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversationState,
            path: format!(
                "{}?conversationId={}&actorDeviceId={device}",
                route.path, f.cid
            ),
            method: "GET".into(),
            body: None,
        })
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let current: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        current["state"]["participants"]
            .as_array()
            .unwrap()
            .iter()
            .all(|participant| participant["userDid"] != ALICE),
        "the newly invited zero-leaf account must actually be removed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_coordinates_background_retries_old_intent_but_explicit_leave_can_replace_it() {
    let f = fixture(false).await;
    f.world
        .delivery_service()
        .set_next_leave_custom_response(409, json!({"error":"StaleCoordinates"}));
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .is_err());
    let old = records(&f)[0].clone();
    let mut newer = f.current.clone();
    newer["coordinates"]["stateVersion"] = json!(20);
    newer["snapshotSeq"] = json!(20);
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, newer);
    f.world
        .delivery_service()
        .set_next_leave_custom_response(409, json!({"error":"StaleCoordinates"}));
    f.world
        .client("Alice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    assert_eq!(
        records(&f),
        vec![old.clone()],
        "background replay must not mint renewed user intent"
    );
    assert_eq!(requests(&f).len(), 2);
    assert!(requests(&f)
        .iter()
        .all(|request| request.body.as_ref() == Some(&old.request_body)));
    assert!(markers(&f).is_empty());
    f.world
        .delivery_service()
        .set_next_leave_custom_response(409, json!({"error":"StaleCoordinates"}));
    assert_eq!(
        f.world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap(),
        LeaveOutcome::Left
    );
    let all = records(&f);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], old);
    assert_eq!(
        all[1].replaces_operation.as_deref(),
        signed_body(&old)["transitionId"].as_str()
    );
    assert_eq!(signed_body(&all[1])["prior"]["stateVersion"], 20);
    assert_ne!(all[1].request_body, old.request_body);
    assert_eq!(requests(&f).len(), 4);
    assert_terminal(&f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn recreating_a_closed_direct_conversation_keeps_the_original_history() {
    let f = fixture(true).await;
    f.world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap();
    let created = f
        .world
        .client("Alice")
        .orchestrator
        .create_group("History survives exit", Some(&[BOB.into()]), None)
        .await
        .unwrap();
    assert_ne!(created.conversation_id, f.cid);
    assert_ne!(created.group_id, hex::encode(&f.group));
    assert_terminal(&f).await;
    assert!(f
        .world
        .client("Alice")
        .storage
        .get_conversation(ALICE, &created.conversation_id)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn obsolete_generation_exit_neither_replays_nor_blocks_a_native_successor() {
    let mut f = fixture(false).await;
    f.world
        .delivery_service()
        .set_next_leave_custom_response(409, json!({"error":"StaleCoordinates"}));
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .is_err());
    let pending = records(&f);
    let before = f
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    let alice = f.world.client("Alice");
    let identity = format!(
        "{ALICE}#{}",
        alice.orchestrator.require_actor_device_id().await.unwrap()
    );
    let successor = alice
        .orchestrator
        .mls_context()
        .create_group(identity.as_bytes().to_vec(), None)
        .unwrap()
        .group_id;
    let successor_hex = hex::encode(&successor);
    alice
        .storage
        .set_conversation_group_id_for_test(&f.cid, &successor_hex);
    alice
        .storage
        .set_group_state(&GroupState {
            conversation_id: f.cid.clone(),
            group_id: successor_hex.clone(),
            epoch: 0,
            members: vec![identity],
        })
        .await
        .unwrap();
    alice.storage.set_epoch_pair_for_test(&f.cid, 0, 0);
    alice
        .storage
        .set_conversation_state(&f.cid, ConversationState::Active)
        .await
        .unwrap();
    let mut current = f.current.clone();
    current["coordinates"] = json!({"conversationId":f.cid, "groupId":STANDARD.encode(&successor),
        "generation":1,"stateVersion":1,"epoch":0,"lifecycle":"active",
        "confirmationTag":STANDARD.encode(alice.orchestrator.mls_context().get_confirmation_tag(successor.clone()).unwrap()),
        "groupContextHash":STANDARD.encode(alice.orchestrator.mls_context().get_group_context_hash(successor.clone()).unwrap())});
    current["participants"] =
        json!([{"userDid":ALICE,"role":"admin","status":"active","leafCount":1}]);
    current["leaves"] = json!([{"userDid":ALICE,"deviceId":alice.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":0,"deviceStatus":"active"}]);
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, current);
    f.world
        .delivery_service()
        .set_conversation_group_id_for_test(&f.cid, &successor_hex);
    f.world
        .delivery_service()
        .set_conversation_epoch_for_test(&f.cid, 0);
    f.world.restart_client("Alice").await;
    let report = f
        .world
        .client("Alice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    assert_eq!(
        report.healthy, 1,
        "historical exit must not block the successor's startup reconciliation"
    );
    assert_eq!(
        requests(&f).len(),
        1,
        "old group intent must not be replayed against a successor"
    );
    assert_eq!(records(&f), pending);
    assert!(markers(&f).is_empty());
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation_state(&f.cid)
            .await
            .unwrap(),
        Some(ConversationState::Active)
    );
    assert_eq!(
        f.world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(successor)
            .unwrap(),
        0
    );
    assert_history(&f).await;
    assert_no_recovery_mutation(&f, before);
}

#[tokio::test(flavor = "multi_thread")]
async fn generated_exit_output_roundtrip_accepts_fixed_reference_tags_and_real_bytes() {
    for close in [true, false] {
        let mut f = fixture(close).await;
        f.world
            .delivery_service()
            .roundtrip_next_account_exit_response_for_test();
        f.world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap();
        let proof = records(&f);
        let response = proof[0].accepted_response.as_ref().unwrap();
        let entry = &response["result"]["entry"];
        assert!(entry.get("$type").is_none());
        assert!(entry["signedRequest"]["body"].get("$type").is_none());
        assert!(entry["signedRequest"]["signature"]["$bytes"].is_string());
        assert!(entry["signedRequest"]["body"]["prior"]["groupId"]["$bytes"].is_string());
        if close {
            assert!(entry["tombstone"].get("$type").is_none());
            assert!(response["result"]["tombstone"].get("$type").is_none());
            let _: catbird_atproto::blue_catbird::chat::close_conversation::CloseConversationOutput = serde_json::from_value(response.clone()).unwrap();
        } else {
            assert_eq!(
                response["result"]["$type"],
                "blue.catbird.chat.defs#zeroLeafLeaveResult"
            );
            let _: catbird_atproto::blue_catbird::chat::request_leave::RequestLeaveOutput =
                serde_json::from_value(response.clone()).unwrap();
        }
        assert_terminal(&f).await;
        f.world.restart_client("Alice").await;
        assert_eq!(records(&f), proof);
        assert_eq!(
            f.world
                .client("Alice")
                .orchestrator
                .leave_conversation(&f.cid)
                .await
                .unwrap(),
            LeaveOutcome::Left
        );
        assert_eq!(requests(&f).len(), 1);
        assert_terminal(&f).await;
    }
}

async fn seed_pending_reset_close(
    f: &ExitFixture,
    target: &[u8],
    generation: i32,
    notified_at_ms: i64,
) {
    f.world
        .client("Alice")
        .storage
        .mark_reset_pending(&f.cid, &hex::encode(target), generation, notified_at_ms)
        .await
        .unwrap();
    let mut current = f.current.clone();
    current["coordinates"] = json!({"conversationId":f.cid,"groupId":STANDARD.encode(target),
        "generation":generation,"stateVersion":1,"epoch":0,"lifecycle":"active",
        "confirmationTag":STANDARD.encode([71;32]),"groupContextHash":STANDARD.encode([72;32])});
    current["participants"][0]["leafCount"] = json!(0);
    current["leaves"] = json!([]);
    current["snapshotSeq"] = json!(1);
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, current);
}

#[tokio::test(flavor = "multi_thread")]
async fn matching_pending_reset_close_archives_authority_and_preserves_history_after_reopen() {
    let mut f = fixture(true).await;
    let target = [81; 32];
    let notified_at_ms = chrono::Utc::now().timestamp_millis();
    seed_pending_reset_close(&f, &target, 7, notified_at_ms).await;
    assert!(
        f.world
            .client("Alice")
            .orchestrator
            .mls_context()
            .get_epoch(target.to_vec())
            .is_err(),
        "leafless close does not require adopting the reset group"
    );
    f.world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .unwrap();
    let proof = records(&f);
    assert_eq!(proof.len(), 1);
    assert!(proof[0].local_completion);
    let evidence = proof[0].reset_evidence.as_ref().unwrap();
    assert_eq!(evidence.new_group_id, hex::encode(target));
    assert_eq!(evidence.reset_generation, 7);
    assert_eq!(evidence.notified_at_ms, notified_at_ms);
    assert_terminal(&f).await;
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation(ALICE, &f.cid)
            .await
            .unwrap()
            .unwrap()
            .group_id,
        hex::encode(target)
    );
    assert_eq!(markers(&f).len(), 1);
    f.world.restart_client("Alice").await;
    f.world
        .client("Alice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    assert_eq!(records(&f), proof);
    assert_eq!(requests(&f).len(), 1);
    assert_eq!(markers(&f).len(), 1);
    assert_terminal(&f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_close_cannot_erase_a_newer_pending_reset_target_or_generation() {
    for same_target in [false, true] {
        let mut f = fixture(true).await;
        let target = [81; 32];
        let notified_at_ms = chrono::Utc::now().timestamp_millis();
        seed_pending_reset_close(&f, &target, 7, notified_at_ms).await;
        f.world
            .client("Alice")
            .storage
            .fail_next_set_conversation_state();
        assert!(f
            .world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .is_err());
        let accepted = records(&f);
        assert_eq!(accepted.len(), 1);
        assert!(accepted[0].accepted_response.is_some());
        assert!(!accepted[0].local_completion);
        assert_eq!(
            accepted[0]
                .reset_evidence
                .as_ref()
                .unwrap()
                .reset_generation,
            7
        );
        let newer_target = if same_target { target } else { [82; 32] };
        f.world
            .client("Alice")
            .storage
            .mark_reset_pending(&f.cid, &hex::encode(newer_target), 8, notified_at_ms + 1)
            .await
            .unwrap();
        let expected = ConversationState::ResetPending {
            new_group_id: hex::encode(newer_target),
            reset_generation: 8,
            notified_at_ms: notified_at_ms + 1,
        };
        f.world.restart_client("Alice").await;
        f.world
            .client("Alice")
            .orchestrator
            .startup_reconcile()
            .await
            .unwrap();
        assert!(f
            .world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .is_err());
        assert_eq!(
            f.world
                .client("Alice")
                .storage
                .get_conversation_state(&f.cid)
                .await
                .unwrap(),
            Some(expected)
        );
        assert_eq!(
            records(&f),
            accepted,
            "old accepted proof and archived reset authority stay immutable"
        );
        assert_eq!(requests(&f).len(), 1);
        assert!(markers(&f).is_empty());
        assert_history(&f).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_reset_exit_projection_with_lost_reply_reuses_archive_after_native_reopen() {
    let mut f = fixture(true).await;
    let target = [83; 32];
    let notified_at_ms = chrono::Utc::now().timestamp_millis();
    seed_pending_reset_close(&f, &target, 7, notified_at_ms).await;
    f.world
        .client("Alice")
        .storage
        .lose_next_account_exit_projection_response();
    assert!(f
        .world
        .client("Alice")
        .orchestrator
        .leave_conversation(&f.cid)
        .await
        .is_err());
    let pending = records(&f);
    assert_eq!(pending.len(), 1);
    assert!(!pending[0].local_completion);
    assert!(pending[0].accepted_response.is_some());
    let archived = pending[0].reset_evidence.as_ref().unwrap();
    assert_eq!(archived.new_group_id, hex::encode(target));
    assert_eq!(archived.reset_generation, 7);
    assert_eq!(archived.notified_at_ms, notified_at_ms);
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation_state(&f.cid)
            .await
            .unwrap(),
        Some(ConversationState::Closed),
        "the host's exact terminal CAS committed before its response was lost"
    );
    assert!(
        markers(&f).is_empty(),
        "marker completion is still pending after the lost host response"
    );
    assert_eq!(requests(&f).len(), 1);
    assert_history(&f).await;
    f.world.restart_client("Alice").await;
    assert_eq!(records(&f), pending);
    f.world
        .client("Alice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    let completed = records(&f);
    assert_eq!(completed.len(), 1);
    assert!(completed[0].local_completion);
    assert_eq!(completed[0].request_body, pending[0].request_body);
    assert_eq!(completed[0].accepted_response, pending[0].accepted_response);
    assert_eq!(completed[0].reset_evidence, pending[0].reset_evidence);
    assert_eq!(
        requests(&f).len(),
        1,
        "saved accepted proof completes host CAS without another HTTP exit"
    );
    assert_eq!(markers(&f).len(), 1);
    assert_terminal(&f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_phone_can_close_direct_conversation_while_its_sibling_remains_active() {
    let mut f = fixture(true).await;
    f.world.add_client_with_did("AliceSibling", ALICE).await;
    f.world.register_device("AliceSibling").await.unwrap();
    let sibling = f.world.client("AliceSibling");
    let sibling_device = sibling
        .orchestrator
        .require_actor_device_id()
        .await
        .unwrap();
    let sibling_identity = format!("{ALICE}#{sibling_device}");
    let package = sibling
        .orchestrator
        .mls_context()
        .create_key_package(sibling_identity.as_bytes().to_vec())
        .unwrap();
    let bob = f.world.client("Bob");
    let added = bob
        .orchestrator
        .mls_context()
        .add_members(
            f.group.clone(),
            vec![KeyPackageData {
                data: package.key_package_data,
            }],
        )
        .unwrap();
    bob.orchestrator
        .mls_context()
        .merge_pending_commit(f.group.clone())
        .unwrap();
    sibling
        .orchestrator
        .mls_context()
        .process_welcome(
            added.welcome_data,
            sibling_identity.as_bytes().to_vec(),
            None,
        )
        .unwrap();
    let original_device = f
        .world
        .client("Alice")
        .orchestrator
        .require_actor_device_id()
        .await
        .unwrap();
    assert_ne!(sibling_device, original_device);
    let original_identity = format!("{ALICE}#{original_device}");
    let removal = bob
        .orchestrator
        .mls_context()
        .remove_members(f.group.clone(), vec![original_identity.as_bytes().to_vec()])
        .unwrap();
    bob.orchestrator
        .mls_context()
        .merge_pending_commit(f.group.clone())
        .unwrap();
    sibling
        .orchestrator
        .mls_context()
        .process_commit(f.group.clone(), removal)
        .unwrap();
    sibling
        .orchestrator
        .mls_context()
        .merge_incoming_commit(f.group.clone(), 3)
        .unwrap();
    assert_eq!(
        sibling
            .orchestrator
            .mls_context()
            .get_epoch(f.group.clone())
            .unwrap(),
        3
    );
    assert!(sibling
        .orchestrator
        .mls_context()
        .group_is_active(f.group.clone())
        .unwrap());
    let live_members = bob
        .orchestrator
        .mls_context()
        .group_member_identities(f.group.clone())
        .unwrap();
    assert!(live_members
        .iter()
        .any(|member| member == sibling_identity.as_bytes()));
    assert!(!live_members
        .iter()
        .any(|member| member == original_identity.as_bytes()));
    let mut current = f.current.clone();
    current["coordinates"]["epoch"] = json!(3);
    current["coordinates"]["stateVersion"] = json!(21);
    current["coordinates"]["confirmationTag"] = json!(STANDARD.encode(
        bob.orchestrator
            .mls_context()
            .get_confirmation_tag(f.group.clone())
            .unwrap()
    ));
    current["coordinates"]["groupContextHash"] = json!(STANDARD.encode(
        bob.orchestrator
            .mls_context()
            .get_group_context_hash(f.group.clone())
            .unwrap()
    ));
    current["snapshotSeq"] = json!(21);
    current["leaves"] = json!([
        {"userDid":BOB,"deviceId":bob.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":1,"deviceStatus":"active"},
        {"userDid":ALICE,"deviceId":sibling_device,"leafIndex":2,"deviceStatus":"active"},
    ]);
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, current);
    f.world
        .delivery_service()
        .set_conversation_epoch_for_test(&f.cid, 3);
    // The offline phone retains epoch 1's history and a durable removal state;
    // its account still has the sibling's genuine epoch 3 leaf.
    f.world
        .client("Alice")
        .storage
        .set_conversation_state(&f.cid, ConversationState::DeviceRemoved)
        .await
        .unwrap();
    f.world.restart_client("Alice").await;
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation_state(&f.cid)
            .await
            .unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert_history(&f).await;
    assert!(records(&f).is_empty());
    assert_eq!(
        f.world
            .client("Alice")
            .orchestrator
            .leave_conversation(&f.cid)
            .await
            .unwrap(),
        LeaveOutcome::Left
    );
    let proof = records(&f);
    assert_eq!(proof.len(), 1);
    assert!(proof[0].accepted_response.is_some());
    assert!(proof[0].local_completion);
    assert_eq!(signed_body(&proof[0])["actorDeviceId"], original_device);
    assert_eq!(signed_body(&proof[0])["prior"]["epoch"], 3);
    assert_eq!(requests(&f).len(), 1);
    assert_eq!(
        requests(&f)[0].operation,
        CanonicalOperation::CloseConversation
    );
    assert_eq!(markers(&f).len(), 1);
    assert_terminal(&f).await;
    assert_eq!(
        f.world
            .client("Alice")
            .storage
            .get_conversation(ALICE, &f.cid)
            .await
            .unwrap()
            .unwrap()
            .epoch,
        3
    );
    f.world.restart_client("Alice").await;
    f.world
        .client("Alice")
        .orchestrator
        .startup_reconcile()
        .await
        .unwrap();
    assert_eq!(records(&f), proof);
    assert_eq!(requests(&f).len(), 1);
    assert_terminal(&f).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cleared_reset_reinvitation_without_restart_uses_fresh_unarchived_exit() {
    let f = fixture(false).await;
    let target = [84; 32];
    let target_hex = hex::encode(target);
    let notified_at_ms = chrono::Utc::now().timestamp_millis();
    let bob = f.world.client("Bob");
    let bob_device = bob.orchestrator.require_actor_device_id().await.unwrap();
    let bob_identity = format!("{BOB}#{bob_device}");
    bob.orchestrator
        .mls_context()
        .create_group_with_id(bob_identity.into_bytes(), target.to_vec(), None)
        .unwrap();
    seed_pending_reset_close(&f, &target, 7, notified_at_ms).await;
    let mut current = f.current.clone();
    current["coordinates"] = json!({"conversationId":f.cid,"groupId":STANDARD.encode(target),
        "generation":7,"stateVersion":1,"epoch":0,"lifecycle":"active",
        "confirmationTag":STANDARD.encode(bob.orchestrator.mls_context().get_confirmation_tag(target.to_vec()).unwrap()),
        "groupContextHash":STANDARD.encode(bob.orchestrator.mls_context().get_group_context_hash(target.to_vec()).unwrap())});
    current["snapshotSeq"] = json!(1);
    current["leaves"] =
        json!([{"userDid":BOB,"deviceId":bob_device,"leafIndex":0,"deviceStatus":"active"}]);
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, current.clone());
    f.world
        .delivery_service()
        .set_conversation_group_id_for_test(&f.cid, &target_hex);
    let alice = f.world.client("Alice");
    alice.storage.lose_next_account_exit_projection_response();
    assert!(alice.orchestrator.leave_conversation(&f.cid).await.is_err());
    let old = records(&f)[0].clone();
    assert!(old.accepted_response.is_some());
    assert!(!old.local_completion);
    assert_eq!(old.reset_evidence.as_ref().unwrap().reset_generation, 7);
    assert_eq!(
        alice.storage.get_conversation_state(&f.cid).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert!(alice.storage.get_persisted_reset_pending(&f.cid).is_none());
    assert!(
        matches!(alice.orchestrator.conversation_states().lock().await.get(&f.cid),
        Some(ConversationState::ResetPending {new_group_id,reset_generation:7,..}) if new_group_id == &target_hex),
        "lost host response leaves stale reset authority in the current process cache"
    );
    assert_eq!(markers(&f).len(), 0);
    assert_history(&f).await;

    // No restart, Welcome, or successful old completion repairs the cache.
    // The remaining peer advances the same reset group before a fresh invite.
    bob.orchestrator
        .mls_context()
        .self_update(target.to_vec())
        .unwrap();
    bob.orchestrator
        .mls_context()
        .merge_pending_commit(target.to_vec())
        .unwrap();
    current["coordinates"]["epoch"] = json!(1);
    current["coordinates"]["stateVersion"] = json!(4);
    current["coordinates"]["confirmationTag"] = json!(STANDARD.encode(
        bob.orchestrator
            .mls_context()
            .get_confirmation_tag(target.to_vec())
            .unwrap()
    ));
    current["coordinates"]["groupContextHash"] = json!(STANDARD.encode(
        bob.orchestrator
            .mls_context()
            .get_group_context_hash(target.to_vec())
            .unwrap()
    ));
    current["snapshotSeq"] = json!(4);
    f.world
        .delivery_service()
        .set_lifecycle_state_for_test(&f.cid, current);
    f.world
        .delivery_service()
        .set_conversation_epoch_for_test(&f.cid, 1);
    assert_eq!(
        alice.orchestrator.leave_conversation(&f.cid).await.unwrap(),
        LeaveOutcome::Left
    );
    let all = records(&f);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].request_body, old.request_body);
    assert_eq!(all[0].accepted_response, old.accepted_response);
    assert_eq!(all[0].reset_evidence, old.reset_evidence);
    assert!(all[0].local_completion);
    assert_eq!(
        all[1].replaces_operation.as_deref(),
        signed_body(&old)["transitionId"].as_str()
    );
    assert_ne!(all[1].request_body, old.request_body);
    assert!(
        all[1].reset_evidence.is_none(),
        "new accepted departure must not inherit an already-cleared reset archive"
    );
    assert!(all[1].accepted_response.is_some());
    assert!(all[1].local_completion);
    assert_eq!(signed_body(&all[1])["prior"]["generation"], 7);
    assert_eq!(signed_body(&all[1])["prior"]["epoch"], 1);
    assert_eq!(signed_body(&all[1])["prior"]["stateVersion"], 4);
    assert_eq!(requests(&f).len(), 2);
    assert_eq!(markers(&f).len(), 1);
    assert_eq!(
        alice
            .storage
            .get_conversation(ALICE, &f.cid)
            .await
            .unwrap()
            .unwrap()
            .epoch,
        1
    );
    assert!(alice.storage.get_persisted_reset_pending(&f.cid).is_none());
    assert_eq!(
        alice
            .orchestrator
            .conversation_states()
            .lock()
            .await
            .get(&f.cid),
        Some(&ConversationState::DeviceRemoved)
    );
    assert!(
        alice
            .orchestrator
            .mls_context()
            .get_epoch(target.to_vec())
            .is_err(),
        "zero-leaf exit does not require a local Welcome"
    );
    assert_terminal(&f).await;
}
