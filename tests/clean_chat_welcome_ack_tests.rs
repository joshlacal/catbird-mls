//! Welcome acceptance must be durable before its delivery is acknowledged.
#![allow(dead_code)]
mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    canonical_transport::{CanonicalOperation, PreparedRequest},
    welcome_ack::{WelcomeAcceptance, WelcomeDelivery},
    ConversationState, MLSStorageBackend, MlsCryptoContext,
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

const ALICE: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
const CHARLIE: &str = "did:plc:cccccccccccccccccccccccc";
const EPOCH: u64 = 2;

struct WelcomeFixture {
    world: TestWorld,
    conversation_id: String,
    group: Vec<u8>,
    welcome: Vec<u8>,
    envelope: Value,
    key_package_ref: Vec<u8>,
}

async fn welcome_fixture() -> WelcomeFixture {
    let mut world = TestWorld::new();
    for (name, did) in [("Alice", ALICE), ("Bob", BOB), ("Charlie", CHARLIE)] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let alice = world.client("Alice");
    let created = alice
        .orchestrator
        .create_group("Durable Welcome", Some(&[BOB.into(), CHARLIE.into()]), None)
        .await
        .unwrap();
    let cid = created.conversation_id;
    let group = hex::decode(created.group_id).unwrap();
    let mut bob_package = None;
    let mut bob_welcome = None;
    // Each real Add has exactly one target and one Welcome delivery.
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
        panic!("native generated artifact must be a KeyPackage message");
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
    let coordinates = json!({
        "conversationId":cid,"groupId":STANDARD.encode(&group),"generation":0,
        "stateVersion":4,"epoch":EPOCH,"lifecycle":"active",
        "confirmationTag":STANDARD.encode(alice.orchestrator.mls_context().get_confirmation_tag(group.clone()).unwrap()),
        "groupContextHash":STANDARD.encode(alice.orchestrator.mls_context().get_group_context_hash(group.clone()).unwrap()),
    });
    let requests = world.delivery_service().submitted_prepared_requests();
    let create = requests
        .iter()
        .find(|r| r.operation == CanonicalOperation::CreateConversation)
        .unwrap();
    let create: Value = serde_json::from_slice(create.body.as_deref().unwrap()).unwrap();
    let mut metadata_snapshot = create["signedRequest"]["body"]["metadataSnapshot"].clone();
    let metadata = catbird_mls::metadata::GroupMetadataV1 {
        version: 1,
        title: "Durable Welcome".into(),
        description: "Keep encrypted metadata and history".into(),
        avatar_blob_locator: None,
        avatar_content_type: None,
    };
    let key: [u8; 32] = alice
        .orchestrator
        .mls_context()
        .export_metadata_key(group.clone(), EPOCH)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = [7; 12];
    let ciphertext = catbird_mls::metadata::encrypt_metadata_snapshot_with_nonce(
        &key, &group, EPOCH, 1, &nonce, &metadata,
    )
    .unwrap();
    metadata_snapshot["coordinate"] = json!({
        "conversationId":STANDARD.encode(uuid::Uuid::parse_str(&cid).unwrap().as_bytes()),
        "generation":0,"epoch":EPOCH,"groupId":coordinates["groupId"],
        "confirmationTag":coordinates["confirmationTag"],"groupContextHash":coordinates["groupContextHash"],
    });
    metadata_snapshot["nonce"] = json!(STANDARD.encode(nonce));
    metadata_snapshot["ciphertext"] = json!(STANDARD.encode(&ciphertext));
    metadata_snapshot["ciphertextSize"] = json!(ciphertext.len());
    metadata_snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&ciphertext)));
    let mut leaves = Vec::new();
    for name in ["Alice", "Charlie", "Bob"] {
        let client = world.client(name);
        leaves.push(json!({"userDid":client.did,"deviceId":client.orchestrator.require_actor_device_id().await.unwrap(),"leafIndex":leaves.len(),"deviceStatus":"active"}));
    }
    let state = json!({
        "conversationKind":"group","snapshotSeq":5,"coordinates":coordinates,"leaves":leaves,
        "participants":[{"userDid":ALICE,"role":"admin","status":"active","leafCount":1},
            {"userDid":BOB,"role":"member","status":"active","leafCount":1},
            {"userDid":CHARLIE,"role":"member","status":"active","leafCount":1}],
        "metadataSnapshot":metadata_snapshot,
    });
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state);
    world
        .delivery_service()
        .set_conversation_epoch_for_test(&cid, EPOCH);
    let bob = world.client("Bob");
    bob.storage
        .ensure_conversation_exists(BOB, &cid, &hex::encode(&group))
        .await
        .unwrap();
    bob.storage
        .set_conversation_state(&cid, ConversationState::DeviceRemoved)
        .await
        .unwrap();
    bob.storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "history-before-welcome".into(),
            conversation_id: cid.clone(),
            sender_did: BOB.into(),
            text: "Keep my saved messages".into(),
            timestamp: Utc::now(),
            epoch: 0,
            sequence_number: 0,
            is_own: true,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    assert!(bob
        .orchestrator
        .mls_context()
        .get_epoch(group.clone())
        .is_err());
    let envelope = json!({
        "welcomeId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"transitionSeq":5,
        "coordinates":coordinates,"status":"pending","opaqueWelcome":STANDARD.encode(&welcome),
        "sha256":STANDARD.encode(Sha256::digest(&welcome)),"recipientDid":BOB,
        "recipientDeviceId":bob.orchestrator.require_actor_device_id().await.unwrap(),
        "provenance":{"recoveryRequestId":uuid::Uuid::new_v4().to_string(),"keyPackageRef":STANDARD.encode(&package.hash_ref)},
        "expiresAt":expires_at,
    });
    world
        .delivery_service()
        .set_welcome_delivery_for_test(envelope.clone());
    WelcomeFixture {
        world,
        conversation_id: cid,
        group,
        welcome,
        envelope,
        key_package_ref: package.hash_ref,
    }
}

fn acknowledgements(fixture: &WelcomeFixture) -> Vec<PreparedRequest> {
    fixture
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|request| request.operation == CanonicalOperation::AcknowledgeWelcome)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_durable_welcome_is_acknowledged_with_exact_delivery_binding() {
    let fixture = welcome_fixture().await;
    let bob = fixture.world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .join_or_rejoin_from_available_welcome(
                &fixture.conversation_id,
                fixture.welcome.clone(),
            )
            .await
            .unwrap(),
        EPOCH
    );
    let requests = acknowledgements(&fixture);
    assert_eq!(
        requests.len(),
        1,
        "a verified, persisted Welcome must acknowledge its exact delivery"
    );
    let ack: Value = serde_json::from_slice(requests[0].body.as_deref().unwrap()).unwrap();
    let body = &ack["signedRequest"]["body"];
    assert_eq!(body["welcomeId"], fixture.envelope["welcomeId"]);
    assert_eq!(body["transitionSeq"], fixture.envelope["transitionSeq"]);
    assert_eq!(body["coordinates"], fixture.envelope["coordinates"]);
    assert_eq!(body["actorDid"], fixture.envelope["recipientDid"]);
    assert_eq!(body["actorDeviceId"], fixture.envelope["recipientDeviceId"]);
    assert_eq!(
        bob.storage
            .get_group_state(&hex::encode(&fixture.group))
            .await
            .unwrap()
            .unwrap()
            .epoch,
        EPOCH
    );
    assert_eq!(
        bob.storage
            .get_conversation_state(&fixture.conversation_id)
            .await
            .unwrap(),
        Some(ConversationState::Active)
    );
    assert!(bob
        .storage
        .message_exists("history-before-welcome")
        .await
        .unwrap());
}

fn acceptances(fixture: &WelcomeFixture) -> Vec<WelcomeAcceptance> {
    fixture
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .list_welcome_acceptances()
        .unwrap()
}

fn has_selected_key_package(fixture: &WelcomeFixture) -> bool {
    fixture
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .debug_check_key_package_hash(hex::encode(&fixture.key_package_ref))
        .unwrap()
}

async fn assert_saved_active_membership(fixture: &WelcomeFixture) {
    let bob = fixture.world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(fixture.group.clone())
            .unwrap(),
        EPOCH
    );
    assert!(bob
        .orchestrator
        .mls_context()
        .group_is_active(fixture.group.clone())
        .unwrap());
    assert_eq!(
        bob.storage
            .get_group_state(&hex::encode(&fixture.group))
            .await
            .unwrap()
            .unwrap()
            .epoch,
        EPOCH
    );
    assert_eq!(
        bob.storage
            .get_conversation_state(&fixture.conversation_id)
            .await
            .unwrap(),
        Some(ConversationState::Active)
    );
    assert!(bob
        .storage
        .message_exists("history-before-welcome")
        .await
        .unwrap());
    assert!(!bob
        .storage
        .needs_rejoin(&fixture.conversation_id)
        .await
        .unwrap());
    assert!(
        !has_selected_key_package(fixture),
        "the one-time package remains consumed"
    );
}

fn assert_only_ack_writes_after(fixture: &WelcomeFixture, before: usize) {
    for request in &fixture
        .world
        .delivery_service()
        .submitted_prepared_requests()[before..]
    {
        if request.method != "GET" {
            assert_eq!(
                request.operation,
                CanonicalOperation::AcknowledgeWelcome,
                "Welcome acknowledgement must not mutate membership or reset the group"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn completed_receipt_survives_native_restart_and_healthy_replays_are_quiet() {
    let mut fixture = welcome_fixture().await;
    let before = fixture
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    fixture
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&fixture.conversation_id, fixture.welcome.clone())
        .await
        .unwrap();
    let records = acceptances(&fixture);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].delivery.envelope, fixture.envelope);
    assert!(records[0].projection_completed);
    assert_eq!(records[0].request_body, acknowledgements(&fixture)[0].body);
    assert_eq!(
        records[0].terminal_response.as_ref().unwrap()["body"]["status"],
        "acknowledged"
    );
    assert_saved_active_membership(&fixture).await;

    fixture.world.restart_client("Bob").await;
    assert_eq!(
        acceptances(&fixture),
        records,
        "the native encrypted database retains the exact proof"
    );
    for _ in 0..2 {
        let bob = fixture.world.client("Bob");
        assert_eq!(
            bob.orchestrator
                .retry_pending_welcome_acknowledgements()
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            bob.orchestrator
                .join_or_rejoin_from_available_welcome(
                    &fixture.conversation_id,
                    fixture.welcome.clone()
                )
                .await
                .unwrap(),
            EPOCH
        );
    }
    assert_eq!(acceptances(&fixture), records);
    assert_eq!(acknowledgements(&fixture).len(), 1);
    assert_saved_active_membership(&fixture).await;
    assert_only_ack_writes_after(&fixture, before);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_application_projection_keeps_native_receipt_and_sends_no_ack() {
    let mut fixture = welcome_fixture().await;
    fixture
        .world
        .client("Bob")
        .storage
        .fail_next_set_group_state();
    let result = fixture
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&fixture.conversation_id, fixture.welcome.clone())
        .await;
    assert!(
        result.is_err(),
        "host persistence failure must be returned before acknowledgement"
    );
    assert!(acknowledgements(&fixture).is_empty());
    let records = acceptances(&fixture);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].delivery.envelope, fixture.envelope);
    assert!(!records[0].projection_completed);
    assert!(records[0].request_body.is_none());
    assert!(records[0].terminal_response.is_none());
    assert!(!has_selected_key_package(&fixture));
    let bob = fixture.world.client("Bob");
    assert_eq!(
        bob.orchestrator
            .mls_context()
            .get_epoch(fixture.group.clone())
            .unwrap(),
        EPOCH
    );
    assert_eq!(
        bob.storage
            .get_conversation_state(&fixture.conversation_id)
            .await
            .unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
    assert!(bob
        .storage
        .message_exists("history-before-welcome")
        .await
        .unwrap());

    fixture.world.restart_client("Bob").await;
    assert_eq!(acceptances(&fixture), records);
    fixture
        .world
        .client("Bob")
        .orchestrator
        .retry_pending_welcome_acknowledgements()
        .await
        .unwrap();
    assert_saved_active_membership(&fixture).await;
    assert_eq!(acknowledgements(&fixture).len(), 1);
    let records = acceptances(&fixture);
    assert_eq!(records.len(), 1);
    assert!(records[0].projection_completed);
    assert_eq!(
        records[0].terminal_response.as_ref().unwrap()["body"]["status"],
        "acknowledged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_ack_with_lost_response_restarts_with_identical_signed_request() {
    let mut fixture = welcome_fixture().await;
    let before = fixture
        .world
        .delivery_service()
        .submitted_prepared_requests()
        .len();
    fixture
        .world
        .delivery_service()
        .lose_next_welcome_ack_responses(100);
    assert_eq!(
        fixture
            .world
            .client("Bob")
            .orchestrator
            .join_or_rejoin_from_available_welcome(
                &fixture.conversation_id,
                fixture.welcome.clone()
            )
            .await
            .unwrap(),
        EPOCH,
        "ACK transport failure must not undo durable verified membership"
    );
    assert_saved_active_membership(&fixture).await;
    let pending = acceptances(&fixture);
    assert_eq!(pending.len(), 1);
    assert!(pending[0].projection_completed);
    assert!(pending[0].terminal_response.is_none());
    let signed = pending[0]
        .request_body
        .clone()
        .expect("exact ACK journaled before transmission");
    let attempts = acknowledgements(&fixture);
    assert!(!attempts.is_empty());
    assert!(attempts
        .iter()
        .all(|request| request.body.as_ref() == Some(&signed)));

    fixture
        .world
        .delivery_service()
        .lose_next_welcome_ack_responses(0);
    fixture.world.restart_client("Bob").await;
    assert_eq!(acceptances(&fixture), pending);
    assert_eq!(
        fixture
            .world
            .client("Bob")
            .orchestrator
            .retry_pending_welcome_acknowledgements()
            .await
            .unwrap(),
        1
    );
    let completed = acceptances(&fixture);
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].delivery, pending[0].delivery);
    assert_eq!(completed[0].request_body.as_ref(), Some(&signed));
    assert_eq!(
        completed[0].terminal_response.as_ref().unwrap()["body"]["status"],
        "acknowledged"
    );
    assert_eq!(acknowledgements(&fixture).len(), attempts.len() + 1);
    assert!(acknowledgements(&fixture)
        .iter()
        .all(|request| request.body.as_ref() == Some(&signed)));
    assert_saved_active_membership(&fixture).await;
    assert_only_ack_writes_after(&fixture, before);
}

#[tokio::test(flavor = "multi_thread")]
async fn superseded_or_expired_ack_is_bookkeeping_and_preserves_joined_group() {
    for (status, error) in [
        ("superseded", "WelcomeSuperseded"),
        ("expired", "WelcomeExpired"),
    ] {
        let mut fixture = welcome_fixture().await;
        let before = fixture
            .world
            .delivery_service()
            .submitted_prepared_requests()
            .len();
        fixture
            .world
            .client("Bob")
            .storage
            .fail_next_set_group_state();
        assert!(fixture
            .world
            .client("Bob")
            .orchestrator
            .join_or_rejoin_from_available_welcome(
                &fixture.conversation_id,
                fixture.welcome.clone()
            )
            .await
            .is_err());
        assert!(acknowledgements(&fixture).is_empty());
        assert_eq!(acceptances(&fixture).len(), 1);
        fixture
            .world
            .delivery_service()
            .set_welcome_ack_status_for_test(
                fixture.envelope["welcomeId"].as_str().unwrap(),
                status,
            );
        fixture.world.restart_client("Bob").await;
        fixture
            .world
            .client("Bob")
            .orchestrator
            .retry_pending_welcome_acknowledgements()
            .await
            .unwrap();
        assert_saved_active_membership(&fixture).await;
        let records = acceptances(&fixture);
        assert_eq!(records.len(), 1);
        assert!(records[0].projection_completed);
        let terminal = records[0].terminal_response.as_ref().unwrap();
        assert_eq!(terminal["status"], 400);
        assert_eq!(terminal["body"]["error"], error);
        assert_eq!(acknowledgements(&fixture).len(), 1);
        assert_eq!(
            fixture
                .world
                .client("Bob")
                .orchestrator
                .retry_pending_welcome_acknowledgements()
                .await
                .unwrap(),
            0
        );
        assert_eq!(acknowledgements(&fixture).len(), 1);
        assert_only_ack_writes_after(&fixture, before);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_delivery_binding_rolls_back_import_and_preserves_original_package() {
    let fixture = welcome_fixture().await;
    let valid = WelcomeDelivery::from_value(fixture.envelope.clone()).unwrap();
    let identity = valid.recipient_identity().into_bytes();
    for field in [
        "hash",
        "group",
        "epoch",
        "context",
        "confirmation",
        "did",
        "device",
        "package",
        "expiry",
    ] {
        let mut envelope = fixture.envelope.clone();
        match field {
            "hash" => envelope["sha256"] = json!(STANDARD.encode([44; 32])),
            "group" => envelope["coordinates"]["groupId"] = json!(STANDARD.encode([44; 32])),
            "epoch" => envelope["coordinates"]["epoch"] = json!(EPOCH + 1),
            "context" => {
                envelope["coordinates"]["groupContextHash"] = json!(STANDARD.encode([44; 32]))
            }
            "confirmation" => {
                envelope["coordinates"]["confirmationTag"] = json!(STANDARD.encode([44; 32]))
            }
            "did" => envelope["recipientDid"] = json!(ALICE),
            "device" => envelope["recipientDeviceId"] = json!(uuid::Uuid::new_v4().to_string()),
            "package" => envelope["provenance"]["keyPackageRef"] = json!(STANDARD.encode([44; 32])),
            "expiry" => {
                let expiry =
                    chrono::DateTime::parse_from_rfc3339(envelope["expiresAt"].as_str().unwrap())
                        .unwrap();
                envelope["expiresAt"] = json!((expiry + chrono::Duration::seconds(1))
                    .to_rfc3339_opts(SecondsFormat::Millis, true));
            }
            _ => unreachable!(),
        }
        let bob = fixture.world.client("Bob");
        if let Ok(delivery) = WelcomeDelivery::from_value(envelope) {
            assert!(
                bob.orchestrator
                    .mls_context()
                    .process_welcome_delivery(&delivery, identity.clone(), None)
                    .is_err(),
                "invalid {field} binding must reject"
            );
        }
        assert!(
            bob.orchestrator
                .mls_context()
                .get_epoch(fixture.group.clone())
                .is_err(),
            "invalid {field} must not publish native membership"
        );
        assert!(
            has_selected_key_package(&fixture),
            "invalid {field} must roll back one-time KeyPackage consumption"
        );
        assert!(
            acceptances(&fixture).is_empty(),
            "invalid {field} must not create receipt"
        );
        assert!(acknowledgements(&fixture).is_empty());
        assert!(bob
            .storage
            .message_exists("history-before-welcome")
            .await
            .unwrap());
    }
    fixture
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&fixture.conversation_id, fixture.welcome.clone())
        .await
        .unwrap();
    assert_saved_active_membership(&fixture).await;
    assert_eq!(acknowledgements(&fixture).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn supplied_welcome_bytes_must_match_authoritative_delivery_before_import() {
    let fixture = welcome_fixture().await;
    let mut altered = fixture.welcome.clone();
    altered.push(0);
    assert!(fixture
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&fixture.conversation_id, altered)
        .await
        .is_err());
    assert!(acceptances(&fixture).is_empty());
    assert!(acknowledgements(&fixture).is_empty());
    assert!(has_selected_key_package(&fixture));
    assert!(fixture
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .get_epoch(fixture.group.clone())
        .is_err());
    fixture
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&fixture.conversation_id, fixture.welcome.clone())
        .await
        .unwrap();
    assert_saved_active_membership(&fixture).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_receipt_updates_cannot_mint_or_rebind_a_verified_acceptance() {
    let fixture = welcome_fixture().await;
    let fabricated = WelcomeAcceptance {
        delivery: WelcomeDelivery::from_value(fixture.envelope.clone()).unwrap(),
        projection_completed: false,
        request_body: None,
        terminal_response: None,
    };
    assert!(fixture
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .update_welcome_acceptance(&fabricated)
        .is_err());
    assert!(acceptances(&fixture).is_empty());
    assert!(has_selected_key_package(&fixture));
    fixture
        .world
        .client("Bob")
        .orchestrator
        .join_or_rejoin_from_available_welcome(&fixture.conversation_id, fixture.welcome.clone())
        .await
        .unwrap();
    let original = acceptances(&fixture);
    let mut altered = original[0].clone();
    altered.delivery.envelope["transitionSeq"] = json!(6);
    assert!(fixture
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .update_welcome_acceptance(&altered)
        .is_err());
    let mut reverted = original[0].clone();
    reverted.projection_completed = false;
    assert!(fixture
        .world
        .client("Bob")
        .orchestrator
        .mls_context()
        .update_welcome_acceptance(&reverted)
        .is_err());
    assert_eq!(acceptances(&fixture), original);
}

#[tokio::test(flavor = "multi_thread")]
async fn ack_waits_for_every_application_projection_write() {
    for boundary in ["conversation", "join_info", "rejoin_flag"] {
        let mut fixture = welcome_fixture().await;
        let storage = &fixture.world.client("Bob").storage;
        match boundary {
            "conversation" => storage.fail_next_ensure_conversation_exists(),
            "join_info" => storage.fail_next_update_join_info(),
            "rejoin_flag" => storage.fail_next_clear_rejoin_flag(),
            _ => unreachable!(),
        }
        assert!(
            fixture
                .world
                .client("Bob")
                .orchestrator
                .join_or_rejoin_from_available_welcome(
                    &fixture.conversation_id,
                    fixture.welcome.clone()
                )
                .await
                .is_err(),
            "the failed {boundary} projection must be returned"
        );
        assert!(
            acknowledgements(&fixture).is_empty(),
            "{boundary} must persist before ACK"
        );
        let pending = acceptances(&fixture);
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].projection_completed);
        assert!(pending[0].request_body.is_none());
        assert!(pending[0].terminal_response.is_none());
        assert!(!has_selected_key_package(&fixture));
        assert!(fixture
            .world
            .client("Bob")
            .storage
            .message_exists("history-before-welcome")
            .await
            .unwrap());
        fixture.world.restart_client("Bob").await;
        fixture
            .world
            .client("Bob")
            .orchestrator
            .retry_pending_welcome_acknowledgements()
            .await
            .unwrap();
        assert_saved_active_membership(&fixture).await;
        assert_eq!(acknowledgements(&fixture).len(), 1);
    }
}
