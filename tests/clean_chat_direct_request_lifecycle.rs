//! Native sender preflight checks. These are not delivery-service publication tests.
#![allow(dead_code)]
mod e2e_harness;
use catbird_mls::orchestrator::{MLSStorageBackend, MlsCryptoContext, OrchestratorError};
use catbird_mls::{DirectRequestInput, MLSError};
use e2e_harness::TestWorld;

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_receipt_resolution_refuses_before_reservation_or_crypto() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let client = world.client("Alice");
    let result = client
        .orchestrator
        .start_direct_request(DirectRequestInput {
            draft_id: "11111111-1111-4111-8111-111111111111".into(),
            recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
            text: "Retain this draft".into(),
            invitation: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(OrchestratorError::Mls(
            MLSError::OperationNotSupported { .. }
        ))
    ));
    assert!(client
        .orchestrator
        .mls_context()
        .list_direct_request_intents()
        .unwrap()
        .is_empty());
    assert!(client
        .orchestrator
        .mls_context()
        .list_direct_request_journal()
        .unwrap()
        .is_empty());
    assert!(client
        .orchestrator
        .mls_context()
        .list_direct_request_projections()
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_draft_never_creates_a_durable_request_attempt() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let client = world.client("Alice");
    for (id, text) in [
        ("not-a-uuid", "hello"),
        ("11111111-1111-4111-8111-111111111111", "  "),
    ] {
        let result = client
            .orchestrator
            .start_direct_request(DirectRequestInput {
                draft_id: id.into(),
                recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
                text: text.into(),
                invitation: None,
            })
            .await;
        assert!(matches!(result, Err(OrchestratorError::InvalidInput(_))));
    }
    assert!(client
        .orchestrator
        .mls_context()
        .list_direct_request_intents()
        .unwrap()
        .is_empty());
}

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{canonical_transport::CanonicalOperation as Op, CredentialStore};
use catbird_mls::{DirectRequestOutcome, RequestConsent, RequestCrypto, RequestPreview};
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn receipt_authority() -> (p256::ecdsa::SigningKey, Vec<u8>, String) {
    let key = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(true);
    let id = protocol::direct_request_receipt_key_id(point.as_bytes()).unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(point.as_bytes());
    let doc=serde_json::to_vec(&json!({"id":"did:web:chat.catbird.blue","verificationMethod":[{"id":id,"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)}]})).unwrap();
    (key, doc, id)
}
fn es256(key: &p256::ecdsa::SigningKey, bytes: &[u8]) -> String {
    let sig: p256::ecdsa::Signature = key.sign(bytes);
    STANDARD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
}
fn utc(delta: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(delta))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn last_request(world: &TestWorld, op: Op) -> Value {
    let requests = world.delivery_service().submitted_prepared_requests();
    serde_json::from_slice(
        requests
            .iter()
            .rev()
            .find(|r| r.operation == op)
            .unwrap()
            .body
            .as_ref()
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread")]
async fn native_sender_exact_retry_and_recipient_preview_survive_reopen_without_acceptance() {
    sender_fixture(false, false).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn legacy_pending_direct_retains_exact_prior_and_builds_successor_generation() {
    sender_fixture(true, false).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn native_dag_json_read_preview_acceptance_and_exact_retry_survive_restart() {
    sender_fixture(false, true).await;
}

fn last_request_bytes(world: &TestWorld, op: Op) -> Vec<u8> {
    world
        .delivery_service()
        .submitted_prepared_requests()
        .iter()
        .rev()
        .find(|r| r.operation == op)
        .unwrap()
        .body
        .clone()
        .unwrap()
}

/// Independent read fixture producer follows the exact embedded lexicon bytes
/// declarations. It never guesses from field names or base64-looking strings.
fn read_bytes(mode: bool, name: &str, tagged: bool, value: &Value) -> Value {
    if !mode {
        return value.clone();
    }
    let contract: Value = serde_json::from_str(include_str!(
        "../src/chat_v2/transcript/vectors/blue.catbird.chat.defs.json"
    ))
    .unwrap();
    fn convert(defs: &Value, schema: &Value, value: &mut Value) {
        match schema["type"].as_str().unwrap() {
            "bytes" => {
                assert!(value.is_string());
                *value = json!({"$bytes":value.clone()});
            }
            "ref" => convert(
                defs,
                &defs[schema["ref"].as_str().unwrap().strip_prefix('#').unwrap()],
                value,
            ),
            "union" => {
                let name = value["$type"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("blue.catbird.chat.defs#")
                    .unwrap();
                assert!(schema["refs"].as_array().unwrap().iter().any(|r| r
                    .as_str()
                    .unwrap()
                    .strip_prefix('#')
                    == Some(name)));
                convert(defs, &defs[name], value);
            }
            "object" => {
                for (field, item) in value.as_object_mut().unwrap() {
                    if field != "$type" {
                        convert(defs, &schema["properties"][field], item);
                    }
                }
            }
            "array" => {
                for item in value.as_array_mut().unwrap() {
                    convert(defs, &schema["items"], item)
                }
            }
            "string" | "integer" | "boolean" => {}
            other => panic!("unsupported read fixture schema {other}"),
        }
    }
    let mut presented = value.clone();
    convert(&contract["defs"], &contract["defs"][name], &mut presented);
    assert_eq!(
        protocol::normalize_read_presentation(
            &serde_json::to_vec(&presented).unwrap(),
            name,
            tagged
        )
        .unwrap(),
        *value
    );
    presented
}

async fn seed_pending_origin(world: &TestWorld, group: bool) -> (Value, Value) {
    let alice = world.client("Alice");
    let mut members = vec![world.client("Bob").did.clone()];
    if group {
        members.push("did:plc:cccccccccccccccccccccccc".into());
    }
    let mut view = alice
        .orchestrator
        .create_group("Pending", Some(&members), None)
        .await
        .unwrap();
    let wrapper = last_request(world, Op::CreateConversation);
    let b = &wrapper["signedRequest"]["body"];
    let mut participants = b["manifest"]["participants"].clone();
    for p in participants.as_array_mut().unwrap() {
        p["leafCount"] = json!(if p["status"] == "active" { 1 } else { 0 });
    }
    let state = json!({"conversationKind":b["conversationKind"],"coordinates":b["next"],"cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519","participants":participants,"leaves":[{"userDid":b["actorDid"],"deviceId":b["actorDeviceId"],"deviceStatus":"active","leafOrigin":"genesis","keyId":b["keyId"]}],"metadataSnapshot":b["metadataSnapshot"],"snapshotSeq":1});
    view.canonical_state = Some(
        catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
            &serde_json::to_vec(&state).unwrap(),
        )
        .unwrap(),
    );
    let cid = view.conversation_id.clone();
    world
        .delivery_service()
        .set_conversation_view_for_test(&cid, view);
    world
        .delivery_service()
        .set_lifecycle_state_for_test(&cid, state.clone());
    let entry = json!({"$type":"blue.catbird.chat.defs#creationEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":1,"signedRequest":wrapper["signedRequest"],"receivedAt":utc(0)});
    (state, entry)
}
async fn sender_fixture(legacy: bool, dag_json: bool) {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    let (authority, doc, method) = receipt_authority();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(doc.clone());
    }
    let (invitation_state, invitation_entry) = seed_pending_origin(&world, true).await;
    let invitation_provenance = invitation_state["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["userDid"] == world.client("Bob").did)
        .unwrap()["invitationProvenance"]
        .clone();
    let legacy_state = if legacy {
        Some(seed_pending_origin(&world, false).await.0)
    } else {
        None
    };
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries":[invitation_entry],"hasMore":false,"nextAfterSeq":1}),
    );
    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: world.client("Bob").did.clone(),
        text: "Real encrypted request".into(),
        invitation: Some(catbird_mls::GroupInvitationReference {
            authority_did: "did:web:chat.catbird.blue".into(),
            conversation_id: invitation_state["coordinates"]["conversationId"]
                .as_str()
                .unwrap()
                .into(),
            invitation_transition_id: invitation_provenance["invitationTransitionId"]
                .as_str()
                .unwrap()
                .into(),
            invited_by_did: world.client("Alice").did.clone(),
            invited_by_device_id: world
                .client("Alice")
                .credentials
                .get_device_uuid(&world.client("Alice").did)
                .await
                .unwrap()
                .unwrap(),
            recipient_did: world.client("Bob").did.clone(),
        }),
    };
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error":"unavailable"}),
    );
    let unknown = world
        .client("Alice")
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .unwrap();
    assert!(matches!(
        unknown,
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));
    let original = last_request(&world, Op::PrepareDirectRequest);
    let original_bytes = last_request_bytes(&world, Op::PrepareDirectRequest);
    let prepare = &original["signedRequest"]["body"];
    let alice = world.client("Alice");
    let device = alice
        .credentials
        .get_device_uuid(&alice.did)
        .await
        .unwrap()
        .unwrap();
    let pubkey = alice
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{}#{device}", alice.did))
        .unwrap();
    let verified = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&original["signedRequest"]).unwrap(),
        &pubkey,
    )
    .unwrap();
    let bob = world.client("Bob");
    let bob_device = bob
        .credentials
        .get_device_uuid(&bob.did)
        .await
        .unwrap()
        .unwrap();
    let identity = format!("{}#{bob_device}", bob.did).into_bytes();
    let package = bob
        .orchestrator
        .mls_context()
        .create_key_package(identity.clone())
        .unwrap();
    let bob_public = bob
        .orchestrator
        .mls_context()
        .identity_public_key(String::from_utf8(identity.clone()).unwrap())
        .unwrap();
    let grant_id = uuid::Uuid::new_v4().to_string();
    let grant = json!({"$type":"blue.catbird.chat.defs#directRequestGrantBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2","actorDid":bob.did,"actorDeviceId":bob_device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"authGeneration":1,"grantId":grant_id,"grantRevision":1,"purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1","keyPackageRef":STANDARD.encode(&package.hash_ref),"keyPackageSha256":STANDARD.encode(Sha256::digest(&package.key_package_data)),"expiresAt":utc(29*86400),"idempotencyKey":grant_id,"signedAt":utc(0)});
    let signature = bob
        .orchestrator
        .mls_context()
        .sign_with_identity_key(
            String::from_utf8(identity).unwrap(),
            protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Grant,
                &serde_json::to_vec(&grant).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let selected = json!({"actorDid":bob.did,"actorDeviceId":bob_device,"keyId":grant["keyId"],"authGeneration":1,"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage","bytes":STANDARD.encode(&package.key_package_data),"sha256":STANDARD.encode(Sha256::digest(&package.key_package_data)),"keyPackageRef":STANDARD.encode(&package.hash_ref)},"grant":{"body":grant,"signature":STANDARD.encode(signature)}});
    let mut preparation = json!({"protocolVersion":"2","requestId":prepare["requestId"],"firstMessageId":prepare["firstMessageId"],"conversationId":prepare["conversationId"],"recipientDid":prepare["recipientDid"],"origin":prepare["origin"],"profile":prepare["profile"],"creator":{"actorDid":prepare["actorDid"],"actorDeviceId":prepare["actorDeviceId"],"keyId":prepare["keyId"],"authGeneration":prepare["authGeneration"]},"selectedDevices":[selected],"preparedAt":utc(0),"leaseExpiresAt":utc(600),"minimumImportUntil":utc(7*86400+300-5),"preparationRequestDigest":STANDARD.encode(verified.request_digest()),"authorityDid":"did:web:chat.catbird.blue","receiptKeyId":method});
    let signing = protocol::direct_request_preparation_signing_bytes(
        &serde_json::to_vec(&preparation).unwrap(),
    )
    .unwrap();
    preparation["preparationDigest"] = json!(STANDARD.encode(Sha256::digest(&signing)));
    preparation["preparationSignature"] = json!(es256(&authority, &signing));
    let read_preparation = read_bytes(
        dag_json,
        "directRequestPreparationView",
        false,
        &preparation,
    );
    if dag_json {
        assert!(read_preparation["selectedDevices"][0]["grant"]["signature"]
            .get("$bytes")
            .is_some());
    }
    world.delivery_service().queue_request_operation_response(Op::PrepareDirectRequest,200,json!({"outcome":{"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":read_preparation}}));
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        503,
        json!({"error":"lost"}),
    );
    let retry = alice
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(retry, DirectRequestOutcome::OutcomeUnknown { .. }));
    assert_eq!(original, last_request(&world, Op::PrepareDirectRequest));
    assert_eq!(
        original_bytes,
        last_request_bytes(&world, Op::PrepareDirectRequest)
    );
    let publication = last_request(&world, Op::PublishDirectRequest);
    let publication_bytes = last_request_bytes(&world, Op::PublishDirectRequest);
    let p = &publication["signedRequest"]["body"];
    if let Some(legacy) = legacy_state {
        assert_eq!(p["conversationId"], legacy["coordinates"]["conversationId"]);
        assert_eq!(p["origin"]["exactPrior"], legacy["coordinates"]);
        assert_eq!(
            p["next"]["generation"].as_u64(),
            Some(legacy["coordinates"]["generation"].as_u64().unwrap() + 1)
        );
        assert_eq!(
            p["artifacts"]["metadataSnapshot"]["authorProof"]["originSeq"],
            json!(2)
        );
        let raw = world
            .client("Alice")
            .orchestrator
            .mls_context()
            .read_direct_request_intent(&input.draft_id)
            .unwrap()
            .unwrap();
        catbird_mls::orchestrator::direct_requests::DirectRequestIntent::decode(
            &raw,
            &world.client("Alice").did,
            &device,
        )
        .unwrap();
        return;
    }
    let verified_publish = protocol::verify_signed_request(
        protocol::DirectRequestKind::Publish,
        &serde_json::to_vec(&publication["signedRequest"]).unwrap(),
        &pubkey,
    )
    .unwrap();
    let body = json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":method,"receipt":{"$type":"blue.catbird.chat.defs#directRequestPublishedReceipt","requestId":p["requestId"],"requestKind":"publish","requestDigest":STANDARD.encode(verified_publish.request_digest()),"preparationRequestDigest":STANDARD.encode(verified.request_digest()),"actorDid":p["actorDid"],"actorDeviceId":p["actorDeviceId"],"actorKeyId":p["keyId"],"authGeneration":p["authGeneration"],"conversationId":p["conversationId"],"firstMessageId":p["firstMessageId"],"coordinates":p["next"],"recordedAt":utc(0)}});
    let receipt = json!({"$type":"blue.catbird.chat.defs#signedDirectRequestReceipt","signature":es256(&authority,&protocol::direct_request_signing_bytes(protocol::DirectRequestKind::Outcome,&serde_json::to_vec(&body).unwrap()).unwrap()),"body":body});
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequest,
        200,
        json!({"outcome":read_bytes(dag_json, "signedDirectRequestReceipt", true, &receipt)}),
    );
    let sent = alice
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(sent, DirectRequestOutcome::RequestSent { .. }));
    assert_eq!(publication, last_request(&world, Op::PublishDirectRequest));
    assert_eq!(
        publication_bytes,
        last_request_bytes(&world, Op::PublishDirectRequest)
    );
    let cid = p["conversationId"].as_str().unwrap();
    // Replaying a published outcome must validate an existing encrypted
    // projection instead of treating mere presence as completed adoption.
    let saved = alice
        .orchestrator
        .mls_context()
        .read_direct_request_projection(cid)
        .unwrap()
        .unwrap();
    let mut corrupted: Value = serde_json::from_slice(&saved).unwrap();
    corrupted["sender_public_key"] = json!([0]);
    let corrupted = serde_json::to_vec(&corrupted).unwrap();
    assert!(alice
        .orchestrator
        .mls_context()
        .compare_exchange_direct_request_projection(cid, Some(&saved), &corrupted)
        .unwrap());
    assert!(alice
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .is_err());
    assert!(alice
        .orchestrator
        .mls_context()
        .compare_exchange_direct_request_projection(cid, Some(&corrupted), &saved)
        .unwrap());
    let publication_entry = json!({"$type":"blue.catbird.chat.defs#directRequestEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":1,"signedRequest":publication["signedRequest"],"receivedAt":receipt["body"]["receipt"]["recordedAt"]});
    let publication_entry = read_bytes(dag_json, "directRequestEntry", true, &publication_entry);
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries":[publication_entry],"nextAfterSeq":1,"hasMore":false}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetDirectRequestOutcome,
        200,
        json!({"outcome":read_bytes(dag_json, "signedDirectRequestReceipt", true, &receipt)}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error":"offline"}),
    );
    let view = bob.orchestrator.refresh_request_preview(cid).await.unwrap();
    assert_eq!(view.consent, RequestConsent::IncomingPending);
    assert_eq!(view.crypto, RequestCrypto::Ready);
    let group_id = hex::encode(
        STANDARD
            .decode(p["next"]["groupId"].as_str().unwrap())
            .unwrap(),
    );
    let durable_group = bob
        .storage
        .get_group_state(&group_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable_group.conversation_id, cid);
    assert_eq!(durable_group.epoch, p["next"]["epoch"].as_u64().unwrap());

    assert_eq!(
        view.preview,
        Some(RequestPreview::Ready {
            invitation: input.invitation.clone(),
            text: input.text.clone()
        })
    );
    assert!(
        !view.capabilities.can_send
            && !view.capabilities.can_emit_receipts
            && !view.capabilities.can_administer
    );
    assert!(bob.storage.get_conversation_messages(cid).is_empty());
    let intro_meta = view.introduction.as_ref().unwrap();
    assert_eq!(intro_meta.sender_did, p["actorDid"]);
    assert_eq!(intro_meta.sender_device_id, p["actorDeviceId"]);
    assert_eq!(
        intro_meta.received_at,
        receipt["body"]["receipt"]["recordedAt"]
    );
    let request_envelope =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&publication_entry, cid)
            .unwrap()
            .unwrap();
    world
        .delivery_service()
        .queue_incoming_page(vec![request_envelope.clone()], Some("1".into()));
    let (messages, cursor) = bob
        .orchestrator
        .fetch_messages(cid, None, 100, None, None, None)
        .await
        .unwrap();
    assert!(messages.is_empty());
    assert_eq!(cursor.as_deref(), Some("1"));
    assert!(bob.storage.get_conversation_messages(cid).is_empty());
    let mut forged_entry = publication_entry.clone();
    forged_entry["entryId"] = json!(uuid::Uuid::new_v4().to_string());
    let forged =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&forged_entry, cid)
            .unwrap()
            .unwrap();
    world
        .delivery_service()
        .queue_incoming_page(vec![forged], Some("2".into()));
    assert!(bob
        .orchestrator
        .fetch_messages(cid, Some("1"), 100, None, None, None)
        .await
        .is_err());
    assert!(bob.storage.get_conversation_messages(cid).is_empty());
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":{"directRequest":{"consent":"accepted"}}}),
    );
    assert_eq!(
        bob.orchestrator
            .refresh_request_preview(cid)
            .await
            .unwrap()
            .consent,
        RequestConsent::IncomingPending
    );
    for name in ["Alice", "Bob"] {
        let ordinary = catbird_mls::orchestrator::IncomingEnvelope {
            canonical_entry_json: None,
            conversation_id: cid.into(),
            sender_did: world.client("Alice").did.clone(),
            ciphertext: vec![0; 32],
            timestamp: chrono::Utc::now(),
            server_message_id: Some(uuid::Uuid::new_v4().to_string()),
            server_sequence: Some(2),
            server_epoch: p["next"]["epoch"].as_u64(),
        };
        let result = world
            .client(name)
            .orchestrator
            .process_incoming_message(&ordinary)
            .await;
        assert!(
            matches!(result,Err(OrchestratorError::InvalidInput(ref why)) if why=="RequestNotAccepted")
        );
        assert!(world
            .client(name)
            .storage
            .get_conversation_messages(cid)
            .is_empty());
    }

    let cid = cid.to_owned();
    world.restart_client("Bob").await;
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error":"offline"}),
    );
    let retained = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    assert_eq!(retained, view);
    // Acceptance is policy-only. Losing its first response keeps exact intent
    // bytes; an authority-signed commit proof advances consent at the same epoch.
    world.delivery_service().queue_request_operation_response(
        Op::AcceptConversation,
        503,
        json!({"error":"lost acceptance response"}),
    );
    assert!(world
        .client("Bob")
        .orchestrator
        .accept_conversation(&cid)
        .await
        .is_err());
    let pending_accept = last_request(&world, Op::AcceptConversation);
    let pending_accept_bytes = last_request_bytes(&world, Op::AcceptConversation);
    let accepted = &pending_accept["directRequest"]["body"];
    let acceptance = protocol::verify_signed_request(
        protocol::DirectRequestKind::Accept,
        &serde_json::to_vec(&pending_accept["directRequest"]).unwrap(),
        &bob_public,
    )
    .unwrap();
    let entry = json!({"entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":2,"signedRequest":pending_accept["directRequest"],"receivedAt":utc(0)});
    let acceptance_receipt = json!({"$type":"blue.catbird.chat.defs#directRequestAcceptanceCommitReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPTANCE-COMMIT\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":method,"requestId":accepted["requestId"],"acceptanceDigest":STANDARD.encode(acceptance.request_digest()),"entryHash":STANDARD.encode(protocol::direct_request_acceptance_entry_hash(&serde_json::to_vec(&entry).unwrap()).unwrap()),"prior":accepted["prior"],"next":accepted["next"],"recordedAt":utc(0)});
    let proof = json!({"entry":entry,"receipt":{"body":acceptance_receipt,"signature":es256(&authority,&protocol::direct_request_signing_bytes(protocol::DirectRequestKind::AcceptanceCommit,&serde_json::to_vec(&acceptance_receipt).unwrap()).unwrap())}});
    world.delivery_service().queue_request_operation_response(
        Op::AcceptConversation,
        200,
        json!({"coordinates":read_bytes(dag_json, "conversationCoordinates", false, &accepted["next"]),"acceptanceProof":read_bytes(dag_json, "directRequestAcceptanceProof", false, &proof)}),
    );
    world
        .client("Bob")
        .orchestrator
        .accept_conversation(&cid)
        .await
        .unwrap();
    assert_eq!(pending_accept, last_request(&world, Op::AcceptConversation));
    assert_eq!(
        pending_accept_bytes,
        last_request_bytes(&world, Op::AcceptConversation)
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error":"offline"}),
    );
    let accepted_view = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    assert_eq!(accepted_view.consent, RequestConsent::Accepted);
    assert!(accepted_view.capabilities.can_send);
    if dag_json {
        world.restart_client("Bob").await;
        world.delivery_service().queue_request_operation_response(
            Op::GetConversationState,
            503,
            json!({"error":"offline after accepted read proof"}),
        );
        let reopened = world
            .client("Bob")
            .orchestrator
            .refresh_request_preview(&cid)
            .await
            .unwrap();
        assert_eq!(
            reopened, accepted_view,
            "accepted read proof and decrypted preview must survive reopen"
        );
    }
    assert_eq!(accepted["prior"]["epoch"], accepted["next"]["epoch"]);
    let state = json!({"conversationKind":"direct","coordinates":accepted["next"],"cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519","participants":[{"userDid":p["actorDid"],"role":"admin","status":"active","leafCount":1},{"userDid":p["recipientDid"],"role":"admin","status":"active","leafCount":1,"invitationProvenance":{"invitationTransitionId":p["requestId"],"invitedByDid":p["actorDid"],"invitedByDeviceId":p["actorDeviceId"]}}],"leaves":[{"userDid":p["actorDid"],"deviceId":p["actorDeviceId"],"leafOrigin":"genesis","keyId":p["keyId"],"deviceStatus":"active"},{"userDid":p["recipientDid"],"deviceId":bob_device,"leafOrigin":"keyPackage","joinKeyPackageRef":STANDARD.encode(&package.hash_ref),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"deviceStatus":"active"}],"metadataSnapshot":p["artifacts"]["metadataSnapshot"],"snapshotSeq":2,"directRequest":{"requestId":p["requestId"],"firstMessageId":p["firstMessageId"],"senderDid":p["actorDid"],"recipientDid":p["recipientDid"],"consent":"accepted","importUntil":p["importUntil"],"contextHash":p["contextHash"],"preparationDigest":p["preparationDigest"],"acceptanceProof":proof}});
    let typed = catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
        &serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    let encoded =
        catbird_mls::orchestrator::canonical_transport::encode_conversation_state(&typed).unwrap();
    assert_eq!(
        catbird_mls::orchestrator::canonical_transport::decode_conversation_state(&encoded)
            .unwrap(),
        typed
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":read_bytes(dag_json, "conversationState", false, &state)}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetDeviceKey, 200,
        json!({"ownerDid":p["recipientDid"],"deviceId":bob_device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"signaturePublicKey":STANDARD.encode([0u8;32])}),
    );
    let unverified = world
        .client("Alice")
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    assert_eq!(unverified.consent, RequestConsent::OutgoingPending);
    assert!(!unverified.capabilities.can_send);
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":read_bytes(dag_json, "conversationState", false, &state)}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetDeviceKey, 200,
        json!({"ownerDid":p["recipientDid"],"deviceId":bob_device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"signaturePublicKey":STANDARD.encode(&bob_public)}),
    );
    let sender = world
        .client("Alice")
        .orchestrator
        .refresh_request_preview(&cid)
        .await
        .unwrap();
    assert_eq!(sender.consent, RequestConsent::Accepted);
    // The group-note lookup consumes a separate authenticated canonical state
    // and exact signed policy invitation. It never reuses request consent.
    let invitation_id = uuid::Uuid::new_v4().to_string();
    let mut group_state = state.clone();
    group_state.as_object_mut().unwrap().remove("directRequest");
    group_state["conversationKind"] = json!("group");
    group_state["coordinates"]["stateVersion"] = json!(3);
    group_state["snapshotSeq"] = json!(3);
    let provenance = json!({"invitationTransitionId":invitation_id,"invitedByDid":p["actorDid"],"invitedByDeviceId":p["actorDeviceId"]});
    group_state["participants"][1]["status"] = json!("pending");
    group_state["participants"][1]["leafCount"] = json!(0);
    group_state["leaves"]
        .as_array_mut()
        .unwrap()
        .retain(|leaf| leaf["userDid"] != p["recipientDid"]);
    group_state["participants"][1]["invitationProvenance"] = provenance.clone();
    let invitation_body = json!({"$type":"blue.catbird.chat.defs#policyTransitionBody","signatureDomain":"CATBIRD-CHAT-POLICY\0","transitionId":invitation_id,"idempotencyKey":invitation_id,"actorDid":p["actorDid"],"actorDeviceId":p["actorDeviceId"],"keyId":p["keyId"],"authGeneration":1,"prior":state["coordinates"],"next":group_state["coordinates"],"participantChanges":[{"$type":"blue.catbird.chat.defs#addParticipant","userDid":p["recipientDid"],"role":"member","status":"pending","invitationProvenance":provenance}],"signedAt":utc(0)});
    use catbird_mls::chat_v2::transcript::{
        decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
    };
    let strict = decode_strict_json(&serde_json::to_vec(&invitation_body).unwrap()).unwrap();
    let transcript = SigningTranscript::build_for(
        SignedMutationKind::PolicyTransition,
        &project_signed_body(SignedMutationKind::PolicyTransition, &strict).unwrap(),
    )
    .unwrap();
    let author = world.client("Alice");
    let signature = author
        .orchestrator
        .mls_context()
        .sign_with_identity_key(
            format!("{}#{}", author.did, p["actorDeviceId"].as_str().unwrap()),
            transcript.bytes().to_vec(),
        )
        .unwrap();
    author
        .credentials
        .set_authorized_device_keys(&author.did, vec![pubkey.clone()]);
    let invitation_entry = json!({"$type":"blue.catbird.chat.defs#policyEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":3,"signedRequest":{"body":invitation_body,"signature":STANDARD.encode(signature)},"receivedAt":utc(0)});
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries":[invitation_entry],"hasMore":false,"nextAfterSeq":3}),
    );
    let link = author
        .orchestrator
        .get_group_invitation_reference(&cid, p["recipientDid"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(link.invitation_transition_id, invitation_id);
    assert_eq!(link.recipient_did, p["recipientDid"]);
    let mut forged_invitation = invitation_entry.clone();
    forged_invitation["signedRequest"]["body"]["participantChanges"][0]["userDid"] =
        json!("did:plc:cccccccccccccccccccccccc");
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":group_state}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetEntries,
        200,
        json!({"entries":[forged_invitation],"hasMore":false,"nextAfterSeq":3}),
    );
    assert!(author
        .orchestrator
        .get_group_invitation_reference(&cid, p["recipientDid"].as_str().unwrap())
        .await
        .is_err());
    group_state["participants"][1]["status"] = json!("active");
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":group_state}),
    );
    assert!(author
        .orchestrator
        .get_group_invitation_reference(&cid, p["recipientDid"].as_str().unwrap())
        .await
        .unwrap()
        .is_none());
    let mut acceptance_entry = proof["entry"].clone();
    acceptance_entry["$type"] = json!("blue.catbird.chat.defs#directRequestAcceptanceEntry");
    let acceptance_entry = read_bytes(
        dag_json,
        "directRequestAcceptanceEntry",
        true,
        &acceptance_entry,
    );
    let acceptance_envelope =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&acceptance_entry, &cid)
            .unwrap()
            .unwrap();
    world
        .delivery_service()
        .queue_incoming_page(vec![acceptance_envelope.clone()], Some("2".into()));
    let (introduced, cursor) = world
        .client("Alice")
        .orchestrator
        .fetch_messages(&cid, None, 100, None, None, None)
        .await
        .unwrap();
    assert_eq!(cursor.as_deref(), Some("2"));
    assert_eq!(introduced.len(), 1);
    assert_eq!(introduced[0].id, p["firstMessageId"]);
    assert_eq!(introduced[0].sender_did, p["actorDid"]);
    assert_eq!(introduced[0].text, input.text);
    world
        .delivery_service()
        .queue_incoming_page(vec![acceptance_envelope], Some("2".into()));
    let (duplicate, _) = world
        .client("Alice")
        .orchestrator
        .fetch_messages(&cid, None, 100, None, None, None)
        .await
        .unwrap();
    assert!(duplicate.is_empty());
    let native_policy = world
        .client("Alice")
        .orchestrator
        .mls_context()
        .get_conversation_policy(&world.client("Alice").did, &cid)
        .unwrap()
        .unwrap();
    assert_eq!(native_policy.coordinates, typed.coordinates);
    assert!(native_policy
        .direct_request
        .unwrap()
        .acceptance_proof
        .is_some());
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .list_direct_request_views()
            .await
            .unwrap()
            .len(),
        1
    );
    let alice = world.client("Alice");
    let actor_public = alice
        .orchestrator
        .mls_context()
        .identity_public_key(format!(
            "{}#{}",
            alice.did,
            alice.orchestrator.require_actor_device_id().await.unwrap()
        ))
        .unwrap();
    alice
        .credentials
        .set_authorized_device_keys(&alice.did, vec![actor_public]);
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        200,
        json!({"state":read_bytes(dag_json, "conversationState", false, &state)}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::CloseConversation,
        503,
        json!({"error":"lost"}),
    );
    assert!(alice.orchestrator.close_direct_request(&cid).await.is_err());
    assert_ne!(
        alice
            .orchestrator
            .list_direct_request_views()
            .await
            .unwrap()[0]
            .consent,
        RequestConsent::Closed
    );
    let close = last_request(&world, Op::CloseConversation);
    let body = &close["signedRequest"]["body"];
    let tombstone = json!({"$type":"blue.catbird.chat.defs#conversationCloseTombstone","conversationId":cid,"conversationKind":"direct","retired":body["retired"],"closedByDid":body["actorDid"],"closedByDeviceId":body["actorDeviceId"],"terminalSeq":3,"closedAt":utc(0)});
    let entry = json!({"$type":"blue.catbird.chat.defs#conversationCloseEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":3,"signedRequest":close["signedRequest"],"receivedAt":tombstone["closedAt"],"tombstone":tombstone});
    world.delivery_service().queue_request_operation_response(
        Op::CloseConversation,
        200,
        json!({"result":{"entry":entry,"tombstone":tombstone}}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        404,
        json!({"error":"ConversationNotFound"}),
    );
    let closed = alice.orchestrator.close_direct_request(&cid).await.unwrap();
    assert_eq!(closed.consent, RequestConsent::Closed);
    assert!(!closed.capabilities.can_send);
    let closed_envelope =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&entry, &cid)
            .unwrap()
            .unwrap();
    assert!(alice
        .orchestrator
        .process_incoming_message(&closed_envelope)
        .await
        .is_ok());
    let mut server_read_entry = entry.clone();
    server_read_entry["signedRequest"]["signature"] =
        json!({"$bytes": entry["signedRequest"]["signature"]});
    let read_closed_envelope =
        catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(&server_read_entry, &cid)
            .unwrap()
            .unwrap();
    assert!(alice
        .orchestrator
        .process_incoming_message(&read_closed_envelope)
        .await
        .is_ok());
    assert!(alice
        .orchestrator
        .process_incoming_message(&closed_envelope)
        .await
        .is_ok());
    assert_eq!(close, last_request(&world, Op::CloseConversation));
    assert!(alice
        .orchestrator
        .mls_context()
        .get_epoch(
            STANDARD
                .decode(p["next"]["groupId"].as_str().unwrap())
                .unwrap()
        )
        .is_err());
    assert_eq!(alice.orchestrator.mls_context().list_direct_request_journal().unwrap()[0].phase,catbird_mls::orchestrator::direct_request_journal::DirectRequestJournalPhase::RetiredPublished);
    let projection = alice
        .orchestrator
        .mls_context()
        .read_direct_request_projection(&cid)
        .unwrap();
    alice
        .storage
        .delete_conversations(&alice.did, &[&cid])
        .await
        .unwrap();
    assert!(
        matches!(alice.orchestrator.resume_direct_request(&input.draft_id).await,Err(OrchestratorError::InvalidInput(code)) if code=="RequestRetired")
    );
    assert_eq!(
        alice
            .orchestrator
            .refresh_request_preview(&cid)
            .await
            .unwrap()
            .consent,
        RequestConsent::Closed
    );
    assert!(alice
        .storage
        .get_conversation(&alice.did, &cid)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .read_direct_request_projection(&cid)
            .unwrap(),
        projection
    );
    world.restart_client("Alice").await;
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .list_direct_request_views()
            .await
            .unwrap()[0]
            .consent,
        RequestConsent::Closed
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_proof_fences_edits_and_retains_exact_prior_attempt_across_restart() {
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let (authority, doc, method) = receipt_authority();
    let alice = world.client("Alice");
    alice.credentials.set_request_authority_document(doc);
    let mut input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        text: "Original".into(),
        invitation: None,
    };
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error":"lost"}),
    );
    assert!(matches!(
        alice
            .orchestrator
            .start_direct_request(input.clone())
            .await
            .unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));
    let prepare = last_request(&world, Op::PrepareDirectRequest);
    let p = &prepare["signedRequest"]["body"];
    input.text = "Edited".into();
    assert!(alice
        .orchestrator
        .start_direct_request(input.clone())
        .await
        .is_err());
    world.delivery_service().queue_request_operation_response(
        Op::CancelDirectRequestPreparation,
        503,
        json!({"error":"lost"}),
    );
    assert!(matches!(
        alice
            .orchestrator
            .cancel_direct_request(&input.draft_id)
            .await
            .unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));
    let cancel = last_request(&world, Op::CancelDirectRequestPreparation);
    let device = alice
        .credentials
        .get_device_uuid(&alice.did)
        .await
        .unwrap()
        .unwrap();
    let public = alice
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{}#{device}", alice.did))
        .unwrap();
    let verified_prepare = protocol::verify_signed_request(
        protocol::DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare["signedRequest"]).unwrap(),
        &public,
    )
    .unwrap();
    let verified_cancel = protocol::verify_signed_request(
        protocol::DirectRequestKind::Cancel,
        &serde_json::to_vec(&cancel["signedRequest"]).unwrap(),
        &public,
    )
    .unwrap();
    let receipt = json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":method,"receipt":{"$type":"blue.catbird.chat.defs#directRequestCancelledReceipt","requestId":p["requestId"],"requestKind":"cancel","requestDigest":STANDARD.encode(verified_cancel.request_digest()),"preparationRequestDigest":STANDARD.encode(verified_prepare.request_digest()),"actorDid":p["actorDid"],"actorDeviceId":p["actorDeviceId"],"actorKeyId":p["keyId"],"authGeneration":p["authGeneration"],"recordedAt":utc(0)}});
    let signature = es256(
        &authority,
        &protocol::direct_request_signing_bytes(
            protocol::DirectRequestKind::Outcome,
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap(),
    );
    world.delivery_service().queue_request_operation_response(Op::CancelDirectRequestPreparation,200,json!({"outcome":{"$type":"blue.catbird.chat.defs#signedDirectRequestReceipt","body":receipt,"signature":signature}}));
    assert!(matches!(
        alice
            .orchestrator
            .cancel_direct_request(&input.draft_id)
            .await
            .unwrap(),
        DirectRequestOutcome::TerminalNotPublished { .. }
    ));
    assert_eq!(
        cancel,
        last_request(&world, Op::CancelDirectRequestPreparation)
    );
    world.delivery_service().queue_request_operation_response(
        Op::PrepareDirectRequest,
        503,
        json!({"error":"lost"}),
    );
    assert!(matches!(
        alice
            .orchestrator
            .start_direct_request(input.clone())
            .await
            .unwrap(),
        DirectRequestOutcome::OutcomeUnknown { .. }
    ));
    let fresh = last_request(&world, Op::PrepareDirectRequest);
    assert_ne!(
        prepare["signedRequest"]["body"]["requestId"],
        fresh["signedRequest"]["body"]["requestId"]
    );
    let raw = alice
        .orchestrator
        .mls_context()
        .read_direct_request_intent(&input.draft_id)
        .unwrap()
        .unwrap();
    let intent = catbird_mls::orchestrator::direct_requests::DirectRequestIntent::decode(
        &raw, &alice.did, &device,
    )
    .unwrap();
    assert_eq!(intent.previous_attempts.len(), 1);
    assert_eq!(intent.input.text, "Edited");
    world.restart_client("Alice").await;
    assert_eq!(
        world
            .client("Alice")
            .orchestrator
            .mls_context()
            .read_direct_request_intent(&input.draft_id)
            .unwrap()
            .unwrap(),
        raw
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn request_key_pool_retries_exact_durable_batch_and_counts_reserved_custody() {
    use catbird_mls::orchestrator::direct_request_keys::DirectRequestKeyPublication;
    let mut world = TestWorld::new();
    world
        .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        .await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let device = alice.orchestrator.require_actor_device_id().await.unwrap();
    let public = alice
        .orchestrator
        .mls_context()
        .identity_public_key(format!("{}#{device}", alice.did))
        .unwrap();
    let generation = alice
        .credentials
        .get_auth_generation(&alice.did)
        .await
        .unwrap()
        .unwrap();
    let stats = |usable, reserved, revision, enabled| json!({"items":[{"device":{"deviceId":device,"status":"active","keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"signaturePublicKey":STANDARD.encode(&public),"authGeneration":generation},"directRequestKeyPool":{"enabled":enabled,"revision":revision,"usableCount":usable,"reservedCount":reserved,"asOf":utc(0),"usableUntil":utc(605400)}}],"hasMore":false});
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(0, 0, 1, false),
    );
    alice
        .orchestrator
        .replenish_direct_request_keys_if_needed()
        .await
        .unwrap();
    assert!(alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .is_none());
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(0, 64, 1, true),
    );
    alice
        .orchestrator
        .replenish_direct_request_keys_if_needed()
        .await
        .unwrap();
    assert!(alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .is_none());
    let before = alice
        .orchestrator
        .mls_context()
        .list_key_package_hashes()
        .unwrap()
        .len();
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(0, 62, 1, true),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        503,
        json!({"error":"temporary"}),
    );
    assert!(alice
        .orchestrator
        .replenish_direct_request_keys_if_needed()
        .await
        .is_err());
    let raw = alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .unwrap();
    let record = DirectRequestKeyPublication::decode(&raw, &alice.did, &device).unwrap();
    assert!(!record.acknowledged);
    assert_eq!(record.body().unwrap()["keys"].as_array().unwrap().len(), 2);
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap()
            .len(),
        before + 2
    );
    world.restart_client("Alice").await;
    let alice = world.client("Alice");
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .read_direct_request_key_publication(&device)
            .unwrap()
            .unwrap(),
        raw
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(0, 64, 1, true),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        200,
        json!({"revision":2,"enabled":true}),
    );
    alice
        .orchestrator
        .replenish_direct_request_keys_if_needed()
        .await
        .unwrap();
    let sent: Vec<_> = world
        .delivery_service()
        .submitted_prepared_requests()
        .into_iter()
        .filter(|r| r.operation == Op::PublishDirectRequestKeys)
        .collect();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body.as_ref().unwrap(), &record.exact_request);
    assert_eq!(sent[0].body, sent[1].body);
    let acknowledged = alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .unwrap();
    assert!(
        DirectRequestKeyPublication::decode(&acknowledged, &alice.did, &device)
            .unwrap()
            .acknowledged
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap()
            .len(),
        before + 2
    );
    // Explicit revocation is a zero-key signed next revision. A lost reply
    // is retained byte-for-byte on ordinary retry, never reported confirmed.
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(2, 62, 2, true),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        503,
        json!({"error":"temporary"}),
    );
    assert!(alice
        .orchestrator
        .set_direct_request_delivery_enabled(false)
        .await
        .is_err());
    let revocation = alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .unwrap();
    let pending = DirectRequestKeyPublication::decode(&revocation, &alice.did, &device).unwrap();
    assert_eq!(pending.body().unwrap()["enabled"], false);
    assert!(pending.body().unwrap()["keys"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!pending.acknowledged);
    assert_eq!(
        alice
            .orchestrator
            .get_direct_request_delivery_enabled()
            .await
            .unwrap(),
        None
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(0, 0, 3, false),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        200,
        json!({"revision":3,"enabled":false}),
    );
    alice
        .orchestrator
        .replenish_direct_request_keys_if_needed()
        .await
        .unwrap();
    let latest = last_request(&world, Op::PublishDirectRequestKeys);
    assert_eq!(
        serde_json::from_slice::<Value>(&pending.exact_request).unwrap(),
        latest
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap()
            .len(),
        before + 2
    );
    assert_eq!(
        alice
            .orchestrator
            .get_direct_request_delivery_enabled()
            .await
            .unwrap(),
        Some(false)
    );
    // Only an explicit enable creates the initial full request-purpose pool.
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(0, 0, 3, false),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        200,
        json!({"revision":4,"enabled":true}),
    );
    alice
        .orchestrator
        .set_direct_request_delivery_enabled(true)
        .await
        .unwrap();
    assert_eq!(
        last_request(&world, Op::PublishDirectRequestKeys)["signedRequest"]["body"]["keys"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap()
            .len(),
        before + 66
    );
    // A new explicit preference may supersede an unknown older revision. Only
    // acknowledgment of the higher revision establishes the new preference.
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(64, 0, 4, true),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        503,
        json!({"error":"lost"}),
    );
    assert!(alice
        .orchestrator
        .set_direct_request_delivery_enabled(false)
        .await
        .is_err());
    let old_unknown = alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .unwrap();
    world.delivery_service().queue_request_operation_response(
        Op::GetOwnDevices,
        200,
        stats(64, 0, 4, true),
    );
    world.delivery_service().queue_request_operation_response(
        Op::PublishDirectRequestKeys,
        200,
        json!({"revision":6,"enabled":true}),
    );
    alice
        .orchestrator
        .set_direct_request_delivery_enabled(true)
        .await
        .unwrap();
    assert_eq!(
        alice
            .orchestrator
            .get_direct_request_delivery_enabled()
            .await
            .unwrap(),
        Some(true)
    );
    let mut late = DirectRequestKeyPublication::decode(&old_unknown, &alice.did, &device).unwrap();
    late.acknowledged = true;
    assert!(!alice
        .orchestrator
        .mls_context()
        .acknowledge_direct_request_key_publication(
            &device,
            &old_unknown,
            &serde_json::to_vec(&late).unwrap()
        )
        .unwrap());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap()
            .len(),
        before + 66
    );
    let retained = alice
        .orchestrator
        .mls_context()
        .read_direct_request_key_publication(&device)
        .unwrap()
        .unwrap();
    let too_many =
        catbird_mls::orchestrator::direct_request_keys::DirectRequestKeyPublicationInput {
            actor_did: alice.did.clone(),
            actor_device_id: device.clone(),
            auth_generation: 1,
            revision: 7,
            count: 64,
            enabled: true,
        };
    assert!(alice
        .orchestrator
        .mls_context()
        .prepare_direct_request_key_publication(&too_many, Some(&retained))
        .is_err());
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .read_direct_request_key_publication(&device)
            .unwrap()
            .unwrap(),
        retained
    );
    assert_eq!(
        alice
            .orchestrator
            .mls_context()
            .list_key_package_hashes()
            .unwrap()
            .len(),
        before + 66
    );
}
