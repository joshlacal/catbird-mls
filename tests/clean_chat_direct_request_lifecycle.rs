//! Native sender preflight checks. These are not delivery-service publication tests.
#![allow(dead_code)]
mod e2e_harness;
use catbird_mls::orchestrator::{MlsCryptoContext, OrchestratorError};
use catbird_mls::{DirectRequestInput, MLSError};
use e2e_harness::TestWorld;

#[tokio::test]
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

#[tokio::test]
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
#[tokio::test]
async fn native_sender_exact_retry_and_recipient_preview_survive_reopen_without_acceptance() {
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
    let input = DirectRequestInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        recipient_did: world.client("Bob").did.clone(),
        text: "Real encrypted request".into(),
        invitation: None,
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
    let mut preparation = json!({"protocolVersion":"2","requestId":prepare["requestId"],"firstMessageId":prepare["firstMessageId"],"conversationId":prepare["conversationId"],"recipientDid":prepare["recipientDid"],"origin":prepare["origin"],"profile":prepare["profile"],"creator":{"actorDid":prepare["actorDid"],"actorDeviceId":prepare["actorDeviceId"],"keyId":prepare["keyId"],"authGeneration":prepare["authGeneration"]},"selectedDevices":[selected],"preparedAt":utc(0),"leaseExpiresAt":utc(600),"minimumImportUntil":utc(28*86400),"preparationRequestDigest":STANDARD.encode(verified.request_digest()),"authorityDid":"did:web:chat.catbird.blue","receiptKeyId":method});
    let signing = protocol::direct_request_preparation_signing_bytes(
        &serde_json::to_vec(&preparation).unwrap(),
    )
    .unwrap();
    preparation["preparationDigest"] = json!(STANDARD.encode(Sha256::digest(&signing)));
    preparation["preparationSignature"] = json!(es256(&authority, &signing));
    world.delivery_service().queue_request_operation_response(Op::PrepareDirectRequest,200,json!({"outcome":{"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":preparation}}));
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
    let publication = last_request(&world, Op::PublishDirectRequest);
    let p = &publication["signedRequest"]["body"];
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
        json!({"outcome":receipt}),
    );
    let sent = alice
        .orchestrator
        .resume_direct_request(&input.draft_id)
        .await
        .unwrap();
    assert!(matches!(sent, DirectRequestOutcome::RequestSent { .. }));
    assert_eq!(publication, last_request(&world, Op::PublishDirectRequest));
    let cid = p["conversationId"].as_str().unwrap();
    world.delivery_service().queue_request_operation_response(Op::GetEntries,200,json!({"entries":[{"$type":"blue.catbird.chat.defs#directRequestEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":1,"signedRequest":publication["signedRequest"],"receivedAt":utc(0)}],"nextAfterSeq":1,"hasMore":false}));
    world.delivery_service().queue_request_operation_response(
        Op::GetDirectRequestOutcome,
        200,
        json!({"outcome":receipt}),
    );
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error":"offline"}),
    );
    let view = bob.orchestrator.refresh_request_preview(cid).await.unwrap();
    assert_eq!(view.consent, RequestConsent::IncomingPending);
    assert_eq!(view.crypto, RequestCrypto::Ready);
    assert_eq!(
        view.preview,
        Some(RequestPreview::Ready {
            text: input.text.clone()
        })
    );
    assert!(
        !view.capabilities.can_send
            && !view.capabilities.can_emit_receipts
            && !view.capabilities.can_administer
    );
    assert!(bob.storage.get_conversation_messages(cid).is_empty());
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
}
