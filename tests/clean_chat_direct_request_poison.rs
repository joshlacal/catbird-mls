//! C17: real XWING/SQLCipher poisoned introduction isolation.
//! HTTP authority is a signed synthetic fixture; this is not a DS admission test.
#![allow(dead_code)]
mod e2e_harness;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request as protocol;
use catbird_mls::orchestrator::{
    canonical_transport::CanonicalOperation as Op, direct_request_bootstrap::*, CredentialStore,
    MLSStorageBackend, MlsCryptoContext,
};
use catbird_mls::{RequestConsent, RequestCrypto, RequestPreview};
use e2e_harness::TestWorld;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn utc(seconds: u64) -> String {
    chrono::DateTime::from_timestamp(seconds as i64, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
struct Proof {
    welcome: DirectRequestWelcomeInput,
    body: Value,
    entry: Value,
    authority: p256::ecdsa::SigningKey,
    authority_doc: Vec<u8>,
}
impl Proof {
    fn cid(&self) -> &str {
        self.body["conversationId"].as_str().unwrap()
    }
    fn gid(&self) -> Vec<u8> {
        STANDARD
            .decode(self.body["next"]["groupId"].as_str().unwrap())
            .unwrap()
    }
    fn resign(&mut self, world: &TestWorld) {
        let actor = format!(
            "{}#{}",
            self.body["actorDid"].as_str().unwrap(),
            self.body["actorDeviceId"].as_str().unwrap()
        );
        let signing = protocol::direct_request_signing_bytes(
            protocol::DirectRequestKind::Publish,
            &serde_json::to_vec(&self.body).unwrap(),
        )
        .unwrap();
        let signature = world
            .client("Alice")
            .orchestrator
            .mls_context()
            .sign_with_identity_key(actor, signing.clone())
            .unwrap();
        let publication = json!({"body":self.body,"signature":STANDARD.encode(signature)});
        let key = self.authority.verifying_key().to_encoded_point(true);
        let receipt_body = json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":protocol::direct_request_receipt_key_id(key.as_bytes()).unwrap(),"receipt":{"$type":"blue.catbird.chat.defs#directRequestPublishedReceipt","requestId":self.body["requestId"],"requestKind":"publish","requestDigest":STANDARD.encode(Sha256::digest(signing)),"preparationRequestDigest":self.body["preparationRequestDigest"],"actorDid":self.body["actorDid"],"actorDeviceId":self.body["actorDeviceId"],"actorKeyId":self.body["keyId"],"authGeneration":1,"conversationId":self.body["conversationId"],"firstMessageId":self.body["firstMessageId"],"coordinates":self.body["next"],"recordedAt":self.body["signedAt"]}});
        let signature: p256::ecdsa::Signature = self.authority.sign(
            &protocol::direct_request_signing_bytes(
                protocol::DirectRequestKind::Outcome,
                &serde_json::to_vec(&receipt_body).unwrap(),
            )
            .unwrap(),
        );
        let receipt = json!({"body":receipt_body,"signature":STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes())});
        self.welcome.publication_request = serde_json::to_vec(&publication).unwrap();
        self.welcome.published_receipt = serde_json::to_vec(&receipt).unwrap();
        self.entry = json!({"$type":"blue.catbird.chat.defs#directRequestEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":self.body["conversationId"],"seq":1,"signedRequest":publication,"receivedAt":self.body["signedAt"]});
        catbird_mls::orchestrator::direct_request_shared_crypto::validate_request_welcome_receipt(
            &self.welcome,
        )
        .unwrap();
    }
    fn queue(&self, world: &TestWorld) {
        world.delivery_service().queue_request_operation_response(
            Op::GetEntries,
            200,
            json!({"entries":[self.entry],"hasMore":false,"nextAfterSeq":1}),
        );
        let mut outcome = serde_json::from_slice::<Value>(&self.welcome.published_receipt).unwrap();
        outcome["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
        world.delivery_service().queue_request_operation_response(Op::GetDirectRequestOutcome, 200, json!({"outcome": outcome}));
        offline_state(world);
    }
}
fn offline_state(world: &TestWorld) {
    world.delivery_service().queue_request_operation_response(
        Op::GetConversationState,
        503,
        json!({"error":"offline"}),
    );
}
async fn world() -> TestWorld {
    let mut world = TestWorld::new();
    for (name, did) in [
        ("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Bob", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
    ] {
        world.add_client_with_did(name, did).await;
        world.register_device(name).await.unwrap();
    }
    world
}
async fn proof(world: &TestWorld) -> Proof {
    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let device = alice
        .credentials
        .get_device_uuid(&alice.did)
        .await
        .unwrap()
        .unwrap();
    let bob_device = bob
        .credentials
        .get_device_uuid(&bob.did)
        .await
        .unwrap()
        .unwrap();
    let actor = format!("{}#{device}", alice.did);
    let recipient = format!("{}#{bob_device}", bob.did);
    let public = alice
        .orchestrator
        .mls_context()
        .identity_public_key(actor.clone())
        .unwrap();
    let package = bob
        .orchestrator
        .mls_context()
        .create_key_package(recipient.as_bytes().to_vec())
        .unwrap();
    let now = chrono::Utc::now().timestamp() as u64;
    let authority = p256::ecdsa::SigningKey::from_slice(&[63; 32]).unwrap();
    let point = authority.verifying_key().to_encoded_point(true);
    let authority_key = point.as_bytes().to_vec();
    let method = protocol::direct_request_receipt_key_id(&authority_key).unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(&authority_key);
    let authority_doc=serde_json::to_vec(&json!({"id":"did:web:chat.catbird.blue","verificationMethod":[{"id":method,"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)}]})).unwrap();
    for name in ["Alice", "Bob"] {
        world
            .client(name)
            .credentials
            .set_request_authority_document(authority_doc.clone());
    }
    let ctx = json!({"protocolVersion":"2","requestId":uuid::Uuid::new_v4().to_string(),"firstMessageId":uuid::Uuid::new_v4().to_string(),"conversationId":uuid::Uuid::new_v4().to_string(),"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},"actorDid":alice.did,"actorDeviceId":device,"actorKeyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"recipientDid":bob.did,"preparationDigest":STANDARD.encode([42;32])});
    let input = DirectRequestBootstrapInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&ctx).unwrap(),
        group_id: Sha256::digest(uuid::Uuid::new_v4().as_bytes()).to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: vec![package.key_package_data],
        expected_package_refs: vec![package.hash_ref.clone()],
        authority_import_until: now + 20 * 86400,
        preparation_request_digest: [21; 32],
        receipt_authority_key: authority_key.clone(),
        text: "Valid independent introduction".into(),
        invitation: None,
        metadata: catbird_mls::metadata::GroupMetadataV1 {
            version: 1,
            title: "Poison isolation".into(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    };
    let journal = alice
        .orchestrator
        .mls_context()
        .prepare_direct_request_bootstrap(&input)
        .unwrap();
    let b = &journal.bootstrap;
    let artifact = |bytes: &Vec<u8>, kind: &str| json!({"framing":"mlsMessage","contentType":kind,"bytes":STANDARD.encode(bytes),"sha256":STANDARD.encode(Sha256::digest(bytes))});
    let metadata = json!({"coordinate":metadata_coordinate(&b.coordinates).unwrap(),"originTransitionId":ctx["requestId"],"metadataVersion":1,"nonce":STANDARD.encode(&b.metadata_nonce),"ciphertext":STANDARD.encode(&b.metadata_ciphertext),"ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),"ciphertextSize":b.metadata_ciphertext.len(),"authorProof":{"authorDid":alice.did,"authorDeviceId":device,"authorKeyId":ctx["actorKeyId"],"signaturePublicKey":STANDARD.encode(&public),"authGenerationAtOrigin":1,"originTransitionId":ctx["requestId"],"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}});
    let body = json!({"$type":"blue.catbird.chat.defs#directRequestPublicationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-PUBLISH\0","protocolVersion":"2","actorDid":alice.did,"actorDeviceId":device,"keyId":ctx["actorKeyId"],"authGeneration":1,"requestId":ctx["requestId"],"firstMessageId":ctx["firstMessageId"],"conversationId":ctx["conversationId"],"recipientDid":bob.did,"origin":ctx["origin"],"profile":"encryptedIntroduction1","preparationDigest":ctx["preparationDigest"],"preparationRequestDigest":STANDARD.encode(input.preparation_request_digest),"contextHash":STANDARD.encode(b.context_hash),"next":b.coordinates,"importUntil":utc(b.import_until),"artifacts":{"genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),"addCommit":artifact(&b.add_commit,"publicMessageCommit"),"finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),"welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":[{"recipientDid":bob.did,"recipientDeviceId":bob_device,"provenance":{"requestId":ctx["requestId"],"preparationDigest":ctx["preparationDigest"],"contextHash":STANDARD.encode(b.context_hash),"grantId":uuid::Uuid::new_v4().to_string(),"grantRevision":1,"keyPackageRef":STANDARD.encode(package.hash_ref),"importUntil":utc(b.import_until)}}]},"metadataSnapshot":metadata,"initialCiphertext":STANDARD.encode(&b.initial_ciphertext)},"idempotencyKey":uuid::Uuid::new_v4().to_string(),"signedAt":utc(now)});
    let welcome = DirectRequestWelcomeInput {
        bootstrap: b.clone(),
        local_identity: recipient.into_bytes(),
        local_package_ref: input.expected_package_refs[0].clone(),
        publication_request: vec![],
        actor_signature_public_key: public,
        published_receipt: vec![],
        receipt_authority_key: authority_key,
        preparation_request_digest: input.preparation_request_digest,
    };
    let mut proof = Proof {
        welcome,
        body,
        entry: Value::Null,
        authority,
        authority_doc,
    };
    proof.resign(world);
    alice
        .orchestrator
        .mls_context()
        .persist_direct_request_publish(&journal.request_id, &proof.welcome.publication_request)
        .unwrap();
    alice
        .orchestrator
        .mls_context()
        .confirm_published_bootstrap(
            &journal.request_id,
            &proof.welcome.published_receipt,
            &proof.welcome.receipt_authority_key,
        )
        .unwrap();
    proof
}

#[derive(Debug, Clone, Copy)]
enum Poison {
    CorruptCiphertext,
    WrongAad,
    UnsupportedContent,
}
fn poison(world: &TestWorld, proof: &mut Proof, kind: Poison) {
    let cipher = match kind {
        Poison::CorruptCiphertext => {
            let mut bytes = proof.welcome.bootstrap.initial_ciphertext.clone();
            *bytes.last_mut().unwrap() ^= 0x80;
            bytes
        }
        Poison::WrongAad | Poison::UnsupportedContent => {
            let valid = protocol::encode_direct_request_introduction(
                br#"{"text":"well formed but wrong AAD"}"#,
            )
            .unwrap();
            let (plain, aad) = match kind {
                Poison::WrongAad => (valid, b"wrong authenticated context".to_vec()),
                Poison::UnsupportedContent => (
                    serde_ipld_dagcbor::to_vec(&json!({"text":"unsupported","version":999}))
                        .unwrap(),
                    protocol::direct_request_application_aad(
                        &proof.welcome.bootstrap.context_hash,
                        &serde_json::to_vec(&proof.welcome.bootstrap.coordinates).unwrap(),
                        proof.body["firstMessageId"].as_str().unwrap(),
                    )
                    .unwrap(),
                ),
                _ => unreachable!(),
            };
            world
                .client("Alice")
                .orchestrator
                .mls_context()
                .encrypt_message_with_aad(proof.gid(), plain, aad, 1)
                .unwrap()
                .ciphertext
        }
    };
    proof.body["artifacts"]["initialCiphertext"] = json!(STANDARD.encode(&cipher));
    proof.welcome.bootstrap.initial_ciphertext = cipher;
    proof.resign(world);
}

fn native_snapshot(world: &TestWorld) -> Vec<(String, Vec<String>)> {
    let connection =
        rusqlite::Connection::open(world.client("Bob")._temp_dir.join("mls.db")).unwrap();
    let key = "test-key-Bob";
    for (name, value) in [
        ("cipher_memory_security", "OFF".into()),
        ("key", key.into()),
        ("cipher_plaintext_header_size", "32".into()),
        (
            "cipher_salt",
            format!("x'{}'", hex::encode(&Sha256::digest(key.as_bytes())[..16])),
        ),
        ("cipher_page_size", "4096".into()),
        ("kdf_iter", "256000".into()),
        ("cipher_hmac_algorithm", "HMAC_SHA512".into()),
        ("cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512".into()),
    ] {
        connection.pragma_update(None, name, value).unwrap();
    }
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut q = connection
                .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
                .unwrap();
            let count = q.column_count();
            let mut rows = q
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<Result<Vec<_>, _>>()
                        .map(|v| format!("{v:?}"))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}

async fn poisoned_case(kind: Poison) {
    let mut world = world().await;
    let unrelated = world
        .client("Bob")
        .orchestrator
        .create_group("Unaffected conversation", None, None)
        .await
        .unwrap();
    world
        .client("Bob")
        .orchestrator
        .send_message(&unrelated.conversation_id, "before poison")
        .await
        .unwrap();
    let mut bad = proof(&world).await;
    poison(&world, &mut bad, kind);
    bad.queue(&world);
    let start = world.delivery_service().submitted_prepared_requests().len();
    let view = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(bad.cid())
        .await
        .unwrap();
    assert_eq!(view.consent, RequestConsent::IncomingPending);
    assert_eq!(
        view.crypto,
        RequestCrypto::Ready,
        "valid Welcome remains imported: {kind:?}"
    );
    assert_eq!(
        view.preview,
        Some(RequestPreview::Unavailable {
            code: "InvalidIntroduction".into()
        })
    );
    assert!(
        !view.capabilities.can_send
            && !view.capabilities.can_emit_receipts
            && !view.capabilities.can_administer
    );
    assert!(world
        .client("Bob")
        .storage
        .get_conversation_messages(bad.cid())
        .is_empty());
    assert_eq!(
        world
            .client("Bob")
            .orchestrator
            .mls_context()
            .get_epoch(bad.gid())
            .unwrap(),
        1
    );
    let settled = native_snapshot(&world);
    for _ in 0..3 {
        offline_state(&world);
        assert_eq!(
            world
                .client("Bob")
                .orchestrator
                .refresh_request_preview(bad.cid())
                .await
                .unwrap(),
            view
        );
        assert_eq!(
            native_snapshot(&world),
            settled,
            "poison replay must not advance any native ratchet/cache row"
        );
    }
    let mutations = world.delivery_service().submitted_prepared_requests()[start..]
        .iter()
        .filter(|r| r.method != "GET")
        .map(|r| r.operation)
        .collect::<Vec<_>>();
    assert!(
        mutations.is_empty(),
        "preview must emit no acceptance, receipt, reset or recovery mutation: {mutations:?}"
    );
    world.restart_client("Bob").await;
    let reopened = native_snapshot(&world);
    let reopened_requests = world.delivery_service().submitted_prepared_requests().len();
    offline_state(&world);
    assert_eq!(
        world
            .client("Bob")
            .orchestrator
            .refresh_request_preview(bad.cid())
            .await
            .unwrap(),
        view
    );
    assert_eq!(native_snapshot(&world), reopened);
    assert_eq!(
        world
            .client("Bob")
            .orchestrator
            .mls_context()
            .decrypt_direct_request_introduction(&bad.welcome)
            .unwrap(),
        DirectRequestIntroductionResult::Unavailable {
            code: "InvalidIntroduction".into()
        }
    );
    assert_eq!(native_snapshot(&world), reopened);
    assert!(
        world.delivery_service().submitted_prepared_requests()[reopened_requests..]
            .iter()
            .all(|r| r.method == "GET"),
        "reopened poisoned preview must not emit mutation effects"
    );
    let after = world
        .client("Bob")
        .orchestrator
        .send_message(
            &unrelated.conversation_id,
            "after poisoned preview and reopen",
        )
        .await
        .unwrap();
    assert!(!after.id.is_empty());
    let good = proof(&world).await;
    good.queue(&world);
    let good_view = world
        .client("Bob")
        .orchestrator
        .refresh_request_preview(good.cid())
        .await
        .unwrap();
    assert_eq!(
        good_view.preview,
        Some(RequestPreview::Ready {
            text: "Valid independent introduction".into(),
            invitation: None
        })
    );
    assert_eq!(good_view.consent, RequestConsent::IncomingPending);
    offline_state(&world);
    assert_eq!(
        world
            .client("Bob")
            .orchestrator
            .refresh_request_preview(bad.cid())
            .await
            .unwrap(),
        view
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn c17_corrupt_ciphertext_is_durable_and_isolated() {
    poisoned_case(Poison::CorruptCiphertext).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn c17_wrong_authenticated_context_is_durable_and_isolated() {
    poisoned_case(Poison::WrongAad).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn c17_unsupported_plaintext_is_durable_and_isolated() {
    poisoned_case(Poison::UnsupportedContent).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn c17_invalid_welcome_final_tree_provenance_rolls_back_every_native_row() {
    let mut world = world().await;
    let mut bad = proof(&world).await;
    let original = bad.welcome.clone();
    bad.body["next"]["confirmationTag"] = json!(STANDARD.encode([99; 32]));
    bad.welcome.bootstrap.coordinates = bad.body["next"].clone();
    bad.body["artifacts"]["metadataSnapshot"]["coordinate"] = metadata_coordinate(&bad.welcome.bootstrap.coordinates).unwrap();
    bad.resign(&world);
    let before = native_snapshot(&world);
    assert!(world
        .client("Bob")
        .orchestrator
        .mls_context()
        .process_direct_request_welcome(&bad.welcome)
        .is_err());
    assert_eq!(native_snapshot(&world),before,"post-StagedWelcome final coordinate rejection must roll back group, key-package consumption and manifest rows");
    assert!(world
        .client("Bob")
        .orchestrator
        .mls_context()
        .get_epoch(bad.gid())
        .is_err());
    world.restart_client("Bob").await;
    world
        .client("Bob")
        .orchestrator
        .mls_context()
        .process_direct_request_welcome(&original)
        .unwrap();
    assert!(matches!(
        world
            .client("Bob")
            .orchestrator
            .mls_context()
            .decrypt_direct_request_introduction(&original)
            .unwrap(),
        DirectRequestIntroductionResult::Ready { .. }
    ));
}
