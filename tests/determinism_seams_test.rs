use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES;
use catbird_mls::sim_hooks::{
    ChaChaSimEntropy, FixedStepClock, SeededOpenMlsCryptoProvider, SimClientHooks, SimClock,
    SimEntropy, TxAutocommitProbe,
};
use catbird_mls::{
    buggify, CatbirdMlsClient, CatbirdMlsClientConfig, MLSError, PlatformHttpHeader,
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport, SqlDriver,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::SigningKey as P256SigningKey;
use tls_codec::Serialize as _;

struct DeterministicKeyStore {
    items: Mutex<HashMap<String, Vec<u8>>>,
    dpop_tokens: Mutex<HashMap<String, (String, i64)>>,
}

impl DeterministicKeyStore {
    fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            dpop_tokens: Mutex::new(HashMap::new()),
        }
    }
}

impl PlatformKeyStore for DeterministicKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let mut guard = self.items.lock().unwrap();
        let key = format!("db:{account_did_hash}");
        Ok(guard.entry(key).or_insert_with(|| vec![0x5a; 32]).clone())
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.items.lock().unwrap().get(&key_id).cloned())
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.items.lock().unwrap().insert(key_id, keypair_bytes);
        Ok(())
    }

    fn delete_account_keys(&self, _account_did_hash: String) -> Result<(), MLSError> {
        self.items.lock().unwrap().clear();
        self.dpop_tokens.lock().unwrap().clear();
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(self
            .dpop_tokens
            .lock()
            .unwrap()
            .get(&account_did_hash)
            .map(|(t, _)| t.clone()))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.dpop_tokens
            .lock()
            .unwrap()
            .insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedHttpCall {
    method: String,
    url: String,
    headers: Vec<PlatformHttpHeader>,
    body: Option<Vec<u8>>,
}

struct PdsRepoRecord {
    repo: String,
    collection: String,
    rkey: String,
    value: serde_json::Value,
}

struct DeterministicMockTransport {
    probe: OnceLock<TxAutocommitProbe>,
    client_ref: OnceLock<Arc<CatbirdMlsClient>>,
    calls: Mutex<Vec<RecordedHttpCall>>,
    pds_records: Mutex<Vec<PdsRepoRecord>>,
    sequencer_signing_key: P256SigningKey,
    sequencer_pub_multibase: String,
}

impl DeterministicMockTransport {
    fn new() -> Self {
        let sk = P256SigningKey::from_bytes((&[0x33u8; 32]).into()).unwrap();
        let sec1_compressed = sk.verifying_key().to_encoded_point(true);
        // multicodec p256-pub = 0x1200 -> varint [0x80, 0x24]
        let mut codec_prefixed = vec![0x80, 0x24];
        codec_prefixed.extend_from_slice(sec1_compressed.as_bytes());
        let pub_multibase = multibase::encode(multibase::Base::Base58Btc, &codec_prefixed);
        Self {
            probe: OnceLock::new(),
            client_ref: OnceLock::new(),
            calls: Mutex::new(Vec::new()),
            pds_records: Mutex::new(Vec::new()),
            sequencer_signing_key: sk,
            sequencer_pub_multibase: pub_multibase,
        }
    }

    fn attach_client(&self, client: &Arc<CatbirdMlsClient>) {
        let _ = self.probe.set(client.autocommit_probe());
        let _ = self.client_ref.set(Arc::clone(client));
    }

    fn recorded_calls(&self) -> Vec<RecordedHttpCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl PlatformTransport for DeterministicMockTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let method = &request.method;
        let url = &request.url;

        if let Some(probe) = self.probe.get() {
            assert!(
                !probe.is_in_transaction(),
                "I6 violation: probe.is_in_transaction() true during execute_http({method} {url})!"
            );
        }
        if let Some(client) = self.client_ref.get() {
            assert!(
                !client.is_in_transaction(),
                "I6 violation: client.is_in_transaction() true during execute_http({method} {url})!"
            );
            assert!(
                !client.is_in_write_transaction(),
                "I6 violation: client.is_in_write_transaction() true during execute_http({method} {url})!"
            );
        }

        let mut sorted_headers = request.headers.clone();
        sorted_headers.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.value.cmp(&b.value)));
        self.calls.lock().unwrap().push(RecordedHttpCall {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: sorted_headers,
            body: request.body.clone(),
        });

        let json_resp = |status: u16, val: serde_json::Value| PlatformHttpResponse {
            status,
            headers: vec![PlatformHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: serde_json::to_vec(&val).unwrap(),
        };
        let json_ok = |val: serde_json::Value| json_resp(200, val);

        if url.contains("/xrpc/com.atproto.space.getSpace") {
            return Ok(json_resp(
                400,
                serde_json::json!({
                    "error": "InvalidRequest",
                    "message": "space parameter required"
                }),
            ));
        }

        if url.contains("/xrpc/com.atproto.space.listRecords") {
            return Ok(json_ok(serde_json::json!({
                "records": []
            })));
        }

        if url.contains("/xrpc/com.atproto.space.applyWrites") {
            return Ok(json_ok(serde_json::json!({
                "results": []
            })));
        }

        if url.contains("/xrpc/com.atproto.repo.putRecord") {
            if let Some(ref b) = request.body {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(b) {
                    let repo = val["repo"].as_str().unwrap_or("").to_string();
                    let collection = val["collection"].as_str().unwrap_or("").to_string();
                    let rkey = val["rkey"].as_str().unwrap_or("").to_string();
                    let record = val["record"].clone();
                    let mut store = self.pds_records.lock().unwrap();
                    store.retain(|r| {
                        !(r.repo == repo && r.collection == collection && r.rkey == rkey)
                    });
                    store.push(PdsRepoRecord {
                        repo: repo.clone(),
                        collection: collection.clone(),
                        rkey: rkey.clone(),
                        value: record,
                    });
                    return Ok(json_ok(serde_json::json!({
                        "uri": format!("at://{repo}/{collection}/{rkey}"),
                        "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    })));
                }
            }
        }

        if url.contains("/xrpc/com.atproto.repo.listRecords") {
            let store = self.pds_records.lock().unwrap();
            let records: Vec<serde_json::Value> = store
                .iter()
                .filter(|r| url.contains(&r.collection))
                .map(|r| {
                    serde_json::json!({
                        "uri": format!("at://{}/{}/{}", r.repo, r.collection, r.rkey),
                        "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "value": r.value,
                    })
                })
                .collect();
            return Ok(json_ok(serde_json::json!({
                "records": records
            })));
        }

        if url.contains("/xrpc/com.atproto.identity.resolveDid") {
            if url.contains("mls.catbird.test") {
                return Ok(json_ok(serde_json::json!({
                    "didDoc": {
                        "id": "did:web:mls.catbird.test",
                        "verificationMethod": [{
                            "id": "did:web:mls.catbird.test#mls-receipt-1",
                            "type": "Multikey",
                            "controller": "did:web:mls.catbird.test",
                            "publicKeyMultibase": self.sequencer_pub_multibase,
                        }]
                    }
                })));
            }
            return Ok(json_resp(
                404,
                serde_json::json!({ "error": "DidNotFound" }),
            ));
        }

        if url.contains("/.well-known/did.json") {
            return Ok(json_ok(serde_json::json!({
                "id": "did:web:mls.catbird.test",
                "verificationMethod": [{
                    "id": "did:web:mls.catbird.test#mls-receipt-1",
                    "type": "Multikey",
                    "controller": "did:web:mls.catbird.test",
                    "publicKeyMultibase": self.sequencer_pub_multibase,
                }]
            })));
        }

        if url.contains("blue.catbird.chat.enrollDevice") {
            return Ok(json_ok(serde_json::json!({
                "enrolled": true,
                "authGeneration": 1
            })));
        }

        if url.contains("blue.catbird.chat.publishDirectRequestKeys") {
            return Ok(json_ok(serde_json::json!({
                "published": true,
                "revision": 1
            })));
        }

        if url.contains("blue.catbird.chat.replenishKeyPackages") {
            return Ok(json_ok(serde_json::json!({
                "availableCount": 4
            })));
        }

        if url.contains("blue.catbird.chat.createConversation") {
            let req_json: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                    .unwrap_or_default();
            let sbody = req_json.pointer("/signedRequest/body").unwrap_or(&req_json);
            let next_coords = sbody
                .get("next")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            return Ok(json_ok(serde_json::json!({
                "seq": 1,
                "coordinates": next_coords
            })));
        }

        if url.contains("blue.catbird.chat.sendMessage") {
            let req_json: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
            let sbody = req_json
                .pointer("/signedRequest/body")
                .unwrap_or(&req_json["body"]);
            let cid = sbody["prior"]["conversationId"].as_str().unwrap();
            let group_id_b64 = sbody["prior"]["groupId"]["$bytes"]
                .as_str()
                .or_else(|| sbody["prior"]["groupId"].as_str())
                .unwrap();
            let group_id = BASE64.decode(group_id_b64).unwrap();
            let epoch = sbody["prior"]["epoch"].as_u64().unwrap_or(0);
            let msg_id = sbody["messageId"].as_str().unwrap();
            let sender_did = sbody["actorDid"].as_str().unwrap();
            let sender_dev_id = sbody["actorDeviceId"].as_str().unwrap();
            let archive_commitment_b64 = sbody["aad"]["archiveCommitment"]["$bytes"]
                .as_str()
                .or_else(|| sbody["aad"]["archiveCommitment"].as_str())
                .unwrap();
            let archive_commitment: [u8; 32] = BASE64
                .decode(archive_commitment_b64)
                .unwrap()
                .try_into()
                .unwrap();

            let receipt_kid = "did:web:mls.catbird.test#mls-receipt-1";
            let payload = labyrinth_protocol::receipt::SequencerReceiptPayload {
                sequencer_did: "did:web:mls.catbird.test".to_string(),
                conversation_id: cid.to_string(),
                group_id,
                epoch,
                sender_device_did_url: format!("{sender_did}#{sender_dev_id}"),
                entry_id: msg_id.to_string(),
                archive_commitment,
                seq: 2,
                issued_at_ms: 1_793_620_000_500,
            };
            let signed = labyrinth_protocol::receipt::sign_sequencer_receipt(
                &self.sequencer_signing_key,
                receipt_kid,
                &payload,
            )
            .unwrap();

            return Ok(json_ok(serde_json::json!({
                "seq": 2,
                "entry": {
                    "entryId": msg_id,
                    "seq": 2,
                    "epoch": epoch,
                },
                "sequencerReceipt": {
                    "sequencerDid": "did:web:mls.catbird.test",
                    "kid": receipt_kid,
                    "conversationId": cid,
                    "generation": 0,
                    "groupId": { "$bytes": group_id_b64 },
                    "epoch": epoch,
                    "seq": 2,
                    "senderDid": sender_did,
                    "senderDeviceId": sender_dev_id,
                    "entryId": msg_id,
                    "archiveCommitment": { "$bytes": archive_commitment_b64 },
                    "issuedAtMs": 1_793_620_000_500_i64,
                    "signature": { "$bytes": BASE64.encode(signed.signature) }
                }
            })));
        }

        if url.contains("com.atproto.repo.getRecord") {
            return Ok(json_resp(
                404,
                serde_json::json!({ "error": "RecordNotFound" }),
            ));
        }

        Ok(json_ok(serde_json::json!({
            "uri": "at://did:plc:aliceaaaaaaaaaaaaaaaaaaa/record/1",
            "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })))
    }

    fn connect_realtime_stream(
        &self,
        _home_ds_endpoint: String,
        _cursor_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

fn default_test_scopes() -> Vec<String> {
    REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn pinned_base_epoch_ms() -> i64 {
    static BASE_MS: OnceLock<i64> = OnceLock::new();
    *BASE_MS.get_or_init(|| {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (secs as i64) * 1_000
    })
}

fn test_client_config(storage_root: String) -> CatbirdMlsClientConfig {
    CatbirdMlsClientConfig {
        storage_root,
        account_did: "did:plc:aliceaaaaaaaaaaaaaaaaaaa".to_string(),
        device_id: "44444444-4444-4444-8444-444444444444".to_string(),
        home_ds_did: "did:web:mls.catbird.test".to_string(),
        home_ds_endpoint: "https://mls.catbird.test".to_string(),
        pds_endpoint: "https://pds.catbird.test".to_string(),
    }
}

#[test]
fn fixed_step_clock_is_monotonic_and_deterministic() {
    let c1 = FixedStepClock::new(1_793_620_000_000, 25);
    let c2 = FixedStepClock::new(1_793_620_000_000, 25);
    assert_eq!(c1.now_ms(), 1_793_620_000_000);
    assert_eq!(c1.now_ms(), 1_793_620_000_025);
    assert_eq!(c1.now_ms(), 1_793_620_000_050);

    assert_eq!(c2.now_ms(), 1_793_620_000_000);
    assert_eq!(c2.now_ms(), 1_793_620_000_025);
    assert_eq!(c2.now_ms(), 1_793_620_000_050);
}

#[test]
fn two_seeded_clients_produce_byte_identical_enrollment_and_ciphertexts() {
    let base_ms = pinned_base_epoch_ms();
    let run = |seed: u64| -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn SimClock> = Arc::new(FixedStepClock::new(base_ms, 10));
        let entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"alice-dev-1"));
        let hooks = SimClientHooks::new(clock, entropy);

        let cfg = test_client_config(dir.path().to_string_lossy().into_owned());
        let keystore = Arc::new(DeterministicKeyStore::new());
        let transport = Arc::new(DeterministicMockTransport::new());
        let client =
            CatbirdMlsClient::open_with_hooks(cfg, keystore, transport.clone(), None, hooks)
                .unwrap();
        transport.attach_client(&client);

        let receipt = client.enroll_device(&default_test_scopes()).unwrap();

        let convo_id = "11111111-1111-4111-8111-111111111111";
        let _convo = client
            .create_group(
                convo_id,
                "did:web:mls.catbird.test",
                vec![],
                Some("Pressure Tank".to_string()),
                Some("Deterministic test group".to_string()),
            )
            .unwrap();

        let msg_id = "22222222-2222-4222-8222-222222222222";
        let _msg = client
            .send_message(convo_id, msg_id, "hydrostatic seal holds")
            .unwrap();
        let flushed = client.flush_labyrinth_queue().unwrap();
        assert_eq!(flushed, 1);

        let send_call = transport
            .recorded_calls()
            .into_iter()
            .find(|c| c.url.contains("blue.catbird.chat.sendMessage"))
            .expect("expected live sendMessage HTTP call");
        let send_json: serde_json::Value =
            serde_json::from_slice(send_call.body.as_deref().unwrap()).unwrap();
        let sbody = send_json
            .pointer("/signedRequest/body")
            .unwrap_or(&send_json["body"]);
        let ciphertext_b64 = sbody["applicationMessage"]["bytes"]["$bytes"]
            .as_str()
            .or_else(|| sbody["applicationMessage"]["bytes"].as_str())
            .unwrap()
            .to_string();

        (
            receipt.direct_request_kp_bytes,
            receipt.recovery_kp_bytes,
            receipt.signature_public_key,
            ciphertext_b64,
        )
    };

    assert_eq!(run(8_492_014), run(8_492_014));
    assert_ne!(run(8_492_014), run(8_492_015));
}

#[test]
fn two_seeded_clients_produce_identical_full_http_wire_transcripts_and_enforce_i6() {
    let base_ms = pinned_base_epoch_ms();
    let run_transcript = |seed: u64| -> Vec<RecordedHttpCall> {
        let dir = tempfile::tempdir().unwrap();
        let hooks = SimClientHooks::new(
            Arc::new(FixedStepClock::new(base_ms, 25)),
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"wire-transcript")),
        );
        let cfg = test_client_config(dir.path().to_string_lossy().into_owned());
        let keystore = Arc::new(DeterministicKeyStore::new());
        let transport = Arc::new(DeterministicMockTransport::new());
        let client =
            CatbirdMlsClient::open_with_hooks(cfg, keystore, transport.clone(), None, hooks)
                .unwrap();
        transport.attach_client(&client);

        client.enroll_device(&default_test_scopes()).unwrap();
        let convo_id = "11111111-1111-4111-8111-111111111111";
        client
            .create_group(
                convo_id,
                "did:web:mls.catbird.test",
                vec![],
                Some("Tank".to_string()),
                None,
            )
            .unwrap();
        client
            .send_message(
                convo_id,
                "22222222-2222-4222-8222-222222222222",
                "wire transcript msg",
            )
            .unwrap();
        let flushed = client.flush_labyrinth_queue().unwrap();
        assert_eq!(flushed, 1);
        transport.recorded_calls()
    };

    let t1 = run_transcript(99_101);
    let t2 = run_transcript(99_101);
    let t3 = run_transcript(99_102);
    assert!(!t1.is_empty());
    assert_eq!(t1, t2);
    assert_ne!(t1, t3);
}

#[test]
fn seeded_openmls_crypto_provider_draws_strictly_from_sim_entropy() {
    let base_secs = (pinned_base_epoch_ms() / 1_000) as u64;
    let lifetime = Lifetime::init(base_secs.saturating_sub(60), base_secs + 30 * 86_400);
    let run_openmls = |seed: u64| -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let alice_entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"alice-openmls"));
        let bob_entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"bob-openmls"));

        let alice_provider = SeededOpenMlsCryptoProvider::new(alice_entropy);
        let bob_provider = SeededOpenMlsCryptoProvider::new(bob_entropy);

        let suite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
        let (alice_sk, alice_pk) = alice_provider
            .crypto()
            .signature_key_gen(suite.signature_algorithm())
            .unwrap();
        let alice_signer =
            SignatureKeyPair::from_raw(suite.signature_algorithm(), alice_sk, alice_pk);
        alice_signer.store(alice_provider.storage()).unwrap();

        let (bob_sk, bob_pk) = bob_provider
            .crypto()
            .signature_key_gen(suite.signature_algorithm())
            .unwrap();
        let bob_signer = SignatureKeyPair::from_raw(suite.signature_algorithm(), bob_sk, bob_pk);
        bob_signer.store(bob_provider.storage()).unwrap();

        let bob_kp = KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(Capabilities::builder().ciphersuites(vec![suite]).build())
            .build(
                suite,
                &bob_provider,
                &bob_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(b"did:plc:bob#dev1".to_vec()).into(),
                    signature_key: bob_signer.public().into(),
                },
            )
            .unwrap();
        let bob_kp_bytes = bob_kp.key_package().tls_serialize_detached().unwrap();

        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .lifetime(lifetime)
            .use_ratchet_tree_extension(true)
            .build();
        let gid: [u8; 32] = alice_provider.rand().random_array().unwrap();
        let mut group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &cfg,
            GroupId::from_slice(&gid),
            CredentialWithKey {
                credential: BasicCredential::new(b"did:plc:alice#dev1".to_vec()).into(),
                signature_key: alice_signer.public().into(),
            },
        )
        .unwrap();

        let (commit, welcome, _) = group
            .add_members(
                &alice_provider,
                &alice_signer,
                &[bob_kp.key_package().clone()],
            )
            .unwrap();
        group.merge_pending_commit(&alice_provider).unwrap();
        let msg = group
            .create_message(&alice_provider, &alice_signer, b"pq welcome + msg")
            .unwrap();

        (
            bob_kp_bytes,
            welcome.tls_serialize_detached().unwrap(),
            commit
                .tls_serialize_detached()
                .unwrap()
                .into_iter()
                .chain(msg.tls_serialize_detached().unwrap())
                .collect(),
        )
    };

    assert_eq!(run_openmls(4242), run_openmls(4242));
    assert_ne!(run_openmls(4242), run_openmls(4243));
}

#[test]
fn sql_driver_reports_active_write_transaction() {
    let driver = SqlDriver::open_in_memory_for_test().unwrap();
    assert!(!driver.is_in_transaction());
    driver
        .write_tx(|_tx| {
            assert!(driver.is_in_transaction());
            Ok(())
        })
        .unwrap();
    assert!(!driver.is_in_transaction());
}

#[test]
fn sql_driver_reports_active_transactions_via_sqlite_autocommit() {
    let driver = Arc::new(SqlDriver::open_in_memory_for_test().unwrap());
    let probe = driver.autocommit_probe();
    assert!(!driver.is_in_transaction());
    assert!(!driver.is_in_write_transaction());
    assert!(!probe.is_in_transaction());

    driver
        .read_tx(|_tx| {
            assert!(driver.is_in_transaction());
            assert!(!driver.is_in_write_transaction());
            assert!(probe.is_in_transaction());
            Ok(())
        })
        .unwrap();
    assert!(!driver.is_in_transaction());
    assert!(!probe.is_in_transaction());

    driver
        .write_tx(|_tx| {
            assert!(driver.is_in_transaction());
            assert!(driver.is_in_write_transaction());
            assert!(probe.is_in_transaction());
            Ok(())
        })
        .unwrap();
    assert!(!driver.is_in_transaction());
    assert!(!driver.is_in_write_transaction());
    assert!(!probe.is_in_transaction());

    let rollback_res: Result<(), MLSError> = driver.write_tx(|_tx| {
        assert!(driver.is_in_transaction());
        assert!(probe.is_in_transaction());
        Err(MLSError::invalid_input("intentional rollback"))
    });
    assert!(rollback_res.is_err());
    assert!(!driver.is_in_transaction());
    assert!(!driver.is_in_write_transaction());
    assert!(!probe.is_in_transaction());
}

#[test]
fn buggify_defaults_to_false_when_unconfigured() {
    assert!(!buggify!("after_http_2xx_before_db_commit"));
    assert!(!buggify!("between_labyrinth_enqueue_and_flush"));
    assert!(!buggify!("before_wal_passive_checkpoint"));
}

#[cfg(feature = "sim")]
#[test]
fn buggify_controller_fires_all_three_initial_sites_under_sim_feature() {
    use catbird_mls::sim_hooks::BuggifyController;

    // 1. Site: `before_wal_passive_checkpoint`
    let driver = SqlDriver::open_in_memory_for_test().unwrap();
    driver.passive_checkpoint().unwrap();

    BuggifyController::with_enabled_sites(&["before_wal_passive_checkpoint"], || {
        assert!(buggify!("before_wal_passive_checkpoint"));
        assert!(!buggify!("after_http_2xx_before_db_commit"));
        let err = driver
            .passive_checkpoint()
            .expect_err("expected before_wal_passive_checkpoint fault");
        assert!(err.to_string().contains("before_wal_passive_checkpoint"));
    });
    assert!(!buggify!("before_wal_passive_checkpoint"));
    driver.passive_checkpoint().unwrap();

    // 2. Sites: `after_http_2xx_before_db_commit` and `between_labyrinth_enqueue_and_flush`
    let dir = tempfile::tempdir().unwrap();
    let hooks = SimClientHooks::new(
        Arc::new(FixedStepClock::new(pinned_base_epoch_ms(), 15)),
        Arc::new(ChaChaSimEntropy::from_seed(77_777, b"buggify-sites")),
    );
    let cfg = test_client_config(dir.path().to_string_lossy().into_owned());
    let keystore = Arc::new(DeterministicKeyStore::new());
    let transport = Arc::new(DeterministicMockTransport::new());
    let client =
        CatbirdMlsClient::open_with_hooks(cfg, keystore, transport.clone(), None, hooks).unwrap();
    transport.attach_client(&client);

    client.enroll_device(&default_test_scopes()).unwrap();
    let convo_id = "11111111-1111-4111-8111-111111111111";
    client
        .create_group(
            convo_id,
            "did:web:mls.catbird.test",
            vec![],
            Some("Buggify Group".to_string()),
            None,
        )
        .unwrap();

    // Fault right after HTTP 2xx on `sendMessage` before local SQLite `write_tx`.
    BuggifyController::with_enabled_sites(&["after_http_2xx_before_db_commit"], || {
        let err = client
            .send_message(
                convo_id,
                "33333333-3333-4333-8333-333333333333",
                "crash before local commit",
            )
            .expect_err("expected after_http_2xx_before_db_commit fault");
        assert!(err.to_string().contains("after_http_2xx_before_db_commit"));
    });
    assert!(
        client
            .list_pending_labyrinth_queue(Some(convo_id), 10)
            .unwrap()
            .is_empty(),
        "local write_tx must not have committed when after_http_2xx_before_db_commit fired"
    );

    // Now send cleanly so item lands in `labyrinth_queue`, then fault `between_labyrinth_enqueue_and_flush`.
    client
        .send_message(
            convo_id,
            "44444444-4444-4444-8444-555555555555",
            "durable outbox item",
        )
        .unwrap();
    assert_eq!(
        client
            .list_pending_labyrinth_queue(Some(convo_id), 10)
            .unwrap()
            .len(),
        1
    );

    BuggifyController::with_enabled_sites(&["between_labyrinth_enqueue_and_flush"], || {
        let err = client
            .flush_labyrinth_queue()
            .expect_err("expected between_labyrinth_enqueue_and_flush fault");
        assert!(err
            .to_string()
            .contains("between_labyrinth_enqueue_and_flush"));
    });
    assert_eq!(
        client
            .list_pending_labyrinth_queue(Some(convo_id), 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(client.flush_labyrinth_queue().unwrap(), 1);
    assert!(client
        .list_pending_labyrinth_queue(Some(convo_id), 10)
        .unwrap()
        .is_empty());
}
