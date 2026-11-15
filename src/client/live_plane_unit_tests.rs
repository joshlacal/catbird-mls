use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::SigningKey as P256SigningKey;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::client::config::CatbirdMlsClientConfig;
use crate::client::traits::{
    PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore,
    PlatformTransport,
};
use crate::orchestrator::canonical_transport::{derive_key_id, CanonicalOperation};
use crate::storage::{
    ConversationRow, GroupMetadataRow, OpenMlsKvStorage, RequestRow, RusqliteKvBackend,
};

const SEQUENCER_DID: &str = "did:web:sequencer.example.com";
const OTHER_SEQUENCER_DID: &str = "did:web:other-seq.example.com";
const DS_URL: &str = "https://sequencer.example.com";
const PDS_URL: &str = "https://pds.example.com";
const ALICE_DID: &str = "did:plc:aliceplaneaaaaaaaaaaaaaa";
const BOB_DID: &str = "did:plc:bobplanebbbbbbbbbbbbbbbb";
const CAROL_DID: &str = "did:plc:carolplanecccccccccccccc";
const CONVO_ID: &str = "11111111-1111-4111-8111-111111111111";
const CONVO_ID_2: &str = "22222222-2222-4222-8222-222222222222";
const DEV_A1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEV_B1: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DEV_C1: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

struct PlaneMemKeyStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl PlaneMemKeyStore {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl PlatformKeyStore for PlaneMemKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let mut g = self.map.lock().unwrap();
        Ok(g.entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| vec![0x53; 32])
            .clone())
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.map.lock().unwrap().get(&key_id).cloned())
    }

    fn store_signature_keypair(&self, key_id: String, bytes: Vec<u8>) -> Result<(), MLSError> {
        self.map.lock().unwrap().insert(key_id, bytes);
        Ok(())
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        let mut g = self.map.lock().unwrap();
        g.remove(&format!("db:{account_did_hash}"));
        g.remove(&format!("mls-signer:{account_did_hash}"));
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        _account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(None)
    }

    fn store_cached_chat_dpop_token(
        &self,
        _account_did_hash: String,
        _token: String,
        _expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        Ok(())
    }
}

type RouteHandler =
    Box<dyn FnMut(&PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> + Send>;

#[derive(Default)]
struct PlaneMockState {
    authority_mls_keys: BTreeMap<String, P256SigningKey>,
    authority_dr_keys: BTreeMap<String, P256SigningKey>,
    pds_raw_records: BTreeMap<String, Vec<Value>>,
    exact_get: HashMap<String, VecDeque<Result<PlatformHttpResponse, MLSError>>>,
    route_handlers: Vec<(String, RouteHandler)>,
    seen_urls: Vec<String>,
}

struct PlaneMockTransport {
    state: Arc<Mutex<PlaneMockState>>,
}

impl PlaneMockTransport {
    fn new() -> (Arc<Self>, Arc<Mutex<PlaneMockState>>) {
        let mut st = PlaneMockState::default();
        st.authority_mls_keys.insert(
            SEQUENCER_DID.to_string(),
            P256SigningKey::from_slice(&[17u8; 32]).unwrap(),
        );
        st.authority_dr_keys.insert(
            SEQUENCER_DID.to_string(),
            P256SigningKey::from_slice(&[29u8; 32]).unwrap(),
        );
        let state = Arc::new(Mutex::new(st));
        (
            Arc::new(Self {
                state: state.clone(),
            }),
            state,
        )
    }
}

fn http_json(status: u16, val: &Value) -> Result<PlatformHttpResponse, MLSError> {
    Ok(PlatformHttpResponse {
        status,
        headers: vec![PlatformHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body: serde_json::to_vec(val).unwrap(),
    })
}

fn sec1_bytes(key: &P256SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn p256_multikey(key: &P256SigningKey) -> String {
    let sec1 = sec1_bytes(key);
    let mut prefixed = Vec::with_capacity(2 + sec1.len());
    prefixed.extend_from_slice(&[0x80, 0x24]);
    prefixed.extend_from_slice(&sec1);
    multibase::encode(multibase::Base::Base58Btc, prefixed)
}

fn authority_did_doc(did: &str, mls_key: &P256SigningKey, dr_key: &P256SigningKey) -> Value {
    let dr_sec1 = sec1_bytes(dr_key);
    let dr_kid = dr_transcript::direct_request_receipt_key_id_for_authority(did, &dr_sec1).unwrap();
    json!({
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#mls-receipt-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": p256_multikey(mls_key),
            },
            {
                "id": dr_kid,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": p256_multikey(dr_key),
            }
        ]
    })
}

impl PlatformTransport for PlaneMockTransport {
    fn execute_http(&self, req: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let mut st = self.state.lock().unwrap();
        st.seen_urls.push(req.url.clone());

        if req.method == "GET" {
            if let Some(q) = st.exact_get.get_mut(&req.url) {
                if let Some(resp) = q.pop_front() {
                    return resp;
                }
            }
        }

        for (needle, handler) in &mut st.route_handlers {
            if req.url.contains(needle.as_str()) {
                return handler(&req);
            }
        }

        if req.url.ends_with("/.well-known/did.json") {
            let host = req
                .url
                .split("://")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or_default()
                .replace(':', "%3A");
            let did = format!("did:web:{host}");
            if let (Some(mls_k), Some(dr_k)) = (
                st.authority_mls_keys.get(&did),
                st.authority_dr_keys.get(&did),
            ) {
                return http_json(200, &authority_did_doc(&did, mls_k, dr_k));
            }
            return http_json(404, &json!({ "error": "NotFound" }));
        }

        if req.url.contains("/xrpc/com.atproto.identity.resolveDid") {
            let did_param = req
                .url
                .split("did=")
                .nth(1)
                .and_then(|s| s.split('&').next())
                .unwrap_or_default();
            let decoded = did_param.replace("%3A", ":").replace("%3a", ":");
            if let (Some(mls_k), Some(dr_k)) = (
                st.authority_mls_keys.get(&decoded),
                st.authority_dr_keys.get(&decoded),
            ) {
                return http_json(
                    200,
                    &json!({ "didDoc": authority_did_doc(&decoded, mls_k, dr_k) }),
                );
            }
            if decoded.starts_with("did:plc:") {
                return http_json(
                    200,
                    &json!({
                        "didDoc": {
                            "id": decoded,
                            "service": [{
                                "id": "#atproto_pds",
                                "type": "AtprotoPersonalDataServer",
                                "serviceEndpoint": PDS_URL,
                            }]
                        }
                    }),
                );
            }
            return http_json(404, &json!({ "error": "DidNotFound" }));
        }

        if req.url.contains("/xrpc/com.atproto.repo.listRecords")
            && req.url.contains("collection=blue.catbird.chat.device")
        {
            let repo_param = req
                .url
                .split("repo=")
                .nth(1)
                .and_then(|s| s.split('&').next())
                .unwrap_or_default();
            let did = repo_param.replace("%3A", ":").replace("%3a", ":");
            let records = st.pds_raw_records.get(&did).cloned().unwrap_or_default();
            return http_json(200, &json!({ "records": records }));
        }

        http_json(
            404,
            &json!({ "error": "UnhandledMockRoute", "url": req.url }),
        )
    }

    fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

fn clone_pending(p: &chat_wire::PendingGroupCreation) -> chat_wire::PendingGroupCreation {
    serde_json::from_value(serde_json::to_value(p).unwrap()).unwrap()
}

fn register_pds_device(st: &mut PlaneMockState, did: &str, dev_id: &str, pub_key: &[u8]) {
    let record = json!({
        "uri": format!("at://{did}/blue.catbird.chat.device/{dev_id}"),
        "value": {
            "$type": "blue.catbird.chat.device",
            "deviceId": dev_id,
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
            "algorithm": "Ed25519",
            "credentialDid": format!("{did}#{dev_id}"),
            "createdAt": "2026-11-14T00:00:00.000Z",
        }
    });
    st.pds_raw_records
        .entry(did.to_string())
        .or_default()
        .push(record);
}

fn new_plane_client_with_cfg(
    did: &str,
    dev_id: &str,
    ds_url: &str,
    home_ds_did: &str,
    transport: Arc<PlaneMockTransport>,
) -> (tempfile::TempDir, Arc<CatbirdMlsClient>, SignatureKeyPair) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = CatbirdMlsClientConfig {
        account_did: did.to_string(),
        device_id: dev_id.to_string(),
        storage_root: dir.path().to_string_lossy().into_owned(),
        home_ds_did: home_ds_did.to_string(),
        home_ds_endpoint: ds_url.to_string(),
        pds_endpoint: PDS_URL.to_string(),
    };
    let client =
        CatbirdMlsClient::open(cfg, Arc::new(PlaneMemKeyStore::new()), transport, None).unwrap();
    let signer = client
        .hooks
        .signature_keypair(CIPHERSUITE.signature_algorithm())
        .unwrap();
    let signer_json = serde_json::to_string(&signer).unwrap();
    let key_id = derive_key_id(signer.public());
    let now_ms = client.hooks.now_ms();
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta("enrolled_signer_json", &signer_json, now_ms)?;
            tx.put_account_meta("enrolled_device_id", dev_id, now_ms)?;
            tx.put_account_meta("enrolled_signer_key_id", &key_id, now_ms)?;
            tx.put_account_meta("auth_generation", "1", now_ms)?;
            Ok(())
        })
        .unwrap();
    (dir, client, signer)
}

fn new_plane_client(
    did: &str,
    dev_id: &str,
    transport: Arc<PlaneMockTransport>,
) -> (tempfile::TempDir, Arc<CatbirdMlsClient>, SignatureKeyPair) {
    new_plane_client_with_cfg(did, dev_id, DS_URL, SEQUENCER_DID, transport)
}

fn sign_control_receipt(
    mls_key: &P256SigningKey,
    sequencer_did: &str,
    cid: &str,
    coord: &Value,
    seq: u64,
    entry_id: &str,
    sender_did: &str,
    sender_dev: &str,
    digest: &[u8; 32],
) -> Value {
    let group_id = chat_wire::json_bytes(&coord["groupId"]).unwrap();
    let generation = coord["generation"].as_i64().unwrap_or(0);
    let epoch = coord["epoch"].as_u64().unwrap_or(0);
    let kid = format!("{sequencer_did}#mls-receipt-1");
    let payload = SequencerReceiptPayload {
        sequencer_did: sequencer_did.to_string(),
        conversation_id: cid.to_string(),
        group_id: group_id.clone(),
        epoch,
        sender_device_did_url: format!("{sender_did}#{sender_dev}"),
        entry_id: entry_id.to_string(),
        archive_commitment: *digest,
        seq,
        issued_at_ms: 1_763_000_000_000 + seq as i64,
    };
    let signed = sign_sequencer_receipt(mls_key, &kid, &payload).unwrap();
    json!({
        "kid": signed.key_id,
        "sequencerDid": sequencer_did,
        "conversationId": cid,
        "generation": generation,
        "groupId": { "$bytes": STANDARD.encode(&group_id) },
        "epoch": epoch,
        "seq": seq,
        "entryId": entry_id,
        "senderDid": sender_did,
        "senderDeviceId": sender_dev,
        "archiveCommitment": { "$bytes": STANDARD.encode(digest) },
        "issuedAtMs": 1_763_000_000_000i64 + seq as i64,
        "signature": { "$bytes": STANDARD.encode(signed.signature) },
    })
}

fn make_key_package_bytes(
    client: &CatbirdMlsClient,
    did: &str,
    dev_id: &str,
    signer: &SignatureKeyPair,
) -> (Vec<u8>, Vec<u8>) {
    let now_secs = client.hooks.now_secs();
    client
        .db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = client.hooks.openmls_provider(storage);
            signer.store(provider.storage()).unwrap();
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let bundle = KeyPackage::builder()
                .leaf_node_capabilities(caps)
                .key_package_lifetime(Lifetime::init(
                    now_secs.saturating_sub(60),
                    now_secs + 29 * 86_400,
                ))
                .build(
                    CIPHERSUITE,
                    &provider,
                    signer,
                    CredentialWithKey {
                        credential: BasicCredential::new(format!("{did}#{dev_id}").into_bytes())
                            .into(),
                        signature_key: signer.public().into(),
                    },
                )
                .unwrap();
            let kp_ref = bundle
                .key_package()
                .hash_ref(provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec();
            let kp_bytes = MlsMessageOut::from(bundle.key_package().clone())
                .tls_serialize_detached()
                .unwrap();
            Ok((kp_bytes, kp_ref))
        })
        .unwrap()
}

fn seed_active_two_member_group(
    alice: &CatbirdMlsClient,
    alice_signer: &SignatureKeyPair,
    bob: &CatbirdMlsClient,
    bob_signer: &SignatureKeyPair,
    cid: &str,
    last_seq: i64,
) -> (Vec<u8>, Value) {
    let group_id = Sha256::digest(format!("seed-group:{cid}:{last_seq}").as_bytes()).to_vec();
    let convo_uuid = uuid::Uuid::parse_str(cid).unwrap();
    let (bob_kp_bytes, _) = make_key_package_bytes(bob, BOB_DID, DEV_B1, bob_signer);
    let MlsMessageBodyIn::KeyPackage(bob_kp_in) =
        MlsMessageIn::tls_deserialize_exact(&bob_kp_bytes)
            .unwrap()
            .extract()
    else {
        panic!("expected KeyPackage");
    };
    let now_secs = alice.hooks.now_secs();
    let coords = alice
        .db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = alice.hooks.openmls_provider(storage);
            alice_signer.store(provider.storage()).unwrap();
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .capabilities(caps)
                .lifetime(Lifetime::init(
                    now_secs.saturating_sub(60),
                    now_secs + 29 * 86_400,
                ))
                .use_ratchet_tree_extension(true)
                .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .max_past_epochs(5)
                .sender_ratchet_configuration(
                    crate::types::GroupConfig::default().sender_ratchet_configuration(),
                )
                .build();
            let mut group = MlsGroup::new_with_group_id(
                &provider,
                alice_signer,
                &cfg,
                GroupId::from_slice(&group_id),
                CredentialWithKey {
                    credential: BasicCredential::new(format!("{ALICE_DID}#{DEV_A1}").into_bytes())
                        .into(),
                    signature_key: alice_signer.public().into(),
                },
            )
            .unwrap();
            let bob_kp = crate::sim_hooks::validate_key_package_at(
                bob_kp_in,
                provider.crypto(),
                ProtocolVersion::Mls10,
                now_secs,
            )
            .unwrap();
            group
                .add_members(&provider, alice_signer, &[bob_kp])
                .unwrap();
            group.merge_pending_commit(&provider).unwrap();
            let epoch = group.epoch().as_u64();
            let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
            let meta_key = derive_metadata_key_from_group(
                &mut group,
                provider.crypto(),
                provider.storage(),
                &group_id,
                epoch,
            )
            .unwrap();
            let snap = chat_wire::build_encrypted_metadata_snapshot_json_with_nonce(
                &meta_key,
                &group_id,
                &convo_uuid,
                0,
                epoch,
                &gch,
                &ctag,
                &alice.hooks.uuid_v4().to_string(),
                1,
                1,
                ALICE_DID,
                DEV_A1,
                1,
                alice_signer.public(),
                "Initial Title",
                "Initial Description",
                None,
                [4u8; 12],
            )?;
            let coords = json!({
                "conversationId": cid,
                "generation": 0,
                "stateVersion": 1,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
                "lifecycle": "active",
            });
            let now_ms = alice.hooks.now_ms();
            tx.upsert_conversation(&ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                generation: 0,
                epoch: epoch as i64,
                last_seq,
                sequencer_did: SEQUENCER_DID.to_string(),
                space_uri: None,
                title: Some("Initial Title".into()),
                unread_count: 0,
                updated_at_ms: now_ms,
            })?;
            tx.upsert_group_metadata(&GroupMetadataRow {
                conversation_id: cid.to_string(),
                metadata_version: 1,
                epoch: epoch as i64,
                title: Some("Initial Title".into()),
                description: Some("Initial Description".into()),
                avatar_setter_did: None,
                avatar_blob_cid: None,
                avatar_sym_key: None,
                avatar_sha256: None,
                avatar_mime_type: None,
                metadata_json: r#"{"title":"Initial Title","description":"Initial Description"}"#
                    .into(),
                updated_at_ms: now_ms,
            })?;
            tx.put_account_meta(
                &format!("conversation_coords:{cid}"),
                &serde_json::to_string(&coords)?,
                now_ms,
            )?;
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{cid}"),
                &serde_json::to_string(&snap)?,
                now_ms,
            )?;
            let roster = json!({
                ALICE_DID: { "role": "admin", "status": "active" },
                BOB_DID: { "role": "member", "status": "active" },
            });
            tx.put_account_meta(
                &chat_wire::conversation_roster_key(cid),
                &serde_json::to_string(&roster)?,
                now_ms,
            )?;
            Ok(coords)
        })
        .unwrap();
    (group_id, coords)
}

#[test]
fn live_plane_primitives_did_resolution_and_enrollment_boundaries() {
    let (transport, state) = PlaneMockTransport::new();
    let (dir, client, signer) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    let (dir_b, bob_client, bob_signer) = new_plane_client(BOB_DID, DEV_B1, transport.clone());
    {
        let mut st = state.lock().unwrap();
        register_pds_device(&mut st, ALICE_DID, DEV_A1, signer.public());
        register_pds_device(&mut st, BOB_DID, DEV_B1, bob_signer.public());
    }
    let (_gid, coords) =
        seed_active_two_member_group(&client, &signer, &bob_client, &bob_signer, CONVO_ID, 1);

    // 1. require_send_coordinate: generation and epoch disjunctions.
    client
        .db
        .read_tx(|tx| {
            let convo = tx.get_conversation(CONVO_ID)?.unwrap();
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = client.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .unwrap()
                .unwrap();
            assert!(require_send_coordinate(&convo, &coords, &group, &provider).is_ok());

            let mut wrong_epoch = coords.clone();
            wrong_epoch["epoch"] = json!(convo.epoch + 1);
            assert!(require_send_coordinate(&convo, &wrong_epoch, &group, &provider).is_err());

            let mut wrong_gen = coords.clone();
            wrong_gen["generation"] = json!(convo.generation + 1);
            assert!(require_send_coordinate(&convo, &wrong_gen, &group, &provider).is_err());
            Ok(())
        })
        .unwrap();

    // 2-3. participant_removal_key exact formatting.
    assert_eq!(
        participant_removal_key(CONVO_ID, BOB_DID),
        format!("{CONVO_ID}:{BOB_DID}")
    );

    // 4-5. GroupCreationFlightGuard::is_active before, during, and after guard lifetime.
    let root = dir.path().to_str().unwrap();
    assert!(!GroupCreationFlightGuard::is_active(
        root, ALICE_DID, CONVO_ID
    ));
    {
        let guard = GroupCreationFlightGuard::try_acquire(root, ALICE_DID, CONVO_ID)
            .expect("initial flight guard acquire");
        assert!(GroupCreationFlightGuard::is_active(
            root, ALICE_DID, CONVO_ID
        ));
        assert!(GroupCreationFlightGuard::try_acquire(root, ALICE_DID, CONVO_ID).is_none());
        drop(guard);
    }
    assert!(!GroupCreationFlightGuard::is_active(
        root, ALICE_DID, CONVO_ID
    ));

    // 6. uuid_v4 requires BOTH Version::Random AND Variant::RFC4122.
    assert!(uuid_v4("11111111-1111-4111-8111-111111111111", "id").is_ok());
    // UUIDv1 with RFC4122 variant -> rejected.
    assert!(uuid_v4("11111111-1111-1111-8111-111111111111", "id").is_err());
    // Version nibble 4 with Microsoft reserved variant (0xc0) -> rejected.
    assert!(uuid_v4("11111111-1111-4111-c111-111111111111", "id").is_err());

    // 7-10. resolve_did_document status guards and scheme selection.
    let fake_plc = "did:plc:statusguardaaaaaaaaaaaaa";
    let plc_url = format!("https://plc.directory/{fake_plc}");
    state
        .lock()
        .unwrap()
        .exact_get
        .entry(plc_url.clone())
        .or_default()
        .push_back(http_json(500, &json!({ "id": fake_plc })));
    assert!(
        client.resolve_did_document(fake_plc).is_err(),
        "a PLC directory server error without a cached document must fail closed"
    );
    state
        .lock()
        .unwrap()
        .exact_get
        .entry(plc_url)
        .or_default()
        .push_back(http_json(404, &json!({ "error": "NotFound" })));
    assert_eq!(client.resolve_did_document(fake_plc).unwrap(), None);

    // 8. did:web:127.0.0.1%3A18080 and did:web:localhost%3A18081 MUST use http://, not https://.
    for (did_web, expected_wk) in [
        (
            "did:web:127.0.0.1%3A18080",
            "http://127.0.0.1:18080/.well-known/did.json",
        ),
        (
            "did:web:localhost%3A18081",
            "http://localhost:18081/.well-known/did.json",
        ),
    ] {
        state
            .lock()
            .unwrap()
            .exact_get
            .entry(expected_wk.to_string())
            .or_default()
            .push_back(http_json(200, &json!({ "id": did_web })));
        let doc = client
            .resolve_did_document(did_web)
            .unwrap()
            .expect("http well-known must resolve");
        let parsed: Value = serde_json::from_slice(&doc).unwrap();
        assert_eq!(parsed["id"], did_web);
    }

    // 9. Remote did:web well-known requires status == 200 (not 503 with JSON body).
    let remote_web = "did:web:peer-check.example.com";
    let remote_wk = "https://peer-check.example.com/.well-known/did.json";
    state
        .lock()
        .unwrap()
        .exact_get
        .entry(remote_wk.to_string())
        .or_default()
        .push_back(http_json(503, &json!({ "id": remote_web })));
    // Non-200 from both PDS resolveDid (mock 404) and the did:web document, with nothing
    // cached, fails closed instead of reporting "no document".
    assert!(client.resolve_did_document(remote_web).is_err());
    let cached_key = format!("did_doc:{remote_web}");
    assert!(client
        .db
        .read_tx(|tx| tx.get_account_meta(&cached_key))
        .unwrap()
        .is_none());

    state
        .lock()
        .unwrap()
        .exact_get
        .entry(remote_wk.to_string())
        .or_default()
        .push_back(http_json(200, &json!({ "id": remote_web })));
    assert!(client.resolve_did_document(remote_web).unwrap().is_some());

    // A cached document still wins over a later non-200 from both sources.
    state
        .lock()
        .unwrap()
        .exact_get
        .entry(remote_wk.to_string())
        .or_default()
        .push_back(http_json(503, &json!({ "error": "Unavailable" })));
    let cached = client
        .resolve_did_document(remote_web)
        .unwrap()
        .expect("cached did:web document must be returned");
    let cached: Value = serde_json::from_slice(&cached).unwrap();
    assert_eq!(cached["id"], remote_web);

    // A did:web document with the wrong id is refused, and with nothing cached fails closed.
    let mismatched_web = "did:web:mismatch-check.example.com";
    state
        .lock()
        .unwrap()
        .exact_get
        .entry("https://mismatch-check.example.com/.well-known/did.json".to_string())
        .or_default()
        .push_back(http_json(
            200,
            &json!({ "id": "did:web:other.example.com" }),
        ));
    assert!(client.resolve_did_document(mismatched_web).is_err());

    // 10. Home DS fallback ds_base()/.well-known/did.json requires status == 200.
    let (home_transport, home_state) = PlaneMockTransport::new();
    home_state.lock().unwrap().authority_mls_keys.clear();
    home_state.lock().unwrap().authority_dr_keys.clear();
    let custom_ds = "http://127.0.0.1:19991";
    let (_home_dir, home_client, _) = new_plane_client_with_cfg(
        ALICE_DID,
        DEV_A1,
        custom_ds,
        "did:web:custom-home.example.com",
        home_transport,
    );
    let ds_wk = format!("{custom_ds}/.well-known/did.json");
    home_state
        .lock()
        .unwrap()
        .exact_get
        .entry(ds_wk.clone())
        .or_default()
        .push_back(http_json(
            500,
            &json!({ "id": "did:web:custom-home.example.com" }),
        ));
    assert!(home_client
        .resolve_did_document("did:web:custom-home.example.com")
        .is_err());
    home_state
        .lock()
        .unwrap()
        .exact_get
        .entry(ds_wk)
        .or_default()
        .push_back(http_json(
            200,
            &json!({ "id": "did:web:custom-home.example.com" }),
        ));
    assert!(home_client
        .resolve_did_document("did:web:custom-home.example.com")
        .unwrap()
        .is_some());

    // 12-14. enroll_device_live completion identity binding.
    let key_id = derive_key_id(signer.public());
    let set_enrollment_meta =
        |bound_dev: Option<&str>, bound_key: Option<&str>, scoped: Option<&str>| {
            let now_ms = client.hooks.now_ms();
            client
                .db
                .write_tx(|tx| {
                    tx.put_account_meta("auth_generation", "1", now_ms)?;
                    match bound_dev {
                        Some(v) => tx.put_account_meta("enrolled_device_id", v, now_ms)?,
                        None => tx.delete_account_meta("enrolled_device_id")?,
                    }
                    match bound_key {
                        Some(v) => tx.put_account_meta("enrolled_signer_key_id", v, now_ms)?,
                        None => tx.delete_account_meta("enrolled_signer_key_id")?,
                    }
                    match scoped {
                        Some(v) => tx.put_account_meta("scoped_identity", v, now_ms)?,
                        None => tx.delete_account_meta("scoped_identity")?,
                    }
                    tx.delete_account_meta("enrolled_signer_json")?;
                    Ok(())
                })
                .unwrap();
        };
    let expected_scoped = format!("{ALICE_DID}#{DEV_A1}");
    // Legacy scoped_identity match when bound_device is None and key matches -> Ok(()).
    set_enrollment_meta(None, Some(&key_id), Some(&expected_scoped));
    assert!(client.enroll_device_live(DEV_A1, signer.public()).is_ok());

    // bound_device is Some(other) even though scoped_identity matches -> mismatch!
    set_enrollment_meta(Some(DEV_B1), Some(&key_id), Some(&expected_scoped));
    assert!(matches!(
        client.enroll_device_live(DEV_A1, signer.public()),
        Err(MLSError::InvalidState(msg)) if msg == "EnrollmentDeviceIdentityMismatch"
    ));

    // bound_device is None and scoped_identity mismatches -> mismatch!
    set_enrollment_meta(None, Some(&key_id), Some(&format!("{ALICE_DID}#{DEV_B1}")));
    assert!(matches!(
        client.enroll_device_live(DEV_A1, signer.public()),
        Err(MLSError::InvalidState(msg)) if msg == "EnrollmentDeviceIdentityMismatch"
    ));

    // bound_device matches, bound_key mismatches -> EnrollmentDeviceIdentityMismatch (not signer missing).
    set_enrollment_meta(Some(DEV_A1), Some("wrong-key-id"), None);
    assert!(matches!(
        client.enroll_device_live(DEV_A1, signer.public()),
        Err(MLSError::InvalidState(msg)) if msg == "EnrollmentDeviceIdentityMismatch"
    ));

    // bound_device mismatches, bound_key matches -> EnrollmentDeviceIdentityMismatch.
    set_enrollment_meta(Some(DEV_B1), Some(&key_id), None);
    assert!(matches!(
        client.enroll_device_live(DEV_A1, signer.public()),
        Err(MLSError::InvalidState(msg)) if msg == "EnrollmentDeviceIdentityMismatch"
    ));

    drop((dir, dir_b));
}

#[test]
fn live_plane_c33_retry_and_publication_outcome_binding_boundaries() {
    let (transport, state) = PlaneMockTransport::new();
    let (dir_a, client, signer) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    let (dir_b, bob_client, bob_signer) = new_plane_client(BOB_DID, DEV_B1, transport.clone());
    {
        let mut st = state.lock().unwrap();
        register_pds_device(&mut st, ALICE_DID, DEV_A1, signer.public());
        register_pds_device(&mut st, BOB_DID, DEV_B1, bob_signer.public());
    }

    // 15. MAX_RETRY_AFTER_SECS * 1_000 (300_000 ms) vs + 1_000 (1_300 ms).
    let now_ms = client.hooks.now_ms();
    let deferred_journal = PendingDirectRequestCreation {
        version: DIRECT_REQUEST_CREATION_VERSION,
        request_id: "33333333-3333-4333-8333-333333333333".to_string(),
        first_message_id: "44444444-4444-4444-8444-444444444444".to_string(),
        conversation_id: CONVO_ID.to_string(),
        intro_text: "hi".to_string(),
        prepare_wrapper: Vec::new(),
        retry_at_ms: now_ms + 5_000,
        retry_code: Some("DeferredRateLimit".to_string()),
        publish: None,
    };
    let deferred_raw = serde_json::to_string(&deferred_journal).unwrap();
    client
        .db
        .write_tx(|tx| {
            tx.put_pending_op(DIRECT_REQUEST_CREATION_OP, BOB_DID, &deferred_raw, now_ms)
        })
        .unwrap();
    assert!(matches!(
        client.create_c33_direct_request_live(CONVO_ID, DEV_A1, BOB_DID, None),
        Err(MLSError::InvalidState(code)) if code == "DeferredRateLimit"
    ));

    // 16-25. publish_c33_direct_request outcome binding disjunctions.
    let request_id = "33333333-3333-4333-8333-333333333333";
    let first_message_id = "44444444-4444-4444-8444-444444444444";
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()));
    let prepare_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "keyId": key_id,
        "authGeneration": 1,
        "requestId": request_id,
        "firstMessageId": first_message_id,
        "conversationId": CONVO_ID,
        "recipientDid": BOB_DID,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": request_id,
        "signedAt": "2026-11-15T12:00:00.000Z",
    });
    let prepare_wrapper =
        chat_wire::sign_direct_request_wrapper(DirectRequestKind::Prepare, prepare_body, &signer)
            .unwrap();
    let prepare = dr_transcript::verify_signed_request(
        DirectRequestKind::Prepare,
        &prepare_wrapper,
        signer.public(),
    )
    .unwrap();

    let (bob_kp_bytes, bob_kp_ref) =
        make_key_package_bytes(&bob_client, BOB_DID, DEV_B1, &bob_signer);
    let prep_digest_b64 = STANDARD.encode([0x11u8; 32]);
    let context_val = json!({
        "protocolVersion": "2",
        "requestId": request_id,
        "firstMessageId": first_message_id,
        "conversationId": CONVO_ID,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "actorKeyId": key_id,
        "recipientDid": BOB_DID,
        "preparationDigest": prep_digest_b64,
    });
    let context_json = serde_json::to_vec(&context_val).unwrap();
    let group_id_bytes = vec![0x72u8; 32];
    let now_secs = client.hooks.now_secs();
    let (mls_key, dr_key) = {
        let st = state.lock().unwrap();
        (
            st.authority_mls_keys[SEQUENCER_DID].clone(),
            st.authority_dr_keys[SEQUENCER_DID].clone(),
        )
    };
    let dr_sec1 = sec1_bytes(&dr_key);
    let mls_sec1 = sec1_bytes(&mls_key);
    let (bootstrap, kv_batch) = client
        .db
        .read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let boot = {
                let storage = OpenMlsKvStorage::new(&overlay);
                let provider = client.hooks.openmls_provider(storage);
                signer.store(provider.storage()).unwrap();
                let (_g, boot) = direct_request_bootstrap::prepare_with_provider(
                    &provider,
                    &signer,
                    &DirectRequestBootstrapInput {
                        draft_id: request_id.to_string(),
                        context_json,
                        group_id: group_id_bytes.clone(),
                        generation: 0,
                        state_version: 1,
                        key_packages: vec![bob_kp_bytes.clone()],
                        expected_package_refs: vec![bob_kp_ref.clone()],
                        authority_import_until: now_secs + 14 * 86_400,
                        preparation_request_digest: *prepare.request_digest(),
                        receipt_authority_key: dr_sec1.clone(),
                        sequencer_did: SEQUENCER_DID.to_string(),
                        sequencer_receipt_authority_key: mls_sec1.clone(),
                        text: "hello direct".to_string(),
                        invitation: None,
                        metadata: GroupMetadataV1 {
                            version: 1,
                            title: String::new(),
                            description: String::new(),
                            avatar_blob_locator: None,
                            avatar_content_type: None,
                            space_avatar: None,
                        },
                    },
                    now_secs,
                )?;
                boot
            };
            Ok((boot, overlay.into_batch()))
        })
        .unwrap();

    let import_until_str = chat_wire::unix_secs_rfc3339_millis(bootstrap.import_until).unwrap();
    let artifact = |data: &[u8], content_type: &str| {
        json!({
            "framing": "mlsMessage",
            "contentType": content_type,
            "bytes": STANDARD.encode(data),
            "sha256": STANDARD.encode(Sha256::digest(data)),
        })
    };
    let mut publish_body = prepare.body().clone();
    publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    publish_body["signedAt"] = json!("2026-11-15T12:00:01.000Z");
    publish_body["preparationDigest"] = json!(prep_digest_b64);
    publish_body["preparationRequestDigest"] = json!(STANDARD.encode(prepare.request_digest()));
    publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    publish_body["next"] = bootstrap.coordinates.clone();
    publish_body["archiveCommitment"] = json!(STANDARD.encode(bootstrap.archive_commitment));
    publish_body["originalSenderAttestation"] = json!({
        "senderDid": bootstrap.original_sender_attestation.sender_did,
        "senderDeviceId": bootstrap.original_sender_attestation.sender_device_id,
        "senderTransportPubkey": STANDARD.encode(&bootstrap.original_sender_attestation.sender_transport_public_key),
        "signature": STANDARD.encode(&bootstrap.original_sender_attestation.signature),
    });
    publish_body["importUntil"] = json!(import_until_str);
    publish_body["artifacts"] = json!({
        "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
        "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
        "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
        "welcome": {
            "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
            "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
            "deliveries": [{
                "recipientDid": BOB_DID,
                "recipientDeviceId": DEV_B1,
                "provenance": {
                    "requestId": request_id,
                    "preparationDigest": prep_digest_b64,
                    "contextHash": STANDARD.encode(bootstrap.context_hash),
                    "grantId": "55555555-5555-4555-8555-555555555555",
                    "grantRevision": 1,
                    "keyPackageRef": STANDARD.encode(&bob_kp_ref),
                    "importUntil": import_until_str,
                }
            }],
        },
        "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot": {
            "coordinate": direct_request_bootstrap::metadata_coordinate(&bootstrap.coordinates).unwrap(),
            "originTransitionId": request_id,
            "metadataVersion": 1,
            "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
            "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
            "ciphertextSize": bootstrap.metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": ALICE_DID,
                "authorDeviceId": DEV_A1,
                "authorKeyId": key_id,
                "signaturePublicKey": STANDARD.encode(signer.public()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": request_id,
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
    });
    let publish_wrapper =
        chat_wire::sign_direct_request_wrapper(DirectRequestKind::Publish, publish_body, &signer)
            .unwrap();
    let verified_pub = dr_transcript::verify_signed_request(
        DirectRequestKind::Publish,
        &publish_wrapper,
        signer.public(),
    )
    .unwrap();
    let pending_pub = PendingDirectRequestCreation {
        version: DIRECT_REQUEST_CREATION_VERSION,
        request_id: request_id.to_string(),
        first_message_id: first_message_id.to_string(),
        conversation_id: CONVO_ID.to_string(),
        intro_text: "hello direct".to_string(),
        prepare_wrapper: prepare_wrapper.clone(),
        retry_at_ms: 0,
        retry_code: None,
        publish: Some(PendingDirectRequestPublication {
            group_id: group_id_bytes.clone(),
            sequencer_did: SEQUENCER_DID.to_string(),
            bootstrap: bootstrap.clone(),
            kv_batch,
            publish_wrapper,
        }),
    };
    let pending_raw = serde_json::to_string(&pending_pub).unwrap();

    let opening_seq_payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_string(),
        conversation_id: CONVO_ID.to_string(),
        group_id: group_id_bytes.clone(),
        epoch: bootstrap.coordinates["epoch"].as_u64().unwrap_or(1),
        sender_device_did_url: format!("{ALICE_DID}#{DEV_A1}"),
        entry_id: first_message_id.to_string(),
        archive_commitment: bootstrap.archive_commitment,
        seq: 1,
        issued_at_ms: 1_763_000_000_001,
    };
    let signed_opening_rcpt = sign_sequencer_receipt(
        &mls_key,
        &format!("{SEQUENCER_DID}#mls-receipt-1"),
        &opening_seq_payload,
    )
    .unwrap();
    let dr_kid =
        dr_transcript::direct_request_receipt_key_id_for_authority(SEQUENCER_DID, &dr_sec1)
            .unwrap();
    let base_receipt = json!({
        "$type": "blue.catbird.chat.defs#directRequestPublishedReceipt",
        "requestId": request_id,
        "requestDigest": STANDARD.encode(verified_pub.request_digest()),
        "recordedAt": "2026-11-15T12:00:02.000Z",
        "conversationId": CONVO_ID,
        "firstMessageId": first_message_id,
        "coordinates": bootstrap.coordinates,
        "preparationRequestDigest": STANDARD.encode(prepare.request_digest()),
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "actorKeyId": key_id,
        "authGeneration": 1,
        "requestKind": "publish",
        "sequencerReceipt": {
            "conversationId": CONVO_ID,
            "generation": 0,
            "groupId": STANDARD.encode(&group_id_bytes),
            "epoch": bootstrap.coordinates["epoch"],
            "entryId": first_message_id,
            "seq": 1,
            "senderDid": ALICE_DID,
            "senderDeviceId": DEV_A1,
            "archiveCommitment": STANDARD.encode(bootstrap.archive_commitment),
            "issuedAtMs": 1_763_000_000_001i64,
            "sequencerDid": SEQUENCER_DID,
            "kid": signed_opening_rcpt.key_id,
            "signature": STANDARD.encode(signed_opening_rcpt.signature),
        }
    });

    let sign_outcome = |receipt: Value| -> Value {
        let body = json!({
            "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
            "protocolVersion": "2",
            "authorityDid": SEQUENCER_DID,
            "keyId": dr_kid,
            "receipt": receipt,
        });
        let signing_bytes = dr_transcript::direct_request_signing_bytes(
            DirectRequestKind::Outcome,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let sig: p256::ecdsa::Signature = dr_key.sign(&signing_bytes);
        let sig = sig.normalize_s().unwrap_or(sig);
        json!({
            "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
            "body": body,
            "signature": STANDARD.encode(sig.to_bytes()),
        })
    };

    let mut wrong_coords = bootstrap.coordinates.clone();
    wrong_coords["stateVersion"] = json!(99);
    let mutations: Vec<(&str, Value)> = vec![
        ("requestId", json!("99999999-9999-4999-8999-999999999999")),
        ("conversationId", json!(CONVO_ID_2)),
        (
            "firstMessageId",
            json!("88888888-8888-4888-8888-888888888888"),
        ),
        ("actorDid", json!(BOB_DID)),
        ("actorDeviceId", json!(DEV_B1)),
        ("actorKeyId", json!(URL_SAFE_NO_PAD.encode([0x44u8; 32]))),
        ("authGeneration", json!(2)),
        ("requestDigest", json!(STANDARD.encode([0x99u8; 32]))),
        (
            "preparationRequestDigest",
            json!(STANDARD.encode([0x88u8; 32])),
        ),
        ("coordinates", wrong_coords),
    ];

    for (field, mutated_val) in mutations {
        let mut forged_receipt = base_receipt.clone();
        forged_receipt[field] = mutated_val;
        let forged_outcome = sign_outcome(forged_receipt);
        {
            let mut st = state.lock().unwrap();
            st.route_handlers.clear();
            st.route_handlers.push((
                "/xrpc/blue.catbird.chat.publishDirectRequest".to_string(),
                Box::new(move |_| http_json(200, &json!({ "outcome": forged_outcome }))),
            ));
        }
        client
            .db
            .write_tx(|tx| {
                tx.put_pending_op(DIRECT_REQUEST_CREATION_OP, BOB_DID, &pending_raw, now_ms)
            })
            .unwrap();
        let cloned_pending: PendingDirectRequestCreation =
            serde_json::from_str(&pending_raw).unwrap();
        let err = client
            .publish_c33_direct_request(
                cloned_pending,
                pending_raw.clone(),
                &prepare,
                BOB_DID,
                DEV_A1,
                &signer,
                &key_id,
                1,
            )
            .expect_err(&format!("field {field} mismatch must fail"));
        assert!(
            err.to_string()
                .contains("C33 publication outcome binding mismatch"),
            "unexpected error for {field}: {err}"
        );
    }

    // Positive control: valid outcome succeeds and adopts the conversation.
    let valid_outcome = sign_outcome(base_receipt);
    {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.publishDirectRequest".to_string(),
            Box::new(move |_| http_json(200, &json!({ "outcome": valid_outcome }))),
        ));
    }
    client
        .db
        .write_tx(|tx| tx.put_pending_op(DIRECT_REQUEST_CREATION_OP, BOB_DID, &pending_raw, now_ms))
        .unwrap();
    let cloned_pending: PendingDirectRequestCreation = serde_json::from_str(&pending_raw).unwrap();
    let adopted = client
        .publish_c33_direct_request(
            cloned_pending,
            pending_raw,
            &prepare,
            BOB_DID,
            DEV_A1,
            &signer,
            &key_id,
            1,
        )
        .expect("valid published outcome must adopt conversation");
    assert_eq!(adopted.conversation_id, CONVO_ID);

    drop((dir_a, dir_b));
}

fn build_journaled_group_creation(
    client: &CatbirdMlsClient,
    signer: &SignatureKeyPair,
    cid: &str,
    operation_id: &str,
    signed_at: &str,
) -> (chat_wire::PendingGroupCreation, Value) {
    let convo_uuid = uuid::Uuid::parse_str(cid).unwrap();
    let group_id =
        Sha256::digest(format!("journal-group:{cid}:{operation_id}").as_bytes()).to_vec();
    let (ggi, gch, ctag, snap, kv_batch) = client
        .db
        .read_tx(|tx| {
            client.stage_genesis_group(
                tx,
                signer,
                1,
                DEV_A1,
                &convo_uuid,
                &group_id,
                0,
                operation_id,
                1,
                1,
                "Group Title",
                "Group Desc",
            )
        })
        .unwrap();

    let mut participants = vec![
        json!({
            "userDid": ALICE_DID,
            "status": "active",
            "role": "admin"
        }),
        json!({
            "userDid": BOB_DID,
            "status": "pending",
            "role": "member",
            "invitationProvenance": {
                "invitationTransitionId": operation_id,
                "invitedByDid": ALICE_DID,
                "invitedByDeviceId": DEV_A1,
            }
        }),
    ];
    participants.sort_by(|a, b| {
        a["userDid"]
            .as_str()
            .unwrap()
            .cmp(b["userDid"].as_str().unwrap())
    });
    let next_coords = json!({
        "conversationId": cid,
        "generation": 0,
        "stateVersion": 0,
        "groupId": { "$bytes": STANDARD.encode(&group_id) },
        "epoch": 0,
        "groupContextHash": { "$bytes": STANDARD.encode(gch) },
        "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
        "lifecycle": "active",
    });
    let create_body = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\0",
        "conversationId": cid,
        "conversationKind": "group",
        "transitionId": operation_id,
        "idempotencyKey": operation_id,
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "keyId": derive_key_id(signer.public()),
        "authGeneration": 1,
        "absence": true,
        "next": next_coords,
        "manifest": {
            "participants": participants,
            "actorLeaf": {
                "userDid": ALICE_DID,
                "deviceId": DEV_A1,
                "leafOrigin": "genesis",
            }
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": { "$bytes": STANDARD.encode(&ggi) },
            "sha256": STANDARD.encode(Sha256::digest(&ggi)),
        },
        "metadataSnapshot": snap,
        "signedAt": signed_at,
    });
    let prepared = chat_wire::sign_clean_chat_mutation(
        ALICE_DID,
        DEV_A1,
        Some(1),
        CanonicalOperation::CreateConversation,
        &create_body,
        signer,
    )
    .unwrap();
    let req_bytes = prepared.body.unwrap_or_default();
    let req_val: Value = serde_json::from_slice(&req_bytes).unwrap();
    let wire_signed_at = req_val["signedRequest"]["body"]["signedAt"]
        .as_str()
        .unwrap()
        .to_string();
    let pending = chat_wire::PendingGroupCreation {
        version: chat_wire::GROUP_CREATION_JOURNAL_VERSION,
        conversation_id: cid.to_string(),
        journal_id: operation_id.to_string(),
        sequencer_did: SEQUENCER_DID.to_string(),
        group_id,
        signer_public_key: signer.public().to_vec(),
        attempts: vec![chat_wire::PendingGroupCreationAttempt {
            operation_id: operation_id.to_string(),
            signed_at: wire_signed_at,
            request: req_bytes,
            expired_confirmed: false,
        }],
        kv_batch,
        title: Some("Group Title".into()),
        description: Some("Group Desc".into()),
        new_signer_json: None,
        created_at_ms: client.hooks.now_ms(),
        retry_at_ms: 0,
        retry_count: 0,
        retry_code: None,
    };
    (pending, create_body)
}

#[test]
#[ignore = "fixture predates PLC-directory DID resolution and repository-proof device directories"]
fn live_plane_group_creation_journal_presence_and_entry_proof_boundaries() {
    let (transport, state) = PlaneMockTransport::new();
    let (dir, client, signer) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    let (dir_b, bob_client, bob_signer) = new_plane_client(BOB_DID, DEV_B1, transport.clone());
    let op_id_1 = "66666666-6666-4666-8666-666666666661";
    let (pending, create_body) = build_journaled_group_creation(
        &client,
        &signer,
        CONVO_ID,
        op_id_1,
        &client.hooks.now_rfc3339_millis(),
    );

    // 26. stage_genesis_group leaf lifetime not_after == now_secs + 29 * 86_400.
    client
        .db
        .read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            pending.kv_batch.apply(&overlay)?;
            let storage = OpenMlsKvStorage::new(&overlay);
            let provider = client.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&pending.group_id))
                .unwrap()
                .unwrap();
            let openmls::treesync::LeafNodeSource::KeyPackage(lt) =
                group.own_leaf_node().unwrap().leaf_node_source()
            else {
                panic!("expected KeyPackage leaf_node_source on genesis leaf");
            };
            let now_secs = client.hooks.now_secs();
            assert!(
                lt.validate_with_time(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_secs + 28 * 86_400)
                )
                .is_ok(),
                "leaf lifetime must remain valid 28 days into the future"
            );
            assert!(
                lt.validate_with_time(
                    std::time::UNIX_EPOCH
                        + std::time::Duration::from_secs(now_secs.saturating_sub(30))
                )
                .is_ok(),
                "leaf lifetime must tolerate 30s clock back-skew"
            );
            Ok(())
        })
        .unwrap();

    // 27-32. verified_pending_group_creation journal invariants.
    let base_verified = client.verified_pending_group_creation(&pending).unwrap();
    assert_eq!(base_verified.len(), 1);

    let mut empty_attempts = clone_pending(&pending);
    empty_attempts.attempts.clear();
    assert!(client
        .verified_pending_group_creation(&empty_attempts)
        .is_err());

    let mut mismatched_first = clone_pending(&pending);
    mismatched_first.journal_id = "66666666-6666-4666-8666-666666666699".to_string();
    assert!(client
        .verified_pending_group_creation(&mismatched_first)
        .is_err());

    // Build GROUP_CREATION_MAX_ATTEMPTS valid attempts via resign_pending_group_creation.
    let mut multi = clone_pending(&pending);
    let init_payload = serde_json::to_string(&multi).unwrap();
    client
        .db
        .write_tx(|tx| {
            tx.put_pending_op(
                GROUP_CREATION_OP,
                &multi.journal_id,
                &init_payload,
                multi.created_at_ms,
            )
        })
        .unwrap();
    let multi_jid = multi.journal_id.clone();
    while multi.attempts.len() < chat_wire::GROUP_CREATION_MAX_ATTEMPTS {
        let cur_raw = serde_json::to_string(&multi).unwrap();
        let vb = client.verified_pending_group_creation(&multi).unwrap()[0]
            .body
            .clone();
        client
            .resign_pending_group_creation(&multi_jid, &cur_raw, &mut multi, &vb)
            .unwrap();
    }
    assert_eq!(multi.attempts.len(), chat_wire::GROUP_CREATION_MAX_ATTEMPTS);
    // Exactly GROUP_CREATION_MAX_ATTEMPTS is valid (kills #28 ==, #29 >=, #31, #32).
    assert_eq!(
        client
            .verified_pending_group_creation(&multi)
            .unwrap()
            .len(),
        chat_wire::GROUP_CREATION_MAX_ATTEMPTS
    );
    // Resigning once more evicts index 1 while keeping index 0 and staying at cap (#61).
    let cur_raw = serde_json::to_string(&multi).unwrap();
    let vb = client.verified_pending_group_creation(&multi).unwrap()[0]
        .body
        .clone();
    client
        .resign_pending_group_creation(&multi_jid, &cur_raw, &mut multi, &vb)
        .unwrap();
    assert_eq!(multi.attempts.len(), chat_wire::GROUP_CREATION_MAX_ATTEMPTS);
    assert_eq!(multi.attempts[0].operation_id, multi.journal_id);

    // GROUP_CREATION_MAX_ATTEMPTS + 1 -> rejected (#28).
    let mut over_cap = clone_pending(&multi);
    over_cap
        .attempts
        .push(multi.attempts.last().unwrap().clone());
    assert!(client.verified_pending_group_creation(&over_cap).is_err());

    // #30: metadata provenance requires BOTH snapshot.originTransitionId AND authorProof.originTransitionId.
    let sign_custom_attempt = |body: &Value| -> chat_wire::PendingGroupCreationAttempt {
        let prep = chat_wire::sign_clean_chat_mutation(
            ALICE_DID,
            DEV_A1,
            Some(1),
            CanonicalOperation::CreateConversation,
            body,
            &signer,
        )
        .unwrap();
        let bytes = prep.body.unwrap_or_default();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        chat_wire::PendingGroupCreationAttempt {
            operation_id: body["transitionId"].as_str().unwrap().to_string(),
            signed_at: v["signedRequest"]["body"]["signedAt"]
                .as_str()
                .unwrap()
                .to_string(),
            request: bytes,
            expired_confirmed: false,
        }
    };
    let wrong_tid = "66666666-6666-4666-8666-666666666677";
    let mut bad_snap_origin = create_body.clone();
    bad_snap_origin["metadataSnapshot"]["originTransitionId"] = json!(wrong_tid);
    let mut p_bad_snap = clone_pending(&pending);
    p_bad_snap.attempts = vec![sign_custom_attempt(&bad_snap_origin)];
    assert!(client.verified_pending_group_creation(&p_bad_snap).is_err());

    let mut bad_author_origin = create_body.clone();
    bad_author_origin["metadataSnapshot"]["authorProof"]["originTransitionId"] = json!(wrong_tid);
    let mut p_bad_author = clone_pending(&pending);
    p_bad_author.attempts = vec![sign_custom_attempt(&bad_author_origin)];
    assert!(client
        .verified_pending_group_creation(&p_bad_author)
        .is_err());

    // #31 & #32: second attempt changing genesis coordinates or genesisGroupInfo -> rejected.
    let op_id_2 = "66666666-6666-4666-8666-666666666662";
    let mut body_2 = create_body.clone();
    body_2["transitionId"] = json!(op_id_2);
    body_2["idempotencyKey"] = json!(op_id_2);
    body_2["metadataSnapshot"]["originTransitionId"] = json!(op_id_2);
    body_2["metadataSnapshot"]["authorProof"]["originTransitionId"] = json!(op_id_2);
    for p in body_2["manifest"]["participants"].as_array_mut().unwrap() {
        if let Some(ip) = p.pointer_mut("/invitationProvenance/invitationTransitionId") {
            *ip = json!(op_id_2);
        }
    }
    let mut body_diff_next = body_2.clone();
    body_diff_next["next"]["stateVersion"] = json!(1);
    let mut p_diff_next = clone_pending(&pending);
    p_diff_next
        .attempts
        .push(sign_custom_attempt(&body_diff_next));
    assert!(client
        .verified_pending_group_creation(&p_diff_next)
        .is_err());

    let mut body_diff_ggi = body_2;
    let alt_ggi = vec![0x99u8; 48];
    body_diff_ggi["genesisGroupInfo"]["bytes"] = json!({ "$bytes": STANDARD.encode(&alt_ggi) });
    body_diff_ggi["genesisGroupInfo"]["sha256"] = json!(STANDARD.encode(Sha256::digest(&alt_ggi)));
    let mut p_diff_ggi = clone_pending(&pending);
    p_diff_ggi
        .attempts
        .push(sign_custom_attempt(&body_diff_ggi));
    assert!(client.verified_pending_group_creation(&p_diff_ggi).is_err());

    // 33-37. pending_group_creation_presence HTTP status and conversationId checks.
    let set_state_resp = |status: u16, body: Value| {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(move |_| http_json(status, &body)),
        ));
    };
    set_state_resp(400, json!({ "error": "ConversationNotFound" }));
    assert!(matches!(
        client
            .pending_group_creation_presence(&pending, &base_verified[0].body)
            .unwrap(),
        GroupCreationPresence::Absent
    ));

    set_state_resp(400, json!({ "error": "InvalidRequest" }));
    assert!(client
        .pending_group_creation_presence(&pending, &base_verified[0].body)
        .is_err());

    set_state_resp(500, json!({ "error": "ConversationNotFound" }));
    assert!(client
        .pending_group_creation_presence(&pending, &base_verified[0].body)
        .is_err());

    set_state_resp(
        200,
        json!({ "state": { "coordinates": { "conversationId": CONVO_ID } } }),
    );
    assert!(matches!(
        client
            .pending_group_creation_presence(&pending, &base_verified[0].body)
            .unwrap(),
        GroupCreationPresence::Exists
    ));

    set_state_resp(
        200,
        json!({ "state": { "coordinates": { "conversationId": CONVO_ID_2 } } }),
    );
    assert!(client
        .pending_group_creation_presence(&pending, &base_verified[0].body)
        .is_err());

    // 38-59. pending_group_creation_entry_proof own & foreign branches.
    let mls_key = state.lock().unwrap().authority_mls_keys[SEQUENCER_DID].clone();
    let own_rcpt = sign_control_receipt(
        &mls_key,
        SEQUENCER_DID,
        CONVO_ID,
        &base_verified[0].body["next"],
        1,
        op_id_1,
        ALICE_DID,
        DEV_A1,
        &base_verified[0].digest,
    );
    let own_entry = json!({
        "$type": CREATION_ENTRY_KIND,
        "conversationId": CONVO_ID,
        "seq": 1,
        "entryId": op_id_1,
        "signedRequest": base_verified[0].submitted["signedRequest"],
        "sequencerReceipt": own_rcpt,
    });
    let set_entries_resp = |entry: Value| {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getEntries".to_string(),
            Box::new(move |_| http_json(200, &json!({ "entries": [entry] }))),
        ));
    };
    set_entries_resp(own_entry.clone());
    assert!(matches!(
        client
            .pending_group_creation_entry_proof(&pending, &base_verified)
            .unwrap(),
        GroupCreationEntryProof::Own(0)
    ));

    // Entry header checks (#38-#42).
    for mutated_entry in [
        {
            let mut e = own_entry.clone();
            e["$type"] = json!(POLICY_ENTRY_KIND);
            e
        },
        {
            let mut e = own_entry.clone();
            e["seq"] = json!(2);
            e
        },
        {
            let mut e = own_entry.clone();
            e["conversationId"] = json!(CONVO_ID_2);
            e
        },
    ] {
        set_entries_resp(mutated_entry);
        assert!(client
            .pending_group_creation_entry_proof(&pending, &base_verified)
            .is_err());
    }

    // Foreign creation proof (#43-#59).
    let build_foreign_entry = |conv_id: &str, tid: &str, idem: &str, entry_id: &str| -> Value {
        let (bob_pending, mut bob_body) = build_journaled_group_creation(
            &bob_client,
            &bob_signer,
            conv_id,
            tid,
            &bob_client.hooks.now_rfc3339_millis(),
        );
        let _ = bob_pending;
        bob_body["actorDid"] = json!(BOB_DID);
        bob_body["actorDeviceId"] = json!(DEV_B1);
        bob_body["keyId"] = json!(derive_key_id(bob_signer.public()));
        bob_body["idempotencyKey"] = json!(idem);
        for p in bob_body["manifest"]["participants"].as_array_mut().unwrap() {
            if p["userDid"] == ALICE_DID {
                *p = json!({
                    "userDid": ALICE_DID,
                    "status": "pending",
                    "role": "member",
                    "invitationProvenance": {
                        "invitationTransitionId": tid,
                        "invitedByDid": BOB_DID,
                        "invitedByDeviceId": DEV_B1,
                    }
                });
            } else if p["userDid"] == BOB_DID {
                *p = json!({
                    "userDid": BOB_DID,
                    "status": "active",
                    "role": "admin",
                });
            }
        }
        bob_body["manifest"]["actorLeaf"] = json!({
            "userDid": BOB_DID,
            "deviceId": DEV_B1,
            "leafOrigin": "genesis",
        });
        bob_body["metadataSnapshot"]["authorProof"]["authorDid"] = json!(BOB_DID);
        bob_body["metadataSnapshot"]["authorProof"]["authorDeviceId"] = json!(DEV_B1);
        bob_body["metadataSnapshot"]["authorProof"]["authorKeyId"] =
            json!(derive_key_id(bob_signer.public()));
        bob_body["metadataSnapshot"]["authorProof"]["signaturePublicKey"] =
            json!({ "$bytes": STANDARD.encode(bob_signer.public()) });
        let prep = chat_wire::sign_clean_chat_mutation(
            BOB_DID,
            DEV_B1,
            Some(1),
            CanonicalOperation::CreateConversation,
            &bob_body,
            &bob_signer,
        )
        .unwrap();
        let submitted: Value = serde_json::from_slice(&prep.body.unwrap()).unwrap();
        let (v_body, digest) = chat_wire::verify_signed_mutation_body_and_digest(
            &submitted["signedRequest"],
            SignedMutationKind::Creation,
            bob_signer.public(),
        )
        .unwrap();
        let rcpt = sign_control_receipt(
            &mls_key,
            SEQUENCER_DID,
            CONVO_ID,
            &v_body["next"],
            1,
            entry_id,
            BOB_DID,
            DEV_B1,
            &digest,
        );
        json!({
            "$type": CREATION_ENTRY_KIND,
            "conversationId": CONVO_ID,
            "seq": 1,
            "entryId": entry_id,
            "signedRequest": submitted["signedRequest"],
            "sequencerReceipt": rcpt,
        })
    };

    let foreign_tid = "77777777-7777-4777-8777-777777777771";
    let valid_foreign = build_foreign_entry(CONVO_ID, foreign_tid, foreign_tid, foreign_tid);

    // First: PDS holds ONLY another device ID under bob_signer's key -> must fail (#45, #47)!
    let wrong_key = Ed25519SigningKey::from_bytes(&[0x91; 32]);
    {
        let mut st = state.lock().unwrap();
        st.pds_raw_records.clear();
        register_pds_device(&mut st, BOB_DID, DEV_C1, bob_signer.public());
    }
    client
        .db
        .write_tx(|tx| tx.delete_account_meta(&format!("pds_device_keys:{BOB_DID}")))
        .unwrap();
    set_entries_resp(valid_foreign.clone());
    assert!(client
        .pending_group_creation_entry_proof(&pending, &base_verified)
        .is_err());

    // Second: PDS holds [DEV_B1 with wrong key, DEV_B1 with bob_signer's key] -> must find #2 and return Foreign!
    // (Simultaneously kills #43, #44, #46, #47, #48, #49, #51, #53, #55, #57, #59!)
    {
        let mut st = state.lock().unwrap();
        st.pds_raw_records.clear();
        register_pds_device(
            &mut st,
            BOB_DID,
            DEV_B1,
            wrong_key.verifying_key().as_bytes(),
        );
        register_pds_device(&mut st, BOB_DID, DEV_B1, bob_signer.public());
    }
    client
        .db
        .write_tx(|tx| tx.delete_account_meta(&format!("pds_device_keys:{BOB_DID}")))
        .unwrap();
    set_entries_resp(valid_foreign);
    assert!(matches!(
        client
            .pending_group_creation_entry_proof(&pending, &base_verified)
            .unwrap(),
        GroupCreationEntryProof::Foreign
    ));

    // Third: foreign entry with transitionId != entryId -> must fail (#50).
    let mismatched_entry_id = "77777777-7777-4777-8777-777777777772";
    let bad_entry_id = build_foreign_entry(CONVO_ID, foreign_tid, foreign_tid, mismatched_entry_id);
    set_entries_resp(bad_entry_id);
    assert!(client
        .pending_group_creation_entry_proof(&pending, &base_verified)
        .is_err());

    // Fourth: foreign entry with idempotencyKey != transitionId -> must fail (#52, #54)!
    let bad_idem = build_foreign_entry(CONVO_ID, foreign_tid, mismatched_entry_id, foreign_tid);
    set_entries_resp(bad_idem);
    assert!(client
        .pending_group_creation_entry_proof(&pending, &base_verified)
        .is_err());

    // 60-65. CAS ownership guards in resign, defer, and delete_pending_group_creation.
    let mut cas_pending = clone_pending(&pending);
    let cas_jid = cas_pending.journal_id.clone();
    assert!(matches!(
        client.resign_pending_group_creation(
            &cas_jid,
            "stale-expected-payload",
            &mut cas_pending,
            &base_verified[0].body,
        ),
        Err(MLSError::InvalidState(code)) if code == "GroupCreationOwnershipChanged"
    ));
    assert!(matches!(
        client.defer_pending_group_creation_retry(
            &cas_jid,
            "stale-expected-payload",
            &mut cas_pending,
            "TempError".into(),
            None,
        ),
        Err(MLSError::InvalidState(code)) if code == "GroupCreationOwnershipChanged"
    ));
    assert!(matches!(
        client.delete_pending_group_creation(&cas_pending.journal_id, "stale-expected-payload"),
        Err(MLSError::InvalidState(code)) if code == "GroupCreationOwnershipChanged"
    ));

    let fresh_raw = serde_json::to_string(&pending).unwrap();
    client
        .db
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM pending_ops WHERE op_kind = ?1",
                    [GROUP_CREATION_OP],
                )
                .unwrap();
            tx.put_pending_op(
                GROUP_CREATION_OP,
                &pending.journal_id,
                &fresh_raw,
                pending.created_at_ms,
            )
        })
        .unwrap();
    client
        .delete_pending_group_creation(&pending.journal_id, &fresh_raw)
        .unwrap();
    assert!(client
        .db
        .read_tx(|tx| group_creation_record(tx.conn(), CONVO_ID))
        .unwrap()
        .is_none());

    drop((dir, dir_b));
}

#[test]
#[ignore = "fixture predates PLC-directory DID resolution and repository-proof device directories"]
fn live_plane_resolve_status_retry_and_cancel_group_creation_boundaries() {
    let (transport, state) = PlaneMockTransport::new();
    let (dir, client, signer) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    let (dir_b, bob_client, bob_signer) = new_plane_client(BOB_DID, DEV_B1, transport.clone());
    {
        let mut st = state.lock().unwrap();
        register_pds_device(&mut st, ALICE_DID, DEV_A1, signer.public());
        register_pds_device(&mut st, BOB_DID, DEV_B1, bob_signer.public());
    }

    let op_id = "66666666-6666-4666-8666-666666666663";
    let (base_pending, _) = build_journaled_group_creation(
        &client,
        &signer,
        CONVO_ID,
        op_id,
        "2026-01-01T00:00:00.000Z", // expired by wall-clock > 15m + 5m skew
    );

    let save_journal = |key: &str, p: &chat_wire::PendingGroupCreation| {
        let raw = serde_json::to_string(p).unwrap();
        client
            .db
            .write_tx(|tx| {
                tx.conn()
                    .execute(
                        "DELETE FROM pending_ops WHERE op_kind = ?1",
                        [GROUP_CREATION_OP],
                    )
                    .unwrap();
                tx.put_pending_op(GROUP_CREATION_OP, key, &raw, p.created_at_ms)
            })
            .unwrap();
    };

    // 66-67 & 77-82. Version, conversation_id, and journal_id checks in status & resolve.
    save_journal(&base_pending.journal_id, &base_pending);
    let st_ok = client
        .pending_group_creation_status(CONVO_ID)
        .unwrap()
        .expect("journaled status must return Some");
    assert_eq!(st_ok.conversation_id, CONVO_ID);

    let mut bad_ver = clone_pending(&base_pending);
    bad_ver.version = 99;
    save_journal(&bad_ver.journal_id, &bad_ver);
    assert!(client.pending_group_creation_status(CONVO_ID).is_err());
    assert!(client
        .resolve_pending_group_creation(CONVO_ID, GroupCreationResolutionMode::ExplicitRetry)
        .is_err());

    // Mismatched op_key vs journal_id (#67, #81, #82).
    save_journal("wrong-op-key", &base_pending);
    assert!(client.pending_group_creation_status(CONVO_ID).is_err());
    assert!(client
        .resolve_pending_group_creation(CONVO_ID, GroupCreationResolutionMode::ExplicitRetry)
        .is_err());

    // Mismatched conversation_id via non-canonical stored string (#66, #79, #80).
    let raw_upper_cid = serde_json::to_string(&base_pending)
        .unwrap()
        .replace(CONVO_ID, &CONVO_ID.to_uppercase());
    // Note: SQLite json_extract matches exact string; test uppercase lookup vs canonicalized check:
    let upper_cid_convo = "ABCDEF12-3456-4789-8ABC-DEF123456789";
    let mut upper_pending = clone_pending(&base_pending);
    upper_pending.conversation_id = upper_cid_convo.to_string();
    let _ = raw_upper_cid;
    save_journal(&upper_pending.journal_id, &upper_pending);
    // 69, 71, 73, 75: 2 expired attempts where attempt 0 gets 409 IdempotencyConflict (exists evidence)
    // and attempt 1 gets 400 SignedOperationExpired (not exists evidence), getConversationState -> Absent,
    // ExplicitRetry -> defers with ConversationExistsUnresolved!
    let mut two_expired = clone_pending(&base_pending);
    save_journal(&two_expired.journal_id, &two_expired);
    let raw0 = serde_json::to_string(&two_expired).unwrap();
    let vb0 = client
        .verified_pending_group_creation(&two_expired)
        .unwrap()[0]
        .body
        .clone();
    let jid0 = two_expired.journal_id.clone();
    client
        .resign_pending_group_creation(&jid0, &raw0, &mut two_expired, &vb0)
        .unwrap();
    // Mark attempt 1 as server-confirmed expired too so attempts_expired == true.
    two_expired.attempts[1].expired_confirmed = true;
    save_journal(&two_expired.journal_id, &two_expired);
    {
        let call_idx = Arc::new(Mutex::new(0usize));
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.createConversation".to_string(),
            Box::new(move |_| {
                let mut idx = call_idx.lock().unwrap();
                *idx += 1;
                if *idx == 1 {
                    http_json(409, &json!({ "error": "IdempotencyConflict" }))
                } else {
                    http_json(400, &json!({ "error": "SignedOperationExpired" }))
                }
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| http_json(400, &json!({ "error": "ConversationNotFound" }))),
        ));
    }
    assert!(matches!(
        client.retry_pending_group_creation(CONVO_ID),
        Err(MLSError::GroupCreationPending { last_error_code, .. })
            if last_error_code == "ConversationExistsUnresolved"
    ));

    // 70: Unexpired attempt + 503 ServiceUnavailable + Absent -> CreationAttemptsMayStillCommit (does NOT resign).
    let fresh_op_id = "66666666-6666-4666-8666-666666666664";
    let (unexpired_pending, _) = build_journaled_group_creation(
        &client,
        &signer,
        CONVO_ID,
        fresh_op_id,
        &client.hooks.now_rfc3339_millis(),
    );
    save_journal(&unexpired_pending.journal_id, &unexpired_pending);
    {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.createConversation".to_string(),
            Box::new(|_| http_json(503, &json!({ "error": "ServiceUnavailable" }))),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| http_json(400, &json!({ "error": "ConversationNotFound" }))),
        ));
    }
    assert!(matches!(
        client.retry_pending_group_creation(CONVO_ID),
        Err(MLSError::GroupCreationPending { last_error_code, .. })
            if last_error_code == "CreationAttemptsMayStillCommit"
    ));

    // 72 & 74: Expired attempt + 409 IdempotencyConflict + Exists + Foreign entry -> GroupCreationRejected("ForeignConversationCreation").
    save_journal(&base_pending.journal_id, &base_pending);
    let mls_key = state.lock().unwrap().authority_mls_keys[SEQUENCER_DID].clone();
    let foreign_tid = "77777777-7777-4777-8777-777777777775";
    let (_, mut bob_body) = build_journaled_group_creation(
        &bob_client,
        &bob_signer,
        CONVO_ID,
        foreign_tid,
        &bob_client.hooks.now_rfc3339_millis(),
    );
    bob_body["actorDid"] = json!(BOB_DID);
    bob_body["actorDeviceId"] = json!(DEV_B1);
    bob_body["keyId"] = json!(derive_key_id(bob_signer.public()));
    for p in bob_body["manifest"]["participants"].as_array_mut().unwrap() {
        if p["userDid"] == ALICE_DID {
            *p = json!({
                "userDid": ALICE_DID,
                "status": "pending",
                "role": "member",
                "invitationProvenance": {
                    "invitationTransitionId": foreign_tid,
                    "invitedByDid": BOB_DID,
                    "invitedByDeviceId": DEV_B1,
                }
            });
        } else if p["userDid"] == BOB_DID {
            *p = json!({ "userDid": BOB_DID, "status": "active", "role": "admin" });
        }
    }
    bob_body["manifest"]["actorLeaf"] =
        json!({ "userDid": BOB_DID, "deviceId": DEV_B1, "leafOrigin": "genesis" });
    bob_body["metadataSnapshot"]["authorProof"]["authorDid"] = json!(BOB_DID);
    bob_body["metadataSnapshot"]["authorProof"]["authorDeviceId"] = json!(DEV_B1);
    bob_body["metadataSnapshot"]["authorProof"]["authorKeyId"] =
        json!(derive_key_id(bob_signer.public()));
    bob_body["metadataSnapshot"]["authorProof"]["signaturePublicKey"] =
        json!({ "$bytes": STANDARD.encode(bob_signer.public()) });
    let bob_prep = chat_wire::sign_clean_chat_mutation(
        BOB_DID,
        DEV_B1,
        Some(1),
        CanonicalOperation::CreateConversation,
        &bob_body,
        &bob_signer,
    )
    .unwrap();
    let bob_sub: Value = serde_json::from_slice(&bob_prep.body.unwrap()).unwrap();
    let (bob_vbody, bob_digest) = chat_wire::verify_signed_mutation_body_and_digest(
        &bob_sub["signedRequest"],
        SignedMutationKind::Creation,
        bob_signer.public(),
    )
    .unwrap();
    let bob_rcpt = sign_control_receipt(
        &mls_key,
        SEQUENCER_DID,
        CONVO_ID,
        &bob_vbody["next"],
        1,
        foreign_tid,
        BOB_DID,
        DEV_B1,
        &bob_digest,
    );
    let foreign_entry = json!({
        "$type": CREATION_ENTRY_KIND,
        "conversationId": CONVO_ID,
        "seq": 1,
        "entryId": foreign_tid,
        "signedRequest": bob_sub["signedRequest"],
        "sequencerReceipt": bob_rcpt,
    });
    {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.createConversation".to_string(),
            Box::new(|_| http_json(409, &json!({ "error": "IdempotencyConflict" }))),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| {
                http_json(
                    200,
                    &json!({ "state": { "coordinates": { "conversationId": CONVO_ID } } }),
                )
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getEntries".to_string(),
            Box::new(move |_| http_json(200, &json!({ "entries": [foreign_entry] }))),
        ));
    }
    assert!(matches!(
        client.retry_pending_group_creation(CONVO_ID),
        Err(MLSError::GroupCreationRejected { code, .. }) if code == "ForeignConversationCreation"
    ));

    // 60 & 76: Expired attempt + 400 SignedOperationExpired + Absent:
    // resigns (attempts grows from 1 to 2) and second pass succeeds on fresh attempt -> Adopted (#83)!
    save_journal(&base_pending.journal_id, &base_pending);
    {
        let mls_k = mls_key.clone();
        let signer_pub = signer.public().to_vec();
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.createConversation".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let tid = wire["signedRequest"]["body"]["transitionId"]
                    .as_str()
                    .unwrap();
                if tid == op_id {
                    return http_json(400, &json!({ "error": "SignedOperationExpired" }));
                }
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::Creation,
                    &signer_pub,
                )
                .unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k,
                    SEQUENCER_DID,
                    CONVO_ID,
                    &vbody["next"],
                    1,
                    tid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                http_json(
                    200,
                    &json!({
                        "result": {
                            "coordinates": vbody["next"],
                            "entry": {
                                "$type": CREATION_ENTRY_KIND,
                                "conversationId": CONVO_ID,
                                "seq": 1,
                                "entryId": tid,
                                "signedRequest": wire["signedRequest"],
                                "sequencerReceipt": rcpt,
                            }
                        }
                    }),
                )
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| http_json(400, &json!({ "error": "ConversationNotFound" }))),
        ));
    }
    // First retry sees SignedOperationExpired + Absent -> resigns into 2 attempts ("GroupCreationResigned").
    assert!(matches!(
        client.retry_pending_group_creation(CONVO_ID),
        Err(MLSError::GroupCreationPending { last_error_code, .. })
            if last_error_code == "GroupCreationResigned"
    ));
    // Second retry submits the resigned attempt and adopts the conversation (#60, #83)!
    let adopted = client
        .retry_pending_group_creation(CONVO_ID)
        .unwrap()
        .expect("resigned retry must adopt conversation");
    assert_eq!(adopted.conversation_id, CONVO_ID);

    // Also verify #76 negative branch: expired attempt + 503 ServiceUnavailable + Absent -> CreationAttemptsMayStillCommit (NOT resigned).
    let op_id_transient = "66666666-6666-4666-8666-666666666669";
    let (expired_transient, _) = build_journaled_group_creation(
        &client,
        &signer,
        CONVO_ID_2,
        op_id_transient,
        "2026-01-01T00:00:00.000Z",
    );
    save_journal(&expired_transient.journal_id, &expired_transient);
    {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.createConversation".to_string(),
            Box::new(|_| http_json(503, &json!({ "error": "ServiceUnavailable" }))),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| http_json(400, &json!({ "error": "ConversationNotFound" }))),
        ));
    }
    assert!(matches!(
        client.retry_pending_group_creation(CONVO_ID_2),
        Err(MLSError::GroupCreationPending { last_error_code, .. })
            if last_error_code == "CreationAttemptsMayStillCommit"
    ));
    // Cancel expired creation when absent -> returns Ok(true).
    assert!(client.cancel_pending_group_creation(CONVO_ID_2).unwrap());
    assert!(!client.cancel_pending_group_creation(CONVO_ID_2).unwrap());

    drop((dir, dir_b));
}

#[test]
fn live_plane_send_reserve_finish_commit_removal_and_metadata_boundaries() {
    let (transport, state) = PlaneMockTransport::new();
    let (dir, client, signer) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    let (dir_b, bob_client, bob_signer) = new_plane_client(BOB_DID, DEV_B1, transport.clone());
    {
        let mut st = state.lock().unwrap();
        register_pds_device(&mut st, ALICE_DID, DEV_A1, signer.public());
        register_pds_device(&mut st, BOB_DID, DEV_B1, bob_signer.public());
    }
    let (group_id, _coords) =
        seed_active_two_member_group(&client, &signer, &bob_client, &bob_signer, CONVO_ID, 1);
    let convo_uuid = uuid::Uuid::parse_str(CONVO_ID).unwrap();

    // 88-89. reserve_application_send idempotency conflict checks.
    let msg_uuid = uuid::Uuid::parse_str("81818181-8181-4181-8181-818181818181").unwrap();
    let display_json = r#"{"text":"hello"}"#;
    let frame_json = r#"{"messageType":"text","text":"hello","version":1}"#;
    let (_, _, reserved_pending, retry0) = client
        .reserve_application_send(convo_uuid, msg_uuid, DEV_A1, display_json, frame_json)
        .unwrap();
    assert!(!retry0);
    // Same msg_uuid + different display_json -> InvalidInput (#88, #89).
    assert!(client
        .reserve_application_send(
            convo_uuid,
            msg_uuid,
            DEV_A1,
            r#"{"text":"different"}"#,
            frame_json,
        )
        .is_err());
    // Same msg_uuid + different sender_device_id -> InvalidInput (#89).
    assert!(client
        .reserve_application_send(convo_uuid, msg_uuid, DEV_B1, display_json, frame_json)
        .is_err());

    // 90-92. finish_application_send senderDid, senderDeviceId, and generation bindings.
    let mls_key = state.lock().unwrap().authority_mls_keys[SEQUENCER_DID].clone();
    let msg_id_str = msg_uuid.hyphenated().to_string();
    let frame_nonce: [u8; 32] = STANDARD
        .decode(reserved_pending.archive.frame_nonce_b64.as_deref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let commitment = labyrinth_protocol::receipt::compute_archive_commitment(
        &frame_nonce,
        reserved_pending.archive.labyrinth_frame_json.as_bytes(),
    );
    let app_payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_string(),
        conversation_id: CONVO_ID.to_string(),
        group_id: group_id.clone(),
        epoch: reserved_pending.body["prior"]["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!("{ALICE_DID}#{DEV_A1}"),
        entry_id: msg_id_str.clone(),
        archive_commitment: commitment,
        seq: 2,
        issued_at_ms: 1_763_000_000_010,
    };
    let signed_app = sign_sequencer_receipt(
        &mls_key,
        &format!("{SEQUENCER_DID}#mls-receipt-1"),
        &app_payload,
    )
    .unwrap();
    let app_receipt = json!({
        "kid": signed_app.key_id,
        "sequencerDid": SEQUENCER_DID,
        "conversationId": CONVO_ID,
        "generation": 0,
        "groupId": { "$bytes": STANDARD.encode(&group_id) },
        "epoch": reserved_pending.body["prior"]["epoch"],
        "seq": 2,
        "entryId": msg_id_str,
        "senderDid": ALICE_DID,
        "senderDeviceId": DEV_A1,
        "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
        "issuedAtMs": 1_763_000_000_010i64,
        "signature": { "$bytes": STANDARD.encode(signed_app.signature) },
    });

    let clone_pending = |p: &PendingApplicationSend| -> PendingApplicationSend {
        serde_json::from_str(&serde_json::to_string(p).unwrap()).unwrap()
    };
    let mut bad_did = clone_pending(&reserved_pending);
    bad_did.archive.sender_did = BOB_DID.to_string();
    assert!(client
        .finish_application_send(bad_did, &app_receipt, &msg_id_str, None, false)
        .is_err());

    let mut bad_dev = clone_pending(&reserved_pending);
    bad_dev.archive.sender_device_id = DEV_B1.to_string();
    assert!(client
        .finish_application_send(bad_dev, &app_receipt, &msg_id_str, None, false)
        .is_err());

    let mut bad_gen = clone_pending(&reserved_pending);
    bad_gen.body["prior"]["generation"] = json!(99);
    assert!(client
        .finish_application_send(bad_gen, &app_receipt, &msg_id_str, None, false)
        .is_err());

    let (finished_row, gap) = client
        .finish_application_send(reserved_pending, &app_receipt, &msg_id_str, None, false)
        .unwrap();
    assert_eq!(finished_row.message_id, msg_id_str);
    assert!(!gap);

    // 85-87. send_message_live stale-coordinates retry + stale-send watermark vs non-stale refusal.
    let counter_key = chat_wire::send_counter_key(CONVO_ID);
    let baseline_counter = client
        .db
        .read_tx(|tx| tx.get_account_meta(&counter_key))
        .unwrap()
        .unwrap_or_else(|| "0".into());

    // Subcase A (#86): StaleCoordinates then terminal NotParticipant -> watermark does NOT advance.
    {
        let calls = Arc::new(Mutex::new(0usize));
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.sendMessage".to_string(),
            Box::new(move |_| {
                let mut n = calls.lock().unwrap();
                *n += 1;
                if *n == 1 {
                    http_json(409, &json!({ "error": "StaleCoordinates" }))
                } else {
                    http_json(403, &json!({ "error": "NotParticipant" }))
                }
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getEntries".to_string(),
            Box::new(|_| http_json(200, &json!({ "entries": [] }))),
        ));
    }
    assert!(client
        .send_message_live(CONVO_ID, "82828282-8282-4282-8282-828282828282", "retry-a",)
        .is_err());
    let after_non_stale = client
        .db
        .read_tx(|tx| tx.get_account_meta(&counter_key))
        .unwrap()
        .unwrap_or_else(|| "0".into());
    assert_eq!(after_non_stale, baseline_counter);

    // Subcase B (#87): StaleCoordinates then StaleSend -> watermark DOES advance!
    {
        let calls = Arc::new(Mutex::new(0usize));
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.sendMessage".to_string(),
            Box::new(move |_| {
                let mut n = calls.lock().unwrap();
                *n += 1;
                if *n == 1 {
                    http_json(409, &json!({ "error": "StaleCoordinates" }))
                } else {
                    http_json(409, &json!({ "error": "StaleSend" }))
                }
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getEntries".to_string(),
            Box::new(|_| http_json(200, &json!({ "entries": [] }))),
        ));
    }
    assert!(client
        .send_message_live(CONVO_ID, "83838383-8383-4383-8383-838383838383", "retry-b",)
        .is_err());
    let after_stale_send = client
        .db
        .read_tx(|tx| tx.get_account_meta(&counter_key))
        .unwrap()
        .unwrap();
    assert_ne!(after_stale_send, baseline_counter);
    assert_eq!(after_stale_send, "2");

    // Subcase C (#85): StaleCoordinates then 200 valid I13 receipt -> succeeds!
    let msg_c = "84848484-8484-4484-8484-848484848484";
    {
        let calls = Arc::new(Mutex::new(0usize));
        let mls_k = mls_key.clone();
        let gid = group_id.clone();
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.sendMessage".to_string(),
            Box::new(move |req| {
                let mut n = calls.lock().unwrap();
                *n += 1;
                if *n == 1 {
                    return http_json(409, &json!({ "error": "StaleCoordinates" }));
                }
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let body = &wire["signedRequest"]["body"];
                let comm: [u8; 32] = chat_wire::json_bytes(&body["aad"]["archiveCommitment"])
                    .unwrap()
                    .try_into()
                    .unwrap();
                let epoch = body["prior"]["epoch"].as_u64().unwrap();
                let payload = SequencerReceiptPayload {
                    sequencer_did: SEQUENCER_DID.to_string(),
                    conversation_id: CONVO_ID.to_string(),
                    group_id: gid.clone(),
                    epoch,
                    sender_device_did_url: format!("{ALICE_DID}#{DEV_A1}"),
                    entry_id: msg_c.to_string(),
                    archive_commitment: comm,
                    seq: 3,
                    issued_at_ms: 1_763_000_000_020,
                };
                let signed = sign_sequencer_receipt(
                    &mls_k,
                    &format!("{SEQUENCER_DID}#mls-receipt-1"),
                    &payload,
                )
                .unwrap();
                http_json(
                    200,
                    &json!({
                        "sequencerReceipt": {
                            "kid": signed.key_id,
                            "sequencerDid": SEQUENCER_DID,
                            "conversationId": CONVO_ID,
                            "generation": 0,
                            "groupId": { "$bytes": STANDARD.encode(&gid) },
                            "epoch": epoch,
                            "seq": 3,
                            "entryId": msg_c,
                            "senderDid": ALICE_DID,
                            "senderDeviceId": DEV_A1,
                            "archiveCommitment": { "$bytes": STANDARD.encode(comm) },
                            "issuedAtMs": 1_763_000_000_020i64,
                            "signature": { "$bytes": STANDARD.encode(signed.signature) },
                        }
                    }),
                )
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getEntries".to_string(),
            Box::new(|_| http_json(200, &json!({ "entries": [] }))),
        ));
    }
    let sent_row = client
        .send_message_live(CONVO_ID, msg_c, "retry-c")
        .unwrap();
    assert_eq!(sent_row.seq, 3);

    // 105-107. update_group_metadata_live_or_offline contiguous vs behind-cursor vs gap.
    // Case 1: auth_seq == last_seq + 1 (4) -> advances last_seq to 4 without calling getEntries (#105).
    let install_meta_echo = |echo_seq: u64, register_entries: bool| {
        let mls_k = mls_key.clone();
        let pub_k = signer.public().to_vec();
        let mut st = state.lock().unwrap();
        st.seen_urls.clear();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.submitTransition".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::MetadataTransition,
                    &pub_k,
                )
                .unwrap();
                let tid = vbody["transitionId"].as_str().unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k,
                    SEQUENCER_DID,
                    CONVO_ID,
                    &vbody["next"],
                    echo_seq,
                    tid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                http_json(
                    200,
                    &json!({
                        "coordinates": vbody["next"],
                        "entry": {
                            "$type": METADATA_ENTRY_KIND,
                            "conversationId": CONVO_ID,
                            "seq": echo_seq,
                            "entryId": tid,
                            "signedRequest": wire["signedRequest"],
                            "sequencerReceipt": rcpt,
                        }
                    }),
                )
            }),
        ));
        if register_entries {
            st.route_handlers.push((
                "/xrpc/blue.catbird.chat.getEntries".to_string(),
                Box::new(|_| http_json(200, &json!({ "entries": [] }))),
            ));
        }
    };
    install_meta_echo(4, false);
    client
        .update_group_metadata_live_or_offline(CONVO_ID, "Title 4".into(), "Desc 4".into(), None)
        .unwrap();
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_conversation(CONVO_ID))
            .unwrap()
            .unwrap()
            .last_seq,
        4
    );
    assert!(!state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("getEntries")));

    // Case 2: auth_seq < last_seq + 1 (last_seq = 6, echo_seq = 5) -> keeps last_seq == 6, no getEntries (#105, #106).
    client
        .db
        .write_tx(|tx| {
            let mut c = tx.get_conversation(CONVO_ID)?.unwrap();
            c.last_seq = 6;
            tx.upsert_conversation(&c)
        })
        .unwrap();
    install_meta_echo(5, false);
    client
        .update_group_metadata_live_or_offline(CONVO_ID, "Title 5".into(), "Desc 5".into(), None)
        .unwrap();
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_conversation(CONVO_ID))
            .unwrap()
            .unwrap()
            .last_seq,
        6
    );

    // Case 3: auth_seq > last_seq + 1 (last_seq = 6, echo_seq = 9) -> triggers getEntries (#107).
    install_meta_echo(9, true);
    client
        .update_group_metadata_live_or_offline(CONVO_ID, "Title 9".into(), "Desc 9".into(), None)
        .unwrap();
    assert!(state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("getEntries")));

    // 96-104. complete_participant_removals while BOB still holds a leaf:
    // (a) journaled commit_transition == 1 -> keeps intent (#96, #97).
    let rem_key = participant_removal_key(CONVO_ID, BOB_DID);
    let rem_payload = participant_removal_payload(CONVO_ID, BOB_DID);
    let now_ms = client.hooks.now_ms();
    client
        .db
        .write_tx(|tx| {
            tx.put_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key, &rem_payload, now_ms)?;
            tx.put_pending_op(
                "commit_transition",
                "dummy-ct-1",
                &json!({ "conversation_id": CONVO_ID }).to_string(),
                now_ms,
            )
        })
        .unwrap();
    assert!(!client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .unwrap());
    assert!(client
        .db
        .read_tx(|tx| tx.get_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key))
        .unwrap()
        .is_some());

    // (b) journaled commit_transition == 0 while BOB still holds leaf -> forgets intent (#98)!
    client
        .db
        .write_tx(|tx| tx.delete_pending_op("commit_transition", "dummy-ct-1"))
        .unwrap();
    assert!(!client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .unwrap());
    assert!(client
        .db
        .read_tx(|tx| tx.get_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key))
        .unwrap()
        .is_none());

    // 94-95. commit_generic_transition(RemoveLeaves { BOB_DID }) at auth_seq == last_seq + 1 (7):
    // merges immediately (no getEntries needed), advances epoch & last_seq to 7, and queues PARTICIPANT_REMOVAL_OP!
    {
        let mls_k = mls_key.clone();
        let pub_k = signer.public().to_vec();
        let mut st = state.lock().unwrap();
        st.seen_urls.clear();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.submitTransition".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::CommitTransition,
                    &pub_k,
                )
                .unwrap();
                let tid = vbody["transitionId"].as_str().unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k,
                    SEQUENCER_DID,
                    CONVO_ID,
                    &vbody["next"],
                    7,
                    tid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                http_json(
                    200,
                    &json!({
                        "coordinates": vbody["next"],
                        "entry": {
                            "$type": COMMIT_ENTRY_KIND,
                            "conversationId": CONVO_ID,
                            "seq": 7,
                            "entryId": tid,
                            "signedRequest": wire["signedRequest"],
                            "sequencerReceipt": rcpt,
                        }
                    }),
                )
            }),
        ));
    }
    assert!(client
        .commit_generic_transition(
            CONVO_ID,
            DEV_A1,
            &convo_uuid,
            GenericCommitOp::RemoveLeaves {
                target_did: BOB_DID
            },
        )
        .unwrap());
    let after_commit = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    assert_eq!(after_commit.last_seq, 7);
    assert_eq!(after_commit.epoch, 2);

    // Also test commit_generic_transition SelfUpdate when auth_seq <= last_seq (last_seq = 10, echo_seq = 9):
    // keeps last_seq == 10 (#95 negative direction)!
    client
        .db
        .write_tx(|tx| {
            let mut c = tx.get_conversation(CONVO_ID)?.unwrap();
            c.last_seq = 10;
            tx.upsert_conversation(&c)
        })
        .unwrap();
    {
        let mls_k = mls_key.clone();
        let pub_k = signer.public().to_vec();
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.submitTransition".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::CommitTransition,
                    &pub_k,
                )
                .unwrap();
                let tid = vbody["transitionId"].as_str().unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k,
                    SEQUENCER_DID,
                    CONVO_ID,
                    &vbody["next"],
                    9,
                    tid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                http_json(
                    200,
                    &json!({
                        "coordinates": vbody["next"],
                        "entry": {
                            "$type": COMMIT_ENTRY_KIND,
                            "conversationId": CONVO_ID,
                            "seq": 9,
                            "entryId": tid,
                            "signedRequest": wire["signedRequest"],
                            "sequencerReceipt": rcpt,
                        }
                    }),
                )
            }),
        ));
    }
    assert!(client
        .commit_generic_transition(CONVO_ID, DEV_A1, &convo_uuid, GenericCommitOp::SelfUpdate)
        .unwrap());
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_conversation(CONVO_ID))
            .unwrap()
            .unwrap()
            .last_seq,
        10
    );

    // Now BOB has 0 leaves in the local group! Test #99..#104 in complete_participant_removals:
    let cur_coords = client.local_coordinates(CONVO_ID).unwrap().unwrap();
    let reinsert_rem = || {
        client
            .db
            .write_tx(|tx| {
                tx.put_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key, &rem_payload, now_ms)
            })
            .unwrap();
    };

    // #99 & #101: getConversationState -> 400 ConversationNotFound forgets intent and returns Ok(false).
    reinsert_rem();
    {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| http_json(400, &json!({ "error": "ConversationNotFound" }))),
        ));
    }
    assert!(!client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .unwrap());
    assert!(client
        .db
        .read_tx(|tx| tx.get_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key))
        .unwrap()
        .is_none());

    // #100 & #101: getConversationState -> 403 NotParticipant returns Err and keeps intent.
    reinsert_rem();
    {
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(|_| http_json(403, &json!({ "error": "NotParticipant" }))),
        ));
    }
    assert!(client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .is_err());
    assert!(client
        .db
        .read_tx(|tx| tx.get_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key))
        .unwrap()
        .is_some());

    // #102: participant leafCount == 1 -> skips submitTransition and keeps intent.
    {
        let c_coords = cur_coords.clone();
        let mut st = state.lock().unwrap();
        st.seen_urls.clear();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(move |_| {
                http_json(
                    200,
                    &json!({
                        "state": {
                            "coordinates": c_coords,
                            "participants": [
                                { "userDid": ALICE_DID, "role": "admin", "status": "active", "leafCount": 1 },
                                { "userDid": BOB_DID, "role": "member", "status": "active", "leafCount": 1 },
                            ]
                        }
                    }),
                )
            }),
        ));
    }
    assert!(!client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .unwrap());
    assert!(!state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("submitTransition")));

    // #103a: leafCount == 0, submitTransition -> 409 StaleCoordinates keeps intent and returns Ok(false).
    let set_zero_leaf_state = |submit_handler: RouteHandler| {
        let c_coords = cur_coords.clone();
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(move |_| {
                http_json(
                    200,
                    &json!({
                        "state": {
                            "coordinates": c_coords,
                            "participants": [
                                { "userDid": ALICE_DID, "role": "admin", "status": "active", "leafCount": 1 },
                                { "userDid": BOB_DID, "role": "member", "status": "active", "leafCount": 0 },
                            ]
                        }
                    }),
                )
            }),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.submitTransition".to_string(),
            submit_handler,
        ));
    };
    set_zero_leaf_state(Box::new(|_| {
        http_json(409, &json!({ "error": "StaleCoordinates" }))
    }));
    assert!(!client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .unwrap());
    assert!(client
        .db
        .read_tx(|tx| tx.get_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key))
        .unwrap()
        .is_some());

    // #103b: submitTransition -> 403 NotAdmin forgets intent and returns Err.
    set_zero_leaf_state(Box::new(|_| {
        http_json(403, &json!({ "error": "NotAdmin" }))
    }));
    assert!(client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .is_err());
    assert!(client
        .db
        .read_tx(|tx| tx.get_pending_op(PARTICIPANT_REMOVAL_OP, &rem_key))
        .unwrap()
        .is_none());

    // #104: submitTransition echoes new_seq == c.last_seq (10) -> returns Ok(false) (NOT gap=true)!
    reinsert_rem();
    {
        let mls_k = mls_key.clone();
        let pub_k = signer.public().to_vec();
        set_zero_leaf_state(Box::new(move |req| {
            let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
            let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                &wire["signedRequest"],
                SignedMutationKind::PolicyTransition,
                &pub_k,
            )
            .unwrap();
            let tid = vbody["transitionId"].as_str().unwrap();
            let rcpt = sign_control_receipt(
                &mls_k,
                SEQUENCER_DID,
                CONVO_ID,
                &vbody["next"],
                10,
                tid,
                ALICE_DID,
                DEV_A1,
                &digest,
            );
            http_json(
                200,
                &json!({
                    "coordinates": vbody["next"],
                    "entry": {
                        "$type": POLICY_ENTRY_KIND,
                        "conversationId": CONVO_ID,
                        "seq": 10,
                        "entryId": tid,
                        "signedRequest": wire["signedRequest"],
                        "sequencerReceipt": rcpt,
                    }
                }),
            )
        }));
    }
    assert!(!client
        .complete_participant_removals(CONVO_ID, DEV_A1, &signer)
        .unwrap());

    drop((dir, dir_b));
}

#[test]
fn live_plane_direct_request_consent_close_and_reset_boundaries() {
    let (transport, state) = PlaneMockTransport::new();
    let (dir, client, signer) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    let (dir_b, bob_client, bob_signer) = new_plane_client(BOB_DID, DEV_B1, transport.clone());
    {
        let mut st = state.lock().unwrap();
        register_pds_device(&mut st, ALICE_DID, DEV_A1, signer.public());
        register_pds_device(&mut st, BOB_DID, DEV_B1, bob_signer.public());
    }
    let (_gid, coords) =
        seed_active_two_member_group(&client, &signer, &bob_client, &bob_signer, CONVO_ID, 1);
    let now_ms = client.hooks.now_ms();

    // 111. verify_direct_request_acceptance requestId and prior bindings.
    let fixture: Value = serde_json::from_str(include_str!(
        "../chat_v2/transcript/vectors/direct_request_vectors.json"
    ))
    .unwrap();
    let mut consent_body = fixture["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "Accept")
        .unwrap()["body"]
        .clone();
    consent_body["actorDid"] = json!(ALICE_DID);
    consent_body["actorDeviceId"] = json!(DEV_A1);
    consent_body["keyId"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public())));
    let mut bare_prior = coords.clone();
    for field in ["groupId", "groupContextHash", "confirmationTag"] {
        bare_prior[field] = json!(coords[field]["$bytes"].as_str().unwrap());
    }
    let mut bare_next = bare_prior.clone();
    bare_next["stateVersion"] = json!(bare_prior["stateVersion"].as_u64().unwrap() + 1);
    let req_id_v = "91919191-9191-4191-8191-919191919191";
    consent_body["requestId"] = json!(req_id_v);
    consent_body["transitionId"] = json!(req_id_v);
    consent_body["idempotencyKey"] = json!(req_id_v);
    consent_body["prior"] = bare_prior.clone();
    consent_body["next"] = bare_next.clone();
    let accept_wrapper_bytes = chat_wire::sign_direct_request_wrapper(
        DirectRequestKind::Accept,
        consent_body.clone(),
        &signer,
    )
    .unwrap();
    let accept_wrapper: Value = serde_json::from_slice(&accept_wrapper_bytes).unwrap();
    let checked_accept = dr_transcript::verify_signed_request(
        DirectRequestKind::Accept,
        &accept_wrapper_bytes,
        signer.public(),
    )
    .unwrap();
    let legacy_entry = json!({
        "entryId": req_id_v,
        "conversationId": CONVO_ID,
        "seq": 2,
        "signedRequest": accept_wrapper,
        "receivedAt": "2026-11-15T12:00:00.000Z",
    });
    let (mls_key, dr_key) = {
        let st = state.lock().unwrap();
        (
            st.authority_mls_keys[SEQUENCER_DID].clone(),
            st.authority_dr_keys[SEQUENCER_DID].clone(),
        )
    };
    let dr_sec1 = sec1_bytes(&dr_key);
    let mut commit_body = fixture["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "AcceptanceCommit")
        .unwrap()["body"]
        .clone();
    commit_body["authorityDid"] = json!(SEQUENCER_DID);
    commit_body["keyId"] = json!(dr_transcript::direct_request_receipt_key_id_for_authority(
        SEQUENCER_DID,
        &dr_sec1
    )
    .unwrap());
    commit_body["requestId"] = json!(req_id_v);
    commit_body["prior"] = bare_prior.clone();
    commit_body["next"] = bare_next.clone();
    commit_body["acceptanceDigest"] = json!(STANDARD.encode(checked_accept.request_digest()));
    commit_body["entryHash"] = json!(STANDARD.encode(
        dr_transcript::direct_request_acceptance_entry_hash(
            &serde_json::to_vec(&legacy_entry).unwrap()
        )
        .unwrap()
    ));
    let commit_signing = dr_transcript::direct_request_signing_bytes(
        DirectRequestKind::AcceptanceCommit,
        &serde_json::to_vec(&commit_body).unwrap(),
    )
    .unwrap();
    let commit_sig: p256::ecdsa::Signature = dr_key.sign(&commit_signing);
    let commit_sig = commit_sig.normalize_s().unwrap_or(commit_sig);
    let signed_commit_rcpt = json!({
        "body": commit_body,
        "signature": STANDARD.encode(commit_sig.to_bytes()),
    });
    let mut next_wire = coords.clone();
    next_wire["stateVersion"] = bare_next["stateVersion"].clone();
    let ctrl_rcpt = sign_control_receipt(
        &mls_key,
        SEQUENCER_DID,
        CONVO_ID,
        &next_wire,
        2,
        req_id_v,
        ALICE_DID,
        DEV_A1,
        checked_accept.request_digest(),
    );
    let mut entry_with_rcpt = legacy_entry;
    entry_with_rcpt["sequencerReceipt"] = ctrl_rcpt;
    let answer_bytes = serde_json::to_vec(&json!({
        "acceptanceProof": {
            "entry": entry_with_rcpt,
            "receipt": signed_commit_rcpt,
        }
    }))
    .unwrap();
    let valid_pub = json!({
        "requestId": req_id_v,
        "next": bare_prior,
    });
    let (v_seq, _) = client
        .verify_direct_request_acceptance(CONVO_ID, &answer_bytes, signer.public(), &valid_pub)
        .unwrap();
    assert_eq!(v_seq, 2);

    let mut wrong_req_pub = valid_pub.clone();
    wrong_req_pub["requestId"] = json!("92929292-9292-4292-8292-929292929292");
    assert!(client
        .verify_direct_request_acceptance(CONVO_ID, &answer_bytes, signer.public(), &wrong_req_pub)
        .is_err());

    let mut wrong_prior_pub = valid_pub;
    wrong_prior_pub["next"]["stateVersion"] = json!(99);
    assert!(client
        .verify_direct_request_acceptance(
            CONVO_ID,
            &answer_bytes,
            signer.public(),
            &wrong_prior_pub,
        )
        .is_err());

    // 112-113. archive_accepted_opening_messages enqueues once and skips once marked "archived".
    let staged_opening = QueuedLabyrinthArchivePayload {
        version: 1,
        conversation_id: CONVO_ID.to_string(),
        group_id_hex: hex::encode([0x61u8; 32]),
        expected_member_dids: vec![ALICE_DID.to_string(), BOB_DID.to_string()],
        sequencer_did: SEQUENCER_DID.to_string(),
        space_uri: None,
        message_id: "93939393-9393-4393-8393-939393939393".to_string(),
        epoch: 1,
        seq: 1,
        sender_did: ALICE_DID.to_string(),
        sender_device_id: DEV_A1.to_string(),
        plaintext_json: r#"{"text":"hi"}"#.to_string(),
        labyrinth_frame_json: r#"{"messageType":"text","text":"hi","version":1}"#.to_string(),
        mls_ciphertext_b64: String::new(),
        created_at_ms: now_ms,
        frame_nonce_b64: None,
        sequencer_receipt_json: None,
        original_sender_attestation_json: None,
    };
    let opening_key = format!("c33_pending_opening:{CONVO_ID}");
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &opening_key,
                &serde_json::to_string(&staged_opening).unwrap(),
                now_ms,
            )
        })
        .unwrap();
    client.archive_accepted_opening_messages(CONVO_ID).unwrap();
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_account_meta(&opening_key))
            .unwrap()
            .as_deref(),
        Some("archived")
    );
    let queued_count: i64 = client
        .db
        .read_tx(|tx| {
            Ok(tx
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM labyrinth_queue WHERE item_id = ?1",
                    [&staged_opening.message_id],
                    |r| r.get(0),
                )
                .unwrap())
        })
        .unwrap();
    assert_eq!(queued_count, 1);
    // Second call sees "archived" and returns Ok(()) without parse failure (#113).
    client.archive_accepted_opening_messages(CONVO_ID).unwrap();

    // 110 & 114-120. accept & decline request matching + offline/non-UUID/uninitialized guards.
    let mk_req = |rid: &str, cid: &str, updated: i64| RequestRow {
        request_id: rid.to_string(),
        conversation_id: cid.to_string(),
        sender_did: BOB_DID.to_string(),
        recipient_did: ALICE_DID.to_string(),
        consent: "pending".to_string(),
        first_message_id: None,
        first_message_archived: false,
        payload_json: "{}".to_string(),
        expires_at_ms: updated + 86_400_000,
        updated_at_ms: updated,
    };
    client
        .db
        .write_tx(|tx| {
            tx.upsert_request(&mk_req("req-first", "offline-convo-first", now_ms + 10))?;
            tx.upsert_request(&mk_req("req-second", "offline-convo-second", now_ms + 5))?;
            Ok(())
        })
        .unwrap();
    // Accept by conversation_id when 2 rows exist -> ONLY second becomes "accepted" (#110).
    client
        .accept_direct_request_live_or_offline("offline-convo-second")
        .unwrap();
    let reqs_after_accept = client.db.read_tx(|tx| tx.list_requests(None)).unwrap();
    assert_eq!(
        reqs_after_accept
            .iter()
            .find(|r| r.request_id == "req-first")
            .unwrap()
            .consent,
        "pending"
    );
    assert_eq!(
        reqs_after_accept
            .iter()
            .find(|r| r.request_id == "req-second")
            .unwrap()
            .consent,
        "accepted"
    );

    // Decline with 2 pending rows (Row A has live CONVO_ID + coords; Row B has UUIDv4 without coords/convo):
    // declining Row B MUST NOT close CONVO_ID (#114, #117) and MUST mark ONLY Row B "declined" (#118, #119, #120)!
    let unseeded_uuid = "94949494-9494-4494-8494-949494949494";
    client
        .db
        .write_tx(|tx| {
            tx.conn().execute("DELETE FROM requests", []).unwrap();
            tx.upsert_request(&mk_req("req-live-a", CONVO_ID, now_ms + 20))?;
            tx.upsert_request(&mk_req("req-unseeded-b", unseeded_uuid, now_ms + 10))?;
            Ok(())
        })
        .unwrap();
    client
        .decline_direct_request_live_or_offline("req-unseeded-b")
        .unwrap();
    assert!(!client.is_conversation_closed(CONVO_ID).unwrap());
    let reqs_after_decline = client.db.read_tx(|tx| tx.list_requests(None)).unwrap();
    assert_eq!(
        reqs_after_decline
            .iter()
            .find(|r| r.request_id == "req-live-a")
            .unwrap()
            .consent,
        "pending"
    );
    assert_eq!(
        reqs_after_decline
            .iter()
            .find(|r| r.request_id == "req-unseeded-b")
            .unwrap()
            .consent,
        "declined"
    );
    // Also decline by conversation_id (#119).
    let unseeded_uuid_2 = "95959595-9595-4595-8595-959595959595";
    client
        .db
        .write_tx(|tx| tx.upsert_request(&mk_req("req-unseeded-c", unseeded_uuid_2, now_ms + 5)))
        .unwrap();
    client
        .decline_direct_request_live_or_offline(unseeded_uuid_2)
        .unwrap();
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.list_requests(None))
            .unwrap()
            .iter()
            .find(|r| r.request_id == "req-unseeded-c")
            .unwrap()
            .consent,
        "declined"
    );

    // #115: non-UUID device_id client declining UUIDv4 request MUST NOT mark conversation closed.
    let (leg_dir, leg_client, _) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    leg_client
        .db
        .write_tx(|tx| {
            tx.put_account_meta("enrolled_device_id", "legacy-dev", now_ms)?;
            tx.upsert_request(&mk_req("req-leg", CONVO_ID_2, now_ms))
        })
        .unwrap();
    leg_client
        .decline_direct_request_live_or_offline("req-leg")
        .unwrap();
    assert!(!leg_client.is_conversation_closed(CONVO_ID_2).unwrap());

    // #116: UUIDv4 device_id client WITHOUT enrolled_signer_json declining UUIDv4 request MUST succeed offline.
    let (no_sig_dir, no_sig_client, _) = new_plane_client(ALICE_DID, DEV_A1, transport.clone());
    no_sig_client
        .db
        .write_tx(|tx| {
            tx.delete_account_meta("enrolled_signer_json")?;
            tx.upsert_request(&mk_req("req-nosig", CONVO_ID_2, now_ms))
        })
        .unwrap();
    no_sig_client
        .decline_direct_request_live_or_offline("req-nosig")
        .unwrap();

    // 121-125. is_conversation_closed, offline close_conversation, and complete_pending_closes.
    client
        .db
        .write_tx(|tx| tx.put_account_meta("conversation_closed:flag-check", "false", now_ms))
        .unwrap();
    assert!(!client.is_conversation_closed("flag-check").unwrap());
    client
        .db
        .write_tx(|tx| tx.put_account_meta("conversation_closed:flag-check", "true", now_ms))
        .unwrap();
    assert!(client.is_conversation_closed("flag-check").unwrap());

    // Offline close_conversation (#122, #123):
    assert!(matches!(
        client.close_conversation("missing-offline-id"),
        Err(MLSError::GroupNotFound { .. })
    ));
    // Direct request only (no ConversationRow) -> succeeds!
    client
        .db
        .write_tx(|tx| tx.upsert_request(&mk_req("req-close-only", "direct-offline-id", now_ms)))
        .unwrap();
    client.close_conversation("direct-offline-id").unwrap();
    assert!(client.is_conversation_closed("direct-offline-id").unwrap());
    // ConversationRow only (no RequestRow) -> succeeds!
    client
        .db
        .write_tx(|tx| {
            tx.upsert_conversation(&ConversationRow {
                conversation_id: "convo-offline-id".into(),
                group_id: vec![0x44; 32],
                generation: 0,
                epoch: 0,
                last_seq: 0,
                sequencer_did: SEQUENCER_DID.into(),
                space_uri: None,
                title: None,
                unread_count: 0,
                updated_at_ms: now_ms,
            })
        })
        .unwrap();
    client.close_conversation("convo-offline-id").unwrap();
    assert!(client.is_conversation_closed("convo-offline-id").unwrap());

    // complete_pending_closes (#124, #125): 1 journaled close replayed to 200 -> closed == 1!
    let close_cid = "96969696-9696-4696-8696-969696969696";
    let (_, close_coords) =
        seed_active_two_member_group(&client, &signer, &bob_client, &bob_signer, close_cid, 1);
    let mut close_retired = close_coords.clone();
    close_retired["stateVersion"] = json!(2);
    close_retired["lifecycle"] = json!("superseded");
    let close_tid = "97979797-9797-4797-8797-979797979797";
    let close_body = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseBody",
        "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
        "transitionId": close_tid,
        "idempotencyKey": close_tid,
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "keyId": derive_key_id(signer.public()),
        "authGeneration": 1,
        "conversationKind": "group",
        "prior": close_coords,
        "retired": close_retired,
        "signedAt": client.hooks.now_rfc3339_millis(),
    });
    let close_prep = chat_wire::sign_clean_chat_mutation(
        ALICE_DID,
        DEV_A1,
        Some(1),
        CanonicalOperation::CloseConversation,
        &close_body,
        &signer,
    )
    .unwrap();
    let close_wire: Value = serde_json::from_slice(&close_prep.body.unwrap()).unwrap();
    let close_raw = serde_json::to_string(&close_wire["signedRequest"]).unwrap();
    client
        .db
        .write_tx(|tx| tx.put_pending_op(CONVERSATION_CLOSE_OP, close_cid, &close_raw, now_ms))
        .unwrap();
    {
        let mls_k = mls_key.clone();
        let pub_k = signer.public().to_vec();
        let mut st = state.lock().unwrap();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.closeConversation".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::ConversationClose,
                    &pub_k,
                )
                .unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k,
                    SEQUENCER_DID,
                    close_cid,
                    &vbody["retired"],
                    2,
                    close_tid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                http_json(
                    200,
                    &json!({
                        "entry": {
                            "$type": CONVERSATION_CLOSE_ENTRY_KIND,
                            "conversationId": close_cid,
                            "seq": 2,
                            "entryId": close_tid,
                            "signedRequest": wire["signedRequest"],
                            "sequencerReceipt": rcpt,
                        }
                    }),
                )
            }),
        ));
    }
    let (closed_cnt, close_failures) = client.complete_pending_closes().unwrap();
    assert_eq!(closed_cnt, 1);
    assert!(close_failures.is_empty());

    // 126-131. reset_conversation pending reset verification, tail check, and activation coordinate checks.
    // Seed fresh conversation CONVO_ID_2 at seq 1 with only ALICE_DID active admin so sync is trivial.
    let reset_gid = vec![0x52u8; 32];
    let reset_uuid = uuid::Uuid::parse_str(CONVO_ID_2).unwrap();
    let (_, reset_gch, reset_ctag, reset_snap, reset_kv) = client
        .db
        .read_tx(|tx| {
            client.stage_genesis_group(
                tx,
                &signer,
                1,
                DEV_A1,
                &reset_uuid,
                &reset_gid,
                0,
                "98989898-9898-4898-8898-989898989891",
                1,
                1,
                "Resettable",
                "",
            )
        })
        .unwrap();
    let reset_prior = chat_wire::canonicalize_wire_coordinate(
        &json!({
            "conversationId": CONVO_ID_2,
            "generation": 0,
            "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(&reset_gid) },
            "epoch": 0,
            "groupContextHash": { "$bytes": STANDARD.encode(reset_gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(reset_ctag) },
            "lifecycle": "active",
        }),
        None,
    )
    .unwrap();
    client
        .db
        .write_tx(|tx| {
            reset_kv.apply(&RusqliteKvBackend(tx.conn()))?;
            tx.upsert_conversation(&ConversationRow {
                conversation_id: CONVO_ID_2.into(),
                group_id: reset_gid.clone(),
                generation: 0,
                epoch: 0,
                last_seq: 1,
                sequencer_did: SEQUENCER_DID.into(),
                space_uri: None,
                title: Some("Resettable".into()),
                unread_count: 0,
                updated_at_ms: now_ms,
            })?;
            tx.put_account_meta(
                &format!("conversation_coords:{CONVO_ID_2}"),
                &serde_json::to_string(&reset_prior)?,
                now_ms,
            )?;
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{CONVO_ID_2}"),
                &serde_json::to_string(&reset_snap)?,
                now_ms,
            )?;
            tx.put_account_meta(
                &chat_wire::conversation_roster_key(CONVO_ID_2),
                &serde_json::to_string(&json!({
                    ALICE_DID: { "role": "admin", "status": "active" }
                }))?,
                now_ms,
            )
        })
        .unwrap();

    let state_view = json!({
        "state": {
            "conversationKind": "group",
            "coordinates": reset_prior,
            "participants": [{
                "userDid": ALICE_DID,
                "role": "admin",
                "status": "active",
            }],
            "metadataSnapshot": reset_snap,
        }
    });

    // Helper installing reset mock handlers with configurable tail behavior and activation tamper.
    #[derive(Clone, Copy)]
    enum ResetMode {
        MissingFromTail,
        TailAdvancesPastRequest,
        TamperRetired,
        TamperSuccessor,
    }
    let install_reset_handlers = |mode: ResetMode| {
        let mls_k = mls_key.clone();
        let pub_k = signer.public().to_vec();
        let sv = state_view.clone();
        let prior_c = reset_prior.clone();
        let last_req_entry: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
        let last_req_entry_get = last_req_entry.clone();
        let get_calls = Arc::new(Mutex::new(0usize));
        let mut st = state.lock().unwrap();
        st.seen_urls.clear();
        st.route_handlers.clear();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getConversationState".to_string(),
            Box::new(move |_| http_json(200, &sv)),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.acknowledgeEntries".to_string(),
            Box::new(|_| http_json(200, &json!({}))),
        ));
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.requestReset".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::ResetRequest,
                    &pub_k,
                )
                .unwrap();
                let rid = vbody["resetRequestId"].as_str().unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k,
                    SEQUENCER_DID,
                    CONVO_ID_2,
                    &vbody["prior"],
                    2,
                    rid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                let entry = json!({
                    "$type": crate::chat_v2::wire::RESET_REQUEST_ENTRY_KIND,
                    "conversationId": CONVO_ID_2,
                    "seq": 2,
                    "entryId": rid,
                    "signedRequest": wire["signedRequest"],
                    "sequencerReceipt": rcpt,
                });
                *last_req_entry.lock().unwrap() = Some(entry.clone());
                http_json(200, &json!({ "entry": entry }))
            }),
        ));
        let mls_k_get = mls_key.clone();
        let reset_gid_get = reset_gid.clone();
        let signer_clone =
            serde_json::from_str::<SignatureKeyPair>(&serde_json::to_string(&signer).unwrap())
                .unwrap();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.getEntries".to_string(),
            Box::new(move |req| {
                let mut n = get_calls.lock().unwrap();
                *n += 1;
                if req.url.contains("afterSeq=1") {
                    if let Some(req_entry) = last_req_entry_get.lock().unwrap().clone() {
                        return match mode {
                            ResetMode::MissingFromTail => {
                                // Return an unrelated own resetRequestEntry at seq 2 with a different ID so convo.last_seq reaches 2,
                                // while verified_pending() != Some(&id) (#129)!
                                let other_id = "98989898-9898-4898-8898-989898989899";
                                let other_body = json!({
                                    "$type": "blue.catbird.chat.defs#resetRequestBody",
                                    "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
                                    "resetRequestId": other_id,
                                    "idempotencyKey": other_id,
                                    "actorDid": ALICE_DID,
                                    "actorDeviceId": DEV_A1,
                                    "keyId": derive_key_id(signer_clone.public()),
                                    "authGeneration": 1,
                                    "prior": prior_c,
                                    "reason": "manualRecovery",
                                    "signedAt": "2026-11-15T12:00:00.000Z",
                                });
                                let prep = chat_wire::sign_clean_chat_mutation(
                                    ALICE_DID,
                                    DEV_A1,
                                    Some(1),
                                    CanonicalOperation::RequestReset,
                                    &other_body,
                                    &signer_clone,
                                )
                                .unwrap();
                                let w: Value =
                                    serde_json::from_slice(&prep.body.unwrap()).unwrap();
                                let (vb, dg) = chat_wire::verify_signed_mutation_body_and_digest(
                                    &w["signedRequest"],
                                    SignedMutationKind::ResetRequest,
                                    signer_clone.public(),
                                )
                                .unwrap();
                                let rcpt = sign_control_receipt(
                                    &mls_k_get,
                                    SEQUENCER_DID,
                                    CONVO_ID_2,
                                    &vb["prior"],
                                    2,
                                    other_id,
                                    ALICE_DID,
                                    DEV_A1,
                                    &dg,
                                );
                                http_json(
                                    200,
                                    &json!({
                                        "entries": [{
                                            "$type": crate::chat_v2::wire::RESET_REQUEST_ENTRY_KIND,
                                            "conversationId": CONVO_ID_2,
                                            "seq": 2,
                                            "entryId": other_id,
                                            "signedRequest": w["signedRequest"],
                                            "sequencerReceipt": rcpt,
                                        }]
                                    }),
                                )
                            }
                            ResetMode::TailAdvancesPastRequest => {
                                // Also include a second benign entry at seq 3 so convo.last_seq (3) > request_seq (2) (#128)!
                                let nop_id = "98989898-9898-4898-8898-989898989898";
                                let payload = SequencerReceiptPayload {
                                    sequencer_did: SEQUENCER_DID.to_string(),
                                    conversation_id: CONVO_ID_2.to_string(),
                                    group_id: reset_gid_get.clone(),
                                    epoch: 0,
                                    sender_device_did_url: format!("{ALICE_DID}#{DEV_A1}"),
                                    entry_id: nop_id.to_string(),
                                    archive_commitment: [0x55; 32],
                                    seq: 3,
                                    issued_at_ms: 1_763_000_000_099,
                                };
                                let signed = sign_sequencer_receipt(
                                    &mls_k_get,
                                    &format!("{SEQUENCER_DID}#mls-receipt-1"),
                                    &payload,
                                )
                                .unwrap();
                                let pruned_app = json!({
                                    "$type": crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
                                    "conversationId": CONVO_ID_2,
                                    "seq": 3,
                                    "entryId": nop_id,
                                    "payloadPruned": true,
                                    "sequencerReceipt": {
                                        "kid": signed.key_id,
                                        "sequencerDid": SEQUENCER_DID,
                                        "conversationId": CONVO_ID_2,
                                        "generation": 0,
                                        "groupId": { "$bytes": STANDARD.encode(&reset_gid_get) },
                                        "epoch": 0,
                                        "seq": 3,
                                        "entryId": nop_id,
                                        "senderDid": ALICE_DID,
                                        "senderDeviceId": DEV_A1,
                                        "archiveCommitment": { "$bytes": STANDARD.encode([0x55u8; 32]) },
                                        "issuedAtMs": 1_763_000_000_099i64,
                                        "signature": { "$bytes": STANDARD.encode(signed.signature) },
                                    }
                                });
                                http_json(200, &json!({ "entries": [req_entry, pruned_app] }))
                            }
                            _ => http_json(200, &json!({ "entries": [req_entry] })),
                        };
                    }
                }
                http_json(200, &json!({ "entries": [] }))
            }),
        ));
        let mls_k_act = mls_key.clone();
        let pub_k_act = signer.public().to_vec();
        st.route_handlers.push((
            "/xrpc/blue.catbird.chat.activateReset".to_string(),
            Box::new(move |req| {
                let wire: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                let (vbody, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                    &wire["signedRequest"],
                    SignedMutationKind::ResetActivation,
                    &pub_k_act,
                )
                .unwrap();
                let tid = vbody["transitionId"].as_str().unwrap();
                let act_seq = vbody["metadataSnapshot"]["authorProof"]["originSeq"]
                    .as_u64()
                    .unwrap();
                let rcpt = sign_control_receipt(
                    &mls_k_act,
                    SEQUENCER_DID,
                    CONVO_ID_2,
                    &vbody["successor"],
                    act_seq,
                    tid,
                    ALICE_DID,
                    DEV_A1,
                    &digest,
                );
                let mut retired_ans = vbody["retired"].clone();
                let mut succ_ans = vbody["successor"].clone();
                if matches!(mode, ResetMode::TamperRetired) {
                    retired_ans["stateVersion"] = json!(99);
                }
                if matches!(mode, ResetMode::TamperSuccessor) {
                    succ_ans["stateVersion"] = json!(99);
                }
                http_json(
                    200,
                    &json!({
                        "entry": {
                            "$type": RESET_ACTIVATION_ENTRY_KIND,
                            "conversationId": CONVO_ID_2,
                            "seq": act_seq,
                            "entryId": tid,
                            "signedRequest": wire["signedRequest"],
                            "sequencerReceipt": rcpt,
                        },
                        "retiredCoordinates": retired_ans,
                        "successorCoordinates": succ_ans,
                    }),
                )
            }),
        ));
    };

    // #126 & #127: stale verified_reset_request (wrong actorDeviceId or wrong prior) is NOT reused;
    // AND #129: when tail advances to seq 2 with a DIFFERENT resetRequestId, reset_conversation fails!
    let reset_req_key = chat_wire::verified_reset_request_key(CONVO_ID_2);
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &reset_req_key,
                &json!({
                    "resetRequestId": "10101010-1010-4010-8010-101010101010",
                    "actorDid": ALICE_DID,
                    "actorDeviceId": DEV_B1,
                    "prior": reset_prior,
                })
                .to_string(),
                now_ms,
            )
        })
        .unwrap();
    install_reset_handlers(ResetMode::MissingFromTail);
    assert!(client.reset_conversation(CONVO_ID_2).is_err());
    assert!(state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("requestReset")));

    // Reset last_seq back to 1 and test #127 (wrong prior in verified_reset_request) + #130 (TamperRetired).
    let mut stale_prior = reset_prior.clone();
    stale_prior["stateVersion"] = json!(77);
    client
        .db
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "UPDATE conversations SET last_seq = 1 WHERE conversation_id = ?1",
                    [CONVO_ID_2],
                )
                .unwrap();
            tx.put_account_meta(
                &reset_req_key,
                &json!({
                    "resetRequestId": "10101010-1010-4010-8010-101010101011",
                    "actorDid": ALICE_DID,
                    "actorDeviceId": DEV_A1,
                    "prior": stale_prior,
                })
                .to_string(),
                now_ms,
            )
        })
        .unwrap();
    install_reset_handlers(ResetMode::TamperRetired);
    assert!(client.reset_conversation(CONVO_ID_2).is_err());
    assert!(state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("requestReset")));
    assert!(state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("activateReset")));

    // Test #131 (TamperSuccessor):
    client
        .db
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "UPDATE conversations SET last_seq = 1 WHERE conversation_id = ?1",
                    [CONVO_ID_2],
                )
                .unwrap();
            tx.delete_account_meta(&reset_req_key)
        })
        .unwrap();
    install_reset_handlers(ResetMode::TamperSuccessor);
    assert!(client.reset_conversation(CONVO_ID_2).is_err());
    assert!(state
        .lock()
        .unwrap()
        .seen_urls
        .iter()
        .any(|u| u.contains("activateReset")));

    // Positive + #128 (TailAdvancesPastRequest: convo.last_seq (3) > request_seq (2)): succeeds and reaches generation 1!
    client
        .db
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "UPDATE conversations SET last_seq = 1 WHERE conversation_id = ?1",
                    [CONVO_ID_2],
                )
                .unwrap();
            tx.delete_account_meta(&reset_req_key)
        })
        .unwrap();
    install_reset_handlers(ResetMode::TailAdvancesPastRequest);
    let reset_row = client.reset_conversation(CONVO_ID_2).unwrap();
    assert_eq!(reset_row.generation, 1);
    assert_eq!(reset_row.last_seq, 4);

    let _ = OTHER_SEQUENCER_DID;
    drop((dir, dir_b, leg_dir, no_sig_dir));
}

#[test]
fn did_web_resolution_fails_closed_on_non_success_without_cached_document() {
    let (transport, state) = PlaneMockTransport::new();
    let (_dir, client, _signer) = new_plane_client(ALICE_DID, DEV_A1, transport);
    let peer_web = "did:web:closed-check.example.com";
    let resolve_url = format!(
        "{PDS_URL}/xrpc/com.atproto.identity.resolveDid?did={}",
        chat_wire::urlencode_form_component(peer_web)
    );
    let well_known = "https://closed-check.example.com/.well-known/did.json".to_string();
    let queue = |url: &str, status: u16, body: Value| {
        state
            .lock()
            .unwrap()
            .exact_get
            .entry(url.to_string())
            .or_default()
            .push_back(http_json(status, &body));
    };

    // Non-200 from resolveDid AND from the did:web document: an error, never `Ok(None)`.
    queue(&resolve_url, 502, json!({ "error": "BadGateway" }));
    queue(&well_known, 404, json!({ "error": "NotFound" }));
    let err = client
        .resolve_did_document(peer_web)
        .expect_err("non-200 from every source without a cached document must fail closed");
    assert!(
        err.to_string().contains("404"),
        "the last failing source's status is reported: {err}"
    );

    // Same for every status pairing: a 200 alone is a document.
    for (resolve_status, well_known_status) in [(500, 503), (404, 500), (429, 410)] {
        queue(&resolve_url, resolve_status, json!({ "error": "x" }));
        queue(&well_known, well_known_status, json!({ "error": "y" }));
        assert!(client.resolve_did_document(peer_web).is_err());
    }

    // The sequencer receipt key lookup inherits the failure instead of reporting no key.
    queue(&resolve_url, 503, json!({ "error": "Unavailable" }));
    queue(&well_known, 503, json!({ "error": "Unavailable" }));
    assert!(client
        .resolve_sequencer_receipt_key(peer_web, &format!("{peer_web}#mls-receipt-1"))
        .is_err());

    // A successful did:web document is cached and then outlives later failures.
    queue(&resolve_url, 404, json!({ "error": "DidNotFound" }));
    queue(&well_known, 200, json!({ "id": peer_web }));
    assert!(client.resolve_did_document(peer_web).unwrap().is_some());
    queue(&resolve_url, 500, json!({ "error": "x" }));
    queue(&well_known, 500, json!({ "error": "y" }));
    let cached: Value =
        serde_json::from_slice(&client.resolve_did_document(peer_web).unwrap().unwrap()).unwrap();
    assert_eq!(cached["id"], peer_web);

    // The home sequencer still resolves through ds_base() when both earlier sources fail.
    let (home_transport, home_state) = PlaneMockTransport::new();
    home_state.lock().unwrap().authority_mls_keys.clear();
    home_state.lock().unwrap().authority_dr_keys.clear();
    let custom_ds = "http://127.0.0.1:19992";
    let home_did = "did:web:closed-home.example.com";
    let (_home_dir, home_client, _) =
        new_plane_client_with_cfg(ALICE_DID, DEV_A1, custom_ds, home_did, home_transport);
    home_state
        .lock()
        .unwrap()
        .exact_get
        .entry(format!("{custom_ds}/.well-known/did.json"))
        .or_default()
        .push_back(http_json(200, &json!({ "id": home_did })));
    let home_doc: Value =
        serde_json::from_slice(&home_client.resolve_did_document(home_did).unwrap().unwrap())
            .unwrap();
    assert_eq!(home_doc["id"], home_did);
}
