use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use labyrinth_protocol::receipt::{
    compute_archive_commitment, expected_receipt_key_id, sign_sequencer_receipt,
    SequencerReceiptPayload,
};
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::SigningKey as P256SigningKey;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::client::chat_wire::sign_clean_chat_mutation;
use crate::client::config::CatbirdMlsClientConfig;
use crate::client::traits::{
    PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore,
    PlatformTransport,
};
use crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope;
use crate::orchestrator::canonical_transport::{derive_key_id, CanonicalOperation};
use crate::orchestrator::MLSMessagePayload;
use crate::storage::{ConversationRow, MessageRow, OpenMlsKvStorage, RusqliteKvBackend};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

const SEQUENCER_DID: &str = "did:web:sequencer.example.com";
const PINNED_SEQUENCER_DID: &str = "did:web:pinned.example.com";
const UNTRUSTED_SEQUENCER_DID: &str = "did:web:untrusted.example.com";
const DS_URL: &str = "https://sequencer.example.com";
const PDS_URL: &str = "https://pds.example.com";
const ALICE_DID: &str = "did:plc:aliceunitaaaaaaaaaaaaaaa";
const BOB_DID: &str = "did:plc:bobunitbbbbbbbbbbbbbbbbb";
const CAROL_DID: &str = "did:plc:carolunitccccccccccccccc";
const CONVO_ID: &str = "11111111-1111-4111-8111-111111111111";
const DEV_A1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEV_A2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DEV_B1: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const DEV_C1: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

struct UnitMemKeyStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl UnitMemKeyStore {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl PlatformKeyStore for UnitMemKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let mut g = self.map.lock().unwrap();
        Ok(g.entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| vec![0x42; 32])
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

#[derive(Default)]
struct SyncMockState {
    authority_keys: BTreeMap<String, P256SigningKey>,
    pds_devices: BTreeMap<String, Vec<(String, Vec<u8>)>>,
    fail_next_did_resolve_for: Option<String>,
    entries_by_after: BTreeMap<i64, Vec<Value>>,
    conversation_state: Option<Value>,
    pending_leaf_recoveries: Vec<Value>,
    submitted_transitions: Vec<Value>,
    acked_welcomes: Vec<Value>,
}

struct SyncMockTransport {
    state: Arc<Mutex<SyncMockState>>,
}

impl SyncMockTransport {
    fn new() -> (Arc<Self>, Arc<Mutex<SyncMockState>>) {
        let mut st = SyncMockState::default();
        st.authority_keys.insert(
            SEQUENCER_DID.to_string(),
            P256SigningKey::from_slice(&[11u8; 32]).unwrap(),
        );
        st.authority_keys.insert(
            PINNED_SEQUENCER_DID.to_string(),
            P256SigningKey::from_slice(&[22u8; 32]).unwrap(),
        );
        st.authority_keys.insert(
            UNTRUSTED_SEQUENCER_DID.to_string(),
            P256SigningKey::from_slice(&[33u8; 32]).unwrap(),
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

fn json_http(status: u16, val: &Value) -> Result<PlatformHttpResponse, MLSError> {
    Ok(PlatformHttpResponse {
        status,
        headers: vec![PlatformHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body: serde_json::to_vec(val).unwrap(),
    })
}

fn query_params(url: &str) -> BTreeMap<String, String> {
    let Some((_, q)) = url.split_once('?') else {
        return BTreeMap::new();
    };
    q.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                k.replace("%3A", ":").replace("%23", "#"),
                v.replace("%3A", ":").replace("%23", "#"),
            ))
        })
        .collect()
}

fn authority_did_doc(did: &str, sk: &P256SigningKey) -> Value {
    let sec1 = sk.verifying_key().to_encoded_point(true);
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(sec1.as_bytes());
    let multibase_str = multibase::encode(multibase::Base::Base58Btc, multikey);
    json!({
        "id": did,
        "verificationMethod": [{
            "id": expected_receipt_key_id(did),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase_str,
        }],
    })
}

fn plc_atproto_secret(did: &str) -> p256::SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(b"catbird-sync-mock-atproto:");
    hasher.update(did.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    p256::SecretKey::from_slice(&digest).unwrap()
}

fn plc_did_doc(did: &str) -> Value {
    let sk = P256SigningKey::from(&plc_atproto_secret(did));
    let sec1 = sk.verifying_key().to_encoded_point(true);
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(sec1.as_bytes());
    let multibase_str = multibase::encode(multibase::Base::Base58Btc, multikey);
    json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase_str,
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": PDS_URL,
        }],
    })
}

impl PlatformTransport for SyncMockTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let q = query_params(&request.url);
        let mut st = self.state.lock().unwrap();
        if let Some(plc_did) = request.url.strip_prefix("https://plc.directory/") {
            if st.fail_next_did_resolve_for.as_deref() == Some(plc_did) {
                st.fail_next_did_resolve_for = None;
                return Err(MLSError::Internal("injected DID resolver outage".into()));
            }
            return json_http(200, &plc_did_doc(plc_did));
        }
        if request.url.ends_with("/.well-known/did.json") {
            let host = request
                .url
                .strip_prefix("https://")
                .or_else(|| request.url.strip_prefix("http://"))
                .unwrap_or(&request.url)
                .split('/')
                .next()
                .unwrap_or("sequencer.example.com");
            let did = format!("did:web:{host}");
            if let Some(sk) = st.authority_keys.get(&did) {
                return json_http(200, &authority_did_doc(&did, sk));
            }
        }
        if request
            .url
            .contains("/xrpc/com.atproto.identity.resolveDid")
        {
            let did = q.get("did").cloned().unwrap_or_default();
            if let Some(sk) = st.authority_keys.get(&did) {
                return json_http(200, &json!({ "didDoc": authority_did_doc(&did, sk) }));
            }
            return json_http(200, &json!({ "didDoc": plc_did_doc(&did) }));
        }
        if request.url.contains("/xrpc/com.atproto.repo.listRecords") {
            if request
                .url
                .contains("collection=blue.catbird.chat.deviceRevocation")
            {
                return json_http(200, &json!({ "records": [] }));
            }
            let repo = q.get("repo").cloned().unwrap_or_default();
            let devices = st.pds_devices.get(&repo).cloned().unwrap_or_default();
            let records: Vec<Value> = devices
                .into_iter()
                .map(|(dev_id, pk)| {
                    let value = json!({
                        "$type": "blue.catbird.chat.device",
                        "algorithm": "Ed25519",
                        "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(pk) },
                        "createdAt": "2026-11-14T00:00:00.000Z",
                    });
                    #[allow(unused_mut)]
                    let mut entry = json!({
                        "uri": format!("at://{repo}/blue.catbird.chat.device/{dev_id}"),
                        "value": value,
                    });
                    #[cfg(feature = "labyrinth")]
                    {
                        let secret = plc_atproto_secret(&repo);
                        let signing_key = atproto_spaces::tokens::SpaceSigningKey::from_p256_secret(
                            &secret,
                            format!("{repo}#atproto"),
                        );
                        let (record_cid, record_cbor) =
                            crate::labyrinth::repo_proof::encode_atproto_json_record_dagcbor(
                                &entry["value"],
                            )
                            .unwrap();
                        let (_, car_bytes) = crate::labyrinth::repo_proof::build_repo_proof_car_v1(
                            &repo,
                            "3lb2zzzzzzzzz",
                            &[(format!("blue.catbird.chat.device/{dev_id}"), record_cbor)],
                            &signing_key,
                        )
                        .unwrap();
                        entry["cid"] = json!(record_cid.to_string());
                        entry["proof"] = json!(STANDARD.encode(car_bytes));
                    }
                    entry
                })
                .collect();
            return json_http(200, &json!({ "records": records }));
        }
        if request.url.contains("/xrpc/blue.catbird.chat.getEntries") {
            let after = q
                .get("afterSeq")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let entries = st.entries_by_after.get(&after).cloned().unwrap_or_default();
            return json_http(200, &json!({ "entries": entries }));
        }
        if request
            .url
            .contains("/xrpc/blue.catbird.chat.getConversationState")
        {
            let state = st.conversation_state.clone().unwrap_or_else(|| json!({}));
            return json_http(
                200,
                &json!({
                    "state": state,
                    "pendingLeafRecoveryRequests": st.pending_leaf_recoveries,
                    "pendingResetRequests": [],
                    "pendingLeaveRequests": [],
                    "accountDeletions": [],
                }),
            );
        }
        if request
            .url
            .contains("/xrpc/blue.catbird.chat.submitTransition")
        {
            let req_json: Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
            let sr = req_json["signedRequest"].clone();
            let body = &sr["body"];
            let cid = body["next"]["conversationId"]
                .as_str()
                .or_else(|| body["prior"]["conversationId"].as_str())
                .unwrap_or(CONVO_ID);
            let (_, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                &sr,
                chat_wire::signed_entry_kind(&json!({ "signedRequest": &sr })).unwrap(),
                &st.pds_devices
                    .get(body["actorDid"].as_str().unwrap_or_default())
                    .and_then(|list| {
                        list.iter()
                            .find(|(d, _)| Some(d.as_str()) == body["actorDeviceId"].as_str())
                    })
                    .map(|(_, pk)| pk.clone())
                    .unwrap(),
            )
            .unwrap();
            let seq = 2i64;
            let entry_id = body["transitionId"].as_str().unwrap_or("entry-2");
            let sk = st.authority_keys.get(SEQUENCER_DID).unwrap().clone();
            let receipt = sign_control_receipt(
                &sk,
                SEQUENCER_DID,
                body,
                &body["next"],
                entry_id,
                seq as u64,
                digest,
            );
            let entry = json!({
                "entryId": entry_id,
                "conversationId": cid,
                "seq": seq,
                "receivedAt": body["signedAt"],
                "signedRequest": sr,
                "sequencerReceipt": receipt,
            });
            st.submitted_transitions.push(entry.clone());
            return json_http(
                200,
                &json!({
                    "coordinates": body["next"],
                    "entry": entry,
                }),
            );
        }
        if request
            .url
            .contains("/xrpc/blue.catbird.chat.acknowledgeWelcome")
        {
            let req_json: Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
            st.acked_welcomes.push(req_json);
            return json_http(200, &json!({ "acknowledged": true }));
        }
        if request
            .url
            .contains("/xrpc/blue.catbird.chat.acknowledgeEntries")
        {
            return json_http(200, &json!({ "watermarkSeq": 1 }));
        }
        json_http(200, &json!({}))
    }

    fn connect_realtime_stream(&self, _url: String, _cursor: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

fn open_unit_client(
    tmp: &tempfile::TempDir,
    label: &str,
    did: &str,
    device_id: &str,
    transport: Arc<dyn PlatformTransport>,
    hooks: crate::sim_hooks::SimClientHooks,
) -> (Arc<CatbirdMlsClient>, Arc<UnitMemKeyStore>) {
    let ks = Arc::new(UnitMemKeyStore::new());
    let client = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join(label).to_string_lossy().into_owned(),
            account_did: did.to_string(),
            device_id: device_id.to_string(),
            home_ds_did: SEQUENCER_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        ks.clone(),
        transport,
        None,
        hooks,
    )
    .expect("open unit client");
    (client, ks)
}

#[allow(clippy::too_many_arguments)]
fn sign_control_receipt(
    sk: &P256SigningKey,
    authority_did: &str,
    body: &Value,
    coord: &Value,
    entry_id: &str,
    seq: u64,
    request_digest: [u8; 32],
) -> Value {
    let group_id = chat_wire::json_bytes(&coord["groupId"]).unwrap();
    let payload = SequencerReceiptPayload {
        sequencer_did: authority_did.to_string(),
        conversation_id: coord["conversationId"].as_str().unwrap().to_string(),
        group_id: group_id.clone(),
        epoch: coord["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            body["actorDid"].as_str().unwrap(),
            body["actorDeviceId"].as_str().unwrap()
        ),
        entry_id: entry_id.to_string(),
        archive_commitment: request_digest,
        seq,
        issued_at_ms: 1_762_000_000_000,
    };
    let key_id = expected_receipt_key_id(authority_did);
    let signed = sign_sequencer_receipt(sk, &key_id, &payload).unwrap();
    json!({
        "sequencerDid": authority_did,
        "conversationId": payload.conversation_id,
        "generation": coord["generation"],
        "groupId": { "$bytes": STANDARD.encode(group_id) },
        "epoch": payload.epoch,
        "senderDid": body["actorDid"],
        "senderDeviceId": body["actorDeviceId"],
        "entryId": entry_id,
        "archiveCommitment": { "$bytes": STANDARD.encode(request_digest) },
        "seq": seq,
        "issuedAtMs": payload.issued_at_ms,
        "kid": signed.key_id,
        "signature": { "$bytes": STANDARD.encode(signed.signature) },
    })
}

#[allow(clippy::too_many_arguments)]
fn sign_app_receipt(
    sk: &P256SigningKey,
    authority_did: &str,
    cid: &str,
    generation: i64,
    group_id: &[u8],
    epoch: u64,
    sender_did: &str,
    sender_device_id: &str,
    entry_id: &str,
    seq: u64,
    commitment: [u8; 32],
) -> Value {
    let payload = SequencerReceiptPayload {
        sequencer_did: authority_did.to_string(),
        conversation_id: cid.to_string(),
        group_id: group_id.to_vec(),
        epoch,
        sender_device_did_url: format!("{sender_did}#{sender_device_id}"),
        entry_id: entry_id.to_string(),
        archive_commitment: commitment,
        seq,
        issued_at_ms: 1_762_000_000_000,
    };
    let key_id = expected_receipt_key_id(authority_did);
    let signed = sign_sequencer_receipt(sk, &key_id, &payload).unwrap();
    json!({
        "sequencerDid": authority_did,
        "conversationId": cid,
        "generation": generation,
        "groupId": { "$bytes": STANDARD.encode(group_id) },
        "epoch": epoch,
        "senderDid": sender_did,
        "senderDeviceId": sender_device_id,
        "entryId": entry_id,
        "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
        "seq": seq,
        "issuedAtMs": payload.issued_at_ms,
        "kid": signed.key_id,
        "signature": { "$bytes": STANDARD.encode(signed.signature) },
    })
}

fn build_kp_value_and_bundle(
    client: &CatbirdMlsClient,
    did: &str,
    device_id: &str,
) -> (SignatureKeyPair, KeyPackage, Value) {
    let now_secs = client.hooks.now_secs();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("ed25519 signer");
    let scoped = format!("{did}#{device_id}");
    let caps = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let cred = CredentialWithKey {
        credential: BasicCredential::new(scoped.into_bytes()).into(),
        signature_key: signer.public().into(),
    };
    let (kp, kp_val) = client
        .db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = client.hooks.openmls_provider(storage);
            signer
                .store(provider.storage())
                .map_err(|e| MLSError::Internal(format!("store signer: {e:?}")))?;
            let bundle = KeyPackage::builder()
                .key_package_lifetime(Lifetime::init(
                    now_secs.saturating_sub(60),
                    now_secs + 86_400,
                ))
                .leaf_node_capabilities(caps)
                .build(CIPHERSUITE, &provider, &signer, cred)
                .map_err(|e| MLSError::Cryptography(format!("build KP: {e:?}")))?;
            let kp_bytes = MlsMessageOut::from(bundle.key_package().clone())
                .tls_serialize_detached()
                .unwrap();
            let kp_ref = bundle
                .key_package()
                .hash_ref(provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec();
            let val = json!({
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                "sha256": STANDARD.encode(Sha256::digest(&kp_bytes)),
                "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
            });
            Ok((bundle.key_package().clone(), val))
        })
        .expect("build KP in db");
    (signer, kp, kp_val)
}

/// Seed a 1-member (or multi-member) active MLS group in `client.db`, returning
/// `(alice_signer, group_id, current_coords)`.
fn seed_active_group(
    client: &CatbirdMlsClient,
    cid: &str,
    sequencer_did: &str,
    generation: i64,
    last_seq: i64,
    extra_kps: &[KeyPackage],
) -> (SignatureKeyPair, Vec<u8>, Value) {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("group signer");
    let group_id = vec![0x55; 32];
    let now_secs = client.hooks.now_secs();
    let now_ms = client.hooks.now_ms();
    let scoped = format!("{}#{}", client.normalized_did, client.config.device_id);
    let coords = client
        .db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = client.hooks.openmls_provider(storage);
            signer
                .store(provider.storage())
                .map_err(|e| MLSError::Internal(format!("store signer: {e:?}")))?;
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let create_cfg = MlsGroupCreateConfig::builder()
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
                &signer,
                &create_cfg,
                GroupId::from_slice(&group_id),
                CredentialWithKey {
                    credential: BasicCredential::new(scoped.into_bytes()).into(),
                    signature_key: signer.public().into(),
                },
            )
            .map_err(|e| MLSError::Cryptography(format!("new group: {e:?}")))?;
            if !extra_kps.is_empty() {
                group
                    .add_members(&provider, &signer, extra_kps)
                    .map_err(|e| MLSError::Cryptography(format!("add_members: {e:?}")))?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("merge_pending_commit: {e:?}")))?;
            }
            let epoch = group.epoch().as_u64() as i64;
            let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
            let coords = json!({
                "conversationId": cid,
                "generation": generation,
                "stateVersion": 1,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(ctag) },
                "lifecycle": "active",
            });
            let canon = chat_wire::canonicalize_wire_coordinate(&coords, Some(cid))?;
            tx.upsert_conversation(&ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                generation,
                epoch,
                last_seq,
                space_uri: None,
                sequencer_did: sequencer_did.to_string(),
                title: Some("Unit Group".to_string()),
                unread_count: 0,
                updated_at_ms: now_ms,
            })?;
            tx.put_account_meta(&format!("conversation_kind:{cid}"), "group", now_ms)?;
            tx.put_account_meta(
                &format!("conversation_coords:{cid}"),
                &canon.to_string(),
                now_ms,
            )?;
            Ok(canon)
        })
        .expect("seed active group");
    (signer, group_id, coords)
}

#[test]
fn store_roster_clears_invitation_closed_only_for_pending_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, _) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "roster",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );

    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &chat_wire::invitation_closed_key(CONVO_ID, BOB_DID),
                "3",
                100,
            )?;
            tx.put_account_meta(
                &chat_wire::invitation_closed_key(CONVO_ID, CAROL_DID),
                "4",
                100,
            )?;
            tx.put_account_meta(
                &chat_wire::invitation_closed_key(CONVO_ID, ALICE_DID),
                "5",
                100,
            )?;
            let roster = json!({
                ALICE_DID: { "role": "admin", "status": "active" },
                BOB_DID: { "role": "member", "status": "pending" },
                CAROL_DID: { "role": "member", "status": "removed" },
            });
            store_roster(tx, CONVO_ID, &roster, 200)
        })
        .unwrap();

    client
        .db
        .read_tx(|tx| {
            assert_eq!(
                tx.get_account_meta(&chat_wire::verified_participant_admission_key(
                    CONVO_ID, ALICE_DID
                ))?,
                Some("true".to_string())
            );
            assert!(
                tx.get_account_meta(&chat_wire::invitation_closed_key(CONVO_ID, BOB_DID))?
                    .is_none(),
                "pending participant must clear closed invitation marker"
            );
            assert_eq!(
                tx.get_account_meta(&chat_wire::invitation_closed_key(CONVO_ID, CAROL_DID))?,
                Some("4".to_string()),
                "non-pending participant must preserve closed invitation marker"
            );
            assert_eq!(
                tx.get_account_meta(&chat_wire::invitation_closed_key(CONVO_ID, ALICE_DID))?,
                Some("5".to_string()),
                "active participant must preserve closed invitation marker"
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn require_participant_enforces_roster_admission_seq_window_and_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "req_part",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (alice_signer, _, coords) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 1, &[]);
    let sk = state
        .lock()
        .unwrap()
        .authority_keys
        .get(SEQUENCER_DID)
        .unwrap()
        .clone();

    let mut keys_by_did: BTreeMap<String, Vec<AuthorizedPeerDeviceKey>> = BTreeMap::new();
    keys_by_did.insert(
        ALICE_DID.to_string(),
        vec![
            AuthorizedPeerDeviceKey {
                did: ALICE_DID.to_string(),
                device_id: DEV_A1.to_string(),
                signature_public_key: alice_signer.public().to_vec(),
            },
            AuthorizedPeerDeviceKey {
                did: ALICE_DID.to_string(),
                device_id: DEV_A2.to_string(),
                signature_public_key: alice_signer.public().to_vec(),
            },
        ],
    );

    // 1. `admission.is_some() && roster_active(...)`: each half alone must NOT short-circuit.
    // Put a seq=1 non-inviting entry so falling through reaches `reads_seq_one == true` -> `Err`.
    state.lock().unwrap().entries_by_after.insert(
        0,
        vec![json!({
            "seq": 1,
            "signedRequest": { "body": { "$type": "blue.catbird.chat.defs#metadataTransitionBody" } }
        })],
    );
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &chat_wire::verified_participant_admission_key(CONVO_ID, CAROL_DID),
                "true",
                100,
            )
        })
        .unwrap();
    assert!(
        client
            .require_participant(
                DEV_A1,
                &alice_signer,
                CONVO_ID,
                SEQUENCER_DID,
                CAROL_DID,
                None,
                5,
                &[],
                &keys_by_did,
            )
            .is_err(),
        "admission without active roster must not short-circuit"
    );

    client
        .db
        .write_tx(|tx| {
            let roster = json!({
                ALICE_DID: { "role": "admin", "status": "active" },
                CAROL_DID: { "role": "member", "status": "active" },
            });
            store_roster(tx, CONVO_ID, &roster, 100)?;
            tx.delete_account_meta(&chat_wire::verified_participant_admission_key(
                CONVO_ID, CAROL_DID,
            ))
        })
        .unwrap();
    assert!(
        client
            .require_participant(
                DEV_A1,
                &alice_signer,
                CONVO_ID,
                SEQUENCER_DID,
                CAROL_DID,
                None,
                5,
                &[],
                &keys_by_did,
            )
            .is_err(),
        "active roster without verified admission must not short-circuit"
    );

    // Clear roster so subsequent checks traverse `entries`.
    client
        .db
        .write_tx(|tx| clear_roster_baseline(tx, CONVO_ID))
        .unwrap();

    // 2. Strict window `seq > after_seq && seq < before_seq` (`after_seq = 0`, `before_seq = 5`):
    // Unsigned inviting entries at exact boundaries `seq = 0` and `seq = 5` (no `seq = 1`) must be
    // excluded, returning `Ok(None)` instead of selecting an unverified boundary entry (`Err`).
    let transition_id = "22222222-2222-4222-8222-222222222222";
    let mut next_coords = coords.clone();
    next_coords["stateVersion"] = json!(2);
    let invite_body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\0",
        "transitionId": transition_id,
        "idempotencyKey": transition_id,
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "keyId": derive_key_id(alice_signer.public()),
        "authGeneration": 1,
        "signedAt": "2026-11-13T00:00:00.000Z",
        "prior": coords,
        "next": next_coords,
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#addParticipant",
            "userDid": CAROL_DID,
            "role": "member",
            "status": "pending",
            "invitationProvenance": {
                "invitationTransitionId": transition_id,
                "invitedByDid": ALICE_DID,
                "invitedByDeviceId": DEV_A1,
            }
        }],
    });
    let boundary_unsigned = |seq: i64| {
        json!({
            "seq": seq,
            "signedRequest": {
                "body": invite_body,
                "signature": { "$bytes": STANDARD.encode([0u8; 64]) },
            }
        })
    };
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(0, vec![boundary_unsigned(0), boundary_unsigned(5)]);
    assert_eq!(
        client
            .require_participant(
                DEV_A1,
                &alice_signer,
                CONVO_ID,
                SEQUENCER_DID,
                CAROL_DID,
                None,
                5,
                &[],
                &keys_by_did,
            )
            .unwrap(),
        None
    );

    // 3. Exact provenance guard (`*provenance == invited`):
    let prepared = sign_clean_chat_mutation(
        ALICE_DID,
        DEV_A1,
        Some(1),
        CanonicalOperation::SubmitTransition,
        &invite_body,
        &alice_signer,
    )
    .unwrap();
    let req_val: Value = serde_json::from_slice(prepared.body.as_deref().unwrap()).unwrap();
    let sr = req_val["signedRequest"].clone();
    let (_, req_digest) = chat_wire::verify_signed_mutation_body_and_digest(
        &sr,
        SignedMutationKind::PolicyTransition,
        alice_signer.public(),
    )
    .unwrap();
    let receipt = sign_control_receipt(
        &sk,
        SEQUENCER_DID,
        &invite_body,
        &next_coords,
        transition_id,
        2,
        req_digest,
    );
    let signed_invite_entry = json!({
        "entryId": transition_id,
        "conversationId": CONVO_ID,
        "seq": 2,
        "signedRequest": sr,
        "sequencerReceipt": receipt,
    });
    let exact_provenance = json!({
        "invitationTransitionId": transition_id,
        "invitedByDid": ALICE_DID,
        "invitedByDeviceId": DEV_A1,
    });
    assert_eq!(
        client
            .require_participant(
                DEV_A1,
                &alice_signer,
                CONVO_ID,
                SEQUENCER_DID,
                CAROL_DID,
                Some(&exact_provenance),
                5,
                std::slice::from_ref(&signed_invite_entry),
                &keys_by_did,
            )
            .unwrap(),
        Some(2)
    );

    let wrong_device_provenance = json!({
        "invitationTransitionId": transition_id,
        "invitedByDid": ALICE_DID,
        "invitedByDeviceId": DEV_A2,
    });
    assert!(
        client
            .require_participant(
                DEV_A1,
                &alice_signer,
                CONVO_ID,
                SEQUENCER_DID,
                CAROL_DID,
                Some(&wrong_device_provenance),
                5,
                std::slice::from_ref(&signed_invite_entry),
                &keys_by_did,
            )
            .is_err(),
        "provenance naming a different inviter device must be rejected even when its key verifies"
    );
}

#[test]
fn finish_received_archive_evidence_validates_outer_sender_own_device_and_counter_presence() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "finish_ev",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (_, group_id, _) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 5, &[]);
    let sk = state
        .lock()
        .unwrap()
        .authority_keys
        .get(SEQUENCER_DID)
        .unwrap()
        .clone();

    let stage_cached_message = |msg_id: &str, sender_did: &str, sender_dev: &str, seq: i64| {
        let sender_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let payload_json = serde_json::to_string(&MLSMessagePayload::text("hello unit")).unwrap();
        let nonce = [0x24u8; 32];
        let commitment = compute_archive_commitment(&nonce, payload_json.as_bytes());
        let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
            CONVO_ID,
            msg_id,
            &commitment,
        );
        let attestation = OriginalSenderArchiveAttestationEnvelope {
            sender_did: sender_did.to_string(),
            sender_device_id: sender_dev.to_string(),
            sender_transport_public_key: sender_signer.public().to_vec(),
            signature: sender_signer.sign(&transcript).unwrap(),
        };
        let evidence = json!({
            "version": 1,
            "message_id": msg_id,
            "conversation_id": CONVO_ID,
            "group_id_hex": hex::encode(&group_id),
            "epoch": 0u64,
            "expected_member_dids": [ALICE_DID],
            "seq": 0i64,
            "sender_did": sender_did,
            "sender_device_id": sender_dev,
            "sequencer_did": SEQUENCER_DID,
            "space_uri": Value::Null,
            "plaintext_json": payload_json,
            "labyrinth_frame_json": payload_json,
            "mls_ciphertext_b64": STANDARD.encode([1u8; 16]),
            "frame_nonce_b64": STANDARD.encode(nonce),
            "sequencer_receipt_json": Value::Null,
            "original_sender_attestation_json": serde_json::to_string(&attestation).unwrap(),
            "created_at_ms": 1_000i64,
        });
        client
            .db
            .write_tx(|tx| {
                tx.insert_message(&MessageRow {
                    message_id: msg_id.to_string(),
                    conversation_id: CONVO_ID.to_string(),
                    group_id: group_id.clone(),
                    epoch: 0,
                    seq: 0,
                    sender_did: sender_did.to_string(),
                    sender_device_id: sender_dev.to_string(),
                    plaintext_json: payload_json.clone(),
                    created_at_ms: 1_000,
                    is_own: sender_did == ALICE_DID,
                })?;
                tx.put_labyrinth_state(
                    &format!("native.message:{CONVO_ID}:{msg_id}"),
                    &serde_json::to_vec(&evidence)?,
                    1_000,
                )
            })
            .unwrap();
        sign_app_receipt(
            &sk,
            SEQUENCER_DID,
            CONVO_ID,
            0,
            &group_id,
            0,
            sender_did,
            sender_dev,
            msg_id,
            seq as u64,
            commitment,
        )
    };

    // 1. Outer sender mismatch on device ID alone or DID alone must fail closed.
    let m1 = "33333333-3333-4333-8333-333333333331";
    let r1 = stage_cached_message(m1, BOB_DID, DEV_B1, 6);
    assert!(client
        .finish_received_archive_evidence(
            CONVO_ID,
            m1,
            6,
            m1,
            &r1,
            Some((BOB_DID, DEV_A1)),
            Some(1),
            DEV_A1,
        )
        .is_err());
    assert!(client
        .finish_received_archive_evidence(
            CONVO_ID,
            m1,
            6,
            m1,
            &r1,
            Some((ALICE_DID, DEV_B1)),
            Some(1),
            DEV_A1,
        )
        .is_err());

    // 2. Own `(ALICE_DID, DEV_A1)` never writes `peer_send_counter_key`.
    let m_own = "33333333-3333-4333-8333-333333333332";
    let r_own = stage_cached_message(m_own, ALICE_DID, DEV_A1, 5);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            m_own,
            5,
            m_own,
            &r_own,
            Some((ALICE_DID, DEV_A1)),
            Some(1),
            DEV_A1,
        )
        .unwrap();
    let own_counter_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, 0, ALICE_DID, DEV_A1);
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_account_meta(&own_counter_key))
            .unwrap(),
        None
    );

    // 3. Own sibling `(ALICE_DID, DEV_A2)` DOES record `peer_send_counter_key`.
    let m_sib = "33333333-3333-4333-8333-333333333333";
    let r_sib = stage_cached_message(m_sib, ALICE_DID, DEV_A2, 5);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            m_sib,
            5,
            m_sib,
            &r_sib,
            Some((ALICE_DID, DEV_A2)),
            Some(1),
            DEV_A1,
        )
        .unwrap();
    let sib_counter_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, 0, ALICE_DID, DEV_A2);
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_account_meta(&sib_counter_key))
            .unwrap(),
        Some("1".to_string())
    );

    // 4. `send_counter = None` (a counter this device cannot learn) completes the entry and
    // counts it, so the device's next counter is still compared exactly; it never refuses.
    let bob_counter_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, 0, BOB_DID, DEV_B1);
    client
        .db
        .write_tx(|tx| tx.put_account_meta(&bob_counter_key, "3", 1_000))
        .unwrap();
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            m1,
            6,
            m1,
            &r1,
            Some((BOB_DID, DEV_B1)),
            None,
            DEV_A1,
        )
        .unwrap();
    let m_next = "33333333-3333-4333-8333-333333333335";
    let r_next = stage_cached_message(m_next, BOB_DID, DEV_B1, 7);
    client
        .finish_received_archive_evidence(
            CONVO_ID,
            m_next,
            7,
            m_next,
            &r_next,
            Some((BOB_DID, DEV_B1)),
            Some(5),
            DEV_A1,
        )
        .unwrap();
    assert_eq!(
        client
            .db
            .read_tx(|tx| crate::client::send_counter::list_send_counter_evidence(tx, CONVO_ID))
            .unwrap(),
        vec![],
        "3, one uncounted entry, then 5 is contiguous"
    );
    // Within the epoch a counter that does not increase is still refused.
    let m_back = "33333333-3333-4333-8333-333333333336";
    let r_back = stage_cached_message(m_back, BOB_DID, DEV_B1, 8);
    assert!(client
        .finish_received_archive_evidence(
            CONVO_ID,
            m_back,
            8,
            m_back,
            &r_back,
            Some((BOB_DID, DEV_B1)),
            Some(5),
            DEV_A1,
        )
        .is_err());
}

#[test]
fn record_undecryptable_entry_tracks_sibling_counter_without_touching_own_device() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "undec",
        ALICE_DID,
        DEV_A1,
        transport.clone(),
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (sib_client, _) = open_unit_client(
        &tmp,
        "undec_sib",
        ALICE_DID,
        DEV_A2,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (sib_signer, sib_kp, _) = build_kp_value_and_bundle(&sib_client, ALICE_DID, DEV_A2);
    let (own_signer, group_id, _) =
        seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 0, &[sib_kp]);

    let sk = state
        .lock()
        .unwrap()
        .authority_keys
        .get(SEQUENCER_DID)
        .unwrap()
        .clone();
    let receipt_sec1 = sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let keys = vec![
        AuthorizedPeerDeviceKey {
            did: ALICE_DID.to_string(),
            device_id: DEV_A1.to_string(),
            signature_public_key: own_signer.public().to_vec(),
        },
        AuthorizedPeerDeviceKey {
            did: ALICE_DID.to_string(),
            device_id: DEV_A2.to_string(),
            signature_public_key: sib_signer.public().to_vec(),
        },
    ];
    let convo_uuid = uuid::Uuid::parse_str(CONVO_ID).unwrap();

    let record_one =
        |msg_id: &str, seq: i64, dev_id: &str, signer: &SignatureKeyPair, counter: u64| {
            let msg_uuid = uuid::Uuid::parse_str(msg_id).unwrap();
            let commitment = [0x5Au8; 32];
            let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
                CONVO_ID,
                msg_id,
                &commitment,
            );
            let attestation = OriginalSenderArchiveAttestationEnvelope {
                sender_did: ALICE_DID.to_string(),
                sender_device_id: dev_id.to_string(),
                sender_transport_public_key: signer.public().to_vec(),
                signature: signer.sign(&transcript).unwrap(),
            };
            let aad_prior = chat_wire::build_aad_prior_coordinate(
                &convo_uuid,
                &group_id,
                0,
                1,
                1,
                &[8u8; 32],
                &[9u8; 32],
            );
            let signed_aad = json!({
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": 0,
                "messageId": STANDARD.encode(msg_uuid.as_bytes()),
                "prior": aad_prior,
                "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
                "originalSenderAttestation": attestation.to_aad_json(),
            });
            let receipt = sign_app_receipt(
                &sk,
                SEQUENCER_DID,
                CONVO_ID,
                0,
                &group_id,
                1,
                ALICE_DID,
                dev_id,
                msg_id,
                seq as u64,
                commitment,
            );
            let evidence = chat_wire::UndecryptableEntryEvidence {
                version: 1,
                conversation_id: CONVO_ID.to_string(),
                message_id: msg_id.to_string(),
                entry_id: msg_id.to_string(),
                seq,
                epoch: 1,
                sender_did: ALICE_DID.to_string(),
                sender_device_id: dev_id.to_string(),
                send_counter: Some(counter),
                reason: "SecretReuseError".to_string(),
                recorded_at_ms: 2_000,
            };
            client
                .record_undecryptable_entry(&evidence, &signed_aad, &receipt, &receipt_sec1, &keys)
                .unwrap();
        };

    record_one(
        "44444444-4444-4444-8444-444444444441",
        1,
        DEV_A1,
        &own_signer,
        1,
    );
    let own_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, 1, ALICE_DID, DEV_A1);
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_account_meta(&own_key))
            .unwrap(),
        None
    );

    record_one(
        "44444444-4444-4444-8444-444444444442",
        2,
        DEV_A2,
        &sib_signer,
        1,
    );
    let sib_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, 1, ALICE_DID, DEV_A2);
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_account_meta(&sib_key))
            .unwrap(),
        Some("1".to_string())
    );
}

#[test]
fn fulfill_leaf_recovery_and_join_pending_welcome_boundary_guards() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (alice, _) = open_unit_client(
        &tmp,
        "alice_lr",
        ALICE_DID,
        DEV_A1,
        transport.clone(),
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (bob, _) = open_unit_client(
        &tmp,
        "bob_lr",
        BOB_DID,
        DEV_B1,
        transport.clone(),
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (carol, _) = open_unit_client(
        &tmp,
        "carol_lr",
        CAROL_DID,
        DEV_C1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );

    let (alice_signer, _, prior_coords) =
        seed_active_group(&alice, CONVO_ID, SEQUENCER_DID, 0, 1, &[]);
    let (bob_signer, _, bob_kp_val) = build_kp_value_and_bundle(&bob, BOB_DID, DEV_B1);
    let (carol_signer, _, carol_kp_val) = build_kp_value_and_bundle(&carol, CAROL_DID, DEV_C1);
    let (_, _, alice_kp_val) = build_kp_value_and_bundle(&alice, ALICE_DID, DEV_A1);

    {
        let mut st = state.lock().unwrap();
        st.pds_devices.insert(
            ALICE_DID.to_string(),
            vec![(DEV_A1.to_string(), alice_signer.public().to_vec())],
        );
        st.pds_devices.insert(
            BOB_DID.to_string(),
            vec![(DEV_B1.to_string(), bob_signer.public().to_vec())],
        );
        st.pds_devices.insert(
            CAROL_DID.to_string(),
            vec![(DEV_C1.to_string(), carol_signer.public().to_vec())],
        );
        st.conversation_state = Some(json!({
            "conversationKind": "group",
            "sequencerDid": SEQUENCER_DID,
            "coordinates": prior_coords,
        }));
    }

    let make_recovery_view = |req_id: &str,
                              did: &str,
                              dev: &str,
                              kind: &str,
                              signer: &SignatureKeyPair,
                              kp_val: &Value| {
        let body = chat_wire::leaf_recovery_request_body(
            req_id,
            did,
            dev,
            &derive_key_id(signer.public()),
            1,
            &prior_coords,
            kind,
            "2026-11-13T00:00:00.000Z",
        )
        .unwrap();
        let prepared = sign_clean_chat_mutation(
            did,
            dev,
            Some(1),
            CanonicalOperation::RequestLeafRecovery,
            &body,
            signer,
        )
        .unwrap();
        let req_json: Value = serde_json::from_slice(prepared.body.as_deref().unwrap()).unwrap();
        json!({
            "conversationId": CONVO_ID,
            "recoveryRequestId": req_id,
            "requesterDid": did,
            "requesterDeviceId": dev,
            "recoveryKind": kind,
            "boundCoordinate": prior_coords,
            "status": "open",
            "requestedAt": "2026-11-13T00:00:00.000Z",
            "expiresAt": "2099-01-01T00:00:00.000Z",
            "signedRequest": req_json["signedRequest"],
            "reservation": {
                "conversationId": CONVO_ID,
                "recoveryRequestId": req_id,
                "boundCoordinate": prior_coords,
                "requesterDid": did,
                "requesterDeviceId": dev,
                "requesterKeyId": derive_key_id(signer.public()),
                "requesterAuthGeneration": 1,
                "keyPackageRef": kp_val["keyPackageRef"],
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "purpose": "leafRecovery",
                "status": "active",
                "expiresAt": "2099-01-01T00:00:00.000Z",
                "keyPackage": kp_val,
            }
        })
    };

    // 1. Zero-leaf Carol asking for `"replace"` -> skipped cleanly (`Ok(0)`), never `AdmissionProofUnavailable`.
    state.lock().unwrap().pending_leaf_recoveries = vec![make_recovery_view(
        "55555555-5555-4555-8555-555555555551",
        CAROL_DID,
        DEV_C1,
        "replace",
        &carol_signer,
        &carol_kp_val,
    )];
    assert_eq!(
        alice
            .fulfill_leaf_recovery(CONVO_ID, DEV_A1, &alice_signer, 1)
            .unwrap(),
        0
    );

    // 2. Own `(ALICE_DID, DEV_A1)` asking for `"add"` with no stored admission -> skipped (`Ok(0)`).
    state.lock().unwrap().pending_leaf_recoveries = vec![make_recovery_view(
        "55555555-5555-4555-8555-555555555552",
        ALICE_DID,
        DEV_A1,
        "add",
        &alice_signer,
        &alice_kp_val,
    )];
    assert_eq!(
        alice
            .fulfill_leaf_recovery(CONVO_ID, DEV_A1, &alice_signer, 1)
            .unwrap(),
        0
    );

    // 3. Zero-leaf Carol asking for `"add"` with active roster row BUT missing `verified_participant_admission` -> `Err(AdmissionProofUnavailable)`.
    alice
        .db
        .write_tx(|tx| {
            let roster = json!({
                ALICE_DID: { "role": "admin", "status": "active" },
                BOB_DID: { "role": "member", "status": "active" },
                CAROL_DID: { "role": "member", "status": "active" },
            });
            store_roster(tx, CONVO_ID, &roster, 100)?;
            tx.delete_account_meta(&chat_wire::verified_participant_admission_key(
                CONVO_ID, CAROL_DID,
            ))
        })
        .unwrap();
    state.lock().unwrap().pending_leaf_recoveries = vec![make_recovery_view(
        "55555555-5555-4555-8555-555555555553",
        CAROL_DID,
        DEV_C1,
        "add",
        &carol_signer,
        &carol_kp_val,
    )];
    assert!(matches!(
        alice.fulfill_leaf_recovery(CONVO_ID, DEV_A1, &alice_signer, 1),
        Err(MLSError::AdmissionProofUnavailable { .. })
    ));

    // 4. Fulfill Bob's valid `"add"` recovery, then re-sign the fulfillment receipt under
    // `PINNED_SEQUENCER_DID` while `getConversationState` advertises `UNTRUSTED_SEQUENCER_DID`.
    // Bob's retired row with `sequencer_did = PINNED_SEQUENCER_DID` must keep its pinned authority!
    state.lock().unwrap().pending_leaf_recoveries = vec![make_recovery_view(
        "55555555-5555-4555-8555-555555555554",
        BOB_DID,
        DEV_B1,
        "add",
        &bob_signer,
        &bob_kp_val,
    )];
    assert_eq!(
        alice
            .fulfill_leaf_recovery(CONVO_ID, DEV_A1, &alice_signer, 1)
            .unwrap(),
        1
    );

    let mut fulfillment = state
        .lock()
        .unwrap()
        .submitted_transitions
        .pop()
        .expect("fulfillment transition");
    let (_, f_digest) = chat_wire::verify_signed_mutation_body_and_digest(
        &fulfillment["signedRequest"],
        SignedMutationKind::LeafRecoveryFulfillment,
        alice_signer.public(),
    )
    .unwrap();
    let pinned_sk = state
        .lock()
        .unwrap()
        .authority_keys
        .get(PINNED_SEQUENCER_DID)
        .unwrap()
        .clone();
    let f_body = fulfillment["signedRequest"]["body"].clone();
    let next_coords = f_body["next"].clone();
    fulfillment["sequencerReceipt"] = sign_control_receipt(
        &pinned_sk,
        PINNED_SEQUENCER_DID,
        &f_body,
        &next_coords,
        f_body["transitionId"].as_str().unwrap(),
        2,
        f_digest,
    );
    let welcome_bytes_val = f_body["manifest"]["welcomeBundle"]["opaqueWelcome"].clone();
    {
        let mut st = state.lock().unwrap();
        st.entries_by_after.insert(1, vec![fulfillment]);
        st.conversation_state = Some(json!({
            "conversationKind": "group",
            "sequencerDid": UNTRUSTED_SEQUENCER_DID,
            "coordinates": next_coords,
        }));
    }

    // Seed retired ConversationRow on Bob (`group_id` has no MlsGroup in Bob's openmls_kv).
    bob.db
        .write_tx(|tx| {
            tx.upsert_conversation(&ConversationRow {
                conversation_id: CONVO_ID.to_string(),
                group_id: vec![0x99; 32],
                generation: 0,
                epoch: 0,
                last_seq: 1,
                space_uri: None,
                sequencer_did: PINNED_SEQUENCER_DID.to_string(),
                title: Some("Retired".to_string()),
                unread_count: 2,
                updated_at_ms: 500,
            })
        })
        .unwrap();

    let w_env = json!({
        "welcomeId": "66666666-6666-4666-8666-666666666666",
        "transitionSeq": 2,
        "coordinates": next_coords,
        "opaqueWelcome": welcome_bytes_val,
    });
    assert!(
        bob.join_pending_welcome(DEV_B1, &bob_signer, 1, &w_env, CONVO_ID)
            .unwrap(),
        "retired row must retain non-empty pinned sequencer authority over state view"
    );
    let bob_row = bob
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    assert_eq!(bob_row.sequencer_did, PINNED_SEQUENCER_DID);
    assert_eq!(bob_row.unread_count, 2);
}

#[test]
fn maybe_auto_self_update_respects_thresholds_group_kind_retired_and_closed_guards() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, _) = SyncMockTransport::new();
    let base_now_ms = 1_762_000_000_000i64;

    let open_with_pcs = |label: &str, max_age_ms: i64, max_msgs: u64| {
        let mut hooks = crate::sim_hooks::SimClientHooks::system_default();
        hooks.clock = Arc::new(crate::sim_hooks::FixedStepClock::new(base_now_ms, 0));
        hooks.pcs_max_age_ms = max_age_ms;
        hooks.pcs_max_messages = max_msgs;
        let (client, _) =
            open_unit_client(&tmp, label, ALICE_DID, DEV_A1, transport.clone(), hooks);
        seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 0, 1, &[]);
        client
    };

    let marker = format!("pcs_epoch_started_at:{CONVO_ID}:0:0");

    // Note: keystore holds no enrolled MLS signer, so any `self_update(cid)` call deterministically
    // returns `Err(...)`, while skipping `self_update` returns `Ok(())`.

    // 1. `pcs_max_age_ms = 100, pcs_max_messages = 0`:
    let c_age = open_with_pcs("pcs_age", 100, 0);
    // Exact boundary `age == 100` (`> 100` is false) -> `Ok(())`.
    c_age
        .db
        .write_tx(|tx| tx.put_account_meta(&marker, &(base_now_ms - 100).to_string(), base_now_ms))
        .unwrap();
    c_age.maybe_auto_self_update(CONVO_ID).unwrap();

    // `age == 50` with 1 stored message (`pcs_max_messages == 0` disabled) -> `Ok(())`.
    c_age
        .db
        .write_tx(|tx| {
            tx.put_account_meta(&marker, &(base_now_ms - 50).to_string(), base_now_ms)?;
            tx.insert_message(&MessageRow {
                message_id: "66666666-6666-4666-8666-666666666661".to_string(),
                conversation_id: CONVO_ID.to_string(),
                group_id: vec![0x55; 32],
                epoch: 0,
                seq: 1,
                sender_did: ALICE_DID.to_string(),
                sender_device_id: DEV_A1.to_string(),
                plaintext_json: "{\"text\":\"m1\"}".to_string(),
                created_at_ms: base_now_ms,
                is_own: true,
            })
        })
        .unwrap();
    c_age.maybe_auto_self_update(CONVO_ID).unwrap();

    // `age == 101 > 100` on active group -> triggers `self_update` (`Err`).
    c_age
        .db
        .write_tx(|tx| tx.put_account_meta(&marker, &(base_now_ms - 101).to_string(), base_now_ms))
        .unwrap();
    assert!(c_age.maybe_auto_self_update(CONVO_ID).is_err());

    // Non-group (`conversation_kind` != `"group"`), active, unclosed -> skipped (`Ok(())`).
    c_age
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &format!("conversation_kind:{CONVO_ID}"),
                "direct",
                base_now_ms,
            )
        })
        .unwrap();
    c_age.maybe_auto_self_update(CONVO_ID).unwrap();

    // Restore `"group"`, mark conversation closed (active MLS group, not retired) -> skipped (`Ok(())`).
    c_age
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &format!("conversation_kind:{CONVO_ID}"),
                "group",
                base_now_ms,
            )?;
            tx.put_account_meta(
                &format!("conversation_closed:{CONVO_ID}"),
                "true",
                base_now_ms,
            )
        })
        .unwrap();
    c_age.maybe_auto_self_update(CONVO_ID).unwrap();

    // Unclose, but make conversation retired (point `group_id` at missing MlsGroup) -> skipped (`Ok(())`).
    c_age
        .db
        .write_tx(|tx| {
            tx.delete_account_meta(&format!("conversation_closed:{CONVO_ID}"))?;
            let mut row = tx.get_conversation(CONVO_ID)?.unwrap();
            row.group_id = vec![0xEE; 32];
            tx.upsert_conversation(&row)
        })
        .unwrap();
    c_age.maybe_auto_self_update(CONVO_ID).unwrap();

    // 2. `pcs_max_age_ms = 0` (disabled), `pcs_max_messages = 1`:
    let c_msg = open_with_pcs("pcs_msg", 0, 1);
    // `age = 500`, `message_count = 0` -> `Ok(())` (age threshold disabled when `pcs_max_age_ms == 0`).
    c_msg
        .db
        .write_tx(|tx| tx.put_account_meta(&marker, &(base_now_ms - 500).to_string(), base_now_ms))
        .unwrap();
    c_msg.maybe_auto_self_update(CONVO_ID).unwrap();

    // Exact boundary `message_count == 1 == pcs_max_messages` -> `Ok(())`.
    c_msg
        .db
        .write_tx(|tx| {
            tx.insert_message(&MessageRow {
                message_id: "66666666-6666-4666-8666-666666666662".to_string(),
                conversation_id: CONVO_ID.to_string(),
                group_id: vec![0x55; 32],
                epoch: 0,
                seq: 1,
                sender_did: ALICE_DID.to_string(),
                sender_device_id: DEV_A1.to_string(),
                plaintext_json: "{\"text\":\"m1\"}".to_string(),
                created_at_ms: base_now_ms,
                is_own: true,
            })
        })
        .unwrap();
    c_msg.maybe_auto_self_update(CONVO_ID).unwrap();

    // `message_count == 2 > pcs_max_messages` -> triggers `self_update` (`Err`).
    c_msg
        .db
        .write_tx(|tx| {
            tx.insert_message(&MessageRow {
                message_id: "66666666-6666-4666-8666-666666666663".to_string(),
                conversation_id: CONVO_ID.to_string(),
                group_id: vec![0x55; 32],
                epoch: 0,
                seq: 2,
                sender_did: ALICE_DID.to_string(),
                sender_device_id: DEV_A1.to_string(),
                plaintext_json: "{\"text\":\"m2\"}".to_string(),
                created_at_ms: base_now_ms,
                is_own: true,
            })
        })
        .unwrap();
    assert!(c_msg.maybe_auto_self_update(CONVO_ID).is_err());
}

#[test]
fn verify_application_prior_and_nse_deferred_marker_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, _) = SyncMockTransport::new();
    let (client, _) = open_unit_client(
        &tmp,
        "prior_fork",
        ALICE_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (signer, _, _) = seed_active_group(&client, CONVO_ID, SEQUENCER_DID, 1, 1, &[]);

    let coord_at = |generation: i64, epoch: i64, gch_byte: u8| {
        json!({
            "conversationId": CONVO_ID,
            "generation": generation,
            "stateVersion": 1,
            "groupId": { "$bytes": STANDARD.encode([0x55u8; 32]) },
            "epoch": epoch,
            "groupContextHash": { "$bytes": STANDARD.encode([gch_byte; 32]) },
            "confirmationTag": { "$bytes": STANDARD.encode([0x09u8; 32]) },
            "lifecycle": "active",
        })
    };
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta(
                &format!("conversation_coords:{CONVO_ID}"),
                &coord_at(1, 2, 0x08).to_string(),
                100,
            )
        })
        .unwrap();

    // 1. `prior_epoch = 1 < local_epoch = 2` (even with different hash) -> `Ok(())`.
    client
        .verify_application_prior_or_flag_fork(
            CONVO_ID,
            2,
            &json!({ "prior": coord_at(1, 1, 0xFE) }),
            || Ok(()),
        )
        .unwrap();

    // 2. `prior_epoch = 3 > local_epoch = 2` (same generation & hash) -> `WrongEpoch` (`!ForkDetected`).
    let err_ahead = client
        .verify_application_prior_or_flag_fork(
            CONVO_ID,
            2,
            &json!({ "prior": coord_at(1, 3, 0x08) }),
            || Ok(()),
        )
        .unwrap_err();
    assert!(!matches!(err_ahead, MLSError::ForkDetected { .. }));

    // 3. `prior_epoch == local_epoch == 2`, `prior.generation = 0 != local.generation = 1` -> `WrongEpoch`.
    let err_gen = client
        .verify_application_prior_or_flag_fork(
            CONVO_ID,
            2,
            &json!({ "prior": coord_at(0, 2, 0x08) }),
            || Ok(()),
        )
        .unwrap_err();
    assert!(!matches!(err_gen, MLSError::ForkDetected { .. }));

    // 4. `sync_conversation_entries` NSE deferred-control marker boundary (`< 1` invalid; `== 1` valid + cleared):
    let convo = client
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    client
        .db
        .write_tx(|tx| tx.put_pending_op(NSE_DEFERRED_CONTROL_OP, CONVO_ID, "0", 100))
        .unwrap();
    assert!(client
        .sync_conversation_entries(DEV_A1, &signer, &convo)
        .is_err());

    client
        .db
        .write_tx(|tx| tx.put_pending_op(NSE_DEFERRED_CONTROL_OP, CONVO_ID, "1", 100))
        .unwrap();
    assert_eq!(
        client
            .sync_conversation_entries(DEV_A1, &signer, &convo)
            .unwrap(),
        0
    );
    assert_eq!(
        client
            .db
            .read_tx(|tx| tx.get_pending_op(NSE_DEFERRED_CONTROL_OP, CONVO_ID))
            .unwrap(),
        None
    );
}

#[test]
fn apply_conversation_entries_reset_pruned_redelivery_fork_and_counter_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let (transport, state) = SyncMockTransport::new();
    let (alice, _) = open_unit_client(
        &tmp,
        "apply_alice",
        ALICE_DID,
        DEV_A1,
        transport.clone(),
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    let (alice_sib, _) = open_unit_client(
        &tmp,
        "apply_sib",
        ALICE_DID,
        DEV_A2,
        transport.clone(),
        crate::sim_hooks::SimClientHooks::system_default(),
    );
    // Give Bob the SAME UUID string `DEV_A1` as Alice's canonical device so we isolate
    // `sender_did == self.normalized_did` from `sender_device_id == canonical_dev_id`!
    let (bob_same_dev, _) = open_unit_client(
        &tmp,
        "apply_bob",
        BOB_DID,
        DEV_A1,
        transport,
        crate::sim_hooks::SimClientHooks::system_default(),
    );

    let (sib_signer, sib_kp, _) = build_kp_value_and_bundle(&alice_sib, ALICE_DID, DEV_A2);
    let (bob_signer, bob_kp, _) = build_kp_value_and_bundle(&bob_same_dev, BOB_DID, DEV_A1);
    let (alice_signer, group_id, coords) =
        seed_active_group(&alice, CONVO_ID, SEQUENCER_DID, 0, 1, &[sib_kp, bob_kp]);

    let sk = state
        .lock()
        .unwrap()
        .authority_keys
        .get(SEQUENCER_DID)
        .unwrap()
        .clone();
    {
        let mut st = state.lock().unwrap();
        st.pds_devices.insert(
            ALICE_DID.to_string(),
            vec![
                (DEV_A1.to_string(), alice_signer.public().to_vec()),
                (DEV_A2.to_string(), sib_signer.public().to_vec()),
            ],
        );
        st.pds_devices.insert(
            BOB_DID.to_string(),
            vec![(DEV_A1.to_string(), bob_signer.public().to_vec())],
        );
    }

    // Export group info / ratchet tree is already in Alice's DB; create independent sender MlsGroups
    // for `(ALICE_DID, DEV_A2)` and `(BOB_DID, DEV_A1)` by cloning Alice's openmls_kv into their DBs
    // or building a signed application entry! Wait: for `ForkDetected` (`L4821-4822`) and stale
    // `sendCounter` (`L4865`), lines 4790-4889 execute BEFORE `MlsGroup::process_message` (`L4986`)!
    // And for `entry_seq == current.last_seq` (`L4790`), let's build a real `Welcome` for Bob so Bob
    // creates real `PrivateMessage`s that Alice decrypts cleanly!
    let convo_uuid = uuid::Uuid::parse_str(CONVO_ID).unwrap();

    // 1. Own `LeaveRequest` at seq 2 must NOT write `verified_reset_request_key`; own `ResetRequest`
    // at seq 3 MUST write `verified_reset_request_key`.
    let leave_id = "77777777-7777-4777-8777-777777777771";
    let leave_body = json!({
        "$type": "blue.catbird.chat.defs#leaveRequestBody",
        "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\0",
        "leaveRequestId": leave_id,
        "idempotencyKey": leave_id,
        "actorDid": ALICE_DID,
        "actorDeviceId": DEV_A1,
        "keyId": derive_key_id(alice_signer.public()),
        "authGeneration": 1,
        "prior": coords,
        "signedAt": "2026-11-13T00:00:00.000Z",
    });
    let leave_prep = sign_clean_chat_mutation(
        ALICE_DID,
        DEV_A1,
        Some(1),
        CanonicalOperation::RequestLeave,
        &leave_body,
        &alice_signer,
    )
    .unwrap();
    let leave_sr = serde_json::from_slice::<Value>(leave_prep.body.as_deref().unwrap()).unwrap()
        ["signedRequest"]
        .clone();
    let (_, leave_digest) = chat_wire::verify_signed_mutation_body_and_digest(
        &leave_sr,
        SignedMutationKind::LeaveRequest,
        alice_signer.public(),
    )
    .unwrap();
    let leave_entry = json!({
        "$type": "blue.catbird.chat.defs#leaveRequestEntry",
        "entryId": leave_id,
        "conversationId": CONVO_ID,
        "seq": 2,
        "receivedAt": "2026-11-13T00:00:00.000Z",
        "signedRequest": leave_sr,
        "sequencerReceipt": sign_control_receipt(&sk, SEQUENCER_DID, &leave_body, &coords, leave_id, 2, leave_digest),
    });

    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(1, vec![leave_entry]);
    let convo_row = alice
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap();
    assert_eq!(
        alice
            .db
            .read_tx(|tx| tx.get_account_meta(&chat_wire::verified_reset_request_key(CONVO_ID)))
            .unwrap(),
        None,
        "own LeaveRequest must never write verified_reset_request_key"
    );

    // 2. Pruned application entries (`L4753-4754`):
    // Pre-seed counters for own `(ALICE_DID, DEV_A1)` = `"3"` and sibling `(ALICE_DID, DEV_A2)` = `"3"`.
    let epoch = coords["epoch"].as_i64().unwrap();
    let own_counter_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, epoch, ALICE_DID, DEV_A1);
    let sib_counter_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, epoch, ALICE_DID, DEV_A2);
    alice
        .db
        .write_tx(|tx| {
            tx.put_account_meta(&own_counter_key, "3", 100)?;
            tx.put_account_meta(&sib_counter_key, "3", 100)
        })
        .unwrap();

    let pruned_own_id = "77777777-7777-4777-8777-777777777772";
    let pruned_sib_id = "77777777-7777-4777-8777-777777777773";
    let pruned_own = json!({
        "$type": crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
        "entryId": pruned_own_id,
        "conversationId": CONVO_ID,
        "seq": 3,
        "payloadPruned": true,
        "sequencerReceipt": sign_app_receipt(&sk, SEQUENCER_DID, CONVO_ID, 0, &group_id, epoch as u64, ALICE_DID, DEV_A1, pruned_own_id, 3, [9u8; 32]),
    });
    let pruned_sib = json!({
        "$type": crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
        "entryId": pruned_sib_id,
        "conversationId": CONVO_ID,
        "seq": 4,
        "payloadPruned": true,
        "sequencerReceipt": sign_app_receipt(&sk, SEQUENCER_DID, CONVO_ID, 0, &group_id, epoch as u64, ALICE_DID, DEV_A2, pruned_sib_id, 4, [9u8; 32]),
    });
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(2, vec![pruned_own, pruned_sib]);
    let convo_row = alice
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap();
    assert_eq!(
        alice
            .db
            .read_tx(|tx| tx.get_account_meta(&own_counter_key))
            .unwrap(),
        Some("3".to_string()),
        "pruned entry from own device must not advance peer_send_counter_key"
    );
    assert_eq!(
        alice
            .db
            .read_tx(|tx| tx.get_account_meta(&sib_counter_key))
            .unwrap(),
        Some("3".to_string()),
        "a pruned entry never invents a counter for the sibling device"
    );
    // Never received here: each pruned entry leaves receipt evidence and a neutral placeholder,
    // and counts once toward the sibling's next counter.
    for pruned_id in [pruned_own_id, pruned_sib_id] {
        assert!(alice
            .db
            .read_tx(|tx| tx
                .get_labyrinth_state(&chat_wire::unavailable_message_key(CONVO_ID, pruned_id)))
            .unwrap()
            .is_some());
        let row = alice
            .db
            .read_tx(|tx| tx.get_message(pruned_id))
            .unwrap()
            .expect("placeholder row");
        assert!(row
            .plaintext_json
            .contains(chat_wire::UNAVAILABLE_MESSAGE_NOTICE));
    }
    let continuity: crate::client::send_counter::PeerCounterContinuity = serde_json::from_str(
        &alice
            .db
            .read_tx(|tx| {
                tx.get_account_meta(&crate::client::send_counter::peer_send_continuity_key(
                    CONVO_ID, 0, ALICE_DID, DEV_A2,
                ))
            })
            .unwrap()
            .expect("sibling continuity"),
    )
    .unwrap();
    assert_eq!((continuity.counter, continuity.skipped), (3, 1));

    // Helper to build a signed `applicationMessageEntry` at `seq` (before ciphertext decryption).
    let make_signed_app_entry = |msg_id: &str,
                                 seq: i64,
                                 actor_did: &str,
                                 actor_dev: &str,
                                 outer_signer: &SignatureKeyPair,
                                 prior: &Value,
                                 send_counter: u64,
                                 att_dev: &str,
                                 att_signer: &SignatureKeyPair,
                                 ct_bytes: &[u8]| {
        let msg_uuid = uuid::Uuid::parse_str(msg_id).unwrap();
        let commitment = [0x33u8; 32];
        let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
            CONVO_ID,
            msg_id,
            &commitment,
        );
        let attestation = OriginalSenderArchiveAttestationEnvelope {
            sender_did: actor_did.to_string(),
            sender_device_id: att_dev.to_string(),
            sender_transport_public_key: att_signer.public().to_vec(),
            signature: att_signer.sign(&transcript).unwrap(),
        };
        let gch = chat_wire::json_bytes(&prior["groupContextHash"]).unwrap();
        let ctag = chat_wire::json_bytes(&prior["confirmationTag"]).unwrap();
        let aad_prior =
            chat_wire::build_aad_prior_coordinate(&convo_uuid, &group_id, 0, 1, epoch, &gch, &ctag);
        let aad_val = json!({
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
            "generation": 0,
            "messageId": STANDARD.encode(msg_uuid.as_bytes()),
            "prior": aad_prior,
            "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
            "originalSenderAttestation": attestation.to_aad_json(),
        });
        let body = json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": msg_id,
            "actorDid": actor_did,
            "actorDeviceId": actor_dev,
            "keyId": derive_key_id(outer_signer.public()),
            "authGeneration": 1,
            "sendCounter": send_counter,
            "signedAt": "2026-11-13T00:00:00.000Z",
            "prior": prior,
            "aad": aad_val,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": { "$bytes": STANDARD.encode(ct_bytes) },
                "sha256": { "$bytes": STANDARD.encode(Sha256::digest(ct_bytes)) },
            },
            "blobBindings": [],
        });
        let prep = sign_clean_chat_mutation(
            actor_did,
            actor_dev,
            Some(1),
            CanonicalOperation::SendMessage,
            &body,
            outer_signer,
        )
        .unwrap();
        let sr = serde_json::from_slice::<Value>(prep.body.as_deref().unwrap()).unwrap()
            ["signedRequest"]
            .clone();
        let receipt = sign_app_receipt(
            &sk,
            SEQUENCER_DID,
            CONVO_ID,
            0,
            &group_id,
            epoch as u64,
            actor_did,
            att_dev,
            msg_id,
            seq as u64,
            commitment,
        );
        json!({
            "$type": crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
            "entryId": msg_id,
            "conversationId": CONVO_ID,
            "seq": seq,
            "receivedAt": "2026-11-13T00:00:00.000Z",
            "signedRequest": sr,
            "sequencerReceipt": receipt,
        })
    };

    // 3. Fork-evidence attestation checks (`L4821-4822`):
    // Forked prior at current epoch (`gch` differs from local `coords`):
    let mut forked_prior = coords.clone();
    forked_prior["groupContextHash"] = json!({ "$bytes": STANDARD.encode([0xDDu8; 32]) });

    // (a) Mismatched `attestation.sender_device_id` (`DEV_B1 != DEV_A1`) with matching key ->
    // must reject with `Cryptography`, NOT `ForkDetected` (`fork_detected_key` stays `None`).
    let fork_bad_dev = make_signed_app_entry(
        "77777777-7777-4777-8777-777777777774",
        5,
        BOB_DID,
        DEV_A1,
        &bob_signer,
        &forked_prior,
        1,
        DEV_B1,
        &bob_signer,
        &[0u8; 8],
    );
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(4, vec![fork_bad_dev]);
    let convo_row = alice
        .db
        .read_tx(|tx| tx.get_conversation(CONVO_ID))
        .unwrap()
        .unwrap();
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    let err_dev = alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap_err();
    assert!(!matches!(err_dev, MLSError::ForkDetected { .. }));
    assert!(
        err_dev
            .to_string()
            .contains("fork evidence sender is not the signed current leaf"),
        "expected fork sender device check failure, got: {err_dev}"
    );
    assert_eq!(
        alice
            .db
            .read_tx(|tx| tx.get_account_meta(&chat_wire::fork_detected_key(CONVO_ID)))
            .unwrap(),
        None
    );

    // (b) Mismatched `attestation.sender_transport_public_key` (`rogue_signer != bob_signer`) with
    // matching `(BOB_DID, DEV_A1)` -> must reject with `Cryptography`, NOT `ForkDetected`.
    let rogue_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let fork_bad_key = make_signed_app_entry(
        "77777777-7777-4777-8777-777777777775",
        5,
        BOB_DID,
        DEV_A1,
        &bob_signer,
        &forked_prior,
        1,
        DEV_A1,
        &rogue_signer,
        &[0u8; 8],
    );
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(4, vec![fork_bad_key]);
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    let err_key = alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap_err();
    assert!(!matches!(err_key, MLSError::ForkDetected { .. }));
    assert!(
        err_key
            .to_string()
            .contains("fork evidence sender is not the signed current leaf"),
        "expected fork sender transport key check failure, got: {err_key}"
    );
    assert_eq!(
        alice
            .db
            .read_tx(|tx| tx.get_account_meta(&chat_wire::fork_detected_key(CONVO_ID)))
            .unwrap(),
        None
    );

    // 4. Stale `sendCounter` on both a peer and an own sibling is evidence only. These two
    // malformed MLS bodies still fail at deserialization; no message is delivered.
    let bob_same_dev_key = chat_wire::peer_send_counter_key(CONVO_ID, 0, epoch, BOB_DID, DEV_A1);
    alice
        .db
        .write_tx(|tx| {
            tx.put_account_meta(&bob_same_dev_key, "10", 100)?;
            tx.put_account_meta(&sib_counter_key, "10", 100)
        })
        .unwrap();

    let stale_bob = make_signed_app_entry(
        "77777777-7777-4777-8777-777777777776",
        5,
        BOB_DID,
        DEV_A1,
        &bob_signer,
        &coords,
        1,
        DEV_A1,
        &bob_signer,
        &[0u8; 8],
    );
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(4, vec![stale_bob]);
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    let err_stale_bob = alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap_err();
    assert!(
        err_stale_bob.to_string().contains("deserialize app msg"),
        "peer sharing device UUID string still rejects malformed MLS bytes: {err_stale_bob}"
    );

    let stale_sib = make_signed_app_entry(
        "77777777-7777-4777-8777-777777777777",
        5,
        ALICE_DID,
        DEV_A2,
        &sib_signer,
        &coords,
        1,
        DEV_A2,
        &sib_signer,
        &[0u8; 8],
    );
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(4, vec![stale_sib]);
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    let err_stale_sib = alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap_err();
    assert!(
        err_stale_sib.to_string().contains("deserialize app msg"),
        "own sibling device still rejects malformed MLS bytes: {err_stale_sib}"
    );

    // 5. Re-delivery at `entry_seq == current.last_seq`:
    // Without a pending archive receipt at `seq == 4`, re-delivery at cursor is skipped (`Ok(())`).
    // With a pending archive receipt at `seq == 4`, `cursor_seq` rewinds to `3` and `peer_counter`
    // stays `None` (`entry_seq > current.last_seq` is false), reaching `deserialize app msg`.
    let redeliver_msg_id = "77777777-7777-4777-8777-777777777778";
    let redelivered_at_cursor = make_signed_app_entry(
        redeliver_msg_id,
        4,
        BOB_DID,
        DEV_A1,
        &bob_signer,
        &coords,
        10,
        DEV_A1,
        &bob_signer,
        &[0u8; 8],
    );
    state
        .lock()
        .unwrap()
        .entries_by_after
        .insert(4, vec![redelivered_at_cursor.clone()]);
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap();

    alice
        .db
        .write_tx(|tx| {
            tx.put_pending_op(
                NATIVE_ARCHIVE_RECEIPT_OP,
                redeliver_msg_id,
                &json!({
                    "conversation_id": CONVO_ID,
                    "seq": 4,
                    "entry_id": redeliver_msg_id,
                })
                .to_string(),
                100,
            )
        })
        .unwrap();
    {
        let mut st = state.lock().unwrap();
        st.entries_by_after.remove(&4);
        st.entries_by_after.insert(3, vec![redelivered_at_cursor]);
    }
    let mut pass = EntryPass {
        max_seq: convo_row.last_seq,
        ..EntryPass::default()
    };
    let err_redeliver = alice
        .apply_conversation_entries(DEV_A1, &alice_signer, &convo_row, &mut pass)
        .unwrap_err();
    assert!(
        err_redeliver.to_string().contains("deserialize app msg"),
        "entry at current.last_seq must bypass fresh sendCounter monotonicity check: {err_redeliver}"
    );
}

#[path = "live_integrity_unit_tests.rs"]
mod live_integrity_unit_tests;
