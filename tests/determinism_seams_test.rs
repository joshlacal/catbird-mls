#[cfg(feature = "labyrinth")]
#[path = "support/native_archive_auth.rs"]
mod native_archive_auth;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use catbird_mls::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
};
use catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES;
use catbird_mls::sim_hooks::{
    build_staged_welcome_at, validate_key_package_at, ChaChaSimEntropy, FixedStepClock,
    SeededOpenMlsCryptoProvider, SimClientHooks, SimClock, SimEntropy, TxAutocommitProbe,
};
use catbird_mls::{
    buggify, CatbirdMlsClient, CatbirdMlsClientConfig, MLSError, PlatformHttpHeader,
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport, SqlDriver,
};
use openmls::prelude::*;
use openmls::treesync::errors::{LeafNodeValidationError, LifetimeError};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::SigningKey as P256SigningKey;
use tls_codec::{Deserialize as _, Serialize as _};

/// Fixed simulation start epoch (`2025-11-01T12:26:40.000Z`) — zero host wall-clock reads.
const PINNED_START_MS: i64 = 1_762_000_000_000;
const PINNED_START_SECS: u64 = 1_762_000_000;
const PINNED_RECEIPT_ISSUED_AT_MS: i64 = 1_762_000_000_500;
/// Fixed upper-bound constant (`2100-01-01T00:00:00Z`) for OpenMLS `add_members` leaves.
const PINNED_FAR_NOT_AFTER_SECS: u64 = 4_102_444_800;

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
    #[cfg(feature = "labyrinth")]
    archive_auth: native_archive_auth::NativeArchiveAuthFixture,
    labyrinth_epochs: Mutex<std::collections::BTreeMap<String, Vec<serde_json::Value>>>,
    chat_device_pubkeys: Mutex<std::collections::BTreeMap<String, Vec<serde_json::Value>>>,
    conversations: Mutex<std::collections::BTreeMap<String, serde_json::Value>>,
}

impl DeterministicMockTransport {
    fn new(clock: Arc<dyn SimClock>) -> Self {
        #[cfg(not(feature = "labyrinth"))]
        let _ = &clock;
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
            #[cfg(feature = "labyrinth")]
            archive_auth: native_archive_auth::NativeArchiveAuthFixture::new(
                "did:plc:aliceaaaaaaaaaaaaaaaaaaa",
                Arc::new(move || clock.now_ms()),
            ),
            labyrinth_epochs: Mutex::new(std::collections::BTreeMap::new()),
            chat_device_pubkeys: Mutex::new(std::collections::BTreeMap::new()),
            conversations: Mutex::new(std::collections::BTreeMap::new()),
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

impl DeterministicMockTransport {
    fn execute_http_raw(
        &self,
        request: &PlatformHttpRequest,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let url = &request.url;

        let json_resp = |status: u16, val: serde_json::Value| PlatformHttpResponse {
            status,
            headers: vec![PlatformHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: serde_json::to_vec(&val).unwrap(),
        };
        let json_ok = |val: serde_json::Value| json_resp(200, val);

        if let Some(did) = url.strip_prefix("https://plc.directory/") {
            return Ok(json_ok(serde_json::json!({
                "id": did,
                "service": [{
                    "id": format!("{did}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.catbird.test",
                }]
            })));
        }

        if url.contains("/xrpc/com.atproto.repo.createRecord") {
            if let Some(ref b) = request.body {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(b) {
                    let repo = val["repo"].as_str().unwrap_or("").to_string();
                    let collection = val["collection"].as_str().unwrap_or("").to_string();
                    let rkey = val["rkey"].as_str().unwrap_or("").to_string();
                    let record = val["record"].clone();
                    let mut store = self.pds_records.lock().unwrap();
                    if store
                        .iter()
                        .any(|r| r.repo == repo && r.collection == collection && r.rkey == rkey)
                    {
                        return Ok(json_resp(
                            400,
                            serde_json::json!({ "error": "RecordAlreadyExists" }),
                        ));
                    }
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

        if url.contains("/xrpc/com.atproto.repo.getRecord") {
            let store = self.pds_records.lock().unwrap();
            if let Some(found) = store
                .iter()
                .find(|r| url.contains(&r.collection) && url.contains(&format!("rkey={}", r.rkey)))
            {
                return Ok(json_ok(serde_json::json!({
                    "uri": format!("at://{}/{}/{}", found.repo, found.collection, found.rkey),
                    "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "value": found.value,
                })));
            }
            return Ok(json_resp(
                400,
                serde_json::json!({ "error": "RecordNotFound" }),
            ));
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
            let req_json: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                    .unwrap_or_default();
            let sbody = req_json.pointer("/signedRequest/body").unwrap_or(&req_json);
            let pk = &sbody["signaturePublicKey"];
            let wrapped_pk = if pk.is_string() {
                serde_json::json!({ "$bytes": pk })
            } else {
                pk.clone()
            };
            if let Some(did) = sbody["actorDid"].as_str() {
                self.chat_device_pubkeys
                    .lock()
                    .unwrap()
                    .entry(did.to_string())
                    .or_default()
                    .push(serde_json::json!({ "signingPublicKey": wrapped_pk.clone() }));
            }
            // `mls-ds` answers the registered `deviceView`.
            let key = catbird_mls::client::chat_wire::json_bytes(pk).unwrap_or_default();
            return Ok(json_ok(serde_json::json!({ "device": {
                "deviceId": sbody["deviceId"],
                "keyId": catbird_mls::canonical_transport::derive_key_id(&key),
                "signaturePublicKey": wrapped_pk,
                "authGeneration": 1,
                "status": "active",
                "createdAt": "2026-11-03T00:00:00.000Z",
                "updatedAt": "2026-11-03T00:00:00.000Z",
                "availablePackageCount": 2,
                "reservedPackageCount": 0,
            }})));
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
            let kind = SignedMutationKind::Creation;
            let strict =
                decode_strict_json(&serde_json::to_vec(sbody).unwrap()).expect("creation body");
            let projected = project_signed_body(kind, &strict).expect("creation projection");
            let request_digest = *SigningTranscript::build_for(kind, &projected)
                .expect("creation transcript")
                .request_digest();
            let group_id_b64 = next_coords["groupId"]["$bytes"]
                .as_str()
                .or_else(|| next_coords["groupId"].as_str())
                .expect("creation groupId");
            let group_id = BASE64.decode(group_id_b64).expect("creation groupId bytes");
            let generation = next_coords["generation"]
                .as_u64()
                .expect("creation generation");
            let epoch = next_coords["epoch"].as_u64().expect("creation epoch");
            let actor_did = sbody["actorDid"].as_str().expect("creation actor DID");
            let actor_device_id = sbody["actorDeviceId"]
                .as_str()
                .expect("creation actor device");
            let entry_id = sbody["transitionId"].as_str().expect("creation transition");
            let receipt_kid = "did:web:mls.catbird.test#mls-receipt-1";
            let signed = labyrinth_protocol::receipt::sign_sequencer_receipt(
                &self.sequencer_signing_key,
                receipt_kid,
                &labyrinth_protocol::receipt::SequencerReceiptPayload {
                    sequencer_did: "did:web:mls.catbird.test".to_string(),
                    conversation_id: sbody["conversationId"]
                        .as_str()
                        .expect("creation conversation")
                        .to_string(),
                    group_id,
                    epoch,
                    sender_device_did_url: format!("{actor_did}#{actor_device_id}"),
                    entry_id: entry_id.to_string(),
                    archive_commitment: request_digest,
                    seq: 1,
                    issued_at_ms: PINNED_RECEIPT_ISSUED_AT_MS,
                },
            )
            .expect("sign creation receipt");
            let control_receipt = serde_json::json!({
                "sequencerDid": "did:web:mls.catbird.test",
                "kid": receipt_kid,
                "conversationId": sbody["conversationId"],
                "generation": generation,
                "groupId": { "$bytes": group_id_b64 },
                "epoch": epoch,
                "seq": 1,
                "senderDid": actor_did,
                "senderDeviceId": actor_device_id,
                "entryId": entry_id,
                "archiveCommitment": { "$bytes": BASE64.encode(request_digest) },
                "issuedAtMs": PINNED_RECEIPT_ISSUED_AT_MS,
                "signature": { "$bytes": BASE64.encode(signed.signature) }
            });
            if let Some(cid) = sbody["conversationId"].as_str() {
                let mut parts = sbody["manifest"]["participants"].clone();
                let creator_did = sbody["manifest"]["actorLeaf"]["userDid"].as_str();
                if let Some(arr) = parts.as_array_mut() {
                    for p in arr {
                        let lc = usize::from(p["userDid"].as_str() == creator_did);
                        p["leafCount"] = serde_json::json!(lc);
                    }
                }
                self.conversations.lock().unwrap().insert(
                    cid.to_string(),
                    serde_json::json!({
                        "conversationKind": "group",
                        "sequencerDid": "did:web:mls.catbird.test",
                        "coordinates": next_coords,
                        "participants": parts,
                        "leaves": [sbody["manifest"]["actorLeaf"]],
                        "metadataSnapshot": sbody["metadataSnapshot"],
                        "snapshotSeq": 1,
                    }),
                );
            }
            // `mls-ds` answers `{result}` carrying the creation entry it sequenced at seq 1.
            return Ok(json_ok(serde_json::json!({ "result": {
                "$type": "blue.catbird.chat.defs#conversationCreatedResult",
                "coordinates": next_coords,
                "entry": {
                    "entryId": sbody["transitionId"],
                    "conversationId": sbody["conversationId"],
                    "seq": 1,
                    "signedRequest": req_json["signedRequest"],
                    "receivedAt": sbody["signedAt"],
                    "sequencerReceipt": control_receipt,
                },
            }})));
        }

        if url.contains("blue.catbird.chat.getConversationState") {
            let cid = url
                .split_once('?')
                .and_then(|(_, q)| {
                    q.split('&')
                        .find_map(|kv| kv.strip_prefix("conversationId="))
                })
                .unwrap_or_default();
            let state = self
                .conversations
                .lock()
                .unwrap()
                .get(cid)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            return Ok(json_ok(serde_json::json!({
                "state": state,
                "pendingLeafRecoveryRequests": [],
                "pendingResetRequests": [],
                "pendingLeaveRequests": [],
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
                issued_at_ms: PINNED_RECEIPT_ISSUED_AT_MS,
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
                    "issuedAtMs": PINNED_RECEIPT_ISSUED_AT_MS,
                    "signature": { "$bytes": BASE64.encode(signed.signature) }
                }
            })));
        }

        if url.contains("com.atproto.repo.getRecord") {
            let mut q = std::collections::BTreeMap::new();
            if let Some((_, qs)) = url.split_once('?') {
                for pair in qs.split('&').filter(|s| !s.is_empty()) {
                    if let Some((k, v)) = pair.split_once('=') {
                        q.insert(k.to_string(), urlencoding_decode(v));
                    }
                }
            }
            let repo = q.get("repo").map(String::as_str).unwrap_or("");
            let collection = q.get("collection").map(String::as_str).unwrap_or("");
            let rkey = q.get("rkey").map(String::as_str).unwrap_or("");
            let found = self
                .pds_records
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.repo == repo && r.collection == collection && r.rkey == rkey)
                .map(|r| {
                    (
                        r.repo.clone(),
                        r.collection.clone(),
                        r.rkey.clone(),
                        r.value.clone(),
                    )
                });
            if let Some((repo, collection, rkey, value)) = found {
                return Ok(json_ok(serde_json::json!({
                    "uri": format!("at://{repo}/{collection}/{rkey}"),
                    "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "value": value,
                })));
            }
            return Ok(json_resp(
                404,
                serde_json::json!({ "error": "RecordNotFound" }),
            ));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.") {
            let mut q = std::collections::BTreeMap::new();
            if let Some((_, qs)) = url.split_once('?') {
                for pair in qs.split('&').filter(|s| !s.is_empty()) {
                    if let Some((k, v)) = pair.split_once('=') {
                        let decoded = urlencoding_decode(v);
                        q.insert(k.to_string(), decoded);
                    }
                }
            }
            if url.contains("/xrpc/blue.catbird.labyrinth.publishEpochHead") {
                let body_json: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                        .unwrap_or_default();
                let did = body_json["epoch"]["did"]
                    .as_str()
                    .unwrap_or("did:plc:aliceaaaaaaaaaaaaaaaaaaa")
                    .to_string();
                let epoch = body_json["epoch"].clone();
                let epoch_num = |val: &serde_json::Value| {
                    val.get("epochNumber")
                        .or_else(|| val.get("seq"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or_default()
                };
                let target_num = epoch_num(&epoch);
                let mut epochs = self.labyrinth_epochs.lock().unwrap();
                let chain = epochs.entry(did).or_default();
                chain.retain(|known| epoch_num(known) != target_num);
                chain.push(epoch);
                chain.sort_by_key(epoch_num);
                return Ok(json_ok(serde_json::json!({})));
            }
            if url.contains("/xrpc/blue.catbird.labyrinth.getEpochHead") {
                let did = q.get("did").cloned().unwrap_or_default();
                if let Some(chain) = self
                    .labyrinth_epochs
                    .lock()
                    .unwrap()
                    .get(&did)
                    .filter(|c| !c.is_empty())
                    .cloned()
                {
                    let latest = chain.last().unwrap().clone();
                    return Ok(json_ok(
                        serde_json::json!({ "epoch": latest, "chain": chain }),
                    ));
                }
                return Ok(json_resp(
                    404,
                    serde_json::json!({ "error": "EpochNotFound" }),
                ));
            }
            if url.contains("/xrpc/blue.catbird.labyrinth.getChatDeviceKeys") {
                let did = q.get("did").cloned().unwrap_or_default();
                let items = self
                    .chat_device_pubkeys
                    .lock()
                    .unwrap()
                    .get(&did)
                    .cloned()
                    .unwrap_or_default();
                return Ok(json_ok(serde_json::json!({ "items": items })));
            }
        }

        Ok(json_ok(serde_json::json!({
            "uri": "at://did:plc:aliceaaaaaaaaaaaaaaaaaaa/record/1",
            "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })))
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
        #[cfg(feature = "labyrinth")]
        {
            self.archive_auth
                .execute(&request, |request| self.execute_http_raw(request))
        }
        #[cfg(not(feature = "labyrinth"))]
        {
            self.execute_http_raw(&request)
        }
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

fn urlencoding_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_s) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_s, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn default_test_scopes() -> Vec<String> {
    REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn hash_recorded_calls(calls: &[RecordedHttpCall]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(calls.len() as u64).to_le_bytes());
    for call in calls {
        hasher.update(&(call.method.len() as u64).to_le_bytes());
        hasher.update(call.method.as_bytes());
        hasher.update(&(call.url.len() as u64).to_le_bytes());
        hasher.update(call.url.as_bytes());
        hasher.update(&(call.headers.len() as u64).to_le_bytes());
        for h in &call.headers {
            hasher.update(&(h.name.len() as u64).to_le_bytes());
            hasher.update(h.name.as_bytes());
            hasher.update(&(h.value.len() as u64).to_le_bytes());
            hasher.update(h.value.as_bytes());
        }
        match &call.body {
            Some(body) => {
                hasher.update(&[1]);
                hasher.update(&(body.len() as u64).to_le_bytes());
                hasher.update(body);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    hasher.finalize().to_hex().to_string()
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
    let c1 = FixedStepClock::new(PINNED_START_MS, 25);
    let c2 = FixedStepClock::new(PINNED_START_MS, 25);
    assert_eq!(c1.now_ms(), 1_762_000_000_000);
    assert_eq!(c1.now_ms(), 1_762_000_000_025);
    assert_eq!(c1.now_ms(), 1_762_000_000_050);

    assert_eq!(c2.now_ms(), 1_762_000_000_000);
    assert_eq!(c2.now_ms(), 1_762_000_000_025);
    assert_eq!(c2.now_ms(), 1_762_000_000_050);
}

#[test]
fn two_seeded_clients_produce_byte_identical_enrollment_and_ciphertexts() {
    let run = |seed: u64| -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn SimClock> = Arc::new(FixedStepClock::new(1_762_000_000_000, 10));
        let entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"alice-dev-1"));
        let hooks = SimClientHooks::new(clock, entropy);

        let cfg = test_client_config(dir.path().to_string_lossy().into_owned());
        let keystore = Arc::new(DeterministicKeyStore::new());
        let transport = Arc::new(DeterministicMockTransport::new(hooks.clock.clone()));
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
        #[cfg(feature = "labyrinth")]
        assert!(transport.archive_auth.committed_space_write_count() > 0);

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

    let out_a = run(8_492_014);
    let out_b = run(8_492_014);
    let out_c = run(8_492_015);
    assert_eq!(out_a, out_b);
    assert_ne!(out_a, out_c);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&(out_a.0.len() as u64).to_le_bytes());
    hasher.update(&out_a.0);
    hasher.update(&(out_a.1.len() as u64).to_le_bytes());
    hasher.update(&out_a.1);
    hasher.update(&(out_a.2.len() as u64).to_le_bytes());
    hasher.update(&out_a.2);
    hasher.update(&(out_a.3.len() as u64).to_le_bytes());
    hasher.update(out_a.3.as_bytes());
    let digest_hex = hasher.finalize().to_hex().to_string();
    assert_eq!(
        digest_hex, "2eede06b61413adc5cc7bda913feb93f2d5313d1c0f101621efca6f87747c99b",
        "cross-process enrollment + X-Wing ciphertext blake3 digest drifted"
    );
}

#[test]
fn two_seeded_clients_produce_identical_full_http_wire_transcripts_and_enforce_i6() {
    let run_transcript = |seed: u64| -> Vec<RecordedHttpCall> {
        let dir = tempfile::tempdir().unwrap();
        let hooks = SimClientHooks::new(
            Arc::new(FixedStepClock::new(PINNED_START_MS, 25)),
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"wire-transcript")),
        );
        let cfg = test_client_config(dir.path().to_string_lossy().into_owned());
        let keystore = Arc::new(DeterministicKeyStore::new());
        let transport = Arc::new(DeterministicMockTransport::new(hooks.clock.clone()));
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
        #[cfg(feature = "labyrinth")]
        {
            assert!(transport.archive_auth.committed_space_write_count() > 0);
            let calls = transport.recorded_calls();
            // A sender flush creates the MEK and writes its batch with one conversation-Space
            // applyWrites to the writer's PDS; Space reads (and their home-DS relays) happen
            // only when loading history (`find_meks`/`load_*`), never on a solo-group flush.
            assert!(!calls
                .iter()
                .any(|call| call.url.contains("/xrpc/blue.catbird.chat.relaySpace")));
            assert!(calls.iter().any(|call| {
                call.url.ends_with("/xrpc/com.atproto.space.applyWrites")
                    && call.body.as_deref().is_some_and(|body| {
                        String::from_utf8_lossy(body)
                            .contains("/space/blue.catbird.labyrinth.conversation/")
                    })
            }));
        }
        transport.recorded_calls()
    };

    let t1 = run_transcript(99_101);
    let t2 = run_transcript(99_101);
    let t3 = run_transcript(99_102);
    assert!(!t1.is_empty());
    assert_eq!(t1, t2);
    assert_ne!(t1, t3);
    // Moved in Task 4 R1 (two separate processes agree; seed 99_102 gives 96be9104…): the flush
    // is the native LabyrinthSession sealing the I13 `ArchivedReceipt { signed, generation }`
    // against the account-bound native Space host, and a solo-group flush makes no Space reads.
    // Moved again for seed 2323: every `sendMessage` body now signs its `sendCounter`.
    // Moved again in R4 (two separate processes agree): enrollment checks the `enrollDevice`
    // answer before any PDS write, so the device and declaration `putRecord`s now follow
    // `enrollDevice` on the wire instead of preceding it.
    // Moved in Task 5: creation now verifies its mandatory I13 control receipt, including the
    // receipt authority lookup, before accepting the sequenced transition.
    // Moved again in Task 5: confirmed sendCounter persistence adds a clock tick before Labyrinth flush.
    // Moved in Wave 2 (two separate processes agree): pre-flush MLS enrollment + X-Wing ciphertext
    // digest (`2eede06b61413adc5cc7bda913feb93f2d5313d1c0f101621efca6f87747c99b` above) is
    // unchanged, while `flush_labyrinth_queue()` now speaks Nov-12 Spaces (`listWriters` +
    // RFC 9421 `Accept-Signature` in `native_archive_space.rs`) and `EpochPublic` / `mailboxKeys`
    // carry `membersHash`.
    // Moved again (two separate processes agree): DID documents resolve only from PLC or the
    // did:web host's did.json, never through the account PDS or the DS endpoint.
    assert_eq!(
        hash_recorded_calls(&t1),
        "fa90714947b1a703d085dd4d0cf7865aa07c481863313acbab4dde8ddc14c482",
        "cross-process HTTP wire transcript blake3 digest drifted"
    );
}

#[cfg(feature = "labyrinth")]
#[test]
fn two_seeded_clients_produce_byte_identical_recovery_code_and_mailbox_epoch_writes() {
    let run_mailbox_flow = |seed: u64| -> (String, String, Vec<Vec<u8>>) {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let shared_clock: Arc<dyn SimClock> = Arc::new(FixedStepClock::new(PINNED_START_MS, 10));
        let hooks1 = SimClientHooks::new(
            shared_clock.clone(),
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"labyrinth-mailbox")),
        );
        let hooks2 = SimClientHooks::new(
            shared_clock.clone(),
            Arc::new(ChaChaSimEntropy::from_seed(seed, b"labyrinth-mailbox-dev2")),
        );
        let cfg1 = test_client_config(dir1.path().to_string_lossy().into_owned());
        let mut cfg2 = test_client_config(dir2.path().to_string_lossy().into_owned());
        cfg2.device_id = "00000000-0000-4000-8000-000000000002".to_string();
        let keystore1 = Arc::new(DeterministicKeyStore::new());
        let keystore2 = Arc::new(DeterministicKeyStore::new());
        let transport = Arc::new(DeterministicMockTransport::new(shared_clock));
        let client =
            CatbirdMlsClient::open_with_hooks(cfg1, keystore1, transport.clone(), None, hooks1)
                .unwrap();
        transport.attach_client(&client);
        let client2 =
            CatbirdMlsClient::open_with_hooks(cfg2, keystore2, transport.clone(), None, hooks2)
                .unwrap();

        client.enroll_device(&default_test_scopes()).unwrap();

        // Advance local Labyrinth epoch via live 2-device hybrid PQ CPace + ML-KEM-768 OTC pairing
        // over `OwnerMailbox` (`otcSession`) so `complete_otc_pairing` + `setup_recovery_code`
        // publish Device, Epoch(0), rotated Epoch(1), and `VirtualDevice` deterministically.
        let offer = client.initiate_otc_pairing().unwrap();
        let initiated = client2.start_otc_pairing(&offer.six_digit_code).unwrap();
        client
            .respond_otc_pairing(&initiated.session_id_hex, Some(&offer.six_digit_code))
            .unwrap();
        let completion = client2.complete_otc_pairing(&offer.six_digit_code).unwrap();
        assert!(completion.new_epoch_seq >= 1);

        let recovery_code = client2.setup_recovery_code().unwrap();

        let apply_writes_bodies: Vec<Vec<u8>> = transport
            .recorded_calls()
            .into_iter()
            .filter(|c| c.url.contains("/xrpc/com.atproto.space.applyWrites"))
            .map(|c| c.body.expect("applyWrites body present"))
            .collect();
        assert!(apply_writes_bodies.len() >= 4);
        assert!(transport.archive_auth.committed_space_write_count() > 0);

        (offer.formatted_code, recovery_code, apply_writes_bodies)
    };

    let m1 = run_mailbox_flow(8_492_014);
    let m2 = run_mailbox_flow(8_492_014);
    let m3 = run_mailbox_flow(8_492_015);
    assert_eq!(m1, m2);
    assert_ne!(m1, m3);

    let mut hasher = blake3::Hasher::new();
    hasher.update(m1.0.as_bytes());
    hasher.update(m1.1.as_bytes());
    for body in &m1.2 {
        hasher.update(&(body.len() as u64).to_le_bytes());
        hasher.update(body);
    }
    // Moved in Wave 2 (two separate processes agree): live 2-device CPace+ML-KEM-768 OTC pairing
    // over `OwnerMailbox` (`otcSession`), Nov-12 Spaces `Accept-Signature` + `listWriters`, and
    // `EpochPublic` / `mailboxKeys` `membersHash`.
    // Moved again with strict DID resolution (two separate processes agree; the base revision
    // reproduced the previous digest).
    assert_eq!(
        hasher.finalize().to_hex().to_string(),
        "ef378930c3db7a79fa6a0f0bb0b66558adb0fa6ca2d3886ad1a2d2ec9c1760a9",
        "cross-process Labyrinth recovery code + EpochPublic XEdDSA applyWrites digest drifted"
    );
}

#[test]
fn seeded_openmls_crypto_provider_draws_strictly_from_sim_entropy() {
    // Pure compile-time constants — zero host wall-clock reads.
    let creator_lifetime = Lifetime::init(PINNED_START_SECS - 60, PINNED_START_SECS + 30 * 86_400);
    let joiner_lifetime = Lifetime::init(PINNED_START_SECS - 60, PINNED_FAR_NOT_AFTER_SECS);
    let run_openmls = |seed: u64| -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
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
            .key_package_lifetime(joiner_lifetime)
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
            .lifetime(creator_lifetime)
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

        let (commit, welcome_out, _) = group
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

        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
        let msg_bytes = msg.tls_serialize_detached().unwrap();

        // Bob stages Welcome against `PINNED_START_SECS` and decrypts Alice's X-Wing message.
        let MlsMessageBodyIn::Welcome(welcome_in) =
            MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                .unwrap()
                .extract()
        else {
            panic!("expected Welcome");
        };
        let join_cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mut bob_group = build_staged_welcome_at(
            &bob_provider,
            &join_cfg,
            welcome_in,
            None,
            PINNED_START_SECS,
        )
        .unwrap()
        .into_group(&bob_provider)
        .unwrap();
        let proto_msg = MlsMessageIn::tls_deserialize_exact(&msg_bytes)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let processed = bob_group.process_message(&bob_provider, proto_msg).unwrap();
        let ProcessedMessageContent::ApplicationMessage(app_msg) = processed.into_content() else {
            panic!("expected ApplicationMessage");
        };
        let decrypted = app_msg.into_bytes();
        assert_eq!(decrypted, b"pq welcome + msg");

        (
            bob_kp_bytes,
            welcome_bytes,
            commit
                .tls_serialize_detached()
                .unwrap()
                .into_iter()
                .chain(msg_bytes)
                .collect(),
            decrypted,
        )
    };

    let o1 = run_openmls(4242);
    let o2 = run_openmls(4242);
    let o3 = run_openmls(4243);
    assert_eq!(o1, o2);
    assert_ne!(o1, o3);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&o1.0);
    hasher.update(&o1.1);
    hasher.update(&o1.2);
    hasher.update(&o1.3);
    assert_eq!(
        hasher.finalize().to_hex().to_string(),
        "b4db2ae80e97896e6e9e8c3bc9481e7818394db7339476ff4a3c1eb1a2d880d2",
        "cross-process OpenMLS X-Wing Welcome + ciphertext digest drifted"
    );
}

#[test]
fn sim_clock_virtual_time_travel_validates_and_expires_welcomes() {
    let suite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let join_cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mint_welcome = |seed: u64| {
        let alice_provider = SeededOpenMlsCryptoProvider::new(Arc::new(
            ChaChaSimEntropy::from_seed(seed, b"tt-alice"),
        ));
        let bob_provider = SeededOpenMlsCryptoProvider::new(Arc::new(ChaChaSimEntropy::from_seed(
            seed, b"tt-bob",
        )));
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
            .key_package_lifetime(Lifetime::init(
                PINNED_START_SECS - 60,
                PINNED_FAR_NOT_AFTER_SECS,
            ))
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

        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .lifetime(Lifetime::init(
                PINNED_START_SECS - 60,
                PINNED_START_SECS + 29 * 86_400,
            ))
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
        let bob_kp_bytes = MlsMessageOut::from(bob_kp.key_package().clone())
            .tls_serialize_detached()
            .unwrap();
        let (_commit, welcome_out, _) = group
            .add_members(
                &alice_provider,
                &alice_signer,
                &[bob_kp.key_package().clone()],
            )
            .unwrap();
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
        let MlsMessageBodyIn::Welcome(welcome_in) =
            MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                .unwrap()
                .extract()
        else {
            panic!("expected Welcome");
        };
        (bob_provider, bob_kp_bytes, welcome_in)
    };

    // 1. Rewinding SimClock before `not_before` rejects both KP and Welcome with `NotValidYet`.
    let (bob_early, kp_bytes_early, welcome_early) = mint_welcome(5150);
    let MlsMessageBodyIn::KeyPackage(kp_in_early) =
        MlsMessageIn::tls_deserialize_exact(&kp_bytes_early)
            .unwrap()
            .extract()
    else {
        panic!("expected KeyPackage");
    };
    assert!(matches!(
        validate_key_package_at(
            kp_in_early,
            bob_early.crypto(),
            ProtocolVersion::Mls10,
            PINNED_START_SECS - 120
        ),
        Err(KeyPackageVerifyError::LifetimeError(LifetimeError::NotValidYet { now, .. }))
            if now == PINNED_START_SECS - 120
    ));
    let err_early = build_staged_welcome_at(
        &bob_early,
        &join_cfg,
        welcome_early,
        None,
        PINNED_START_SECS - 120,
    )
    .expect_err("Welcome before SimClock not_before must fail");
    assert!(matches!(
        err_early,
        WelcomeError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
            LifetimeError::NotValidYet { now, .. }
        )) if now == PINNED_START_SECS - 120
    ));

    // 2. Advancing SimClock to `+7 days` succeeds cleanly.
    let (bob_ok, _kp_bytes_ok, welcome_ok) = mint_welcome(5150);
    let _joined = build_staged_welcome_at(
        &bob_ok,
        &join_cfg,
        welcome_ok,
        None,
        PINNED_START_SECS + 7 * 86_400,
    )
    .expect("Welcome at +7d SimClock must succeed")
    .into_group(&bob_ok)
    .unwrap();

    // 3. Advancing SimClock past `not_after` rejects both KP and Welcome with `Expired`.
    let (bob_exp, kp_bytes_exp, welcome_exp) = mint_welcome(5150);
    let MlsMessageBodyIn::KeyPackage(kp_in_exp) =
        MlsMessageIn::tls_deserialize_exact(&kp_bytes_exp)
            .unwrap()
            .extract()
    else {
        panic!("expected KeyPackage");
    };
    assert!(matches!(
        validate_key_package_at(
            kp_in_exp,
            bob_exp.crypto(),
            ProtocolVersion::Mls10,
            PINNED_FAR_NOT_AFTER_SECS + 86_400
        ),
        Err(KeyPackageVerifyError::LifetimeError(LifetimeError::Expired { now, .. }))
            if now == PINNED_FAR_NOT_AFTER_SECS + 86_400
    ));
    let err_exp = build_staged_welcome_at(
        &bob_exp,
        &join_cfg,
        welcome_exp,
        None,
        PINNED_FAR_NOT_AFTER_SECS + 86_400,
    )
    .expect_err("Welcome past SimClock not_after must fail");
    assert!(matches!(
        err_exp,
        WelcomeError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
            LifetimeError::Expired { now, .. }
        )) if now == PINNED_FAR_NOT_AFTER_SECS + 86_400
    ));
}

#[cfg(feature = "sim")]
#[test]
fn sim_clock_virtual_time_travel_validates_and_expires_29_day_key_package() {
    let suite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let clock = FixedStepClock::new(PINNED_START_MS, 10);
    let t0 = clock.now_secs();
    assert_eq!(t0, PINNED_START_SECS);

    let provider = SeededOpenMlsCryptoProvider::new(Arc::new(ChaChaSimEntropy::from_seed(
        6060,
        b"kp-time-travel",
    )));
    let (sk, pk) = provider
        .crypto()
        .signature_key_gen(suite.signature_algorithm())
        .unwrap();
    let signer = SignatureKeyPair::from_raw(suite.signature_algorithm(), sk, pk);
    signer.store(provider.storage()).unwrap();

    // Narrow 29-day KeyPackage minted in Nov 2025 (`1_762_000_000`), already expired on real wall-clock!
    let kp_bundle = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(t0 - 60, t0 + 29 * 86_400))
        .leaf_node_capabilities(Capabilities::builder().ciphersuites(vec![suite]).build())
        .build(
            suite,
            &provider,
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(b"did:plc:bob#dev1".to_vec()).into(),
                signature_key: signer.public().into(),
            },
        )
        .unwrap();
    let kp_bytes = MlsMessageOut::from(kp_bundle.key_package().clone())
        .tls_serialize_detached()
        .unwrap();
    let parse_kp_in = |bytes: &[u8]| -> KeyPackageIn {
        let MlsMessageBodyIn::KeyPackage(kp_in) = MlsMessageIn::tls_deserialize_exact(bytes)
            .unwrap()
            .extract()
        else {
            panic!("expected KeyPackage");
        };
        kp_in
    };

    // Valid at `t0` (`2025-11-01`).
    validate_key_package_at(
        parse_kp_in(&kp_bytes),
        provider.crypto(),
        ProtocolVersion::Mls10,
        clock.now_secs(),
    )
    .expect("29-day KP must validate at SimClock t0");

    // Advance SimClock by `+7 days`: still valid.
    clock.advance_ms(7 * 86_400 * 1_000);
    validate_key_package_at(
        parse_kp_in(&kp_bytes),
        provider.crypto(),
        ProtocolVersion::Mls10,
        clock.now_secs(),
    )
    .expect("29-day KP must validate at SimClock t0 + 7d");

    // Advance SimClock by another `+23 days` (`+30 days` total): deterministically expired!
    clock.advance_ms(23 * 86_400 * 1_000);
    let err = validate_key_package_at(
        parse_kp_in(&kp_bytes),
        provider.crypto(),
        ProtocolVersion::Mls10,
        clock.now_secs(),
    )
    .expect_err("29-day KP must expire at SimClock t0 + 30d");
    assert!(matches!(
        err,
        KeyPackageVerifyError::LifetimeError(LifetimeError::Expired { not_after, now })
            if not_after == t0 + 29 * 86_400 && now >= t0 + 30 * 86_400
    ));

    // Cryptographic signature tampering MUST still fail with `InvalidSignature` even at valid `t0`.
    let mut tampered = kp_bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let sig_err = validate_key_package_at(
        parse_kp_in(&tampered),
        provider.crypto(),
        ProtocolVersion::Mls10,
        t0,
    )
    .expect_err("tampered KP signature must be rejected");
    assert!(matches!(sig_err, KeyPackageVerifyError::InvalidSignature));
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
fn list_requests_breaks_equal_updated_at_ties_by_request_id_whatever_the_insertion_order() {
    use catbird_mls::storage::RequestRow;
    // (request_id, consent, updated_at_ms): newest first, then request_id ascending.
    let rows = [
        ("r0", "incomingPending", 100),
        ("r1", "incoming_pending", 100),
        ("r2", "outgoingPending", 100),
        ("r3", "incomingPending", 100),
        ("r4", "incoming_pending", 200),
        ("r5", "incomingPending", 200),
        ("r6", "accepted", 100),
        ("r7", "accepted", 100),
        ("r8", "accepted", 100),
    ];
    let ids = |v: Vec<RequestRow>| v.into_iter().map(|r| r.request_id).collect::<Vec<_>>();
    let mut order: Vec<usize> = (0..rows.len()).collect();
    let mut seed = 0x9e37_79b9_u32;
    for round in 0..8 {
        if round == 1 {
            order.reverse();
        } else if round > 1 {
            // Fixed-seed Fisher-Yates: varied, reproducible insertion orders.
            for i in (1..order.len()).rev() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                order.swap(i, (seed >> 8) as usize % (i + 1));
            }
        }
        let driver = SqlDriver::open_in_memory_for_test().unwrap();
        driver
            .write_tx(|tx| {
                for &i in &order {
                    let (id, consent, at) = rows[i];
                    tx.upsert_request(&RequestRow {
                        request_id: id.into(),
                        conversation_id: format!("c-{id}"),
                        sender_did: "did:plc:sender".into(),
                        recipient_did: "did:plc:recipient".into(),
                        consent: consent.into(),
                        first_message_id: None,
                        first_message_archived: false,
                        payload_json: "{}".into(),
                        expires_at_ms: 0,
                        updated_at_ms: at,
                    })?;
                }
                Ok(())
            })
            .unwrap();
        let list =
            |filter: Option<&str>| ids(driver.read_tx(|tx| tx.list_requests(filter)).unwrap());
        let ctx = format!("insertion order {order:?}");
        assert_eq!(
            list(None),
            ["r4", "r5", "r0", "r1", "r2", "r3", "r6", "r7", "r8"],
            "{ctx}"
        );
        assert_eq!(
            list(Some("pending")),
            ["r4", "r5", "r0", "r1", "r2", "r3"],
            "{ctx}"
        );
        assert_eq!(
            list(Some("incomingPending")),
            ["r4", "r5", "r0", "r1", "r3"],
            "{ctx}"
        );
        assert_eq!(list(Some("accepted")), ["r6", "r7", "r8"], "{ctx}");
    }
}

#[cfg(feature = "legacy-orchestrator")]
#[tokio::test]
async fn stored_conversations_list_breaks_equal_updated_at_ties_by_conversation_id() {
    use catbird_mls::orchestrator::MLSStorageBackend;
    use catbird_mls::storage::ConversationRow;
    let rows = [
        ("c3", 100),
        ("c0", 100),
        ("c4", 200),
        ("c2", 100),
        ("c1", 200),
    ];
    let mut order: Vec<usize> = (0..rows.len()).collect();
    let mut seed = 0x0bad_5eed_u32;
    for round in 0..8 {
        if round == 1 {
            order.reverse();
        } else if round > 1 {
            for i in (1..order.len()).rev() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                order.swap(i, (seed >> 8) as usize % (i + 1));
            }
        }
        let driver = SqlDriver::open_in_memory_for_test().unwrap();
        driver
            .write_tx(|tx| {
                for &i in &order {
                    let (cid, at) = rows[i];
                    tx.upsert_conversation(&ConversationRow {
                        conversation_id: cid.into(),
                        group_id: vec![i as u8; 16],
                        generation: 0,
                        epoch: 0,
                        last_seq: 0,
                        sequencer_did: String::new(),
                        space_uri: None,
                        title: None,
                        unread_count: 0,
                        updated_at_ms: at,
                    })?;
                }
                Ok(())
            })
            .unwrap();
        let ids: Vec<String> = MLSStorageBackend::list_conversations(&driver, "did:plc:alice")
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.conversation_id)
            .collect();
        assert_eq!(
            ids,
            ["c1", "c4", "c0", "c2", "c3"],
            "insertion order {order:?}"
        );
    }
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
        Arc::new(FixedStepClock::new(PINNED_START_MS, 15)),
        Arc::new(ChaChaSimEntropy::from_seed(77_777, b"buggify-sites")),
    );
    let cfg = test_client_config(dir.path().to_string_lossy().into_owned());
    let keystore = Arc::new(DeterministicKeyStore::new());
    let transport = Arc::new(DeterministicMockTransport::new(hooks.clock.clone()));
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

    // Fault after HTTP 2xx, before promoting the durable send journal into message/archive rows.
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
        "the archive queue must not commit before receipt-verified send finalization"
    );
    let pending_sends = client
        .db()
        .read_tx(|tx| {
            Ok(tx
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM pending_ops WHERE op_kind = 'application_send'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap())
        })
        .unwrap();
    assert_eq!(
        pending_sends, 1,
        "crash recovery material must already be durable"
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
