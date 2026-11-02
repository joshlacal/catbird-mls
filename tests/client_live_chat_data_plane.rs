//! Deep live data-plane & sync engine tests for `CatbirdMlsClient` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`, `C33`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use catbird_mls::client::{
    CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpHeader, PlatformHttpRequest,
    PlatformHttpResponse, PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::groups::lifecycle::MemberRole;
use catbird_mls::MLSError;
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};

const DS_DID: &str = "did:web:ds.catbird.blue";
const DS_URL: &str = "https://ds.catbird.blue";
const PDS_URL: &str = "https://pds.catbird.blue";
const ALICE_DID: &str = "did:plc:alicecleanuseraaaaaaaaaa";
const BOB_DID: &str = "did:plc:bobcleanuserbbbbbbbbbbbb";
const EVE_DID: &str = "did:plc:evecleanusereeeeeeeeeeee";

struct MemKeyStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemKeyStore {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl PlatformKeyStore for MemKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let mut g = self.map.lock().unwrap();
        Ok(g.entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| {
                let mut k = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut k);
                k
            })
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

struct MockDsState {
    receipt_sk: P256SigningKey,
    tamper_next_receipt: bool,
    omit_next_receipt: bool,
    empty_stub_next_send: bool,
    lose_next_send_response: bool,
    fail_next_entries: bool,
    stale_next_submit_transition: bool,
    // PDS records: (repo, collection, rkey) -> value
    pds_records: BTreeMap<(String, String, String), Value>,
    // Direct request published keys: actor_did -> (device_id, key_package_val, grant_val)
    dr_keys: BTreeMap<String, Vec<(String, Value, Value)>>,
    // Conversation KPs: (actor_did, device_id) -> Vec<Value>
    convo_kps: BTreeMap<(String, String), Vec<Value>>,
    // Conversations: cid -> state JSON
    conversations: BTreeMap<String, Value>,
    // Conversation entries: cid -> Vec<Value>
    entries: BTreeMap<String, Vec<Value>>,
    // Pending welcomes: (did, device_id) -> Vec<Value>
    pending_welcomes: BTreeMap<(String, String), Vec<Value>>,
    // Retained leaf recoveries: conversation_id -> Vec<leafRecoveryView>.
    leaf_recoveries: BTreeMap<String, Vec<Value>>,
    // Acked welcomes
    acked_welcomes: Vec<String>,
    // Acked entry watermarks: (cid, device_id) -> i64
    acked_watermarks: BTreeMap<(String, String), i64>,
    // Space applyWrites records
    space_writes: Vec<Value>,
}

struct SharedMockDs {
    inner: Mutex<MockDsState>,
}

impl SharedMockDs {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(MockDsState {
                receipt_sk: P256SigningKey::random(&mut rand::rngs::OsRng),
                tamper_next_receipt: false,
                omit_next_receipt: false,
                empty_stub_next_send: false,
                lose_next_send_response: false,
                fail_next_entries: false,
                stale_next_submit_transition: false,
                pds_records: BTreeMap::new(),
                dr_keys: BTreeMap::new(),
                convo_kps: BTreeMap::new(),
                conversations: BTreeMap::new(),
                entries: BTreeMap::new(),
                pending_welcomes: BTreeMap::new(),
                leaf_recoveries: BTreeMap::new(),
                acked_welcomes: Vec::new(),
                acked_watermarks: BTreeMap::new(),
                space_writes: Vec::new(),
            }),
        })
    }

    fn receipt_jwk_did_doc(&self) -> Value {
        let g = self.inner.lock().unwrap();
        let pt = g.receipt_sk.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(pt.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(pt.y().unwrap());
        json!({
            "id": DS_DID,
            "verificationMethod": [{
                "id": format!("{DS_DID}#mls-receipt-1"),
                "type": "JsonWebKey2020",
                "controller": DS_DID,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y
                }
            }]
        })
    }
}

fn ok_json(val: Value) -> Result<PlatformHttpResponse, MLSError> {
    Ok(PlatformHttpResponse {
        status: 200,
        headers: vec![PlatformHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body: serde_json::to_vec(&val).unwrap(),
    })
}

fn pct_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex_str, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_map(url: &str) -> BTreeMap<String, String> {
    let Some((_, q)) = url.split_once('?') else {
        return BTreeMap::new();
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((pct_decode(k), pct_decode(v)))
        })
        .collect()
}

impl PlatformTransport for SharedMockDs {
    fn execute_http(&self, req: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let url = req.url.as_str();
        let q = query_map(url);
        let body_json: Value = req
            .body
            .as_deref()
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_else(|| json!({}));

        if url.ends_with("/.well-known/did.json")
            || (url.contains("/xrpc/com.atproto.identity.resolveDid")
                && q.get("did").map(String::as_str) == Some(DS_DID))
        {
            return ok_json(self.receipt_jwk_did_doc());
        }

        if url.contains("/xrpc/com.atproto.identity.resolveDid") {
            let did = q.get("did").cloned().unwrap_or_default();
            return ok_json(json!({
                "didDoc": {
                    "id": did,
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": PDS_URL
                    }]
                }
            }));
        }

        let mut g = self.inner.lock().unwrap();

        if url.contains("/xrpc/com.atproto.repo.putRecord") {
            let repo = body_json["repo"].as_str().unwrap_or_default().to_string();
            let coll = body_json["collection"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let rkey = body_json["rkey"].as_str().unwrap_or_default().to_string();
            let rec = body_json["record"].clone();
            g.pds_records
                .insert((repo.clone(), coll.clone(), rkey.clone()), rec);
            return ok_json(json!({
                "uri": format!("at://{repo}/{coll}/{rkey}"),
                "cid": "bafyreimock"
            }));
        }

        if url.contains("/xrpc/com.atproto.repo.listRecords") {
            let repo = q.get("repo").cloned().unwrap_or_default();
            let coll = q.get("collection").cloned().unwrap_or_default();
            let records: Vec<Value> = g
                .pds_records
                .iter()
                .filter(|((r, c, _), _)| r == &repo && c == &coll)
                .map(|((r, c, rk), val)| {
                    json!({
                        "uri": format!("at://{r}/{c}/{rk}"),
                        "cid": "bafyreimock",
                        "value": val
                    })
                })
                .collect();
            return ok_json(json!({ "records": records }));
        }

        if url.contains("/xrpc/com.atproto.space.getSpace")
            || url.contains("/xrpc/com.atproto.space.putSpace")
        {
            return ok_json(json!({ "uri": q.get("space").cloned().unwrap_or_default() }));
        }

        if url.contains("/xrpc/com.atproto.space.uploadBlob") {
            let digest = hex::encode(Sha256::digest(req.body.as_deref().unwrap_or(&[])));
            return ok_json(json!({
                "blob": {
                    "$type": "blob",
                    "ref": { "$link": format!("bafkrei{}", &digest[..32]) },
                    "mimeType": "application/octet-stream",
                    "size": req.body.as_ref().map(|b| b.len()).unwrap_or(0)
                }
            }));
        }

        if url.contains("/xrpc/com.atproto.space.applyWrites") {
            g.space_writes.push(body_json.clone());
            return ok_json(json!({
                "commit": { "rev": "3kzzzzzzzzzzz", "cid": "bafyreispacecommit" }
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.enrollDevice") {
            let b = &body_json["signedRequest"]["body"];
            let did = b["actorDid"].as_str().unwrap().to_string();
            let dev = b["deviceId"].as_str().unwrap().to_string();
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            g.convo_kps.entry((did, dev)).or_default().extend(kps);
            return ok_json(json!({
                "device": { "authGeneration": 1 }
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.replenishKeyPackages") {
            let b = &body_json["signedRequest"]["body"];
            let did = b["actorDid"].as_str().unwrap().to_string();
            let dev = b["actorDeviceId"].as_str().unwrap().to_string();
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            g.convo_kps.entry((did, dev)).or_default().extend(kps);
            return ok_json(json!({ "acceptedCount": 4 }));
        }

        if url.contains("/xrpc/blue.catbird.chat.publishDirectRequestKeys") {
            let sr = &body_json["signedRequest"];
            let b = &sr["body"];
            let did = b["actorDid"].as_str().unwrap().to_string();
            let dev = b["actorDeviceId"].as_str().unwrap().to_string();
            let mut list = Vec::new();
            for item in b["keys"].as_array().cloned().unwrap_or_default() {
                list.push((
                    dev.clone(),
                    item["keyPackage"].clone(),
                    item["grant"].clone(),
                ));
            }
            g.dr_keys.insert(did, list);
            return ok_json(json!({ "published": true }));
        }

        if url.contains("/xrpc/blue.catbird.chat.prepareDirectRequest") {
            let b = &body_json["signedRequest"]["body"];
            let recipient_did = b["recipientDid"].as_str().unwrap().to_string();
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let avail = g
                .dr_keys
                .get_mut(&recipient_did)
                .ok_or_else(|| MLSError::Internal(format!("no DR keys for {recipient_did}")))?;
            let (dev_id, kp, grant) = avail.pop().expect("at least 1 DR key");
            let prep_digest = STANDARD.encode(Sha256::digest(cid.as_bytes()));
            return ok_json(json!({
                "outcome": {
                    "conversationId": cid,
                    "authorityDid": DS_DID,
                    "receiptKeyId": "#mls-receipt-1",
                    "preparationDigest": { "$bytes": prep_digest },
                    "selectedDevices": [{
                        "actorDid": recipient_did,
                        "actorDeviceId": dev_id,
                        "keyPackage": kp,
                        "grant": grant,
                    }]
                }
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.publishDirectRequest") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let coords = b["next"].clone();
            g.conversations.insert(
                cid.clone(),
                json!({
                    "conversationKind": "direct",
                    "sequencerDid": DS_DID,
                    "coordinates": coords,
                    "participants": [
                        { "userDid": b["actorDid"], "status": "active", "role": "admin" },
                        { "userDid": b["recipientDid"], "status": "pending", "role": "member" }
                    ]
                }),
            );
            g.entries.entry(cid).or_default().push(json!({
                "$type": "blue.catbird.chat.defs#directRequestEntry",
                "seq": 1,
                "sequencerDid": DS_DID,
                "signedRequest": sr,
            }));
            return ok_json(json!({ "seq": 1 }));
        }

        if url.contains("/xrpc/blue.catbird.chat.createConversation") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let coords = b["next"].clone();
            let parts = b["manifest"]["participants"].clone();
            g.conversations.insert(
                cid.clone(),
                json!({
                    "conversationKind": "group",
                    "sequencerDid": DS_DID,
                    "coordinates": coords.clone(),
                    "participants": parts,
                    "leaves": [b["manifest"]["actorLeaf"]],
                    "metadataSnapshot": b["metadataSnapshot"],
                    "snapshotSeq": 1,
                }),
            );
            g.entries.entry(cid).or_default().push(json!({
                "$type": "blue.catbird.chat.defs#creationEntry",
                "seq": 1,
                "coordinates": coords.clone(),
                "signedRequest": sr,
            }));
            return ok_json(json!({
                "seq": 1,
                "state": { "coordinates": coords }
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.acceptConversation") {
            if let Some(dr) = body_json.get("directRequest") {
                let b = &dr["body"];
                let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
                let next_coords = b["next"].clone();
                let entries = g.entries.entry(cid.clone()).or_default();
                let next_seq = (entries.len() as i64) + 1;
                entries.push(json!({
                    "$type": "blue.catbird.chat.defs#directRequestAcceptanceEntry",
                    "seq": next_seq,
                    "coordinates": next_coords.clone(),
                    "signedRequest": dr,
                }));
                if let Some(st) = g.conversations.get_mut(&cid) {
                    st["coordinates"] = next_coords.clone();
                }
                return ok_json(json!({
                    "seq": next_seq,
                    "coordinates": next_coords
                }));
            }
            // Acceptance creates a post-acceptance-coordinate request, not an inviter inbox row.
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
            let next_coords = b["next"].clone();
            let invitee_did = b["actorDid"].as_str().unwrap().to_string();
            let invitee_dev = b["actorDeviceId"].as_str().unwrap().to_string();
            let rec_req_id = b["recoveryRequestId"].as_str().unwrap().to_string();
            let kp = g
                .convo_kps
                .get_mut(&(invitee_did.clone(), invitee_dev.clone()))
                .and_then(|v| v.pop())
                .expect("invitee must have conversation KP");
            if let Some(st) = g.conversations.get_mut(&cid) {
                st["coordinates"] = next_coords.clone();
                if let Some(arr) = st["participants"].as_array_mut() {
                    for p in arr {
                        if p["userDid"].as_str() == Some(&invitee_did) {
                            p["status"] = json!("active");
                        }
                    }
                }
            }
            let entries = g.entries.entry(cid.clone()).or_default();
            let next_seq = (entries.len() as i64) + 1;
            entries.push(json!({
                "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
                "seq": next_seq,
                "coordinates": next_coords.clone(),
                "signedRequest": sr,
            }));
            g.conversations.get_mut(&cid).unwrap()["snapshotSeq"] = json!(next_seq);
            let expires_at =
                (chrono::DateTime::parse_from_rfc3339(b["signedAt"].as_str().unwrap()).unwrap()
                    + chrono::Duration::minutes(5))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let requests = g.leaf_recoveries.entry(cid.clone()).or_default();
            for request in requests
                .iter_mut()
                .filter(|request| request["status"] == "open")
            {
                request["status"] = json!("superseded");
                request["reservation"]["status"] = json!("released");
            }
            requests.push(json!({
                "$type": "blue.catbird.chat.defs#leafRecoveryView",
                "conversationId": cid,
                "recoveryRequestId": rec_req_id,
                "requesterDid": invitee_did,
                "requesterDeviceId": invitee_dev,
                "recoveryKind": "add",
                "boundCoordinate": next_coords,
                "status": "open",
                "requestedAt": b["signedAt"],
                "expiresAt": expires_at,
                "reservation": {
                    "conversationId": cid,
                    "recoveryRequestId": rec_req_id,
                    "boundCoordinate": next_coords,
                    "requesterDid": invitee_did,
                    "requesterDeviceId": invitee_dev,
                    "requesterKeyId": b["keyId"],
                    "requesterAuthGeneration": b["authGeneration"],
                    "keyPackageRef": kp["keyPackageRef"],
                    "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    "purpose": "leafRecovery",
                    "status": "active",
                    "expiresAt": expires_at,
                    "keyPackage": kp,
                },
            }));
            return ok_json(json!({ "seq": next_seq }));
        }

        if url.contains("/xrpc/blue.catbird.chat.submitTransition") {
            if g.stale_next_submit_transition {
                g.stale_next_submit_transition = false;
                return Ok(PlatformHttpResponse {
                    status: 400,
                    headers: vec![PlatformHttpHeader {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    }],
                    body: serde_json::to_vec(&json!({
                        "error": "StaleCoordinates",
                        "message": "StaleCoordinates"
                    }))
                    .unwrap(),
                });
            }
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let btype = b["$type"].as_str().unwrap_or("");
            let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
            let next_coords = b["next"].clone();
            let next_seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as i64) + 1;
            assert_eq!(
                g.conversations[&cid]["coordinates"], b["prior"],
                "fixture rejects transitions built against a superseded coordinate"
            );

            if btype.ends_with("leafRecoveryFulfillmentBody") {
                let wb = &b["manifest"]["welcomeBundle"];
                let welcome_id = wb["welcomeId"].as_str().unwrap().to_string();
                let opaque = wb["opaqueWelcome"].clone();
                let snap = b["metadataSnapshot"].clone();
                for del in wb["deliveries"].as_array().cloned().unwrap_or_default() {
                    let r_did = del["recipientDid"].as_str().unwrap().to_string();
                    let r_dev = del["recipientDeviceId"].as_str().unwrap().to_string();
                    g.pending_welcomes
                        .entry((r_did, r_dev))
                        .or_default()
                        .push(json!({
                            "welcomeId": welcome_id,
                            "conversationId": cid,
                            "sequencerDid": DS_DID,
                            "transitionSeq": next_seq,
                            "coordinates": next_coords,
                            "opaqueWelcome": opaque,
                            "metadataSnapshot": snap,
                        }));
                }
            }

            g.entries.entry(cid.clone()).or_default().push(json!({
                "seq": next_seq,
                "coordinates": next_coords.clone(),
                "signedRequest": sr,
            }));
            if let Some(st) = g.conversations.get_mut(&cid) {
                st["coordinates"] = next_coords.clone();
                st["snapshotSeq"] = json!(next_seq);
                if let Some(snapshot) = b.get("metadataSnapshot") {
                    st["metadataSnapshot"] = snapshot.clone();
                }
                for change in b["manifest"]["leafChanges"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    let leaves = st["leaves"].as_array_mut().unwrap();
                    if change["$type"] == "blue.catbird.chat.defs#removeLeaf" {
                        leaves.retain(|leaf| {
                            leaf["userDid"] != change["userDid"]
                                || leaf["deviceId"] != change["deviceId"]
                        });
                    } else if change["$type"] == "blue.catbird.chat.defs#addLeafByRecovery" {
                        leaves.push(json!({
                            "userDid": change["userDid"],
                            "deviceId": change["deviceId"],
                            "leafOrigin": "recovery",
                        }));
                    }
                }
            }
            for request in g.leaf_recoveries.get_mut(&cid).into_iter().flatten() {
                if request["status"] == "open" {
                    let fulfilled = request["recoveryRequestId"] == b["recoveryRequestId"];
                    request["status"] = json!(if fulfilled { "fulfilled" } else { "superseded" });
                    request["reservation"]["status"] =
                        json!(if fulfilled { "consumed" } else { "released" });
                }
            }
            return ok_json(json!({
                "seq": next_seq,
                "state": { "coordinates": next_coords }
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.sendMessage") {
            if g.empty_stub_next_send {
                g.empty_stub_next_send = false;
                return ok_json(json!({ "ok": true }));
            }
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
            let msg_id = b["messageId"].as_str().unwrap().to_string();
            let lose_response = std::mem::take(&mut g.lose_next_send_response);
            if let Some(entry) = g.entries.get(&cid).and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry["messageId"].as_str() == Some(msg_id.as_str()))
            }) {
                assert_eq!(
                    entry["signedRequest"], sr,
                    "uncertain send retries must replay the exact signed ciphertext"
                );
                if lose_response {
                    return Err(MLSError::Internal(
                        "send response lost after publication".into(),
                    ));
                }
                return ok_json(json!({
                    "seq": entry["seq"],
                    "sequencerReceipt": entry["sequencerReceipt"],
                }));
            }
            let actor_did = b["actorDid"].as_str().unwrap().to_string();
            let actor_dev = b["actorDeviceId"].as_str().unwrap().to_string();
            let gen = b["prior"]["generation"].as_u64().unwrap_or(0);
            let epoch = b["prior"]["epoch"].as_u64().unwrap_or(0);
            let group_id =
                catbird_mls::client::chat_wire::json_bytes(&b["prior"]["groupId"]).unwrap();
            let commit_arr: [u8; 32] =
                catbird_mls::client::chat_wire::json_bytes(&b["aad"]["archiveCommitment"])
                    .unwrap()
                    .try_into()
                    .unwrap();

            if g.omit_next_receipt {
                g.omit_next_receipt = false;
                let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as u64) + 1;
                return ok_json(json!({ "seq": seq }));
            }

            let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as u64) + 1;
            let mut payload = SequencerReceiptPayload {
                sequencer_did: DS_DID.to_string(),
                conversation_id: cid.clone(),
                group_id,
                epoch,
                sender_device_did_url: format!("{actor_did}#{actor_dev}"),
                entry_id: msg_id.clone(),
                archive_commitment: commit_arr,
                seq,
                issued_at_ms: 1_762_000_000_000,
            };
            if g.tamper_next_receipt {
                g.tamper_next_receipt = false;
                payload.archive_commitment[0] ^= 0xff;
            }
            let kid_full = format!("{DS_DID}#mls-receipt-1");
            let signed = sign_sequencer_receipt(&g.receipt_sk, &kid_full, &payload).unwrap();
            let rcpt_json = json!({
                "kid": signed.key_id,
                "sequencerDid": signed.payload.sequencer_did,
                "conversationId": signed.payload.conversation_id,
                "generation": gen,
                "groupId": { "$bytes": STANDARD.encode(&signed.payload.group_id) },
                "epoch": signed.payload.epoch,
                "seq": signed.payload.seq,
                "entryId": signed.payload.entry_id,
                "senderDid": actor_did,
                "senderDeviceId": actor_dev,
                "archiveCommitment": { "$bytes": STANDARD.encode(signed.payload.archive_commitment) },
                "issuedAtMs": signed.payload.issued_at_ms,
                "signature": { "$bytes": STANDARD.encode(signed.signature) },
            });
            g.entries.entry(cid.clone()).or_default().push(json!({
                "$type": "blue.catbird.chat.defs#applicationMessageEntry",
                "seq": seq,
                "messageId": msg_id,
                "signedRequest": sr,
                "sequencerReceipt": rcpt_json.clone(),
            }));
            if lose_response {
                return Err(MLSError::Internal(
                    "send response lost after publication".into(),
                ));
            }
            return ok_json(json!({
                "seq": seq,
                "sequencerReceipt": rcpt_json,
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.getConversations") {
            let list: Vec<Value> = g.conversations.values().cloned().collect();
            return ok_json(json!({ "conversations": list }));
        }

        if url.contains("/xrpc/blue.catbird.chat.getPendingWelcomes") {
            let dev = q.get("actorDeviceId").cloned().unwrap_or_default();
            let found: Vec<Value> = g
                .pending_welcomes
                .iter_mut()
                .filter(|((_, d), _)| d == &dev)
                .flat_map(|(_, v)| std::mem::take(v))
                .collect();
            return ok_json(json!({ "welcomes": found }));
        }

        if url.contains("/xrpc/blue.catbird.chat.acknowledgeWelcome") {
            let wid = body_json["signedRequest"]["body"]["welcomeId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            g.acked_welcomes.push(wid);
            return ok_json(json!({ "acknowledged": true }));
        }

        if url.contains("/xrpc/blue.catbird.chat.getConversationState") {
            let cid = q.get("conversationId").expect("conversation ID");
            let dev = q.get("actorDeviceId").expect("actor device ID");
            let state = g
                .conversations
                .get(cid)
                .expect("conversation state")
                .clone();
            let current_leaf = state["leaves"].as_array().is_some_and(|leaves| {
                leaves
                    .iter()
                    .any(|leaf| leaf["deviceId"].as_str() == Some(dev.as_str()))
            });
            let requests: Vec<Value> = g
                .leaf_recoveries
                .get(cid)
                .into_iter()
                .flatten()
                .filter(|request| {
                    current_leaf
                        && request["requesterDeviceId"].as_str() != Some(dev.as_str())
                        && request["status"] == "open"
                        && request["boundCoordinate"] == state["coordinates"]
                })
                .cloned()
                .collect();
            return ok_json(json!({
                "state": state,
                "pendingLeafRecoveryRequests": requests,
                "pendingResetRequests": [],
                "pendingLeaveRequests": [],
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.getLeafRecoveryInbox") {
            let dev = q.get("actorDeviceId").cloned().unwrap_or_default();
            let requests: Vec<Value> = g
                .leaf_recoveries
                .values()
                .flatten()
                .filter(|request| request["requesterDeviceId"].as_str() == Some(dev.as_str()))
                .cloned()
                .collect();
            return ok_json(json!({
                "items": requests,
                "inventorySessionId": q.get("inventorySessionId"),
                "snapshotEventCursor": "fixture-events",
                "snapshotExpiresAt": "2099-01-01T00:00:00.000Z",
                "hasMore": false,
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.getEntries") {
            if std::mem::take(&mut g.fail_next_entries) {
                return Err(MLSError::Internal("entries response unavailable".into()));
            }
            let cid = q.get("conversationId").cloned().unwrap_or_default();
            let after: i64 = q.get("afterSeq").and_then(|s| s.parse().ok()).unwrap_or(0);
            let list: Vec<Value> = g
                .entries
                .get(&cid)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e["seq"].as_i64().unwrap_or(0) > after)
                .collect();
            return ok_json(json!({ "entries": list }));
        }

        if url.contains("/xrpc/blue.catbird.chat.acknowledgeEntries") {
            let cid = body_json["conversationId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let dev = body_json["actorDeviceId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let wm = body_json["upToSeq"].as_i64().unwrap_or(0);
            g.acked_watermarks.insert((cid, dev), wm);
            return ok_json(json!({ "watermarkSeq": wm }));
        }

        ok_json(json!({}))
    }

    fn connect_realtime_stream(&self, _url: String, _cursor: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

#[test]
fn live_catbird_mls_client_c33_dm_i4_i13_i14_labyrinth_and_group_sync() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let alice_dev = uuid::Uuid::new_v4().to_string();
    let bob_dev = uuid::Uuid::new_v4().to_string();

    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice").to_string_lossy().into_owned(),
            account_did: ALICE_DID.to_string(),
            device_id: alice_dev.clone(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.clone(),
        None,
    )
    .expect("open alice");

    let bob = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("bob").to_string_lossy().into_owned(),
            account_did: BOB_DID.to_string(),
            device_id: bob_dev.clone(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.clone(),
        None,
    )
    .expect("open bob");

    // 1. Live device enrollment publishes ADR-009 PDS `blue.catbird.chat.device` + DS `enrollDevice` + C33 DR keys
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    {
        let g = ds.inner.lock().unwrap();
        assert!(g.pds_records.contains_key(&(
            ALICE_DID.to_string(),
            "blue.catbird.chat.device".to_string(),
            alice_dev.clone()
        )));
        assert!(g.pds_records.contains_key(&(
            BOB_DID.to_string(),
            "blue.catbird.chat.device".to_string(),
            bob_dev.clone()
        )));
    }

    // 2. Negative `I4` test: Eve's PDS `blue.catbird.chat.device` key is forged -> `create_group` MUST fail closed!
    let eve_dev = uuid::Uuid::new_v4().to_string();
    let eve = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("eve").to_string_lossy().into_owned(),
            account_did: EVE_DID.to_string(),
            device_id: eve_dev.clone(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.clone(),
        None,
    )
    .expect("open eve");
    eve.enroll_device(&scopes).expect("enroll eve");
    {
        let mut g = ds.inner.lock().unwrap();
        g.pds_records.insert(
            (
                EVE_DID.to_string(),
                "blue.catbird.chat.device".to_string(),
                eve_dev,
            ),
            json!({
                "$type": "blue.catbird.chat.device",
                "mlsSignaturePublicKey": { "$bytes": STANDARD.encode([0xAAu8; 32]) },
                "algorithm": "Ed25519",
                "createdAt": "2026-10-31T00:00:00.000Z"
            }),
        );
    }
    let bad_c33_cid = uuid::Uuid::new_v4().to_string();
    let i4_err = alice
        .create_group(
            &bad_c33_cid,
            DS_DID,
            vec![EVE_DID.to_string()],
            None,
            Some("Should fail I4!".to_string()),
        )
        .expect_err("forged PDS device key must be rejected by I4 before group creation");
    assert!(
        i4_err.to_string().contains("I4") || i4_err.to_string().contains("authorized"),
        "unexpected I4 error: {i4_err}"
    );

    // 3. Positive `C33` 1:1 Direct Request: Alice -> Bob (`prepareDirectRequest` + `publishDirectRequest`)
    let dm_cid = uuid::Uuid::new_v4().to_string();
    let alice_dm = alice
        .create_group(
            &dm_cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("Hey Bob, live C33!".to_string()),
        )
        .expect("alice create C33 DM");
    assert_eq!(alice_dm.epoch, 1);

    // Before acceptance, Alice's opening message MUST NOT be in the Labyrinth outbox (`C33` pending exclusion)!
    assert_eq!(
        alice
            .db()
            .read_tx(|tx| tx.list_labyrinth_queue(None, 20))
            .unwrap()
            .len(),
        0,
        "C33: opening message must not be archived before recipient acceptance"
    );

    // 4. `bob.sync()` imports C33 Welcome, verifies `I4`, joins identical `group_id`, decrypts opening message
    let synced = bob.sync().expect("bob sync C33");
    assert!(synced >= 1);
    let bob_convos = bob.list_conversations(None, 20).expect("bob convos");
    let bob_dm = bob_convos
        .iter()
        .find(|c| c.conversation_id == dm_cid)
        .expect("bob joined dm_cid");
    assert_eq!(
        bob_dm.group_id, alice_dm.group_id,
        "Alice and Bob must share identical MLS group_id"
    );
    let bob_reqs = bob
        .list_requests(Some("incomingPending"))
        .expect("bob pending requests");
    assert_eq!(bob_reqs.len(), 1);
    let bob_msgs = bob.list_messages(&dm_cid, None, 20).expect("bob msgs");
    assert_eq!(bob_msgs.len(), 1);
    assert!(bob_msgs[0].plaintext_json.contains("Hey Bob, live C33!"));

    // 5. Bob accepts direct request -> Alice syncs `directRequestAcceptanceEntry` -> opening message archived!
    bob.accept_direct_request(&bob_reqs[0].request_id)
        .expect("bob accept direct request");
    let alice_synced = alice.sync().expect("alice sync acceptance");
    assert!(alice_synced >= 1);
    assert_eq!(
        alice
            .list_requests(Some("accepted"))
            .expect("alice accepted")
            .len(),
        1
    );

    // 6. Negative `I13` check: tampered `sequencerReceipt` is rejected!
    ds.inner.lock().unwrap().tamper_next_receipt = true;
    let tampered_msg_id = uuid::Uuid::new_v4().to_string();
    let i13_err = alice
        .send_message(&dm_cid, &tampered_msg_id, "tampered receipt test")
        .expect_err("tampered ES256 sequencerReceipt must fail I13");
    assert!(
        i13_err.to_string().contains("I13") || i13_err.to_string().contains("receipt"),
        "unexpected I13 error: {i13_err}"
    );
    // Clean up tampered test entry from mock DS log so valid messages follow cleanly
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(&dm_cid)
        .unwrap()
        .pop();

    // 7. Alice sends real `MLS_256_XWING` message with verified `I13` ES256 receipt -> Bob syncs + `I14` ack -> Alice flushes Labyrinth!
    let msg1_id = uuid::Uuid::new_v4().to_string();
    let sent1 = alice
        .send_message(&dm_cid, &msg1_id, "Hello after C33 acceptance!")
        .expect("alice send_message");
    assert!(sent1.seq >= 3);

    let flushed = alice.flush_labyrinth_queue().expect("flush labyrinth");
    assert!(flushed >= 1);
    assert!(
        !ds.inner.lock().unwrap().space_writes.is_empty(),
        "Labyrinth sealed batch must be written via com.atproto.space.applyWrites"
    );

    let bob_applied = bob.sync().expect("bob sync message");
    assert!(bob_applied >= 1);
    let bob_msgs_after = bob.list_messages(&dm_cid, None, 20).expect("bob msgs");
    assert!(bob_msgs_after
        .iter()
        .any(|m| m.plaintext_json.contains("Hello after C33 acceptance!")));
    assert!(
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .contains_key(&(dm_cid.clone(), bob_dev.clone())),
        "I14: bob.sync() must submit signed acknowledgeEntries watermark"
    );

    // 8. Multi-member group flow: createGroup(title) -> Bob accepts invite -> Alice fulfills leaf recovery -> Bob joins via Welcome -> metadata update + D3 check
    let grp_cid = uuid::Uuid::new_v4().to_string();
    let alice_grp = alice
        .create_group(
            &grp_cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Aviary HQ".to_string()),
            Some("Clean-slate group".to_string()),
        )
        .expect("alice create titled group");
    assert_eq!(alice_grp.title.as_deref(), Some("Aviary HQ"));

    // Bob syncs -> submits `#participantAcceptanceBody` -> Alice syncs -> fulfills `#leafRecoveryFulfillmentBody` -> Bob syncs -> joins `StagedWelcome`!
    let _ = bob.sync().expect("bob sync group invite");
    let alice_fulfilled = alice.sync().expect("alice fulfill leaf recovery");
    assert!(alice_fulfilled >= 1);
    let bob_joined = bob.sync().expect("bob join pending welcome");
    assert!(bob_joined >= 1);
    assert!(
        !ds.inner.lock().unwrap().acked_welcomes.is_empty(),
        "bob must acknowledge pending welcome"
    );

    let bob_grp = bob
        .list_conversations(None, 20)
        .unwrap()
        .into_iter()
        .find(|c| c.conversation_id == grp_cid)
        .expect("bob joined group");
    assert_eq!(bob_grp.group_id, alice_grp.group_id);
    assert_eq!(bob_grp.title.as_deref(), Some("Aviary HQ"));

    // Alice updates encrypted metadata -> Bob syncs and decrypts new title!
    alice
        .update_group_metadata(
            &grp_cid,
            "Aviary Launch Room".to_string(),
            "Updated description".to_string(),
            None,
        )
        .expect("alice update metadata");
    bob.sync().expect("bob sync metadata");
    let bob_meta = bob
        .get_group_metadata(&grp_cid)
        .expect("get meta")
        .expect("meta present");
    assert_eq!(bob_meta.title.as_deref(), Some("Aviary Launch Room"));

    // D3: non-admin removal rejected; admin removal succeeds and advances epoch
    assert!(bob
        .remove_group_member(MemberRole::Member, &grp_cid, ALICE_DID)
        .is_err());
    alice
        .remove_group_member(MemberRole::Admin, &grp_cid, BOB_DID)
        .expect("admin remove bob");
}

#[test]
fn adversarial_round2_fault_regressions_i2_i6_i13_i14_and_avatar_preservation() {
    use catbird_mls::groups::metadata_v1::SpaceAvatarPointer;

    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let alice_dev = uuid::Uuid::new_v4().to_string();
    let bob_dev = uuid::Uuid::new_v4().to_string();
    let eve_dev = uuid::Uuid::new_v4().to_string();

    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice").to_string_lossy().into_owned(),
            account_did: ALICE_DID.to_string(),
            device_id: alice_dev.clone(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        alice_keys.clone(),
        ds.clone(),
        None,
    )
    .expect("open alice");
    let bob = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("bob").to_string_lossy().into_owned(),
            account_did: BOB_DID.to_string(),
            device_id: bob_dev,
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.clone(),
        None,
    )
    .expect("open bob");
    let eve = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("eve").to_string_lossy().into_owned(),
            account_did: EVE_DID.to_string(),
            device_id: eve_dev,
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.clone(),
        None,
    )
    .expect("open eve");

    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    eve.enroll_device(&scopes).expect("enroll eve");

    let grp_cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &grp_cid,
            DS_DID,
            vec![BOB_DID.to_string(), EVE_DID.to_string()],
            Some("Adversarial Room".to_string()),
            Some("Testing edge cases".to_string()),
        )
        .expect("alice create group");

    // Eve's acceptance supersedes Bob's earlier request: only the current coordinate is fulfillable.
    let _ = bob.sync().expect("bob sync invite");
    let _ = eve.sync().expect("eve sync invite");

    // 1. Simulate HTTP 400 StaleCoordinates on leaf recovery fulfillment during alice.sync():
    // KvWriteOverlay must discard staged add_members + merge_pending_commit so Alice's group epoch stays 0!
    {
        let mut g = ds.inner.lock().unwrap();
        let requests = &g.leaf_recoveries[&grp_cid];
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["status"], "superseded");
        assert_eq!(requests[1]["status"], "open");
        assert_eq!(
            requests[1]["boundCoordinate"],
            g.conversations[&grp_cid]["coordinates"]
        );
        g.stale_next_submit_transition = true;
    }
    alice
        .sync()
        .expect("alice sync skips stale leaf recovery cleanly without corrupting epoch");
    assert_eq!(
        alice
            .db()
            .read_tx(|tx| tx.get_conversation(&grp_cid))
            .unwrap()
            .unwrap()
            .epoch,
        0,
        "StaleCoordinates must leave the local MLS epoch unchanged"
    );
    assert_eq!(
        ds.inner.lock().unwrap().leaf_recoveries[&grp_cid][1]["status"],
        "open",
        "discovering a request and losing a transition must not consume the request"
    );
    alice
        .sync()
        .expect("retry current recovery after stale prior");
    let eve_joined = eve.sync().expect("eve joins the retried recovery Welcome");
    assert!(
        eve_joined >= 1,
        "retrying the current recovery must succeed because stale rejection did not corrupt openmls_kv"
    );

    // Let's also create a clean 3-member group where both Bob and Eve join cleanly
    let clean_cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &clean_cid,
            DS_DID,
            vec![BOB_DID.to_string(), EVE_DID.to_string()],
            Some("Clean Trio".to_string()),
            None,
        )
        .expect("create clean trio");
    bob.sync().expect("bob accept");
    alice.sync().expect("alice fulfill bob");
    bob.sync().expect("bob join welcome");
    eve.sync().expect("eve accept at the new coordinate");
    alice.sync().expect("alice fulfill eve");
    eve.sync().expect("eve join welcome");
    bob.sync().expect("bob sync eve addition");

    // 2. Empty stub response (`{"ok":true}`) and omitted `sequencerReceipt` on sendMessage MUST fail closed (`I13`)
    // AND leave zero phantom `MessageRow`/`LabyrinthQueueRow` rows while reserving sender generations.
    ds.inner.lock().unwrap().empty_stub_next_send = true;
    let bad_stub_mid = uuid::Uuid::new_v4().to_string();
    assert!(
        alice
            .send_message(&clean_cid, &bad_stub_mid, "should reject stub")
            .is_err(),
        "live sendMessage must reject empty/stub JSON"
    );
    ds.inner.lock().unwrap().omit_next_receipt = true;
    let missing_rcpt_mid = uuid::Uuid::new_v4().to_string();
    assert!(
        alice
            .send_message(
                &clean_cid,
                &missing_rcpt_mid,
                "should reject missing I13 receipt"
            )
            .is_err(),
        "live sendMessage must reject missing sequencerReceipt (I13)"
    );
    assert!(
        alice
            .list_messages(&clean_cid, None, 20)
            .unwrap()
            .is_empty(),
        "failed sends must commit zero phantom MessageRows"
    );
    assert!(
        alice
            .db()
            .read_tx(|tx| tx.list_labyrinth_queue(None, 20))
            .unwrap()
            .iter()
            .all(|q| q.conversation_id != clean_cid),
        "failed sends must commit zero LabyrinthQueueRows"
    );

    // Reserved-but-unpublished generations may be skipped; they must never be reused.
    let valid_mid = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&clean_cid, &valid_mid, "ratchet intact after failed sends")
        .expect("alice send after failed attempts");
    bob.sync().expect("bob sync valid message");
    eve.sync().expect("eve sync valid message");
    assert!(bob
        .list_messages(&clean_cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m
            .plaintext_json
            .contains("ratchet intact after failed sends")));

    // 3. Concurrent peer message at seq = N landing before Alice's own send at seq = N + 1 (`I2` gap-sync):
    // Bob sends while Alice has NOT synced yet; then Alice sends. Alice must gap-sync Bob's message!
    let bob_concurrent_mid = uuid::Uuid::new_v4().to_string();
    let bob_sent = bob
        .send_message(&clean_cid, &bob_concurrent_mid, "Bob concurrent first!")
        .expect("bob concurrent send");
    let alice_concurrent_mid = uuid::Uuid::new_v4().to_string();
    let alice_sent = alice
        .send_message(
            &clean_cid,
            &alice_concurrent_mid,
            "Alice concurrent second!",
        )
        .expect("alice concurrent send triggers gap-sync");
    assert_eq!(alice_sent.seq, bob_sent.seq + 1);
    let alice_msgs = alice
        .list_messages(&clean_cid, None, 20)
        .expect("alice list_messages");
    assert!(
        alice_msgs
            .iter()
            .any(|m| m.plaintext_json.contains("Bob concurrent first!")),
        "Alice must automatically gap-sync concurrent peer message instead of skipping seq {}",
        bob_sent.seq
    );
    assert!(alice_msgs
        .iter()
        .any(|m| m.plaintext_json.contains("Alice concurrent second!")));

    // 4. SpaceAvatarPointer survives metadata updates (`avatar: None`) AND epoch rotation (`remove_group_member`),
    // plus StaleCoordinates on `remove_group_member` rolls back `MlsGroup` epoch cleanly!
    bob.sync().expect("bob catch up");
    eve.sync().expect("eve catch up");

    let avatar = SpaceAvatarPointer {
        setter_did: ALICE_DID.to_string(),
        space_blob_cid: "bafkreiavatarclean0001".to_string(),
        sym_key: vec![0x42; 32],
        sha256: vec![0x99; 32],
        mime_type: Some("image/png".to_string()),
    };
    alice
        .update_group_metadata(
            &clean_cid,
            "Avatar Set".to_string(),
            "With avatar".to_string(),
            Some(avatar),
        )
        .expect("set avatar");
    // Subsequent rename passing `avatar: None` MUST preserve existing SpaceAvatarPointer!
    alice
        .update_group_metadata(
            &clean_cid,
            "Renamed Keep Avatar".to_string(),
            "Still has avatar".to_string(),
            None,
        )
        .expect("rename preserving avatar");
    bob.sync().expect("bob sync metadata with avatar");
    let bob_meta_1 = bob
        .get_group_metadata(&clean_cid)
        .unwrap()
        .expect("bob meta 1");
    assert_eq!(bob_meta_1.title.as_deref(), Some("Renamed Keep Avatar"));
    assert_eq!(
        bob_meta_1.avatar_blob_cid.as_deref(),
        Some("bafkreiavatarclean0001")
    );

    // Inject StaleCoordinates on remove_group_member: return the classified error and leave epoch uncorrupted.
    let epoch_before = alice
        .list_conversations(None, 20)
        .unwrap()
        .into_iter()
        .find(|c| c.conversation_id == clean_cid)
        .unwrap()
        .epoch;
    ds.inner.lock().unwrap().stale_next_submit_transition = true;
    assert!(matches!(
        alice.remove_group_member(MemberRole::Admin, &clean_cid, EVE_DID),
        Err(MLSError::InvalidState(code)) if code == "StaleCoordinates"
    ));
    let epoch_after_stale = alice
        .list_conversations(None, 20)
        .unwrap()
        .into_iter()
        .find(|c| c.conversation_id == clean_cid)
        .unwrap()
        .epoch;
    assert_eq!(epoch_after_stale, epoch_before);

    // Now real remove_group_member succeeds at the uncorrupted epoch and carries SpaceAvatarPointer into next_epoch!
    alice
        .remove_group_member(MemberRole::Admin, &clean_cid, EVE_DID)
        .expect("remove eve after stale prior");
    bob.sync().expect("bob sync eve removal");
    let bob_meta_2 = bob
        .get_group_metadata(&clean_cid)
        .unwrap()
        .expect("bob meta after epoch rotation");
    assert_eq!(
        bob_meta_2.avatar_blob_cid.as_deref(),
        Some("bafkreiavatarclean0001"),
        "SpaceAvatarPointer must survive epoch-advancing commit re-encryption"
    );

    // 5. `payloadPruned: true` entry in `getEntries` (`I14`) is skipped cleanly without aborting subsequent live entries!
    {
        let mut g = ds.inner.lock().unwrap();
        let list = g.entries.entry(clean_cid.clone()).or_default();
        let pruned_seq = (list.len() as i64) + 1;
        list.push(json!({
            "$type": "blue.catbird.chat.defs#applicationMessageEntry",
            "seq": pruned_seq,
            "messageId": uuid::Uuid::new_v4().to_string(),
            "payloadPruned": true
        }));
    }
    let after_pruned_mid = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(
            &clean_cid,
            &after_pruned_mid,
            "Live message after payloadPruned entry",
        )
        .expect("alice send after pruned");
    bob.sync()
        .expect("bob sync advances past payloadPruned entry without crashing");
    assert!(bob
        .list_messages(&clean_cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m
            .plaintext_json
            .contains("Live message after payloadPruned entry")));

    // 6. Publication can succeed after the sender loses the response. Preserve both the
    // exact retry ciphertext and its plaintext across restart without reusing sender keys.
    let uncertain_mid = uuid::Uuid::new_v4().to_string();
    for _ in 0..2 {
        ds.inner.lock().unwrap().lose_next_send_response = true;
        assert!(alice
            .send_message(&clean_cid, &uncertain_mid, "accepted without a response")
            .is_err());
    }
    assert!(!alice
        .list_messages(&clean_cid, None, 100)
        .unwrap()
        .iter()
        .any(|m| m.message_id == uncertain_mid));
    bob.sync().expect("bob decrypts the uncertain publication");
    let cursor_before = alice
        .db()
        .read_tx(|tx| tx.get_conversation(&clean_cid))
        .unwrap()
        .unwrap()
        .last_seq;
    ds.inner.lock().unwrap().fail_next_entries = true;
    let later_mid = uuid::Uuid::new_v4().to_string();
    assert!(
        alice
            .send_message(&clean_cid, &later_mid, "later sender generation")
            .is_err(),
        "the follow-up gap fetch fails after the later send is durable"
    );
    let mut historical = alice
        .list_messages(&clean_cid, None, 100)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == later_mid)
        .expect("later send was durably accepted");
    historical.epoch = 0;
    alice
        .import_conversation_history(&clean_cid, vec![historical])
        .expect("import ahead-of-cursor history");
    assert_eq!(
        alice
            .db()
            .read_tx(|tx| tx.get_conversation(&clean_cid))
            .unwrap()
            .unwrap()
            .last_seq,
        cursor_before,
        "historical imports must not jump over unresolved live entries"
    );
    drop(alice);
    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice").to_string_lossy().into_owned(),
            account_did: ALICE_DID.to_string(),
            device_id: alice_dev,
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        alice_keys,
        ds.clone(),
        None,
    )
    .expect("reopen alice");
    let published_entry = ds.inner.lock().unwrap().entries[&clean_cid]
        .iter()
        .find(|entry| entry["messageId"].as_str() == Some(uncertain_mid.as_str()))
        .unwrap()
        .clone();
    for tamper_ciphertext in [true, false] {
        {
            let mut state = ds.inner.lock().unwrap();
            let entry = state
                .entries
                .get_mut(&clean_cid)
                .unwrap()
                .iter_mut()
                .find(|entry| entry["messageId"].as_str() == Some(uncertain_mid.as_str()))
                .unwrap();
            if tamper_ciphertext {
                entry["signedRequest"]["body"]["applicationMessage"]["bytes"] =
                    json!({ "$bytes": STANDARD.encode([0_u8]) });
            } else {
                entry["sequencerReceipt"]["signature"] =
                    json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
            }
        }
        assert!(
            alice.sync().is_err(),
            "unproven own echoes must fail closed"
        );
        let mut state = ds.inner.lock().unwrap();
        *state
            .entries
            .get_mut(&clean_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["messageId"].as_str() == Some(uncertain_mid.as_str()))
            .unwrap() = published_entry.clone();
    }
    alice
        .sync()
        .expect("recover own publication from durable journal");
    let recovered = alice.list_messages(&clean_cid, None, 100).unwrap();
    assert_eq!(
        recovered
            .iter()
            .filter(|m| m.message_id == uncertain_mid)
            .count(),
        1
    );
    assert!(alice
        .list_pending_labyrinth_queue(Some(&clean_cid), 100)
        .unwrap()
        .iter()
        .any(|item| item.message_id == uncertain_mid && item.sequencer_receipt_json.is_some()));
    let next_mid = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&clean_cid, &next_mid, "next generation after restart")
        .expect("send after uncertain publication recovery");
    bob.sync()
        .expect("no SecretReuseError after uncertain send");
    let alice_messages = alice.list_messages(&clean_cid, None, 100).unwrap();
    let bob_messages = bob.list_messages(&clean_cid, None, 100).unwrap();
    for id in [&uncertain_mid, &later_mid, &next_mid] {
        let a = alice_messages.iter().find(|m| &m.message_id == id).unwrap();
        let b = bob_messages.iter().find(|m| &m.message_id == id).unwrap();
        let a_text: Value = serde_json::from_str(&a.plaintext_json).unwrap();
        let b_text: Value = serde_json::from_str(&b.plaintext_json).unwrap();
        assert_eq!((a.seq, &a_text["text"]), (b.seq, &b_text["text"]));
    }
}
