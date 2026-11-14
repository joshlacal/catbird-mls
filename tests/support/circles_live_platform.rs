//! A live-device `PlatformTransport` for driving `CatbirdMlsClient`'s real
//! Circles constructor path (`circles_open_session`) in tests.
//!
//! Every request goes over HTTP-shaped `PlatformHttpRequest`s, the way the
//! iOS/Android transports see them:
//! - the PDS (`PDS_URL`): `com.atproto.repo.{putRecord,getRecord,listRecords,deleteRecord}`
//!   with real `swapRecord` CAS semantics and canonical DAG-CBOR CIDs, plus
//!   `com.atproto.space.*` served with Nov-12 ES256 Space credentials & RFC 9421 MACs;
//! - mls-ds (`DS_URL`): device enrollment and the Labyrinth epoch directory
//!   (`publishEpochHead`, `getEpochHead`, `getMailboxKeysRecord`,
//!   `getChatDeviceKeys`, `getMemberDevices`).

#[path = "native_archive_auth.rs"]
mod native_archive_auth;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use atproto_spaces::lthash::compute_dagcbor_cid;
use catbird_mls::client::{
    CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest, PlatformHttpResponse,
    PlatformKeyStore, PlatformTransport,
};
use catbird_mls::MLSError;
use serde_json::{json, Value};

pub const DS_DID: &str = "did:web:ds.circles.test";
pub const DS_URL: &str = "https://ds.circles.test";
pub const PDS_URL: &str = "https://pds.circles.test";
pub const MAILBOX_KEYS: &str = "blue.catbird.labyrinth.mailboxKeys";

#[derive(Default)]
pub struct LiveState {
    /// `(repo, collection, rkey) -> (record value, cid)`.
    pub repo: BTreeMap<(String, String, String), (Value, String)>,
    /// mls-ds epoch heads (`EpochPublicDef` JSON) per DID, ascending.
    heads: HashMap<String, Vec<Value>>,
    /// Enrolled chat device signing keys (`$bytes` objects) per DID.
    chat_keys: HashMap<String, Vec<Value>>,
    /// `"<METHOD> <url>"` of every request, for diagnostics.
    pub log: Vec<String>,
    /// Refuse `com.atproto.identity.resolveDid` at the transport, as
    /// CatbirdMLSCore's outbound validator does on a device.
    pub refuse_resolve_did: bool,
}

#[derive(Clone)]
pub struct LiveWorld {
    pub archive_auth: Arc<native_archive_auth::NativeArchiveAuthFixture>,
    pub state: Arc<Mutex<LiveState>>,
}

impl Default for LiveWorld {
    fn default() -> Self {
        Self::with_clock(Arc::new(|| chrono::Utc::now().timestamp_millis()))
    }
}

#[allow(dead_code)]
impl LiveWorld {
    /// Construct a `LiveWorld` sharing a controllable clock with `NativeArchiveAuthFixture`.
    pub fn with_clock(now_ms: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            archive_auth: Arc::new(native_archive_auth::NativeArchiveAuthFixture::new(
                "did:plc:worlddefault000000000000",
                now_ms,
            )),
            state: Arc::new(Mutex::new(LiveState::default())),
        }
    }

    /// A live (UUIDv4 device) client for `did` on this world.
    pub fn client(&self, did: &str, storage_root: &std::path::Path) -> Arc<CatbirdMlsClient> {
        self.client_with_hooks(
            did,
            storage_root,
            catbird_mls::sim_hooks::SimClientHooks::system_default(),
        )
    }

    /// A live (UUIDv4 device) client for `did` with custom `SimClientHooks` (e.g. `FixedStepClock`).
    pub fn client_with_hooks(
        &self,
        did: &str,
        storage_root: &std::path::Path,
        hooks: catbird_mls::sim_hooks::SimClientHooks,
    ) -> Arc<CatbirdMlsClient> {
        let transport = Arc::new(LiveTransport {
            did: did.to_owned(),
            archive_auth: self.archive_auth.clone(),
            state: self.state.clone(),
        });
        CatbirdMlsClient::open_with_hooks(
            CatbirdMlsClientConfig {
                storage_root: storage_root.display().to_string(),
                account_did: did.to_owned(),
                device_id: uuid::Uuid::new_v4().to_string(),
                home_ds_did: DS_DID.to_owned(),
                home_ds_endpoint: DS_URL.to_owned(),
                pds_endpoint: PDS_URL.to_owned(),
            },
            Arc::new(MemKeyStore::default()),
            transport,
            None,
            hooks,
        )
        .expect("open client")
    }

    /// Clear `did`'s epoch heads, chat keys, and `mailboxKeys` so a fresh device simulates a full-chain reset.
    pub fn reset_peer_chain(&self, did: &str) {
        let mut st = self.state.lock().unwrap();
        st.heads.remove(did);
        st.chat_keys.remove(did);
        st.repo
            .retain(|(r, c, _), _| !(r == did && c == MAILBOX_KEYS));
    }

    /// The stored public-repo `mailboxKeys/<rkey>` record of `did`, if any.
    pub fn mailbox_keys(&self, did: &str, rkey: &str) -> Option<Value> {
        self.state
            .lock()
            .unwrap()
            .repo
            .get(&(did.to_owned(), MAILBOX_KEYS.to_owned(), rkey.to_owned()))
            .map(|(v, _)| v.clone())
    }

    /// Remove all stored public-repo `mailboxKeys/*` records for `did` (test helper).
    pub fn clear_mailbox_keys(&self, did: &str) {
        self.state
            .lock()
            .unwrap()
            .repo
            .retain(|(r, c, _), _| !(r == did && c == MAILBOX_KEYS));
    }

    pub fn has_ds_head(&self, did: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .heads
            .get(did)
            .is_some_and(|h| !h.is_empty())
    }

    pub fn ds_head_seqs(&self, did: &str) -> Vec<u64> {
        self.state
            .lock()
            .unwrap()
            .heads
            .get(did)
            .map(|list| {
                list.iter()
                    .filter_map(|e| e["epochNumber"].as_u64())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct MemKeyStore(Mutex<HashMap<String, Vec<u8>>>);

impl PlatformKeyStore for MemKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| vec![0x5a; 32])
            .clone())
    }
    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(&key_id).cloned())
    }
    fn store_signature_keypair(&self, key_id: String, bytes: Vec<u8>) -> Result<(), MLSError> {
        self.0.lock().unwrap().insert(key_id, bytes);
        Ok(())
    }
    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        self.0
            .lock()
            .unwrap()
            .retain(|k, _| !k.contains(&account_did_hash));
        Ok(())
    }
    fn load_cached_chat_dpop_token(&self, _: String) -> Result<Option<String>, MLSError> {
        Ok(None)
    }
    fn store_cached_chat_dpop_token(&self, _: String, _: String, _: i64) -> Result<(), MLSError> {
        Ok(())
    }
}

struct LiveTransport {
    did: String,
    archive_auth: Arc<native_archive_auth::NativeArchiveAuthFixture>,
    state: Arc<Mutex<LiveState>>,
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

/// `https://plc.directory/<did>` (the did:plc fallback resolver).
pub const PLC_URL: &str = "https://plc.directory/";

fn reply(status: u16, body: Value) -> Result<PlatformHttpResponse, MLSError> {
    Ok(PlatformHttpResponse {
        status,
        headers: Vec::new(),
        body: serde_json::to_vec(&body).unwrap(),
    })
}

fn ok(body: Value) -> Result<PlatformHttpResponse, MLSError> {
    reply(200, body)
}

fn canonical_record_cid(value: &Value) -> Result<String, MLSError> {
    let typed: catbird_atproto::types::value::Data = serde_json::from_value(value.clone())
        .map_err(|e| MLSError::Internal(format!("circles live fixture record decode: {e}")))?;
    let dagcbor = serde_ipld_dagcbor::to_vec(&typed)
        .map_err(|e| MLSError::Internal(format!("circles live fixture record encode: {e}")))?;
    Ok(compute_dagcbor_cid(&dagcbor).to_string())
}

impl LiveTransport {
    fn repo(
        &self,
        nsid: &str,
        q: &HashMap<String, String>,
        body: &Value,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let mut st = self.state.lock().unwrap();
        match nsid {
            "com.atproto.repo.putRecord" => {
                let key = (
                    body["repo"].as_str().unwrap_or_default().to_owned(),
                    body["collection"].as_str().unwrap_or_default().to_owned(),
                    body["rkey"].as_str().unwrap_or_default().to_owned(),
                );
                if key.0 != self.did {
                    return reply(
                        401,
                        json!({ "error": "AuthRequired", "message": "not your repo" }),
                    );
                }
                if let Some(swap) = body["swapRecord"].as_str() {
                    if st.repo.get(&key).map(|(_, cid)| cid.as_str()) != Some(swap) {
                        return reply(
                            400,
                            json!({ "error": "InvalidSwap", "message": "record was at another cid" }),
                        );
                    }
                }
                let cid = canonical_record_cid(&body["record"])?;
                let uri = format!("at://{}/{}/{}", key.0, key.1, key.2);
                st.repo.insert(key, (body["record"].clone(), cid.clone()));
                ok(json!({ "uri": uri, "cid": cid }))
            }
            "com.atproto.repo.getRecord" => {
                let key = (
                    q.get("repo").cloned().unwrap_or_default(),
                    q.get("collection").cloned().unwrap_or_default(),
                    q.get("rkey").cloned().unwrap_or_default(),
                );
                match st.repo.get(&key) {
                    Some((value, cid)) => ok(json!({
                        "uri": format!("at://{}/{}/{}", key.0, key.1, key.2),
                        "cid": cid,
                        "value": value,
                    })),
                    None => reply(
                        400,
                        json!({ "error": "RecordNotFound", "message": "Could not locate record" }),
                    ),
                }
            }
            "com.atproto.repo.listRecords" => {
                let repo = q.get("repo").cloned().unwrap_or_default();
                let coll = q.get("collection").cloned().unwrap_or_default();
                let records: Vec<Value> = st
                    .repo
                    .iter()
                    .filter(|((r, c, _), _)| *r == repo && *c == coll)
                    .map(|((r, c, k), (v, cid))| json!({ "uri": format!("at://{r}/{c}/{k}"), "cid": cid, "value": v }))
                    .collect();
                ok(json!({ "records": records }))
            }
            "com.atproto.repo.deleteRecord" => {
                let key = (
                    body["repo"].as_str().unwrap_or_default().to_owned(),
                    body["collection"].as_str().unwrap_or_default().to_owned(),
                    body["rkey"].as_str().unwrap_or_default().to_owned(),
                );
                if key.0 != self.did {
                    return reply(
                        401,
                        json!({ "error": "AuthRequired", "message": "not your repo" }),
                    );
                }
                st.repo.remove(&key);
                ok(json!({}))
            }
            other => reply(501, json!({ "error": "Unmocked", "message": other })),
        }
    }

    fn ds(
        &self,
        nsid: &str,
        q: &HashMap<String, String>,
        body: &Value,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let mut st = self.state.lock().unwrap();
        match nsid {
            "blue.catbird.chat.enrollDevice" => {
                let b = &body["signedRequest"]["body"];
                let dev = b["deviceId"].as_str().unwrap_or_default().to_owned();
                let pk_raw = catbird_mls::client::chat_wire::json_bytes(&b["signaturePublicKey"])?;
                let key_id = catbird_mls::orchestrator::canonical_transport::derive_key_id(&pk_raw);
                let pk = if b["signaturePublicKey"].is_string() {
                    json!({ "$bytes": b["signaturePublicKey"] })
                } else {
                    b["signaturePublicKey"].clone()
                };
                let keys = st.chat_keys.entry(self.did.clone()).or_default();
                if !keys.contains(&pk) {
                    keys.push(pk.clone());
                }
                ok(json!({
                    "device": {
                        "deviceId": dev,
                        "keyId": key_id,
                        "signaturePublicKey": pk,
                        "authGeneration": 1,
                        "status": "active",
                        "createdAt": "2026-11-07T00:00:00.000Z",
                        "updatedAt": "2026-11-07T00:00:00.000Z",
                        "availablePackageCount": 2,
                        "reservedPackageCount": 0,
                    }
                }))
            }
            "blue.catbird.chat.replenishKeyPackages" => ok(json!({ "acceptedCount": 4 })),
            "blue.catbird.chat.publishDirectRequestKeys" => ok(json!({ "published": true })),
            "blue.catbird.labyrinth.publishEpochHead" => {
                let epoch = body["epoch"].clone();
                let n = epoch["epochNumber"].as_u64();
                let list = st.heads.entry(self.did.clone()).or_default();
                list.retain(|e| e["epochNumber"].as_u64() != n);
                list.push(epoch);
                list.sort_by_key(|e| e["epochNumber"].as_u64());
                ok(json!({}))
            }
            "blue.catbird.labyrinth.getEpochHead" => {
                let did = q.get("did").cloned().unwrap_or_default();
                let seq = q.get("epochNumber").and_then(|s| s.parse::<u64>().ok());
                let list = st.heads.get(&did).cloned().unwrap_or_default();
                let found = match seq {
                    Some(n) => list
                        .iter()
                        .find(|e| e["epochNumber"].as_u64() == Some(n))
                        .cloned(),
                    None => list.last().cloned(),
                };
                match found {
                    Some(epoch) => {
                        let upto = epoch["epochNumber"].as_u64();
                        let chain: Vec<Value> = list
                            .iter()
                            .filter(|e| e["epochNumber"].as_u64() <= upto)
                            .cloned()
                            .collect();
                        let floor = chain
                            .first()
                            .and_then(|e| e["epochNumber"].as_u64())
                            .unwrap_or(0);
                        ok(json!({
                            "epoch": epoch,
                            "chain": chain,
                            "floorSeq": floor,
                            "receivedAt": "2026-11-07T00:00:00Z"
                        }))
                    }
                    None => reply(404, json!({ "error": "EpochNotFound", "message": "none" })),
                }
            }
            "blue.catbird.labyrinth.getMailboxKeysRecord" => {
                let did = q.get("did").cloned().unwrap_or_default();
                let rkey = q.get("rkey").cloned().unwrap_or_default();
                let key = (did.clone(), MAILBOX_KEYS.to_owned(), rkey.clone());
                match st.repo.get(&key) {
                    Some((value, cid)) => ok(json!({
                        "uri": format!("at://{did}/{MAILBOX_KEYS}/{rkey}"),
                        "cid": cid,
                        "value": value,
                    })),
                    None => reply(404, json!({ "error": "RecordNotFound", "message": "none" })),
                }
            }
            "blue.catbird.labyrinth.deleteAccountData" => {
                st.heads.remove(&self.did);
                st.chat_keys.remove(&self.did);
                ok(json!({}))
            }
            "blue.catbird.labyrinth.getChatDeviceKeys"
            | "blue.catbird.labyrinth.getMemberDevices" => {
                let did = q.get("did").cloned().unwrap_or_default();
                let items: Vec<Value> = st
                    .chat_keys
                    .get(&did)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|k| json!({ "signingPublicKey": k, "joinedSeq": 0 }))
                    .collect();
                ok(json!({ "items": items }))
            }
            other => reply(501, json!({ "error": "Unmocked", "message": other })),
        }
    }
}

impl PlatformTransport for LiveTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        self.state
            .lock()
            .unwrap()
            .log
            .push(format!("{} {}", request.method, request.url));
        if let Some(did) = request.url.strip_prefix(PLC_URL) {
            return ok(self.archive_auth.did_document(did, PDS_URL)?);
        }
        let (path, query) = match request.url.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (request.url.as_str(), None),
        };
        let Some((base, nsid)) = path.rsplit_once("/xrpc/") else {
            return reply(404, json!({ "error": "NotFound" }));
        };
        let q: HashMap<String, String> = query_pairs(query).into_iter().collect();
        let body: Value = request
            .body
            .as_deref()
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or(Value::Null);
        if nsid == "com.atproto.identity.resolveDid" {
            if self.state.lock().unwrap().refuse_resolve_did {
                return Err(MLSError::InvalidInput {
                    message: "outbound request not allowed: com.atproto.identity.resolveDid".into(),
                });
            }
            let did = q.get("did").cloned().unwrap_or_default();
            return ok(json!({ "didDoc": self.archive_auth.did_document(&did, PDS_URL)? }));
        }
        match base {
            PDS_URL if nsid == "com.atproto.sync.getRecord" => {
                let did = q.get("did").cloned().unwrap_or_default();
                let collection = q.get("collection").cloned().unwrap_or_default();
                let rkey = q.get("rkey").cloned().unwrap_or_default();
                let stored = self
                    .state
                    .lock()
                    .unwrap()
                    .repo
                    .get(&(did.clone(), collection.clone(), rkey.clone()))
                    .map(|(v, _)| v.clone());
                self.archive_auth.build_signed_car_response(
                    &did,
                    &collection,
                    &rkey,
                    stored.as_ref(),
                )
            }
            PDS_URL
                if nsid.starts_with("com.atproto.repo.")
                    && nsid != "com.atproto.repo.uploadBlob" =>
            {
                self.repo(nsid, &q, &body)
            }
            PDS_URL
                if nsid.starts_with("com.atproto.space.")
                    || nsid == "com.atproto.repo.uploadBlob" =>
            {
                self.archive_auth.execute_for(&self.did, &request, |_| {
                    reply(501, json!({ "error": "Unmocked", "message": request.url }))
                })
            }
            DS_URL
                if matches!(
                    nsid,
                    "blue.catbird.chat.relaySpaceCredential" | "blue.catbird.chat.relaySpaceRead"
                ) =>
            {
                self.archive_auth.execute_for(&self.did, &request, |_| {
                    reply(501, json!({ "error": "Unmocked", "message": request.url }))
                })
            }
            DS_URL => self.ds(nsid, &q, &body),
            _ => reply(501, json!({ "error": "Unmocked", "message": request.url })),
        }
    }

    fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}
