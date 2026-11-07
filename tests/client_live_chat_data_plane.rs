//! Deep live data-plane & sync engine tests for `CatbirdMlsClient` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`, `C33`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use catbird_mls::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use catbird_mls::client::chat_wire;
use catbird_mls::orchestrator::canonical_transport::{derive_key_id, CanonicalOperation};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::signature::Signer as _;

#[path = "fixtures/direct_request_i13.rs"]
mod direct_request_i13;
#[allow(dead_code)]
#[path = "support/native_archive_auth.rs"]
mod native_archive_auth;
use native_archive_auth::NativeArchiveAuthFixture;
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
const CAROL_DID: &str = "did:plc:carolcleanusercccccccccc";

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
    // Retained receipt generation 2; generation 1 remains `receipt_sk`.
    historical_receipt_sk: Option<P256SigningKey>,
    rotated_outcome_sk: Option<P256SigningKey>,
    rotate_outcome_key_on_next_publish: bool,
    tamper_next_receipt: bool,
    omit_next_receipt: bool,
    empty_stub_next_send: bool,
    lose_next_send_response: bool,
    fail_next_entries: bool,
    stale_next_submit_transition: bool,
    defer_next_commit_transition: bool,
    deferred_commit_transition: Option<PlatformHttpRequest>,
    lose_next_commit_response: bool,
    fail_next_commit_status: Option<u16>,
    next_ack_error: Option<(u16, String)>,
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
    // Verified `getEpochHead` chains: account DID -> `epochPublic`s in epoch order.
    labyrinth_epochs: BTreeMap<String, Vec<Value>>,
    // Enrolled chat device keys: (account DID, device ID) -> Ed25519 signing key.
    device_keys: BTreeMap<(String, String), [u8; 32]>,
    // Published request-key revisions: (account DID, device ID) -> revision (`prior + 1` only).
    dr_revisions: BTreeMap<(String, String), i64>,
    // Apply the next `enrollDevice` / `publishDirectRequestKeys`, then lose its response.
    lose_next_enroll_response: bool,
    lose_next_dr_keys_response: bool,
    // Signed `getConversationState.accountDeletions`: cid -> `#accountDeletedEntry`s.
    account_deletions: BTreeMap<String, Vec<Value>>,
    // Persistent authenticated state denials: (session DID, conversation) -> (status, code).
    conversation_state_errors: BTreeMap<(String, String), (u16, String)>,
    // Every request as (session account, URL, body), for exact-replay and no-network checks.
    http_log: Vec<(String, String, Vec<u8>)>,
    // One-shot XRPC refusals: (route suffix, status, error code, `Retry-After`).
    xrpc_failures: Vec<(&'static str, u16, &'static str, Option<&'static str>)>,
    // Answer the next prepare with a signed expiry receipt: "valid", "badSignature" or
    // "wrongRequestId" (`expired_prepare_receipt`).
    next_prepare_receipt: Option<&'static str>,
    // `mls-ds` send order: (conversation, actor DID, actor device) -> last accepted
    // (prior.generation, prior.epoch, sendCounter). A first-seen send at or below it is refused
    // `StaleSend` and writes nothing; `enforce_send_order: false` is a DS without the rule.
    send_order: BTreeMap<(String, String, String), (u64, u64, u64)>,
    enforce_send_order: bool,
    // Refuse every first-seen send `StaleSend`.
    refuse_sends: bool,
    // Hold the next `sendMessage` in the network: the client sees a transport error and the
    // request reaches the DS only on `deliver_held_sends`.
    hold_next_send: bool,
    held_sends: Vec<Value>,
    // Every `sendMessage` the DS saw: (messageId, sendCounter, ciphertext, outcome).
    send_attempts: Vec<(String, u64, String, &'static str)>,
    // Sign every new I13 receipt (application and C33 opening) under the current generation
    // `#mls-receipt-2` (`historical_receipt_sk`); generation 1 stays retained in the DID document.
    rotated_sequencer_receipts: bool,
    // `getMemberDevices` answers this exact key list for the DID instead of its enrolled devices.
    member_devices_override: Option<(String, Vec<[u8; 32]>)>,
    // Present this key for the enrolling device in `enrollDevice` and `getOwnDevices` answers
    // (reads still verify under the registered key): a DS reporting another key.
    enroll_answer_key: Option<[u8; 32]>,
    // Answer the next `acceptConversation(directRequest)` with a 2xx the coordinator did not
    // sign (receipt by another key, unsigned coordinates) and sequence nothing.
    forge_next_acceptance: bool,
    // Sequence the next `submitTransition` but forge its answer: "entry" carries another
    // signed request, "coordinates" are not the signed `next`.
    forge_next_transition_answer: Option<&'static str>,
    // `getEntries` serves `actorDeviceId` only entries from this seq on: the device joined there,
    // and mls-ds never makes a device a recipient of control entries sequenced before it joined.
    readable_from: BTreeMap<String, i64>,
    // `prepareDirectRequest` also selects a request key of another of the actor's devices: mls-ds
    // makes the sender's other devices Welcome recipients of its opening.
    select_sender_siblings: bool,
    // Sequence the next `closeConversation` (and wipe it), then lose its response.
    lose_next_close_response: bool,
    // Sequence the next `closeConversation` but answer with an entry carrying another request.
    forge_next_close_answer: bool,
    // Closed conversation -> (exact request bytes, recorded answer): mls-ds answers an exact
    // replay with the recorded result and refuses any other close.
    closes: BTreeMap<String, (Vec<u8>, Value)>,
}

struct SharedMockDs {
    inner: Mutex<MockDsState>,
    archive_auth: NativeArchiveAuthFixture,
}

impl SharedMockDs {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(MockDsState {
                receipt_sk: P256SigningKey::random(&mut rand::rngs::OsRng),
                historical_receipt_sk: None,
                rotated_outcome_sk: None,
                rotate_outcome_key_on_next_publish: false,
                tamper_next_receipt: false,
                omit_next_receipt: false,
                empty_stub_next_send: false,
                lose_next_send_response: false,
                fail_next_entries: false,
                stale_next_submit_transition: false,
                defer_next_commit_transition: false,
                deferred_commit_transition: None,
                lose_next_commit_response: false,
                fail_next_commit_status: None,
                next_ack_error: None,
                pds_records: BTreeMap::new(),
                dr_keys: BTreeMap::new(),
                convo_kps: BTreeMap::new(),
                conversations: BTreeMap::new(),
                entries: BTreeMap::new(),
                pending_welcomes: BTreeMap::new(),
                leaf_recoveries: BTreeMap::new(),
                acked_welcomes: Vec::new(),
                acked_watermarks: BTreeMap::new(),
                labyrinth_epochs: BTreeMap::new(),
                device_keys: BTreeMap::new(),
                dr_revisions: BTreeMap::new(),
                lose_next_enroll_response: false,
                lose_next_dr_keys_response: false,
                account_deletions: BTreeMap::new(),
                conversation_state_errors: BTreeMap::new(),
                http_log: Vec::new(),
                xrpc_failures: Vec::new(),
                next_prepare_receipt: None,
                send_order: BTreeMap::new(),
                enforce_send_order: true,
                refuse_sends: false,
                hold_next_send: false,
                held_sends: Vec::new(),
                send_attempts: Vec::new(),
                rotated_sequencer_receipts: false,
                member_devices_override: None,
                enroll_answer_key: None,
                forge_next_acceptance: false,
                forge_next_transition_answer: None,
                readable_from: BTreeMap::new(),
                select_sender_siblings: false,
                lose_next_close_response: false,
                forge_next_close_answer: false,
                closes: BTreeMap::new(),
            }),
            archive_auth: NativeArchiveAuthFixture::new(
                ALICE_DID,
                Arc::new(|| chrono::Utc::now().timestamp_millis()),
            ),
        })
    }

    fn receipt_did_doc(&self) -> Value {
        let g = self.inner.lock().unwrap();
        let method = dr_transcript::direct_request_receipt_key_id_for_authority(
            DS_DID,
            g.receipt_sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        let mut document: Value = serde_json::from_slice(&direct_request_i13::authority_document(
            &g.receipt_sk,
            &method,
            DS_DID,
        ))
        .unwrap();
        if let Some(rotated) = &g.rotated_outcome_sk {
            let rotated_method = dr_transcript::direct_request_receipt_key_id_for_authority(
                DS_DID,
                rotated.verifying_key().to_encoded_point(true).as_bytes(),
            )
            .unwrap();
            let rotated_document: Value = serde_json::from_slice(
                &direct_request_i13::authority_document(rotated, &rotated_method, DS_DID),
            )
            .unwrap();
            document["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .push(rotated_document["verificationMethod"][0].clone());
        }
        if let Some(historical) = &g.historical_receipt_sk {
            let request_method = dr_transcript::direct_request_receipt_key_id_for_authority(
                DS_DID,
                historical.verifying_key().to_encoded_point(true).as_bytes(),
            )
            .unwrap();
            let historical_document: Value = serde_json::from_slice(
                &direct_request_i13::authority_document(historical, &request_method, DS_DID),
            )
            .unwrap();
            let mut receipt_method = historical_document["verificationMethod"][1].clone();
            receipt_method["id"] = json!(format!("{DS_DID}#mls-receipt-2"));
            document["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .push(receipt_method);
        }
        document
    }

    fn for_account(self: &Arc<Self>, account_did: &str) -> Arc<dyn PlatformTransport> {
        Arc::new(AccountTransport {
            ds: self.clone(),
            account_did: account_did.to_owned(),
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

fn xrpc_error(status: u16, code: &str, message: &str) -> Result<PlatformHttpResponse, MLSError> {
    Ok(PlatformHttpResponse {
        status,
        headers: vec![PlatformHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body: serde_json::to_vec(&json!({ "error": code, "message": message })).unwrap(),
    })
}

/// The coordinator's signed `#directRequestExpiredReceipt` for the prepare body `b` (a replay
/// after its lease expired). `fault` forges it: "badSignature" signs with another key,
/// "wrongRequestId" binds another request; "valid" leaves it intact.
fn expired_prepare_receipt(sk: &P256SigningKey, b: &Value, fault: &str) -> Value {
    let transcript = dr_transcript::direct_request_signing_bytes(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(b).unwrap(),
    )
    .unwrap();
    let digest = STANDARD.encode(Sha256::digest(&transcript));
    let request_id = match fault {
        "wrongRequestId" => json!(uuid::Uuid::new_v4().to_string()),
        _ => b["requestId"].clone(),
    };
    let body = json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2", "authorityDid": DS_DID,
        "keyId": dr_transcript::direct_request_receipt_key_id_for_authority(
            DS_DID, sk.verifying_key().to_encoded_point(true).as_bytes(),
        ).unwrap(),
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestExpiredReceipt",
            "requestId": request_id, "requestKind": "expiry",
            "requestDigest": digest, "preparationRequestDigest": digest,
            "recordedAt": b["signedAt"],
            "actorDid": b["actorDid"], "actorDeviceId": b["actorDeviceId"],
            "actorKeyId": b["keyId"], "authGeneration": b["authGeneration"],
        },
    });
    let transcript = dr_transcript::direct_request_signing_bytes(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let forger = P256SigningKey::random(&mut rand::rngs::OsRng);
    let signer = if fault == "badSignature" { &forger } else { sk };
    let signature: p256::ecdsa::Signature = signer.sign(&transcript);
    let signature = signature.normalize_s().unwrap_or(signature);
    json!({
        "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "body": body, "signature": STANDARD.encode(signature.to_bytes()),
    })
}

/// `mls-ds` device-signed Labyrinth request (`labyrinth::auth::verify_signed_write`,
/// `read_auth::verify`): base64url claim `header`, and Ed25519 `{header}-signature` over
/// `domain || claim` by the session account's enrolled key for the claim's `device_field`.
fn device_signed_claim(
    g: &MockDsState,
    account: &str,
    req: &PlatformHttpRequest,
    header: &str,
    device_field: &str,
    domain: &[u8],
) -> Result<(Value, [u8; 32]), &'static str> {
    let decoded = |name: &str| {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| URL_SAFE_NO_PAD.decode(&h.value).ok())
    };
    let claim_bytes = decoded(header).ok_or("missing device-signed claim")?;
    let signature: [u8; 64] = decoded(&format!("{header}-signature"))
        .and_then(|s| s.try_into().ok())
        .ok_or("missing device signature")?;
    let claim: Value = serde_json::from_slice(&claim_bytes).map_err(|_| "malformed claim")?;
    let device = claim[device_field]
        .as_str()
        .ok_or("claim names no device")?;
    let key = *g
        .device_keys
        .get(&(account.to_owned(), device.to_owned()))
        .ok_or("device is not enrolled for the session account")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .and_then(|k| {
            k.verify_strict(
                &[domain, &claim_bytes].concat(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
        })
        .map_err(|_| "device signature does not verify")?;
    Ok((claim, key))
}

/// `read_auth::verify`: the claim names the session account, this route, and this exact
/// canonical query (every decoded pair, sorted, RFC 3986 re-encoded). Ordinary
/// directory reads bind the claim device to `actorDeviceId`; fixed-shape reads do not.
fn verify_read(
    g: &MockDsState,
    account: &str,
    req: &PlatformHttpRequest,
    nsid: &str,
    actor_device_param: bool,
) -> Result<(), &'static str> {
    use catbird_mls::labyrinth::write_auth::{canonical_query_params, READ_DOMAIN, READ_HEADER};
    let (claim, _) = device_signed_claim(g, account, req, READ_HEADER, "deviceId", READ_DOMAIN)?;
    let pairs: Vec<(String, String)> = req
        .url
        .split_once('?')
        .map_or("", |(_, q)| q)
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (pct_decode(k), pct_decode(v)))
        .collect();
    let params: Vec<(&str, String)> = pairs.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    let devices = pairs
        .iter()
        .filter(|(k, _)| k == "actorDeviceId")
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>();
    let expected_devices = [claim["deviceId"].as_str().unwrap_or_default()];
    if claim["did"] != account
        || claim["nsid"] != nsid
        || claim["query"] != canonical_query_params(&params)
        || (actor_device_param && devices != expected_devices)
        || (!actor_device_param && !devices.is_empty())
    {
        return Err("read claim does not bind this account, route, and query");
    }
    Ok(())
}

impl SharedMockDs {
    /// One request on `account`'s authenticated session (the DPoP/service-auth principal).
    fn execute(
        &self,
        account: &str,
        req: PlatformHttpRequest,
    ) -> Result<PlatformHttpResponse, MLSError> {
        self.inner.lock().unwrap().http_log.push((
            account.to_owned(),
            req.url.clone(),
            req.body.clone().unwrap_or_default(),
        ));
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
            return ok_json(self.receipt_did_doc());
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

        let path = url.split('?').next().unwrap_or(url);
        if let Some(i) = g.xrpc_failures.iter().position(|f| path.ends_with(f.0)) {
            let (_, status, code, retry_after) = g.xrpc_failures.remove(i);
            let mut resp = xrpc_error(status, code, "injected refusal")?;
            if let Some(value) = retry_after {
                resp.headers.push(PlatformHttpHeader {
                    name: "Retry-After".to_string(),
                    value: value.to_string(),
                });
            }
            return Ok(resp);
        }

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

        if url.contains("/xrpc/blue.catbird.labyrinth.getMailboxKeysRecord") {
            if let Err(message) = verify_read(
                &g,
                account,
                &req,
                "blue.catbird.labyrinth.getMailboxKeysRecord",
                false,
            ) {
                return xrpc_error(401, "InvalidSignature", message);
            }
            let repo = q.get("did").cloned().unwrap_or_default();
            let rkey = q.get("rkey").cloned().unwrap_or_default();
            let collection = labyrinth::records::nsid::MAILBOX_KEYS.to_string();
            let Some((value, cid)) = self.archive_auth.mailbox_keys_record(&repo, &rkey) else {
                return Ok(PlatformHttpResponse {
                    status: 404,
                    headers: Vec::new(),
                    body: br#"{"error":"RecordNotFound"}"#.to_vec(),
                });
            };
            return ok_json(json!({
                "uri": format!("at://{repo}/{collection}/{rkey}"),
                "cid": cid,
                "value": value
            }));
        }

        if url.contains("/xrpc/com.atproto.repo.getRecord") {
            let key = (
                q.get("repo").cloned().unwrap_or_default(),
                q.get("collection").cloned().unwrap_or_default(),
                q.get("rkey").cloned().unwrap_or_default(),
            );
            let Some(value) = g.pds_records.get(&key).cloned() else {
                return Ok(PlatformHttpResponse {
                    status: 400,
                    headers: Vec::new(),
                    body: br#"{"error":"RecordNotFound"}"#.to_vec(),
                });
            };
            let (repo, collection, rkey) = key;
            return ok_json(json!({
                "uri": format!("at://{repo}/{collection}/{rkey}"),
                "cid": "bafyreimock",
                "value": value
            }));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.publishEpochHead") {
            // `mls-ds` `record_head`: a chat device of the session account signed this exact
            // body and attested a head that verifies and extends the account's chain by one.
            use catbird_mls::labyrinth::write_auth::{WRITE_BODY_HEADER, WRITE_DOMAIN};
            let nsid = "blue.catbird.labyrinth.publishEpochHead";
            let (write, device_key) = match device_signed_claim(
                &g,
                account,
                &req,
                WRITE_BODY_HEADER,
                "actorDeviceId",
                WRITE_DOMAIN,
            ) {
                Ok(verified) => verified,
                Err(message) => return xrpc_error(401, "InvalidSignature", message),
            };
            let payload_sha256 =
                hex::encode(Sha256::digest(req.body.as_deref().unwrap_or_default()));
            if write["endpointNsid"] != nsid || write["payloadSha256"] != payload_sha256 {
                return xrpc_error(
                    400,
                    "InvalidRequest",
                    "write body does not bind this payload",
                );
            }
            let parse = |value: &Value| {
                serde_json::from_value::<labyrinth::records::EpochPublicDef>(value.clone())
                    .ok()
                    .and_then(|def| def.to_public().ok())
            };
            let epoch_json = body_json["epoch"].clone();
            let Some(epoch) = parse(&epoch_json).filter(|e| e.verify(account, None).is_ok()) else {
                return xrpc_error(400, "InvalidRequest", "epoch head does not verify");
            };
            if epoch.attestation.transport_public_key != device_key {
                return xrpc_error(400, "AttestationNotCaller", "head not attested by caller");
            }
            let chain = g.labyrinth_epochs.entry(account.to_owned()).or_default();
            if let Some(existing) = chain
                .iter()
                .find(|e| e["epochNumber"] == epoch_json["epochNumber"])
            {
                return if *existing == epoch_json {
                    ok_json(json!({}))
                } else {
                    xrpc_error(409, "EpochHeadConflict", "different head at this epoch")
                };
            }
            let links = match chain.last().and_then(parse) {
                None => epoch.seq == 0,
                Some(latest) => epoch
                    .verify_link(latest.seq, &latest.head, &latest.keys.sig)
                    .is_ok(),
            };
            if !links {
                return xrpc_error(400, "InvalidEpochChain", "head does not extend the chain");
            }
            chain.push(epoch_json);
            return ok_json(json!({}));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.getEpochHead") {
            if let Err(message) = verify_read(
                &g,
                account,
                &req,
                "blue.catbird.labyrinth.getEpochHead",
                true,
            ) {
                return xrpc_error(401, "InvalidSignature", message);
            }
            let chain = g
                .labyrinth_epochs
                .get(q.get("did").map_or("", String::as_str))
                .cloned()
                .unwrap_or_default();
            let end = match q.get("epochNumber") {
                Some(n) => n.parse::<u64>().ok().and_then(|n| {
                    chain
                        .iter()
                        .position(|e| e["epochNumber"].as_u64() == Some(n))
                }),
                None => chain.len().checked_sub(1),
            };
            let Some(end) = end else {
                return xrpc_error(404, "EpochNotFound", "no such epoch head");
            };
            let chain = &chain[..=end];
            return ok_json(json!({
                "epoch": chain[end], "chain": chain, "floorSeq": chain[0]["epochNumber"],
            }));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.getChatDeviceKeys") {
            let nsid = "blue.catbird.labyrinth.getChatDeviceKeys";
            if let Err(message) = verify_read(&g, account, &req, nsid, true) {
                return xrpc_error(401, "InvalidSignature", message);
            }
            let did = q.get("did").cloned().unwrap_or_default();
            let items: Vec<Value> = g
                .device_keys
                .iter()
                .filter(|((owner, _), _)| *owner == did)
                .map(|(_, key)| {
                    json!({
                        "keyId": derive_key_id(key),
                        "signingPublicKey": { "$bytes": STANDARD.encode(key) },
                    })
                })
                .collect();
            return ok_json(json!({ "items": items }));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.getMemberDevices") {
            // Every enrolled device of `did` has been a member since the conversation began.
            let did = q.get("did").cloned().unwrap_or_default();
            let keys: Vec<[u8; 32]> = match &g.member_devices_override {
                Some((owner, keys)) if *owner == did => keys.clone(),
                _ => g
                    .device_keys
                    .iter()
                    .filter(|((owner, _), _)| *owner == did)
                    .map(|(_, key)| *key)
                    .collect(),
            };
            let items: Vec<Value> = keys
                .iter()
                .map(|key| {
                    json!({
                        "signingPublicKey": { "$bytes": STANDARD.encode(key) },
                        "joinedSeq": 0,
                    })
                })
                .collect();
            return ok_json(json!({ "items": items }));
        }

        if url.contains("/xrpc/blue.catbird.chat.enrollDevice") {
            let b = &body_json["signedRequest"]["body"];
            let did = b["actorDid"].as_str().unwrap().to_string();
            if did != account {
                return xrpc_error(403, "NotAuthorized", "actorDid is not the session account");
            }
            let dev = b["deviceId"].as_str().unwrap().to_string();
            // `mls-ds` enrollment is create-only (`lock_enrollment_absence_scope`).
            if g.device_keys.contains_key(&(did.clone(), dev.clone())) {
                return xrpc_error(400, "DeviceAlreadyExists", "DeviceAlreadyExists");
            }
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            let key: [u8; 32] = chat_wire::json_bytes(&b["signaturePublicKey"])
                .unwrap()
                .try_into()
                .unwrap();
            g.device_keys.insert((did.clone(), dev.clone()), key);
            g.convo_kps
                .entry((did, dev.clone()))
                .or_default()
                .extend(kps);
            if std::mem::take(&mut g.lose_next_enroll_response) {
                return Err(MLSError::Internal(
                    "enrollDevice response lost after registration".into(),
                ));
            }
            // `mls-ds` answers the registered `deviceView`.
            let presented = g.enroll_answer_key.unwrap_or(key);
            return ok_json(json!({ "device": {
                "deviceId": dev,
                "keyId": derive_key_id(&presented),
                "signaturePublicKey": { "$bytes": STANDARD.encode(presented) },
                "authGeneration": 1,
                "status": "active",
                "createdAt": "2026-11-03T00:00:00.000Z",
                "updatedAt": "2026-11-03T00:00:00.000Z",
                "availablePackageCount": 2,
                "reservedPackageCount": 0,
            }}));
        }

        if url.contains("/xrpc/blue.catbird.chat.getOwnDevices") {
            // `mls-ds` verifies the chat read signature against the device's registered key.
            let device = match device_signed_claim(
                &g,
                account,
                &req,
                chat_wire::CHAT_READ_HEADER,
                "deviceId",
                b"CATBIRD-CHAT-READ\0",
            ) {
                Ok((claim, _)) if claim["nsid"] == "blue.catbird.chat.getOwnDevices" => {
                    claim["deviceId"].as_str().unwrap().to_owned()
                }
                Ok(_) => return xrpc_error(401, "InvalidSignature", "claim names another route"),
                Err(message) => return xrpc_error(401, "InvalidSignature", message),
            };
            let items: Vec<Value> = g
                .device_keys
                .iter()
                .filter(|((owner, _), _)| owner == account)
                .map(|((owner, dev), key)| {
                    let key = &g.enroll_answer_key.filter(|_| *dev == device).unwrap_or(*key);
                    let mut item = json!({ "device": {
                        "deviceId": dev,
                        "keyId": derive_key_id(key),
                        "signaturePublicKey": { "$bytes": STANDARD.encode(key) },
                        "authGeneration": 1,
                        "status": "active",
                        "createdAt": "2026-11-03T00:00:00.000Z",
                        "updatedAt": "2026-11-03T00:00:00.000Z",
                        "availablePackageCount": g.convo_kps.get(&(owner.clone(), dev.clone())).map_or(0, Vec::len),
                        "reservedPackageCount": 0,
                    }});
                    // Present only for the authenticated device once its request capability exists.
                    if let Some(revision) = g.dr_revisions.get(&(owner.clone(), dev.clone())) {
                        if *dev == device {
                            item["directRequestKeyPool"] = json!({
                                "enabled": true,
                                "revision": revision,
                                "usableCount": 8,
                                "reservedCount": 0,
                                "asOf": "2026-11-03T00:00:00.000Z",
                                "usableUntil": "2026-11-10T00:10:00.000Z",
                            });
                        }
                    }
                    item
                })
                .collect();
            return ok_json(json!({
                "items": items,
                "hasMore": false,
                "snapshotExpiresAt": "2026-11-03T00:05:00.000Z",
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
            // `mls-ds` `publish_request_keys`: each publication advances the revision by one.
            let revision = b["revision"].as_i64().unwrap();
            let prior = g.dr_revisions.get(&(did.clone(), dev.clone())).copied();
            if revision != prior.unwrap_or(0) + 1 {
                return xrpc_error(
                    400,
                    "InvalidRequest",
                    "request-key revision must advance by one",
                );
            }
            g.dr_revisions.insert((did.clone(), dev.clone()), revision);
            let mut list = Vec::new();
            for item in b["keys"].as_array().cloned().unwrap_or_default() {
                list.push((
                    dev.clone(),
                    item["keyPackage"].clone(),
                    item["grant"].clone(),
                ));
            }
            g.dr_keys.insert(did, list);
            if std::mem::take(&mut g.lose_next_dr_keys_response) {
                return Err(MLSError::Internal(
                    "publishDirectRequestKeys response lost after publication".into(),
                ));
            }
            return ok_json(json!({ "published": true }));
        }

        if url.contains("/xrpc/blue.catbird.chat.prepareDirectRequest") {
            let b = &body_json["signedRequest"]["body"];
            if let Some(fault) = g.next_prepare_receipt.take() {
                let outcome = expired_prepare_receipt(&g.receipt_sk, b, fault);
                return ok_json(json!({ "outcome": outcome }));
            }
            let recipient_did = b["recipientDid"].as_str().unwrap().to_string();
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let avail = g
                .dr_keys
                .get_mut(&recipient_did)
                .ok_or_else(|| MLSError::Internal(format!("no DR keys for {recipient_did}")))?;
            let (dev_id, kp, grant) = avail.pop().expect("at least 1 DR key");
            let mut selected = vec![json!({
                "actorDid": recipient_did,
                "actorDeviceId": dev_id,
                "keyPackage": kp,
                "grant": grant,
            })];
            if g.select_sender_siblings {
                let actor_did = b["actorDid"].as_str().unwrap().to_string();
                let keys = g.dr_keys.get_mut(&actor_did).expect("sibling request keys");
                let at = keys
                    .iter()
                    .position(|(device, _, _)| b["actorDeviceId"] != device.as_str())
                    .expect("a sibling device");
                let (device, kp, grant) = keys.remove(at);
                selected.push(json!({
                    "actorDid": actor_did,
                    "actorDeviceId": device,
                    "keyPackage": kp,
                    "grant": grant,
                }));
            }
            let prep_digest = STANDARD.encode(Sha256::digest(cid.as_bytes()));
            let preparation_outcome_key = g
                .rotated_outcome_sk
                .clone()
                .unwrap_or_else(|| g.receipt_sk.clone());
            return ok_json(json!({
                "outcome": {
                    "conversationId": cid,
                    "authorityDid": DS_DID,
                    "receiptKeyId": dr_transcript::direct_request_receipt_key_id_for_authority(
                        DS_DID, preparation_outcome_key.verifying_key().to_encoded_point(true).as_bytes(),
                    ).unwrap(),
                    "preparationDigest": { "$bytes": prep_digest },
                    "selectedDevices": selected,
                }
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.publishDirectRequest") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let coords = b["next"].clone();
            let opening_receipt = match (&g.historical_receipt_sk, g.rotated_sequencer_receipts) {
                (Some(current), true) => direct_request_i13::receipt_with_key_id(
                    current,
                    &format!("{DS_DID}#mls-receipt-2"),
                    b,
                    1,
                    DS_DID,
                ),
                _ => direct_request_i13::receipt(&g.receipt_sk, b, 1, DS_DID),
            };
            if std::mem::take(&mut g.rotate_outcome_key_on_next_publish) {
                g.rotated_outcome_sk = Some(P256SigningKey::random(&mut rand::rngs::OsRng));
            }
            let outcome_key = g
                .rotated_outcome_sk
                .clone()
                .unwrap_or_else(|| g.receipt_sk.clone());
            let publication_transcript = dr_transcript::direct_request_signing_bytes(
                DirectRequestKind::Publish,
                &serde_json::to_vec(b).unwrap(),
            )
            .unwrap();
            let outcome_body = json!({
                "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
                "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
                "protocolVersion": "2", "authorityDid": DS_DID,
                "keyId": dr_transcript::direct_request_receipt_key_id_for_authority(
                    DS_DID, outcome_key.verifying_key().to_encoded_point(true).as_bytes(),
                ).unwrap(),
                "receipt": {
                    "$type": "blue.catbird.chat.defs#directRequestPublishedReceipt",
                    "requestId": b["requestId"], "requestKind": "publish",
                    "requestDigest": STANDARD.encode(Sha256::digest(&publication_transcript)),
                    "recordedAt": b["signedAt"], "conversationId": cid,
                    "firstMessageId": b["firstMessageId"], "coordinates": coords,
                    "preparationRequestDigest": b["preparationRequestDigest"],
                    "actorDid": b["actorDid"], "actorDeviceId": b["actorDeviceId"],
                    "actorKeyId": b["keyId"], "authGeneration": b["authGeneration"],
                    "sequencerReceipt": opening_receipt,
                },
            });
            let transcript = dr_transcript::direct_request_signing_bytes(
                DirectRequestKind::Outcome,
                &serde_json::to_vec(&outcome_body).unwrap(),
            )
            .unwrap();
            let signature: p256::ecdsa::Signature = outcome_key.sign(&transcript);
            let signature = signature.normalize_s().unwrap_or(signature);
            let outcome = json!({
                "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
                "body": outcome_body, "signature": STANDARD.encode(signature.to_bytes()),
            });
            g.conversations.insert(
                cid.clone(),
                json!({
                    "conversationKind": "direct",
                    "sequencerDid": DS_DID,
                    "coordinates": coords,
                    "participants": [
                        { "userDid": b["actorDid"], "status": "active", "role": "admin", "leafCount": 1 },
                        { "userDid": b["recipientDid"], "status": "pending", "role": "member", "leafCount": 0 }
                    ],
                    "directRequest": {
                        "requestId": b["requestId"],
                        "firstMessageId": b["firstMessageId"],
                        "senderDid": b["actorDid"],
                        "recipientDid": b["recipientDid"],
                        "consent": "incomingPending",
                        "importUntil": b["importUntil"],
                        "contextHash": b["contextHash"],
                        "preparationDigest": b["preparationDigest"]
                    }
                }),
            );
            g.entries.entry(cid.clone()).or_default().push(json!({
                "$type": "blue.catbird.chat.defs#directRequestEntry",
                "entryId": b["firstMessageId"], "conversationId": cid,
                "publicationReceipt": outcome.clone(), "sequencerReceipt": opening_receipt,
                "seq": 1,
                "sequencerDid": DS_DID,
                "signedRequest": sr,
            }));
            return ok_json(json!({ "outcome": outcome }));
        }

        if url.contains("/xrpc/blue.catbird.chat.createConversation") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let coords = b["next"].clone();
            let mut parts = b["manifest"]["participants"].clone();
            let creator_did = b["manifest"]["actorLeaf"]["userDid"].as_str();
            if let Some(arr) = parts.as_array_mut() {
                for p in arr {
                    let lc = usize::from(p["userDid"].as_str() == creator_did);
                    p["leafCount"] = json!(lc);
                }
            }
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
            g.entries.entry(cid.clone()).or_default().push(json!({
                "$type": "blue.catbird.chat.defs#creationEntry",
                "seq": 1,
                "coordinates": coords.clone(),
                "signedRequest": sr,
            }));
            return ok_json(json!({ "result": {
                "$type": "blue.catbird.chat.defs#conversationCreatedResult",
                "coordinates": coords,
                "entry": {
                    "entryId": b["transitionId"], "conversationId": cid, "seq": 1,
                    "signedRequest": sr, "receivedAt": b["signedAt"],
                },
            }}));
        }

        if url.contains("/xrpc/blue.catbird.chat.acceptConversation") {
            if let Some(dr) = body_json.get("directRequest") {
                let b = &dr["body"];
                let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
                let mut next_coords = b["next"].clone();
                let entry = json!({
                    "$type": "blue.catbird.chat.defs#directRequestAcceptanceEntry",
                    "entryId": uuid::Uuid::new_v4().to_string(),
                    "conversationId": cid,
                    "seq": g.entries.get(&cid).map_or(0, Vec::len) as i64 + 1,
                    "signedRequest": dr,
                    "receivedAt": b["signedAt"],
                });
                let mut receipt = acceptance_commit_receipt(&g.receipt_sk, &entry);
                let mut proof_entry = entry.clone();
                proof_entry.as_object_mut().unwrap().remove("$type");
                if std::mem::take(&mut g.forge_next_acceptance) {
                    // Coordinates the coordinator never signed; nothing is sequenced.
                    next_coords["stateVersion"] =
                        json!(next_coords["stateVersion"].as_i64().unwrap() + 5);
                    receipt["body"]["next"] = next_coords.clone();
                    return ok_json(json!({
                        "coordinates": next_coords,
                        "acceptanceProof": { "entry": proof_entry, "receipt": receipt },
                    }));
                }
                g.entries.entry(cid.clone()).or_default().push(entry);
                if let Some(st) = g.conversations.get_mut(&cid) {
                    st["coordinates"] = next_coords.clone();
                    if let Some(parts) = st["participants"].as_array_mut() {
                        for p in parts {
                            p["status"] = json!("active");
                            p["leafCount"] = json!(1);
                        }
                    }
                }
                return ok_json(json!({
                    "coordinates": next_coords,
                    "acceptanceProof": { "entry": proof_entry, "receipt": receipt },
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
            let is_commit = btype.ends_with("commitTransitionBody")
                || btype.ends_with("leafRecoveryFulfillmentBody");
            if is_commit {
                if let Some(status) = g.fail_next_commit_status.take() {
                    return Ok(PlatformHttpResponse {
                        status,
                        headers: vec![],
                        body: serde_json::to_vec(&json!({
                            "error": if status == 403 { "AdminRequired" } else { "Unavailable" }
                        }))
                        .unwrap(),
                    });
                }
            }
            if is_commit && std::mem::take(&mut g.defer_next_commit_transition) {
                g.deferred_commit_transition = Some(req);
                return Err(MLSError::Internal(
                    "transition timed out before deferred publication".into(),
                ));
            }
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
                for change in b["participantChanges"].as_array().into_iter().flatten() {
                    if change["$type"] == "blue.catbird.chat.defs#removeParticipant" {
                        if let Some(parts) = st["participants"].as_array_mut() {
                            parts.retain(|p| p["userDid"] != change["userDid"]);
                        }
                    }
                }
                let leaves_snap = st["leaves"].as_array().cloned().unwrap_or_default();
                if let Some(parts) = st["participants"].as_array_mut() {
                    for p in parts {
                        let lc = leaves_snap
                            .iter()
                            .filter(|l| l["userDid"] == p["userDid"])
                            .count();
                        p["leafCount"] = json!(lc);
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
            if is_commit && std::mem::take(&mut g.lose_next_commit_response) {
                return Err(MLSError::Internal(
                    "transition response lost after acceptance".into(),
                ));
            }
            let entry_kind = match btype.trim_start_matches("blue.catbird.chat.defs#") {
                "commitTransitionBody" => "commitEntry",
                "leafRecoveryFulfillmentBody" => "leafRecoveryFulfillmentEntry",
                "policyTransitionBody" => "policyEntry",
                "metadataTransitionBody" => "metadataEntry",
                other => panic!("fixture has no entry kind for {other}"),
            };
            let mut answer = json!({
                "coordinates": next_coords,
                "entry": {
                    "$type": format!("blue.catbird.chat.defs#{entry_kind}"),
                    "entryId": b["transitionId"], "conversationId": cid, "seq": next_seq,
                    "signedRequest": sr, "receivedAt": b["signedAt"],
                },
                "welcomes": [],
            });
            match g.forge_next_transition_answer.take() {
                Some("entry") => {
                    answer["entry"]["signedRequest"]["body"]["transitionId"] =
                        json!(uuid::Uuid::new_v4().to_string())
                }
                Some("coordinates") => {
                    answer["coordinates"]["stateVersion"] =
                        json!(next_coords["stateVersion"].as_i64().unwrap() + 5)
                }
                _ => {}
            }
            return ok_json(answer);
        }

        if url.contains("/xrpc/blue.catbird.chat.sendMessage") {
            if g.empty_stub_next_send {
                g.empty_stub_next_send = false;
                return ok_json(json!({ "ok": true }));
            }
            if std::mem::take(&mut g.hold_next_send) {
                let attempt = send_attempt(&body_json, "held");
                g.send_attempts.push(attempt);
                g.held_sends.push(body_json);
                return Err(MLSError::Internal("sendMessage held by the network".into()));
            }
            let lose_response = std::mem::take(&mut g.lose_next_send_response);
            let response = sequence_send(&mut g, &body_json)?;
            if lose_response && response.status == 200 {
                return Err(MLSError::Internal(
                    "send response lost after publication".into(),
                ));
            }
            return Ok(response);
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
            if let Some((status, code)) = g
                .conversation_state_errors
                .get(&(account.to_owned(), cid.to_owned()))
                .cloned()
            {
                return xrpc_error(status, &code, "authenticated conversation-state denial");
            }
            let Some(state) = g.conversations.get(cid).cloned() else {
                return xrpc_error(400, "ConversationNotFound", "conversation not found");
            };
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
                // Plain `#accountDeletedEntry` refs: the state list carries no `$type`.
                "accountDeletions": g.account_deletions.get(cid).into_iter().flatten().map(|entry| {
                    let mut entry = entry.clone();
                    entry.as_object_mut().unwrap().remove("$type");
                    entry
                }).collect::<Vec<_>>(),
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
            let readable_from = q
                .get("actorDeviceId")
                .and_then(|device| g.readable_from.get(device))
                .copied()
                .unwrap_or(0);
            let list: Vec<Value> = g
                .entries
                .get(&cid)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|e| {
                    let seq = e["seq"].as_i64().unwrap_or(0);
                    seq > after && seq >= readable_from
                })
                .collect();
            return ok_json(json!({ "entries": list }));
        }

        if url.contains("/xrpc/blue.catbird.chat.acknowledgeEntries") {
            if let Some((status, code)) = g.next_ack_error.take() {
                return Ok(PlatformHttpResponse {
                    status,
                    headers: vec![],
                    body: serde_json::to_vec(&json!({
                        "error": code, "message": "unrelated HTTP 404 detail",
                    }))
                    .unwrap(),
                });
            }
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

        if url.contains("/xrpc/blue.catbird.chat.closeConversation") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            assert_eq!(b["$type"], "blue.catbird.chat.defs#conversationCloseBody");
            assert_eq!(b["signatureDomain"], "CATBIRD-CHAT-CLOSE\0");
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
            let raw = req.body.clone().unwrap_or_default();
            if let Some((recorded, answer)) = g.closes.get(&cid) {
                return if *recorded == raw {
                    ok_json(answer.clone())
                } else {
                    xrpc_error(409, "ConversationClosed", "conversation is closed")
                };
            }
            let next_seq = (g.entries.get(&cid).map(Vec::len).unwrap_or(0) as i64) + 1;
            // A `ref`, not a union member: `mls-ds` presents it without `$type`.
            let tombstone = json!({
                "conversationId": cid,
                "conversationKind": b["conversationKind"],
                "retired": b["retired"],
                "terminalSeq": next_seq,
                "closedByDid": b["actorDid"],
                "closedByDeviceId": b["actorDeviceId"],
                "closedAt": b["signedAt"],
            });
            let entry = json!({
                "$type": "blue.catbird.chat.defs#conversationCloseEntry",
                "entryId": b["transitionId"],
                "conversationId": cid,
                "seq": next_seq,
                "receivedAt": b["signedAt"],
                "signedRequest": sr,
                "tombstone": tombstone,
            });
            // The close wipe: `getEntries` serves nothing new for it, so no echo arrives.
            g.conversations.remove(&cid);
            g.entries.remove(&cid);
            g.leaf_recoveries.remove(&cid);
            let mut answer = json!({
                "result": {
                    "tombstone": tombstone,
                    "entry": entry,
                }
            });
            g.closes.insert(cid, (raw, answer.clone()));
            if std::mem::take(&mut g.lose_next_close_response) {
                return Err(MLSError::Internal(
                    "close response lost after sequencing".into(),
                ));
            }
            if std::mem::take(&mut g.forge_next_close_answer) {
                answer["result"]["entry"]["signedRequest"]["body"]["transitionId"] =
                    json!(uuid::Uuid::new_v4().to_string());
            }
            return ok_json(answer);
        }

        ok_json(json!({}))
    }
}

/// Server-compatible `#accountDeletedEntry`: the v2 authority transcript binds the exact retained
/// receipt method and then the complete v1 deletion record transcript.
fn signed_account_deletion(
    key: &P256SigningKey,
    key_id: &str,
    sequencer: &str,
    cid: &str,
    deleted: &str,
    seq: i64,
) -> Value {
    let entry_id = uuid::Uuid::new_v4().to_string();
    let received_at = "2026-11-03T00:00:00.000Z";
    let seq_text = seq.to_string();
    let fields = [sequencer, cid, deleted, &seq_text, &entry_id, received_at];
    let mut message = b"catbird-mls-account-deletion-authority-v2\0".to_vec();
    message.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
    message.extend_from_slice(key_id.as_bytes());
    message.extend_from_slice(b"catbird-mls-account-deletion-v1\0");
    for field in fields {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    let signature: p256::ecdsa::Signature = key.sign(&message);
    let signature = signature.normalize_s().unwrap_or(signature);
    json!({
        "$type": "blue.catbird.chat.defs#accountDeletedEntry",
        "entryId": entry_id,
        "conversationId": cid,
        "seq": seq,
        "deletedDid": deleted,
        "sequencerDid": sequencer,
        "receivedAt": received_at,
        "sequencerAuthority": {
            "sequencerDid": sequencer,
            "keyId": key_id,
            "signature": { "$bytes": STANDARD.encode(signature.to_bytes()) },
        },
    })
}

struct AccountTransport {
    ds: Arc<SharedMockDs>,
    account_did: String,
}

impl PlatformTransport for AccountTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        self.ds
            .archive_auth
            .execute_for(&self.account_did, &request, |raw| {
                self.ds.execute(&self.account_did, raw.clone())
            })
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
        ds.for_account(ALICE_DID),
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
        ds.for_account(BOB_DID),
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
        ds.for_account(EVE_DID),
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
    let preparation_receipt_method = {
        let mut state = ds.inner.lock().unwrap();
        state.rotate_outcome_key_on_next_publish = true;
        dr_transcript::direct_request_receipt_key_id_for_authority(
            DS_DID,
            state
                .receipt_sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap()
    };
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
    let publication_receipt_method = {
        let state = ds.inner.lock().unwrap();
        let rotated = state
            .rotated_outcome_sk
            .as_ref()
            .expect("publish rotated the retained outcome key");
        dr_transcript::direct_request_receipt_key_id_for_authority(
            DS_DID,
            rotated.verifying_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap()
    };
    assert_ne!(
        preparation_receipt_method, publication_receipt_method,
        "publication outcome verification resolves its own retained keyId"
    );

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
        ds.archive_auth.committed_space_write_count() > 0,
        "Labyrinth sealed batch must be written via com.atproto.space.applyWrites"
    );

    let bob_applied = bob.sync().expect("bob sync message");
    assert!(bob_applied >= 1);

    // NSE already consumed this message's MLS ratchet. Retain its genuine authenticated
    // frame/nonce, require the real I13 receipt even after payload pruning, and do not replay MLS.
    let archive_key = format!("native.message:{dm_cid}:{msg1_id}");
    let mut pending_evidence: Value = bob
        .db()
        .read_tx(|tx| {
            Ok(serde_json::from_slice(&tx.get_labyrinth_state(&archive_key)?.unwrap()).unwrap())
        })
        .unwrap();
    pending_evidence["sequencer_receipt_json"] = Value::Null;
    bob.db()
        .write_tx(|tx| {
            tx.put_labyrinth_state(
                &archive_key,
                &serde_json::to_vec(&pending_evidence).unwrap(),
                1,
            )?;
            tx.put_pending_op(
                "native_archive_receipt",
                &msg1_id,
                &json!({
                    "conversation_id": dm_cid, "seq": sent1.seq,
                })
                .to_string(),
                1,
            )
        })
        .unwrap();
    let mls_snapshot = || {
        bob.db()
            .read_tx(|tx| {
                let mut stmt = tx
                    .conn()
                    .prepare(
                        "SELECT value_bytes FROM openmls_kv ORDER BY version, scope, key_bytes",
                    )
                    .unwrap();
                let bytes = stmt
                    .query_map([], |row| row.get::<_, Vec<u8>>(0))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                Ok(bytes)
            })
            .unwrap()
    };
    let before_receipt_replay = mls_snapshot();
    let receipt = {
        let mut state = ds.inner.lock().unwrap();
        let entry = state
            .entries
            .get_mut(&dm_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == msg1_id)
            .unwrap();
        let receipt = entry["sequencerReceipt"].clone();
        let entry_id = entry["entryId"].as_str().unwrap_or(&msg1_id).to_owned();
        *entry = json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "conversationId": dm_cid, "entryId": entry_id, "seq": sent1.seq,
            "payloadPruned": true, "sequencerReceipt": receipt,
        });
        entry["sequencerReceipt"]["signature"] = json!({ "$bytes": STANDARD.encode([0u8; 64]) });
        receipt
    };
    assert!(
        bob.sync().is_err(),
        "cached plaintext is not a substitute for a valid receipt"
    );
    assert_eq!(mls_snapshot(), before_receipt_replay);
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_pending_op("native_archive_receipt", &msg1_id))
        .unwrap()
        .is_some());
    {
        let mut state = ds.inner.lock().unwrap();
        state
            .entries
            .get_mut(&dm_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["seq"] == sent1.seq)
            .unwrap()["sequencerReceipt"] = receipt;
    }
    bob.sync()
        .expect("cached NSE evidence completes against retained I13 metadata after pruning");
    assert_eq!(
        mls_snapshot(),
        before_receipt_replay,
        "receipt replay must not consume another ratchet"
    );
    bob.db()
        .read_tx(|tx| {
            let evidence: Value =
                serde_json::from_slice(&tx.get_labyrinth_state(&archive_key)?.unwrap()).unwrap();
            assert!(evidence["sequencer_receipt_json"].is_string());
            assert!(tx
                .get_pending_op("native_archive_receipt", &msg1_id)?
                .is_none());
            Ok(())
        })
        .unwrap();
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
        ds.for_account(ALICE_DID),
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
        ds.for_account(BOB_DID),
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
        ds.for_account(EVE_DID),
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

    // A history import carries plaintext rows, not live publication evidence. Seeing the same
    // message ID on the live page must still authenticate its receipt and ciphertext before the
    // cursor advances.
    let imported_mid = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(
            &clean_cid,
            &imported_mid,
            "imported before live verification",
        )
        .expect("publish row later imported as history");
    let imported = alice
        .list_messages(&clean_cid, None, 100)
        .unwrap()
        .into_iter()
        .find(|message| message.message_id == imported_mid)
        .expect("published row");
    bob.import_conversation_history(&clean_cid, vec![imported])
        .expect("import evidence-less history row");
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_labyrinth_state(&format!("native.message:{clean_cid}:{imported_mid}")))
        .unwrap()
        .is_none());
    let cursor_before_import_reconciliation = bob
        .db()
        .read_tx(|tx| tx.get_conversation(&clean_cid))
        .unwrap()
        .unwrap()
        .last_seq;
    let published_import = {
        let mut state = ds.inner.lock().unwrap();
        let entry = state
            .entries
            .get_mut(&clean_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == imported_mid)
            .unwrap();
        let original = entry.clone();
        entry["signedRequest"]["body"]["applicationMessage"]["bytes"] =
            json!({ "$bytes": STANDARD.encode([0_u8]) });
        original
    };
    assert!(
        bob.sync().is_err(),
        "an imported row without retained evidence must not bypass live authentication"
    );
    assert_eq!(
        bob.db()
            .read_tx(|tx| tx.get_conversation(&clean_cid))
            .unwrap()
            .unwrap()
            .last_seq,
        cursor_before_import_reconciliation
    );
    {
        let mut state = ds.inner.lock().unwrap();
        *state
            .entries
            .get_mut(&clean_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == imported_mid)
            .unwrap() = published_import;
    }
    bob.sync()
        .expect("authenticate the live row behind imported history");
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_labyrinth_state(&format!("native.message:{clean_cid}:{imported_mid}")))
        .unwrap()
        .is_some());

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
    let alice_rows = alice.list_messages(&clean_cid, None, 20).unwrap();
    assert!(
        alice_rows
            .iter()
            .all(|row| row.message_id != bad_stub_mid && row.message_id != missing_rcpt_mid),
        "failed sends must commit zero phantom MessageRows"
    );
    assert!(
        alice
            .db()
            .read_tx(|tx| tx.list_labyrinth_queue(None, 20))
            .unwrap()
            .iter()
            .all(|row| row.item_id != bad_stub_mid && row.item_id != missing_rcpt_mid),
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

    // 5. A `payloadPruned` entry (O7) in `getEntries` (`I14`) is skipped cleanly under its own
    // I13 receipt, which mls-ds keeps serving, without aborting subsequent live entries!
    alice
        .send_message(
            &clean_cid,
            &uuid::Uuid::new_v4().to_string(),
            "pruned before bob reads it",
        )
        .expect("alice send before pruning");
    prune_entry(&ds, &clean_cid, ds.entry_count(&clean_cid));
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
    // Restored history rows are historical frames at epoch 0 (as the Phase 1 simulator's
    // restore imports them); the next sync verifies the cached row's receipt against its
    // retained archive evidence, not the row, and must not wedge on it.
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
        ds.for_account(ALICE_DID),
        None,
    )
    .expect("reopen alice");
    let published_entry = ds.inner.lock().unwrap().entries[&clean_cid]
        .iter()
        .find(|entry| entry["signedRequest"]["body"]["messageId"] == uncertain_mid.as_str())
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
                .find(|entry| entry["signedRequest"]["body"]["messageId"] == uncertain_mid.as_str())
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
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == uncertain_mid.as_str())
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

#[test]
fn staged_commit_journal_recovers_deferred_add_and_accepted_remove_after_restart() {
    use openmls::prelude::{GroupId, MlsGroup};
    use openmls_traits::OpenMlsProvider;

    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let open = |name: &str, did: &str, device: &str, keys: Arc<MemKeyStore>| {
        CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join(name).to_string_lossy().into_owned(),
                account_did: did.to_string(),
                device_id: device.to_string(),
                home_ds_did: DS_DID.to_string(),
                home_ds_endpoint: DS_URL.to_string(),
                pds_endpoint: PDS_URL.to_string(),
            },
            keys,
            ds.for_account(did),
            None,
        )
        .unwrap()
    };
    let alice_device = uuid::Uuid::new_v4().to_string();
    let alice_keys = Arc::new(MemKeyStore::new());
    let mut alice = open("alice", ALICE_DID, &alice_device, alice_keys.clone());
    let bob = open(
        "bob",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        Arc::new(MemKeyStore::new()),
    );
    let eve = open(
        "eve",
        EVE_DID,
        &uuid::Uuid::new_v4().to_string(),
        Arc::new(MemKeyStore::new()),
    );
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for client in [&alice, &bob, &eve] {
        client.enroll_device(&scopes).unwrap();
    }
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string(), EVE_DID.to_string()],
            Some("Commit journal recovery".into()),
            None,
        )
        .unwrap();
    bob.sync().unwrap();

    let local_row = |client: &CatbirdMlsClient| {
        client
            .db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
    };
    let mls_state = |client: &CatbirdMlsClient| {
        client
            .db()
            .write_tx(|tx| {
                let row = tx.get_conversation(&cid)?.unwrap();
                let provider = tx.openmls_provider();
                let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&row.group_id))
                    .unwrap()
                    .unwrap();
                assert!(group.pending_commit().is_none());
                assert_eq!(row.epoch as u64, group.epoch().as_u64());
                Ok((
                    group.epoch().as_u64(),
                    group
                        .members()
                        .map(|member| member.credential.serialized_content().to_vec())
                        .collect::<Vec<_>>(),
                ))
            })
            .unwrap()
    };
    let pending_count = |client: &CatbirdMlsClient| {
        client
            .db()
            .read_tx(|tx| {
                Ok(tx
                    .conn()
                    .query_row(
                        "SELECT COUNT(*) FROM pending_ops WHERE op_kind = 'commit_transition'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap())
            })
            .unwrap()
    };
    let control_state = |client: &CatbirdMlsClient| {
        client
            .db()
            .read_tx(|tx| {
                Ok((
                    tx.get_account_meta(&format!("conversation_coords:{cid}"))?,
                    tx.get_account_meta(&format!("metadata_snapshot_json:{cid}"))?,
                    tx.get_account_meta(&format!("last_removed_member:{cid}"))?,
                ))
            })
            .unwrap()
    };
    let corrupt_own_entry = |original: &Value, field: u8| {
        let mut entry = original.clone();
        match field {
            0 => {
                entry["signedRequest"]["body"]["commit"]["bytes"] =
                    json!({ "$bytes": STANDARD.encode([0_u8]) })
            }
            1 => {
                entry["signedRequest"]["body"]["manifest"]["participantChanges"] = json!([{
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": BOB_DID,
                }])
            }
            2 => {
                entry["signedRequest"]["body"]["metadataSnapshot"]["originTransitionId"] =
                    json!(uuid::Uuid::new_v4().to_string())
            }
            _ => {
                entry["signedRequest"]["signature"] =
                    json!({ "$bytes": STANDARD.encode([0_u8; 64]) })
            }
        }
        entry
    };
    let reject_appended_own_echo = |client: &CatbirdMlsClient, mut entry: Value| {
        let cursor = local_row(client).last_seq;
        let state = mls_state(client);
        let controls = control_state(client);
        let journals = pending_count(client);
        {
            let mut server = ds.inner.lock().unwrap();
            let entries = server.entries.get_mut(&cid).unwrap();
            entry["seq"] = json!((entries.len() + 1) as i64);
            entries.push(entry);
        }
        assert!(
            client.sync().is_err(),
            "own labels cannot replace a valid wrapper signature"
        );
        assert_eq!(local_row(client).last_seq, cursor);
        assert_eq!(mls_state(client), state);
        assert_eq!(control_state(client), controls);
        assert_eq!(pending_count(client), journals);
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(&cid)
            .unwrap()
            .pop();
    };

    let mut add_echo = None;
    for remove in [false, true] {
        let perform = |client: &CatbirdMlsClient| {
            if remove {
                client.remove_group_member(MemberRole::Admin, &cid, EVE_DID)
            } else {
                client.sync().map(|_| ())
            }
        };
        let before = mls_state(&alice);
        ds.inner.lock().unwrap().stale_next_submit_transition = true;
        let stale = perform(&alice);
        if remove {
            assert!(
                matches!(stale, Err(MLSError::InvalidState(code)) if code == "StaleCoordinates")
            );
        } else {
            stale.expect("leaf fulfillment skips a deterministically rejected transition");
        }
        assert_eq!(mls_state(&alice), before);
        assert_eq!(
            pending_count(&alice),
            0,
            "stale commits must discard their journal"
        );
        let cursor_before = local_row(&alice).last_seq;
        ds.inner.lock().unwrap().fail_next_commit_status = Some(403);
        assert!(perform(&alice).is_err());
        assert_eq!(mls_state(&alice), before);
        assert_eq!(
            pending_count(&alice),
            0,
            "non-retryable 4xx must erase staged private keys"
        );
        ds.inner.lock().unwrap().fail_next_commit_status = Some(503);
        assert!(perform(&alice).is_err());
        assert_eq!(mls_state(&alice), before);
        assert_eq!(
            pending_count(&alice),
            1,
            "uncertain 5xx must retain recovery material"
        );
        if remove {
            for (client, target) in [(&bob, EVE_DID), (&eve, BOB_DID)] {
                ds.inner.lock().unwrap().fail_next_commit_status = Some(503);
                assert!(client
                    .remove_group_member(MemberRole::Admin, &cid, target)
                    .is_err());
                assert_eq!(pending_count(client), 1);
            }
        }

        let unread_before_remove = uuid::Uuid::new_v4().to_string();
        if remove {
            eve.send_message(
                &cid,
                &unread_before_remove,
                "unread application before the sender is removed",
            )
            .unwrap();
            ds.inner.lock().unwrap().lose_next_commit_response = true;
        } else {
            ds.inner.lock().unwrap().defer_next_commit_transition = true;
        }
        assert!(perform(&alice).is_err());
        assert_eq!(
            mls_state(&alice),
            before,
            "uncertain commits must not apply their batch"
        );
        assert_eq!(local_row(&alice).last_seq, cursor_before);
        let pending_before_recovery = pending_count(&alice);
        assert_eq!(pending_before_recovery, 2);
        let (transition_id, payload, created_at): (String, String, i64) = alice
            .db()
            .read_tx(|tx| {
                Ok(tx
                    .conn()
                    .query_row(
                        "SELECT op_key, payload_json, created_at_ms FROM pending_ops \
                         WHERE op_kind = 'commit_transition' ORDER BY created_at_ms DESC, rowid DESC LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .unwrap())
            })
            .unwrap();
        let pending: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(pending["transition_id"], transition_id);
        assert_eq!(pending["commit_sha256"].as_array().unwrap().len(), 32);
        assert!(!pending["kv_batch"].as_array().unwrap().is_empty());

        drop(alice);
        alice = open("alice", ALICE_DID, &alice_device, alice_keys.clone());
        assert_eq!(mls_state(&alice), before);
        let deferred = ds.inner.lock().unwrap().deferred_commit_transition.take();
        if let Some(request) = deferred {
            ds.execute(ALICE_DID, request)
                .expect("server accepts the reordered commit after restart");
        }
        bob.sync().expect("peer applies the accepted commit");
        assert_eq!(
            pending_count(&bob),
            0,
            "a peer Commit retires losing private epoch keys"
        );
        if remove {
            eve.sync()
                .expect("removed leaf reconciles the winning Commit");
            assert_eq!(
                pending_count(&eve),
                0,
                "kick cleanup erases all staged private keys"
            );
        }
        let mut accepted = ds.inner.lock().unwrap().entries[&cid]
            .last()
            .unwrap()
            .clone();
        // Real read presentations may wrap bytes, including the wrapper signature.
        let signature =
            catbird_mls::client::chat_wire::json_bytes(&accepted["signedRequest"]["signature"])
                .unwrap();
        accepted["signedRequest"]["signature"] = json!({ "$bytes": STANDARD.encode(signature) });

        if !remove {
            let controls = control_state(&alice);
            for field in [0, 1, 2, 3] {
                *ds.inner
                    .lock()
                    .unwrap()
                    .entries
                    .get_mut(&cid)
                    .unwrap()
                    .last_mut()
                    .unwrap() = corrupt_own_entry(&accepted, field);
                assert!(
                    alice.sync().is_err(),
                    "every own Commit field must be authenticated"
                );
                assert_eq!(mls_state(&alice), before);
                assert_eq!(local_row(&alice).last_seq, cursor_before);
                assert_eq!(pending_count(&alice), pending_before_recovery);
                assert_eq!(control_state(&alice), controls);
            }
            *ds.inner
                .lock()
                .unwrap()
                .entries
                .get_mut(&cid)
                .unwrap()
                .last_mut()
                .unwrap() = accepted.clone();

            alice
                .db()
                .write_tx(|tx| {
                    tx.delete_pending_op("commit_transition", &transition_id)?;
                    Ok(())
                })
                .unwrap();
            assert!(
                alice.sync().is_err(),
                "an unapplied own commit requires its exact journal"
            );
            assert_eq!(mls_state(&alice), before);
            assert_eq!(local_row(&alice).last_seq, cursor_before);
            alice
                .db()
                .write_tx(|tx| {
                    tx.put_pending_op("commit_transition", &transition_id, &payload, created_at)?;
                    tx.conn()
                        .execute_batch(
                            "CREATE TEMP TRIGGER fail_commit_journal_delete \
                     BEFORE DELETE ON pending_ops WHEN OLD.op_kind = 'commit_transition' \
                     BEGIN SELECT RAISE(ABORT, 'commit journal delete interrupted'); END;",
                        )
                        .unwrap();
                    Ok(())
                })
                .unwrap();
            assert!(
                alice.sync().is_err(),
                "journal deletion and batch application must be atomic"
            );
            assert_eq!(
                mls_state(&alice),
                before,
                "failed journal deletion rolls back the MLS batch"
            );
            assert_eq!(local_row(&alice).last_seq, cursor_before);
            assert_eq!(pending_count(&alice), pending_before_recovery);
            alice
                .db()
                .write_tx(|tx| {
                    tx.conn()
                        .execute_batch("DROP TRIGGER fail_commit_journal_delete;")
                        .unwrap();
                    Ok(())
                })
                .unwrap();
        }

        alice
            .sync()
            .expect("recover accepted own commit from the durable journal");
        if remove {
            assert!(alice
                .list_messages(&cid, None, 100)
                .unwrap()
                .iter()
                .any(|message| message.message_id == unread_before_remove));
        }
        assert_eq!(mls_state(&alice), mls_state(&bob));
        assert_eq!(mls_state(&alice).0, before.0 + 1);
        assert_eq!(pending_count(&alice), 0);
        let accepted_cursor = local_row(&alice).last_seq;
        alice.sync().expect("recovery is idempotent");
        assert_eq!(local_row(&alice).last_seq, accepted_cursor);
        assert_eq!(mls_state(&alice), mls_state(&bob));
        for field in [1, 2, 3] {
            reject_appended_own_echo(&alice, corrupt_own_entry(&accepted, field));
        }
        let message_id = uuid::Uuid::new_v4().to_string();
        alice
            .send_message(&cid, &message_id, "message after own commit recovery")
            .unwrap();
        bob.sync()
            .expect("recovered MLS secrets decrypt on the surviving peer");
        assert!(bob
            .list_messages(&cid, None, 100)
            .unwrap()
            .iter()
            .any(|message| message.message_id == message_id));

        if !remove {
            eve.sync().unwrap();
            alice
                .sync()
                .expect("normal accepted add clears its journal atomically");
            eve.sync().unwrap();
            bob.sync().unwrap();
            assert_eq!(pending_count(&alice), 0);
            assert_eq!(mls_state(&alice), mls_state(&eve));
            for field in [1, 2, 3] {
                reject_appended_own_echo(&alice, corrupt_own_entry(&accepted, field));
            }
            add_echo = Some(accepted.clone());
        } else {
            assert_eq!(
                alice
                    .db()
                    .read_tx(|tx| tx.get_account_meta(&format!("last_removed_member:{cid}")))
                    .unwrap()
                    .as_deref(),
                Some(EVE_DID),
            );
        }
    }

    // An authenticated own echo superseded by later Commits closes only its cursor gap on Alice.
    // To Bob the same replayed Commit is a peer's for an epoch long past, and it is refused.
    let controls = control_state(&alice);
    let state = mls_state(&alice);
    let mut old_echo = add_echo.expect("the add round's accepted Commit");
    let echo_seq = {
        let mut server = ds.inner.lock().unwrap();
        let entries = server.entries.get_mut(&cid).unwrap();
        let seq = (entries.len() + 1) as i64;
        old_echo["seq"] = json!(seq);
        entries.push(old_echo);
        seq
    };
    alice
        .sync()
        .expect("authenticated superseded own echo closes only its cursor gap");
    assert_eq!(mls_state(&alice), state);
    assert_eq!(
        control_state(&alice),
        controls,
        "older echoes must not regress control state"
    );
    let error = bob.sync().expect_err("a replayed peer Commit is refused");
    assert!(error.to_string().contains("local MLS epoch"), "{error}");
    assert!(local_row(&bob).last_seq < echo_seq);
}

#[test]
fn close_conversation_retires_coordinate_wipes_mock_ds_and_keeps_local_history_unsendable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_dev = uuid::Uuid::new_v4().to_string();
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
        ds.for_account(ALICE_DID),
        None,
    )
    .expect("open alice");
    alice.enroll_device(&scopes).expect("enroll alice");

    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(&cid, DS_DID, Vec::new(), Some("Solo Close".into()), None)
        .expect("create solo group");
    let msg_id = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&cid, &msg_id, "retained before close")
        .expect("send before close");
    let outsider_dev = uuid::Uuid::new_v4().to_string();
    let outsider = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("outsider").to_string_lossy().into_owned(),
            account_did: EVE_DID.into(),
            device_id: outsider_dev.clone(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(EVE_DID),
        None,
    )
    .unwrap();
    outsider.enroll_device(&scopes).unwrap();
    let load_signer = |client: &CatbirdMlsClient| -> SignatureKeyPair {
        client
            .db()
            .read_tx(|tx| {
                Ok(
                    serde_json::from_str(&tx.get_account_meta("enrolled_signer_json")?.unwrap())
                        .unwrap(),
                )
            })
            .unwrap()
    };
    let signer = load_signer(&alice);
    let outsider_signer = load_signer(&outsider);
    let coordinates = || -> Value {
        alice
            .db()
            .read_tx(|tx| {
                Ok(serde_json::from_str(
                    &tx.get_account_meta(&format!("conversation_coords:{cid}"))?
                        .unwrap(),
                )
                .unwrap())
            })
            .unwrap()
    };
    let mls_bytes = || {
        alice.db().read_tx(|tx| {
            let mut stmt = tx.conn().prepare(
                "SELECT scope, key_bytes, value_bytes FROM openmls_kv ORDER BY version, scope, key_bytes",
            ).unwrap();
            let rows = stmt.query_map([], |row| Ok((
                row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
            ))).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
            Ok(rows)
        }).unwrap()
    };
    let signed_control = |close: bool, case: u8, prior: Value| {
        let nonmember = case == 4;
        let (did, device, key) = if nonmember {
            (EVE_DID, outsider_dev.as_str(), &outsider_signer)
        } else {
            (ALICE_DID, alice_dev.as_str(), &signer)
        };
        let mut prior = prior;
        let mut next = prior.clone();
        next["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
        if close {
            next["lifecycle"] = json!("superseded");
        }
        if case == 2 {
            prior["conversationId"] = json!(uuid::Uuid::new_v4().to_string());
        }
        if case == 3 {
            next["conversationId"] = json!(uuid::Uuid::new_v4().to_string());
        }
        let tid = uuid::Uuid::new_v4().to_string();
        let mut body = json!({
            "$type": if close { "blue.catbird.chat.defs#conversationCloseBody" }
                else { "blue.catbird.chat.defs#policyTransitionBody" },
            "signatureDomain": if close { "CATBIRD-CHAT-CLOSE\0" } else { "CATBIRD-CHAT-POLICY\0" },
            "transitionId": tid, "idempotencyKey": tid, "actorDid": did, "actorDeviceId": device,
            "keyId": derive_key_id(key.public()), "authGeneration": 1,
            "signedAt": "2026-11-03T00:00:00.000Z", "prior": prior,
        });
        let operation = if close {
            body["retired"] = next;
            body["conversationKind"] = json!("group");
            CanonicalOperation::CloseConversation
        } else {
            body["next"] = next;
            body["participantChanges"] = json!([{
                "$type": "blue.catbird.chat.defs#removeParticipant", "userDid": EVE_DID,
            }]);
            CanonicalOperation::SubmitTransition
        };
        let prepared =
            chat_wire::sign_clean_chat_mutation(did, device, Some(1), operation, &body, key)
                .unwrap();
        let mut wrapper: Value = serde_json::from_slice::<Value>(&prepared.body.unwrap()).unwrap()
            ["signedRequest"]
            .clone();
        if case == 0 {
            wrapper = body;
        }
        if case == 1 {
            wrapper["signature"] = json!({ "$bytes": STANDARD.encode([0u8; 64]) });
        }
        wrapper
    };

    // Valid signatures from an unrelated PDS DID are still not conversation authority;
    // raw, forged, and cross-CID bodies must have no close or coordinate effect.
    for close in [false, true] {
        for case in 0..5 {
            let before = coordinates();
            let mls_before = mls_bytes();
            let seq = alice
                .db()
                .read_tx(|tx| Ok(tx.get_conversation(&cid)?.unwrap().last_seq + 1))
                .unwrap();
            ds.inner
                .lock()
                .unwrap()
                .entries
                .get_mut(&cid)
                .unwrap()
                .push(json!({
                    "$type": if close { "blue.catbird.chat.defs#conversationCloseEntry" }
                        else { "blue.catbird.chat.defs#policyEntry" },
                    "seq": seq, "signedRequest": signed_control(close, case, before.clone()),
                }));
            assert!(
                alice.sync().is_err(),
                "case {case}, close={close} must fail closed"
            );
            ds.inner
                .lock()
                .unwrap()
                .entries
                .get_mut(&cid)
                .unwrap()
                .pop();
            assert_eq!(coordinates(), before);
            assert_eq!(mls_bytes(), mls_before);
            assert!(alice
                .db()
                .read_tx(|tx| tx.get_account_meta(&format!("conversation_closed:{cid}")))
                .unwrap()
                .is_none());
        }
    }
    let pinned = alice
        .db()
        .read_tx(|tx| tx.get_conversation(&cid))
        .unwrap()
        .unwrap();
    ds.inner
        .lock()
        .unwrap()
        .conversations
        .get_mut(&cid)
        .unwrap()["sequencerDid"] = json!(EVE_DID);
    alice
        .sync()
        .expect("unsigned inventory does not replace pinned authority");
    assert_eq!(
        alice
            .db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
            .sequencer_did,
        pinned.sequencer_did
    );
    ds.inner
        .lock()
        .unwrap()
        .conversations
        .get_mut(&cid)
        .unwrap()["sequencerDid"] = json!(DS_DID);

    for code in ["RouteNotFound", "ConversationNotFound"] {
        let seq = alice
            .db()
            .read_tx(|tx| Ok(tx.get_conversation(&cid)?.unwrap().last_seq + 1))
            .unwrap();
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(&cid)
            .unwrap()
            .push(json!({
                "$type": "blue.catbird.chat.defs#policyEntry", "seq": seq,
                "signedRequest": signed_control(false, 5, coordinates()),
            }));
        ds.inner.lock().unwrap().next_ack_error = Some((404, code.into()));
        let result = alice.sync();
        if code == "ConversationNotFound" {
            result.expect("only the exact close-race code is ignored");
        } else {
            assert!(
                matches!(&result, Err(MLSError::InvalidState(actual)) if actual == code),
                "{code}: {result:?}"
            );
        }
    }

    let good_coordinates = coordinates();
    let mut stale = good_coordinates.clone();
    stale["epoch"] = json!(good_coordinates["epoch"].as_u64().unwrap() + 1);
    alice
        .db()
        .write_tx(|tx| {
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &stale.to_string(), 1)
        })
        .unwrap();
    let before_stale_send = mls_bytes();
    let stale_mid = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        &alice.send_message(&cid, &stale_mid, "must not reserve a stale sender generation"),
        Err(MLSError::InvalidState(code)) if code == "StaleCoordinates",
    ));
    assert_eq!(mls_bytes(), before_stale_send);
    assert!(alice
        .db()
        .read_tx(|tx| tx.get_pending_op("application_send", &stale_mid))
        .unwrap()
        .is_none());
    alice
        .db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &format!("conversation_coords:{cid}"),
                &good_coordinates.to_string(),
                1,
            )
        })
        .unwrap();

    let group_id = pinned.group_id;
    alice
        .db()
        .write_tx(|tx| {
            tx.put_epoch_secret(&hex::encode(&group_id), 0, b"epoch secret", 1)?;
            tx.put_epoch_secret(&cid, 0, b"conversation secret", 1)?;
            for (kind, payload) in [
                (
                    "application_send",
                    json!({"archive":{"conversation_id":cid,"plaintext_json":"secret"}}),
                ),
                (
                    "participant_removal",
                    json!({"conversation_id":cid,"target_did":EVE_DID}),
                ),
                (
                    "commit_transition",
                    json!({"conversation_id":cid,"kv_batch":"private"}),
                ),
                (
                    "direct_request_acceptance",
                    json!({"next":{"conversationId":cid},"wrapper":"private"}),
                ),
                (
                    "native_archive_receipt",
                    json!({"conversation_id":cid,"seq":3,"entry_id":"receipt-entry"}),
                ),
            ] {
                tx.put_pending_op(kind, kind, &payload.to_string(), 1)?;
            }
            tx.put_pending_op(
                "application_send",
                "other-cid",
                r#"{"archive":{"conversation_id":"unrelated"}}"#,
                1,
            )?;
            tx.put_account_meta(
                &format!("c33_pending_opening:{cid}"),
                r#"{"plaintext_json":"secret"}"#,
                1,
            )
        })
        .unwrap();

    alice.close_conversation(&cid).expect("close conversation");
    alice
        .close_conversation(&cid)
        .expect("close conversation idempotent");
    alice
        .db()
        .read_tx(|tx| {
            let provider =
                alice
                    .sim_hooks()
                    .openmls_provider(catbird_mls::storage::OpenMlsKvStorage::new(
                        catbird_mls::storage::RusqliteKvBackend(tx.conn()),
                    ));
            assert!(
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
                    .unwrap()
                    .is_none()
            );
            let secrets: i64 = tx
                .conn()
                .query_row(
                    "SELECT count(*) FROM epoch_secrets WHERE group_id_hex IN (?1, ?2)",
                    rusqlite::params![hex::encode(&group_id), cid],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(secrets, 0);
            let journals: i64 = tx
                .conn()
                .query_row("SELECT count(*) FROM pending_ops", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                journals, 1,
                "only the unrelated conversation journal survives"
            );
            assert!(tx
                .get_account_meta(&format!("c33_pending_opening:{cid}"))?
                .is_none());
            assert!(tx.list_labyrinth_queue(Some(&cid), 100)?.is_empty());
            assert!(
                tx.get_labyrinth_state(&format!("native.message:{cid}:{msg_id}"))?
                    .is_some(),
                "receipt-bound archive evidence survives terminal close for rescue/unsend"
            );
            Ok(())
        })
        .unwrap();

    assert!(
        !ds.inner.lock().unwrap().conversations.contains_key(&cid),
        "DS operational state must be wiped on closeConversation"
    );
    assert_eq!(
        alice.list_messages(&cid, None, 20).unwrap().len(),
        1,
        "local decrypted history remains readable after close"
    );
    assert!(matches!(
        alice.list_members(&cid),
        Err(MLSError::GroupNotFound { .. })
    ));
    let post_close_msg = uuid::Uuid::new_v4().to_string();
    assert!(
        alice
            .send_message(&cid, &post_close_msg, "must fail")
            .is_err(),
        "closed conversation must reject subsequent sends"
    );
    alice
        .sync()
        .expect("sync skips closed/wiped conversation cleanly");

    let remote_closed_cid = uuid::Uuid::new_v4().to_string();
    let remote_closed = alice
        .create_group(
            &remote_closed_cid,
            DS_DID,
            Vec::new(),
            Some("Received Close".into()),
            None,
        )
        .unwrap();
    let prior: Value = alice
        .db()
        .read_tx(|tx| {
            Ok(serde_json::from_str(
                &tx.get_account_meta(&format!("conversation_coords:{remote_closed_cid}"))?
                    .unwrap(),
            )
            .unwrap())
        })
        .unwrap();
    alice
        .db()
        .write_tx(|tx| {
            tx.put_epoch_secret(&hex::encode(&remote_closed.group_id), 0, b"remote epoch", 1)?;
            tx.put_pending_op("application_send", "received-close", &json!({
            "archive": { "conversation_id": remote_closed_cid, "plaintext_json": "private" },
        }).to_string(), 1)
        })
        .unwrap();
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(&remote_closed_cid)
        .unwrap()
        .push(json!({
            "$type": "blue.catbird.chat.defs#conversationCloseEntry",
            "seq": remote_closed.last_seq + 1, "signedRequest": signed_control(true, 5, prior),
        }));
    alice
        .sync()
        .expect("authorized signed close applies shared terminal cleanup");
    alice
        .db()
        .read_tx(|tx| {
            let provider =
                alice
                    .sim_hooks()
                    .openmls_provider(catbird_mls::storage::OpenMlsKvStorage::new(
                        catbird_mls::storage::RusqliteKvBackend(tx.conn()),
                    ));
            assert!(MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&remote_closed.group_id)
            )
            .unwrap()
            .is_none());
            assert!(tx
                .get_pending_op("application_send", "received-close")?
                .is_none());
            assert_eq!(
                tx.get_account_meta(&format!("conversation_closed:{remote_closed_cid}"))?
                    .as_deref(),
                Some("true")
            );
            Ok(())
        })
        .unwrap();
}

/// `C33` peer on the transport-only home: its home serves the coordinator-sequenced
/// `#accountDeletedEntry(D)`. Ordinary sync applies it, while cross-writer restore
/// accepts only a cursor-complete, MAC-committed writer snapshot whose STAR and
/// oplog heads all reconcile.
#[test]
fn c33_peer_applies_account_deletion_and_restore_reconciles_complete_inventory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let historical_receipt_sk = P256SigningKey::from_slice(&[0x39; 32]).unwrap();
    ds.inner.lock().unwrap().historical_receipt_sk = Some(historical_receipt_sk.clone());
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let open = |name: &str, did: &str| {
        CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join(name).to_string_lossy().into_owned(),
                account_did: did.to_string(),
                device_id: uuid::Uuid::new_v4().to_string(),
                home_ds_did: DS_DID.to_string(),
                home_ds_endpoint: DS_URL.to_string(),
                pds_endpoint: PDS_URL.to_string(),
            },
            Arc::new(MemKeyStore::new()),
            ds.for_account(did),
            None,
        )
        .expect("open client")
    };
    // Alice (D) requests; her home coordinates. Bob is the C33 peer.
    let alice = open("alice", ALICE_DID);
    let bob = open("bob", BOB_DID);
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");

    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("opening from D".into()),
        )
        .expect("alice C33 request");
    bob.sync().expect("bob imports the request");
    let request = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0);
    bob.accept_direct_request(&request.request_id)
        .expect("bob accepts");
    alice.sync().expect("alice syncs acceptance");

    let a1 = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&cid, &a1, "D before deletion, witnessed")
        .unwrap();
    alice
        .flush_labyrinth_queue()
        .expect("alice publishes sender copies");
    bob.sync().expect("bob receives a1");
    let b1 = uuid::Uuid::new_v4().to_string();
    bob.send_message(&cid, &b1, "peer survives").unwrap();
    let writes_before_witness = ds.archive_auth.committed_space_write_count();
    bob.flush_labyrinth_queue()
        .expect("bob publishes witness + own copies");
    assert!(
        ds.archive_auth.committed_space_write_count() > writes_before_witness,
        "bob's witness copy of a1 must be published to the Conversation Space"
    );
    // a2 reaches Bob but its witness copy is still queued when the deletion arrives.
    let a2 = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&cid, &a2, "D before deletion, unflushed")
        .unwrap();
    bob.sync().expect("bob receives a2");
    assert!(bob
        .list_pending_labyrinth_queue(Some(&cid), 100)
        .unwrap()
        .iter()
        .any(|item| item.message_id == a2));
    // A peer public-repo auth failure is a directory prerequisite failure,
    // not proof that the established Conversation Space denied this member.
    // It must retain the durable queue and must never fall back to OwnerBatch.
    {
        let mut state = ds.inner.lock().unwrap();
        state.http_log.clear();
        state.xrpc_failures.push((
            "/xrpc/blue.catbird.labyrinth.getMailboxKeysRecord",
            403,
            "Forbidden",
            None,
        ));
    }
    let writes_before_directory_failure = ds.archive_auth.committed_space_write_count();
    assert!(
        bob.flush_labyrinth_queue().is_err(),
        "foreign mailboxKeys 403 must remain a retryable archive prerequisite failure"
    );
    assert_eq!(
        ds.archive_auth.committed_space_write_count(),
        writes_before_directory_failure,
        "directory failure must not publish an owner fallback"
    );
    assert!(
        bob.list_pending_labyrinth_queue(Some(&cid), 100)
            .unwrap()
            .iter()
            .any(|item| item.message_id == a2),
        "directory failure must retain the exact queued frame"
    );
    let urls: Vec<String> = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .map(|(_, url, _)| url.clone())
        .collect();
    assert!(
        urls.iter().any(|url| {
            url.starts_with(DS_URL)
                && url.contains("/xrpc/blue.catbird.labyrinth.getMailboxKeysRecord")
        }),
        "peer mailboxKeys must route through the account's home"
    );
    assert!(
        !urls.iter().any(|url| {
            url.contains("/xrpc/com.atproto.repo.getRecord")
                && query_map(url).get("repo").map(String::as_str) == Some(ALICE_DID)
        }),
        "native archive must never connect directly to a peer PDS record endpoint"
    );
    let d_messages: Vec<String> = bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| m.sender_did == ALICE_DID)
        .map(|m| m.message_id)
        .collect();
    assert!(d_messages.contains(&a1) && d_messages.contains(&a2));

    // Bob resolves the authority's exact retained method. A field edit, a foreign authority or a
    // key-ID substitution stops Bob's sync at that entry with no effect and his cursor below it
    // (fail-before: an unverified deletion was skipped and later entries carried the cursor
    // past it); the genuine generation-2 server entry at that seq is then applied.
    let sequencer_sk = ds.inner.lock().unwrap().receipt_sk.clone();
    let key_id_1 = format!("{DS_DID}#mls-receipt-1");
    let key_id_2 = format!("{DS_DID}#mls-receipt-2");
    let service_key_id = format!("{DS_DID}#atproto");
    let foreign_did = "did:web:other.example";
    let foreign_key_id = format!("{foreign_did}#mls-receipt-1");
    let foreign_sk = P256SigningKey::random(&mut rand::rngs::OsRng);
    let rogue = |seq: i64| {
        let mut tampered =
            signed_account_deletion(&sequencer_sk, &key_id_1, DS_DID, &cid, EVE_DID, seq);
        tampered["deletedDid"] = json!(ALICE_DID);
        let foreign = signed_account_deletion(
            &foreign_sk,
            &foreign_key_id,
            foreign_did,
            &cid,
            ALICE_DID,
            seq,
        );
        let mut wrong_method =
            signed_account_deletion(&sequencer_sk, &key_id_1, DS_DID, &cid, ALICE_DID, seq);
        wrong_method["sequencerAuthority"]["keyId"] = json!(key_id_2.clone());
        let service_method =
            signed_account_deletion(&sequencer_sk, &service_key_id, DS_DID, &cid, ALICE_DID, seq);
        [
            ("edited deletedDid", tampered),
            ("foreign authority", foreign),
            ("substituted method", wrong_method),
            ("service method", service_method),
        ]
    };
    let next_seq = |g: &MockDsState| {
        g.entries[&cid]
            .iter()
            .filter_map(|e| e["seq"].as_i64())
            .max()
            .unwrap()
            + 1
    };
    let marker = |client: &CatbirdMlsClient| {
        client
            .db()
            .read_tx(|tx| {
                tx.get_labyrinth_state(&format!("native.account_deleted:{cid}:{ALICE_DID}"))
            })
            .unwrap()
    };
    let rogue_seq = next_seq(&ds.inner.lock().unwrap());
    for (name, entry) in rogue(rogue_seq) {
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(&cid)
            .unwrap()
            .push(entry);
        let error = bob.sync().expect_err(name).to_string();
        assert!(error.contains("account deletion"), "{name}: {error}");
        assert_eq!(marker(&bob), None, "{name}");
        assert_eq!(last_seq(&bob, &cid), rogue_seq - 1, "{name}");
        assert_eq!(
            bob.list_messages(&cid, None, 100)
                .unwrap()
                .iter()
                .filter(|m| m.sender_did == ALICE_DID)
                .count(),
            d_messages.len(),
            "{name}: an unverified deletion must hide nothing"
        );
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(&cid)
            .unwrap()
            .pop();
    }
    let deletion_seq = {
        let mut g = ds.inner.lock().unwrap();
        let seq = next_seq(&g);
        let entry = signed_account_deletion(
            &historical_receipt_sk,
            &key_id_2,
            DS_DID,
            &cid,
            ALICE_DID,
            seq,
        );
        g.entries.get_mut(&cid).unwrap().push(entry.clone());
        g.account_deletions
            .entry(cid.clone())
            .or_default()
            .push(entry);
        seq
    };
    bob.sync()
        .expect("bob applies the deletion through ordinary C33 sync");
    assert_eq!(marker(&bob), Some(deletion_seq.to_string().into_bytes()));
    assert!(
        bob.list_pending_labyrinth_queue(Some(&cid), 100)
            .unwrap()
            .iter()
            .all(|item| !d_messages.contains(&item.message_id)),
        "queued witness duty for D must be dropped"
    );

    // D's account deletion purged its mailbox: its epoch head is gone (404 `EpochNotFound`). The
    // survivor's next message still archives, to a roster without D.
    ds.inner.lock().unwrap().labyrinth_epochs.remove(ALICE_DID);
    let b2 = uuid::Uuid::new_v4().to_string();
    bob.send_message(&cid, &b2, "after D's deletion").unwrap();
    bob.flush_labyrinth_queue()
        .expect("a deleted account's purged epoch head never blocks the survivor's archive");
    assert!(bob
        .list_pending_labyrinth_queue(Some(&cid), 100)
        .unwrap()
        .is_empty());

    // Restore consumes every snapshot-bound listRepos page, verifies its
    // inventory commitment, and reconciles each writer's STAR/oplog head
    // before importing any message.
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM messages WHERE message_id IN (?1, ?2)",
                    [&b1, &b2],
                )
                .unwrap();
            Ok(())
        })
        .unwrap();
    ds.archive_auth.set_inventory_fault(Some("truncate"));
    let error = bob
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("a terminal page that omits a committed writer must fail closed");
    assert!(error.to_string().contains("ArchiveInventoryIncomplete"));
    let unchanged = bob.list_messages(&cid, None, 100).unwrap();
    assert!(unchanged
        .iter()
        .all(|message| message.message_id != b1 && message.message_id != b2));
    ds.archive_auth.set_inventory_fault(None);
    assert_eq!(
        bob.restore_conversation_from_owner_mailbox(&cid)
            .expect("committed writer inventory restores the complete Space"),
        2
    );
    let restored = bob.list_messages(&cid, None, 100).unwrap();
    assert!(restored.iter().any(|message| message.message_id == b1));
    assert!(restored.iter().any(|message| message.message_id == b2));
    assert!(restored
        .iter()
        .all(|message| !d_messages.contains(&message.message_id)));

    // A recovered device accepts the same authenticated complete snapshot;
    // account-deleted author copies remain suppressed.
    let code = bob.setup_recovery_code().expect("bob recovery code");
    let bob2 = open("bob2", BOB_DID);
    bob2.enroll_device(&scopes).expect("enroll bob2");
    bob2.restore_with_recovery_code(&code)
        .expect("bob2 recovers the archive");
    assert_eq!(
        bob2.restore_conversation_from_owner_mailbox(&cid)
            .expect("fresh-device restore verifies the paged inventory"),
        2
    );
    let recovered = bob2.list_messages(&cid, None, 100).unwrap();
    assert!(recovered.iter().any(|message| message.message_id == b1));
    assert!(recovered.iter().any(|message| message.message_id == b2));
    assert!(recovered
        .iter()
        .all(|message| !d_messages.contains(&message.message_id)));
}

/// Cold start: the DS authenticates `ConversationNotFound` and this device holds no local state
/// for the conversation. Restore falls back to the account's owner records (as flush does) instead
/// of failing on the Conversation Space lookup.
#[test]
fn restore_of_a_conversation_the_ds_no_longer_knows_falls_back_to_owner_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice").to_string_lossy().into_owned(),
            account_did: ALICE_DID.to_string(),
            device_id: uuid::Uuid::new_v4().to_string(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(ALICE_DID),
        None,
    )
    .expect("open alice");
    alice.enroll_device(&scopes).expect("enroll alice");
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(&cid, DS_DID, Vec::new(), Some("Gone".into()), None)
        .expect("create group");
    let msg_id = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&cid, &msg_id, "kept in owner records")
        .unwrap();
    assert_eq!(alice.rescue_conversation_on_kick(&cid).unwrap(), 1);

    // The DS forgetting the conversation is only a lead: the Space authority itself (here the
    // home DS) must deny the account before owner records stand in for the conversation.
    let space = {
        let mut g = ds.inner.lock().unwrap();
        let conversation = g.conversations.remove(&cid).unwrap();
        g.entries.remove(&cid);
        conversation["conversationSpace"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "at://{DS_DID}/space/blue.catbird.labyrinth.conversation/{cid}-{}",
                    conversation["coordinates"]["generation"].as_u64().unwrap()
                )
            })
    };
    alice
        .db()
        .write_tx(|tx| {
            for table in ["messages", "conversations"] {
                tx.conn()
                    .execute(
                        &format!("DELETE FROM {table} WHERE conversation_id = ?1"),
                        [&cid],
                    )
                    .unwrap();
            }
            // Cold start: no saved Space placement either.
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_state WHERE state_key LIKE 'native.placements:%'",
                    [],
                )
                .unwrap();
            Ok(())
        })
        .unwrap();
    let unproven = alice
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("ConversationNotFound while the Space still admits the account");
    assert!(
        unproven.to_string().contains("ArchiveRemovalUnverified"),
        "{unproven}"
    );
    ds.archive_auth.set_space_denied(ALICE_DID, &space, true);
    assert_eq!(
        alice
            .restore_conversation_from_owner_mailbox(&cid)
            .expect("owner-only restore after authenticated Space denial"),
        1
    );
    let restored = alice.list_messages(&cid, None, 10).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].message_id, msg_id);
}

/// A fresh removed device has no MLS group. Exact authenticated NotEntitled is therefore only a
/// lead: a verified owner receipt must recover the Space pin and that Space must independently
/// deny the account. A malicious NotEntitled for an active member, generic 400, and auth failure
/// must not unlock owner-only history.
#[test]
fn fresh_removed_restore_requires_owner_proof_and_authenticated_space_denial() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect();
    let alice_keys = Arc::new(MemKeyStore::new());
    let bob_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(
        tmp.path(),
        &ds,
        "removal-admin",
        ALICE_DID,
        &uuid::Uuid::new_v4().to_string(),
        &alice_keys,
    );
    let source = live_client(
        tmp.path(),
        &ds,
        "removed-source",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &bob_keys,
    );
    alice.enroll_device(&scopes).expect("enroll admin");
    source
        .enroll_device(&scopes)
        .expect("enroll removed member");
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_owned()],
            Some("Removal proof".into()),
            Some("verified kick".into()),
        )
        .expect("create group");
    source.sync().expect("accept group invitation");
    alice.sync().expect("fulfill group invitation");
    source.sync().expect("join group");
    let code = source.setup_recovery_code().expect("recovery code");
    let message_id = uuid::Uuid::new_v4().to_string();
    source
        .send_message(&cid, &message_id, "owner rescue survives removal")
        .expect("send owner-rescued message");
    alice
        .remove_group_member(MemberRole::Admin, &cid, BOB_DID)
        .expect("sequence verified removal");
    source
        .sync()
        .expect("apply verified removal and seal owner rescue");

    let space = {
        let state = ds.inner.lock().unwrap();
        let conversation = &state.conversations[&cid];
        conversation["conversationSpace"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "at://{DS_DID}/space/blue.catbird.labyrinth.conversation/{cid}-{}",
                    conversation["coordinates"]["generation"].as_u64().unwrap()
                )
            })
    };
    ds.inner.lock().unwrap().conversation_state_errors.insert(
        (BOB_DID.to_owned(), cid.clone()),
        (400, "NotEntitled".into()),
    );
    ds.archive_auth.set_space_denied(BOB_DID, &space, true);

    let removed_keys = Arc::new(MemKeyStore::new());
    let removed = live_client(
        tmp.path(),
        &ds,
        "removed-fresh",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &removed_keys,
    );
    removed
        .restore_with_recovery_code(&code)
        .expect("recover removed member archive keys");
    ds.archive_auth.set_directory_outage(true);
    assert!(
        removed
            .restore_conversation_from_owner_mailbox(&cid)
            .is_err(),
        "directory outage must remain retryable, not prove removal"
    );
    assert!(removed.list_messages(&cid, None, 10).unwrap().is_empty());
    ds.archive_auth.set_directory_outage(false);
    assert_eq!(
        removed
            .restore_conversation_from_owner_mailbox(&cid)
            .expect("authenticated Space denial permits owner restore"),
        1
    );
    assert_eq!(
        removed.list_messages(&cid, None, 10).unwrap()[0].message_id,
        message_id
    );

    // The same DS response is malicious while the Space still admits the account.
    ds.archive_auth.set_space_denied(BOB_DID, &space, false);
    let active_keys = Arc::new(MemKeyStore::new());
    let active = live_client(
        tmp.path(),
        &ds,
        "active-fresh",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &active_keys,
    );
    active
        .restore_with_recovery_code(&code)
        .expect("recover active member archive keys");
    let error = active
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("NotEntitled contradicted by Space access must fail");
    assert!(
        error.to_string().contains("ArchiveRemovalUnverified"),
        "{error}"
    );
    assert!(active.list_messages(&cid, None, 10).unwrap().is_empty());

    for (index, status, error_code) in [(0, 400, "InvalidRequest"), (1, 401, "NotAuthorized")] {
        ds.inner.lock().unwrap().conversation_state_errors.insert(
            (BOB_DID.to_owned(), cid.clone()),
            (status, error_code.to_owned()),
        );
        let keys = Arc::new(MemKeyStore::new());
        let client = live_client(
            tmp.path(),
            &ds,
            &format!("malicious-{index}"),
            BOB_DID,
            &uuid::Uuid::new_v4().to_string(),
            &keys,
        );
        client
            .restore_with_recovery_code(&code)
            .expect("recover archive keys");
        assert!(
            client
                .restore_conversation_from_owner_mailbox(&cid)
                .is_err(),
            "HTTP {status} {error_code} must not prove removal"
        );
        assert!(client.list_messages(&cid, None, 10).unwrap().is_empty());
    }
}

fn live_client(
    root: &std::path::Path,
    ds: &Arc<SharedMockDs>,
    name: &str,
    did: &str,
    device_id: &str,
    keys: &Arc<MemKeyStore>,
) -> Arc<CatbirdMlsClient> {
    CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: root.join(name).to_string_lossy().into_owned(),
            account_did: did.to_string(),
            device_id: device_id.to_string(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        keys.clone(),
        ds.for_account(did),
        None,
    )
    .expect("open client")
}

/// Catbird re-enrolls on every MLS init (`AppState.initializeMLS`). After a cold relaunch the
/// enrolled signer must survive: the Labyrinth session is bound to it as transport key, Bob
/// verifies Alice's MLS leaf with it, and `mls-ds` already holds it (enrollment is create-only).
#[test]
fn reenrolling_after_cold_relaunch_keeps_the_signer_so_archive_and_peers_stay_bound() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_dev = uuid::Uuid::new_v4().to_string();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &alice_dev, &alice_keys);
    let bob_dev = uuid::Uuid::new_v4().to_string();
    let bob_keys = Arc::new(MemKeyStore::new());
    let bob = live_client(tmp.path(), &ds, "bob", BOB_DID, &bob_dev, &bob_keys);
    let enrolled = alice
        .enroll_device(&scopes)
        .expect("enroll alice")
        .signature_public_key;
    bob.enroll_device(&scopes).expect("enroll bob");
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Relaunch".into()),
            None,
        )
        .expect("create group");
    bob.sync().expect("bob accepts the invite");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");
    alice
        .send_message(&cid, &uuid::Uuid::new_v4().to_string(), "before relaunch")
        .unwrap();
    assert!(
        alice
            .flush_labyrinth_queue()
            .expect("first flush enables the archive")
            >= 1
    );

    drop(alice);
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &alice_dev, &alice_keys);
    let again = alice
        .enroll_device(&scopes)
        .expect("re-enrolling an enrolled device is idempotent");
    assert_eq!(again.signature_public_key, enrolled);
    let keychain: SignatureKeyPair = serde_json::from_slice(
        &alice_keys
            .load_signature_keypair(format!("mls-signer:{}", alice.account_did_hash()))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(keychain.public(), enrolled.as_slice());
    assert_eq!(
        ds.inner.lock().unwrap().device_keys[&(ALICE_DID.to_string(), alice_dev.clone())]
            .as_slice(),
        enrolled.as_slice()
    );

    let enroll_posts = || {
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(account, url, _)| {
                account == ALICE_DID && url.ends_with("/xrpc/blue.catbird.chat.enrollDevice")
            })
            .count()
    };
    let before_mismatch = enroll_posts();
    let mismatched = live_client(
        tmp.path(),
        &ds,
        "alice",
        ALICE_DID,
        &uuid::Uuid::new_v4().to_string(),
        &alice_keys,
    );
    assert!(matches!(
        mismatched.enroll_device(&scopes),
        Err(MLSError::InvalidState(code)) if code == "EnrollmentDeviceIdentityMismatch"
    ));
    assert_eq!(
        enroll_posts(),
        before_mismatch,
        "a completed signer may not be rebound to a different device ID"
    );

    let after = uuid::Uuid::new_v4().to_string();
    alice.send_message(&cid, &after, "after relaunch").unwrap();
    assert!(
        alice
            .flush_labyrinth_queue()
            .expect("the archive session still opens under the enrolled transport key")
            >= 1
    );
    bob.sync().expect("bob verifies alice's leaf signature");
    assert!(bob
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m.message_id == after));
}

/// Crash windows of the DS bootstrap: `mls-ds` applied Alice's `enrollDevice` and Bob's request
/// keys, but both responses were lost. Each retry reuses the persisted signer, confirms the DS
/// holds it (`DeviceAlreadyExists`, then a signed `getOwnDevices`), and publishes request keys once.
#[test]
fn enrollment_retry_after_lost_ds_responses_reuses_the_persisted_signer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_dev = uuid::Uuid::new_v4().to_string();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &alice_dev, &alice_keys);
    let bob_dev = uuid::Uuid::new_v4().to_string();
    let bob_keys = Arc::new(MemKeyStore::new());
    let bob = live_client(tmp.path(), &ds, "bob", BOB_DID, &bob_dev, &bob_keys);

    ds.inner.lock().unwrap().lose_next_enroll_response = true;
    assert!(alice.enroll_device(&scopes).is_err());
    ds.inner.lock().unwrap().lose_next_dr_keys_response = true;
    assert!(bob.enroll_device(&scopes).is_err());

    drop(alice); // The app dies before retrying.
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &alice_dev, &alice_keys);
    let alice_key = alice
        .enroll_device(&scopes)
        .expect("alice's retry adopts the DS enrollment")
        .signature_public_key;
    let bob_key = bob
        .enroll_device(&scopes)
        .expect("bob's retry skips the published request keys")
        .signature_public_key;
    {
        let g = ds.inner.lock().unwrap();
        let alice_slot = (ALICE_DID.to_string(), alice_dev.clone());
        let bob_slot = (BOB_DID.to_string(), bob_dev.clone());
        assert_eq!(g.device_keys[&alice_slot].as_slice(), alice_key.as_slice());
        assert_eq!(g.device_keys[&bob_slot].as_slice(), bob_key.as_slice());
        assert_eq!(g.dr_revisions[&alice_slot], 1);
        assert_eq!(g.dr_revisions[&bob_slot], 1);
    }
    bob.enroll_device(&scopes)
        .expect("a completed enrollment is a local no-op");

    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Retry".into()),
            None,
        )
        .expect("create group");
    bob.sync().expect("bob accepts the invite");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");
    let from_alice = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&cid, &from_alice, "alice after retry")
        .unwrap();
    bob.sync().expect("bob verifies alice's leaf signature");
    let from_bob = uuid::Uuid::new_v4().to_string();
    bob.send_message(&cid, &from_bob, "bob after retry")
        .unwrap();
    alice.sync().expect("alice verifies bob's leaf signature");
    assert!(bob
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m.message_id == from_alice));
    assert!(alice
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m.message_id == from_bob));
    assert!(
        alice
            .flush_labyrinth_queue()
            .expect("alice's archive flushes")
            >= 1
    );
}

/// The coordinator's signed `#directRequestAcceptanceCommitReceipt` over a sequenced
/// `#directRequestAcceptanceEntry` (whose `$type` is not part of the hashed entry).
fn acceptance_commit_receipt(sk: &P256SigningKey, entry: &Value) -> Value {
    let mut entry = entry.clone();
    entry.as_object_mut().unwrap().remove("$type");
    let accepted = &entry["signedRequest"]["body"];
    let acceptance = dr_transcript::direct_request_signing_bytes(
        DirectRequestKind::Accept,
        &serde_json::to_vec(accepted).unwrap(),
    )
    .unwrap();
    let body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceCommitReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPTANCE-COMMIT\0",
        "protocolVersion": "2",
        "authorityDid": DS_DID,
        "keyId": dr_transcript::direct_request_receipt_key_id_for_authority(
            DS_DID,
            sk.verifying_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap(),
        "requestId": accepted["requestId"],
        "acceptanceDigest": STANDARD.encode(Sha256::digest(&acceptance)),
        "entryHash": STANDARD.encode(
            dr_transcript::direct_request_acceptance_entry_hash(&serde_json::to_vec(&entry).unwrap())
                .unwrap(),
        ),
        "prior": accepted["prior"],
        "next": accepted["next"],
        "recordedAt": entry["receivedAt"],
    });
    let transcript = dr_transcript::direct_request_signing_bytes(
        DirectRequestKind::AcceptanceCommit,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let signature: p256::ecdsa::Signature = sk.sign(&transcript);
    let signature = signature.normalize_s().unwrap_or(signature);
    json!({ "body": body, "signature": STANDARD.encode(signature.to_bytes()) })
}

/// A key-mismatch refusal writes nothing to the PDS: `mls-ds` must hold the device under this
/// key before either PDS record is written, whether a fresh `enrollDevice` answer names another
/// key or the adopted enrollment (`DeviceAlreadyExists`, then `getOwnDevices`) reports one. Once
/// the DS reports this key, the retry adopts the enrollment and only then writes both records.
///
/// Fail-before: both PDS records were written before `enrollDevice`, and a fresh answer was never
/// checked, so the mismatched enrollment wrote the PDS device record and completed.
#[test]
fn a_key_mismatch_refuses_before_any_pds_write() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_dev = new_id();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &alice_dev, &alice_keys);
    let pds_writes = || {
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(account, url, _)| {
                account == ALICE_DID && url.ends_with("/xrpc/com.atproto.repo.putRecord")
            })
            .count()
    };

    ds.inner.lock().unwrap().enroll_answer_key = Some([7; 32]);
    for (answer, refusal) in [
        ("fresh", "EnrollmentDeviceIdentityMismatch"),
        ("adopted", "DeviceAlreadyExists"),
    ] {
        let result = alice.enroll_device(&scopes);
        assert_eq!(
            pds_writes(),
            0,
            "{answer} answer: no PDS write before mls-ds holds this key"
        );
        assert!(
            matches!(&result, Err(MLSError::InvalidState(code)) if code.starts_with(refusal)),
            "{answer} answer naming another key must refuse: {result:?}"
        );
    }

    ds.inner.lock().unwrap().enroll_answer_key = None;
    let enrolled = alice
        .enroll_device(&scopes)
        .expect("the retry adopts the enrollment once mls-ds reports this key")
        .signature_public_key;
    assert_eq!(pds_writes(), 2, "the device and declaration records, once");
    let g = ds.inner.lock().unwrap();
    let record = &g.pds_records[&(
        ALICE_DID.to_string(),
        "blue.catbird.chat.device".to_string(),
        alice_dev.clone(),
    )];
    assert_eq!(
        chat_wire::json_bytes(&record["mlsSignaturePublicKey"]).unwrap(),
        enrolled
    );
    assert_eq!(
        g.device_keys[&(ALICE_DID.to_string(), alice_dev)].as_slice(),
        enrolled.as_slice()
    );
}

/// Accepting moves the cursor only over its own verified entry: the coordinator's
/// acceptance-commit receipt over the sequenced entry carrying Bob's signed acceptance, and only
/// when that entry is the next one. An answer the coordinator did not sign is refused with
/// nothing changed and the signed acceptance still journaled; its exact replay, verified at seq
/// 2, moves the cursor from 1 to 2 onto the signed coordinates. An acceptance verified at seq 3,
/// behind Alice's seq-2 message Bob has not seen, leaves the cursor to sync, which applies that
/// message first.
///
/// Fail-before: accepting trusted any 2xx answer: the forged one moved the cursor to 2, stored
/// its unsigned coordinates and spent the journal; an answer without a top-level `seq` moved the
/// cursor to 2 over Alice's unseen message.
#[test]
fn accepting_moves_the_cursor_only_over_its_verified_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &new_id(), &alice_keys);
    let bob_keys = Arc::new(MemKeyStore::new());
    let bob = live_client(tmp.path(), &ds, "bob", BOB_DID, &new_id(), &bob_keys);
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    let (next, gap) = (new_id(), new_id());
    for cid in [&next, &gap] {
        alice
            .create_group(
                cid,
                DS_DID,
                vec![BOB_DID.to_string()],
                None,
                Some("Hi".into()),
            )
            .expect("alice requests a conversation with bob");
    }
    bob.sync().expect("bob imports both openings");
    assert_eq!((last_seq(&bob, &next), last_seq(&bob, &gap)), (1, 1));
    let request = |cid: &str| {
        bob.list_requests(None)
            .unwrap()
            .into_iter()
            .find(|r| r.conversation_id == cid)
            .unwrap()
    };
    let coords = |cid: &str| {
        bob.db()
            .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{cid}")))
            .unwrap()
    };
    let journal = |request_id: &str| {
        bob.db()
            .read_tx(|tx| tx.get_pending_op("direct_request_acceptance", request_id))
            .unwrap()
    };

    let request_id = request(&next).request_id;
    let coords_before = coords(&next);
    ds.inner.lock().unwrap().forge_next_acceptance = true;
    let error = bob
        .accept_direct_request(&request_id)
        .expect_err("an answer the coordinator did not sign is refused");
    assert!(error.to_string().contains("C33 acceptance"), "{error}");
    assert_eq!(last_seq(&bob, &next), 1);
    assert_eq!(coords(&next), coords_before);
    assert_eq!(request(&next).consent, "incomingPending");
    assert!(
        journal(&request_id).is_some(),
        "the signed acceptance stays journaled"
    );

    bob.accept_direct_request(&request_id)
        .expect("the verified acceptance is accepted");
    assert_eq!(last_seq(&bob, &next), 2);
    assert_eq!(request(&next).consent, "accepted");
    assert!(journal(&request_id).is_none());
    let (bodies, signed_next) = {
        let g = ds.inner.lock().unwrap();
        let bodies: Vec<&Vec<u8>> = g
            .http_log
            .iter()
            .filter(|(account, url, _)| {
                account == BOB_DID && url.ends_with("/xrpc/blue.catbird.chat.acceptConversation")
            })
            .map(|(_, _, body)| body)
            .collect();
        assert_eq!(bodies.len(), 2);
        let bodies = (bodies[0].clone(), bodies[1].clone());
        (
            bodies,
            g.entries[&next][1]["signedRequest"]["body"]["next"].clone(),
        )
    };
    assert_eq!(
        bodies.0, bodies.1,
        "the retry replays the journaled acceptance"
    );
    let stored: Value = serde_json::from_str(&coords(&next).unwrap()).unwrap();
    assert_eq!(
        chat_wire::canonicalize_wire_coordinate(&stored, None).unwrap(),
        chat_wire::canonicalize_wire_coordinate(&signed_next, None).unwrap(),
    );

    let unseen = new_id();
    alice
        .send_message(&gap, &unseen, "before bob accepts")
        .expect("alice's message is sequenced at seq 2");
    bob.accept_direct_request(&request(&gap).request_id)
        .expect("the acceptance verified at seq 3 is accepted");
    assert_eq!(request(&gap).consent, "accepted");
    assert!(
        bob.list_messages(&gap, None, 20)
            .unwrap()
            .iter()
            .any(|m| m.message_id == unseen && m.seq == 2),
        "the cursor never moved over the unseen seq-2 message"
    );
    assert_eq!(last_seq(&bob, &gap), 3);
}

/// A 2xx answer to Alice's own metadata or commit transition moves her cursor and coordinates
/// only when its `entry` carries exactly her signed request and its `coordinates` are the signed
/// `next`. A forged answer is refused like a lost response: nothing changes (the staged Commit
/// stays journaled and unmerged), and sync then applies the own echo the DS did sequence.
///
/// Fail-before: the commit and metadata sites took `seq` and `coordinates` from any 2xx answer,
/// so Alice stored coordinates she never signed and merged a Commit on an answer that did not
/// carry it.
#[test]
fn forged_own_transition_answers_move_neither_cursor_nor_coordinates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &new_id(), &alice_keys);
    let bob_keys = Arc::new(MemKeyStore::new());
    let bob = live_client(tmp.path(), &ds, "bob", BOB_DID, &new_id(), &bob_keys);
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Group".into()),
            None,
        )
        .expect("create group");
    bob.sync().expect("bob accepts the invite");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");
    // (conversation row, stored coordinates, staged Commit journals) on Alice's device.
    let local = || {
        alice
            .db()
            .read_tx(|tx| {
                let journals: i64 = tx
                    .conn()
                    .query_row(
                        "SELECT COUNT(*) FROM pending_ops WHERE op_kind = 'commit_transition'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                Ok((
                    tx.get_conversation(&cid)?.unwrap(),
                    tx.get_account_meta(&format!("conversation_coords:{cid}"))?,
                    journals,
                ))
            })
            .unwrap()
    };
    let canonical = |raw: &str| {
        chat_wire::canonicalize_wire_coordinate(&serde_json::from_str(raw).unwrap(), None).unwrap()
    };

    let (row, coords, _) = local();
    ds.inner.lock().unwrap().forge_next_transition_answer = Some("coordinates");
    let error = alice
        .update_group_metadata(&cid, "Renamed".into(), String::new(), None)
        .expect_err("coordinates other than the signed next are refused");
    assert!(error.to_string().contains("signed next"), "{error}");
    let (after, after_coords, _) = local();
    assert_eq!((after.last_seq, &after.title), (row.last_seq, &row.title));
    assert_eq!(after_coords, coords);
    alice.sync().expect("sync applies the own metadata echo");
    let (after, after_coords, _) = local();
    assert_eq!(after.last_seq, row.last_seq + 1);
    assert_eq!(after.title.as_deref(), Some("Renamed"));
    let signed_next = {
        let g = ds.inner.lock().unwrap();
        let entry = &g.entries[&cid][(after.last_seq - 1) as usize];
        chat_wire::canonicalize_wire_coordinate(&entry["signedRequest"]["body"]["next"], None)
            .unwrap()
    };
    assert_eq!(canonical(after_coords.as_deref().unwrap()), signed_next);

    let (row, coords, journals) = local();
    ds.inner.lock().unwrap().forge_next_transition_answer = Some("entry");
    let error = alice
        .remove_group_member(MemberRole::Admin, &cid, BOB_DID)
        .expect_err("an entry carrying another signed request is refused");
    assert!(error.to_string().contains("signed request"), "{error}");
    let (after, after_coords, after_journals) = local();
    assert_eq!(
        (after.last_seq, after.epoch),
        (row.last_seq, row.epoch),
        "the staged Commit is not merged"
    );
    assert_eq!(after_coords, coords);
    assert_eq!(
        after_journals,
        journals + 1,
        "the staged Commit stays journaled"
    );
    alice
        .sync()
        .expect("sync recovers the own Commit from its journal");
    let (after, _, after_journals) = local();
    assert_eq!(after.epoch, row.epoch + 1);
    assert_eq!(after_journals, journals);
    assert!(after.last_seq > row.last_seq);
    assert!(!alice
        .list_members(&cid)
        .unwrap()
        .contains(&BOB_DID.to_string()));
}

/// A late group add signs `participantChanges[].invitationProvenance` as the plain object the
/// lexicon declares (no `$type`), so the generated serializer accepts it and the DS records it.
#[test]
fn late_group_add_submits_an_untyped_invitation_provenance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let open = |name: &str, did: &str| {
        CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join(name).to_string_lossy().into_owned(),
                account_did: did.to_string(),
                device_id: uuid::Uuid::new_v4().to_string(),
                home_ds_did: DS_DID.to_string(),
                home_ds_endpoint: DS_URL.to_string(),
                pds_endpoint: PDS_URL.to_string(),
            },
            Arc::new(MemKeyStore::new()),
            ds.for_account(did),
            None,
        )
        .expect("open client")
    };
    let alice = open("alice", ALICE_DID);
    let bob = open("bob", BOB_DID);
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(&cid, DS_DID, Vec::new(), Some("Late add".into()), None)
        .expect("create group");

    alice
        .add_group_members(&cid, vec![BOB_DID.to_string()])
        .expect("late add signs a lexicon-valid policy transition");
    let g = ds.inner.lock().unwrap();
    let body = &g.entries[&cid].last().unwrap()["signedRequest"]["body"];
    assert_eq!(body["$type"], "blue.catbird.chat.defs#policyTransitionBody");
    let change = &body["participantChanges"][0];
    assert_eq!(change["userDid"], BOB_DID);
    let provenance = change["invitationProvenance"].as_object().unwrap();
    assert!(!provenance.contains_key("$type"), "{provenance:?}");
    assert_eq!(provenance["invitedByDid"], ALICE_DID);
}

/// O7: once both homes prune the C33 opening ciphertext, `getEntries` serves the opening row
/// without `signedRequest` and with `payloadPruned: true`. A device that already imported it keeps
/// working; a device that never did records the declared terminal `openingUnavailable` request once,
/// cannot accept it, and never imports a Welcome. Receipts that do not bind the row are rejected.
#[test]
fn c33_pruned_opening_keeps_imported_devices_and_terminates_fresh_ones() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let open = |name: &str, did: &str| {
        let client = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join(name).to_string_lossy().into_owned(),
                account_did: did.to_string(),
                device_id: uuid::Uuid::new_v4().to_string(),
                home_ds_did: DS_DID.to_string(),
                home_ds_endpoint: DS_URL.to_string(),
                pds_endpoint: PDS_URL.to_string(),
            },
            Arc::new(MemKeyStore::new()),
            ds.for_account(did),
            None,
        )
        .expect("open client");
        client.enroll_device(&scopes).expect("enroll");
        client
    };
    let alice = open("alice", ALICE_DID);
    let bob = open("bob", BOB_DID);
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("opening".into()),
        )
        .expect("alice C33 request");
    bob.sync().expect("bob imports the opening");
    let request = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0);
    bob.accept_direct_request(&request.request_id)
        .expect("bob accepts");
    alice.sync().expect("alice syncs acceptance");

    // Frozen audience acknowledged: the DS prunes the opening, keeping receipts verbatim.
    let set_opening = |edit: &dyn Fn(&mut Value)| {
        let mut g = ds.inner.lock().unwrap();
        let opening = g
            .entries
            .get_mut(&cid)
            .unwrap()
            .iter_mut()
            .find(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
            .unwrap();
        edit(opening);
    };
    let original = {
        let g = ds.inner.lock().unwrap();
        g.entries[&cid]
            .iter()
            .find(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
            .unwrap()
            .clone()
    };
    let mut pruned = original.clone();
    let row = pruned.as_object_mut().unwrap();
    row.remove("signedRequest");
    row.remove("sequencerDid");
    row.insert("payloadPruned".into(), json!(true));
    // The mock's live row omits the lexicon-required `receivedAt`; a real pruned row keeps it.
    let received_at = original["publicationReceipt"]["body"]["receipt"]["recordedAt"].clone();
    row.insert("receivedAt".into(), received_at);
    set_opening(&|e| *e = pruned.clone());

    // An imported, accepted conversation keeps working on both sides.
    bob.sync()
        .expect("imported device syncs past its pruned opening");
    let after = uuid::Uuid::new_v4().to_string();
    bob.send_message(&cid, &after, "after prune").unwrap();
    alice.sync().expect("alice syncs after prune");
    assert!(alice
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m.plaintext_json.contains("after prune")));

    // Receipts that do not bind the pruned row are rejected without any local effect.
    let mut seq_mismatch = pruned.clone();
    seq_mismatch["sequencerReceipt"]["seq"] = json!(2);
    let mut id_mismatch = pruned.clone();
    id_mismatch["entryId"] = json!(uuid::Uuid::new_v4().to_string());
    let mut flagged_with_body = pruned.clone();
    flagged_with_body["signedRequest"] = original["signedRequest"].clone();
    for (index, (name, tampered, reason)) in [
        (
            "sequencer receipt mismatch",
            seq_mismatch,
            "receipts mismatch",
        ),
        ("entry identity mismatch", id_mismatch, "receipts mismatch"),
        (
            "payloadPruned with a signed body",
            flagged_with_body,
            "payloadPruned must accompany",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        set_opening(&|e| *e = tampered.clone());
        let probe = open(&format!("probe{index}"), BOB_DID);
        let error = probe.sync().expect_err(name).to_string();
        assert!(error.contains(reason), "{name}: {error}");
        assert!(probe.list_requests(None).unwrap().is_empty(), "{name}");
        assert!(
            probe.list_conversations(None, 20).unwrap().is_empty(),
            "{name}"
        );
    }
    set_opening(&|e| *e = pruned.clone());

    // A fresh device of the recipient reaches the declared terminal state; one of the sender
    // records nothing, since nothing signed names the recipient of its own pruned opening.
    for (name, did) in [("bob_fresh", BOB_DID), ("alice_fresh", ALICE_DID)] {
        let fresh = open(name, did);
        fresh
            .sync()
            .expect("a pruned opening is a terminal state, not a sync error");
        let terminal = fresh.list_requests(Some("openingUnavailable")).unwrap();
        if did == ALICE_DID {
            assert!(fresh.list_requests(None).unwrap().is_empty(), "{name}");
            assert!(fresh.list_conversations(None, 20).unwrap().is_empty());
            continue;
        }
        assert_eq!(terminal.len(), 1, "{name}");
        assert_eq!(terminal[0].conversation_id, cid);
        assert_eq!(terminal[0].request_id, request.request_id);
        assert_eq!(terminal[0].sender_did, ALICE_DID);
        assert_eq!(terminal[0].recipient_did, BOB_DID);
        assert!(fresh.list_conversations(None, 20).unwrap().is_empty());
        assert!(matches!(
            fresh.accept_direct_request(&terminal[0].request_id),
            Err(MLSError::InvalidState(ref code)) if code == "OpeningUnavailable"
        ));
        // Recorded once: later syncs neither re-fetch nor fail.
        set_opening(&|e| e["sequencerReceipt"]["seq"] = json!(9));
        fresh.sync().expect("terminal opening is never re-fetched");
        set_opening(&|e| *e = pruned.clone());
        assert_eq!(
            fresh
                .list_requests(Some("openingUnavailable"))
                .unwrap()
                .len(),
            1
        );
    }
}

/// `directRequestEntry.publicationReceipt` is a closed union with the single
/// option `#signedDirectRequestReceipt`: its `$type` is required and exact.
/// A missing or wrong tag rejects the opening before any local effect.
#[test]
fn c33_opening_publication_receipt_requires_exact_union_tag() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let open = |name: &str, did: &str| {
        let client = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join(name).to_string_lossy().into_owned(),
                account_did: did.to_string(),
                device_id: uuid::Uuid::new_v4().to_string(),
                home_ds_did: DS_DID.to_string(),
                home_ds_endpoint: DS_URL.to_string(),
                pds_endpoint: PDS_URL.to_string(),
            },
            Arc::new(MemKeyStore::new()),
            ds.for_account(did),
            None,
        )
        .expect("open client");
        client.enroll_device(&scopes).expect("enroll");
        client
    };
    let alice = open("alice", ALICE_DID);
    let bob = open("bob", BOB_DID);
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("opening".into()),
        )
        .expect("alice C33 request");
    let set_receipt_tag = |tag: Option<&str>| {
        let mut g = ds.inner.lock().unwrap();
        let receipt = g
            .entries
            .get_mut(&cid)
            .unwrap()
            .iter_mut()
            .find(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
            .unwrap()["publicationReceipt"]
            .as_object_mut()
            .unwrap();
        match tag {
            Some(tag) => receipt.insert("$type".into(), json!(tag)),
            None => receipt.remove("$type"),
        };
    };
    for (name, tag, reason) in [
        ("missing $type", None, "requires $type"),
        (
            "wrong $type",
            Some("blue.catbird.chat.defs#directRequestReceiptBody"),
            "$type must be",
        ),
    ] {
        set_receipt_tag(tag);
        // The addressed device itself: a rejected opening leaves nothing behind.
        let error = bob.sync().expect_err(name).to_string();
        assert!(error.contains("C33 publication receipt"), "{name}: {error}");
        assert!(error.contains(reason), "{name}: {error}");
        assert!(bob.list_requests(None).unwrap().is_empty(), "{name}");
        assert!(
            bob.list_conversations(None, 20).unwrap().is_empty(),
            "{name}"
        );
    }
    set_receipt_tag(Some("blue.catbird.chat.defs#signedDirectRequestReceipt"));
    bob.sync().expect("exact tag imports the opening");
    assert_eq!(bob.list_requests(Some("incomingPending")).unwrap().len(), 1);
}

/// A transient `C33` refusal (`503 CapacityUnavailable`, `Retry-After: 5`) keeps the peer-keyed
/// creation journal. A retry inside the delay sends nothing; after it, and across a restart, the
/// exact signed publication is replayed over the journaled bootstrap (no second prepare, no
/// second recipient key package) and the journaled conversation and text win over the caller's.
/// A transient `acceptConversation` refusal keeps the acceptance journal the same way. Unsigned
/// semantic and authentication refusals after publication also retain the exact publication until
/// a signed outcome resolves it.
#[test]
fn c33_transient_refusal_replays_the_journaled_publication_after_retry_after() {
    use catbird_mls::sim_hooks::{FixedStepClock, OsSimEntropy, SimClientHooks, SimClock as _};

    const PREPARE: &str = "/xrpc/blue.catbird.chat.prepareDirectRequest";
    const PUBLISH: &str = "/xrpc/blue.catbird.chat.publishDirectRequest";
    const ACCEPT: &str = "/xrpc/blue.catbird.chat.acceptConversation";
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Alice's clock moves only when the test moves it.
    let start_ms = chrono::Utc::now().timestamp_millis();
    let clock = Arc::new(FixedStepClock::new(start_ms, 0));
    let alice_dev = uuid::Uuid::new_v4().to_string();
    let alice_keys = Arc::new(MemKeyStore::new());
    let open_alice = || {
        CatbirdMlsClient::open_with_hooks(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join("alice").to_string_lossy().into_owned(),
                account_did: ALICE_DID.to_string(),
                device_id: alice_dev.clone(),
                home_ds_did: DS_DID.to_string(),
                home_ds_endpoint: DS_URL.to_string(),
                pds_endpoint: PDS_URL.to_string(),
            },
            alice_keys.clone(),
            ds.for_account(ALICE_DID),
            None,
            SimClientHooks::new(clock.clone(), Arc::new(OsSimEntropy)),
        )
        .expect("open alice")
    };
    let alice = open_alice();
    let bob_dev = uuid::Uuid::new_v4().to_string();
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob",
        BOB_DID,
        &bob_dev,
        &Arc::new(MemKeyStore::new()),
    );
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    clock.advance_ms(chrono::Utc::now().timestamp_millis() - clock.now_ms());

    let bob_keys_left = || ds.inner.lock().unwrap().dr_keys[BOB_DID].len();
    let posts = |account: &str, route: &str| -> Vec<Vec<u8>> {
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(who, url, _)| who == account && url.ends_with(route))
            .map(|(_, _, body)| body.clone())
            .collect()
    };
    let alice_requests = || {
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(who, _, _)| who == ALICE_DID)
            .count()
    };
    let journal = |client: &CatbirdMlsClient| {
        client
            .db()
            .read_tx(|tx| tx.get_pending_op("direct_request_creation", BOB_DID))
            .unwrap()
    };
    let refuse = |route: &'static str, code: &'static str, retry_after: Option<&'static str>| {
        let status = if code == "CapacityUnavailable" {
            503
        } else {
            400
        };
        ds.inner
            .lock()
            .unwrap()
            .xrpc_failures
            .push((route, status, code, retry_after));
    };
    let create = |client: &CatbirdMlsClient, cid: &str, text: &str| {
        client.create_group(
            cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some(text.to_string()),
        )
    };
    let refusal = |result: Result<_, MLSError>| match result {
        Err(MLSError::InvalidState(code)) => code,
        other => panic!("expected a refusal, got {other:?}"),
    };

    // The DS cannot reach the coordinator: the first publication is refused as transient.
    let keys_before = bob_keys_left();
    refuse(PUBLISH, "CapacityUnavailable", Some("5"));
    let first_cid = uuid::Uuid::new_v4().to_string();
    let first = create(&alice, &first_cid, "first tap");
    assert_eq!(refusal(first), "CapacityUnavailable");
    // One recipient key package is reserved; the attempt is kept, uncommitted.
    assert_eq!(bob_keys_left(), keys_before - 1);
    assert!(journal(&alice).is_some());
    assert!(alice
        .list_conversations(None, 20)
        .unwrap()
        .iter()
        .all(|c| c.conversation_id != first_cid));
    let first_publish = posts(ALICE_DID, PUBLISH);
    assert_eq!(first_publish.len(), 1);
    let prepares = posts(ALICE_DID, PREPARE).len();

    // Inside `Retry-After` a new tap answers the same error without any request.
    clock.advance_ms(4_999);
    let requests = alice_requests();
    let early = create(&alice, &uuid::Uuid::new_v4().to_string(), "early tap");
    assert_eq!(refusal(early), "CapacityUnavailable");
    assert_eq!(alice_requests(), requests);

    // After a restart and the full delay, the journaled publication is replayed exactly: no
    // second prepare or key package, and the journaled conversation, group and text win.
    let journaled: Value = serde_json::from_str(&journal(&alice).unwrap()).unwrap();
    let journaled_group: Vec<u8> =
        serde_json::from_value(journaled["publish"]["group_id"].clone()).unwrap();
    drop(alice);
    let alice = open_alice();
    clock.advance_ms(1);
    let late_cid = uuid::Uuid::new_v4().to_string();
    let row = create(&alice, &late_cid, "late tap").expect("the journaled publication lands");
    assert_eq!(row.conversation_id, first_cid);
    assert_eq!(row.group_id, journaled_group);
    let publishes = posts(ALICE_DID, PUBLISH);
    assert_eq!(publishes.len(), 2);
    assert_eq!(publishes[1], first_publish[0]);
    assert_eq!(posts(ALICE_DID, PREPARE).len(), prepares);
    assert_eq!(bob_keys_left(), keys_before - 1);
    assert!(journal(&alice).is_none());
    let opening = alice.list_messages(&first_cid, None, 20).unwrap();
    assert!(opening[0].plaintext_json.contains("first tap"));
    bob.sync().expect("bob imports the replayed request");
    assert!(bob
        .list_messages(&first_cid, None, 20)
        .unwrap()
        .iter()
        .any(|m| m.plaintext_json.contains("first tap")));

    // A transient `acceptConversation` refusal keeps the exact signed acceptance.
    let request_id = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0)
        .request_id;
    let acceptance = || {
        bob.db()
            .read_tx(|tx| tx.get_pending_op("direct_request_acceptance", &request_id))
            .unwrap()
    };
    refuse(ACCEPT, "CapacityUnavailable", None);
    assert!(matches!(
        bob.accept_direct_request(&request_id),
        Err(MLSError::InvalidState(code)) if code == "CapacityUnavailable"
    ));
    assert!(acceptance().is_some());
    bob.accept_direct_request(&request_id)
        .expect("the journaled acceptance lands");
    assert!(acceptance().is_none());
    let accepts = posts(BOB_DID, ACCEPT);
    assert_eq!(accepts.len(), 2);
    assert_eq!(accepts[0], accepts[1]);

    // An unsigned semantic refusal, followed by an authentication refusal, cannot prove that the
    // publication was not accepted. Both retain and replay the exact immutable publication.
    let prepares_before_unknown = posts(ALICE_DID, PREPARE).len();
    refuse(PUBLISH, "RequestPolicyDenied", None);
    let denied_caller_cid = uuid::Uuid::new_v4().to_string();
    let refused = create(&alice, &denied_caller_cid, "denied");
    assert_eq!(refusal(refused), "RequestPolicyDenied");
    let retained: Value =
        serde_json::from_str(&journal(&alice).expect("unsigned refusal retains the publication"))
            .unwrap();
    let retained_conversation_id = retained["conversation_id"].as_str().unwrap().to_string();
    let retained_publish = retained["publish"]["publish_wrapper"].clone();
    ds.inner
        .lock()
        .unwrap()
        .xrpc_failures
        .push((PUBLISH, 401, "AuthRequired", None));
    assert!(create(&alice, &uuid::Uuid::new_v4().to_string(), "auth retry").is_err());
    let after_auth: Value =
        serde_json::from_str(&journal(&alice).expect("auth refusal retains the publication"))
            .unwrap();
    assert_eq!(after_auth["publish"]["publish_wrapper"], retained_publish);
    assert_eq!(posts(ALICE_DID, PREPARE).len(), prepares_before_unknown + 1);

    let later_caller_cid = uuid::Uuid::new_v4().to_string();
    let resumed = create(&alice, &later_caller_cid, "later tap")
        .expect("a signed published outcome resolves the retained attempt");
    assert_eq!(resumed.conversation_id, retained_conversation_id);
    assert_ne!(resumed.conversation_id, later_caller_cid);
    let publications = posts(ALICE_DID, PUBLISH);
    let replayed = &publications[publications.len() - 3..];
    assert!(replayed.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(journal(&alice).is_none());
}

/// A signed terminal receipt answering a replayed prepare drops the C33 creation journal only once
/// it verifies like a publication outcome. A forged signature or a receipt bound to another
/// request fails closed and leaves the journal byte-for-byte untouched.
#[test]
fn c33_prepare_stage_terminal_receipt_must_verify_before_the_journal_is_dropped() {
    const PREPARE: &str = "/xrpc/blue.catbird.chat.prepareDirectRequest";
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_dev = uuid::Uuid::new_v4().to_string();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &alice_dev, &alice_keys);
    let bob_dev = uuid::Uuid::new_v4().to_string();
    let bob_keys = Arc::new(MemKeyStore::new());
    let bob = live_client(tmp.path(), &ds, "bob", BOB_DID, &bob_dev, &bob_keys);
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    let journal = || {
        alice
            .db()
            .read_tx(|tx| tx.get_pending_op("direct_request_creation", BOB_DID))
            .unwrap()
    };
    let create = || {
        alice.create_group(
            &uuid::Uuid::new_v4().to_string(),
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("hello".to_string()),
        )
    };

    // The DS cannot reach the coordinator, so the journaled attempt stays at its prepare.
    let refusal = (PREPARE, 400, "CapacityUnavailable", None);
    ds.inner.lock().unwrap().xrpc_failures.push(refusal);
    assert!(create().is_err());
    let journaled = journal().expect("a transient refusal keeps the attempt");

    for fault in ["badSignature", "wrongRequestId"] {
        ds.inner.lock().unwrap().next_prepare_receipt = Some(fault);
        let error = create().expect_err(fault);
        assert!(
            matches!(error, MLSError::Cryptography(_)),
            "{fault}: {error}"
        );
        assert_eq!(journal().as_ref(), Some(&journaled), "{fault}");
    }

    ds.inner.lock().unwrap().next_prepare_receipt = Some("valid");
    assert!(matches!(
        create(),
        Err(MLSError::InvalidState(code)) if code == "PreparationExpired"
    ));
    assert!(
        journal().is_none(),
        "a verified terminal receipt resolves the attempt"
    );
}

/// `(messageId, sendCounter, ciphertext, outcome)` of one `sendMessage` the mock DS saw.
fn send_attempt(body_json: &Value, outcome: &'static str) -> (String, u64, String, &'static str) {
    let b = &body_json["signedRequest"]["body"];
    (
        b["messageId"].as_str().unwrap().to_owned(),
        b["sendCounter"].as_u64().expect("signed sendCounter"),
        b["applicationMessage"]["bytes"].to_string(),
        outcome,
    )
}

/// `mls-ds` `resolve_application_send`: an exact replay of a sequenced send returns its stored
/// outcome; a first-seen send is sequenced only if its signed (`prior.generation`,
/// `prior.epoch`, `sendCounter`) exceeds the device's last accepted send, otherwise it is
/// refused `StaleSend` and nothing is written.
fn sequence_send(g: &mut MockDsState, body_json: &Value) -> Result<PlatformHttpResponse, MLSError> {
    let sr = body_json["signedRequest"].clone();
    let b = &sr["body"];
    let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
    let msg_id = b["messageId"].as_str().unwrap().to_string();
    if let Some(entry) = g
        .entries
        .get(&cid)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry["signedRequest"]["body"]["messageId"].as_str() == Some(msg_id.as_str())
            })
        })
        .cloned()
    {
        assert_eq!(
            entry["signedRequest"], sr,
            "uncertain send retries must replay the exact signed ciphertext"
        );
        g.send_attempts.push(send_attempt(body_json, "replayed"));
        // An idempotent replay returns the original accepted outcome.
        return ok_json(json!({
            "entry": entry,
            "sequencerReceipt": entry["sequencerReceipt"],
        }));
    }
    let actor_did = b["actorDid"].as_str().unwrap().to_string();
    let actor_dev = b["actorDeviceId"].as_str().unwrap().to_string();
    let gen = b["prior"]["generation"].as_u64().unwrap_or(0);
    let epoch = b["prior"]["epoch"].as_u64().unwrap_or(0);
    let group_id = chat_wire::json_bytes(&b["prior"]["groupId"]).unwrap();
    let commit_arr: [u8; 32] = chat_wire::json_bytes(&b["aad"]["archiveCommitment"])
        .unwrap()
        .try_into()
        .unwrap();

    if g.omit_next_receipt {
        g.omit_next_receipt = false;
        let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as u64) + 1;
        return ok_json(json!({ "seq": seq }));
    }

    let device = (cid.clone(), actor_did.clone(), actor_dev.clone());
    let position = (
        gen,
        epoch,
        b["sendCounter"].as_u64().expect("signed sendCounter"),
    );
    let last = g.send_order.get(&device).copied();
    if g.refuse_sends || (g.enforce_send_order && last.is_some_and(|last| position <= last)) {
        g.send_attempts.push(send_attempt(body_json, "stale"));
        return xrpc_error(
            400,
            "StaleSend",
            "a newer send from this device was sequenced",
        );
    }
    if last.is_none_or(|last| position > last) {
        g.send_order.insert(device, position);
    }
    g.send_attempts.push(send_attempt(body_json, "accepted"));

    let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as u64) + 1;
    // `mls-ds` mints the entry ID and signs the I13 receipt over that sequenced entry.
    let entry_id = uuid::Uuid::new_v4().to_string();
    let mut payload = SequencerReceiptPayload {
        sequencer_did: DS_DID.to_string(),
        conversation_id: cid.clone(),
        group_id,
        epoch,
        sender_device_did_url: format!("{actor_did}#{actor_dev}"),
        entry_id: entry_id.clone(),
        archive_commitment: commit_arr,
        seq,
        issued_at_ms: 1_762_000_000_000,
    };
    if g.tamper_next_receipt {
        g.tamper_next_receipt = false;
        payload.archive_commitment[0] ^= 0xff;
    }
    let signed = match (&g.historical_receipt_sk, g.rotated_sequencer_receipts) {
        (Some(current), true) => {
            sign_sequencer_receipt(current, &format!("{DS_DID}#mls-receipt-2"), &payload)
        }
        _ => sign_sequencer_receipt(&g.receipt_sk, &format!("{DS_DID}#mls-receipt-1"), &payload),
    }
    .unwrap();
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
    let received_at = b["signedAt"].clone();
    let entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "entryId": entry_id,
        "conversationId": cid.clone(),
        "seq": seq,
        "signedRequest": sr,
        "sequencerReceipt": rcpt_json.clone(),
        "receivedAt": received_at,
    });
    g.entries.entry(cid).or_default().push(entry.clone());
    ok_json(json!({ "entry": entry, "sequencerReceipt": rcpt_json }))
}

impl SharedMockDs {
    /// The network finally delivers every held `sendMessage`. A held copy of a message the
    /// sender has since sequenced under other bytes is a conflicting replay and is refused.
    fn deliver_held_sends(&self) {
        let mut g = self.inner.lock().unwrap();
        for body in std::mem::take(&mut g.held_sends) {
            let sr = &body["signedRequest"];
            let cid = sr["body"]["prior"]["conversationId"].as_str().unwrap();
            let conflict = g.entries.get(cid).is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["signedRequest"]["body"]["messageId"] == sr["body"]["messageId"]
                        && entry["signedRequest"] != *sr
                })
            });
            if conflict {
                g.send_attempts.push(send_attempt(&body, "conflict"));
            } else {
                let _ = sequence_send(&mut g, &body);
            }
        }
    }

    /// `(sendCounter, outcome, ciphertext)` of every `sendMessage` for `message_id`, in order.
    fn send_attempts(&self, message_id: &str) -> Vec<(u64, &'static str, String)> {
        self.inner
            .lock()
            .unwrap()
            .send_attempts
            .iter()
            .filter(|attempt| attempt.0 == message_id)
            .map(|attempt| (attempt.1, attempt.3, attempt.2.clone()))
            .collect()
    }

    fn entry_count(&self, cid: &str) -> i64 {
        self.inner
            .lock()
            .unwrap()
            .entries
            .get(cid)
            .map_or(0, Vec::len) as i64
    }
}

struct SendOrderFixture {
    tmp: tempfile::TempDir,
    ds: Arc<SharedMockDs>,
    cid: String,
    alice: Arc<CatbirdMlsClient>,
    alice_dev: String,
    bob: Arc<CatbirdMlsClient>,
    bob_dev: String,
    bob_keys: Arc<MemKeyStore>,
    eve: Arc<CatbirdMlsClient>,
}

/// Alice creates a live group with Bob and both complete the join. With `invite_eve`, Eve is
/// invited too but accepts only when the test syncs her, so Alice's add Commit comes later.
fn send_order_fixture(invite_eve: bool) -> SendOrderFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let (alice_dev, bob_dev) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    let bob_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(
        tmp.path(),
        &ds,
        "alice",
        ALICE_DID,
        &alice_dev,
        &Arc::new(MemKeyStore::new()),
    );
    let bob = live_client(tmp.path(), &ds, "bob", BOB_DID, &bob_dev, &bob_keys);
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    let eve = live_client(
        tmp.path(),
        &ds,
        "eve",
        EVE_DID,
        &uuid::Uuid::new_v4().to_string(),
        &Arc::new(MemKeyStore::new()),
    );
    eve.enroll_device(&scopes).expect("enroll eve");
    let mut members = vec![BOB_DID.to_string()];
    if invite_eve {
        members.push(EVE_DID.to_string());
    }
    let cid = uuid::Uuid::new_v4().to_string();
    alice
        .create_group(&cid, DS_DID, members, Some("Send order".into()), None)
        .expect("create group");
    bob.sync().expect("bob accepts the invite");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");
    SendOrderFixture {
        tmp,
        ds,
        cid,
        alice,
        alice_dev,
        bob,
        bob_dev,
        bob_keys,
        eve,
    }
}

/// `(seq, text)` of `client`'s rows after `after_seq`, oldest first; a gap row shows its key.
fn timeline_after(client: &CatbirdMlsClient, cid: &str, after_seq: i64) -> Vec<(i64, String)> {
    let mut rows = client.list_messages(cid, None, 200).unwrap();
    rows.sort_by_key(|row| row.seq);
    rows.iter()
        .filter(|row| row.seq > after_seq)
        .map(|row| {
            let payload: Value = serde_json::from_str(&row.plaintext_json).unwrap();
            (
                row.seq,
                payload["text"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Seed 2323, shrunk to six actions (red-team R1, P2): Bob's first send is held by the network;
/// Bob crashes and reopens; both sides send; Bob retries an accepted send whose response was
/// lost; Bob sends twice more; only then does the held request reach `mls-ds`. The
/// counter-enforcing DS refuses it `StaleSend` without sequencing it, so no receiver meets a
/// generation behind its ratchet window and both transcripts stay identical. The same message
/// id then goes out once more as a fresh frame under a new counter.
#[test]
fn seed_2323_shrunk_six_action_repro_never_sequences_a_held_send_behind_newer_sends() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    let baseline = ds.entry_count(cid);

    // 1. Bob's send is held by the network; the client sees a transport error.
    let crash = new_id();
    ds.inner.lock().unwrap().hold_next_send = true;
    assert!(f.bob.send_message(cid, &crash, "crash-b7f3ca61-0").is_err());
    // 2. Mid-flush jetsam: a send, then the process dies and reopens from disk.
    f.bob
        .send_message(cid, &new_id(), "queued-before-jetsam")
        .unwrap();
    drop(f.bob);
    let bob = live_client(f.tmp.path(), ds, "bob", BOB_DID, &f.bob_dev, &f.bob_keys);
    // 3. After the crash: the peer and Bob send, and Bob's sync keeps each accepted send once.
    alice
        .send_message(cid, &new_id(), "peer-before-own-ahead")
        .unwrap();
    bob.send_message(cid, &new_id(), "own-ahead-of-cursor")
        .unwrap();
    bob.sync().unwrap();
    // 4. Bob retries an accepted send whose response was lost: the journal replays its bytes.
    let retry = new_id();
    ds.inner.lock().unwrap().lose_next_send_response = true;
    assert!(bob.send_message(cid, &retry, "retry-b7f3ca61-0").is_err());
    bob.send_message(cid, &retry, "retry-b7f3ca61-0").unwrap();
    // 5, 6. Two more sends.
    bob.send_message(cid, &new_id(), "chat-b7f3ca61-3").unwrap();
    bob.send_message(cid, &new_id(), "send-b7f3ca61-0").unwrap();

    // The held request reaches `mls-ds` last: refused, and nothing is sequenced.
    let sequenced = ds.entry_count(cid);
    ds.deliver_held_sends();
    assert_eq!(ds.entry_count(cid), sequenced);
    alice
        .sync()
        .expect("no entry is behind alice's ratchet window");
    bob.sync().unwrap();
    let expected: Vec<(i64, String)> = [
        "queued-before-jetsam",
        "peer-before-own-ahead",
        "own-ahead-of-cursor",
        "retry-b7f3ca61-0",
        "chat-b7f3ca61-3",
        "send-b7f3ca61-0",
    ]
    .iter()
    .zip(baseline + 1..)
    .map(|(text, seq)| (seq, text.to_string()))
    .collect();
    assert_eq!(timeline_after(alice, cid, baseline), expected);
    assert_eq!(timeline_after(&bob, cid, baseline), expected);

    // The same message id goes out once more as a fresh frame with the next counter.
    let row = bob
        .send_message(cid, &crash, "crash-b7f3ca61-0")
        .expect("StaleSend re-encrypts the held message once");
    let attempts = ds.send_attempts(&crash);
    assert_eq!(
        attempts
            .iter()
            .map(|(counter, outcome, _)| (*counter, *outcome))
            .collect::<Vec<_>>(),
        [(1, "held"), (1, "stale"), (1, "stale"), (7, "accepted")],
        "the refused bytes are resubmitted once from the journal, then replaced"
    );
    assert_eq!(attempts[0].2, attempts[2].2);
    assert_ne!(
        attempts[3].2, attempts[0].2,
        "refused bytes are never sequenced"
    );
    assert_eq!(row.seq, sequenced + 1);
    alice.sync().unwrap();
    let mut expected = expected;
    expected.push((sequenced + 1, "crash-b7f3ca61-0".into()));
    assert_eq!(timeline_after(alice, cid, baseline), expected);
    assert_eq!(timeline_after(&bob, cid, baseline), expected);
}

/// A send held in the network keeps its journal. After a newer send is sequenced, the caller's
/// retry resubmits those exact bytes, `mls-ds` refuses them (`StaleSend`), and the same message
/// id goes out once more as a fresh frame; a second refusal is returned, not retried again.
#[test]
fn stale_send_reencrypts_once_and_never_resubmits_refused_bytes() {
    let f = send_order_fixture(false);
    let (ds, cid, bob) = (&f.ds, f.cid.as_str(), &f.bob);
    let baseline = ds.entry_count(cid);
    let held = new_id();
    ds.inner.lock().unwrap().hold_next_send = true;
    assert!(bob.send_message(cid, &held, "held").is_err());
    bob.send_message(cid, &new_id(), "newer").unwrap();
    let row = bob.send_message(cid, &held, "held").unwrap();
    let attempts = ds.send_attempts(&held);
    assert_eq!(
        attempts
            .iter()
            .map(|(counter, outcome, _)| (*counter, *outcome))
            .collect::<Vec<_>>(),
        [(1, "held"), (1, "stale"), (3, "accepted")]
    );
    assert_eq!(
        attempts[0].2, attempts[1].2,
        "the retry resubmits the journal"
    );
    assert_ne!(
        attempts[2].2, attempts[0].2,
        "the refused bytes are never sequenced"
    );
    assert_eq!(row.seq, baseline + 2);
    ds.deliver_held_sends();
    assert_eq!(ds.send_attempts(&held).last().unwrap().1, "conflict");
    f.alice.sync().unwrap();
    assert_eq!(
        timeline_after(&f.alice, cid, baseline),
        [
            (baseline + 1, "newer".to_string()),
            (baseline + 2, "held".to_string())
        ]
    );

    ds.inner.lock().unwrap().refuse_sends = true;
    let refused = new_id();
    let error = bob.send_message(cid, &refused, "refused").unwrap_err();
    assert!(chat_wire::is_stale_send(&error), "{error:?}");
    assert_eq!(
        ds.send_attempts(&refused)
            .iter()
            .map(|(counter, outcome, _)| (*counter, *outcome))
            .collect::<Vec<_>>(),
        [(4, "stale"), (5, "stale")],
        "exactly one fresh re-encryption"
    );
}

/// Seed 2323 against a DS without the send-order rule: Alice's held send is sequenced behind
/// her ten newer sends, outside Bob's sender-ratchet window (10). Bob records a gap row and
/// evidence for it, advances his cursor, and still applies Alice's later Commit.
#[test]
fn undecryptable_current_epoch_entry_is_tombstoned_and_a_later_commit_applies() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let baseline = ds.entry_count(cid);
    ds.inner.lock().unwrap().enforce_send_order = false;
    let late = new_id();
    ds.inner.lock().unwrap().hold_next_send = true;
    assert!(alice.send_message(cid, &late, "late").is_err());
    for n in 1..=10 {
        alice
            .send_message(cid, &new_id(), &format!("newer {n}"))
            .unwrap();
    }
    ds.deliver_held_sends();
    let late_seq = baseline + 11;
    let epoch_before = bob
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap()
        .epoch;
    // Eve accepts her invitation only now, so Alice's add Commit follows the late entry.
    f.eve.sync().unwrap();
    alice.sync().unwrap();

    bob.sync()
        .expect("an undecryptable entry no longer stops sync");
    let mut expected: Vec<(i64, String)> = (1..=10)
        .map(|n| (baseline + n, format!("newer {n}")))
        .collect();
    expected.push((late_seq, chat_wire::UNDECRYPTABLE_MESSAGE_NOTICE.into()));
    assert_eq!(
        timeline_after(bob, cid, baseline)
            .into_iter()
            .filter(|(seq, _)| *seq <= late_seq)
            .collect::<Vec<_>>(),
        expected
    );
    let gap = bob
        .list_messages(cid, None, 200)
        .unwrap()
        .into_iter()
        .find(|row| row.seq == late_seq)
        .unwrap();
    assert_eq!(
        (gap.message_id.as_str(), gap.sender_did.as_str(), gap.is_own),
        (late.as_str(), ALICE_DID, false)
    );
    assert_eq!(
        gap.plaintext_json,
        serde_json::to_string(&catbird_mls::orchestrator::MLSMessagePayload::system(
            chat_wire::UNDECRYPTABLE_MESSAGE_NOTICE
        ))
        .unwrap()
    );
    let convo = bob
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap();
    assert_eq!(convo.last_seq, ds.entry_count(cid), "cursor past the gap");
    assert!(convo.epoch > epoch_before, "Alice's later Commit applied");
    let evidence: chat_wire::UndecryptableEntryEvidence = serde_json::from_slice(
        &bob.db()
            .write_tx(|tx| {
                tx.get_labyrinth_state(&chat_wire::undecryptable_evidence_key(cid, &late))
            })
            .unwrap()
            .expect("undecryptable evidence"),
    )
    .unwrap();
    assert_eq!(
        (
            evidence.seq,
            evidence.epoch,
            evidence.reason.as_str(),
            evidence.sender_device_id.as_str()
        ),
        (
            late_seq,
            epoch_before,
            "TooDistantInThePast",
            f.alice_dev.as_str()
        )
    );
}

/// Re-sign the I13 receipt of the entry at `entry_seq` with the DS key, now naming `seq`.
fn resign_receipt_seq(ds: &SharedMockDs, cid: &str, entry_seq: i64, seq: u64) {
    let mut g = ds.inner.lock().unwrap();
    let key = g.receipt_sk.clone();
    let entry = g
        .entries
        .get_mut(cid)
        .unwrap()
        .iter_mut()
        .find(|entry| entry["seq"].as_i64() == Some(entry_seq))
        .unwrap();
    let r = entry["sequencerReceipt"].clone();
    let bytes = |value: &Value| STANDARD.decode(value["$bytes"].as_str().unwrap()).unwrap();
    let payload = SequencerReceiptPayload {
        sequencer_did: DS_DID.into(),
        conversation_id: cid.into(),
        group_id: bytes(&r["groupId"]),
        epoch: r["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            r["senderDid"].as_str().unwrap(),
            r["senderDeviceId"].as_str().unwrap()
        ),
        entry_id: r["entryId"].as_str().unwrap().into(),
        archive_commitment: bytes(&r["archiveCommitment"]).try_into().unwrap(),
        seq,
        issued_at_ms: r["issuedAtMs"].as_i64().unwrap(),
    };
    let signed =
        sign_sequencer_receipt(&key, &format!("{DS_DID}#mls-receipt-1"), &payload).unwrap();
    entry["sequencerReceipt"]["seq"] = json!(seq);
    entry["sequencerReceipt"]["signature"] = json!({ "$bytes": STANDARD.encode(signed.signature) });
}

/// Serve the entry at `seq` as mls-ds does once O7 prunes its ciphertext: no `signedRequest`,
/// `payloadPruned`, and its own I13 receipt kept verbatim.
fn prune_entry(ds: &SharedMockDs, cid: &str, seq: i64) {
    let mut g = ds.inner.lock().unwrap();
    let entry = g
        .entries
        .get_mut(cid)
        .unwrap()
        .iter_mut()
        .find(|entry| entry["seq"].as_i64() == Some(seq))
        .unwrap();
    let (entry_id, received_at, receipt) = (
        entry["entryId"].clone(),
        entry["receivedAt"].clone(),
        entry["sequencerReceipt"].clone(),
    );
    *entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "conversationId": cid,
        "entryId": entry_id,
        "seq": seq,
        "receivedAt": received_at,
        "payloadPruned": true,
        "sequencerReceipt": receipt,
    });
}

fn last_seq(client: &CatbirdMlsClient, cid: &str) -> i64 {
    client
        .db()
        .read_tx(|tx| tx.get_conversation(cid))
        .unwrap()
        .unwrap()
        .last_seq
}

/// R3 P0: an undecryptable entry moves the cursor only under its own I13 receipt for exactly
/// its seq. A genuine sequencer signature over another seq leaves no gap row, no evidence and
/// no cursor advance; the exact receipt then authenticates the gap.
#[test]
fn undecryptable_entry_without_its_exact_receipt_never_advances_the_cursor() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let baseline = ds.entry_count(cid);
    ds.inner.lock().unwrap().enforce_send_order = false;
    let late = new_id();
    ds.inner.lock().unwrap().hold_next_send = true;
    assert!(alice.send_message(cid, &late, "late").is_err());
    for n in 1..=10 {
        alice
            .send_message(cid, &new_id(), &format!("newer {n}"))
            .unwrap();
    }
    ds.deliver_held_sends();
    let late_seq = baseline + 11;
    resign_receipt_seq(ds, cid, late_seq, late_seq as u64 + 1);
    bob.sync()
        .expect_err("a receipt for another seq is not this entry's");
    assert!(last_seq(bob, cid) < late_seq);
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_message(&late))
        .unwrap()
        .is_none());
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_labyrinth_state(&chat_wire::undecryptable_evidence_key(cid, &late)))
        .unwrap()
        .is_none());
    resign_receipt_seq(ds, cid, late_seq, late_seq as u64);
    bob.sync().expect("its exact receipt authenticates the gap");
    assert_eq!(last_seq(bob, cid), late_seq);
}

/// A pruned application entry this device never held advances the cursor only under its own
/// signed receipt for exactly that conversation, group, entry and seq.
#[test]
fn pruned_entry_advances_the_cursor_only_under_its_exact_receipt() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    alice
        .send_message(cid, &new_id(), "pruned before bob reads it")
        .unwrap();
    let seq = ds.entry_count(cid);
    prune_entry(ds, cid, seq);
    resign_receipt_seq(ds, cid, seq, seq as u64 + 1);
    bob.sync()
        .expect_err("a pruned entry under another seq's receipt");
    assert!(last_seq(bob, cid) < seq);
    resign_receipt_seq(ds, cid, seq, seq as u64);
    bob.sync()
        .expect("its exact receipt authenticates the pruned entry");
    assert_eq!(last_seq(bob, cid), seq);
}

/// Every `StaleSend` refusal, the second included, drops the refused journal at once: a later
/// retry of the same message id encrypts afresh and never resubmits refused bytes.
#[test]
fn every_stale_send_refusal_drops_the_refused_journal() {
    let f = send_order_fixture(false);
    let (ds, cid, bob) = (&f.ds, f.cid.as_str(), &f.bob);
    ds.inner.lock().unwrap().refuse_sends = true;
    let refused = new_id();
    for _ in 0..2 {
        let error = bob.send_message(cid, &refused, "refused").unwrap_err();
        assert!(chat_wire::is_stale_send(&error), "{error:?}");
        assert!(
            bob.db()
                .read_tx(|tx| tx.get_pending_op("application_send", &refused))
                .unwrap()
                .is_none(),
            "refused bytes keep no journal"
        );
    }
    let attempts = ds.send_attempts(&refused);
    assert_eq!(attempts.len(), 4);
    let frames: std::collections::BTreeSet<&String> =
        attempts.iter().map(|attempt| &attempt.2).collect();
    assert_eq!(frames.len(), 4, "no refused frame is ever resubmitted");
    assert!(
        attempts.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "{attempts:?}"
    );
}

/// R1 #14: a cached row whose plaintext no longer matches its retained archive evidence never
/// borrows that evidence's receipt; re-verification fails closed instead of advancing.
#[test]
fn replaced_display_row_never_inherits_retained_receipt_evidence() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let id = new_id();
    alice.send_message(cid, &id, "authentic").unwrap();
    bob.sync().unwrap();
    let seq = ds.entry_count(cid);
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "UPDATE messages SET plaintext_json = ?1 WHERE message_id = ?2",
                    rusqlite::params![r#"{"text":"forged"}"#, id],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            // `upsert_conversation` never moves a cursor back: rewind it directly.
            tx.conn()
                .execute(
                    "UPDATE conversations SET last_seq = ?1 WHERE conversation_id = ?2",
                    rusqlite::params![seq - 1, cid],
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .unwrap();
    let error = bob
        .sync()
        .expect_err("the replaced row does not match its evidence");
    assert!(error.to_string().contains("binding mismatch"), "{error}");
    assert_eq!(last_seq(bob, cid), seq - 1, "nothing advanced");
}

/// R3 #9: after the sequencer rotates to `#mls-receipt-2` (retaining `#1`), a C33 opening still
/// publishes and imports: each receipt verifies under the method its own `kid` names.
#[test]
fn c33_opening_and_import_verify_a_rotated_receipt_method() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    {
        let mut g = ds.inner.lock().unwrap();
        g.historical_receipt_sk = Some(P256SigningKey::from_slice(&[0x3a; 32]).unwrap());
        g.rotated_sequencer_receipts = true;
    }
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let keys = Arc::new(MemKeyStore::new());
    let alice = live_client(tmp.path(), &ds, "alice", ALICE_DID, &new_id(), &keys);
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob",
        BOB_DID,
        &new_id(),
        &Arc::new(MemKeyStore::new()),
    );
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("rotated opening".into()),
        )
        .expect("the opening receipt verifies under #mls-receipt-2");
    bob.sync()
        .expect("the import verifies under #mls-receipt-2");
    assert_eq!(bob.list_requests(Some("incomingPending")).unwrap().len(), 1);
}

/// Live create and join both carry the `GroupConfig` sender-ratchet window (10 / 2000): a frame
/// sequenced nine generations late still decrypts.
#[test]
fn live_create_and_join_apply_the_group_config_sender_ratchet_window() {
    let f = send_order_fixture(false);
    let (ds, cid) = (&f.ds, f.cid.as_str());
    for client in [&f.alice, &f.bob] {
        let window = client
            .db()
            .write_tx(|tx| {
                let convo = tx.get_conversation(cid)?.unwrap();
                let provider = tx.openmls_provider();
                let group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("{e:?}")))?
                        .unwrap();
                let config = group.configuration().sender_ratchet_configuration();
                Ok((
                    config.out_of_order_tolerance(),
                    config.maximum_forward_distance(),
                ))
            })
            .unwrap();
        assert_eq!(window, (10, 2000));
    }
    let baseline = ds.entry_count(cid);
    ds.inner.lock().unwrap().enforce_send_order = false;
    let late = new_id();
    ds.inner.lock().unwrap().hold_next_send = true;
    assert!(f.alice.send_message(cid, &late, "late").is_err());
    for n in 1..=9 {
        f.alice
            .send_message(cid, &new_id(), &format!("newer {n}"))
            .unwrap();
    }
    ds.deliver_held_sends();
    f.bob.sync().unwrap();
    assert_eq!(
        timeline_after(&f.bob, cid, baseline).last().unwrap(),
        &(baseline + 10, "late".to_string())
    );
}

fn labyrinth_state(client: &CatbirdMlsClient, key: &str) -> Option<Vec<u8>> {
    client
        .db()
        .read_tx(|tx| tx.get_labyrinth_state(key))
        .unwrap()
}

/// R4 item 2 (R3 #5): unsending a message still in `labyrinth_queue` drops the queued copy and
/// writes `native.unsent` in one transaction. A later flush, even of a replayed queue row, and a
/// kick rescue from its cached evidence archive it nowhere.
#[test]
fn unsent_queued_message_is_never_archived_by_a_later_flush_or_kick_rescue() {
    let f = send_order_fixture(false);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    let id = new_id();
    alice.send_message(cid, &id, "take this back").unwrap();
    let queued = || {
        alice
            .db()
            .read_tx(|tx| tx.list_labyrinth_queue(Some(cid), 100))
            .unwrap()
            .into_iter()
            .find(|row| row.item_id == id)
    };
    let row = queued().expect("queued for the archive");
    alice
        .unsend_message(cid, &id)
        .expect("unsend publishes the redaction");
    assert!(queued().is_none(), "the queued copy is dropped");
    assert!(labyrinth_state(alice, &format!("native.unsent:{cid}:{id}")).is_some());

    // A replayed send journal queues it again; its cached evidence stays.
    alice
        .db()
        .write_tx(|tx| tx.enqueue_labyrinth_item(&row))
        .unwrap();
    let writes = ds.archive_auth.committed_space_write_count();
    alice.flush_labyrinth_queue().expect("flush");
    assert!(queued().is_none(), "dequeued without an archive copy");
    assert_eq!(alice.rescue_conversation_on_kick(cid).unwrap(), 0);
    assert_eq!(
        ds.archive_auth.committed_space_write_count(),
        writes,
        "neither the conversation Space nor the owner mailbox gets a copy"
    );
    assert!(labyrinth_state(alice, &format!("native.owner:{cid}:{id}")).is_none());
}

/// R4 item 4 (R3 #7): an archive read checks the member devices mls-ds reports against this
/// device's MLS group at its last applied entry. A DS list that adds or swaps a device fails the
/// read closed; the group's own leaves pass.
#[test]
fn archive_read_fails_closed_when_mls_ds_member_devices_differ_from_the_local_group() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code()
        .expect("bob's archive is enrolled, so alice's copy is sealed to him");
    let id = new_id();
    alice.send_message(cid, &id, "archived").unwrap();
    alice
        .flush_labyrinth_queue()
        .expect("alice archives her copy");
    bob.sync().unwrap();
    let alice_key =
        ds.inner.lock().unwrap().device_keys[&(ALICE_DID.to_owned(), f.alice_dev.clone())];
    for reported in [vec![alice_key, [7; 32]], vec![[7; 32]]] {
        ds.inner.lock().unwrap().member_devices_override = Some((ALICE_DID.to_owned(), reported));
        let error = bob
            .restore_conversation_from_owner_mailbox(cid)
            .expect_err("the reported devices differ from the local group");
        assert!(
            error
                .to_string()
                .contains("disagree with the local MLS group"),
            "{error}"
        );
    }
    ds.inner.lock().unwrap().member_devices_override = None;
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute("DELETE FROM messages WHERE message_id = ?1", [&id])
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        bob.restore_conversation_from_owner_mailbox(cid)
            .expect("the group's own leaves pass"),
        1,
        "alice's copy is read back"
    );
}

/// R4 item 8 (R3 #14): restore replaces an undecryptable gap row with the one archive copy at
/// exactly its sequenced coordinates and clears its `native.undecryptable` evidence; while the
/// gap sits at other coordinates the copy leaves it alone.
#[test]
fn restore_heals_an_undecryptable_gap_only_from_the_copy_at_its_coordinates() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code()
        .expect("bob's archive is enrolled, so alice's copies are sealed to him");
    let baseline = ds.entry_count(cid);
    ds.inner.lock().unwrap().enforce_send_order = false;
    let late = new_id();
    ds.inner.lock().unwrap().hold_next_send = true;
    assert!(alice.send_message(cid, &late, "late").is_err());
    for n in 1..=10 {
        alice
            .send_message(cid, &new_id(), &format!("newer {n}"))
            .unwrap();
    }
    ds.deliver_held_sends();
    let late_seq = baseline + 11;
    bob.sync().expect("bob records the gap");
    alice
        .sync()
        .expect("alice recovers her late send from its journal");
    alice
        .flush_labyrinth_queue()
        .expect("alice archives her copies");
    let gap_key = chat_wire::undecryptable_evidence_key(cid, &late);
    let late_text = || {
        let row = bob
            .db()
            .read_tx(|tx| tx.get_message(&late))
            .unwrap()
            .unwrap();
        let payload: Value = serde_json::from_str(&row.plaintext_json).unwrap();
        payload["text"].as_str().unwrap().to_owned()
    };
    let move_gap = |seq: i64| {
        bob.db()
            .write_tx(|tx| {
                tx.conn()
                    .execute(
                        "UPDATE messages SET seq = ?1 WHERE message_id = ?2",
                        rusqlite::params![seq, late],
                    )
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                Ok(())
            })
            .unwrap();
    };
    assert!(labyrinth_state(bob, &gap_key).is_some());

    move_gap(late_seq + 1);
    assert_eq!(bob.restore_conversation_from_owner_mailbox(cid).unwrap(), 0);
    assert_eq!(late_text(), chat_wire::UNDECRYPTABLE_MESSAGE_NOTICE);
    assert!(labyrinth_state(bob, &gap_key).is_some());

    move_gap(late_seq);
    assert_eq!(bob.restore_conversation_from_owner_mailbox(cid).unwrap(), 1);
    assert_eq!(late_text(), "late");
    assert!(labyrinth_state(bob, &gap_key).is_none());
}

/// R3 #13 over the live path: a kick rescue of 100 cached messages skips only the one whose own
/// evidence is invalid and rescues the other 99. A Space write outage instead fails the rescue:
/// every message stays queued and none is reported skipped.
#[test]
fn live_kick_rescue_skips_only_invalid_evidence_and_fails_on_a_write_outage() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    bob.setup_recovery_code()
        .expect("bob's archive is enrolled");
    let ids: Vec<String> = (0..100).map(|_| new_id()).collect();
    for (n, id) in ids.iter().enumerate() {
        alice.send_message(cid, id, &format!("cached {n}")).unwrap();
    }
    bob.sync().unwrap();
    let corrupt = ids[37].as_str();
    // Its frame nonce no longer opens its receipt's archive commitment, queued or cached.
    bob.db()
        .write_tx(|tx| {
            let nonce = json!(STANDARD.encode([0_u8; 32]));
            let key = format!("native.message:{cid}:{corrupt}");
            let mut evidence: Value =
                serde_json::from_slice(&tx.get_labyrinth_state(&key)?.unwrap())?;
            evidence["frame_nonce_b64"] = nonce.clone();
            tx.put_labyrinth_state(&key, &serde_json::to_vec(&evidence)?, 0)?;
            let mut row = tx
                .list_labyrinth_queue(Some(cid), 200)?
                .into_iter()
                .find(|row| row.item_id == corrupt)
                .unwrap();
            let mut payload: Value = serde_json::from_slice(&row.payload_bytes)?;
            payload["frame_nonce_b64"] = nonce;
            row.payload_bytes = serde_json::to_vec(&payload)?;
            tx.enqueue_labyrinth_item(&row)
        })
        .unwrap();
    let pending = || {
        bob.list_pending_labyrinth_queue(Some(cid), 200)
            .unwrap()
            .into_iter()
            .map(|item| item.message_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(pending().len(), 100);
    let report_key = format!("native.rescue-report:{cid}");

    ds.archive_auth.set_write_outage(true);
    bob.rescue_conversation_on_kick(cid)
        .expect_err("a write outage fails the rescue");
    assert_eq!(pending().len(), 100, "every message stays pending");
    assert!(
        labyrinth_state(bob, &report_key).is_none(),
        "none is reported skipped"
    );

    ds.archive_auth.set_write_outage(false);
    assert_eq!(bob.rescue_conversation_on_kick(cid).unwrap(), 99);
    let report: Value =
        serde_json::from_slice(&labyrinth_state(bob, &report_key).unwrap()).unwrap();
    let skipped: Vec<&str> = report["skippedEvidenceIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    assert!(
        ids.iter()
            .all(|id| skipped.contains(&id.as_str()) == (id == corrupt)),
        "{skipped:?}"
    );
    assert_eq!(pending(), vec![corrupt.to_owned()]);
}

/// `REQUIRED_LABYRINTH_OAUTH_SCOPES` as `enroll_device` takes them.
fn oauth_scopes() -> Vec<String> {
    REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Alice's live `C33` request to Bob: both enrolled, the opening published, Bob not yet synced.
struct C33Request {
    tmp: tempfile::TempDir,
    ds: Arc<SharedMockDs>,
    alice: Arc<CatbirdMlsClient>,
    bob: Arc<CatbirdMlsClient>,
    bob_dev: String,
    cid: String,
}

impl C33Request {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ds = SharedMockDs::new();
        let bob_dev = new_id();
        let alice = enrolled(&tmp, &ds, "alice", ALICE_DID, &new_id());
        let bob = enrolled(&tmp, &ds, "bob", BOB_DID, &bob_dev);
        let cid = new_id();
        alice
            .create_group(
                &cid,
                DS_DID,
                vec![BOB_DID.to_string()],
                None,
                Some("opening".into()),
            )
            .expect("alice C33 request");
        Self {
            tmp,
            ds,
            alice,
            bob,
            bob_dev,
            cid,
        }
    }

    /// Another enrolled device, of `did`, on this DS.
    fn device(&self, name: &str, did: &str, device_id: &str) -> Arc<CatbirdMlsClient> {
        enrolled(&self.tmp, &self.ds, name, did, device_id)
    }
}

fn enrolled(
    tmp: &tempfile::TempDir,
    ds: &Arc<SharedMockDs>,
    name: &str,
    did: &str,
    device_id: &str,
) -> Arc<CatbirdMlsClient> {
    let keys = Arc::new(MemKeyStore::new());
    let client = live_client(tmp.path(), ds, name, did, device_id, &keys);
    client.enroll_device(&oauth_scopes()).expect("enroll");
    client
}

/// A direct request's Welcome joins only through the checked `C33` import. mls-ds offers Bob the
/// Welcome for Alice's request before it serves him the opening entry, first relabeled as a plain
/// `welcomeView`, then as its `directRequestWelcomeView`: Bob joins nothing and acknowledges
/// nothing, as no signed `leafRecoveryFulfillmentEntry` produced that Welcome. Once the opening
/// is served, the checked import imports it as a pending request. A group Welcome then joins as
/// its signed fulfillment's Welcome, taking and acknowledging that fulfillment's signed `next`
/// while the view presents other coordinates.
///
/// Fail-before: with no local conversation and no request-KeyPackage mark, the generic importer
/// joined the request's group with no publication, outcome or `I13` receipt check and no request
/// to consent to, and acknowledged the Welcome; a joined group stored the view's coordinates.
#[test]
fn c33_direct_request_welcome_joins_only_through_the_checked_import() {
    let r = C33Request::new();
    let (ds, bob, cid) = (&r.ds, &r.bob, r.cid.as_str());
    let opening = ds
        .inner
        .lock()
        .unwrap()
        .entries
        .remove(cid)
        .expect("opening entry");
    let b = &opening[0]["signedRequest"]["body"];
    for direct in [false, true] {
        let mut view = json!({
            "welcomeId": b["requestId"], "conversationId": cid, "transitionSeq": 1,
            "coordinates": b["next"], "status": "pending",
            "opaqueWelcome": b["artifacts"]["welcome"]["opaqueWelcome"],
            "recipientDid": BOB_DID, "recipientDeviceId": r.bob_dev,
        });
        if direct {
            view["$type"] = json!("blue.catbird.chat.defs#directRequestWelcomeView");
        }
        ds.inner
            .lock()
            .unwrap()
            .pending_welcomes
            .insert((BOB_DID.to_string(), r.bob_dev.clone()), vec![view]);
        bob.sync().expect("a refused Welcome is not a sync error");
        assert!(
            bob.list_conversations(None, 20).unwrap().is_empty(),
            "joined through the generic import (directRequestWelcomeView: {direct})"
        );
        assert!(bob.list_requests(None).unwrap().is_empty());
    }
    assert!(
        ds.inner.lock().unwrap().acked_welcomes.is_empty(),
        "a direct-request Welcome is never acknowledged"
    );

    ds.inner
        .lock()
        .unwrap()
        .entries
        .insert(cid.to_string(), opening);
    bob.sync().expect("the checked import joins");
    assert_eq!(last_seq(bob, cid), 1);
    assert_eq!(bob.list_requests(Some("incomingPending")).unwrap().len(), 1);
    assert_eq!(bob.list_messages(cid, None, 20).unwrap().len(), 1);

    let gcid = new_id();
    r.alice
        .create_group(
            &gcid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Group".into()),
            None,
        )
        .expect("alice creates a group");
    bob.sync().expect("bob accepts the invitation");
    r.alice.sync().expect("alice fulfills bob's recovery");
    let signed_next = {
        let mut g = ds.inner.lock().unwrap();
        let next = g.entries[&gcid].last().unwrap()["signedRequest"]["body"]["next"].clone();
        for view in g
            .pending_welcomes
            .get_mut(&(BOB_DID.to_string(), r.bob_dev.clone()))
            .unwrap()
        {
            let version = view["coordinates"]["stateVersion"].as_i64().unwrap();
            view["coordinates"]["stateVersion"] = json!(version + 7);
        }
        chat_wire::canonicalize_wire_coordinate(&next, None).unwrap()
    };
    bob.sync()
        .expect("bob joins from the fulfillment's Welcome");
    let stored = bob
        .db()
        .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{gcid}")))
        .unwrap()
        .expect("joined coordinates");
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), signed_next);
    let acknowledged = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .rev()
        .find(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.acknowledgeWelcome"))
        .map(|(_, _, body)| serde_json::from_slice::<Value>(body).unwrap())
        .expect("acknowledged Welcome");
    assert_eq!(
        chat_wire::canonicalize_wire_coordinate(
            &acknowledged["signedRequest"]["body"]["coordinates"],
            None
        )
        .unwrap(),
        signed_next
    );
}

/// A pruned opening's parties come from its signed evidence alone: the coordinator's outcome
/// names the sender, and the account that never imported the opening is the recipient. Alice's
/// opening to Bob is pruned before any import while the inventory names other parties: to a
/// fresh device of Alice it names Eve as the recipient of Alice's own opening, to Bob it names Eve
/// as the sender. Alice's device records nothing, as nothing signed names an own opening's
/// recipient; Bob records the opening as Alice's to Bob, terminally unavailable.
///
/// Fail-before: the inventory named the parties, so Alice's fresh device recorded a terminal
/// request from Alice to Eve that nothing signed names.
#[test]
fn c33_pruned_opening_parties_come_from_its_signed_outcome() {
    let r = C33Request::new();
    let (ds, cid) = (&r.ds, r.cid.as_str());
    let request_id = {
        let mut g = ds.inner.lock().unwrap();
        let opening = &mut g.entries.get_mut(cid).unwrap()[0];
        let request_id = opening["signedRequest"]["body"]["requestId"].clone();
        let received_at = opening["publicationReceipt"]["body"]["receipt"]["recordedAt"].clone();
        let row = opening.as_object_mut().unwrap();
        row.remove("signedRequest");
        row.remove("sequencerDid");
        row.insert("payloadPruned".into(), json!(true));
        row.insert("receivedAt".into(), received_at);
        request_id.as_str().unwrap().to_string()
    };
    let inventory_names = |sender: &str, recipient: &str| {
        let mut g = ds.inner.lock().unwrap();
        let state = g.conversations.get_mut(cid).unwrap();
        state["participants"][0]["userDid"] = json!(sender);
        state["participants"][1]["userDid"] = json!(recipient);
        state["directRequest"]["senderDid"] = json!(sender);
        state["directRequest"]["recipientDid"] = json!(recipient);
    };
    // Eve is a Catbird user with a home DS.
    r.device("eve", EVE_DID, &new_id());

    inventory_names(ALICE_DID, EVE_DID);
    let alice_fresh = r.device("alice_fresh", ALICE_DID, &new_id());
    alice_fresh
        .sync()
        .expect("an own pruned opening is not a sync error");
    assert!(
        alice_fresh.list_requests(None).unwrap().is_empty(),
        "nothing signed names the recipient of an own opening"
    );
    assert!(alice_fresh.list_conversations(None, 20).unwrap().is_empty());

    inventory_names(EVE_DID, BOB_DID);
    r.bob.sync().expect("the signed outcome names the sender");
    let recorded: Vec<_> = r
        .bob
        .list_requests(None)
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                row.conversation_id,
                row.request_id,
                row.sender_did,
                row.recipient_did,
                row.consent,
            )
        })
        .collect();
    assert_eq!(
        recorded,
        [(
            cid.to_string(),
            request_id,
            ALICE_DID.to_string(),
            BOB_DID.to_string(),
            "openingUnavailable".to_string(),
        )]
    );
    assert!(r.bob.list_conversations(None, 20).unwrap().is_empty());
}

/// The signer `client` enrolled with.
fn enrolled_signer(client: &CatbirdMlsClient) -> SignatureKeyPair {
    let raw = client
        .db()
        .read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))
        .unwrap()
        .expect("enrolled signer");
    serde_json::from_str(&raw).unwrap()
}

/// A sequenced `directRequestAcceptanceEntry` takes effect only once it verifies: its exact
/// shape; a signer that is a current leaf of the local group under its PDS-authorized key; its
/// `Accept` signature; a `next` that only advances `prior.stateVersion`; the local request's
/// recipient accepting that request; and an attached coordinator receipt, if any, under the
/// method it names. Each forged, unsigned, untyped, wrong-roster, wrong-request,
/// wrong-transition or forged-receipt variant of Bob's acceptance fails Alice's sync and leaves
/// her request's consent, her coordinates and her cursor as they were. The genuine entry, here
/// with the coordinator's receipt, then advances her cursor exactly to its seq.
///
/// Fail-before: sync applied any entry labeled an acceptance: the first forged one marked
/// Alice's request accepted and moved her cursor and coordinates to its unsigned `next`.
#[test]
fn c33_acceptance_entry_takes_effect_only_once_it_verifies() {
    let r = C33Request::new();
    let (ds, alice, bob, cid) = (&r.ds, &r.alice, &r.bob, r.cid.as_str());
    bob.sync().expect("bob imports the request");
    let request_id = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0)
        .request_id;
    bob.accept_direct_request(&request_id).expect("bob accepts");
    let (at, genuine) = {
        let g = ds.inner.lock().unwrap();
        g.entries[cid]
            .iter()
            .enumerate()
            .find(|(_, e)| e["$type"] == "blue.catbird.chat.defs#directRequestAcceptanceEntry")
            .map(|(at, e)| (at, e.clone()))
            .expect("sequenced acceptance")
    };
    let seq = genuine["seq"].as_i64().unwrap();
    let serve = |entry: Value| ds.inner.lock().unwrap().entries.get_mut(cid).unwrap()[at] = entry;
    // Bob's acceptance body after `edit`, signed by `signer`.
    let resigned = |signer: &SignatureKeyPair, edit: &dyn Fn(&mut Value)| {
        let mut body = genuine["signedRequest"]["body"].clone();
        edit(&mut body);
        body["keyId"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public())));
        let wrapper =
            chat_wire::sign_direct_request_wrapper(DirectRequestKind::Accept, body, signer)
                .unwrap();
        let mut entry = genuine.clone();
        entry["signedRequest"] = serde_json::from_slice(&wrapper).unwrap();
        entry
    };
    let bob_signer = enrolled_signer(bob);
    // Bob's second device is PDS-authorized but never a leaf of this group.
    let bob2_dev = new_id();
    let bob2_signer = enrolled_signer(&r.device("bob2", BOB_DID, &bob2_dev));

    let mut forged = genuine.clone();
    forged["signedRequest"]["signature"] = json!(STANDARD.encode([7u8; 64]));
    let mut unsigned = genuine.clone();
    unsigned.as_object_mut().unwrap().remove("signedRequest");
    let mut untyped = genuine.clone();
    untyped.as_object_mut().unwrap().remove("$type");
    let mut forged_receipt = genuine.clone();
    forged_receipt["sequencerReceipt"] =
        acceptance_commit_receipt(&P256SigningKey::random(&mut rand::rngs::OsRng), &genuine);
    let variants = [
        ("forged signature", forged, "C33 acceptance entry"),
        ("unsigned", unsigned, "C33 acceptance entry"),
        ("untyped", untyped, "C33 acceptance entry: $type"),
        (
            "signed by a device outside the group",
            resigned(&bob2_signer, &|body: &mut Value| {
                body["actorDeviceId"] = json!(bob2_dev)
            }),
            "not an authorized active participant device",
        ),
        (
            "accepting another request",
            resigned(&bob_signer, &|body: &mut Value| {
                body["requestId"] = json!(new_id())
            }),
            "not the local request's recipient accepting it",
        ),
        (
            "advancing stateVersion twice",
            resigned(&bob_signer, &|body: &mut Value| {
                let version = body["next"]["stateVersion"].as_u64().unwrap();
                body["next"]["stateVersion"] = json!(version + 1);
            }),
            "must only advance",
        ),
        (
            "a receipt under a key the coordinator never published",
            forged_receipt,
            "C33 acceptance entry",
        ),
    ];
    let coords = || {
        alice
            .db()
            .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{cid}")))
            .unwrap()
    };
    let consent = || {
        alice
            .list_requests(None)
            .unwrap()
            .into_iter()
            .find(|row| row.conversation_id == cid)
            .unwrap()
            .consent
    };
    let before = coords();
    for (name, entry, reason) in variants {
        serve(entry);
        let error = alice.sync().expect_err(name).to_string();
        assert!(error.contains(reason), "{name}: {error}");
        assert_eq!(consent(), "outgoingPending", "{name}");
        assert_eq!(coords(), before, "{name}");
        assert_eq!(last_seq(alice, cid), seq - 1, "{name}");
    }

    let mut receipted = genuine.clone();
    receipted["sequencerReceipt"] =
        acceptance_commit_receipt(&ds.inner.lock().unwrap().receipt_sk, &genuine);
    serve(receipted);
    alice.sync().expect("the genuine acceptance verifies");
    assert_eq!(consent(), "accepted");
    assert_eq!(last_seq(alice, cid), seq);
    let next = chat_wire::canonicalize_wire_coordinate(
        &genuine["signedRequest"]["body"]["next"],
        Some(cid),
    )
    .unwrap();
    assert_eq!(coords(), Some(serde_json::to_string(&next).unwrap()));
}

/// Only a verified `directRequestAcceptanceEntry` accepts a direct request. A transient refusal
/// leaves Bob's acceptance journaled while mls-ds serves his signed acceptance relabeled as a
/// `participantAcceptanceEntry`, then one whose body alone claims `participantAcceptanceBody`:
/// neither verifies as a participant acceptance, so Bob's sync stops at it, his request stays
/// `incomingPending`, his acceptance journal and staged opening stay as they were, and nothing
/// is queued for the archive. Relabeling only the entry leaves a direct-request body, which
/// must then verify as one and is refused.
///
/// Fail-before: an entry labeled a participant acceptance marked Bob's request accepted, dropped
/// his acceptance journal and archived the staged opening.
#[test]
fn c33_relabeled_acceptance_never_accepts_a_direct_request() {
    const PARTICIPANT_ENTRY: &str = "blue.catbird.chat.defs#participantAcceptanceEntry";
    const PARTICIPANT_BODY: &str = "blue.catbird.chat.defs#participantAcceptanceBody";
    let r = C33Request::new();
    let (ds, bob, cid) = (&r.ds, &r.bob, r.cid.as_str());
    bob.sync().expect("bob imports the request");
    let request_id = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0)
        .request_id;
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/xrpc/blue.catbird.chat.acceptConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    assert!(bob.accept_direct_request(&request_id).is_err());
    let state = || {
        bob.db()
            .read_tx(|tx| {
                Ok((
                    tx.get_pending_op("direct_request_acceptance", &request_id)?,
                    tx.get_account_meta(&format!("c33_pending_opening:{cid}"))?,
                    tx.list_labyrinth_queue(None, 20)?.len(),
                ))
            })
            .unwrap()
    };
    let before = state();
    let journaled: Value = serde_json::from_str(before.0.as_deref().expect("journal")).unwrap();
    assert_ne!(before.1.as_deref().expect("staged opening"), "archived");
    let wrapper: Value = serde_json::from_slice(
        &STANDARD
            .decode(journaled["wrapper"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let relabeled = |entry_type: Option<&str>, body_type: &str| {
        let mut signed = wrapper.clone();
        signed["body"]["$type"] = json!(body_type);
        let mut entry = json!({
            "entryId": new_id(), "conversationId": cid, "seq": 2,
            "signedRequest": signed, "receivedAt": wrapper["body"]["signedAt"],
        });
        if let Some(entry_type) = entry_type {
            entry["$type"] = json!(entry_type);
        }
        entry
    };
    let consent = || bob.list_requests(None).unwrap().remove(0).consent;
    for (name, entry) in [
        (
            "relabeled entry and body",
            relabeled(Some(PARTICIPANT_ENTRY), PARTICIPANT_BODY),
        ),
        ("relabeled body", relabeled(None, PARTICIPANT_BODY)),
    ] {
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(cid)
            .unwrap()
            .push(entry);
        bob.sync().expect_err(name);
        assert_eq!(consent(), "incomingPending", "{name}");
        assert_eq!(state(), before, "{name}");
        assert_eq!(last_seq(bob, cid), 1, "{name}");
        ds.inner.lock().unwrap().entries.get_mut(cid).unwrap().pop();
    }

    let entry = relabeled(
        Some(PARTICIPANT_ENTRY),
        "blue.catbird.chat.defs#directRequestAcceptanceBody",
    );
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(entry);
    let error = bob
        .sync()
        .expect_err("a direct-request body must verify")
        .to_string();
    assert!(error.contains("C33 acceptance entry: $type"), "{error}");
    assert_eq!(consent(), "incomingPending");
    assert_eq!(state(), before);
}

/// `body` signed for `operation` by `signer` as the device `(did, device)`: its `signedRequest`.
fn signed_by(
    signer: &SignatureKeyPair,
    did: &str,
    device: &str,
    operation: CanonicalOperation,
    body: &Value,
) -> Value {
    let mut body = body.clone();
    body["actorDid"] = json!(did);
    body["actorDeviceId"] = json!(device);
    body["keyId"] = json!(derive_key_id(signer.public()));
    let prepared = chat_wire::sign_clean_chat_mutation(
        did,
        device,
        body["authGeneration"].as_i64(),
        operation,
        &body,
        signer,
    )
    .unwrap();
    serde_json::from_slice::<Value>(&prepared.body.unwrap()).unwrap()["signedRequest"].clone()
}

/// The one enrolled device of `did`.
fn enrolled_device(ds: &SharedMockDs, did: &str) -> String {
    let g = ds.inner.lock().unwrap();
    let mut devices = g.device_keys.keys().filter(|(owner, _)| owner == did);
    let (_, device) = devices.next().expect("an enrolled device");
    assert!(devices.next().is_none(), "one device of {did}");
    device.clone()
}

fn stored_coordinates(client: &CatbirdMlsClient, cid: &str) -> Option<String> {
    client
        .db()
        .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{cid}")))
        .unwrap()
}

/// A `participantAcceptanceEntry` takes effect only once it verifies: signed by a PDS-authorized
/// device of its actor, whose invitation (the creation or policy entry its signed provenance
/// names) verifies under exactly the inviter device and invites exactly that actor with exactly
/// that provenance, stepping only `stateVersion`. Eve's acceptance with a forged signature,
/// naming an unknown invitation or another inviter device, signed by never-invited Carol, or
/// stepping `stateVersion` twice fails Alice's sync with her cursor and coordinates unchanged;
/// the genuine one applies its signed `next`. Bob joined after the creation entry, which mls-ds
/// never serves him: there Eve's device signature and coordinate step stand alone.
///
/// Fail-before: sync moved the cursor and coordinates to any acceptance's unsigned `next`.
#[test]
fn participant_acceptance_takes_effect_only_with_its_verified_invitation() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    f.eve.sync().expect("eve accepts");
    // Only the acceptance is under test: nobody fulfills Eve's recovery.
    ds.inner.lock().unwrap().leaf_recoveries.remove(cid);
    let genuine = ds.inner.lock().unwrap().entries[cid]
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        genuine["$type"],
        "blue.catbird.chat.defs#participantAcceptanceEntry"
    );
    let seq = genuine["seq"].as_i64().unwrap();
    let serve = |entry: Value| {
        *ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(cid)
            .unwrap()
            .last_mut()
            .unwrap() = entry
    };
    let eve_dev = genuine["signedRequest"]["body"]["actorDeviceId"]
        .as_str()
        .unwrap()
        .to_owned();
    let eve_signer = enrolled_signer(&f.eve);
    let carol_dev = new_id();
    let carol_signer = enrolled_signer(&enrolled(&f.tmp, ds, "carol", CAROL_DID, &carol_dev));
    let resigned =
        |signer: &SignatureKeyPair, did: &str, device: &str, edit: &dyn Fn(&mut Value)| {
            let mut body = genuine["signedRequest"]["body"].clone();
            edit(&mut body);
            let mut entry = genuine.clone();
            entry["signedRequest"] = signed_by(
                signer,
                did,
                device,
                CanonicalOperation::AcceptConversation,
                &body,
            );
            entry
        };
    let mut forged = genuine.clone();
    forged["signedRequest"]["signature"] = json!(STANDARD.encode([7u8; 64]));
    let variants = [
        ("forged signature", forged, "verify signed transition"),
        (
            "unknown invitation",
            resigned(&eve_signer, EVE_DID, &eve_dev, &|body| {
                body["invitationProvenance"]["invitationTransitionId"] = json!(new_id())
            }),
            "invitation chain: no invitation",
        ),
        (
            "another inviter device",
            resigned(&eve_signer, EVE_DID, &eve_dev, &|body| {
                body["invitationProvenance"]["invitedByDid"] = json!(BOB_DID);
                body["invitationProvenance"]["invitedByDeviceId"] = json!(f.bob_dev);
            }),
            "verify signed transition",
        ),
        (
            "never-invited actor",
            resigned(&carol_signer, CAROL_DID, &carol_dev, &|_| {}),
            "does not invite this participant",
        ),
        (
            "stateVersion stepped twice",
            resigned(&eve_signer, EVE_DID, &eve_dev, &|body| {
                let version = body["next"]["stateVersion"].as_i64().unwrap();
                body["next"]["stateVersion"] = json!(version + 1);
            }),
            "coordinate step",
        ),
    ];
    let before = stored_coordinates(alice, cid);
    for (name, entry, reason) in variants {
        serve(entry);
        let error = alice.sync().expect_err(name).to_string();
        assert!(error.contains(reason), "{name}: {error}");
        assert_eq!(stored_coordinates(alice, cid), before, "{name}");
        assert_eq!(last_seq(alice, cid), seq - 1, "{name}");
    }

    serve(genuine.clone());
    let next = chat_wire::canonicalize_wire_coordinate(
        &genuine["signedRequest"]["body"]["next"],
        Some(cid),
    )
    .unwrap()
    .to_string();
    alice.sync().expect("the genuine acceptance verifies");
    assert_eq!(
        (last_seq(alice, cid), stored_coordinates(alice, cid)),
        (seq, Some(next.clone()))
    );

    // Bob's readable history starts at the fulfillment that added him.
    ds.inner
        .lock()
        .unwrap()
        .readable_from
        .insert(f.bob_dev.clone(), seq - 1);
    bob.sync()
        .expect("a later joiner applies the acceptance on its device signature");
    assert_eq!(
        (last_seq(bob, cid), stored_coordinates(bob, cid)),
        (seq, Some(next))
    );
}

/// A `metadataEntry` takes effect only once it verifies under its signer's current leaf, and
/// only steps `stateVersion`: with a `next` edited after signing or a swapped snapshot it fails
/// Bob's sync with his title, coordinates and cursor unchanged; the genuine entry applies its
/// signed snapshot and `next`.
///
/// Fail-before: sync wrote an unverified metadata entry's `next` and snapshot.
#[test]
fn metadata_entry_takes_effect_only_from_its_verified_body() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    alice
        .update_group_metadata(cid, "Renamed".into(), String::new(), None)
        .expect("alice renames the group");
    let (genuine, joined_snapshot) = {
        let g = ds.inner.lock().unwrap();
        let entries = &g.entries[cid];
        (
            entries.last().unwrap().clone(),
            entries[entries.len() - 2]["signedRequest"]["body"]["metadataSnapshot"].clone(),
        )
    };
    let seq = genuine["seq"].as_i64().unwrap();
    let serve = |entry: Value| {
        *ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(cid)
            .unwrap()
            .last_mut()
            .unwrap() = entry
    };
    let title = || {
        bob.get_group_metadata(cid)
            .unwrap()
            .and_then(|meta| meta.title)
    };
    let mut unsigned_next = genuine.clone();
    let version = genuine["signedRequest"]["body"]["next"]["stateVersion"]
        .as_i64()
        .unwrap();
    unsigned_next["signedRequest"]["body"]["next"]["stateVersion"] = json!(version + 5);
    let mut swapped_snapshot = genuine.clone();
    swapped_snapshot["signedRequest"]["body"]["metadataSnapshot"] = joined_snapshot;
    let before = (title(), stored_coordinates(bob, cid));
    for (name, entry) in [
        ("next edited after signing", unsigned_next),
        ("swapped snapshot", swapped_snapshot),
    ] {
        serve(entry);
        let error = bob.sync().expect_err(name).to_string();
        assert!(
            error.contains("verify signed transition"),
            "{name}: {error}"
        );
        assert_eq!((title(), stored_coordinates(bob, cid)), before, "{name}");
        assert_eq!(last_seq(bob, cid), seq - 1, "{name}");
    }

    serve(genuine.clone());
    bob.sync().expect("the genuine metadata entry verifies");
    let next = chat_wire::canonicalize_wire_coordinate(
        &genuine["signedRequest"]["body"]["next"],
        Some(cid),
    )
    .unwrap()
    .to_string();
    assert_eq!(
        (
            title().as_deref(),
            last_seq(bob, cid),
            stored_coordinates(bob, cid)
        ),
        (Some("Renamed"), seq, Some(next))
    );
}

/// A peer Commit takes effect only from its verified body. Alice's removal of Eve, served to Bob
/// as a `commitEntry` whose `next` was edited after signing, whose re-signed `next` names other
/// MLS state or skips a `stateVersion`, or which Eve re-signed as her own, fails Bob's sync with
/// his MLS epoch, coordinates and cursor unchanged. The same Commit then arrives signed as Alice's
/// `leaveCommitFulfillmentEntry`, unsigned entry `coordinates` beside it: Bob merges it and
/// writes exactly its signed `next`.
///
/// Fail-before: sync merged a Commit from an unverified body and wrote its unsigned `next`, and
/// passed a leave-commit fulfillment without processing its Commit.
#[test]
fn peer_commit_takes_effect_only_from_its_verified_body() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, bob, eve) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob, &f.eve);
    eve.sync().expect("eve accepts");
    alice.sync().expect("alice adds eve");
    eve.sync().expect("eve joins");
    bob.sync().expect("bob applies eve's addition");
    ds.inner.lock().unwrap().defer_next_commit_transition = true;
    assert!(alice
        .remove_group_member(MemberRole::Admin, cid, EVE_DID)
        .is_err());
    let removal = {
        let request = ds
            .inner
            .lock()
            .unwrap()
            .deferred_commit_transition
            .take()
            .expect("the removal Commit");
        serde_json::from_slice::<Value>(request.body.as_deref().unwrap()).unwrap()["signedRequest"]
            ["body"]
            .clone()
    };
    let seq = ds.entry_count(cid) + 1;
    let alice_signer = enrolled_signer(alice);
    let eve_dev = enrolled_device(ds, EVE_DID);
    let entry = |entry_type: &str, signed_request: Value| {
        json!({
            "$type": format!("blue.catbird.chat.defs#{entry_type}"),
            "entryId": new_id(), "conversationId": cid, "seq": seq,
            "signedRequest": signed_request,
        })
    };
    let by_alice = |edit: &dyn Fn(&mut Value)| {
        let mut body = removal.clone();
        edit(&mut body);
        signed_by(
            &alice_signer,
            ALICE_DID,
            &f.alice_dev,
            CanonicalOperation::SubmitTransition,
            &body,
        )
    };
    let mut unsigned_next = by_alice(&|_| {});
    let version = removal["next"]["stateVersion"].as_i64().unwrap();
    unsigned_next["body"]["next"]["stateVersion"] = json!(version + 5);
    let variants = [
        (
            "next edited after signing",
            unsigned_next,
            "verify signed transition",
        ),
        (
            "next naming other MLS state",
            by_alice(&|body| {
                body["next"]["confirmationTag"] = json!({ "$bytes": STANDARD.encode([0u8; 32]) })
            }),
            "coordinate does not name the local MLS state",
        ),
        (
            "next skipping a stateVersion",
            by_alice(&|body| body["next"]["stateVersion"] = json!(version + 1)),
            "next does not step stateVersion",
        ),
        (
            "signed by a leaf that is not the Commit sender",
            signed_by(
                &enrolled_signer(eve),
                EVE_DID,
                &eve_dev,
                CanonicalOperation::SubmitTransition,
                &removal,
            ),
            "MLS sender is not the signed actor device",
        ),
    ];
    let local = || {
        let row = bob
            .db()
            .read_tx(|tx| tx.get_conversation(cid))
            .unwrap()
            .unwrap();
        (row.epoch, row.last_seq, stored_coordinates(bob, cid))
    };
    let before = local();
    assert_eq!(before.1, seq - 1);
    for (name, signed_request, reason) in variants {
        ds.inner
            .lock()
            .unwrap()
            .entries
            .get_mut(cid)
            .unwrap()
            .push(entry("commitEntry", signed_request));
        let error = bob.sync().expect_err(name).to_string();
        assert!(error.contains(reason), "{name}: {error}");
        assert_eq!(local(), before, "{name}");
        ds.inner.lock().unwrap().entries.get_mut(cid).unwrap().pop();
    }

    let mut leave = entry(
        "leaveCommitFulfillmentEntry",
        by_alice(&|body| {
            body["$type"] = json!("blue.catbird.chat.defs#leaveCommitFulfillmentBody");
            body["signatureDomain"] = json!("CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0");
            body["leaveRequestId"] = json!(new_id());
        }),
    );
    let mut unsigned_coordinates = removal["next"].clone();
    unsigned_coordinates["stateVersion"] = json!(version + 9);
    leave["coordinates"] = unsigned_coordinates;
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(leave);
    bob.sync()
        .expect("the verified leave-commit fulfillment applies");
    let next = chat_wire::canonicalize_wire_coordinate(&removal["next"], Some(cid))
        .unwrap()
        .to_string();
    assert_eq!(local(), (before.0 + 1, seq, Some(next)));
    assert!(!bob
        .list_members(cid)
        .unwrap()
        .iter()
        .any(|did| did == EVE_DID));
}

/// A `resetRequestEntry` moves only the cursor, and only once a participant device signed it for
/// this conversation: Eve's, never invited here, fails Bob's sync with his cursor below it;
/// Alice's then moves his cursor and nothing else.
///
/// Fail-before: any control entry sync did not handle advanced the cursor unverified.
#[test]
fn reset_request_moves_only_the_cursor_and_only_from_a_participant() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let prior: Value = serde_json::from_str(&stored_coordinates(bob, cid).unwrap()).unwrap();
    let seq = ds.entry_count(cid) + 1;
    let request = |signer: &SignatureKeyPair, did: &str, device: &str| {
        let body = json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
            "resetRequestId": new_id(), "idempotencyKey": new_id(), "authGeneration": 1,
            "prior": prior, "reason": "manualRecovery", "signedAt": "2026-11-07T00:00:00.000Z",
        });
        json!({
            "$type": "blue.catbird.chat.defs#resetRequestEntry",
            "entryId": new_id(), "conversationId": cid, "seq": seq,
            "signedRequest": signed_by(signer, did, device, CanonicalOperation::RequestReset, &body),
        })
    };
    let before = stored_coordinates(bob, cid);
    let refused = request(
        &enrolled_signer(&f.eve),
        EVE_DID,
        &enrolled_device(ds, EVE_DID),
    );
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(refused);
    let error = bob
        .sync()
        .expect_err("a non-participant's reset request is refused")
        .to_string();
    assert!(error.contains("invitation chain: no invitation"), "{error}");
    assert_eq!(last_seq(bob, cid), seq - 1);
    let accepted = request(&enrolled_signer(alice), ALICE_DID, &f.alice_dev);
    *ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .last_mut()
        .unwrap() = accepted;
    bob.sync().expect("a participant's reset request verifies");
    assert_eq!(
        (last_seq(bob, cid), stored_coordinates(bob, cid)),
        (seq, before)
    );
}

/// A direct conversation's pending invitee may close it from any PDS-authorized device, leaf or
/// not: Bob's second device, holding no leaf of Alice's request, closes it and Alice's sync
/// applies the terminal close at its signed retired coordinate.
///
/// Fail-before: a close signer had to hold a current leaf, so Alice's sync failed at the close
/// and every later sync stalled there.
#[test]
fn pending_invitee_closes_a_direct_conversation_from_any_device() {
    let r = C33Request::new();
    let (ds, alice, cid) = (&r.ds, &r.alice, r.cid.as_str());
    let bob2_dev = new_id();
    let bob2 = r.device("bob2", BOB_DID, &bob2_dev);
    let prior: Value = serde_json::from_str(&stored_coordinates(alice, cid).unwrap()).unwrap();
    let mut retired = prior.clone();
    retired["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
    retired["lifecycle"] = json!("superseded");
    let transition = new_id();
    let close = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseBody",
        "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
        "transitionId": transition, "idempotencyKey": transition, "authGeneration": 1,
        "conversationKind": "direct", "prior": prior, "retired": retired,
        "signedAt": "2026-11-07T00:00:00.000Z",
    });
    let entry = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseEntry",
        "entryId": transition, "conversationId": cid, "seq": 2,
        "signedRequest": signed_by(
            &enrolled_signer(&bob2),
            BOB_DID,
            &bob2_dev,
            CanonicalOperation::CloseConversation,
            &close,
        ),
    });
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(entry);
    alice.sync().expect("the pending invitee's close applies");
    let closed = alice
        .db()
        .read_tx(|tx| tx.get_account_meta(&format!("conversation_closed:{cid}")))
        .unwrap();
    assert_eq!(closed.as_deref(), Some("true"));
}

/// A `C33` opening another device of this account published imports on its sibling as this
/// account's outgoing request: sender and recipient as signed, nothing unread, the opening its
/// sender's own message and not this device's archive duty. The peer's acceptance then verifies
/// here and archives nothing.
///
/// Fail-before: the import fetched only the sender's and this account's device keys, so `I4`
/// refused the recipient's leaf and the sibling's sync failed.
#[test]
fn sibling_device_imports_its_accounts_opening_as_outgoing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "alice", ALICE_DID, &new_id());
    let alice2 = enrolled(&tmp, &ds, "alice2", ALICE_DID, &new_id());
    let bob = enrolled(&tmp, &ds, "bob", BOB_DID, &new_id());
    ds.inner.lock().unwrap().select_sender_siblings = true;
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("opening".into()),
        )
        .expect("alice's request");
    alice2.sync().expect("alice2 imports her account's opening");
    let request = alice2.list_requests(None).unwrap().remove(0);
    assert_eq!(
        (
            request.sender_did.as_str(),
            request.recipient_did.as_str(),
            request.consent.as_str(),
        ),
        (ALICE_DID, BOB_DID, "outgoingPending")
    );
    let convo = alice2
        .list_conversations(None, 20)
        .unwrap()
        .into_iter()
        .find(|row| row.conversation_id == cid)
        .expect("joined");
    assert_eq!(convo.unread_count, 0);
    let messages = alice2.list_messages(&cid, None, 20).unwrap();
    assert!(messages.len() == 1 && messages[0].is_own);
    let archive_duty = || {
        alice2
            .db()
            .read_tx(|tx| {
                Ok((
                    tx.get_account_meta(&format!("c33_pending_opening:{cid}"))?,
                    tx.list_labyrinth_queue(None, 20)?.len(),
                ))
            })
            .unwrap()
    };
    assert_eq!(archive_duty(), (None, 0));

    bob.sync().expect("bob imports the request");
    let request_id = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0)
        .request_id;
    bob.accept_direct_request(&request_id).expect("bob accepts");
    alice2.sync().expect("bob's acceptance verifies on alice2");
    assert_eq!(alice2.list_requests(None).unwrap()[0].consent, "accepted");
    assert_eq!(archive_duty(), (None, 0));
}

/// Contract B for this device's own leaf-recovery fulfillment: nothing moves until the
/// `submitTransition` answer carries exactly the signed fulfillment this device sent. mls-ds
/// sequences Alice's fulfillment of Bob's recovery request but answers with another signed
/// request: Alice's sync fails, her cursor, epoch and coordinates stay put and her journaled
/// Commit stays pending. Her next sync applies the own sequenced echo from `getEntries`, which
/// moves all three to the signed `next`, and Bob joins from the Welcome.
///
/// Fail-before: any 2xx answer merged the Commit and moved Alice's cursor and coordinates.
#[test]
fn own_leaf_recovery_fulfillment_moves_nothing_on_a_forged_answer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "alice", ALICE_DID, &new_id());
    let bob = enrolled(&tmp, &ds, "bob", BOB_DID, &new_id());
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Recovery".into()),
            Some("group".into()),
        )
        .expect("alice creates the group");
    bob.sync().expect("bob accepts the invitation");
    // mls-ds lists Bob's recovery request only once Alice has applied his acceptance.
    let recoveries = ds
        .inner
        .lock()
        .unwrap()
        .leaf_recoveries
        .remove(&cid)
        .expect("bob's recovery request");
    alice.sync().expect("alice applies bob's acceptance");
    ds.inner
        .lock()
        .unwrap()
        .leaf_recoveries
        .insert(cid.clone(), recoveries);
    let local = || {
        alice
            .db()
            .read_tx(|tx| {
                let row = tx.get_conversation(&cid)?.unwrap();
                let coords = tx.get_account_meta(&format!("conversation_coords:{cid}"))?;
                let journals: i64 = tx
                    .conn()
                    .query_row(
                        "SELECT count(*) FROM pending_ops WHERE op_kind = 'commit_transition'",
                        [],
                        |count| count.get(0),
                    )
                    .unwrap();
                Ok((row.last_seq, row.epoch, coords, journals))
            })
            .unwrap()
    };
    let (seq, epoch, coords, journals) = local();
    assert_eq!(journals, 0);

    ds.inner.lock().unwrap().forge_next_transition_answer = Some("entry");
    let refused = alice.sync();
    assert_eq!(local(), (seq, epoch, coords.clone(), 1), "nothing moved");
    let error = refused
        .expect_err("an answer carrying another signed request is refused")
        .to_string();
    assert!(
        error.contains("not this device's signed request"),
        "{error}"
    );

    alice
        .sync()
        .expect("sync applies the own sequenced fulfillment");
    let (seq_after, epoch_after, coords_after, journals_after) = local();
    assert_eq!(
        (seq_after, epoch_after, journals_after),
        (seq + 1, epoch + 1, 0)
    );
    let coords_after: Value = serde_json::from_str(&coords_after.unwrap()).unwrap();
    let coords: Value = serde_json::from_str(&coords.unwrap()).unwrap();
    assert_eq!(coords_after["epoch"], epoch_after);
    assert_eq!(
        coords_after["stateVersion"].as_i64(),
        coords["stateVersion"].as_i64().map(|version| version + 1)
    );
    bob.sync().expect("bob joins from the Welcome");
    assert!(bob
        .list_conversations(None, 20)
        .unwrap()
        .iter()
        .any(|row| row.conversation_id == cid));
}

/// Alice's open group `cid` (with Bob), synced to the DS head.
fn open_group_for_close(
    tmp: &tempfile::TempDir,
    ds: &Arc<SharedMockDs>,
) -> (Arc<CatbirdMlsClient>, String) {
    let alice = enrolled(tmp, ds, "alice", ALICE_DID, &new_id());
    let _bob = enrolled(tmp, ds, "bob", BOB_DID, &new_id());
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Close".into()),
            Some("group".into()),
        )
        .expect("alice creates the group");
    alice.sync().expect("alice syncs");
    (alice, cid)
}

/// `(closed marker, cursor, coordinates, journaled closes)` of `cid` on `client`.
fn close_state(client: &CatbirdMlsClient, cid: &str) -> (bool, i64, Value, i64) {
    client
        .db()
        .read_tx(|tx| {
            let closed = tx
                .get_account_meta(&format!("conversation_closed:{cid}"))?
                .is_some();
            let seq = tx.get_conversation(cid)?.unwrap().last_seq;
            let coords = tx
                .get_account_meta(&format!("conversation_coords:{cid}"))?
                .map_or(Value::Null, |raw| serde_json::from_str(&raw).unwrap());
            let journals: i64 = tx
                .conn()
                .query_row(
                    "SELECT count(*) FROM pending_ops \
                     WHERE op_kind = 'conversation_close' AND op_key = ?1",
                    [cid],
                    |row| row.get(0),
                )
                .unwrap();
            Ok((closed, seq, coords, journals))
        })
        .unwrap()
}

/// Every `closeConversation` request body the DS received, in order.
fn close_requests(ds: &SharedMockDs) -> Vec<Vec<u8>> {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.closeConversation"))
        .map(|(_, _, body)| body.clone())
        .collect()
}

/// The close took effect exactly once from `before`: marker set, coordinate retired one step,
/// cursor onto the contiguous terminal seq, journal erased, and every request the same bytes.
fn assert_closed_by_exact_replay(
    alice: &CatbirdMlsClient,
    ds: &SharedMockDs,
    cid: &str,
    before: &(bool, i64, Value, i64),
) {
    let (closed, seq, coords, journals) = close_state(alice, cid);
    assert!(closed, "the replayed close is applied");
    assert_eq!((seq, journals), (before.1 + 1, 0));
    assert_eq!(coords["lifecycle"], "superseded");
    assert_eq!(
        coords["stateVersion"].as_i64(),
        before.2["stateVersion"].as_i64().map(|version| version + 1)
    );
    let requests = close_requests(ds);
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0], requests[1],
        "the replay sends the identical signed bytes"
    );
}

/// mls-ds sequences Alice's close and wipes the conversation (no echo will ever arrive), but the
/// response is lost. Nothing is applied; her next sync replays the journaled signed close byte
/// for byte, mls-ds answers its recorded result, and the verified answer closes the
/// conversation with the cursor on the contiguous terminal seq.
///
/// Fail-before: nothing was journaled, so the conversation stayed open across syncs (and a retry
/// signed a different close, which mls-ds refuses).
#[test]
fn lost_close_response_is_completed_by_exact_replay_on_sync() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let (alice, cid) = open_group_for_close(&tmp, &ds);
    let before = close_state(&alice, &cid);
    assert!(!before.0);

    ds.inner.lock().unwrap().lose_next_close_response = true;
    alice
        .close_conversation(&cid)
        .expect_err("the close response is lost");
    let (closed, seq, coords, _) = close_state(&alice, &cid);
    assert_eq!(
        (closed, seq, &coords),
        (false, before.1, &before.2),
        "nothing applied"
    );
    assert!(
        !ds.inner.lock().unwrap().entries.contains_key(&cid),
        "mls-ds sequenced the close and wiped the conversation"
    );

    alice.sync().expect("sync replays the journaled close");
    assert_closed_by_exact_replay(&alice, &ds, &cid, &before);
}

/// mls-ds sequences Alice's close but answers with an entry carrying another signed request.
/// The answer is refused: nothing is applied and the signed close stays journaled. Her retry
/// replays exactly those bytes, mls-ds answers its recorded result, and the close applies.
///
/// Fail-before: the refused close left no journal, and the retry signed a different close,
/// which mls-ds refuses, so the conversation could never close.
#[test]
fn forged_close_answer_keeps_the_journal_and_the_replay_closes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let (alice, cid) = open_group_for_close(&tmp, &ds);
    let before = close_state(&alice, &cid);

    ds.inner.lock().unwrap().forge_next_close_answer = true;
    let error = alice
        .close_conversation(&cid)
        .expect_err("an answer carrying another signed request is refused")
        .to_string();
    assert!(
        error.contains("not this device's signed request"),
        "{error}"
    );
    assert_eq!(
        close_state(&alice, &cid),
        (false, before.1, before.2.clone(), 1),
        "nothing applied; the signed close stays journaled"
    );

    alice
        .close_conversation(&cid)
        .expect("the retry replays the journaled close");
    assert_closed_by_exact_replay(&alice, &ds, &cid, &before);
}
