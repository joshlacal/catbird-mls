//! Deep live data-plane & sync engine tests for `CatbirdMlsClient` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`, `C33`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use catbird_mls::canonical_transport::{derive_key_id, CanonicalOperation};
use catbird_mls::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use catbird_mls::chat_v2::transcript::SignedMutationKind;
use catbird_mls::client::chat_wire;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::signature::Signer as _;

#[path = "client_live_chat_data_plane/archive_established.rs"]
mod archive_established;
#[path = "client_live_chat_data_plane/archive_policy.rs"]
mod archive_policy;
#[path = "client_live_chat_data_plane/delete_scrub.rs"]
mod delete_scrub;
#[path = "fixtures/direct_request_i13.rs"]
mod direct_request_i13;
#[path = "client_live_chat_data_plane/idle_flush.rs"]
mod idle_flush;
#[path = "client_live_chat_data_plane/leaf_recovery_signed.rs"]
mod leaf_recovery_signed;
#[allow(dead_code)]
#[path = "support/native_archive_auth.rs"]
mod native_archive_auth;
#[path = "client_live_chat_data_plane/reset_activation.rs"]
mod reset_activation;
#[path = "client_live_chat_data_plane/verified_roster.rs"]
mod verified_roster;
#[path = "client_live_chat_data_plane/wave2_unified.rs"]
mod wave2_unified;
use native_archive_auth::NativeArchiveAuthFixture;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use catbird_mls::client::{
    account_did_hash_hex, CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpHeader,
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
    REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::groups::lifecycle::MemberRole;
use catbird_mls::push::{
    process_push_notification, AuthorizedPeerDeviceKey, FetchedPushEntry, PushFetchBundle,
    PushFetchTransport, PushKeystore, PushWakePayload,
};
use catbird_mls::MLSError;
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};

const DS_DID: &str = "did:web:ds.catbird.blue";
const DS_URL: &str = "https://ds.catbird.blue";
/// Another home DS: it relays the Space requests of conversations `DS_DID` sequences.
const CROSS_HOME_DS_DID: &str = "did:web:home-b.catbird.blue";
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

struct NsePushKeystore(Arc<MemKeyStore>);

impl PushKeystore for NsePushKeystore {
    fn load_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        self.0
            .map
            .lock()
            .unwrap()
            .get(&format!("db:{account_did_hash}"))
            .cloned()
            .ok_or_else(|| MLSError::Internal("push test DB key missing".into()))
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.map.lock().unwrap().get(&key_id).cloned())
    }

    fn load_cached_chat_dpop_token(
        &self,
        _account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(Some("cached-push-test-token".into()))
    }
}

struct MockDsState {
    receipt_sk: P256SigningKey,
    // Retained receipt generation 2; generation 1 remains `receipt_sk`.
    historical_receipt_sk: Option<P256SigningKey>,
    rotated_outcome_sk: Option<P256SigningKey>,
    rotate_outcome_key_on_next_publish: bool,
    tamper_next_publication_coordinates: bool,
    after_next_publish: Option<Arc<dyn Fn() + Send + Sync>>,
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
    refuse_next_pds_directory_for: Option<String>,
    transport_error_next_resolve_for: Option<String>,
    transport_error_next_pds_directory_for: Option<String>,
    malformed_next_pds_directory_for: Option<String>,
    // Direct request published keys: actor_did -> (device_id, key_package_val, grant_val)
    dr_keys: BTreeMap<String, Vec<(String, Value, Value)>>,
    // Conversation KPs: (actor_did, device_id) -> Vec<Value>
    convo_kps: BTreeMap<(String, String), Vec<Value>>,
    // Conversations: cid -> state JSON
    conversations: BTreeMap<String, Value>,
    // Return the same continuation cursor after the first inventory page.
    repeat_conversation_cursor: bool,
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
    // Apply the next `createConversation`, then lose its response.
    lose_next_create_response: bool,
    // Completed create by conversation: exact request bytes and recorded byte-identical answer.
    creates: BTreeMap<String, (Vec<u8>, Value)>,
    // Signed `getConversationState.accountDeletions`: cid -> `#accountDeletedEntry`s.
    account_deletions: BTreeMap<String, Vec<Value>>,
    // Persistent authenticated state denials: (session DID, conversation) -> (status, code).
    conversation_state_errors: BTreeMap<(String, String), (u16, String)>,
    // Every request as (session account, URL, body), for exact-replay and no-network checks.
    http_log: Vec<(String, String, Vec<u8>)>,
    // One-shot XRPC refusals: (route suffix, status, error code, `Retry-After`).
    hosted_erasure_reply: Option<(u16, Value)>,
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
    // Refuse the next otherwise-valid acceptance answer as either a missing outer I13 receipt or
    // an invalid legacy acceptance proof; neither fault is sequenced.
    next_acceptance_fault: Option<&'static str>,
    // Sign only the next group acceptance receipt as another sequencer.
    next_group_acceptance_receipt_sequencer: Option<String>,
    // Return this older genuine entry beside the next acceptance's fresh recovery view.
    next_group_acceptance_answer_entry: Option<Value>,
    // Sequence the next `submitTransition` but forge its answer: "entry" carries another
    // signed request, "coordinates" are not the signed `next`.
    forge_next_transition_answer: Option<&'static str>,
    // Forge the I13 receipt only in the next policy-transition answer.
    forge_next_policy_answer_receipt: bool,
    // `getEntries` serves `actorDeviceId` only entries from this seq on: the device joined there,
    // and mls-ds never makes a device a recipient of control entries sequenced before it joined.
    readable_from: BTreeMap<String, i64>,
    // `getEntries` serves `actorDeviceId` only entries up to this seq and refuses any read past it
    // (`AccessOutsideMembershipInterval`): a reset closed the device's membership interval there.
    readable_until: BTreeMap<String, i64>,
    // `prepareDirectRequest` also selects a request key of another of the actor's devices: mls-ds
    // makes the sender's other devices Welcome recipients of its opening.
    select_sender_siblings: bool,
    // Sequence the next `closeConversation` (and wipe it), then lose its response.
    lose_next_close_response: bool,
    // Sequence the next `closeConversation` but answer with an entry carrying another request.
    forge_next_close_answer: bool,
    // Forge the I13 receipt only in the next exact replayed close answer.
    forge_next_close_replay_receipt: bool,
    // Closed conversation -> (exact request bytes, recorded answer): mls-ds answers an exact
    // replay with the recorded result and refuses any other close.
    closes: BTreeMap<String, (Vec<u8>, Value)>,
    // Reset requests by conversation: `#resetRequestView`s, at most one `pending`.
    reset_requests: BTreeMap<String, Vec<Value>>,
    // Sequence the next `activateReset`, then lose its response.
    lose_next_reset_response: bool,
    // Forge the I13 receipt only in the next reset-activation answer.
    forge_next_reset_activation_receipt: bool,
    // Corrupt only the next successful `requestReset` answer: "missingReceipt" or
    // "forgedReceipt". The stored entry remains the genuine sequenced row.
    next_reset_request_fault: Option<&'static str>,
    // Advertise an own pending request and matching `getEntries` row that were never sequenced.
    fake_pending_reset_seq: Option<i64>,
    // Wave 2 opt-in controls: second-device pending_approval, per-device status/revokedAt, and durable leave requests.
    enroll_second_device_pending: bool,
    device_statuses: BTreeMap<(String, String), String>,
    pending_epoch_publication_rejections: usize,
    aged_pending_notices: BTreeSet<(String, String)>,
    dormant_devices: BTreeSet<(String, String)>,
    revoked_device_at: BTreeMap<(String, String), String>,
    leave_requests: BTreeMap<String, Vec<Value>>,
    pds_repo_status_for: BTreeMap<String, (u16, String)>,
    mock_clock_ms: Option<i64>,
}

struct SharedMockDs {
    inner: Mutex<MockDsState>,
    archive_auth: NativeArchiveAuthFixture,
}

impl SharedMockDs {
    fn new() -> Arc<Self> {
        Self::new_with_now_fn(Arc::new(|| chrono::Utc::now().timestamp_millis()))
    }

    fn new_with_now_fn(now_fn: Arc<dyn Fn() -> i64 + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(MockDsState {
                receipt_sk: P256SigningKey::random(&mut rand::rngs::OsRng),
                historical_receipt_sk: None,
                rotated_outcome_sk: None,
                rotate_outcome_key_on_next_publish: false,
                tamper_next_publication_coordinates: false,
                after_next_publish: None,
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
                refuse_next_pds_directory_for: None,
                transport_error_next_resolve_for: None,
                transport_error_next_pds_directory_for: None,
                malformed_next_pds_directory_for: None,
                dr_keys: BTreeMap::new(),
                convo_kps: BTreeMap::new(),
                conversations: BTreeMap::new(),
                repeat_conversation_cursor: false,
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
                lose_next_create_response: false,
                creates: BTreeMap::new(),
                account_deletions: BTreeMap::new(),
                conversation_state_errors: BTreeMap::new(),
                http_log: Vec::new(),
                hosted_erasure_reply: None,
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
                next_acceptance_fault: None,
                next_group_acceptance_receipt_sequencer: None,
                next_group_acceptance_answer_entry: None,
                forge_next_transition_answer: None,
                forge_next_policy_answer_receipt: false,
                readable_from: BTreeMap::new(),
                readable_until: BTreeMap::new(),
                select_sender_siblings: false,
                lose_next_close_response: false,
                forge_next_close_answer: false,
                forge_next_close_replay_receipt: false,
                closes: BTreeMap::new(),
                reset_requests: BTreeMap::new(),
                lose_next_reset_response: false,
                forge_next_reset_activation_receipt: false,
                next_reset_request_fault: None,
                fake_pending_reset_seq: None,
                enroll_second_device_pending: false,
                device_statuses: BTreeMap::new(),
                pending_epoch_publication_rejections: 0,
                aged_pending_notices: BTreeSet::new(),
                dormant_devices: BTreeSet::new(),
                revoked_device_at: BTreeMap::new(),
                leave_requests: BTreeMap::new(),
                pds_repo_status_for: BTreeMap::new(),
                mock_clock_ms: None,
            }),
            archive_auth: NativeArchiveAuthFixture::new(ALICE_DID, now_fn),
        })
    }

    fn receipt_did_doc_for(&self, authority_did: &str) -> Value {
        let g = self.inner.lock().unwrap();
        let method = dr_transcript::direct_request_receipt_key_id_for_authority(
            authority_did,
            g.receipt_sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        let mut document: Value = serde_json::from_slice(&direct_request_i13::authority_document(
            &g.receipt_sk,
            &method,
            authority_did,
        ))
        .unwrap();
        if authority_did == DS_DID {
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
        }
        document
    }

    fn receipt_did_doc(&self) -> Value {
        self.receipt_did_doc_for(DS_DID)
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

        if url.ends_with("/.well-known/did.json") {
            return ok_json(self.receipt_did_doc());
        }
        if let Some(raw_did) = url.strip_prefix("https://plc.directory/") {
            let did = raw_did.split('?').next().unwrap_or(raw_did).to_string();
            {
                let mut state = self.inner.lock().unwrap();
                if state.transport_error_next_resolve_for.as_deref() == Some(did.as_str()) {
                    state.transport_error_next_resolve_for = None;
                    return Err(MLSError::Internal(
                        "injected DID resolution transport error".into(),
                    ));
                }
            }
            return ok_json(json!({
                "id": did,
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": PDS_URL
                }]
            }));
        }
        if url.contains("/xrpc/com.atproto.identity.resolveDid") {
            let did = q.get("did").cloned().unwrap_or_default();
            let mut state = self.inner.lock().unwrap();
            if state.transport_error_next_resolve_for.as_deref() == Some(did.as_str()) {
                state.transport_error_next_resolve_for = None;
                return Err(MLSError::Internal(
                    "injected DID resolution transport error".into(),
                ));
            }
        }

        if url.contains("/xrpc/com.atproto.identity.resolveDid")
            && q.get("did")
                .is_some_and(|did| matches!(did.as_str(), DS_DID | CROSS_HOME_DS_DID))
        {
            return ok_json(self.receipt_did_doc_for(q.get("did").unwrap()));
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

        if url.contains("/xrpc/com.atproto.repo.createRecord") {
            let repo = body_json["repo"].as_str().unwrap_or_default().to_string();
            let coll = body_json["collection"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let rkey = body_json["rkey"].as_str().unwrap_or_default().to_string();
            if g.pds_records
                .contains_key(&(repo.clone(), coll.clone(), rkey.clone()))
            {
                return xrpc_error(400, "InvalidRequest", "record already exists");
            }
            let rec = body_json["record"].clone();
            g.pds_records
                .insert((repo.clone(), coll.clone(), rkey.clone()), rec);
            return ok_json(json!({
                "uri": format!("at://{repo}/{coll}/{rkey}"),
                "cid": "bafyreimock"
            }));
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

        if url.contains("/xrpc/com.atproto.repo.deleteRecord") {
            let repo = body_json["repo"].as_str().unwrap_or_default().to_string();
            let coll = body_json["collection"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let rkey = body_json["rkey"].as_str().unwrap_or_default().to_string();
            g.pds_records.remove(&(repo, coll, rkey));
            return ok_json(json!({}));
        }

        if url.contains("/xrpc/com.atproto.repo.listRecords")
            && g.transport_error_next_pds_directory_for.as_deref()
                == q.get("repo").map(String::as_str)
        {
            g.transport_error_next_pds_directory_for = None;
            return Err(MLSError::Internal(
                "injected PDS directory transport error".into(),
            ));
        }
        if url.contains("/xrpc/com.atproto.repo.listRecords")
            && g.malformed_next_pds_directory_for.as_deref() == q.get("repo").map(String::as_str)
        {
            g.malformed_next_pds_directory_for = None;
            return ok_json(json!({ "records": "not-an-array" }));
        }

        if url.contains("/xrpc/com.atproto.repo.listRecords")
            && g.refuse_next_pds_directory_for.as_deref() == q.get("repo").map(String::as_str)
        {
            g.refuse_next_pds_directory_for = None;
            return xrpc_error(503, "CapacityUnavailable", "injected PDS refusal");
        }

        if url.contains("/xrpc/com.atproto.repo.listRecords") {
            let repo = q.get("repo").cloned().unwrap_or_default();
            if let Some((status, code)) = g.pds_repo_status_for.get(&repo) {
                return xrpc_error(*status, code, "mock PDS repo status");
            }
            let coll = q.get("collection").cloned().unwrap_or_default();
            let limit = q
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(100)
                .max(1);
            let offset = q
                .get("cursor")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let all_records: Vec<Value> = g
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
            let page: Vec<Value> = all_records
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect();
            let next_offset = offset + page.len();
            if next_offset < all_records.len() && !page.is_empty() {
                return ok_json(json!({
                    "records": page,
                    "cursor": next_offset.to_string(),
                }));
            }
            return ok_json(json!({ "records": page }));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.getRecoveryShareCapabilities") {
            if let Err(message) = verify_read(
                &g,
                account,
                &req,
                "blue.catbird.labyrinth.getRecoveryShareCapabilities",
                false,
            ) {
                return xrpc_error(401, "InvalidSignature", message);
            }
            return ok_json(json!({
                "supported": true,
                "version": 1,
                "hpkeSuite": "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
                "keyId": "mock-recovery-share-kek-1"
            }));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.deleteRecoveryShare") {
            use catbird_mls::labyrinth::write_auth::{WRITE_BODY_HEADER, WRITE_DOMAIN};
            let nsid = "blue.catbird.labyrinth.deleteRecoveryShare";
            let write = match device_signed_claim(
                &g,
                account,
                &req,
                WRITE_BODY_HEADER,
                "actorDeviceId",
                WRITE_DOMAIN,
            ) {
                Ok((write, _)) => write,
                Err(message) => return xrpc_error(401, "InvalidSignature", message),
            };
            let payload_sha256 =
                hex::encode(Sha256::digest(req.body.as_deref().unwrap_or_default()));
            let valid_vid = body_json
                .pointer("/vdeviceId/$bytes")
                .and_then(Value::as_str)
                .and_then(|value| {
                    STANDARD_NO_PAD
                        .decode(value)
                        .or_else(|_| STANDARD.decode(value))
                        .ok()
                })
                .is_some_and(|value| value.len() == 16);
            if write["endpointNsid"] != nsid
                || write["payloadSha256"] != payload_sha256
                || !valid_vid
            {
                return xrpc_error(
                    400,
                    "InvalidRequest",
                    "deleteRecoveryShare is not bound to one virtual device",
                );
            }
            // Candidate writes only version-2 recovery methods, so no remote
            // share exists. The protocol's exact absent-share result is 404.
            return xrpc_error(404, "RecoveryShareNotFound", "share does not exist");
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
            let repo_did = q.get("repo").cloned().unwrap_or_default();
            if let Some((status, code)) = g.pds_repo_status_for.get(&repo_did) {
                return xrpc_error(*status, code, "mock PDS repo status");
            }
            let key = (
                repo_did,
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
            let caller_dev = write["actorDeviceId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let caller = (account.to_owned(), caller_dev.clone());
            let caller_pending =
                g.device_statuses.get(&caller).map(String::as_str) == Some("pending_approval");
            if caller_pending {
                let notice_aged = g.aged_pending_notices.contains(&caller);
                let has_awake_active_sibling =
                    g.device_statuses.iter().any(|((did, device_id), status)| {
                        did == account
                            && device_id != &caller_dev
                            && status == "active"
                            && !g
                                .dormant_devices
                                .contains(&(did.clone(), device_id.clone()))
                    });
                if !notice_aged || has_awake_active_sibling {
                    g.pending_epoch_publication_rejections += 1;
                    return xrpc_error(
                        401,
                        "NotAuthorized",
                        "pending device must wait for the recovery notice hold and dormant siblings",
                    );
                }
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
            if caller_pending {
                g.device_statuses.insert(caller, "active".into());
            }
            return ok_json(json!({}));
        }

        if url.contains("/xrpc/blue.catbird.labyrinth.deleteAccountData") {
            use catbird_mls::labyrinth::write_auth::{
                REVOCATION_PROOF_HEADER, WRITE_BODY_HEADER, WRITE_DOMAIN,
            };
            let nsid = "blue.catbird.labyrinth.deleteAccountData";
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
            if req.headers.iter().any(|header| {
                header
                    .name
                    .eq_ignore_ascii_case("Catbird-Require-Erasure-Completion")
                    && header.value == "1"
            }) {
                if let Some((status, value)) = &g.hosted_erasure_reply {
                    let mut response = ok_json(value.clone())?;
                    response.status = *status;
                    return Ok(response);
                }
            }
            let key_proof = device_key_proof(
                &self.archive_auth,
                account,
                write["actorDeviceId"].as_str().unwrap_or_default(),
                &device_key,
            );
            let revocation_proof = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(REVOCATION_PROOF_HEADER))
                .and_then(|h| URL_SAFE_NO_PAD.decode(&h.value).ok())
                .filter(|b| !b.is_empty());
            let payload_sha256 =
                hex::encode(Sha256::digest(req.body.as_deref().unwrap_or_default()));
            if write["endpointNsid"] != nsid || write["payloadSha256"] != payload_sha256 {
                return xrpc_error(
                    400,
                    "InvalidRequest",
                    "write body does not bind this payload",
                );
            }
            if let Some(mock_now_ms) = g.mock_clock_ms {
                let signed_at_ms = write["signedAt"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.timestamp_millis())
                    .unwrap_or(i64::MIN);
                if (signed_at_ms - mock_now_ms).abs() > 300_000 {
                    return xrpc_error(
                        401,
                        "WriteSkew",
                        "mock deleteAccountData signedAt outside 300s skew window",
                    );
                }
            }
            let actor_write = {
                let header = |name: &str| {
                    req.headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case(name))
                        .and_then(|h| URL_SAFE_NO_PAD.decode(&h.value).ok())
                        .unwrap_or_default()
                };
                json!({
                    "writeBody": { "$bytes": STANDARD.encode(header(WRITE_BODY_HEADER)) },
                    "payloadBytes": { "$bytes": STANDARD.encode(req.body.as_deref().unwrap_or_default()) },
                    "signature": {
                        "$bytes": STANDARD.encode(header(&format!("{WRITE_BODY_HEADER}-signature")))
                    },
                })
            };
            g.labyrinth_epochs.remove(account);
            let receipt_key_id = labyrinth_protocol::receipt::expected_receipt_key_id(DS_DID);
            let affected_cids: Vec<String> = g
                .conversations
                .iter()
                .filter(|(_, st)| {
                    st["participants"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|p| p["userDid"].as_str() == Some(account))
                })
                .map(|(cid, _)| cid.clone())
                .collect();
            for cid in affected_cids {
                let next_seq = g.entries.get(&cid).map_or(0, Vec::len) as i64 + 1;
                let mut del_entry = signed_account_deletion_at(
                    &g.receipt_sk,
                    &receipt_key_id,
                    DS_DID,
                    &cid,
                    account,
                    next_seq,
                    g.mock_clock_ms,
                );
                del_entry["actorWrite"] = actor_write.clone();
                del_entry["keyProof"] = json!({ "$bytes": STANDARD.encode(&key_proof) });
                if let Some(ref rev_proof) = revocation_proof {
                    del_entry["revocationProof"] = json!({ "$bytes": STANDARD.encode(rev_proof) });
                }
                g.entries
                    .entry(cid.clone())
                    .or_default()
                    .push(del_entry.clone());
                g.account_deletions.entry(cid).or_default().push(del_entry);
            }
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
                .map(|((owner, dev), key)| {
                    let mut item = json!({
                        "keyId": derive_key_id(key),
                        "signingPublicKey": { "$bytes": STANDARD.encode(key) },
                    });
                    if let Some(rev_ts) = g.revoked_device_at.get(&(owner.clone(), dev.clone())) {
                        item["revokedAt"] = json!(rev_ts);
                    }
                    item
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
            let already_has_device = g.device_keys.keys().any(|(owner, _)| owner == &did);
            let enroll_status = if g.enroll_second_device_pending && already_has_device {
                "pending_approval"
            } else {
                "active"
            };
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            let key: [u8; 32] = chat_wire::json_bytes(&b["signaturePublicKey"])
                .unwrap()
                .try_into()
                .unwrap();
            g.device_keys.insert((did.clone(), dev.clone()), key);
            g.device_statuses
                .insert((did.clone(), dev.clone()), enroll_status.to_string());
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
                "status": enroll_status,
                "createdAt": "2026-11-03T00:00:00.000Z",
                "updatedAt": "2026-11-03T00:00:00.000Z",
                "availablePackageCount": 2,
                "reservedPackageCount": 0,
            }}));
        }

        if url.contains("/xrpc/blue.catbird.chat.approveDevice") {
            let sr = &body_json["signedRequest"];
            let b = &sr["body"];
            let actor_did = b["actorDid"].as_str().unwrap_or_default().to_string();
            let actor_dev = b["actorDeviceId"].as_str().unwrap_or_default().to_string();
            if actor_did != account {
                return xrpc_error(403, "NotAuthorized", "actorDid is not the session account");
            }
            if g.device_statuses
                .get(&(actor_did.clone(), actor_dev.clone()))
                .map(String::as_str)
                .unwrap_or("active")
                != "active"
            {
                return xrpc_error(403, "DeviceNotActive", "approver device must be active");
            }
            let Some(actor_key) = g.device_keys.get(&(actor_did.clone(), actor_dev)).copied()
            else {
                return xrpc_error(401, "UnknownDevice", "approver device is not enrolled");
            };
            if chat_wire::verify_signed_mutation_body_and_digest(
                sr,
                SignedMutationKind::DeviceApproval,
                &actor_key,
            )
            .is_err()
            {
                return xrpc_error(401, "InvalidSignature", "invalid device approval signature");
            }
            let target_dev = b["targetDeviceId"].as_str().unwrap_or_default().to_string();
            let Some(target_key) = g
                .device_keys
                .get(&(actor_did.clone(), target_dev.clone()))
                .copied()
            else {
                return xrpc_error(404, "DeviceNotFound", "target device not enrolled");
            };
            let target_pub =
                chat_wire::json_bytes(&b["targetSignaturePublicKey"]).unwrap_or_default();
            if target_pub.as_slice() != target_key.as_slice()
                || b["targetKeyId"].as_str() != Some(derive_key_id(&target_key).as_str())
            {
                return xrpc_error(409, "TargetKeyMismatch", "target device key mismatch");
            }
            g.device_statuses
                .insert((actor_did, target_dev), "active".into());
            return ok_json(json!({ "approved": true }));
        }

        if url.contains("/xrpc/blue.catbird.chat.revokeDevice") {
            let sr = &body_json["signedRequest"];
            let b = &sr["body"];
            let actor_did = b["actorDid"].as_str().unwrap_or_default().to_string();
            let actor_dev = b["actorDeviceId"].as_str().unwrap_or_default().to_string();
            if actor_did != account {
                return xrpc_error(403, "NotAuthorized", "actorDid is not the session account");
            }
            if g.device_statuses
                .get(&(actor_did.clone(), actor_dev.clone()))
                .map(String::as_str)
                .unwrap_or("active")
                != "active"
            {
                return xrpc_error(403, "DeviceNotActive", "revoker device must be active");
            }
            let Some(actor_key) = g.device_keys.get(&(actor_did.clone(), actor_dev)).copied()
            else {
                return xrpc_error(401, "UnknownDevice", "revoker device is not enrolled");
            };
            if chat_wire::verify_signed_mutation_body_and_digest(
                sr,
                SignedMutationKind::DeviceRevocation,
                &actor_key,
            )
            .is_err()
            {
                return xrpc_error(
                    401,
                    "InvalidSignature",
                    "invalid device revocation signature",
                );
            }
            let target_dev = b["targetDeviceId"].as_str().unwrap_or_default().to_string();
            let signed_at = b["signedAt"]
                .as_str()
                .unwrap_or("2026-11-12T00:00:00.000Z")
                .to_string();
            g.device_statuses
                .insert((actor_did.clone(), target_dev.clone()), "revoked".into());
            g.revoked_device_at
                .insert((actor_did.clone(), target_dev.clone()), signed_at);
            g.convo_kps.remove(&(actor_did.clone(), target_dev.clone()));
            if let Some(list) = g.dr_keys.get_mut(&actor_did) {
                list.retain(|(d, _, _)| d != &target_dev);
            }
            return ok_json(json!({ "revoked": true }));
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
                    let status = g
                        .device_statuses
                        .get(&(owner.clone(), dev.clone()))
                        .map(String::as_str)
                        .unwrap_or("active");
                    let mut item = json!({ "device": {
                        "deviceId": dev,
                        "keyId": derive_key_id(key),
                        "signaturePublicKey": { "$bytes": STANDARD.encode(key) },
                        "authGeneration": 1,
                        "status": status,
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
            if g.device_statuses
                .get(&(did.clone(), dev.clone()))
                .map(String::as_str)
                == Some("pending_approval")
            {
                return xrpc_error(403, "NotAuthorized", "NotAuthorized");
            }
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            g.convo_kps.entry((did, dev)).or_default().extend(kps);
            return ok_json(json!({ "acceptedCount": 4 }));
        }

        if url.contains("/xrpc/blue.catbird.chat.publishDirectRequestKeys") {
            let sr = &body_json["signedRequest"];
            let b = &sr["body"];
            let did = b["actorDid"].as_str().unwrap().to_string();
            let dev = b["actorDeviceId"].as_str().unwrap().to_string();
            if g.device_statuses
                .get(&(did.clone(), dev.clone()))
                .map(String::as_str)
                == Some("pending_approval")
            {
                return xrpc_error(400, "PreparationConflict", "PreparationConflict");
            }
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
            let mut outcome_body = json!({
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
            if std::mem::take(&mut g.tamper_next_publication_coordinates) {
                outcome_body["receipt"]["coordinates"]["stateVersion"] = json!(99);
            }
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
            let mut dr_leaves = vec![json!({
                "userDid": b["actorDid"],
                "deviceId": b["actorDeviceId"],
                "leafOrigin": "genesis",
            })];
            for del in b["artifacts"]["welcome"]["deliveries"]
                .as_array()
                .into_iter()
                .flatten()
            {
                dr_leaves.push(json!({
                    "userDid": del["recipientDid"],
                    "deviceId": del["recipientDeviceId"],
                    "leafOrigin": "welcome",
                }));
            }
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
                    "leaves": dr_leaves,
                    "metadataSnapshot": b["artifacts"]["metadataSnapshot"],
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
            if let Some(callback) = g.after_next_publish.take() {
                callback();
            }
            return ok_json(json!({ "outcome": outcome }));
        }

        if url.contains("/xrpc/blue.catbird.chat.createConversation") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["conversationId"].as_str().unwrap().to_string();
            let request_bytes = req.body.clone().unwrap_or_default();
            if let Some((recorded_request, recorded_answer)) = g.creates.get(&cid) {
                return if recorded_request == &request_bytes {
                    ok_json(recorded_answer.clone())
                } else {
                    xrpc_error(400, "IdempotencyConflict", "creation bytes changed")
                };
            }
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
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#creationEntry",
                "entryId": b["transitionId"], "conversationId": cid, "seq": 1,
                "signedRequest": sr, "receivedAt": b["signedAt"],
            });
            entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &coords);
            g.entries
                .entry(cid.clone())
                .or_default()
                .push(entry.clone());
            let answer = json!({ "result": {
                "$type": "blue.catbird.chat.defs#conversationCreatedResult",
                "coordinates": coords,
                "entry": entry,
            }});
            g.creates.insert(cid, (request_bytes, answer.clone()));
            if std::mem::take(&mut g.lose_next_create_response) {
                return Err(MLSError::Internal(
                    "createConversation response lost after commit".into(),
                ));
            }
            return ok_json(answer);
        }

        if url.contains("/xrpc/blue.catbird.chat.acceptConversation") {
            if let Some(dr) = body_json.get("directRequest") {
                let b = &dr["body"];
                let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
                let next_coords = b["next"].clone();
                let mut entry = json!({
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
                let fault = g.next_acceptance_fault.take();
                if fault == Some("missingI13") {
                    return ok_json(json!({
                        "coordinates": next_coords,
                        "acceptanceProof": { "entry": proof_entry, "receipt": receipt },
                    }));
                }
                let control_receipt = control_sequencer_receipt(&g, &entry, &next_coords);
                entry["sequencerReceipt"] = control_receipt.clone();
                proof_entry["sequencerReceipt"] = control_receipt;
                if fault == Some("legacyProof") {
                    receipt["signature"] = json!(STANDARD.encode([7u8; 64]));
                    return ok_json(json!({
                        "coordinates": next_coords,
                        "acceptanceProof": { "entry": proof_entry, "receipt": receipt },
                    }));
                }
                g.entries.entry(cid.clone()).or_default().push(entry);
                if let Some(st) = g.conversations.get_mut(&cid) {
                    st["coordinates"] = next_coords.clone();
                    st["directRequest"]["consent"] = json!("accepted");
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
            let mut sr = body_json["signedRequest"].clone();
            if sr["signature"].is_string() {
                sr["signature"] = json!({ "$bytes": sr["signature"].take() });
            }
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
            let next_seq = g.entries.get(&cid).map_or(0, Vec::len) as i64 + 1;
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
                "entryId": b["transitionId"], "conversationId": cid, "seq": next_seq,
                "coordinates": next_coords.clone(), "signedRequest": sr,
                "receivedAt": b["signedAt"],
            });
            let receipt_sequencer = g
                .next_group_acceptance_receipt_sequencer
                .take()
                .unwrap_or_else(|| DS_DID.to_owned());
            entry["sequencerReceipt"] =
                control_sequencer_receipt_for(&g, &entry, &next_coords, &receipt_sequencer);
            g.entries
                .entry(cid.clone())
                .or_default()
                .push(entry.clone());
            let answer_entry = g
                .next_group_acceptance_answer_entry
                .take()
                .unwrap_or_else(|| entry.clone());
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
            let view = json!({
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
            });
            requests.push(view.clone());
            // `mls-ds` `acceptance_response`: the acceptance's entry, coordinate and recovery.
            return ok_json(json!({
                "seq": next_seq, "coordinates": next_coords, "entry": answer_entry, "recovery": view,
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.requestLeafRecovery") {
            // `mls-ds` `plan_leaf_recovery_request_inner`, verifying nothing: one open request per
            // device, of the kind its leaf allows, bound to the current coordinate, reserving one
            // of the requester device's KeyPackages for five minutes. The view carries the exact
            // signed request; every later coordinate change supersedes it.
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
            let did = b["actorDid"].as_str().unwrap().to_string();
            let dev = b["actorDeviceId"].as_str().unwrap().to_string();
            if g.device_statuses
                .get(&(did.clone(), dev.clone()))
                .map(String::as_str)
                == Some("pending_approval")
            {
                return xrpc_error(403, "DevicePendingApproval", "device awaits approval");
            }
            let Some(state) = g.conversations.get(&cid) else {
                return xrpc_error(400, "ConversationNotFound", "conversation not found");
            };
            if state["coordinates"] != b["prior"] {
                return xrpc_error(400, "StaleCoordinates", "StaleCoordinates");
            }
            let holds_leaf = state["leaves"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|leaf| leaf["userDid"] == did && leaf["deviceId"] == dev);
            if holds_leaf != (b["recoveryKind"] == "replace") {
                return xrpc_error(400, "RecoveryKindMismatch", "RecoveryKindMismatch");
            }
            if g.leaf_recoveries
                .get(&cid)
                .into_iter()
                .flatten()
                .any(|request| {
                    request["status"] == "open"
                        && request["requesterDid"] == did
                        && request["requesterDeviceId"] == dev
                })
            {
                return xrpc_error(409, "LeafRecoveryAlreadyOpen", "LeafRecoveryAlreadyOpen");
            }
            let Some(kp) = g
                .convo_kps
                .get_mut(&(did.clone(), dev.clone()))
                .and_then(Vec::pop)
            else {
                return xrpc_error(400, "KeyPackageUnavailable", "KeyPackageUnavailable");
            };
            let expires_at =
                (chrono::DateTime::parse_from_rfc3339(b["signedAt"].as_str().unwrap()).unwrap()
                    + chrono::Duration::minutes(5))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let view = json!({
                "conversationId": cid,
                "recoveryRequestId": b["recoveryRequestId"],
                "requesterDid": did,
                "requesterDeviceId": dev,
                "recoveryKind": b["recoveryKind"],
                "boundCoordinate": b["prior"],
                "status": "open",
                "requestedAt": b["signedAt"],
                "expiresAt": expires_at,
                "reservation": {
                    "conversationId": cid,
                    "recoveryRequestId": b["recoveryRequestId"],
                    "boundCoordinate": b["prior"],
                    "requesterDid": did,
                    "requesterDeviceId": dev,
                    "requesterKeyId": b["keyId"],
                    "requesterAuthGeneration": b["authGeneration"],
                    "keyPackageRef": kp["keyPackageRef"],
                    "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    "purpose": "leafRecovery",
                    "status": "active",
                    "expiresAt": expires_at,
                    "keyPackage": kp,
                },
                "signedRequest": sr,
            });
            g.leaf_recoveries.entry(cid).or_default().push(view.clone());
            return ok_json(json!({ "recovery": view }));
        }

        if url.contains("/xrpc/blue.catbird.chat.requestLeave") {
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let btype = b["$type"].as_str().unwrap_or("");
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
            let Some(state) = g.conversations.get(&cid).cloned() else {
                return xrpc_error(400, "ConversationNotFound", "conversation not found");
            };
            if state["coordinates"] != b["prior"] {
                return xrpc_error(400, "StaleCoordinates", "StaleCoordinates");
            }
            if btype.ends_with("zeroLeafLeaveBody") {
                let next_coords = b["next"].clone();
                let next_seq = (g.entries.get(&cid).map(Vec::len).unwrap_or(0) as i64) + 1;
                let mut entry = json!({
                    "$type": "blue.catbird.chat.defs#zeroLeafLeaveEntry",
                    "entryId": b["transitionId"],
                    "conversationId": cid,
                    "seq": next_seq,
                    "signedRequest": sr,
                    "receivedAt": b["signedAt"],
                });
                entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &next_coords);
                g.entries
                    .entry(cid.clone())
                    .or_default()
                    .push(entry.clone());
                if let Some(st) = g.conversations.get_mut(&cid) {
                    st["coordinates"] = next_coords.clone();
                    st["snapshotSeq"] = json!(next_seq);
                    if let Some(parts) = st["participants"].as_array_mut() {
                        parts.retain(|p| p["userDid"] != b["actorDid"]);
                    }
                }
                return ok_json(json!({
                    "result": {
                        "$type": "blue.catbird.chat.defs#zeroLeafLeaveResult",
                        "coordinates": next_coords,
                        "entry": entry,
                    }
                }));
            }
            let next_seq = (g.entries.get(&cid).map(Vec::len).unwrap_or(0) as i64) + 1;
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#leaveRequestEntry",
                "entryId": b["leaveRequestId"],
                "conversationId": cid,
                "seq": next_seq,
                "signedRequest": sr,
                "receivedAt": b["signedAt"],
            });
            entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &b["prior"]);
            g.entries.entry(cid.clone()).or_default().push(entry);
            let view = json!({
                "leaveRequestId": b["leaveRequestId"],
                "conversationId": cid,
                "requesterDid": b["actorDid"],
                "requesterDeviceId": b["actorDeviceId"],
                "prior": b["prior"],
                "status": "pending",
                "requestedAt": b["signedAt"],
                "expiresAt": "2099-01-01T00:00:00.000Z",
            });
            g.leave_requests.entry(cid).or_default().push(view.clone());
            return ok_json(json!({
                "result": {
                    "$type": "blue.catbird.chat.defs#durableLeaveRequestResult",
                    "leaveRequest": view,
                }
            }));
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
                || btype.ends_with("leafRecoveryFulfillmentBody")
                || btype.ends_with("leaveCommitFulfillmentBody");
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
            if is_commit {
                let prior = &g.conversations[&cid]["metadataSnapshot"];
                let next = &b["metadataSnapshot"];
                let prior_ciphertext =
                    chat_wire::json_bytes(&prior["ciphertext"]).unwrap_or_default();
                let next_ciphertext =
                    chat_wire::json_bytes(&next["ciphertext"]).unwrap_or_default();
                let prior_nonce = chat_wire::json_bytes(&prior["nonce"]).unwrap_or_default();
                let next_nonce = chat_wire::json_bytes(&next["nonce"]).unwrap_or_default();
                let metadata_coordinate = &next["coordinate"];
                let transition_coordinate = &b["next"];
                let conversation_bytes = uuid::Uuid::parse_str(&cid)
                    .map(|uuid| uuid.as_bytes().to_vec())
                    .unwrap_or_default();
                let coordinate_matches = metadata_coordinate["epoch"]
                    == transition_coordinate["epoch"]
                    && metadata_coordinate["generation"] == transition_coordinate["generation"]
                    && chat_wire::json_bytes(&metadata_coordinate["conversationId"])
                        .unwrap_or_default()
                        == conversation_bytes
                    && chat_wire::json_bytes(&metadata_coordinate["groupId"]).unwrap_or_default()
                        == chat_wire::json_bytes(&transition_coordinate["groupId"])
                            .unwrap_or_default()
                    && chat_wire::json_bytes(&metadata_coordinate["groupContextHash"])
                        .unwrap_or_default()
                        == chat_wire::json_bytes(&transition_coordinate["groupContextHash"])
                            .unwrap_or_default()
                    && chat_wire::json_bytes(&metadata_coordinate["confirmationTag"])
                        .unwrap_or_default()
                        == chat_wire::json_bytes(&transition_coordinate["confirmationTag"])
                            .unwrap_or_default();
                let carried_exactly = coordinate_matches
                    && next["metadataVersion"] == prior["metadataVersion"]
                    && next["originTransitionId"] == prior["originTransitionId"]
                    && next_ciphertext.len() == prior_ciphertext.len()
                    && next["authorProof"] == prior["authorProof"]
                    && next.get("avatarBinding") == prior.get("avatarBinding")
                    && next_nonce != prior_nonce;
                if !carried_exactly {
                    return xrpc_error(
                        400,
                        "InvalidCommit",
                        "commit metadata must carry prior authenticated plaintext",
                    );
                }
            }

            let entry_kind = match btype.trim_start_matches("blue.catbird.chat.defs#") {
                "commitTransitionBody" => "commitEntry",
                "leafRecoveryFulfillmentBody" => "leafRecoveryFulfillmentEntry",
                "leaveCommitFulfillmentBody" => "leaveCommitFulfillmentEntry",
                "policyTransitionBody" => "policyEntry",
                "metadataTransitionBody" => "metadataEntry",
                other => panic!("fixture has no entry kind for {other}"),
            };

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

            let mut entry = json!({
                "$type": format!("blue.catbird.chat.defs#{entry_kind}"),
                "entryId": b["transitionId"],
                "conversationId": cid,
                "seq": next_seq,
                "signedRequest": sr,
                "receivedAt": b["signedAt"],
            });
            entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &next_coords);
            g.entries
                .entry(cid.clone())
                .or_default()
                .push(entry.clone());
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
                for change in b["participantChanges"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .chain(
                        b["manifest"]["participantChanges"]
                            .as_array()
                            .into_iter()
                            .flatten(),
                    )
                {
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
            for leave_req in g.leave_requests.get_mut(&cid).into_iter().flatten() {
                if leave_req["status"] == "pending" {
                    let fulfilled = btype.ends_with("leaveCommitFulfillmentBody")
                        && leave_req["leaveRequestId"] == b["leaveRequestId"];
                    leave_req["status"] = json!(if fulfilled { "fulfilled" } else { "superseded" });
                }
            }
            if is_commit && std::mem::take(&mut g.lose_next_commit_response) {
                return Err(MLSError::Internal(
                    "transition response lost after acceptance".into(),
                ));
            }
            let mut answer = json!({
                "coordinates": next_coords,
                "entry": entry,
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
            if !is_commit && std::mem::take(&mut g.forge_next_policy_answer_receipt) {
                answer["entry"]["sequencerReceipt"]["signature"] =
                    json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
            }
            return ok_json(answer);
        }

        if url.contains("/xrpc/blue.catbird.chat.sendMessage") {
            if std::mem::take(&mut g.hold_next_send) {
                let attempt = send_attempt(&body_json, "held");
                g.send_attempts.push(attempt);
                g.held_sends.push(body_json);
                return Err(MLSError::Internal("sendMessage held by the network".into()));
            }
            let mut response = sequence_send(&mut g, &body_json)?;
            if response.status == 200 && std::mem::take(&mut g.empty_stub_next_send) {
                return ok_json(json!({ "ok": true }));
            }
            if response.status == 200 && std::mem::take(&mut g.omit_next_receipt) {
                let mut answer: Value = serde_json::from_slice(&response.body).unwrap();
                answer.as_object_mut().unwrap().remove("sequencerReceipt");
                answer["entry"]
                    .as_object_mut()
                    .unwrap()
                    .remove("sequencerReceipt");
                response.body = serde_json::to_vec(&answer).unwrap();
            }
            if response.status == 200 && std::mem::take(&mut g.lose_next_send_response) {
                return Err(MLSError::Internal(
                    "send response lost after publication".into(),
                ));
            }
            return Ok(response);
        }

        if url.contains("/xrpc/blue.catbird.chat.requestReset") {
            // mls-ds `plan_reset_request_inner`: an active admin of a group requests at the
            // current coordinate, one pending request at a time.
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
            let state = &g.conversations[&cid];
            if state["coordinates"] != b["prior"] {
                return xrpc_error(400, "StaleCoordinates", "not the current coordinate");
            }
            if !state["participants"].as_array().unwrap().iter().any(|p| {
                p["userDid"] == b["actorDid"] && p["role"] == "admin" && p["status"] == "active"
            }) {
                return xrpc_error(400, "AdminRequired", "active admin required");
            }
            let requests = g.reset_requests.entry(cid.clone()).or_default();
            if requests
                .iter()
                .any(|request| request["status"] == "pending")
            {
                return xrpc_error(400, "ResetAlreadyPending", "a reset request is pending");
            }
            let view = json!({
                "resetRequestId": b["resetRequestId"], "conversationId": cid,
                "requesterDid": b["actorDid"], "requesterDeviceId": b["actorDeviceId"],
                "prior": b["prior"], "reason": b["reason"], "status": "pending",
                "requestedAt": b["signedAt"], "expiresAt": "2099-01-01T00:00:00.000Z",
            });
            requests.push(view.clone());
            let seq = g.entries.get(&cid).map_or(0, Vec::len) as i64 + 1;
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#resetRequestEntry",
                "entryId": b["resetRequestId"], "conversationId": cid,
                "seq": seq, "receivedAt": b["signedAt"], "signedRequest": sr,
            });
            entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &b["prior"]);
            g.entries.entry(cid).or_default().push(entry.clone());
            // A `ref` output carries no `$type`.
            entry.as_object_mut().unwrap().remove("$type");
            match g.next_reset_request_fault.take() {
                Some("missingReceipt") => {
                    entry.as_object_mut().unwrap().remove("sequencerReceipt");
                }
                Some("forgedReceipt") => {
                    entry["sequencerReceipt"]["signature"] =
                        json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
                }
                _ => {}
            }
            return ok_json(json!({ "resetRequest": view, "entry": entry }));
        }

        if url.contains("/xrpc/blue.catbird.chat.activateReset") {
            // mls-ds `plan_reset_activation_inner`: an active admin activates the exact pending
            // request bound to the current coordinate, its metadata authored at the activation's
            // seq; anything else is refused with nothing changed. The successor holds only the
            // activator's leaf, and every open leaf recovery is superseded.
            let sr = body_json["signedRequest"].clone();
            let b = &sr["body"];
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
            let seq = g.entries.get(&cid).map_or(0, Vec::len) as i64 + 1;
            let state = &g.conversations[&cid];
            if !state["participants"].as_array().unwrap().iter().any(|p| {
                p["userDid"] == b["actorDid"] && p["role"] == "admin" && p["status"] == "active"
            }) {
                return xrpc_error(400, "AdminRequired", "active admin required");
            }
            if state["coordinates"] != b["prior"] {
                return xrpc_error(400, "StaleCoordinates", "not the current coordinate");
            }
            if b["metadataSnapshot"]["authorProof"]["originSeq"].as_i64() != Some(seq) {
                return xrpc_error(400, "InvalidRequest", "metadata not authored at its seq");
            }
            let Some(request) =
                g.reset_requests
                    .get_mut(&cid)
                    .into_iter()
                    .flatten()
                    .find(|request| {
                        request["resetRequestId"] == b["resetRequestId"]
                            && request["status"] == "pending"
                            && request["prior"] == b["prior"]
                    })
            else {
                return xrpc_error(400, "ResetRequestNotFound", "no pending reset request");
            };
            request["status"] = json!("consumed");
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#resetActivationEntry",
                "entryId": b["transitionId"], "conversationId": cid, "seq": seq,
                "receivedAt": b["signedAt"], "signedRequest": sr,
            });
            entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &b["successor"]);
            g.entries
                .entry(cid.clone())
                .or_default()
                .push(entry.clone());
            let state = g.conversations.get_mut(&cid).unwrap();
            state["coordinates"] = b["successor"].clone();
            state["snapshotSeq"] = json!(seq);
            state["metadataSnapshot"] = b["metadataSnapshot"].clone();
            state["leaves"] = json!([b["manifest"]["actorLeaf"]]);
            for participant in state["participants"].as_array_mut().unwrap() {
                participant["leafCount"] =
                    json!(usize::from(participant["userDid"] == b["actorDid"]));
            }
            for request in g.leaf_recoveries.get_mut(&cid).into_iter().flatten() {
                if request["status"] == "open" {
                    request["status"] = json!("superseded");
                    request["reservation"]["status"] = json!("released");
                }
            }
            if std::mem::take(&mut g.lose_next_reset_response) {
                return Err(MLSError::Internal(
                    "activateReset response lost after sequencing".into(),
                ));
            }
            entry.as_object_mut().unwrap().remove("$type");
            if std::mem::take(&mut g.forge_next_reset_activation_receipt) {
                entry["sequencerReceipt"]["signature"] =
                    json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
            }
            return ok_json(json!({
                "retiredCoordinates": b["retired"],
                "successorCoordinates": b["successor"],
                "entry": entry,
            }));
        }

        if url.contains("/xrpc/blue.catbird.chat.getConversations") {
            let list: Vec<Value> = g
                .conversations
                .values()
                .filter(|st| {
                    st["participants"].as_array().is_none_or(|parts| {
                        parts.is_empty()
                            || parts.iter().any(|p| p["userDid"].as_str() == Some(account))
                    })
                })
                .cloned()
                .collect();
            let limit = q
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 100);
            let offset = q
                .get("pageCursor")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let page: Vec<Value> = list.iter().skip(offset).take(limit).cloned().collect();
            let next_offset = offset.saturating_add(page.len());
            let next_cursor = if g.repeat_conversation_cursor && offset > 0 {
                Some(offset.to_string())
            } else if next_offset < list.len() && !page.is_empty() {
                Some(next_offset.to_string())
            } else {
                None
            };
            return ok_json(json!({
                "conversations": page,
                "inventorySessionId": "mock-inventory-session",
                "hasMore": next_cursor.is_some(),
                "nextPageCursor": next_cursor,
            }));
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
                // Every coordinate change supersedes the open requests: exactly the open ones
                // are pending, served as the DS holds them.
                .filter(|request| {
                    current_leaf
                        && request["requesterDeviceId"].as_str() != Some(dev.as_str())
                        && request["status"] == "open"
                })
                .cloned()
                .collect();
            let mut pending_reset_requests = g
                .reset_requests
                .get(cid)
                .into_iter()
                .flatten()
                .filter(|request| request["status"] == "pending")
                .cloned()
                .collect::<Vec<_>>();
            if g.fake_pending_reset_seq.is_some() {
                pending_reset_requests.push(json!({
                    "resetRequestId": "00000000-0000-4000-8000-0000000000f1",
                    "conversationId": cid,
                    "requesterDid": account,
                    "requesterDeviceId": dev,
                    "prior": state["coordinates"],
                    "reason": "manualRecovery",
                    "status": "pending",
                    "requestedAt": "2026-11-10T00:00:00.000Z",
                    "expiresAt": "2099-01-01T00:00:00.000Z",
                }));
            }
            let pending_leave_requests = g
                .leave_requests
                .get(cid)
                .into_iter()
                .flatten()
                .filter(|request| request["status"] == "pending")
                .cloned()
                .collect::<Vec<_>>();
            return ok_json(json!({
                "state": state,
                "pendingLeafRecoveryRequests": requests,
                "pendingResetRequests": pending_reset_requests,
                "pendingLeaveRequests": pending_leave_requests,
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
            synthesize_missing_control_receipts(&mut g, &cid);
            let after: i64 = q.get("afterSeq").and_then(|s| s.parse().ok()).unwrap_or(0);
            let device = q.get("actorDeviceId");
            let readable_until = device
                .and_then(|device| g.readable_until.get(device))
                .copied()
                .unwrap_or(i64::MAX);
            if after >= readable_until {
                return xrpc_error(
                    400,
                    "AccessOutsideMembershipInterval",
                    "read past the device's membership interval",
                );
            }
            let readable_from = device
                .and_then(|device| g.readable_from.get(device))
                .copied()
                .unwrap_or(0);
            let mut list: Vec<Value> = g
                .entries
                .get(&cid)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|e| {
                    let seq = e["seq"].as_i64().unwrap_or(0);
                    seq > after && seq >= readable_from && seq <= readable_until
                })
                .collect();
            if let Some(seq) = g.fake_pending_reset_seq.filter(|seq| *seq > after) {
                let prior = g.conversations[&cid]["coordinates"].clone();
                list.push(json!({
                    "$type": "blue.catbird.chat.defs#resetRequestEntry",
                    "entryId": "00000000-0000-4000-8000-0000000000f1",
                    "conversationId": cid,
                    "seq": seq,
                    "receivedAt": "2026-11-10T00:00:00.000Z",
                    "signedRequest": {
                        "body": {
                            "$type": "blue.catbird.chat.defs#resetRequestBody",
                            "actorDid": account,
                            "actorDeviceId": device,
                            "prior": prior,
                        }
                    },
                    "sequencerReceipt": {},
                }));
            }
            list.sort_by_key(|entry| entry["seq"].as_i64().unwrap_or_default());
            let limit = q
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 100);
            list.truncate(limit);
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
            if let Some((recorded, mut answer)) = g.closes.get(&cid).cloned() {
                return if recorded == raw {
                    if std::mem::take(&mut g.forge_next_close_replay_receipt) {
                        answer["result"]["entry"]["sequencerReceipt"]["signature"] =
                            json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
                    }
                    ok_json(answer)
                } else {
                    xrpc_error(409, "ConversationClosed", "conversation is closed")
                };
            }
            if let Some(expected_kind) = g
                .conversations
                .get(&cid)
                .and_then(|conversation| conversation["conversationKind"].as_str())
            {
                assert_eq!(
                    b["conversationKind"].as_str(),
                    Some(expected_kind),
                    "close must bind the authoritative conversation kind"
                );
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
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#conversationCloseEntry",
                "entryId": b["transitionId"],
                "conversationId": cid,
                "seq": next_seq,
                "receivedAt": b["signedAt"],
                "signedRequest": sr,
                "tombstone": tombstone,
            });
            entry["sequencerReceipt"] = control_sequencer_receipt(&g, &entry, &b["retired"]);
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
    signed_account_deletion_at(key, key_id, sequencer, cid, deleted, seq, None)
}

fn signed_account_deletion_at(
    key: &P256SigningKey,
    key_id: &str,
    sequencer: &str,
    cid: &str,
    deleted: &str,
    seq: i64,
    at_ms: Option<i64>,
) -> Value {
    let entry_id = uuid::Uuid::new_v4().to_string();
    let received_at = at_ms
        .and_then(chrono::DateTime::from_timestamp_millis)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let received_at = received_at.as_str();
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

/// `keyProof`: a repo proof, under `did`'s `#atproto` key, of its `chat.device` record for
/// `device_id`.
fn device_key_proof(
    fixture: &NativeArchiveAuthFixture,
    did: &str,
    device_id: &str,
    device_key: &[u8],
) -> Vec<u8> {
    let record = json!({
        "$type": "blue.catbird.chat.device",
        "algorithm": "Ed25519",
        "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(device_key) },
        "createdAt": "2026-11-03T00:00:00.000Z",
    });
    fixture
        .build_signed_car_response(did, "blue.catbird.chat.device", device_id, Some(&record))
        .unwrap()
        .body
}

/// `actorWrite`: the deleting device's own signed `deleteAccountData` request body.
fn deletion_actor_write(signer: &SignatureKeyPair, device_id: &str) -> Value {
    use catbird_mls::labyrinth::write_auth::WriteBody;
    use openmls_traits::signatures::Signer as _;
    let mut op = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut op);
    let body = serde_json::to_vec(&json!({
        "operationId": hex::encode(op),
        "actorDeviceId": device_id,
        "endpointNsid": "blue.catbird.labyrinth.deleteAccountData",
        "payloadSha256": hex::encode(Sha256::digest(b"{}")),
        "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
    .unwrap();
    let signature = signer.sign(&WriteBody::signing_input(&body)).unwrap();
    json!({
        "writeBody": { "$bytes": STANDARD.encode(&body) },
        "payloadBytes": { "$bytes": STANDARD.encode(b"{}") },
        "signature": { "$bytes": STANDARD.encode(signature) },
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
    run_live_catbird_mls_client_c33_dm_i4_i13_i14_labyrinth_and_group_sync(false);
}

#[test]
fn nse_completion_binds_retained_sender_counter_and_exact_replay() {
    run_live_catbird_mls_client_c33_dm_i4_i13_i14_labyrinth_and_group_sync(true);
}

fn run_live_catbird_mls_client_c33_dm_i4_i13_i14_labyrinth_and_group_sync(
    stop_after_nse_completion_controls: bool,
) {
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

    let (peer_counter_key, peer_send_counter) = {
        let state = ds.inner.lock().unwrap();
        let body = &state
            .entries
            .get(&dm_cid)
            .unwrap()
            .iter()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == msg1_id)
            .unwrap()["signedRequest"]["body"];
        (
            chat_wire::peer_send_counter_key(
                &dm_cid,
                body["prior"]["generation"].as_i64().unwrap(),
                body["prior"]["epoch"].as_i64().unwrap(),
                body["actorDid"].as_str().unwrap(),
                body["actorDeviceId"].as_str().unwrap(),
            ),
            body["sendCounter"].as_u64().unwrap(),
        )
    };
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
            )?;
            let mut convo = tx.get_conversation(&dm_cid)?.unwrap();
            convo.last_seq = sent1.seq - 1;
            tx.upsert_conversation(&convo)?;
            tx.put_account_meta(
                &peer_counter_key,
                &peer_send_counter.saturating_sub(1).to_string(),
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
    // A different authorized actor cannot lend its counter to Alice's retained message. The
    // receipt and retained frame remain genuine; only the outer signed body is Bob's.
    let genuine_signed_request = {
        let bob_signer = enrolled_signer(&bob);
        let mut state = ds.inner.lock().unwrap();
        let entry = state
            .entries
            .get_mut(&dm_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == msg1_id)
            .unwrap();
        let genuine = entry["signedRequest"].clone();
        let mut body = genuine["body"].clone();
        body["actorDid"] = json!(BOB_DID);
        body["actorDeviceId"] = json!(bob_dev);
        body["sendCounter"] = json!(peer_send_counter + 100);
        entry["signedRequest"] = signed_by(
            &bob_signer,
            BOB_DID,
            &bob_dev,
            CanonicalOperation::SendMessage,
            &body,
        );
        genuine
    };
    let error = bob
        .sync()
        .expect_err("cached completion must bind the outer actor to the retained sender");
    assert!(
        error
            .to_string()
            .contains("cached application outer sender mismatch"),
        "{error:?}"
    );
    bob.db()
        .read_tx(|tx| {
            assert_eq!(
                tx.get_account_meta(&peer_counter_key)?,
                Some(peer_send_counter.saturating_sub(1).to_string())
            );
            assert!(tx
                .get_pending_op("native_archive_receipt", &msg1_id)?
                .is_some());
            Ok(())
        })
        .unwrap();
    {
        let mut state = ds.inner.lock().unwrap();
        state
            .entries
            .get_mut(&dm_cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == msg1_id)
            .unwrap()["signedRequest"] = genuine_signed_request;
    }
    let before_receipt_replay = mls_snapshot();
    bob.sync()
        .expect("foreground sync completes the NSE message and its peer send counter");
    assert_eq!(
        mls_snapshot(),
        before_receipt_replay,
        "NSE receipt completion must not consume another ratchet"
    );
    bob.db()
        .read_tx(|tx| {
            assert_eq!(
                tx.get_account_meta(&peer_counter_key)?,
                Some(peer_send_counter.to_string()),
                "foreground completion must persist the NSE-decrypted peer send counter"
            );
            Ok(())
        })
        .unwrap();
    let queued_before_replay = bob
        .db()
        .read_tx(|tx| tx.list_labyrinth_queue(None, 100))
        .unwrap()
        .len();
    bob.db()
        .write_tx(|tx| {
            let mut convo = tx.get_conversation(&dm_cid)?.unwrap();
            convo.last_seq = sent1.seq - 1;
            tx.upsert_conversation(&convo)
        })
        .unwrap();
    bob.sync()
        .expect("the exact completed entry replay is idempotent");
    bob.db()
        .read_tx(|tx| {
            assert_eq!(
                tx.get_account_meta(&peer_counter_key)?,
                Some(peer_send_counter.to_string())
            );
            assert_eq!(
                tx.list_labyrinth_queue(None, 100)?.len(),
                queued_before_replay,
                "exact replay must not queue the same archive evidence again"
            );
            Ok(())
        })
        .unwrap();
    let duplicate_id = uuid::Uuid::new_v4().to_string();
    let duplicate_send = alice
        .send_message(&dm_cid, &duplicate_id, "distinct retained message")
        .expect("sequence a distinct message");
    bob.sync().expect("receive the distinct message once");
    let duplicate_archive_key = format!("native.message:{dm_cid}:{duplicate_id}");
    let mut duplicate_evidence: Value = bob
        .db()
        .read_tx(|tx| {
            Ok(
                serde_json::from_slice(&tx.get_labyrinth_state(&duplicate_archive_key)?.unwrap())
                    .unwrap(),
            )
        })
        .unwrap();
    duplicate_evidence["sequencer_receipt_json"] = Value::Null;
    bob.db()
        .write_tx(|tx| {
            tx.put_labyrinth_state(
                &duplicate_archive_key,
                &serde_json::to_vec(&duplicate_evidence).unwrap(),
                1,
            )?;
            tx.put_pending_op(
                "native_archive_receipt",
                &duplicate_id,
                &json!({
                    "conversation_id": dm_cid, "seq": duplicate_send.seq,
                })
                .to_string(),
                1,
            )?;
            tx.dequeue_labyrinth_item(&duplicate_id)?;
            let mut convo = tx.get_conversation(&dm_cid)?.unwrap();
            convo.last_seq = duplicate_send.seq - 1;
            tx.upsert_conversation(&convo)?;
            tx.put_account_meta(&peer_counter_key, &peer_send_counter.to_string(), 1)
        })
        .unwrap();
    rebind_application_send_counter(
        &ds,
        &dm_cid,
        &duplicate_id,
        &enrolled_signer(&alice),
        ALICE_DID,
        &alice_dev,
        peer_send_counter,
    );
    bob.sync()
        .expect("an equal counter on a distinct retained message is evidence only");
    bob.db()
        .read_tx(|tx| {
            assert_eq!(
                tx.get_account_meta(&peer_counter_key)?,
                Some(peer_send_counter.to_string())
            );
            assert!(tx
                .get_pending_op("native_archive_receipt", &duplicate_id)?
                .is_none());
            let evidence =
                tx.get_account_meta(&catbird_mls::client::send_counter::send_counter_gap_key(
                    &dm_cid,
                    duplicate_send.seq,
                ))?;
            assert!(evidence.as_deref().is_some_and(|e| e.contains("regressed")));
            Ok(())
        })
        .unwrap();
    let before_receipt_replay = mls_snapshot();
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
    if stop_after_nse_completion_controls {
        return;
    }

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

/// A DID named by create/add must resolve to at least one valid 32-byte PDS device key. An
/// all-invalid response is never cached and fails without a server effect; restoring the record
/// makes the exact operation retryable.
#[test]
fn zero_valid_pds_device_keys_fail_closed_without_caching_and_clean_retry_succeeds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect();
    let alice_device = uuid::Uuid::new_v4().to_string();
    let bob_device = uuid::Uuid::new_v4().to_string();
    let carol_device = uuid::Uuid::new_v4().to_string();
    let alice = live_client(
        tmp.path(),
        &ds,
        "alice",
        ALICE_DID,
        &alice_device,
        &Arc::new(MemKeyStore::new()),
    );
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob",
        BOB_DID,
        &bob_device,
        &Arc::new(MemKeyStore::new()),
    );
    let carol = live_client(
        tmp.path(),
        &ds,
        "carol",
        CAROL_DID,
        &carol_device,
        &Arc::new(MemKeyStore::new()),
    );
    alice.enroll_device(&scopes).expect("enroll alice");
    bob.enroll_device(&scopes).expect("enroll bob");
    carol.enroll_device(&scopes).expect("enroll carol");

    let cache = |did: &str| {
        alice
            .db()
            .read_tx(|tx| tx.get_account_meta(&format!("authorized_device_keys:{did}")))
            .unwrap()
    };
    let collection = "blue.catbird.chat.device".to_string();
    let bob_record_key = (BOB_DID.to_string(), collection.clone(), bob_device);
    let bob_key = {
        let mut state = ds.inner.lock().unwrap();
        let record = state
            .pds_records
            .get_mut(&bob_record_key)
            .expect("Bob PDS device record");
        std::mem::replace(
            &mut record["mlsSignaturePublicKey"],
            json!({ "$bytes": "" }),
        )
    };

    let conversation_id = uuid::Uuid::new_v4().to_string();
    let create_error = alice
        .create_group(
            &conversation_id,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("PDS key control".into()),
            None,
        )
        .expect_err("create must reject a DID with zero valid PDS device keys");
    assert!(
        create_error.to_string().contains("zero valid"),
        "{create_error}"
    );
    assert_eq!(
        cache(BOB_DID),
        None,
        "an invalid response must not be cached"
    );
    assert!(
        !ds.inner
            .lock()
            .unwrap()
            .conversations
            .contains_key(&conversation_id),
        "PDS validation must precede the create effect"
    );

    ds.inner
        .lock()
        .unwrap()
        .pds_records
        .get_mut(&bob_record_key)
        .unwrap()["mlsSignaturePublicKey"] = bob_key;
    alice
        .create_group(
            &conversation_id,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("PDS key control".into()),
            None,
        )
        .expect("create succeeds after the clean PDS retry");
    let cached_bob: Vec<AuthorizedPeerDeviceKey> =
        serde_json::from_str(&cache(BOB_DID).expect("clean Bob key cached")).unwrap();
    assert!(!cached_bob.is_empty());

    let carol_record_key = (CAROL_DID.to_string(), collection, carol_device);
    let carol_record = ds
        .inner
        .lock()
        .unwrap()
        .pds_records
        .remove(&carol_record_key)
        .expect("Carol PDS device record");
    let entries_before_add = ds.entry_count(&conversation_id);
    let add_error = alice
        .add_group_members(&conversation_id, vec![CAROL_DID.to_string()])
        .expect_err("add must reject a DID with zero valid PDS device keys");
    assert!(add_error.to_string().contains("zero valid"), "{add_error}");
    assert_eq!(
        cache(CAROL_DID),
        None,
        "an invalid add preflight response must not be cached"
    );
    assert_eq!(
        ds.entry_count(&conversation_id),
        entries_before_add,
        "PDS validation must precede the add effect"
    );

    ds.inner
        .lock()
        .unwrap()
        .pds_records
        .insert(carol_record_key.clone(), carol_record.clone());
    alice
        .add_group_members(&conversation_id, vec![CAROL_DID.to_string()])
        .expect("add succeeds after the clean PDS retry");
    let cached_carol: Vec<AuthorizedPeerDeviceKey> =
        serde_json::from_str(&cache(CAROL_DID).expect("clean Carol key cached")).unwrap();
    assert!(!cached_carol.is_empty());
}

/// A DID's unsupported device record cannot hide another usable device. A refused or empty
/// refresh invalidates the stale cache; after a clean retry, an admin can remove the account.
#[test]
fn one_unusable_pds_device_record_does_not_hide_usable_siblings() {
    let f = send_order_fixture(false);
    let extra = (
        BOB_DID.to_string(),
        "blue.catbird.chat.device".to_string(),
        new_id(),
    );
    f.ds.inner.lock().unwrap().pds_records.insert(
        extra.clone(),
        json!({
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode([7u8; 33]) },
            "algorithm": "p256",
            "createdAt": "2026-11-07T00:00:00.000Z",
        }),
    );

    let message_id = new_id();
    f.bob
        .send_message(&f.cid, &message_id, "after one unsupported record")
        .expect("Bob sends");
    f.alice
        .sync()
        .expect("Alice ignores Bob's unusable sibling record");
    assert!(f
        .alice
        .list_messages(&f.cid, None, 100)
        .unwrap()
        .iter()
        .any(|message| message.message_id == message_id));

    let cache_key = format!("authorized_device_keys:{BOB_DID}");
    let cached_bob = || {
        f.alice
            .db()
            .read_tx(|tx| tx.get_account_meta(&cache_key))
            .unwrap()
    };
    assert!(
        cached_bob().is_some(),
        "the clean mixed directory is cached"
    );

    for (case, expected) in [
        ("resolution", "DID resolution transport error"),
        ("transport", "PDS directory transport error"),
        ("parse", "no records array"),
    ] {
        let message_id = new_id();
        f.bob
            .send_message(&f.cid, &message_id, &format!("{case} directory failure"))
            .unwrap();
        match case {
            "resolution" => {
                f.alice
                    .db()
                    .write_tx(|tx| tx.delete_account_meta(&format!("did_doc:{BOB_DID}")))
                    .unwrap();
                f.ds.inner.lock().unwrap().transport_error_next_resolve_for =
                    Some(BOB_DID.to_string());
            }
            "transport" => {
                f.ds.inner
                    .lock()
                    .unwrap()
                    .transport_error_next_pds_directory_for = Some(BOB_DID.to_string());
            }
            "parse" => {
                f.ds.inner.lock().unwrap().malformed_next_pds_directory_for =
                    Some(BOB_DID.to_string());
            }
            _ => unreachable!(),
        }
        let before = last_seq(&f.alice, &f.cid);
        let error = f
            .alice
            .sync()
            .expect_err("directory failure must fail closed");
        assert!(error.to_string().contains(expected), "{case}: {error}");
        assert_eq!(last_seq(&f.alice, &f.cid), before, "{case}");
        assert_eq!(
            cached_bob(),
            None,
            "{case} failure must invalidate the stale device-key cache"
        );
        f.alice.sync().expect("clean retry applies the held entry");
        assert!(
            cached_bob().is_some(),
            "{case} clean retry repopulates the cache"
        );
    }

    f.ds.inner.lock().unwrap().refuse_next_pds_directory_for = Some(BOB_DID.to_string());
    let refused_message = new_id();
    f.bob
        .send_message(&f.cid, &refused_message, "refused directory refresh")
        .unwrap();
    let before_refusal = last_seq(&f.alice, &f.cid);
    let refusal = f.alice.sync().expect_err("a refused refresh fails closed");
    assert!(refusal.to_string().contains("HTTP 503"), "{refusal}");
    assert_eq!(last_seq(&f.alice, &f.cid), before_refusal);
    assert_eq!(
        cached_bob(),
        None,
        "a refused refresh invalidates the stale NSE directory cache"
    );
    f.alice
        .sync()
        .expect("the clean retry applies the held entry");
    assert!(
        cached_bob().is_some(),
        "the clean retry repopulates the cache"
    );

    let removed_records = {
        let mut state = f.ds.inner.lock().unwrap();
        let keys: Vec<_> = state
            .pds_records
            .keys()
            .filter(|(repo, _, _)| repo == BOB_DID)
            .cloned()
            .collect();
        keys.into_iter()
            .map(|key| {
                let value = state.pds_records.remove(&key).unwrap();
                (key, value)
            })
            .collect::<Vec<_>>()
    };
    let empty_message = new_id();
    f.bob
        .send_message(&f.cid, &empty_message, "empty directory refresh")
        .unwrap();
    let before_empty = last_seq(&f.alice, &f.cid);
    let empty = f.alice.sync().expect_err("an empty refresh fails closed");
    assert!(empty.to_string().contains("zero valid"), "{empty}");
    assert_eq!(last_seq(&f.alice, &f.cid), before_empty);
    assert_eq!(
        cached_bob(),
        None,
        "an empty refresh invalidates the stale NSE directory cache"
    );
    f.ds.inner
        .lock()
        .unwrap()
        .pds_records
        .extend(removed_records);
    f.alice.sync().expect("restored directory unblocks sync");
    assert!(cached_bob().is_some(), "the restored directory is cached");
    f.alice
        .remove_group_member(MemberRole::Admin, &f.cid, BOB_DID)
        .expect("the unusable sibling record cannot block Bob's removal");
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

    // 5. A `payloadPruned` entry (O7) in `getEntries` (`I14`) Bob never received leaves a
    // neutral placeholder under its own I13 receipt, which mls-ds keeps serving, without
    // aborting subsequent live entries.
    let pruned_mid = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(&clean_cid, &pruned_mid, "pruned before bob reads it")
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
    let bob_messages = bob.list_messages(&clean_cid, None, 20).unwrap();
    assert!(bob_messages.iter().any(|m| m
        .plaintext_json
        .contains("Live message after payloadPruned entry")));
    // Only the sequencer-local entry id survives pruning: the placeholder carries that.
    let placeholders: Vec<_> = bob_messages
        .iter()
        .filter(|m| m.plaintext_json.contains("message.unavailable"))
        .collect();
    assert_eq!(
        placeholders.len(),
        1,
        "a never-received pruned message leaves a placeholder"
    );
    assert_eq!(placeholders[0].sender_did, ALICE_DID);
    assert!(bob_messages
        .iter()
        .all(|m| m.message_id != pruned_mid
            && !m.plaintext_json.contains("pruned before bob reads it")));

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
    // A history import must never downgrade an already-verified live row.
    let verified = alice
        .list_messages(&clean_cid, None, 100)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == later_mid)
        .expect("later send was durably accepted");
    let mut historical = verified.clone();
    historical.epoch = 0;
    assert_eq!(
        alice
            .import_conversation_history(&clean_cid, vec![historical])
            .expect("skip verified ahead-of-cursor row"),
        0
    );
    assert_eq!(
        alice
            .db()
            .read_tx(|tx| tx.get_message(&later_mid))
            .unwrap()
            .unwrap(),
        verified
    );
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

    // Replaying an old own echo under a new seq cannot close even a cursor-only gap: I13 binds
    // the original seq, so both the actor and its peer reject the relabelled row.
    let controls = control_state(&alice);
    let state = mls_state(&alice);
    let alice_cursor = local_row(&alice).last_seq;
    let mut old_echo = add_echo.expect("the add round's accepted Commit");
    let echo_seq = {
        let mut server = ds.inner.lock().unwrap();
        let entries = server.entries.get_mut(&cid).unwrap();
        let seq = (entries.len() + 1) as i64;
        old_echo["seq"] = json!(seq);
        entries.push(old_echo);
        seq
    };
    let error = alice.sync().expect_err("I13 rejects a relabelled own echo");
    assert!(error.to_string().contains("I13"), "{error}");
    assert_eq!(mls_state(&alice), state);
    assert_eq!(control_state(&alice), controls);
    assert_eq!(local_row(&alice).last_seq, alice_cursor);
    let error = bob
        .sync()
        .expect_err("I13 rejects the relabelled peer Commit");
    assert!(error.to_string().contains("I13"), "{error}");
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
            // One conversation's failure surfaces as itself inside the typed aggregate.
            assert!(
                matches!(&result, Err(MLSError::SyncIncomplete { failures, .. })
                    if matches!(failures.as_slice(), [failure] if failure.conversation_id == cid
                        && matches!(&*failure.error, MLSError::InvalidState(actual) if actual == code))),
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
fn c33_peer_quarantines_account_deletion_and_restore_reconciles_complete_inventory() {
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
    let service_device = "service-method-fixture";
    ds.inner.lock().unwrap().pds_records.insert(
        (
            DS_DID.to_string(),
            "blue.catbird.chat.device".to_string(),
            service_device.to_string(),
        ),
        json!({
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": {
                "$bytes": STANDARD.encode(enrolled_signer(&alice).public())
            },
            "algorithm": "ed25519",
            "createdAt": "2026-11-13T00:00:00.000Z",
        }),
    );

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
    // The recovery method must predate every archived copy that a fresh device must open.
    let code = bob.setup_recovery_code().expect("bob recovery code");

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
    // An unsigned missing-Space response after the member's write reaches the real
    // conversation-Space boundary proves no removal. It must neither owner-back up nor dequeue.
    for status in [400, 404] {
        ds.archive_auth
            .set_unsigned_space_not_found(Some("com.atproto.space.applyWrites"), status);
        let writes_before = ds.archive_auth.committed_space_write_count();
        let error = bob
            .flush_labyrinth_queue()
            .expect_err("unsigned SpaceNotFound leaves shared archive work pending");
        assert!(error.to_string().contains("not found: space"), "{error:?}");
        assert_eq!(
            ds.archive_auth.committed_space_write_count(),
            writes_before,
            "HTTP {status}: owner fallback published"
        );
        assert!(
            bob.list_pending_labyrinth_queue(Some(&cid), 100)
                .unwrap()
                .iter()
                .any(|item| item.message_id == a2),
            "HTTP {status}: shared archive work was dequeued"
        );
    }
    ds.archive_auth.set_unsigned_space_not_found(None, 0);
    let d_messages: Vec<String> = bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| m.sender_did == ALICE_DID)
        .map(|m| m.message_id)
        .collect();
    assert!(d_messages.contains(&a1) && d_messages.contains(&a2));

    // Before the deletion, restore must verify the complete writer inventory. Keep this
    // independent of the later deletion hold, which intentionally blocks archive import.
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute("DELETE FROM messages WHERE message_id = ?1", [&b1])
                .unwrap();
            Ok(())
        })
        .unwrap();
    ds.archive_auth.set_inventory_fault(Some("truncate"));
    let error = bob
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("a terminal page that omits a committed writer must fail closed");
    assert!(error.to_string().contains("ArchiveInventoryIncomplete"));
    assert!(bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .iter()
        .all(|message| message.message_id != b1));
    ds.archive_auth.set_inventory_fault(None);
    assert_eq!(
        bob.restore_conversation_from_owner_mailbox(&cid)
            .expect("committed writer inventory restores the complete Space"),
        1
    );
    assert!(bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .iter()
        .any(|message| message.message_id == b1));
    // A state denial cannot be read as an empty deletion inventory. Both archive entry
    // points must stop before restoring Bob's missing local row from the complete Space.
    bob.db()
        .write_tx(|tx| {
            tx.conn()
                .execute("DELETE FROM messages WHERE message_id = ?1", [&b1])
                .unwrap();
            Ok(())
        })
        .unwrap();
    ds.inner.lock().unwrap().conversation_state_errors.insert(
        (BOB_DID.to_owned(), cid.clone()),
        (400, "NotEntitled".into()),
    );
    for error in [
        bob.restore_conversation_from_owner_mailbox(&cid)
            .expect_err("state denial blocks restore"),
        bob.verify_and_reindex_history(&cid)
            .expect_err("state denial blocks reindex"),
    ] {
        assert!(
            error
                .to_string()
                .contains("ArchiveDeletionInventoryUnavailable"),
            "{error}"
        );
    }
    assert!(bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .iter()
        .all(|message| message.message_id != b1));
    ds.inner
        .lock()
        .unwrap()
        .conversation_state_errors
        .remove(&(BOB_DID.to_owned(), cid.clone()));

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
        let error = bob.sync().expect_err(name);
        assert!(
            matches!(&error, MLSError::SyncIncomplete { applied: 0, failures }
                if failures.len() == 1
                    && failures[0].conversation_id == cid
                    && matches!(failures[0].error.as_ref(), MLSError::Cryptography(_))),
            "{name}: {error:?}"
        );
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
    // Use a historical Alice device for the deletion. Its CAR is the only key source,
    // while Alice's active device stays in the live directory to authenticate archive copies.
    let deletion_device = uuid::Uuid::new_v4().to_string();
    let deletion_signer =
        SignatureKeyPair::new(SignatureScheme::ED25519).expect("historical deletion signer");
    let alice_write = deletion_actor_write(&deletion_signer, &deletion_device);
    let alice_proof = device_key_proof(
        &ds.archive_auth,
        ALICE_DID,
        &deletion_device,
        deletion_signer.public(),
    );
    let deletion_seq = {
        let mut g = ds.inner.lock().unwrap();
        let seq = next_seq(&g);
        let mut entry = signed_account_deletion(
            &historical_receipt_sk,
            &key_id_2,
            DS_DID,
            &cid,
            ALICE_DID,
            seq,
        );
        entry["actorWrite"] = alice_write.clone();
        entry["keyProof"] = json!({ "$bytes": STANDARD.encode(&alice_proof) });
        g.entries.get_mut(&cid).unwrap().push(entry.clone());
        g.account_deletions
            .entry(cid.clone())
            .or_default()
            .push(entry);
        // The historical signing device is absent from the current PDS directory; the active
        // device remains available only to authenticate Alice's archived sender copies.
        seq
    };
    let error = bob
        .sync()
        .expect_err("historical revocation status is not proven");
    assert!(
        error.to_string().contains("AccountDeletionUnverified"),
        "{error}"
    );
    assert_eq!(
        marker(&bob),
        None,
        "quarantine must not install a purge marker"
    );
    assert_eq!(last_seq(&bob, &cid), deletion_seq - 1);
    let retained: Vec<_> = bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .into_iter()
        .filter(|message| message.sender_did == ALICE_DID)
        .map(|message| message.message_id)
        .collect();
    assert_eq!(
        retained, d_messages,
        "quarantine must retain local plaintext"
    );
    assert!(
        bob.list_pending_labyrinth_queue(Some(&cid), 100)
            .unwrap()
            .iter()
            .any(|item| item.message_id == a2),
        "queued witness duty remains while deletion is unresolved"
    );

    // A recovered device has no local MLS leaf for Alice. Restoration must retain all
    // archived rows out of view until the deletion's historical status can be proven.
    let recover = |name: &str| {
        let client = open(name, BOB_DID);
        client.enroll_device(&scopes).expect("enroll recovered Bob");
        client
            .restore_with_recovery_code(&code)
            .expect("recover Bob's archive");
        client
    };
    let baseline = recover("bob-baseline");
    let baseline_error = baseline
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("historically unproven genuine deletion blocks archive import");
    assert!(
        baseline_error
            .to_string()
            .contains("ArchiveDeletionUnverified"),
        "{baseline_error}"
    );
    assert!(baseline.list_messages(&cid, None, 100).unwrap().is_empty());
    let bob2 = recover("bob2");
    // The fresh device has no leaf of Alice. An outage resolving her DID while validating the
    // sequenced deletion must abort before any archived row is imported or made visible.
    bob2.db()
        .write_tx(|tx| {
            tx.delete_account_meta(&format!("did_doc:{ALICE_DID}"))?;
            tx.delete_account_meta(&format!("did_doc_meta:{ALICE_DID}"))
        })
        .unwrap();
    ds.inner.lock().unwrap().transport_error_next_resolve_for = Some(ALICE_DID.into());
    let error = bob2
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("DID outage blocks fresh restoration before import");
    assert!(
        error
            .to_string()
            .contains("injected DID resolution transport error"),
        "{error}"
    );
    assert!(bob2.list_messages(&cid, None, 100).unwrap().is_empty());
    let original_proof = {
        let mut state = ds.inner.lock().unwrap();
        let entry = &mut state.account_deletions.get_mut(&cid).unwrap()[0];
        let original = entry["keyProof"].clone();
        entry["keyProof"] = json!({ "$bytes": STANDARD.encode([9u8; 8]) });
        original
    };
    let error = bob2
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("an actor-unverified listed deletion blocks archive import");
    assert!(
        error.to_string().contains("ArchiveDeletionUnverified"),
        "{error}"
    );
    assert!(bob2.list_messages(&cid, None, 100).unwrap().is_empty());
    ds.inner
        .lock()
        .unwrap()
        .account_deletions
        .get_mut(&cid)
        .unwrap()[0]["keyProof"] = original_proof;
    // Even after the resolver recovers, the old device-record CAR alone cannot prove that
    // Alice's signing device was unrevoked at the signed instant. Stay closed until an
    // authenticated revocation-status proof is available.
    let error = bob2
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("fresh restore cannot infer non-revocation from absent cache");
    assert!(
        error.to_string().contains("ArchiveDeletionUnverified"),
        "{error}"
    );
    let evidence = bob2
        .db()
        .read_tx(|tx| {
            tx.get_labyrinth_state(
                &catbird_mls::client::deletion_authority::unverified_deletion_key(
                    &cid,
                    ALICE_DID,
                    deletion_seq,
                ),
            )
        })
        .unwrap()
        .expect("the exact sequenced deletion is retained as evidence");
    let evidence: catbird_mls::client::deletion_authority::UnverifiedAccountDeletion =
        serde_json::from_slice(&evidence).unwrap();
    assert_eq!(
        evidence.reason,
        catbird_mls::client::deletion_authority::UnverifiedDeletionReason::RevocationStatusUnproven,
        "the CAR must bind Alice's device key before historical status blocks the purge"
    );
    assert!(bob2.list_messages(&cid, None, 100).unwrap().is_empty());
}

/// Cold start: a signed Space denial proves removal, but a forgotten conversation state cannot
/// enumerate account deletions. Owner history stays quarantined until that inventory is available.
#[test]
fn forgotten_conversation_state_holds_owner_history_after_space_denial() {
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
    let owner_batch = ds
        .archive_auth
        .drain_apply_calls()
        .into_iter()
        .flat_map(|(_, call)| call["writes"].as_array().cloned().unwrap_or_default())
        .find(|write| write["collection"] == "blue.catbird.labyrinth.ownerBatch")
        .expect("rescue published an owner batch");
    let owner_batch_json = serde_json::to_vec(&owner_batch["value"]).unwrap();

    // The DS forgetting the conversation is only a lead: the Space authority itself (here the
    // home DS) must deny the account, with its signed denial, before owner records stand in for
    // the conversation.
    let (space, group) = {
        let mut g = ds.inner.lock().unwrap();
        let conversation = g.conversations.remove(&cid).unwrap();
        g.entries.remove(&cid);
        let space = conversation["conversationSpace"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "at:space/{DS_DID}/blue.catbird.labyrinth.conversation/{cid}-{}",
                    conversation["coordinates"]["generation"].as_u64().unwrap()
                )
            });
        let group = chat_wire::json_bytes(&conversation["coordinates"]["groupId"]).unwrap();
        (space, group)
    };
    let error = alice
        .open_rescued_owner_batch(&owner_batch_json)
        .expect_err("direct batch open cannot expose plaintext without deletion inventory");
    assert!(
        error
            .to_string()
            .contains("ArchiveDeletionInventoryUnavailable"),
        "{error}"
    );
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
    ds.archive_auth
        .set_space_denied(ALICE_DID, &space, Some(&group));
    let error = alice
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("owner history needs a complete deletion inventory");
    assert!(
        error
            .to_string()
            .contains("ArchiveDeletionInventoryUnavailable"),
        "{error}"
    );
    assert!(alice.list_messages(&cid, None, 10).unwrap().is_empty());
}

/// A fresh removed device has no MLS group. Exact authenticated NotEntitled is only a lead:
/// owner receipts must recover the Space pin, and its authority must independently deny the
/// account. Even then, missing conversation state cannot certify the deletion inventory, so
/// owner plaintext stays held. Generic 400 and auth failure also remain closed.
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
    // Bob's account declares the other home from its first enrollment. A declaration is
    // create-only, so later test devices for this DID must use that same home.
    let source = live_client_homed(
        tmp.path(),
        &ds,
        "removed-source",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &bob_keys,
        CROSS_HOME_DS_DID,
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

    let (space, group) = {
        let state = ds.inner.lock().unwrap();
        let conversation = &state.conversations[&cid];
        let space = conversation["conversationSpace"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "at:space/{DS_DID}/blue.catbird.labyrinth.conversation/{cid}-{}",
                    conversation["coordinates"]["generation"].as_u64().unwrap()
                )
            });
        let group = chat_wire::json_bytes(&conversation["coordinates"]["groupId"]).unwrap();
        (space, group)
    };
    ds.inner.lock().unwrap().conversation_state_errors.insert(
        (BOB_DID.to_owned(), cid.clone()),
        (400, "NotEntitled".into()),
    );
    // A granted credential followed by an unsigned 400/404 SpaceNotFound at the relayed
    // member-repository inventory boundary is not an authority denial.
    for status in [400, 404] {
        ds.archive_auth
            .set_unsigned_space_not_found(Some("com.atproto.space.listWriters"), status);
        let keys = Arc::new(MemKeyStore::new());
        let client = live_client_homed(
            tmp.path(),
            &ds,
            &format!("unsigned-space-not-found-{status}"),
            BOB_DID,
            &uuid::Uuid::new_v4().to_string(),
            &keys,
            CROSS_HOME_DS_DID,
        );
        client
            .restore_with_recovery_code(&code)
            .expect("recover archive keys");
        let error = client
            .restore_conversation_from_owner_mailbox(&cid)
            .expect_err("unsigned SpaceNotFound cannot unlock owner history");
        assert!(
            error.to_string().contains("ArchiveRestorePending"),
            "HTTP {status}: {error:?}"
        );
        assert!(
            client.list_messages(&cid, None, 10).unwrap().is_empty(),
            "HTTP {status}: imported owner history"
        );
    }
    ds.archive_auth.set_unsigned_space_not_found(None, 0);

    // A signed denial binding another MLS group than the owner receipts pinned (the Space a wrong,
    // unsigned generation names) proves no removal across the home relay.
    ds.archive_auth
        .set_space_denied(BOB_DID, &space, Some(&[0x5a; 32]));
    for (index, home) in [CROSS_HOME_DS_DID].into_iter().enumerate() {
        let keys = Arc::new(MemKeyStore::new());
        let client = live_client_homed(
            tmp.path(),
            &ds,
            &format!("misbound-{index}"),
            BOB_DID,
            &uuid::Uuid::new_v4().to_string(),
            &keys,
            home,
        );
        client
            .restore_with_recovery_code(&code)
            .expect("recover archive keys");
        let error = client
            .restore_conversation_from_owner_mailbox(&cid)
            .expect_err("a misbound denial proves no removal");
        assert!(
            error.to_string().contains("ArchiveRestorePending"),
            "{home}: {error}"
        );
        assert!(client.list_messages(&cid, None, 10).unwrap().is_empty());
    }
    ds.archive_auth
        .set_space_denied(BOB_DID, &space, Some(&group));

    let removed_keys = Arc::new(MemKeyStore::new());
    let removed = live_client_homed(
        tmp.path(),
        &ds,
        "removed-fresh",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &removed_keys,
        CROSS_HOME_DS_DID,
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
    let error = removed
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("a denied state cannot certify its deletion inventory");
    assert!(
        error
            .to_string()
            .contains("ArchiveDeletionInventoryUnavailable"),
        "{error}"
    );
    assert!(removed.list_messages(&cid, None, 10).unwrap().is_empty());

    // The other home relays the same signed Space denial, but it cannot turn an inaccessible
    // conversation state into proof that no account deletion occurred.
    let cross_keys = Arc::new(MemKeyStore::new());
    let cross = live_client_homed(
        tmp.path(),
        &ds,
        "removed-cross-home",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &cross_keys,
        CROSS_HOME_DS_DID,
    );
    cross
        .restore_with_recovery_code(&code)
        .expect("recover removed member archive keys");
    let error = cross
        .restore_conversation_from_owner_mailbox(&cid)
        .expect_err("relayed Space denial cannot certify deletion inventory");
    assert!(
        error
            .to_string()
            .contains("ArchiveDeletionInventoryUnavailable"),
        "{error}"
    );
    assert!(cross.list_messages(&cid, None, 10).unwrap().is_empty());

    // The same DS response is malicious while the Space still admits the account.
    ds.archive_auth.set_space_denied(BOB_DID, &space, None);
    let active_keys = Arc::new(MemKeyStore::new());
    let active = live_client_homed(
        tmp.path(),
        &ds,
        "active-fresh",
        BOB_DID,
        &uuid::Uuid::new_v4().to_string(),
        &active_keys,
        CROSS_HOME_DS_DID,
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
        let client = live_client_homed(
            tmp.path(),
            &ds,
            &format!("malicious-{index}"),
            BOB_DID,
            &uuid::Uuid::new_v4().to_string(),
            &keys,
            CROSS_HOME_DS_DID,
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
    live_client_homed(root, ds, name, did, device_id, keys, DS_DID)
}

/// A client whose home DS identity is `home_ds_did`; the shared mock still answers at `DS_URL`.
/// A home other than `DS_DID` relays the Space requests of conversations `DS_DID` sequences.
fn live_client_homed(
    root: &std::path::Path,
    ds: &Arc<SharedMockDs>,
    name: &str,
    did: &str,
    device_id: &str,
    keys: &Arc<MemKeyStore>,
    home_ds_did: &str,
) -> Arc<CatbirdMlsClient> {
    CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: root.join(name).to_string_lossy().into_owned(),
            account_did: did.to_string(),
            device_id: device_id.to_string(),
            home_ds_did: home_ds_did.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        keys.clone(),
        ds.for_account(did),
        None,
    )
    .expect("open client")
}

fn assert_creator_holds_server_genesis(client: &CatbirdMlsClient, ds: &SharedMockDs, cid: &str) {
    let server = ds.inner.lock().unwrap().conversations[cid]["coordinates"].clone();
    client
        .db()
        .write_tx(|tx| {
            let row = tx.get_conversation(cid)?.expect("creator conversation");
            assert_eq!(row.last_seq, 1);
            assert_eq!(row.epoch, 0);
            assert_eq!(row.group_id, chat_wire::json_bytes(&server["groupId"])?);
            let provider = tx.openmls_provider();
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&row.group_id))
                .map_err(|error| MLSError::Internal(format!("load creator genesis: {error:?}")))?
                .expect("creator genesis group");
            let (context_hash, confirmation_tag) =
                chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
            assert_eq!(
                context_hash.as_slice(),
                chat_wire::json_bytes(&server["groupContextHash"])?
            );
            assert_eq!(
                confirmation_tag,
                chat_wire::json_bytes(&server["confirmationTag"])?
            );
            Ok(())
        })
        .unwrap();
}

fn assert_create_replayed_exactly(ds: &SharedMockDs, cid: &str) {
    let state = ds.inner.lock().unwrap();
    assert_eq!(state.conversations.len(), 1);
    assert_eq!(state.entries[cid].len(), 1);
    let requests: Vec<_> = state
        .http_log
        .iter()
        .filter(|(_, url, _)| url.ends_with("/blue.catbird.chat.createConversation"))
        .map(|(_, _, body)| body)
        .collect();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1], "creation replay changed bytes");
}

fn group_creation_journal_count(client: &CatbirdMlsClient) -> i64 {
    client
        .db()
        .read_tx(|tx| {
            tx.conn()
                .query_row(
                    "SELECT COUNT(*) FROM pending_ops WHERE op_kind = 'group_creation'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| MLSError::Internal(error.to_string()))
        })
        .unwrap()
}

fn allow_group_creation_retry_now(client: &CatbirdMlsClient) {
    client
        .db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "UPDATE pending_ops SET payload_json = json_set(payload_json, '$.retry_at_ms', 0) \
                     WHERE op_kind = 'group_creation'",
                    [],
                )
                .map_err(|error| MLSError::Internal(error.to_string()))?;
            Ok(())
        })
        .unwrap();
}

#[cfg(feature = "sim")]
struct StagedCreationFingerprint {
    operation_id: String,
    request: Vec<u8>,
    group_id: Vec<u8>,
    epoch_authenticator: Vec<u8>,
    next: Value,
    attempts: Vec<(String, Vec<u8>)>,
}

#[cfg(feature = "sim")]
fn staged_creation_fingerprint(
    client: &CatbirdMlsClient,
    conversation_id: &str,
) -> StagedCreationFingerprint {
    use catbird_mls::storage::{
        KvWriteOverlay, OpenMlsKvProvider, OpenMlsKvStorage, RusqliteKvBackend,
    };

    client
        .db()
        .read_tx(|tx| {
            let raw: String = tx
                .conn()
                .query_row(
                    "SELECT payload_json FROM pending_ops WHERE op_kind = 'group_creation' \
                     AND json_extract(payload_json, '$.conversation_id') = ?1",
                    [conversation_id],
                    |row| row.get(0),
                )
                .map_err(|error| MLSError::Internal(error.to_string()))?;
            let pending: chat_wire::PendingGroupCreation = serde_json::from_str(&raw)?;
            let attempts = pending
                .attempts
                .iter()
                .map(|attempt| (attempt.operation_id.clone(), attempt.request.clone()))
                .collect();
            let latest = pending
                .attempts
                .last()
                .expect("pending creation has an attempt");
            let request: Value = serde_json::from_slice(&latest.request)?;
            let operation_id = latest.operation_id.clone();
            let request_bytes = latest.request.clone();
            let next = request["signedRequest"]["body"]["next"].clone();
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            pending.kv_batch.apply(&overlay)?;
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&pending.group_id))
                .map_err(|error| MLSError::Internal(format!("load staged genesis: {error:?}")))?
                .expect("staged genesis");
            Ok(StagedCreationFingerprint {
                operation_id,
                request: request_bytes,
                group_id: pending.group_id,
                epoch_authenticator: group.epoch_authenticator().as_slice().to_vec(),
                next,
                attempts,
            })
        })
        .unwrap()
}

#[cfg(feature = "sim")]
fn adopted_epoch_authenticator(client: &CatbirdMlsClient, conversation_id: &str) -> Vec<u8> {
    use catbird_mls::storage::{OpenMlsKvProvider, OpenMlsKvStorage, RusqliteKvBackend};

    client
        .db()
        .read_tx(|tx| {
            let row = tx
                .get_conversation(conversation_id)?
                .expect("adopted conversation");
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&row.group_id))
                .map_err(|error| MLSError::Internal(format!("load adopted genesis: {error:?}")))?
                .expect("adopted genesis");
            Ok(group.epoch_authenticator().as_slice().to_vec())
        })
        .unwrap()
}

#[cfg(feature = "sim")]
fn creation_requests_for(ds: &SharedMockDs, conversation_id: &str) -> Vec<Vec<u8>> {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, body)| {
            url.ends_with("/blue.catbird.chat.createConversation")
                && serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|request| {
                        request
                            .pointer("/signedRequest/body/conversationId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(conversation_id)
        })
        .map(|(_, _, body)| body.clone())
        .collect()
}

fn create_request_count(ds: &SharedMockDs) -> usize {
    ds.inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.ends_with("/blue.catbird.chat.createConversation"))
        .count()
}

fn finish_resumed_group(alice: &CatbirdMlsClient, bob: &CatbirdMlsClient, cid: &str) {
    bob.sync().expect("invitee accepts");
    alice.sync().expect("creator fulfills recovery");
    bob.sync().expect("invitee joins");
    let message_id = uuid::Uuid::new_v4().to_string();
    alice
        .send_message(cid, &message_id, "resumed genesis")
        .expect("creator sends");
    bob.sync().expect("invitee decrypts");
    assert!(bob
        .list_messages(cid, None, 20)
        .unwrap()
        .iter()
        .any(|message| message.message_id == message_id
            && message.plaintext_json.contains("resumed genesis")));
}

#[cfg(feature = "sim")]
#[test]
fn group_creation_resumes_after_verified_2xx_before_local_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let alice_keys = Arc::new(MemKeyStore::new());
    let bob_keys = Arc::new(MemKeyStore::new());
    let alice_device = uuid::Uuid::new_v4().to_string();
    let bob_device = uuid::Uuid::new_v4().to_string();
    let alice = live_client(
        tmp.path(),
        &ds,
        "alice-create-resume",
        ALICE_DID,
        &alice_device,
        &alice_keys,
    );
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob-create-resume",
        BOB_DID,
        &bob_device,
        &bob_keys,
    );
    let scopes = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    alice.enroll_device(&scopes).unwrap();
    bob.enroll_device(&scopes).unwrap();
    let cid = uuid::Uuid::new_v4().to_string();
    let create = || {
        alice.create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Resumable genesis".into()),
            None,
        )
    };
    let error = catbird_mls::sim_hooks::BuggifyController::with_enabled_sites(
        &["after_http_2xx_before_db_commit"],
        create,
    )
    .expect_err("the injected crash boundary fires");
    assert!(
        error
            .to_string()
            .contains("after_http_2xx_before_db_commit"),
        "{error:?}"
    );
    assert!(alice.list_conversations(None, 20).unwrap().is_empty());

    allow_group_creation_retry_now(&alice);
    create().expect("retry adopts the journaled genesis");
    assert_create_replayed_exactly(&ds, &cid);
    assert_creator_holds_server_genesis(&alice, &ds, &cid);
    create().expect("a completed logical retry returns the existing group");
    assert_create_replayed_exactly(&ds, &cid);
    finish_resumed_group(&alice, &bob, &cid);

    assert!(chat_wire::group_creation_refusal_is_exists_evidence(
        400,
        Some("ConversationAlreadyExists")
    ));
    for not_exists in [
        "BlockedRelationship",
        "InvalidMlsArtifact",
        "MetadataNonceReuse",
    ] {
        assert!(!chat_wire::group_creation_refusal_is_exists_evidence(
            400,
            Some(not_exists)
        ));
    }
}

#[test]
fn group_creation_lost_response_replays_on_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let alice_keys = Arc::new(MemKeyStore::new());
    let bob_keys = Arc::new(MemKeyStore::new());
    let alice_device = uuid::Uuid::new_v4().to_string();
    let bob_device = uuid::Uuid::new_v4().to_string();
    let alice = live_client(
        tmp.path(),
        &ds,
        "alice-create-reopen",
        ALICE_DID,
        &alice_device,
        &alice_keys,
    );
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob-create-reopen",
        BOB_DID,
        &bob_device,
        &bob_keys,
    );
    let scopes = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    alice.enroll_device(&scopes).unwrap();
    bob.enroll_device(&scopes).unwrap();
    let cid = uuid::Uuid::new_v4().to_string();
    {
        let mut state = ds.inner.lock().unwrap();
        state.lose_next_create_response = true;
        state.xrpc_failures.push((
            "/blue.catbird.chat.getConversationState",
            503,
            "CapacityUnavailable",
            None,
        ));
    }
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Reopened genesis".into()),
            None,
        )
        .expect_err("the committed response is lost");
    assert!(alice.list_conversations(None, 20).unwrap().is_empty());

    let calls_before_open = create_request_count(&ds);
    drop(alice);
    let alice = live_client(
        tmp.path(),
        &ds,
        "alice-create-reopen",
        ALICE_DID,
        &alice_device,
        &alice_keys,
    );
    assert_eq!(
        create_request_count(&ds),
        calls_before_open,
        "open must never perform creation replay network I/O"
    );
    assert_eq!(group_creation_journal_count(&alice), 1);
    allow_group_creation_retry_now(&alice);
    alice
        .sync()
        .expect("the explicit sync replays the creation journal");
    assert_create_replayed_exactly(&ds, &cid);
    assert_creator_holds_server_genesis(&alice, &ds, &cid);
    finish_resumed_group(&alice, &bob, &cid);
}

/// Permanent pre-lookup refusals retain the only genesis until authenticated server time proves
/// every exact attempt too old to commit, then exit as a typed terminal failure.
#[cfg(feature = "sim")]
#[test]
fn group_creation_permanent_refusal_becomes_terminal_only_after_expiry() {
    let (_tmp, ds, clock, alice, _bob) = r4fix3_clocked_creation_fixture();
    let conversation_id = new_id();
    let refuse = |ds: &SharedMockDs| {
        ds.inner.lock().unwrap().xrpc_failures.push((
            "/blue.catbird.chat.createConversation",
            401,
            "NotAuthorized",
            None,
        ));
    };
    refuse(&ds);
    alice
        .create_group(
            &conversation_id,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Refused".into()),
            None,
        )
        .expect_err("fresh permanent refusal retains the journal");
    assert_eq!(group_creation_journal_count(&alice), 1);
    assert_eq!(
        alice
            .pending_group_creation_status(&conversation_id)
            .unwrap()
            .expect("pending refusal")
            .state,
        chat_wire::PendingGroupCreationState::PendingRetry
    );

    r4fix3_advance_server_and_client(&ds, &clock, 361_000);
    refuse(&ds);
    let error = alice
        .sync()
        .expect_err("expired permanent refusal is terminal");
    assert!(
        matches!(&error, MLSError::SyncIncomplete { failures, .. }
            if matches!(failures.as_slice(), [failure]
                if failure.conversation_id == conversation_id
                    && matches!(&*failure.error, MLSError::GroupCreationRejected {
                        conversation_id: actual,
                        code,
                    } if actual == &conversation_id && code == "NotAuthorized"))),
        "{error:?}"
    );
    assert_eq!(group_creation_journal_count(&alice), 0);
}

#[cfg(feature = "sim")]
#[test]
fn group_creation_expiry_appends_attempt_over_the_same_genesis_and_provenance() {
    let (_tmp, ds, clock, alice, bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Expired creation".into()),
            None,
        )
        .expect_err("first execution is unavailable");
    let before = staged_creation_fingerprint(&alice, &cid);
    assert_eq!(before.attempts.len(), 1);

    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        401,
        "InvalidSignature",
        None,
    ));
    let expired_error = alice
        .sync()
        .expect_err("expired exact replay appends a signed attempt");
    assert!(
        matches!(&expired_error, MLSError::SyncIncomplete { failures, .. }
            if matches!(failures.as_slice(), [failure]
                if failure.conversation_id == cid
                    && matches!(&*failure.error, MLSError::GroupCreationPending {
                        last_error_code, ..
                    } if last_error_code == "GroupCreationResigned"))),
        "{expired_error:?}"
    );
    let after = staged_creation_fingerprint(&alice, &cid);
    assert_eq!(after.attempts.len(), 2);
    assert_eq!(after.attempts[0].0, before.operation_id);
    assert_eq!(after.attempts[0].1, before.request);
    assert_ne!(after.operation_id, before.operation_id);
    assert_eq!(after.group_id, before.group_id, "re-sign minted a group");
    assert_eq!(
        after.epoch_authenticator, before.epoch_authenticator,
        "re-sign minted an epoch-zero state"
    );
    assert_eq!(after.next, before.next, "genesis coordinates changed");

    let fresh: Value = serde_json::from_slice(&after.request).unwrap();
    let fresh_body = &fresh["signedRequest"]["body"];
    assert_eq!(
        fresh_body
            .pointer("/metadataSnapshot/originTransitionId")
            .and_then(Value::as_str),
        Some(after.operation_id.as_str())
    );
    assert_eq!(
        fresh_body
            .pointer("/metadataSnapshot/authorProof/originTransitionId")
            .and_then(Value::as_str),
        Some(after.operation_id.as_str())
    );
    assert!(fresh_body["manifest"]["participants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|participant| participant["status"] == "pending")
        .all(|participant| participant
            .pointer("/invitationProvenance/invitationTransitionId")
            .and_then(Value::as_str)
            == Some(after.operation_id.as_str())));
    let old: Value = serde_json::from_slice(&before.request).unwrap();
    for pointer in [
        "/signedRequest/body/next/groupId",
        "/signedRequest/body/next/groupContextHash",
        "/signedRequest/body/next/confirmationTag",
        "/signedRequest/body/genesisGroupInfo",
    ] {
        assert_eq!(old.pointer(pointer), fresh.pointer(pointer), "{pointer}");
    }

    // The server refuses A again, then accepts B. Both exact A copies remain byte-identical.
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        401,
        "InvalidSignature",
        None,
    ));
    alice
        .sync()
        .expect("fresh attempt creates the staged genesis");
    assert_eq!(group_creation_journal_count(&alice), 0);
    assert_eq!(
        adopted_epoch_authenticator(&alice, &cid),
        before.epoch_authenticator
    );
    let requests = creation_requests_for(&ds, &cid);
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[0], requests[2]);
    assert_eq!(requests[3], after.request);
    finish_resumed_group(&alice, &bob, &cid);
}

#[cfg(feature = "sim")]
#[test]
fn group_creation_cancel_waits_for_expiry_and_backward_clock_is_bounded() {
    let (_tmp, ds, clock, alice, _bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Cancelable".into()),
            None,
        )
        .expect_err("initial post unavailable");
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    let cancel = alice
        .cancel_pending_group_creation(&cid)
        .expect_err("fresh exact bytes may still commit");
    assert!(
        matches!(&cancel, MLSError::GroupCreationCancellationUnproven {
            conversation_id,
            reason,
        } if conversation_id == &cid && reason == "CreationAttemptsMayStillCommit"),
        "{cancel:?}"
    );
    assert_eq!(group_creation_journal_count(&alice), 1);

    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        401,
        "InvalidSignature",
        None,
    ));
    assert!(alice.cancel_pending_group_creation(&cid).unwrap());
    assert_eq!(group_creation_journal_count(&alice), 0);
    let occupied = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        400,
        "ConversationAlreadyExists",
        None,
    ));
    alice
        .create_group(
            &occupied,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Occupied".into()),
            None,
        )
        .expect_err("exists evidence alone does not delete");
    assert_eq!(group_creation_journal_count(&alice), 1);
    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        400,
        "ConversationAlreadyExists",
        None,
    ));
    assert!(alice.cancel_pending_group_creation(&occupied).unwrap());
    assert_eq!(group_creation_journal_count(&alice), 0);

    let rollback = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        Some("300"),
    ));
    alice
        .create_group(
            &rollback,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Rollback".into()),
            None,
        )
        .expect_err("retry is deferred");
    clock.advance_ms(-1_000_000);
    let now = catbird_mls::sim_hooks::SimClock::now_ms(clock.as_ref());
    let status = alice
        .pending_group_creation_status(&rollback)
        .unwrap()
        .expect("rollback journal");
    assert!(
        status.retry_at_ms.unwrap() <= now + chat_wire::GROUP_CREATION_MAX_RETRY_MS,
        "backward jump exposed an unbounded deadline"
    );
    let posts = create_request_count(&ds);
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .sync()
        .expect_err("the retry runs despite the stale far-future deadline");
    assert_eq!(create_request_count(&ds), posts + 1);
}

#[cfg(feature = "sim")]
#[test]
fn committed_expired_creation_replays_at_the_current_endpoint() {
    use catbird_mls::sim_hooks::{FixedStepClock, OsSimEntropy, SimClientHooks};

    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let clock = Arc::new(FixedStepClock::new(
        chrono::Utc::now().timestamp_millis(),
        0,
    ));
    let device_id = new_id();
    let keys = Arc::new(MemKeyStore::new());
    let open = |endpoint: &str| {
        CatbirdMlsClient::open_with_hooks(
            CatbirdMlsClientConfig {
                storage_root: tmp.path().join("alice-endpoint").to_string_lossy().into(),
                account_did: ALICE_DID.into(),
                device_id: device_id.clone(),
                home_ds_did: DS_DID.into(),
                home_ds_endpoint: endpoint.into(),
                pds_endpoint: PDS_URL.into(),
            },
            keys.clone(),
            ds.for_account(ALICE_DID),
            None,
            SimClientHooks::new(clock.clone(), Arc::new(OsSimEntropy)),
        )
        .unwrap()
    };
    let alice = open(DS_URL);
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob-endpoint",
        BOB_DID,
        &new_id(),
        &Arc::new(MemKeyStore::new()),
    );
    alice.enroll_device(&oauth_scopes()).unwrap();
    bob.enroll_device(&oauth_scopes()).unwrap();
    let cid = new_id();
    {
        let mut state = ds.inner.lock().unwrap();
        state.lose_next_create_response = true;
        state.xrpc_failures.push((
            "/blue.catbird.chat.getConversationState",
            503,
            "CapacityUnavailable",
            None,
        ));
    }
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Moved endpoint".into()),
            None,
        )
        .expect_err("lost answer and state failure retain the journal");
    let staged = staged_creation_fingerprint(&alice, &cid);
    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    drop(alice);

    let alice = open("https://moved-home.invalid");
    alice
        .retry_pending_group_creation(&cid)
        .expect("explicit retry resolves the current URL")
        .expect("completed creation");
    assert_eq!(
        adopted_epoch_authenticator(&alice, &cid),
        staged.epoch_authenticator
    );
    let urls = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, body)| {
            url.ends_with("/blue.catbird.chat.createConversation")
                && serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|request| {
                        request
                            .pointer("/signedRequest/body/conversationId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(cid.as_str())
        })
        .map(|(_, url, _)| url.clone())
        .collect::<Vec<_>>();
    assert_eq!(urls.len(), 2);
    assert!(urls[0].starts_with(DS_URL));
    assert!(urls[1].starts_with("https://moved-home.invalid"));
}

// Round-4 review regressions: these were first landed before the fix and captured in the
// R4ClientFix3Create-*-fail-before logs.
#[cfg(feature = "sim")]
fn r4fix3_clocked_creation_fixture() -> (
    tempfile::TempDir,
    Arc<SharedMockDs>,
    Arc<catbird_mls::sim_hooks::FixedStepClock>,
    Arc<CatbirdMlsClient>,
    Arc<CatbirdMlsClient>,
) {
    use catbird_mls::sim_hooks::{FixedStepClock, OsSimEntropy, SimClientHooks};

    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let clock = Arc::new(FixedStepClock::new(
        chrono::Utc::now().timestamp_millis(),
        0,
    ));
    let alice = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice-r4fix3").to_string_lossy().into(),
            account_did: ALICE_DID.into(),
            device_id: new_id(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(ALICE_DID),
        None,
        SimClientHooks::new(clock.clone(), Arc::new(OsSimEntropy)),
    )
    .unwrap();
    let bob = live_client(
        tmp.path(),
        &ds,
        "bob-r4fix3",
        BOB_DID,
        &new_id(),
        &Arc::new(MemKeyStore::new()),
    );
    alice.enroll_device(&oauth_scopes()).unwrap();
    bob.enroll_device(&oauth_scopes()).unwrap();
    (tmp, ds, clock, alice, bob)
}

#[cfg(feature = "sim")]
fn r4fix3_advance_server_and_client(
    _ds: &SharedMockDs,
    clock: &catbird_mls::sim_hooks::FixedStepClock,
    millis: i64,
) {
    clock.advance_ms(millis);
}

#[cfg(feature = "sim")]
#[test]
fn r4fix3_reviewer_mj1a_exists_after_401_remains_retryable() {
    let (_tmp, ds, _clock, alice, _bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    {
        let mut state = ds.inner.lock().unwrap();
        state.lose_next_create_response = true;
        state.xrpc_failures.push((
            "/blue.catbird.chat.getConversationState",
            503,
            "CapacityUnavailable",
            None,
        ));
    }
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("MJ-1a".into()),
            None,
        )
        .expect_err("the lost answer and failed state read retain the journal");
    let staged = staged_creation_fingerprint(&alice, &cid);
    allow_group_creation_retry_now(&alice);
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        401,
        "InvalidSignature",
        None,
    ));
    alice
        .sync()
        .expect("exists after 401 adopts the verified creation entry");
    assert_eq!(group_creation_journal_count(&alice), 0);
    assert_eq!(
        adopted_epoch_authenticator(&alice, &cid),
        staged.epoch_authenticator
    );
}

#[cfg(feature = "sim")]
#[test]
fn r4fix3_reviewer_mj1b_one_failed_state_read_remains_retryable() {
    let (_tmp, ds, clock, alice, _bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("MJ-1b".into()),
            None,
        )
        .expect_err("initial post unavailable");
    r4fix3_advance_server_and_client(&ds, &clock, 361_000);
    {
        let mut state = ds.inner.lock().unwrap();
        state.xrpc_failures.push((
            "/blue.catbird.chat.createConversation",
            401,
            "InvalidSignature",
            None,
        ));
        state.xrpc_failures.push((
            "/blue.catbird.chat.getConversationState",
            503,
            "CapacityUnavailable",
            None,
        ));
    }
    alice.sync().expect_err("one state read is unavailable");
    assert_eq!(
        alice
            .pending_group_creation_status(&cid)
            .unwrap()
            .expect("journal retained")
            .state,
        chat_wire::PendingGroupCreationState::PendingRetry
    );
    allow_group_creation_retry_now(&alice);
    alice
        .sync()
        .expect("the next exact replay must recover from one state-read failure");
    assert_eq!(group_creation_journal_count(&alice), 0);
}

#[cfg(feature = "sim")]
#[test]
fn r4fix3_reviewer_mj1c_server_ahead_expiry_remains_retryable() {
    let (_tmp, ds, clock, alice, _bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("MJ-1c".into()),
            None,
        )
        .expect_err("initial post unavailable");
    r4fix3_advance_server_and_client(&ds, &clock, 297_000);
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        401,
        "InvalidSignature",
        None,
    ));
    alice
        .sync()
        .expect_err("server-ahead expiry is ambiguous and retryable");
    assert_eq!(
        alice
            .pending_group_creation_status(&cid)
            .unwrap()
            .expect("journal retained")
            .state,
        chat_wire::PendingGroupCreationState::PendingRetry
    );
    allow_group_creation_retry_now(&alice);
    alice
        .sync()
        .expect("the ambiguous expiry cannot latch the journal");
    assert_eq!(group_creation_journal_count(&alice), 0);
}

struct R4Fix3CancelDuringCreate {
    inner: Arc<dyn PlatformTransport>,
    client: Mutex<Option<std::sync::Weak<CatbirdMlsClient>>>,
    armed: std::sync::atomic::AtomicBool,
    outcome: Mutex<Option<Result<bool, MLSError>>>,
}

impl PlatformTransport for R4Fix3CancelDuringCreate {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        if request
            .url
            .ends_with("/xrpc/blue.catbird.chat.createConversation")
            && self.armed.swap(false, Ordering::SeqCst)
        {
            let cid = request
                .body
                .as_deref()
                .and_then(|body| serde_json::from_slice::<Value>(body).ok())
                .and_then(|body| {
                    body.pointer("/signedRequest/body/conversationId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap();
            let client = self
                .client
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if let Some(client) = client {
                let cancel = std::thread::spawn(move || client.cancel_pending_group_creation(&cid))
                    .join()
                    .expect("cancel thread");
                *self.outcome.lock().unwrap() = Some(cancel);
            }
        }
        self.inner.execute_http(request)
    }

    fn connect_realtime_stream(&self, _url: String, _cursor: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

#[test]
fn r4fix3_reviewer_mj2a_cancel_during_post_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let transport = Arc::new(R4Fix3CancelDuringCreate {
        inner: ds.for_account(ALICE_DID),
        client: Mutex::new(None),
        armed: std::sync::atomic::AtomicBool::new(false),
        outcome: Mutex::new(None),
    });
    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice-race").to_string_lossy().into(),
            account_did: ALICE_DID.into(),
            device_id: new_id(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        transport.clone(),
        None,
    )
    .unwrap();
    *transport.client.lock().unwrap() = Some(Arc::downgrade(&alice));
    let bob = enrolled(&tmp, &ds, "bob-race", BOB_DID, &new_id());
    alice.enroll_device(&oauth_scopes()).unwrap();
    let cid = new_id();
    transport.armed.store(true, Ordering::SeqCst);
    let created = alice.create_group(
        &cid,
        DS_DID,
        vec![BOB_DID.into()],
        Some("Raced".into()),
        None,
    );
    let cancel = transport
        .outcome
        .lock()
        .unwrap()
        .take()
        .expect("cancel callback ran");
    assert!(
        matches!(&cancel, Err(MLSError::GroupCreationCancellationUnproven {
            conversation_id,
            reason,
        }) if conversation_id == &cid && reason == "CreationRequestInFlight"),
        "{cancel:?}"
    );
    created.expect("the in-flight create retains and adopts its genesis");
    assert_eq!(group_creation_journal_count(&alice), 0);
    finish_resumed_group(&alice, &bob, &cid);
}

#[cfg(feature = "sim")]
#[test]
fn r4fix3_reviewer_mj2b_original_commits_after_resign() {
    let (_tmp, ds, clock, alice, bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("MJ-2b".into()),
            None,
        )
        .expect_err("initial post unavailable");
    let original = staged_creation_fingerprint(&alice, &cid);
    r4fix3_advance_server_and_client(&ds, &clock, 361_000);
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        401,
        "InvalidSignature",
        None,
    ));
    alice
        .sync()
        .expect_err("expired attempt appends a fresh signed attempt");
    let resigned = staged_creation_fingerprint(&alice, &cid);
    assert_ne!(resigned.operation_id, original.operation_id);
    assert_eq!(resigned.group_id, original.group_id);
    assert_eq!(resigned.epoch_authenticator, original.epoch_authenticator);

    ds.for_account(ALICE_DID)
        .execute_http(PlatformHttpRequest {
            method: "POST".into(),
            url: format!("{DS_URL}/xrpc/blue.catbird.chat.createConversation"),
            headers: vec![PlatformHttpHeader {
                name: "content-type".into(),
                value: "application/json".into(),
            }],
            body: Some(original.request.clone()),
        })
        .expect("the delayed original commits");
    {
        let mut state = ds.inner.lock().unwrap();
        state.xrpc_failures.push((
            "/blue.catbird.chat.createConversation",
            503,
            "CapacityUnavailable",
            None,
        ));
        state.xrpc_failures.push((
            "/blue.catbird.chat.createConversation",
            400,
            "ConversationAlreadyExists",
            None,
        ));
    }
    allow_group_creation_retry_now(&alice);
    alice
        .sync()
        .expect("state proof adopts the original attempt's journaled genesis");
    assert_eq!(group_creation_journal_count(&alice), 0);
    assert_eq!(
        adopted_epoch_authenticator(&alice, &cid),
        original.epoch_authenticator
    );
    assert_creator_holds_server_genesis(&alice, &ds, &cid);
    finish_resumed_group(&alice, &bob, &cid);
}

#[cfg(feature = "sim")]
#[test]
fn group_creation_absence_and_foreign_guards_are_controlled() {
    let (_tmp, ds, clock, alice, bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Guards".into()),
            None,
        )
        .expect_err("initial create retained");
    let before = staged_creation_fingerprint(&alice, &cid);
    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    for (status, code) in [(503, "CapacityUnavailable"), (401, "AccountSessionExpired")] {
        {
            let mut state = ds.inner.lock().unwrap();
            state.xrpc_failures.push((
                "/blue.catbird.chat.createConversation",
                401,
                "InvalidSignature",
                None,
            ));
            state.xrpc_failures.push((
                "/blue.catbird.chat.getConversationState",
                status,
                code,
                None,
            ));
        }
        alice
            .cancel_pending_group_creation(&cid)
            .expect_err("a non-404 state refusal is never absence");
        {
            let mut state = ds.inner.lock().unwrap();
            state.xrpc_failures.push((
                "/blue.catbird.chat.createConversation",
                401,
                "InvalidSignature",
                None,
            ));
            state.xrpc_failures.push((
                "/blue.catbird.chat.getConversationState",
                status,
                code,
                None,
            ));
        }
        alice
            .retry_pending_group_creation(&cid)
            .expect_err("expired retry cannot re-sign without ConversationNotFound");
        let current = staged_creation_fingerprint(&alice, &cid);
        assert_eq!(current.attempts.len(), 1);
        assert_eq!(current.operation_id, before.operation_id);
    }

    let existing = new_id();
    {
        let mut state = ds.inner.lock().unwrap();
        state.lose_next_create_response = true;
        state.xrpc_failures.push((
            "/blue.catbird.chat.getConversationState",
            503,
            "CapacityUnavailable",
            None,
        ));
    }
    alice
        .create_group(
            &existing,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Existing".into()),
            None,
        )
        .expect_err("committed response and state read lost");
    let existing_before = staged_creation_fingerprint(&alice, &existing);
    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    {
        let mut state = ds.inner.lock().unwrap();
        state.xrpc_failures.push((
            "/blue.catbird.chat.createConversation",
            401,
            "InvalidSignature",
            None,
        ));
        state.xrpc_failures.push((
            "/blue.catbird.chat.getEntries",
            503,
            "CapacityUnavailable",
            None,
        ));
    }
    alice
        .retry_pending_group_creation(&existing)
        .expect_err("existing conversation with unavailable entry proof retains");
    let existing_after = staged_creation_fingerprint(&alice, &existing);
    assert_eq!(existing_after.attempts.len(), 1);
    assert_eq!(existing_after.operation_id, existing_before.operation_id);

    let foreign = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &foreign,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Foreign".into()),
            None,
        )
        .expect_err("alice retains foreign candidate");
    bob.create_group(
        &foreign,
        DS_DID,
        vec![ALICE_DID.into()],
        Some("Bob owns it".into()),
        None,
    )
    .expect("bob creates the conversation");
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        400,
        "ConversationAlreadyExists",
        None,
    ));
    alice
        .retry_pending_group_creation(&foreign)
        .expect_err("foreign creation while alice's attempt is fresh retains");
    assert_eq!(
        staged_creation_fingerprint(&alice, &foreign).attempts.len(),
        1
    );
    r4fix3_advance_server_and_client(
        &ds,
        &clock,
        chat_wire::GROUP_CREATION_ABANDON_AFTER_MS + 1_000,
    );
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        400,
        "ConversationAlreadyExists",
        None,
    ));
    let rejected = alice
        .retry_pending_group_creation(&foreign)
        .expect_err("receipted foreign creation after expiry is terminal");
    assert!(
        matches!(&rejected, MLSError::GroupCreationRejected {
            conversation_id,
            code,
        } if conversation_id == &foreign && code == "ForeignConversationCreation"),
        "{rejected:?}"
    );
    assert!(alice
        .pending_group_creation_status(&foreign)
        .unwrap()
        .is_none());
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
                account == ALICE_DID
                    && (url.ends_with("/xrpc/com.atproto.repo.putRecord")
                        || url.ends_with("/xrpc/com.atproto.repo.createRecord"))
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

/// Accepting moves the cursor only over its own verified entry: the coordinator's legacy
/// acceptance-commit receipt over the sequenced entry carrying Bob's signed acceptance and the
/// mandatory I13 receipt over that actor digest, entry coordinate and seq, and only when that
/// entry is the next one. An answer the coordinator did not sign or receipt is refused with
/// nothing changed and the signed acceptance still journaled; its exact replay, verified at seq
/// 2, moves the cursor from 1 to 2 onto the signed coordinates. An acceptance verified at seq 3,
/// behind Alice's seq-2 message Bob has not seen, leaves the cursor to sync, which applies that
/// message first.
///
/// Fail-before: accepting trusted any 2xx answer: the forged receipt-free one moved the cursor to
/// 2, stored its unsigned coordinates and spent the journal; an answer without a top-level `seq`
/// moved the cursor to 2 over Alice's unseen message.
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
    for (fault, expectation, reason) in [
        (
            "missingI13",
            "an answer without I13 is refused",
            "missing I13 sequencerReceipt",
        ),
        (
            "legacyProof",
            "an answer with an invalid legacy acceptanceProof is refused",
            "C33 acceptance",
        ),
    ] {
        ds.inner.lock().unwrap().next_acceptance_fault = Some(fault);
        let error = bob
            .accept_direct_request(&request_id)
            .expect_err(expectation);
        assert!(error.to_string().contains(reason), "{error}");
        assert_eq!(last_seq(&bob, &next), 1);
        assert_eq!(coords(&next), coords_before);
        assert_eq!(request(&next).consent, "incomingPending");
        assert!(
            journal(&request_id).is_some(),
            "the signed acceptance stays journaled"
        );
    }

    bob.accept_direct_request(&request_id)
        .expect("the verified acceptance is accepted");
    assert_eq!(last_seq(&bob, &next), 2);
    assert_eq!(request(&next).consent, "accepted");
    assert!(journal(&request_id).is_none());
    let (bodies, signed_next) = {
        let g = ds.inner.lock().unwrap();
        let bodies: Vec<Vec<u8>> = g
            .http_log
            .iter()
            .filter(|(account, url, _)| {
                account == BOB_DID && url.ends_with("/xrpc/blue.catbird.chat.acceptConversation")
            })
            .map(|(_, _, body)| body.clone())
            .collect();
        assert_eq!(bodies.len(), 3);
        (
            bodies,
            g.entries[&next][1]["signedRequest"]["body"]["next"].clone(),
        )
    };
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "each retry replays the journaled acceptance"
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

/// A policy-transition answer is not authority until its I13 receipt verifies. A forged answer
/// leaves the removal intent pending; the genuine sequenced echo then completes the same removal.
#[test]
fn participant_removal_policy_answer_requires_its_i13_receipt() {
    let f = send_order_fixture(false);
    let (alice, ds, cid) = (&f.alice, &f.ds, f.cid.as_str());
    let pending = || {
        alice
            .db()
            .read_tx(|tx| {
                tx.conn()
                    .query_row(
                        "SELECT COUNT(*) FROM pending_ops \
                         WHERE op_kind = 'participant_removal' \
                         AND json_extract(payload_json, '$.conversation_id') = ?1",
                        [cid],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|error| MLSError::Internal(error.to_string()))
            })
            .unwrap()
    };

    ds.inner.lock().unwrap().forge_next_policy_answer_receipt = true;
    let error = alice
        .remove_group_member(MemberRole::Admin, cid, BOB_DID)
        .expect_err("a policy answer with a forged receipt is refused");
    assert!(
        error.to_string().contains("I13") || error.to_string().contains("receipt"),
        "{error}"
    );
    assert_eq!(
        pending(),
        1,
        "the unverified answer cannot consume the intent"
    );

    alice
        .sync()
        .expect("the genuine policy echo completes removal");
    assert_eq!(pending(), 0);
    assert!(!alice
        .list_members(cid)
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

/// Older fixture cases build control entries by hand. Model the DS boundary by adding the same
/// I13 receipt production would issue, while preserving explicit `null`/forged receipt cases.
fn synthesize_missing_control_receipts(g: &mut MockDsState, cid: &str) {
    let candidates: Vec<(usize, Value)> = g
        .entries
        .get(cid)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, entry)| {
            let body_type = entry
                .pointer("/signedRequest/body/$type")
                .and_then(Value::as_str)?;
            if entry.get("sequencerReceipt").is_some()
                || body_type.ends_with("#applicationSendBody")
                || body_type.ends_with("#directRequestAcceptanceBody")
                || body_type.ends_with("#accountDeletedBody")
            {
                return None;
            }
            let kind = SignedMutationKind::from_type_id(body_type)?;
            let actor = entry.pointer("/signedRequest/body/actorDid")?.as_str()?;
            let device = entry
                .pointer("/signedRequest/body/actorDeviceId")?
                .as_str()?;
            let key = g.device_keys.get(&(actor.to_owned(), device.to_owned()))?;
            let (verified_body, _) = chat_wire::verify_signed_mutation_body_and_digest(
                &entry["signedRequest"],
                kind,
                key,
            )
            .ok()?;
            let mut entry = entry.clone();
            if entry.get("conversationId").is_none() {
                entry["conversationId"] = json!(cid);
            }
            if entry.get("entryId").is_none() {
                entry["entryId"] = verified_body.get("transitionId")?.clone();
            }
            if entry.get("receivedAt").is_none() {
                entry["receivedAt"] = entry["signedRequest"]["body"]["signedAt"].clone();
            }
            Some((index, entry))
        })
        .collect();
    for (index, mut entry) in candidates {
        let body = &entry["signedRequest"]["body"];
        let Some(coordinate) = ["next", "successor", "retired", "prior"]
            .iter()
            .find_map(|field| body.get(field))
            .cloned()
        else {
            continue;
        };
        entry["sequencerReceipt"] = control_sequencer_receipt(g, &entry, &coordinate);
        g.entries.get_mut(cid).unwrap()[index] = entry;
    }
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
fn control_sequencer_receipt(g: &MockDsState, entry: &Value, coordinate: &Value) -> Value {
    control_sequencer_receipt_for(g, entry, coordinate, DS_DID)
}

fn control_sequencer_receipt_for(
    g: &MockDsState,
    entry: &Value,
    coordinate: &Value,
    sequencer_did: &str,
) -> Value {
    let signed_request = &entry["signedRequest"];
    let body = &signed_request["body"];
    let actor_did = body["actorDid"].as_str().expect("control actor DID");
    let actor_device_id = body["actorDeviceId"]
        .as_str()
        .expect("control actor device");
    let body_type = body["$type"].as_str().expect("control body type");
    let public_key = g
        .device_keys
        .get(&(actor_did.to_owned(), actor_device_id.to_owned()))
        .expect("enrolled control actor key");
    let request_digest = if let Some(kind) = SignedMutationKind::from_type_id(body_type) {
        chat_wire::verify_signed_mutation_body_and_digest(signed_request, kind, public_key)
            .expect("valid control mutation")
            .1
    } else if body_type == "blue.catbird.chat.defs#directRequestAcceptanceBody" {
        *dr_transcript::verify_received_signed_request(
            DirectRequestKind::Accept,
            &serde_json::to_vec(signed_request).unwrap(),
            public_key,
        )
        .expect("valid direct-request acceptance")
        .request_digest()
    } else {
        panic!("known control mutation kind");
    };
    let conversation_id = entry["conversationId"]
        .as_str()
        .expect("control conversation");
    let entry_id = entry["entryId"].as_str().expect("control entry ID");
    let seq = entry["seq"].as_u64().expect("control seq");
    let generation = coordinate["generation"]
        .as_u64()
        .expect("control generation");
    let group_id = chat_wire::json_bytes(&coordinate["groupId"]).expect("control group ID");
    let epoch = coordinate["epoch"].as_u64().expect("control epoch");
    let issued_at_ms = chrono::DateTime::parse_from_rfc3339(
        entry["receivedAt"].as_str().expect("control receivedAt"),
    )
    .expect("control timestamp")
    .timestamp_millis();
    let payload = SequencerReceiptPayload {
        sequencer_did: sequencer_did.to_owned(),
        conversation_id: conversation_id.to_string(),
        group_id,
        epoch,
        sender_device_did_url: format!("{actor_did}#{actor_device_id}"),
        entry_id: entry_id.to_string(),
        archive_commitment: request_digest,
        seq,
        issued_at_ms,
    };
    let signed = match (
        sequencer_did == DS_DID,
        &g.historical_receipt_sk,
        g.rotated_sequencer_receipts,
    ) {
        (true, Some(current), true) => {
            sign_sequencer_receipt(current, &format!("{DS_DID}#mls-receipt-2"), &payload)
        }
        _ => sign_sequencer_receipt(
            &g.receipt_sk,
            &format!("{sequencer_did}#mls-receipt-1"),
            &payload,
        ),
    }
    .expect("sign control receipt");
    json!({
        "kid": signed.key_id,
        "sequencerDid": signed.payload.sequencer_did,
        "conversationId": signed.payload.conversation_id,
        "generation": generation,
        "groupId": { "$bytes": STANDARD.encode(&signed.payload.group_id) },
        "epoch": signed.payload.epoch,
        "seq": signed.payload.seq,
        "entryId": signed.payload.entry_id,
        "senderDid": actor_did,
        "senderDeviceId": actor_device_id,
        "archiveCommitment": { "$bytes": STANDARD.encode(signed.payload.archive_commitment) },
        "issuedAtMs": signed.payload.issued_at_ms,
        "signature": { "$bytes": STANDARD.encode(signed.signature) },
    })
}

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
        issued_at_ms: g.mock_clock_ms.unwrap_or(1_762_000_000_000),
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

/// Alice creates a live group with Bob and both complete the join. Eve's home is the other DS;
/// with `invite_eve`, she is invited too but accepts only when the test syncs her, so Alice's
/// add Commit comes later.
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
    let eve = live_client_homed(
        tmp.path(),
        &ds,
        "eve",
        EVE_DID,
        &uuid::Uuid::new_v4().to_string(),
        &Arc::new(MemKeyStore::new()),
        CROSS_HOME_DS_DID,
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
        [(1, "held"), (1, "stale"), (1, "stale"), (6, "accepted")],
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
        [(1, "held"), (1, "stale"), (2, "accepted")]
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
        [(3, "stale"), (4, "stale")],
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
    rebind_application_send_counter(
        ds,
        cid,
        &late,
        &enrolled_signer(alice),
        ALICE_DID,
        &f.alice_dev,
        11,
    );
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
        serde_json::to_string(&catbird_mls::MLSMessagePayload::system(
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

/// Re-sign a fixture application body with a chosen peer counter without touching its MLS
/// ciphertext or I13 receipt (the latter binds the unchanged archive commitment).
fn rebind_application_send_counter(
    ds: &SharedMockDs,
    cid: &str,
    message_id: &str,
    signer: &SignatureKeyPair,
    did: &str,
    device: &str,
    send_counter: u64,
) {
    let mut g = ds.inner.lock().unwrap();
    let entry = g
        .entries
        .get_mut(cid)
        .unwrap()
        .iter_mut()
        .find(|entry| {
            entry
                .pointer("/signedRequest/body/messageId")
                .and_then(Value::as_str)
                == Some(message_id)
        })
        .unwrap();
    let mut body = entry["signedRequest"]["body"].clone();
    body["sendCounter"] = json!(send_counter);
    entry["signedRequest"] = signed_by(signer, did, device, CanonicalOperation::SendMessage, &body);
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
    rebind_application_send_counter(
        ds,
        cid,
        &late,
        &enrolled_signer(alice),
        ALICE_DID,
        &f.alice_dev,
        11,
    );
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
    rebind_application_send_counter(
        ds,
        cid,
        &late,
        &enrolled_signer(&f.alice),
        ALICE_DID,
        &f.alice_dev,
        10,
    );
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
    assert!(alice
        .list_messages(cid, None, 100)
        .unwrap()
        .iter()
        .all(|message| message.message_id != id));
    alice
        .verify_and_reindex_history(cid)
        .expect("reindex cannot restore an unsent row");
    assert!(alice
        .list_messages(cid, None, 100)
        .unwrap()
        .iter()
        .all(|message| message.message_id != id));

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
    rebind_application_send_counter(
        ds,
        cid,
        &late,
        &enrolled_signer(alice),
        ALICE_DID,
        &f.alice_dev,
        11,
    );
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

fn seed_inert_conversation_inventory(ds: &SharedMockDs, count: usize) -> Vec<String> {
    let mut state = ds.inner.lock().unwrap();
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let cid = new_id();
        state.conversations.insert(
            cid.clone(),
            json!({
                "conversationKind": "group",
                "coordinates": {
                    "conversationId": cid.clone(),
                    "generation": 0,
                    "epoch": 0,
                    "groupId": { "$bytes": STANDARD.encode([0_u8; 32]) },
                },
                "participants": [],
            }),
        );
        ids.push(cid);
    }
    ids
}

#[test]
fn sync_paginates_conversation_inventory_past_the_server_page_limit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "inventory-pages-alice", ALICE_DID, &new_id());
    let _ = seed_inert_conversation_inventory(&ds, 101);
    ds.inner.lock().unwrap().http_log.clear();

    alice.sync().expect("complete two-page inventory sync");

    let pages: Vec<String> = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.getConversations"))
        .map(|(_, url, _)| url.clone())
        .collect();
    assert_eq!(pages.len(), 2);
    assert!(!pages[0].contains("pageCursor="));
    assert!(pages[1].contains("pageCursor=100"));
}

#[test]
fn sync_reports_repeated_conversation_inventory_cursor_as_incomplete() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "inventory-repeat-alice", ALICE_DID, &new_id());
    let ids = seed_inert_conversation_inventory(&ds, 101);
    let mut state = ds.inner.lock().unwrap();
    state.repeat_conversation_cursor = true;
    state.http_log.clear();
    drop(state);

    let error = alice.sync().expect_err("repeated cursor must not complete");
    assert!(
        matches!(&error, MLSError::SyncIncomplete { applied: 0, failures }
            if failures.len() == 1
                && failures[0].conversation_id == "<conversation-inventory>"
                && matches!(failures[0].error.as_ref(), MLSError::Cryptography(_))),
        "{error:?}"
    );
    assert_eq!(
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(_, url, _)| { url.contains("/xrpc/blue.catbird.chat.getConversations") })
            .count(),
        2,
        "a repeated cursor must stop after the repeated page"
    );
    let no_completion_sentinels = alice
        .db()
        .read_tx(|tx| {
            for cid in &ids {
                if tx
                    .get_account_meta(&format!("conversation_kind:{cid}"))?
                    .is_some()
                {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .unwrap();
    assert!(
        no_completion_sentinels,
        "an incomplete inventory must not process any page as complete"
    );
}

#[test]
fn sync_scans_every_local_conversation_past_the_two_hundred_row_page() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "local-pages-alice", ALICE_DID, &new_id());
    let mut ids = Vec::new();
    alice
        .db()
        .write_tx(|tx| {
            for _ in 0..201 {
                let cid = new_id();
                let group_id = uuid::Uuid::parse_str(&cid).unwrap().as_bytes().to_vec();
                tx.upsert_conversation(&catbird_mls::storage::ConversationRow {
                    conversation_id: cid.clone(),
                    group_id,
                    generation: 0,
                    epoch: 0,
                    last_seq: 0,
                    sequencer_did: DS_DID.into(),
                    space_uri: None,
                    title: None,
                    unread_count: 0,
                    updated_at_ms: 42,
                })?;
                ids.push(cid);
            }
            Ok(())
        })
        .unwrap();
    ds.inner.lock().unwrap().http_log.clear();

    assert_eq!(alice.sync().expect("scan every local page"), 0);
    let state = ds.inner.lock().unwrap();
    let reads = state
        .http_log
        .iter()
        .filter(|(_, url, _)| {
            url.contains("/xrpc/blue.catbird.chat.getConversationState")
                && query_map(url)
                    .get("conversationId")
                    .is_some_and(|cid| ids.contains(cid))
        })
        .count();
    assert_eq!(reads, 201);
}

#[test]
fn own_pds_ghost_device_is_exposed_as_unrecognized() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "ghost-alert-alice", ALICE_DID, &new_id());
    let ghost_id = new_id();
    let ghost_key = [0x71u8; 32];
    let put: Value = serde_json::from_slice(
        &chat_wire::build_pds_device_put_record_body_at(
            ALICE_DID,
            &ghost_id,
            &ghost_key,
            "2026-11-16T00:00:00.000Z",
        )
        .unwrap(),
    )
    .unwrap();
    ds.inner.lock().unwrap().pds_records.insert(
        (
            ALICE_DID.to_owned(),
            "blue.catbird.chat.device".to_owned(),
            ghost_id.clone(),
        ),
        put["record"].clone(),
    );

    let devices = alice.list_devices().expect("read own device directories");
    let ghost = devices
        .iter()
        .find(|device| device.device_id == ghost_id)
        .unwrap();
    assert!(
        ghost.unrecognized,
        "PDS-only chat.device must trigger the alert"
    );
    assert_eq!(ghost.status, "pds_only");
    assert_eq!(ghost.signature_public_key, ghost_key.to_vec());
    assert!(
        !devices
            .iter()
            .find(|device| device.is_current_device)
            .unwrap()
            .unrecognized
    );
}

#[test]
fn verified_own_pds_ghost_remains_visible_when_home_ds_inventory_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "ghost-alert-ds-down", ALICE_DID, &new_id());
    let ghost_id = new_id();
    let ghost_key = [0x72u8; 32];
    let put: Value = serde_json::from_slice(
        &chat_wire::build_pds_device_put_record_body_at(
            ALICE_DID,
            &ghost_id,
            &ghost_key,
            "2026-11-16T00:00:00.000Z",
        )
        .unwrap(),
    )
    .unwrap();
    {
        let mut state = ds.inner.lock().unwrap();
        state.pds_records.insert(
            (
                ALICE_DID.to_owned(),
                "blue.catbird.chat.device".to_owned(),
                ghost_id.clone(),
            ),
            put["record"].clone(),
        );
        state.xrpc_failures.push((
            "/xrpc/blue.catbird.chat.getOwnDevices",
            503,
            "Unavailable",
            None,
        ));
    }

    let devices = alice
        .list_devices()
        .expect("verified PDS inventory remains available");
    let ghost = devices
        .iter()
        .find(|device| device.device_id == ghost_id)
        .unwrap();
    assert_eq!(ghost.status, "ds_unavailable");
    assert!(ghost.unrecognized);
    assert!(devices
        .iter()
        .any(|device| device.is_current_device && !device.unrecognized));
}

#[test]
fn own_device_inventory_refuses_a_pds_list_without_repo_signing_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "ghost-alert-no-repo-key", ALICE_DID, &new_id());
    ds.archive_auth.set_omit_atproto_key_for(Some(ALICE_DID));

    let error = alice
        .list_devices()
        .expect_err("an unsigned PDS directory cannot establish own-device identity");
    assert!(error.to_string().contains("#atproto"), "{error}");
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
    let pending_recoveries = ds
        .inner
        .lock()
        .unwrap()
        .leaf_recoveries
        .remove(&gcid)
        .expect("bob recovery request");
    r.alice
        .sync()
        .expect("alice records bob's acceptance before fulfillment");
    ds.inner
        .lock()
        .unwrap()
        .leaf_recoveries
        .insert(gcid.clone(), pending_recoveries);
    // The fulfiller has no verified roster, so this genuine recovery Welcome carries no roster
    // attestation. The joiner must clear any older baseline and every admission marker.
    r.alice
        .db()
        .write_tx(|tx| {
            let roster_key = chat_wire::conversation_roster_key(&gcid);
            if let Some(raw) = tx.get_account_meta(&roster_key)? {
                let roster: Value = serde_json::from_str(&raw)?;
                for did in roster.as_object().into_iter().flatten().map(|(did, _)| did) {
                    tx.delete_account_meta(&chat_wire::verified_participant_admission_key(
                        &gcid, did,
                    ))?;
                }
            }
            tx.delete_account_meta(&roster_key)
        })
        .unwrap();
    r.alice.sync().expect("alice fulfills bob's recovery");
    let recovery_key = chat_wire::own_leaf_recovery_key(&gcid);
    let recovery_before = bob
        .db()
        .read_tx(|tx| tx.get_account_meta(&recovery_key))
        .unwrap();
    let (genuine_fulfillment, genuine_welcomes) = {
        let g = ds.inner.lock().unwrap();
        (
            g.entries[&gcid].last().unwrap().clone(),
            g.pending_welcomes[&(BOB_DID.to_string(), r.bob_dev.clone())].clone(),
        )
    };
    let genuine_seq = genuine_fulfillment["seq"].as_i64().unwrap();
    let acks_before = ds.inner.lock().unwrap().acked_welcomes.len();
    for fault in ["absent", "forged", "relabelled"] {
        let mut fulfillment = genuine_fulfillment.clone();
        let mut welcomes = genuine_welcomes.clone();
        match fault {
            "absent" => fulfillment["sequencerReceipt"] = Value::Null,
            "forged" => {
                fulfillment["sequencerReceipt"]["signature"] =
                    json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
            }
            "relabelled" => {
                fulfillment["seq"] = json!(genuine_seq + 1);
                for welcome in &mut welcomes {
                    welcome["transitionSeq"] = json!(genuine_seq + 1);
                }
            }
            _ => unreachable!(),
        }
        {
            let mut g = ds.inner.lock().unwrap();
            *g.entries.get_mut(&gcid).unwrap().last_mut().unwrap() = fulfillment;
            g.pending_welcomes
                .insert((BOB_DID.to_string(), r.bob_dev.clone()), welcomes);
        }
        let error = bob
            .sync()
            .expect_err("an unverified fulfillment receipt cannot install its Welcome");
        assert!(
            error.to_string().to_ascii_lowercase().contains("receipt"),
            "{fault}: unexpected error: {error:?}"
        );
        assert!(
            bob.list_conversations(None, 20)
                .unwrap()
                .iter()
                .all(|row| row.conversation_id != gcid),
            "{fault}: installed the group"
        );
        assert_eq!(
            bob.db()
                .read_tx(|tx| tx.get_account_meta(&recovery_key))
                .unwrap(),
            recovery_before,
            "{fault}: consumed the pending recovery"
        );
        assert_eq!(
            ds.inner.lock().unwrap().acked_welcomes.len(),
            acks_before,
            "{fault}: acknowledged the refused Welcome"
        );
    }
    {
        let mut g = ds.inner.lock().unwrap();
        *g.entries.get_mut(&gcid).unwrap().last_mut().unwrap() = genuine_fulfillment;
        g.pending_welcomes
            .insert((BOB_DID.to_string(), r.bob_dev.clone()), genuine_welcomes);
    }
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
    let stale_roster_key = chat_wire::conversation_roster_key(&gcid);
    let stale_marker_key = chat_wire::verified_participant_admission_key(&gcid, EVE_DID);
    bob.db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &stale_roster_key,
                &json!({ (EVE_DID): { "role": "member", "status": "active" } }).to_string(),
                0,
            )?;
            tx.put_account_meta(&stale_marker_key, "true", 0)
        })
        .unwrap();
    bob.sync()
        .expect("bob joins from the fulfillment's Welcome");
    let stored = bob
        .db()
        .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{gcid}")))
        .unwrap()
        .expect("joined coordinates");
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), signed_next);
    bob.db()
        .read_tx(|tx| {
            assert!(
                tx.get_account_meta(&stale_roster_key)?.is_none(),
                "a no-roster Welcome must clear the stale roster"
            );
            assert!(
                tx.get_account_meta(&stale_marker_key)?.is_none(),
                "a no-roster Welcome must clear stale admission markers"
            );
            Ok(())
        })
        .unwrap();
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
/// recipient accepting that request; and a mandatory I13 receipt under the coordinator method it
/// names, binding this seq, signed-request digest and successor coordinate. Each forged, unsigned,
/// untyped, wrong-roster, wrong-request, wrong-transition or wrong-receipt variant of Bob's
/// acceptance fails Alice's sync and leaves her request's consent, coordinates and cursor as they
/// were. The genuine receipted entry then advances her cursor exactly to its seq.
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
    let mut missing_receipt = genuine.clone();
    missing_receipt
        .as_object_mut()
        .unwrap()
        .remove("sequencerReceipt");
    let mut wrong_seq_receipt = genuine.clone();
    let mut other_seq = genuine.clone();
    other_seq["seq"] = json!(seq + 1);
    wrong_seq_receipt["sequencerReceipt"] = {
        let g = ds.inner.lock().unwrap();
        control_sequencer_receipt(&g, &other_seq, &genuine["signedRequest"]["body"]["next"])
    };
    let other_digest = resigned(&bob_signer, &|body: &mut Value| {
        body["requestId"] = json!(new_id())
    });
    let mut wrong_digest_receipt = genuine.clone();
    wrong_digest_receipt["sequencerReceipt"] = {
        let g = ds.inner.lock().unwrap();
        control_sequencer_receipt(&g, &other_digest, &genuine["signedRequest"]["body"]["next"])
    };
    let mut wrong_kid_receipt = genuine.clone();
    wrong_kid_receipt["sequencerReceipt"]["kid"] = json!(format!("{DS_DID}#never-published"));
    let mut wrong_authority_receipt = genuine.clone();
    wrong_authority_receipt["sequencerReceipt"]["sequencerDid"] =
        json!("did:web:other-sequencer.test");
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
            "missing I13 receipt",
            missing_receipt,
            "missing I13 sequencerReceipt",
        ),
        ("receipt for another seq", wrong_seq_receipt, "I13"),
        (
            "receipt for another signed-request digest",
            wrong_digest_receipt,
            "I13",
        ),
        (
            "receipt naming an unpublished kid",
            wrong_kid_receipt,
            "sequencerReceipt kid",
        ),
        (
            "receipt naming another sequencerDid",
            wrong_authority_receipt,
            "I13 sequencerReceipt verify failed",
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

    serve(genuine.clone());
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

/// A cross-home `participantAcceptanceEntry` takes effect only once it verifies: its own
/// sequencing receipt, PDS-authorized actor signature, and either the exact pending provenance
/// in the member-authenticated baseline or the signed historical invitation. Historical
/// invitations must retain their own valid receipt, original sequence, and exact invitee
/// provenance. Closed, forged, unknown, misattributed, never-invited, and skipping acceptances
/// leave cursor, coordinates, roster, and recovery authorization unchanged. The genuine pending
/// invitation and acceptance then apply, including on a later joiner with only the attested
/// pending baseline.
#[test]
fn participant_acceptance_takes_effect_only_with_its_verified_invitation() {
    let f = send_order_fixture(true);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    assert_ne!(CROSS_HOME_DS_DID, DS_DID);
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
    assert_eq!(genuine["sequencerReceipt"]["sequencerDid"], DS_DID);
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
            entry.as_object_mut().unwrap().remove("sequencerReceipt");
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
            "invitation chain: no invitation",
        ),
        (
            "never-invited actor",
            resigned(&carol_signer, CAROL_DID, &carol_dev, &|_| {}),
            "invitation chain: no invitation",
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
    let state = || {
        (
            last_seq(alice, cid),
            stored_coordinates(alice, cid),
            serde_json::to_value(alice.list_members(cid).unwrap()).unwrap(),
            alice
                .db()
                .read_tx(|tx| tx.get_account_meta(&chat_wire::leaf_recovery_authorization_key(cid)))
                .unwrap(),
        )
    };
    let invitation_transition =
        genuine["signedRequest"]["body"]["invitationProvenance"]["invitationTransitionId"].clone();
    let invitation = ds.inner.lock().unwrap().entries[cid]
        .iter()
        .find(|entry| {
            entry["signedRequest"]["body"]["transitionId"] == invitation_transition
                && matches!(
                    chat_wire::signed_entry_kind(entry),
                    Ok(SignedMutationKind::Creation | SignedMutationKind::PolicyTransition)
                )
        })
        .unwrap()
        .clone();
    let invitation_seq = invitation["seq"].as_i64().unwrap();
    let serve_invitation = |replacement: Value| {
        let mut state = ds.inner.lock().unwrap();
        let slot = state
            .entries
            .get_mut(cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["transitionId"] == invitation_transition)
            .unwrap();
        *slot = replacement;
    };
    let mut missing_invitation_receipt = invitation.clone();
    missing_invitation_receipt["sequencerReceipt"] = Value::Null;
    let mut forged_invitation_receipt = invitation.clone();
    forged_invitation_receipt["sequencerReceipt"]["signature"] = json!(STANDARD.encode([9u8; 64]));
    let mut relabelled_after_closure = invitation.clone();
    relabelled_after_closure["seq"] = json!(invitation_seq + 1);
    // A pending participant's no-provenance control must authenticate through the historical
    // invitation branch; unlike an acceptance, it cannot use the pending roster row directly.
    let historical_control = {
        let request_id = new_id();
        let prior: Value = serde_json::from_str(before.as_deref().unwrap()).unwrap();
        let body = json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
            "resetRequestId": request_id,
            "idempotencyKey": request_id,
            "authGeneration": 1,
            "prior": prior,
            "reason": "manualRecovery",
            "signedAt": "2026-11-07T00:00:00.000Z",
        });
        let mut entry = json!({
            "$type": "blue.catbird.chat.defs#resetRequestEntry",
            "entryId": request_id,
            "conversationId": cid,
            "seq": seq,
            "receivedAt": body["signedAt"],
            "signedRequest": signed_by(
                &eve_signer,
                EVE_DID,
                &eve_dev,
                CanonicalOperation::RequestReset,
                &body,
            ),
        });
        entry["sequencerReceipt"] = {
            let state = ds.inner.lock().unwrap();
            control_sequencer_receipt(&state, &entry, &body["prior"])
        };
        entry
    };
    let historical_before = state();
    for (name, historical, closed, reason) in [
        (
            "missing historical invitation receipt",
            missing_invitation_receipt,
            false,
            "I13",
        ),
        (
            "forged historical invitation receipt",
            forged_invitation_receipt,
            false,
            "I13",
        ),
        (
            "invitation relabelled after its closure",
            relabelled_after_closure,
            true,
            "I13",
        ),
    ] {
        serve(historical_control.clone());
        serve_invitation(historical);
        if closed {
            alice
                .db()
                .write_tx(|tx| {
                    tx.put_account_meta(
                        &chat_wire::invitation_closed_key(cid, EVE_DID),
                        &invitation_seq.to_string(),
                        0,
                    )
                })
                .unwrap();
        }
        let error = alice.sync().expect_err(name).to_string();
        assert!(error.contains(reason), "{name}: {error}");
        assert_eq!(state(), historical_before, "{name}");
        serve_invitation(invitation.clone());
        alice
            .db()
            .write_tx(|tx| tx.delete_account_meta(&chat_wire::invitation_closed_key(cid, EVE_DID)))
            .unwrap();
    }
    let historical_before = state();
    serve(genuine.clone());
    alice
        .db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &chat_wire::invitation_closed_key(cid, EVE_DID),
                &(seq - 1).to_string(),
                0,
            )
        })
        .unwrap();
    let error = alice
        .sync()
        .expect_err("a closed invitation cannot be accepted")
        .to_string();
    assert!(
        error.contains("the invitation is no longer pending"),
        "{error}"
    );
    assert_eq!(state(), historical_before);
    alice
        .db()
        .write_tx(|tx| tx.delete_account_meta(&chat_wire::invitation_closed_key(cid, EVE_DID)))
        .unwrap();
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

    // Bob joined after the invitation and applies the acceptance from his member-authenticated
    // pending baseline, without reading the invitation entry.
    ds.inner
        .lock()
        .unwrap()
        .readable_from
        .insert(f.bob_dev.clone(), seq - 1);
    bob.sync()
        .expect("the attested pending invitation verifies the acceptance");
    assert_eq!(
        (last_seq(bob, cid), stored_coordinates(bob, cid)),
        (seq, Some(next))
    );
}

/// Even when an invitation with the claimed transition ID is in the same verified batch, its
/// signed participant row must name the accepting actor. A transition-ID-only match is not proof.
#[test]
fn participant_acceptance_matches_the_found_invitation_provenance() {
    let f = send_order_fixture(true);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    f.eve.sync().expect("Eve publishes her acceptance");
    ds.inner.lock().unwrap().leaf_recoveries.remove(cid);
    let genuine = ds.inner.lock().unwrap().entries[cid]
        .last()
        .unwrap()
        .clone();
    let acceptance_seq = genuine["seq"].as_i64().unwrap();
    let eve_device = genuine["signedRequest"]["body"]["actorDeviceId"]
        .as_str()
        .unwrap()
        .to_owned();
    let original_transition =
        genuine["signedRequest"]["body"]["invitationProvenance"]["invitationTransitionId"].clone();
    let original_invitation = ds.inner.lock().unwrap().entries[cid]
        .iter()
        .find(|entry| entry["signedRequest"]["body"]["transitionId"] == original_transition)
        .unwrap()
        .clone();
    assert_eq!(
        chat_wire::signed_entry_kind(&original_invitation).unwrap(),
        SignedMutationKind::Creation
    );
    let carol_device = new_id();
    let _carol = enrolled(&f.tmp, ds, "provenance-carol", CAROL_DID, &carol_device);

    let claimed_transition = new_id();
    let false_invitation = {
        let mut entry = original_invitation;
        let mut body = entry["signedRequest"]["body"].clone();
        body["transitionId"] = json!(claimed_transition);
        body["idempotencyKey"] = json!(claimed_transition);
        let invitee = body["manifest"]["participants"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["userDid"] == EVE_DID)
            .unwrap();
        invitee["userDid"] = json!(CAROL_DID);
        invitee["invitationProvenance"]["invitationTransitionId"] = json!(claimed_transition);
        entry["entryId"] = json!(claimed_transition);
        entry["seq"] = json!(acceptance_seq);
        entry["signedRequest"] = signed_by(
            &enrolled_signer(alice),
            ALICE_DID,
            &f.alice_dev,
            CanonicalOperation::CreateConversation,
            &body,
        );
        entry["sequencerReceipt"] = {
            let state = ds.inner.lock().unwrap();
            control_sequencer_receipt(&state, &entry, &body["next"])
        };
        entry
    };
    let false_acceptance = {
        let mut entry = genuine;
        let mut body = entry["signedRequest"]["body"].clone();
        body["invitationProvenance"]["invitationTransitionId"] = json!(claimed_transition);
        entry["seq"] = json!(acceptance_seq + 1);
        entry["signedRequest"] = signed_by(
            &enrolled_signer(&f.eve),
            EVE_DID,
            &eve_device,
            CanonicalOperation::AcceptConversation,
            &body,
        );
        entry["sequencerReceipt"] = {
            let state = ds.inner.lock().unwrap();
            control_sequencer_receipt(&state, &entry, &body["next"])
        };
        entry
    };
    {
        let mut state = ds.inner.lock().unwrap();
        *state.entries.get_mut(cid).unwrap().last_mut().unwrap() = false_invitation;
        state.entries.get_mut(cid).unwrap().push(false_acceptance);
    }

    let error = alice
        .sync()
        .expect_err("the found invitation names another invitee")
        .to_string();
    assert!(
        error.contains("does not invite this participant"),
        "{error}"
    );
    assert_eq!(
        last_seq(alice, cid),
        acceptance_seq,
        "only the preceding valid control moved the cursor"
    );
}

#[test]
fn forged_participant_acceptance_on_rosterless_c33_is_a_protocol_violation() {
    let request = C33Request::new();
    let (ds, alice, bob, cid) = (
        &request.ds,
        &request.alice,
        &request.bob,
        request.cid.as_str(),
    );
    bob.sync().expect("honest C33 opening imports");
    let request_id = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0)
        .request_id;
    bob.accept_direct_request(&request_id)
        .expect("honest C33 acceptance succeeds");
    alice.sync().expect("honest C33 acceptance syncs");
    assert_eq!(alice.list_requests(None).unwrap()[0].consent, "accepted");

    let (prior, inviter_device, next_seq) = {
        let state = ds.inner.lock().unwrap();
        let entries = &state.entries[cid];
        let opening = &entries[0]["signedRequest"]["body"];
        let acceptance = entries
            .iter()
            .find(|entry| entry["$type"] == "blue.catbird.chat.defs#directRequestAcceptanceEntry")
            .expect("honest direct acceptance");
        (
            acceptance["signedRequest"]["body"]["next"].clone(),
            opening["actorDeviceId"].as_str().unwrap().to_owned(),
            acceptance["seq"].as_i64().unwrap() + 1,
        )
    };
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);

    // Reuse the complete generated participant-acceptance shape, then bind it to this C33
    // conversation. A sequencer can carry this validly signed/receipted but protocol-invalid row.
    let template = send_order_fixture(true);
    template.eve.sync().expect("template acceptance");
    let mut body = template.ds.inner.lock().unwrap().entries[&template.cid]
        .last()
        .unwrap()["signedRequest"]["body"]
        .clone();
    let transition_id = new_id();
    body["transitionId"] = json!(transition_id);
    body["idempotencyKey"] = json!(transition_id);
    body["recoveryRequestId"] = json!(new_id());
    body["prior"] = prior;
    body["next"] = next.clone();
    body["invitationProvenance"] = json!({
        "invitationTransitionId": ds.inner.lock().unwrap().entries[cid][0]["entryId"],
        "invitedByDid": ALICE_DID,
        "invitedByDeviceId": inviter_device,
    });
    let mut forged = json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
        "entryId": transition_id,
        "conversationId": cid,
        "seq": next_seq,
        "signedRequest": signed_by(
            &enrolled_signer(bob),
            BOB_DID,
            &request.bob_dev,
            CanonicalOperation::AcceptConversation,
            &body,
        ),
        "receivedAt": body["signedAt"],
    });
    forged["sequencerReceipt"] = {
        let state = ds.inner.lock().unwrap();
        control_sequencer_receipt(&state, &forged, &next)
    };

    let local = || {
        alice
            .db()
            .read_tx(|tx| {
                Ok((
                    tx.get_conversation(cid)?.expect("conversation"),
                    tx.get_account_meta(&format!("conversation_coords:{cid}"))?,
                    tx.get_account_meta(&chat_wire::conversation_roster_key(cid))?,
                    tx.list_messages(cid, None, 100)?,
                ))
            })
            .unwrap()
    };
    let before = local();
    assert!(
        before.2.is_none(),
        "C33 legitimately has no verified roster"
    );
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(forged);

    match alice
        .sync()
        .expect_err("participant acceptance is invalid C33 traffic")
    {
        MLSError::SyncIncomplete { applied, failures } => {
            assert_eq!(applied, 0);
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].conversation_id, cid);
            assert!(matches!(
                failures[0].error.as_ref(),
                MLSError::Cryptography(message) if message.contains("invitation chain")
            ));
        }
        error => panic!("expected typed per-conversation failure, got {error:?}"),
    }
    assert_eq!(local(), before, "the invalid entry changes no local state");
    assert_eq!(alice.list_requests(None).unwrap()[0].consent, "accepted");
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

fn missing_metadata_receipt_control() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    alice
        .update_group_metadata(cid, "Receipt gate".into(), String::new(), None)
        .expect("metadata transition");
    let genuine = ds.inner.lock().unwrap().entries[cid]
        .last()
        .unwrap()
        .clone();
    assert_eq!(genuine["$type"], "blue.catbird.chat.defs#metadataEntry");
    let seq = genuine["seq"].as_i64().unwrap();
    let before = (
        bob.get_group_metadata(cid).unwrap(),
        stored_coordinates(bob, cid),
        last_seq(bob, cid),
        ds.inner.lock().unwrap().acked_watermarks.clone(),
    );
    let mut missing = genuine.clone();
    missing["sequencerReceipt"] = Value::Null;
    *ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .last_mut()
        .unwrap() = missing;
    let error = bob.sync().expect_err("metadata without I13").to_string();
    assert!(error.contains("missing sequencerReceipt"), "{error}");
    assert_eq!(
        (
            bob.get_group_metadata(cid).unwrap(),
            stored_coordinates(bob, cid),
            last_seq(bob, cid),
            ds.inner.lock().unwrap().acked_watermarks.clone(),
        ),
        before
    );
    *ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .last_mut()
        .unwrap() = genuine;
    bob.sync().expect("receipted metadata applies");
    assert_eq!(last_seq(bob, cid), seq);
}

fn missing_zero_leaf_leave_receipt_control() {
    let f = send_order_fixture(true);
    let (ds, cid, bob) = (&f.ds, f.cid.as_str(), &f.bob);
    let prior: Value = serde_json::from_str(&stored_coordinates(bob, cid).unwrap()).unwrap();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
    let transition_id = new_id();
    let eve_device = enrolled_device(ds, EVE_DID);
    let body = json!({
        "$type": "blue.catbird.chat.defs#zeroLeafLeaveBody",
        "signatureDomain": "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0",
        "transitionId": transition_id,
        "idempotencyKey": transition_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next,
        "signedAt": "2026-11-10T00:00:00.000Z",
    });
    let seq = ds.entry_count(cid) + 1;
    let mut genuine = json!({
        "$type": "blue.catbird.chat.defs#zeroLeafLeaveEntry",
        "entryId": transition_id,
        "conversationId": cid,
        "seq": seq,
        "receivedAt": body["signedAt"],
        "signedRequest": signed_by(
            &enrolled_signer(&f.eve),
            EVE_DID,
            &eve_device,
            CanonicalOperation::RequestLeave,
            &body,
        ),
    });
    genuine["sequencerReceipt"] = {
        let g = ds.inner.lock().unwrap();
        control_sequencer_receipt(&g, &genuine, &next)
    };
    let before = (
        stored_coordinates(bob, cid),
        last_seq(bob, cid),
        bob.list_members(cid).unwrap(),
        ds.inner.lock().unwrap().acked_watermarks.clone(),
    );
    let mut missing = genuine.clone();
    missing["sequencerReceipt"] = Value::Null;
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(missing);
    let error = bob
        .sync()
        .expect_err("zero-leaf leave without I13")
        .to_string();
    assert!(error.contains("missing sequencerReceipt"), "{error}");
    assert_eq!(
        (
            stored_coordinates(bob, cid),
            last_seq(bob, cid),
            bob.list_members(cid).unwrap(),
            ds.inner.lock().unwrap().acked_watermarks.clone(),
        ),
        before
    );
    *ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .last_mut()
        .unwrap() = genuine;
    bob.sync().expect("receipted zero-leaf leave applies");
    assert_eq!(last_seq(bob, cid), seq);
}

fn missing_leave_commit_fulfillment_receipt_control() {
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
            .expect("removal Commit");
        serde_json::from_slice::<Value>(request.body.as_deref().unwrap()).unwrap()["signedRequest"]
            ["body"]
            .clone()
    };
    let mut body = removal.clone();
    body["$type"] = json!("blue.catbird.chat.defs#leaveCommitFulfillmentBody");
    body["signatureDomain"] = json!("CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0");
    body["leaveRequestId"] = json!(new_id());
    let seq = ds.entry_count(cid) + 1;
    let mut genuine = json!({
        "$type": "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
        "entryId": body["transitionId"],
        "conversationId": cid,
        "seq": seq,
        "receivedAt": body["signedAt"],
        "signedRequest": signed_by(
            &enrolled_signer(alice),
            ALICE_DID,
            &f.alice_dev,
            CanonicalOperation::SubmitTransition,
            &body,
        ),
    });
    genuine["sequencerReceipt"] = {
        let g = ds.inner.lock().unwrap();
        control_sequencer_receipt(&g, &genuine, &body["next"])
    };
    let state = || {
        let row = bob
            .db()
            .read_tx(|tx| tx.get_conversation(cid))
            .unwrap()
            .unwrap();
        (
            row.epoch,
            row.last_seq,
            stored_coordinates(bob, cid),
            bob.list_members(cid).unwrap(),
            ds.inner.lock().unwrap().acked_watermarks.clone(),
        )
    };
    let before = state();
    let mut missing = genuine.clone();
    missing["sequencerReceipt"] = Value::Null;
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .push(missing);
    let error = bob
        .sync()
        .expect_err("leave fulfillment without I13")
        .to_string();
    assert!(error.contains("missing sequencerReceipt"), "{error}");
    assert_eq!(state(), before);
    *ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .last_mut()
        .unwrap() = genuine;
    bob.sync().expect("receipted leave fulfillment applies");
    assert_eq!(last_seq(bob, cid), seq);
}

#[test]
fn metadata_entry_requires_its_sequencer_receipt() {
    missing_metadata_receipt_control();
}

#[test]
fn zero_leaf_leave_entry_requires_its_sequencer_receipt() {
    missing_zero_leaf_leave_receipt_control();
}

#[test]
fn leave_commit_fulfillment_requires_its_sequencer_receipt() {
    missing_leave_commit_fulfillment_receipt_control();
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

/// A verified `resetActivationEntry` retires this device's old-generation leaf (`CHAT_PROTOCOL`
/// §6: every old leaf but the activator only closes), from exactly the state this device holds.
/// Alice activates a reset; Bob, an old leaf, is served it first retiring a coordinate he already
/// left and then opening a successor on the retired group ID: each fails his sync with nothing
/// changed. The genuine one moves his conversation to the successor generation's group,
/// coordinate and cursor in one step, erases the old group and acknowledges nothing. The retired
/// row then reads nothing past its reset: the same activation replayed at the next seq and an
/// old-generation message are never read.
///
/// Fail-before: a reset activation only moved the cursor, so Bob kept the retired group as
/// current and applied old-generation entries after the reset.
#[test]
fn reset_activation_retires_the_old_leaf_from_exactly_its_current_state() {
    let f = send_order_fixture(false);
    let (ds, cid, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let prior: Value = serde_json::from_str(&stored_coordinates(bob, cid).unwrap()).unwrap();
    let version = prior["stateVersion"].as_i64().unwrap();
    let generation = prior["generation"].as_i64().unwrap();
    let creation = ds.inner.lock().unwrap().entries[cid][0].clone();
    let mut participants = creation["signedRequest"]["body"]["manifest"]["participants"].clone();
    for participant in participants.as_array_mut().unwrap() {
        participant["status"] = json!("active");
    }
    let alice_signer = enrolled_signer(alice);
    let alice_key = alice_signer.public().to_vec();
    let successor_group = [0x5a_u8; 32];
    let activation = |prior: &Value, successor_group: &[u8]| {
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
        retired["lifecycle"] = json!("superseded");
        let bytes = |byte: u8| json!({ "$bytes": STANDARD.encode([byte; 32]) });
        let successor = json!({
            "conversationId": cid, "generation": generation + 1, "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(successor_group) }, "epoch": 0,
            "groupContextHash": bytes(0x61), "confirmationTag": bytes(0x62),
            "lifecycle": "active",
        });
        let (transition, ciphertext, group_info) = (new_id(), [0x63_u8; 48], [0x64_u8; 64]);
        let key_id = derive_key_id(&alice_key);
        let body = json!({
            "$type": "blue.catbird.chat.defs#resetActivationBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
            "resetRequestId": new_id(), "transitionId": transition, "idempotencyKey": transition,
            "conversationKind": "group", "authGeneration": 1,
            "prior": prior, "retired": retired, "successor": successor,
            "manifest": {
                "participants": participants,
                "actorLeaf": { "userDid": ALICE_DID, "deviceId": f.alice_dev, "leafOrigin": "genesis" },
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage", "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode(group_info) },
                "sha256": STANDARD.encode(Sha256::digest(group_info)),
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": 1, "authorDeviceId": f.alice_dev,
                    "authorDid": ALICE_DID, "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active", "originSeq": 1,
                    "originTransitionId": transition, "roleAtOrigin": "admin",
                    "signaturePublicKey": { "$bytes": STANDARD.encode(&alice_key) },
                },
                "ciphertext": { "$bytes": STANDARD.encode(ciphertext) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "conversationId": STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes()),
                    "generation": generation + 1, "epoch": 0,
                    "groupId": { "$bytes": STANDARD.encode(successor_group) },
                    "groupContextHash": bytes(0x61), "confirmationTag": bytes(0x62),
                },
                "metadataVersion": 2, "nonce": { "$bytes": STANDARD.encode([0x65_u8; 12]) },
                "originTransitionId": transition,
            },
            "signedAt": "2026-11-07T00:00:00.000Z",
        });
        signed_by(
            &alice_signer,
            ALICE_DID,
            &f.alice_dev,
            CanonicalOperation::ActivateReset,
            &body,
        )
    };
    let serve = |signed_request: Value| {
        let mut g = ds.inner.lock().unwrap();
        let entries = g.entries.get_mut(cid).unwrap();
        let seq = entries.len() as i64 + 1;
        entries.push(json!({
            "$type": "blue.catbird.chat.defs#resetActivationEntry",
            "entryId": new_id(), "conversationId": cid, "seq": seq,
            "receivedAt": "2026-11-07T00:00:00.000Z", "signedRequest": signed_request,
        }));
        seq
    };
    let unserve = || {
        ds.inner.lock().unwrap().entries.get_mut(cid).unwrap().pop();
    };
    let row = || {
        bob.db()
            .read_tx(|tx| tx.get_conversation(cid))
            .unwrap()
            .unwrap()
    };
    let before = (row(), stored_coordinates(bob, cid));

    let mut left = prior.clone();
    left["stateVersion"] = json!(version - 1);
    for (case, request, reason) in [
        (
            "a prior Bob already left",
            activation(&left, &successor_group),
            "prior is not this device's current coordinate",
        ),
        (
            "a successor on the retired group",
            activation(&prior, &chat_wire::json_bytes(&prior["groupId"]).unwrap()),
            "successor is not a fresh group",
        ),
    ] {
        serve(request);
        let error = bob.sync().expect_err(case).to_string();
        assert!(error.contains(reason), "{case}: {error}");
        assert_eq!((row(), stored_coordinates(bob, cid)), before, "{case}");
        assert!(bob.list_members(cid).is_ok(), "{case}: the old group stays");
        unserve();
    }

    let acked = || {
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.to_owned(), f.bob_dev.clone()))
            .copied()
    };
    let acked_before = acked();
    let genuine = activation(&prior, &successor_group);
    let reset_seq = serve(genuine.clone());
    bob.sync()
        .expect("the genuine activation retires bob's leaf");
    let retired = row();
    assert_eq!(
        (
            retired.generation,
            retired.group_id.as_slice(),
            retired.epoch,
            retired.last_seq
        ),
        (generation + 1, successor_group.as_slice(), 0, reset_seq)
    );
    let successor =
        chat_wire::canonicalize_wire_coordinate(&genuine["body"]["successor"], Some(cid)).unwrap();
    assert_eq!(stored_coordinates(bob, cid), Some(successor.to_string()));
    assert!(bob.list_members(cid).is_err(), "the old group is erased");
    assert!(bob.send_message(cid, &new_id(), "retired").is_err());
    assert_eq!(acked(), acked_before, "nothing acknowledged past the reset");
    bob.sync().expect("nothing past the reset is read");

    serve(genuine);
    // Alice never journaled this activation signed with her key, so her own sync would refuse
    // it; her old-generation send is sequenced all the same.
    let _ = alice.send_message(cid, &new_id(), "old generation");
    assert_eq!(ds.entry_count(cid), reset_seq + 2);
    bob.sync()
        .expect("a retired row reads nothing past its reset");
    assert_eq!(row(), retired);
    assert_eq!(stored_coordinates(bob, cid), Some(successor.to_string()));
}

/// One conversation's failing entry never stops another conversation's sync. Alice and Bob
/// share two groups; mls-ds serves Bob, in the first, a genuine message and then one whose
/// signature no longer verifies, and in the second a genuine message. Bob's sync returns the
/// typed aggregate naming only the first conversation, with its cursor and acknowledgement at
/// the genuine message before the forged one; the second conversation's message applies and is
/// acknowledged. The forged entry keeps failing only its own conversation.
///
/// Fail-before: the first failing conversation returned from `sync` before its verified prefix
/// was acknowledged and before any later conversation was read.
#[test]
fn one_conversations_failing_entry_never_stops_another() {
    let f = send_order_fixture(false);
    let (ds, first, alice, bob) = (&f.ds, f.cid.as_str(), &f.alice, &f.bob);
    let second = new_id();
    alice
        .create_group(
            &second,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Second".into()),
            None,
        )
        .expect("alice creates a second group");
    bob.sync().expect("bob accepts");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");

    let (genuine, forged, other) = (new_id(), new_id(), new_id());
    alice.send_message(first, &genuine, "genuine").unwrap();
    alice.send_message(first, &forged, "forged").unwrap();
    alice.send_message(&second, &other, "other").unwrap();
    let seq_of = |cid: &str, message_id: &str| {
        let mut g = ds.inner.lock().unwrap();
        let entry = g
            .entries
            .get_mut(cid)
            .unwrap()
            .iter_mut()
            .find(|entry| entry["signedRequest"]["body"]["messageId"] == message_id)
            .unwrap();
        if message_id == forged {
            entry["signedRequest"]["signature"] = json!(STANDARD.encode([7u8; 64]));
        }
        entry["seq"].as_i64().unwrap()
    };
    let (genuine_seq, forged_seq, other_seq) = (
        seq_of(first, &genuine),
        seq_of(first, &forged),
        seq_of(&second, &other),
    );
    assert_eq!(forged_seq, genuine_seq + 1);
    let acked = |cid: &str| {
        ds.inner
            .lock()
            .unwrap()
            .acked_watermarks
            .get(&(cid.to_owned(), f.bob_dev.clone()))
            .copied()
    };
    let has = |cid: &str, message_id: &str| {
        bob.list_messages(cid, None, 100)
            .unwrap()
            .iter()
            .any(|row| row.message_id == message_id)
    };

    for _ in 0..2 {
        let error = bob
            .sync()
            .expect_err("the forged entry fails its conversation");
        let MLSError::SyncIncomplete { failures, .. } = &error else {
            panic!("not the typed aggregate: {error:?}");
        };
        assert_eq!(failures.len(), 1, "{error}");
        assert_eq!(failures[0].conversation_id, first);
        assert!(
            failures[0]
                .error
                .to_string()
                .contains("verify signed transition"),
            "{error}"
        );
        assert_eq!(
            (last_seq(bob, first), acked(first)),
            (genuine_seq, Some(genuine_seq))
        );
        assert!(has(first, &genuine) && !has(first, &forged));
        assert_eq!(
            (last_seq(bob, &second), acked(&second)),
            (other_seq, Some(other_seq))
        );
        assert!(has(&second, &other));
    }

    // A transiently refused creation is another conversation-scoped failure: it must not starve
    // this account's established conversation, and Retry-After suppresses an immediate resend.
    let pending = send_order_fixture(false);
    let stuck = new_id();
    pending.ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        Some("5"),
    ));
    pending
        .alice
        .create_group(
            &stuck,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Stuck creation".into()),
            None,
        )
        .expect_err("the creation is transiently refused");
    let incoming = new_id();
    pending
        .bob
        .send_message(&pending.cid, &incoming, "healthy conversation")
        .unwrap();
    let error = pending
        .alice
        .sync()
        .expect_err("the pending creation remains a typed failure");
    assert!(
        matches!(&error, MLSError::SyncIncomplete { failures, .. }
            if matches!(failures.as_slice(), [failure] if failure.conversation_id == stuck)),
        "{error:?}"
    );
    assert!(
        pending
            .alice
            .list_messages(&pending.cid, None, 100)
            .unwrap()
            .iter()
            .any(|message| message.message_id == incoming),
        "the healthy conversation still syncs"
    );
    let requests_after_first_sync = create_request_count(&pending.ds);
    let error = pending
        .alice
        .sync()
        .expect_err("Retry-After remains a typed pending-creation status");
    assert!(
        matches!(&error, MLSError::SyncIncomplete { failures, .. }
            if matches!(failures.as_slice(), [failure] if failure.conversation_id == stuck)),
        "{error:?}"
    );
    assert_eq!(
        create_request_count(&pending.ds),
        requests_after_first_sync,
        "the pending creation must not hot-loop before Retry-After"
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

#[test]
fn own_leaf_recovery_fails_closed_when_device_inventory_is_unavailable_or_missing() {
    let f = send_order_fixture(false);
    let alice_second_id = new_id();
    let alice_second = enrolled(
        &f.tmp,
        &f.ds,
        "alice-second-gated",
        ALICE_DID,
        &alice_second_id,
    );
    alice_second.sync().expect("second device requests a leaf");
    let has_second_leaf = || {
        f.ds.inner.lock().unwrap().conversations[&f.cid]["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .any(|leaf| leaf["userDid"] == ALICE_DID && leaf["deviceId"] == alice_second_id)
    };

    f.ds.inner.lock().unwrap().xrpc_failures.push((
        "/xrpc/blue.catbird.chat.getOwnDevices",
        503,
        "CapacityUnavailable",
        None,
    ));
    assert!(
        f.alice.sync().is_err(),
        "an inventory outage cannot authorize recovery"
    );
    assert!(!has_second_leaf());

    let removed_key =
        f.ds.inner
            .lock()
            .unwrap()
            .device_keys
            .remove(&(ALICE_DID.to_owned(), alice_second_id.clone()))
            .expect("second device was enrolled");
    assert!(
        f.alice.sync().is_err(),
        "a PDS-only requester cannot get a leaf"
    );
    assert!(!has_second_leaf());

    f.ds.inner
        .lock()
        .unwrap()
        .device_keys
        .insert((ALICE_DID.to_owned(), alice_second_id.clone()), removed_key);
    let identity_change_key = format!("did_identity_changed:{ALICE_DID}");
    f.alice
        .db()
        .write_tx(|tx| tx.put_account_meta(&identity_change_key, "1", 1))
        .unwrap();
    assert!(
        f.alice.sync().is_err(),
        "an identity-changed requester cannot get a leaf"
    );
    assert!(!has_second_leaf());
    f.alice
        .db()
        .write_tx(|tx| tx.delete_account_meta(&identity_change_key))
        .unwrap();
    f.alice
        .sync()
        .expect("verified active requester can recover");
    assert!(has_second_leaf());
}

/// Leaf-recovery fulfillment adds only the requester of a pending invitation this device
/// verified: the add request of a participant acceptance whose invitation verified, for exactly
/// that device, key, auth generation and KeyPackage, at exactly the coordinate the acceptance
/// bound it to, and only once. mls-ds lists a request for Carol, whom nobody invited, with her
/// own genuine KeyPackage at the current coordinate: Alice sends nothing and nothing moves. Eve
/// accepts her invitation; mls-ds lists her request with another device's KeyPackage, another
/// key, another auth generation and another device: each fails that conversation's sync with no
/// Commit sent and Alice's MLS state unchanged. The genuine request adds Eve once; listed again
/// at the new coordinate, it adds nothing.
///
/// Fail-before: Alice fulfilled any request whose KeyPackage was the requesting account's own,
/// so a delivery service could add anyone with a registered device.
#[test]
fn leaf_recovery_fulfills_only_a_verified_pending_acceptance() {
    let f = send_order_fixture(true);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    let fulfillments = || {
        ds.inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(account, url, body)| {
                account == ALICE_DID
                    && url.ends_with("/xrpc/blue.catbird.chat.submitTransition")
                    && String::from_utf8_lossy(body).contains("leafRecoveryFulfillmentBody")
            })
            .count()
    };
    let epoch = || {
        alice
            .db()
            .read_tx(|tx| tx.get_conversation(cid))
            .unwrap()
            .unwrap()
            .epoch
    };
    let local = || {
        (
            fulfillments(),
            epoch(),
            last_seq(alice, cid),
            stored_coordinates(alice, cid),
        )
    };
    let list = |requests: Vec<Value>| {
        ds.inner
            .lock()
            .unwrap()
            .leaf_recoveries
            .insert(cid.to_owned(), requests);
    };
    let has_leaf = |did: &str, device: &str| {
        ds.inner.lock().unwrap().conversations[cid]["leaves"]
            .as_array()
            .is_some_and(|leaves| {
                leaves
                    .iter()
                    .any(|leaf| leaf["userDid"] == did && leaf["deviceId"] == device)
            })
    };
    let carol_dev = new_id();
    let _carol = enrolled(&f.tmp, ds, "carol", CAROL_DID, &carol_dev);
    let carol_package = ds
        .inner
        .lock()
        .unwrap()
        .convo_kps
        .get_mut(&(CAROL_DID.to_owned(), carol_dev.clone()))
        .and_then(Vec::pop)
        .expect("carol's KeyPackage");

    // An unsigned sequencer-only inventory row for a never-invited device is not this device's
    // work: nothing is sent or moves.
    let current = ds.inner.lock().unwrap().conversations[cid]["coordinates"].clone();
    let injected_id = new_id();
    list(vec![json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryView",
        "conversationId": cid, "recoveryRequestId": injected_id,
        "requesterDid": CAROL_DID, "requesterDeviceId": carol_dev,
        "recoveryKind": "add", "boundCoordinate": current, "status": "open",
        "requestedAt": "2026-11-07T00:00:00.000Z", "expiresAt": "2099-01-01T00:00:00.000Z",
        "reservation": {
            "conversationId": cid, "recoveryRequestId": injected_id, "boundCoordinate": current,
            "requesterDid": CAROL_DID, "requesterDeviceId": carol_dev,
            "requesterKeyId": derive_key_id(enrolled_signer(&_carol).public()),
            "requesterAuthGeneration": 1, "keyPackageRef": carol_package["keyPackageRef"],
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "purpose": "leafRecovery", "status": "active",
            "expiresAt": "2099-01-01T00:00:00.000Z", "keyPackage": carol_package,
        },
    })]);
    let before = local();
    alice
        .sync()
        .expect("an unsigned listing is not this device's work");
    assert_eq!(local(), before, "nobody invited Carol");
    assert!(
        !has_leaf(CAROL_DID, &carol_dev),
        "the never-invited account gets no leaf"
    );

    // Eve accepts; mls-ds lists her request with any field the acceptance did not authorize.
    f.eve.sync().expect("eve accepts her invitation");
    let genuine = ds.inner.lock().unwrap().leaf_recoveries[cid]
        .last()
        .cloned()
        .expect("eve's request");
    assert_eq!(genuine["requesterDid"], EVE_DID);
    let forged = |edit: &dyn Fn(&mut Value)| {
        let mut request = genuine.clone();
        edit(&mut request);
        request
    };
    let variants = [
        (
            "another device's KeyPackage",
            forged(&|request| {
                request["reservation"]["keyPackage"] = carol_package.clone();
                request["reservation"]["keyPackageRef"] = carol_package["keyPackageRef"].clone();
            }),
            "not the authorized device's own",
        ),
        (
            "another key",
            forged(&|request| {
                request["reservation"]["requesterKeyId"] =
                    json!(derive_key_id(enrolled_signer(&_carol).public()))
            }),
            "not the authorized request",
        ),
        (
            "another auth generation",
            forged(&|request| request["reservation"]["requesterAuthGeneration"] = json!(2)),
            "not the authorized request",
        ),
        (
            "another device",
            forged(&|request| {
                request["requesterDeviceId"] = json!(carol_dev);
                request["reservation"]["requesterDeviceId"] = json!(carol_dev);
            }),
            "not a PDS-authorized device",
        ),
    ];
    let mut acceptance_seq = None;
    for (case, request, reason) in variants {
        list(vec![request]);
        let error = alice.sync().expect_err(case);
        assert!(
            matches!(&error, MLSError::SyncIncomplete { failures, .. }
                if failures.len() == 1 && failures[0].conversation_id == cid),
            "{case}: {error:?}"
        );
        assert!(error.to_string().contains(reason), "{case}: {error}");
        // The acceptance itself applied once; nothing else moved.
        let seq = *acceptance_seq.get_or_insert(last_seq(alice, cid));
        assert_eq!(
            (fulfillments(), epoch(), last_seq(alice, cid)),
            (before.0, before.1, seq),
            "{case}"
        );
    }

    list(vec![genuine.clone()]);
    alice.sync().expect("the authorized add");
    assert_eq!((fulfillments(), epoch()), (before.0 + 1, before.1 + 1));
    let eve_dev = genuine["requesterDeviceId"].as_str().unwrap();
    assert!(
        has_leaf(EVE_DID, eve_dev),
        "the honestly invited and accepted account gets its leaf"
    );
    // Listed again at the new coordinate, the consumed unsigned authorization is no work.
    let mut again = genuine;
    let current = ds.inner.lock().unwrap().conversations[cid]["coordinates"].clone();
    again["status"] = json!("open");
    again["boundCoordinate"] = current.clone();
    again["reservation"]["boundCoordinate"] = current;
    list(vec![again]);
    alice
        .sync()
        .expect("a consumed unsigned authorization grants nothing");
    assert_eq!((fulfillments(), epoch()), (before.0 + 1, before.1 + 1));
}

fn synced_group_pair() -> (
    tempfile::TempDir,
    Arc<SharedMockDs>,
    Arc<CatbirdMlsClient>,
    Arc<CatbirdMlsClient>,
    String,
    String,
    String,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_device = new_id();
    let bob_device = new_id();
    let alice = enrolled(&tmp, &ds, "gap-alice", ALICE_DID, &alice_device);
    let bob = enrolled(&tmp, &ds, "gap-bob", BOB_DID, &bob_device);
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Four gaps".into()),
            Some("group".into()),
        )
        .expect("create group");
    bob.sync().expect("bob imports the group");
    alice.sync().expect("alice reaches the DS head");
    bob.sync().expect("bob reaches the DS head");
    (tmp, ds, alice, bob, cid, alice_device, bob_device)
}

#[test]
fn sync_paginates_more_than_one_hundred_cryptographic_entries() {
    let (_tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let mut sent = Vec::with_capacity(101);
    for index in 0..101 {
        let message_id = new_id();
        let text = format!("entry pagination message {index}");
        alice
            .send_message(&cid, &message_id, &text)
            .expect("sequence application message");
        sent.push((message_id, text));
    }
    ds.inner.lock().unwrap().http_log.clear();

    bob.sync().expect("sync both entry pages");
    let stored = bob.list_messages(&cid, None, 200).unwrap();
    for (message_id, text) in &sent {
        let message = stored
            .iter()
            .find(|message| &message.message_id == message_id)
            .unwrap_or_else(|| panic!("missing paginated message {message_id}"));
        let plaintext: Value = serde_json::from_str(&message.plaintext_json).unwrap();
        assert_eq!(plaintext["text"].as_str(), Some(text.as_str()));
    }
    let entry_reads = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(_, url, _)| {
            url.contains("/xrpc/blue.catbird.chat.getEntries")
                && query_map(url).get("conversationId") == Some(&cid)
        })
        .count();
    assert_eq!(
        entry_reads, 2,
        "101 user messages require exactly two pages"
    );
}

#[test]
fn c33_publication_rejects_a_signed_receipt_with_wrong_coordinates() {
    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "u02-alice", ALICE_DID, &new_id());
    let _bob = enrolled(&tmp, &ds, "u02-bob", BOB_DID, &new_id());
    ds.inner.lock().unwrap().tamper_next_publication_coordinates = true;

    let error = alice
        .create_group(
            &new_id(),
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("opening".into()),
        )
        .expect_err("receipt coordinates must bind the published bootstrap");
    assert!(
        matches!(&error, MLSError::Cryptography(message)
            if message == "C33 publication outcome binding mismatch"),
        "{error:?}"
    );
}

#[test]
fn adding_a_member_gap_syncs_an_unsynced_application_entry() {
    let (tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let _carol = enrolled(&tmp, &ds, "u06-carol", CAROL_DID, &new_id());
    let initial_seq = last_seq(&alice, &cid);
    bob.send_message(&cid, &new_id(), "gap-before-add")
        .expect("peer application");

    alice
        .add_group_members(&cid, vec![CAROL_DID.to_string()])
        .expect("policy transition gap sync");
    assert_eq!(last_seq(&alice, &cid), initial_seq + 2);
    assert!(alice
        .list_messages(&cid, None, 10)
        .unwrap()
        .iter()
        .any(|message| message.plaintext_json.contains("gap-before-add")));
}

#[test]
fn application_send_rejects_confirmation_tag_only_coordinate_drift_locally() {
    let (_tmp, ds, alice, _bob, cid, _, _) = synced_group_pair();
    let key = format!("conversation_coords:{cid}");
    let raw = alice
        .db()
        .read_tx(|tx| tx.get_account_meta(&key))
        .unwrap()
        .unwrap();
    let mut coordinates: Value = serde_json::from_str(&raw).unwrap();
    let mut tag = chat_wire::json_bytes(&coordinates["confirmationTag"]).unwrap();
    tag[0] ^= 0x80;
    coordinates["confirmationTag"] = if coordinates["confirmationTag"].is_object() {
        json!({ "$bytes": STANDARD.encode(tag) })
    } else {
        json!(STANDARD.encode(tag))
    };
    alice
        .db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &key,
                &serde_json::to_string(&coordinates)
                    .map_err(|error| MLSError::Internal(error.to_string()))?,
                chrono::Utc::now().timestamp_millis(),
            )
        })
        .unwrap();
    let before = ds.inner.lock().unwrap().http_log.len();

    let error = alice
        .send_message(&cid, &new_id(), "tampered-ctag")
        .expect_err("one coordinate component drifting must fail closed");
    assert!(matches!(error, MLSError::InvalidState(code) if code == "StaleCoordinates"));
    assert_eq!(ds.inner.lock().unwrap().http_log.len(), before);
}

#[test]
fn decline_closes_when_only_the_coordinate_half_of_local_state_exists() {
    let request = C33Request::new();
    let request_id = request
        .alice
        .list_requests(None)
        .unwrap()
        .into_iter()
        .find(|row| row.conversation_id == request.cid)
        .unwrap()
        .request_id;
    request
        .alice
        .db()
        .write_tx(|tx| {
            tx.conn()
                .execute(
                    "DELETE FROM conversations WHERE conversation_id = ?1",
                    [&request.cid],
                )
                .map(|_| ())
                .map_err(|error| MLSError::Internal(error.to_string()))
        })
        .unwrap();
    let close_count = || {
        request
            .ds
            .inner
            .lock()
            .unwrap()
            .http_log
            .iter()
            .filter(|(_, url, _)| url.contains("blue.catbird.chat.closeConversation"))
            .count()
    };
    let before = close_count();

    request
        .alice
        .decline_direct_request(&request_id)
        .expect("decline closes the partial direct conversation");
    assert_eq!(close_count(), before + 1);
}

#[test]
fn closing_a_c33_request_binds_direct_conversation_kind() {
    let request = C33Request::new();
    request
        .alice
        .close_conversation(&request.cid)
        .expect("close direct request");
    let state = request.ds.inner.lock().unwrap();
    let body: Value = serde_json::from_slice(
        &state
            .http_log
            .iter()
            .rev()
            .find(|(_, url, _)| url.contains("blue.catbird.chat.closeConversation"))
            .unwrap()
            .2,
    )
    .unwrap();
    assert_eq!(body["signedRequest"]["body"]["conversationKind"], "direct");
}

#[test]
fn direct_request_publication_detects_journal_ownership_change() {
    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let alice = enrolled(&tmp, &ds, "ownership-alice", ALICE_DID, &new_id());
    let _bob = enrolled(&tmp, &ds, "ownership-bob", BOB_DID, &new_id());
    let weak = Arc::downgrade(&alice);
    ds.inner.lock().unwrap().after_next_publish = Some(Arc::new(move || {
        let client = weak.upgrade().expect("client remains live");
        client
            .db()
            .write_tx(|tx| {
                let raw = tx
                    .get_pending_op("direct_request_creation", BOB_DID)?
                    .expect("publication journal");
                let mut changed: Value = serde_json::from_str(&raw)
                    .map_err(|error| MLSError::Internal(error.to_string()))?;
                changed["publish"] = Value::Null;
                tx.put_pending_op(
                    "direct_request_creation",
                    BOB_DID,
                    &serde_json::to_string(&changed)
                        .map_err(|error| MLSError::Internal(error.to_string()))?,
                    chrono::Utc::now().timestamp_millis(),
                )
            })
            .unwrap();
    }));

    let error = alice
        .create_group(
            &new_id(),
            DS_DID,
            vec![BOB_DID.to_string()],
            None,
            Some("opening".into()),
        )
        .expect_err("changed journal must not be committed");
    assert!(
        matches!(error, MLSError::InvalidState(code) if code == "DirectRequestOwnershipChanged")
    );
}

#[test]
fn legacy_enrollment_marker_rebinds_the_same_signer_key() {
    let tmp = tempfile::tempdir().unwrap();
    let ds = SharedMockDs::new();
    let client = enrolled(&tmp, &ds, "legacy-enroll", ALICE_DID, &new_id());
    let expected_key = derive_key_id(enrolled_signer(&client).public());
    client
        .db()
        .write_tx(|tx| tx.delete_account_meta("enrolled_signer_key_id"))
        .unwrap();

    client
        .enroll_device(&oauth_scopes())
        .expect("migrate legacy enrollment marker");
    assert_eq!(
        client
            .db()
            .read_tx(|tx| tx.get_account_meta("enrolled_signer_key_id"))
            .unwrap()
            .as_deref(),
        Some(expected_key.as_str())
    );
}

/// `getEntries` cannot omit an accepted tail row. Peer counters are evidence only: a jump,
/// duplicate or rewind is stored without blocking a valid MLS message. A missing sequenced row
/// still leaves the durable cursor and ACK watermark at the verified prefix.
///
/// Fail-before: sync rejected a valid counter jump that the sequencer accepts.
#[test]
fn sync_requires_contiguous_entry_seq_and_records_peer_counter_anomalies() {
    let (_tmp, ds, alice, bob, cid, alice_device, _) = synced_group_pair();
    let baseline = last_seq(&bob, &cid);
    let first = new_id();
    let second = new_id();
    alice.send_message(&cid, &first, "first").unwrap();
    alice.send_message(&cid, &second, "second").unwrap();
    let (at, removed, ack_before) = {
        let mut g = ds.inner.lock().unwrap();
        let at = g.entries[&cid]
            .iter()
            .position(|entry| {
                entry
                    .pointer("/signedRequest/body/messageId")
                    .and_then(Value::as_str)
                    == Some(first.as_str())
            })
            .unwrap();
        let removed = g.entries.get_mut(&cid).unwrap().remove(at);
        (at, removed, g.acked_watermarks.clone())
    };
    let error = bob.sync().expect_err("a dropped tail row is a seq gap");
    assert!(
        error
            .to_string()
            .contains("non-contiguous conversation sequence"),
        "{error:?}"
    );
    assert_eq!(last_seq(&bob, &cid), baseline);
    assert_eq!(ds.inner.lock().unwrap().acked_watermarks, ack_before);
    ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(&cid)
        .unwrap()
        .insert(at, removed);
    bob.sync().expect("the restored contiguous tail applies");
    assert!(bob
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|row| row.message_id == first));
    assert!(bob
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|row| row.message_id == second));

    let counter_key = chat_wire::send_counter_key(&cid);
    alice
        .db()
        .write_tx(|tx| {
            tx.put_account_meta(&counter_key, "3", chrono::Utc::now().timestamp_millis())
        })
        .unwrap();
    let order_key = (cid.clone(), ALICE_DID.to_string(), alice_device);
    let before_counter_jump = last_seq(&bob, &cid);
    alice
        .send_message(&cid, &new_id(), "counter four")
        .expect("the mock DS sequences a skipped counter");
    // A skipped counter is evidence, but delivery continues.
    bob.sync().expect("peer sendCounter 2 -> 4 advances");
    assert_eq!(last_seq(&bob, &cid), before_counter_jump + 1);

    let candidate = new_id();
    alice
        .send_message(&cid, &candidate, "counter five")
        .expect("the next increasing counter is sequenced");
    let signer = enrolled_signer(&alice);
    let before_non_increasing = last_seq(&bob, &cid);
    rebind_application_send_counter(&ds, &cid, &candidate, &signer, ALICE_DID, &order_key.2, 4);
    bob.sync().expect("duplicate counter is evidence only");
    assert_eq!(last_seq(&bob, &cid), before_non_increasing + 1);
    assert!(bob
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|row| row.message_id == candidate));
    let evidence = bob
        .db()
        .read_tx(|tx| {
            tx.get_account_meta(&catbird_mls::client::send_counter::send_counter_gap_key(
                &cid,
                before_non_increasing + 1,
            ))
        })
        .unwrap();
    assert!(evidence.as_deref().is_some_and(|e| e.contains("regressed")));

    let rewind = new_id();
    alice.send_message(&cid, &rewind, "counter rewind").unwrap();
    rebind_application_send_counter(&ds, &cid, &rewind, &signer, ALICE_DID, &order_key.2, 3);
    bob.sync().expect("rewound counter is also evidence only");
    assert!(bob
        .list_messages(&cid, None, 20)
        .unwrap()
        .iter()
        .any(|row| row.message_id == rewind));
    let evidence = bob
        .db()
        .read_tx(|tx| {
            tx.get_account_meta(&catbird_mls::client::send_counter::send_counter_gap_key(
                &cid,
                before_non_increasing + 2,
            ))
        })
        .unwrap();
    assert!(evidence.as_deref().is_some_and(|e| e.contains("regressed")));
}

struct NseReceiptFixture {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    ds: Arc<SharedMockDs>,
    alice: Arc<CatbirdMlsClient>,
    bob: Arc<CatbirdMlsClient>,
    bob_keys: Arc<MemKeyStore>,
    cid: String,
    alice_device: String,
    bob_device: String,
}

impl NseReceiptFixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("NSE receipt tempdir");
        let root = tmp.path().to_path_buf();
        let ds = SharedMockDs::new();
        let alice_device = new_id();
        let bob_device = new_id();
        let alice_keys = Arc::new(MemKeyStore::new());
        let bob_keys = Arc::new(MemKeyStore::new());
        let alice = live_client(
            &root,
            &ds,
            "nse-receipt-alice",
            ALICE_DID,
            &alice_device,
            &alice_keys,
        );
        let bob = live_client(
            &root,
            &ds,
            "nse-receipt-bob",
            BOB_DID,
            &bob_device,
            &bob_keys,
        );
        alice
            .enroll_device(&oauth_scopes())
            .expect("enroll NSE receipt Alice");
        bob.enroll_device(&oauth_scopes())
            .expect("enroll NSE receipt Bob");
        let cid = new_id();
        alice
            .create_group(
                &cid,
                DS_DID,
                vec![BOB_DID.to_string()],
                Some("NSE receipts".into()),
                Some("group".into()),
            )
            .expect("create NSE receipt group");
        bob.sync().expect("Bob imports NSE receipt group");
        alice.sync().expect("Alice reaches NSE receipt head");
        bob.sync().expect("Bob reaches NSE receipt head");
        assert!(bob
            .db()
            .read_tx(|tx| tx.get_account_meta(&format!("did_doc:{DS_DID}")))
            .unwrap()
            .is_some());
        Self {
            _tmp: tmp,
            root,
            ds,
            alice,
            bob,
            bob_keys,
            cid,
            alice_device,
            bob_device,
        }
    }

    fn bundle_after_bob_cursor(&self) -> PushFetchBundle {
        let after_seq = last_seq(&self.bob, &self.cid);
        let entries = self.ds.inner.lock().unwrap().entries[&self.cid]
            .iter()
            .filter(|entry| entry["seq"].as_i64().is_some_and(|seq| seq > after_seq))
            .map(fetched_nse_entry)
            .collect();
        PushFetchBundle {
            entries,
            metadata_snapshot: None,
            authorized_device_keys: vec![
                AuthorizedPeerDeviceKey {
                    did: ALICE_DID.into(),
                    device_id: self.alice_device.clone(),
                    signature_public_key: enrolled_signer(&self.alice).public().to_vec(),
                },
                AuthorizedPeerDeviceKey {
                    did: BOB_DID.into(),
                    device_id: self.bob_device.clone(),
                    signature_public_key: enrolled_signer(&self.bob).public().to_vec(),
                },
            ],
        }
    }

    fn process(
        &self,
        bundle: PushFetchBundle,
    ) -> (
        catbird_mls::push::NotificationPreview,
        Arc<NseReceiptTransport>,
    ) {
        let target = bundle
            .entries
            .iter()
            .rev()
            .find(|entry| {
                entry.entry_kind.ends_with("#applicationEntry") || entry.entry_kind == "application"
            })
            .expect("push target application");
        let signed: Value =
            serde_json::from_slice(target.signed_request.as_deref().unwrap()).unwrap();
        let wake = PushWakePayload {
            kind: "application_message".into(),
            conversation_id: self.cid.clone(),
            generation: 0,
            entry_seq: target.seq,
            message_id: signed["body"]["messageId"]
                .as_str()
                .expect("target message ID")
                .to_owned(),
            recipient_account_hash: account_did_hash_hex(BOB_DID).unwrap(),
            fetch_required: true,
            sender_did: Some(
                signed["body"]["actorDid"]
                    .as_str()
                    .expect("target sender")
                    .to_owned(),
            ),
            inline_ciphertext: None,
        };
        let transport = Arc::new(NseReceiptTransport {
            bundle,
            fetch_calls: AtomicUsize::new(0),
            device_key_calls: AtomicUsize::new(0),
        });
        let preview = process_push_notification(
            &self.root.join("nse-receipt-bob"),
            &account_did_hash_hex(BOB_DID).unwrap(),
            Arc::new(NsePushKeystore(self.bob_keys.clone())),
            Some(transport.clone()),
            &wake,
        )
        .expect("NSE receipt processing returns a preview");
        (preview, transport)
    }

    fn state(&self) -> (i64, i64, usize) {
        let row = self
            .bob
            .db()
            .read_tx(|tx| tx.get_conversation(&self.cid))
            .unwrap()
            .unwrap();
        (
            row.epoch,
            row.last_seq,
            self.bob.list_messages(&self.cid, None, 100).unwrap().len(),
        )
    }
}

struct NseReceiptTransport {
    bundle: PushFetchBundle,
    fetch_calls: AtomicUsize,
    device_key_calls: AtomicUsize,
}

impl PushFetchTransport for NseReceiptTransport {
    fn fetch_missing_entries(
        &self,
        _conversation_id: String,
        _after_seq: i64,
        _chat_dpop_token: String,
    ) -> Result<PushFetchBundle, MLSError> {
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.bundle.clone())
    }

    fn get_authorized_device_keys(
        &self,
        did: String,
        _chat_dpop_token: Option<String>,
    ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
        self.device_key_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .bundle
            .authorized_device_keys
            .iter()
            .filter(|key| key.did == did)
            .cloned()
            .collect())
    }
}

fn fetched_nse_entry(entry: &Value) -> FetchedPushEntry {
    let signed_request = &entry["signedRequest"];
    let body = &signed_request["body"];
    let mls_bytes = body
        .pointer("/applicationMessage/bytes")
        .or_else(|| body.pointer("/commit/bytes"))
        .map(chat_wire::json_bytes)
        .transpose()
        .unwrap()
        .unwrap_or_default();
    FetchedPushEntry {
        entry_id: entry["entryId"].as_str().unwrap().to_owned(),
        seq: entry["seq"].as_i64().unwrap(),
        epoch: body["prior"]["epoch"].as_i64().unwrap_or_default(),
        entry_kind: entry["$type"].as_str().unwrap().to_owned(),
        sender_did: body["actorDid"].as_str().unwrap().to_owned(),
        mls_bytes,
        signed_request: Some(serde_json::to_vec(signed_request).unwrap()),
        sequencer_receipt: entry
            .get("sequencerReceipt")
            .filter(|receipt| receipt.is_object())
            .map(|receipt| serde_json::to_vec(receipt).unwrap()),
    }
}

#[test]
fn nse_applies_receipted_peer_commit_and_foreground_does_not_apply_it_twice() {
    let fixture = NseReceiptFixture::new();
    let before = fixture.state();
    fixture
        .alice
        .self_update(&fixture.cid)
        .expect("sequence peer Commit");
    let message_id = new_id();
    fixture
        .alice
        .send_message(&fixture.cid, &message_id, "receipt-verified NSE preview")
        .expect("sequence post-Commit application");
    let bundle = fixture.bundle_after_bob_cursor();
    let target_seq = bundle.entries.last().unwrap().seq;
    let commit_seq = bundle
        .entries
        .iter()
        .find(|entry| entry.entry_kind.ends_with("#commitEntry"))
        .unwrap()
        .seq;
    fixture
        .bob
        .db()
        .write_tx(|tx| {
            tx.put_pending_op(
                "nse_deferred_control",
                &fixture.cid,
                &commit_seq.to_string(),
                1,
            )
        })
        .unwrap();
    let ack_before = fixture.ds.inner.lock().unwrap().acked_watermarks.clone();

    let (preview, transport) = fixture.process(bundle);
    assert_eq!(preview.body, "receipt-verified NSE preview");
    assert!(!preview.fallback_generic);
    assert_eq!(fixture.state(), (before.0 + 1, target_seq, before.2 + 1));
    assert_eq!(
        fixture.ds.inner.lock().unwrap().acked_watermarks,
        ack_before,
        "the NSE never acknowledges entries"
    );
    assert_eq!(transport.fetch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.device_key_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .bob
            .db()
            .read_tx(|tx| tx.get_pending_op("nse_deferred_control", &fixture.cid))
            .unwrap(),
        None,
        "a verified-and-applied Commit clears its deferral marker"
    );

    let after_nse = fixture.state();
    fixture
        .bob
        .sync()
        .expect("foreground completes the retained application receipt");
    assert_eq!(fixture.state(), after_nse);
    assert_eq!(
        fixture
            .bob
            .list_messages(&fixture.cid, None, 100)
            .unwrap()
            .iter()
            .filter(|message| message.message_id == message_id)
            .count(),
        1
    );
}

#[test]
fn nse_defers_missing_forged_and_misbound_commit_receipts_for_foreground() {
    for fault in ["missing", "forged", "wrong-seq", "wrong-entry"] {
        let fixture = NseReceiptFixture::new();
        fixture
            .alice
            .self_update(&fixture.cid)
            .expect("sequence peer Commit");
        let message_id = new_id();
        fixture
            .alice
            .send_message(&fixture.cid, &message_id, fault)
            .expect("sequence post-Commit application");
        let mut bundle = fixture.bundle_after_bob_cursor();
        let commit = bundle
            .entries
            .iter_mut()
            .find(|entry| entry.entry_kind.ends_with("#commitEntry"))
            .expect("fetched Commit");
        match fault {
            "missing" => commit.sequencer_receipt = None,
            "forged" => {
                let mut receipt: Value =
                    serde_json::from_slice(commit.sequencer_receipt.as_deref().unwrap()).unwrap();
                let mut signature = chat_wire::json_bytes(&receipt["signature"]).unwrap();
                signature[0] ^= 1;
                receipt["signature"] = json!({ "$bytes": STANDARD.encode(signature) });
                commit.sequencer_receipt = Some(serde_json::to_vec(&receipt).unwrap());
            }
            "wrong-seq" => {
                let mut receipt: Value =
                    serde_json::from_slice(commit.sequencer_receipt.as_deref().unwrap()).unwrap();
                receipt["seq"] = json!(receipt["seq"].as_i64().unwrap() + 1);
                commit.sequencer_receipt = Some(serde_json::to_vec(&receipt).unwrap());
            }
            "wrong-entry" => {
                let mut receipt: Value =
                    serde_json::from_slice(commit.sequencer_receipt.as_deref().unwrap()).unwrap();
                receipt["entryId"] = json!(new_id());
                commit.sequencer_receipt = Some(serde_json::to_vec(&receipt).unwrap());
            }
            _ => unreachable!(),
        }
        let before = fixture.state();
        let ack_before = fixture.ds.inner.lock().unwrap().acked_watermarks.clone();

        let (preview, _) = fixture.process(bundle);
        assert!(preview.fallback_generic, "{fault}");
        assert_eq!(fixture.state(), before, "{fault}");
        assert_eq!(
            fixture.ds.inner.lock().unwrap().acked_watermarks,
            ack_before,
            "{fault}"
        );
        assert!(fixture
            .bob
            .db()
            .read_tx(|tx| tx.get_pending_op("nse_deferred_control", &fixture.cid))
            .unwrap()
            .is_some());

        assert!(
            fixture
                .bob
                .sync()
                .expect("foreground applies genuine entries")
                > 0
        );
        assert_eq!(fixture.state().0, before.0 + 1, "{fault}");
        assert!(fixture
            .bob
            .list_messages(&fixture.cid, None, 100)
            .unwrap()
            .iter()
            .any(|message| message.message_id == message_id));
    }
}

#[test]
fn nse_missing_local_sequencer_key_defers_without_extra_network_request() {
    let fixture = NseReceiptFixture::new();
    fixture
        .alice
        .self_update(&fixture.cid)
        .expect("sequence peer Commit");
    fixture
        .alice
        .send_message(
            &fixture.cid,
            &new_id(),
            "not decryptable without receipt key",
        )
        .expect("sequence post-Commit application");
    let bundle = fixture.bundle_after_bob_cursor();
    fixture
        .bob
        .db()
        .write_tx(|tx| tx.delete_account_meta(&format!("did_doc:{DS_DID}")))
        .unwrap();
    let before = fixture.state();
    let ack_before = fixture.ds.inner.lock().unwrap().acked_watermarks.clone();

    let (preview, transport) = fixture.process(bundle);
    assert!(preview.fallback_generic);
    assert_eq!(fixture.state(), before);
    assert_eq!(
        fixture.ds.inner.lock().unwrap().acked_watermarks,
        ack_before,
        "the NSE never acknowledges entries"
    );
    assert_eq!(transport.fetch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        transport.device_key_calls.load(Ordering::SeqCst),
        0,
        "a missing receipt key must not trigger any resolver/device network call"
    );
}

#[test]
fn nse_applies_receipted_own_pending_commit_before_preview() {
    let fixture = NseReceiptFixture::new();
    let before = fixture.state();
    fixture.ds.inner.lock().unwrap().lose_next_commit_response = true;
    fixture
        .bob
        .self_update(&fixture.cid)
        .expect_err("own Commit response is lost after sequencing");
    fixture
        .alice
        .sync()
        .expect("peer applies the sequenced own-pending Commit");
    let message_id = new_id();
    fixture
        .alice
        .send_message(&fixture.cid, &message_id, "after own pending Commit")
        .expect("peer sends after own pending Commit");
    let bundle = fixture.bundle_after_bob_cursor();
    let target_seq = bundle.entries.last().unwrap().seq;
    let ack_before = fixture.ds.inner.lock().unwrap().acked_watermarks.clone();

    let (preview, _) = fixture.process(bundle);
    assert_eq!(
        preview.body,
        "after own pending Commit",
        "state={:?}, deferred={:?}",
        fixture.state(),
        fixture
            .bob
            .db()
            .read_tx(|tx| tx.get_pending_op("nse_deferred_control", &fixture.cid))
            .unwrap()
    );
    assert!(!preview.fallback_generic);
    assert_eq!(fixture.state(), (before.0 + 1, target_seq, before.2 + 1));
    assert_eq!(
        fixture.ds.inner.lock().unwrap().acked_watermarks,
        ack_before,
        "the NSE never acknowledges entries"
    );
    fixture
        .bob
        .db()
        .read_tx(|tx| {
            let pending: i64 = tx
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM pending_ops WHERE op_kind = 'commit_transition'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| MLSError::Internal(error.to_string()))?;
            assert_eq!(pending, 0);
            Ok(())
        })
        .unwrap();
    let after_nse = fixture.state();
    fixture
        .bob
        .sync()
        .expect("foreground completes the retained application receipt");
    assert_eq!(fixture.state(), after_nse);
    assert_eq!(
        fixture
            .bob
            .list_messages(&fixture.cid, None, 100)
            .unwrap()
            .iter()
            .filter(|message| message.message_id == message_id)
            .count(),
        1
    );
}

/// D3 leaves a receipt-less push Commit untouched for foreground sync. A native send must apply
/// the deferred Commit only after its I13 receipt verifies, and must not publish from stale state
/// when that receipt is absent.
#[test]
fn native_send_catches_up_an_nse_deferred_commit_after_receipt_verification() {
    let (_tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let before_epoch = bob
        .db()
        .read_tx(|tx| tx.get_conversation(&cid))
        .unwrap()
        .unwrap()
        .epoch;
    alice.self_update(&cid).expect("peer Commit is sequenced");
    let deferred_seq = {
        let state = ds.inner.lock().unwrap();
        state.entries[&cid]
            .iter()
            .rev()
            .find(|entry| entry["$type"] == "blue.catbird.chat.defs#commitEntry")
            .and_then(|entry| entry["seq"].as_i64())
            .expect("deferred Commit seq")
    };
    bob.db()
        .write_tx(|tx| {
            tx.put_pending_op(
                "nse_deferred_control",
                &cid,
                &deferred_seq.to_string(),
                1_762_000_000_000,
            )
        })
        .expect("persist NSE deferred-control marker");
    assert_eq!(
        bob.db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
            .epoch,
        before_epoch,
        "the NSE-deferred Commit has not changed foreground state"
    );

    let message_id = new_id();
    let sent = bob
        .send_message(&cid, &message_id, "send after deferred Commit")
        .expect("send foreground-syncs the verified Commit");
    assert_eq!(sent.epoch, before_epoch + 1);
    assert_eq!(
        bob.db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
            .epoch,
        before_epoch + 1
    );
    assert_eq!(ds.send_attempts(&message_id).len(), 1);
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_pending_op("nse_deferred_control", &cid))
        .unwrap()
        .is_none());

    let (_tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let before_seq = last_seq(&bob, &cid);
    let before_epoch = bob
        .db()
        .read_tx(|tx| tx.get_conversation(&cid))
        .unwrap()
        .unwrap()
        .epoch;
    alice.self_update(&cid).expect("peer Commit is sequenced");
    let (at, deferred_seq) = {
        let state = ds.inner.lock().unwrap();
        state.entries[&cid]
            .iter()
            .enumerate()
            .find(|(_, entry)| entry["$type"] == "blue.catbird.chat.defs#commitEntry")
            .map(|(at, entry)| (at, entry["seq"].as_i64().expect("deferred Commit seq")))
            .expect("deferred Commit entry")
    };
    ds.inner.lock().unwrap().entries.get_mut(&cid).unwrap()[at]["sequencerReceipt"] = Value::Null;
    bob.db()
        .write_tx(|tx| {
            tx.put_pending_op(
                "nse_deferred_control",
                &cid,
                &deferred_seq.to_string(),
                1_762_000_000_000,
            )
        })
        .expect("persist NSE deferred-control marker");

    let message_id = new_id();
    let error = bob
        .send_message(&cid, &message_id, "must not send past unverified Commit")
        .expect_err("receipt-less deferred Commit blocks send");
    assert!(
        error.to_string().contains("sequencerReceipt") || error.to_string().contains("I13"),
        "{error:?}"
    );
    assert_eq!(
        (
            last_seq(&bob, &cid),
            bob.db()
                .read_tx(|tx| tx.get_conversation(&cid))
                .unwrap()
                .unwrap()
                .epoch,
            ds.send_attempts(&message_id).len(),
        ),
        (before_seq, before_epoch, 0)
    );
    assert!(bob
        .db()
        .read_tx(|tx| tx.get_pending_op("nse_deferred_control", &cid))
        .unwrap()
        .is_some());
}

/// With no NSE-deferred control, send starts at `sendMessage`: it performs no network preflight.
#[test]
fn native_send_without_deferred_control_makes_no_preflight_request() {
    let (_tmp, ds, _alice, bob, cid, _, _) = synced_group_pair();
    let before = ds.inner.lock().unwrap().http_log.len();
    let message_id = new_id();

    bob.send_message(&cid, &message_id, "ordinary send")
        .expect("ordinary send succeeds");

    let state = ds.inner.lock().unwrap();
    let requests = &state.http_log[before..];
    assert!(
        requests
            .first()
            .is_some_and(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.sendMessage")),
        "the first ordinary-send request must be sendMessage: {requests:?}"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|(_, url, _)| url.contains("/xrpc/blue.catbird.chat.getConversationState"))
            .count(),
        0,
        "ordinary send must not preflight getConversationState"
    );
}

/// Gap 2 regression. Every Commit/control row must carry the sequencer's I13 receipt, bound to the
/// same entry ID and `seq`. Missing, forged and re-numbered receipts all fail before MLS state,
/// cursor, or ACK changes; the untouched row then applies.
///
/// Fail-before: commit rows were authenticated only by their actor signature, allowing a mirror
/// to invent or reorder a valid actor-authored transition.
#[test]
fn commit_entry_requires_a_valid_seq_bound_sequencer_receipt() {
    let (_tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let before_seq = last_seq(&bob, &cid);
    let before_epoch = bob
        .db()
        .read_tx(|tx| tx.get_conversation(&cid))
        .unwrap()
        .unwrap()
        .epoch;
    alice
        .self_update(&cid)
        .expect("production CatbirdMlsClient::self_update is available");
    let (at, genuine) = {
        let g = ds.inner.lock().unwrap();
        g.entries[&cid]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, entry)| entry["$type"] == "blue.catbird.chat.defs#commitEntry")
            .map(|(at, entry)| (at, entry.clone()))
            .expect("self-update commit entry")
    };
    for (name, mut entry) in [
        ("missing", genuine.clone()),
        ("forged", genuine.clone()),
        ("mismatched seq", genuine.clone()),
    ] {
        match name {
            "missing" => {
                entry["sequencerReceipt"] = Value::Null;
            }
            "forged" => {
                entry["sequencerReceipt"]["signature"] =
                    json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
            }
            _ => {
                entry["sequencerReceipt"]["seq"] = json!(entry["seq"].as_u64().unwrap() + 1);
            }
        }
        ds.inner.lock().unwrap().entries.get_mut(&cid).unwrap()[at] = entry;
        let ack_before = ds.inner.lock().unwrap().acked_watermarks.clone();
        let error = bob.sync().expect_err(name);
        assert!(
            error.to_string().contains("sequencerReceipt") || error.to_string().contains("I13"),
            "{name}: {error:?}"
        );
        assert_eq!(last_seq(&bob, &cid), before_seq, "{name}");
        assert_eq!(
            ds.inner.lock().unwrap().acked_watermarks,
            ack_before,
            "{name}"
        );
        assert_eq!(
            bob.db()
                .read_tx(|tx| tx.get_conversation(&cid))
                .unwrap()
                .unwrap()
                .epoch,
            before_epoch,
            "{name}"
        );
    }
    ds.inner.lock().unwrap().entries.get_mut(&cid).unwrap()[at] = genuine;
    bob.sync()
        .expect("the genuine signed control receipt applies");
    assert_eq!(
        bob.db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
            .epoch,
        before_epoch + 1
    );
    let applied_seq = last_seq(&bob, &cid);
    let ack_after_apply = ds.inner.lock().unwrap().acked_watermarks.clone();
    assert_eq!(
        bob.sync().expect("an applied Commit is not applied again"),
        0
    );
    assert_eq!(last_seq(&bob, &cid), applied_seq);
    assert_eq!(
        bob.db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
            .epoch,
        before_epoch + 1
    );
    assert_eq!(ds.inner.lock().unwrap().acked_watermarks, ack_after_apply);
}

/// Gap 3 regression. If an application row claims the local epoch but its `prior` hash or
/// confirmation tag differs, sync reports `ForkDetected` before attempting AEAD decryption. It
/// writes neither an undecryptable-gap row nor an ACK; restoring the local coordinate applies it.
///
/// Fail-before: the row fell through to decryption and was persisted as an `AeadFailure` gap,
/// permanently advancing the cursor over evidence of an equivocated group state.
#[test]
fn same_epoch_coordinate_mismatch_is_a_fork_not_an_aead_gap() {
    let (_tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let message_id = new_id();
    alice.send_message(&cid, &message_id, "fork probe").unwrap();
    let before_seq = last_seq(&bob, &cid);
    let before_messages = bob.list_messages(&cid, None, 100).unwrap().len();
    let coordinate_key = format!("conversation_coords:{cid}");
    let original = bob
        .db()
        .read_tx(|tx| tx.get_account_meta(&coordinate_key))
        .unwrap()
        .expect("local coordinate");
    let original_json: Value = serde_json::from_str(&original).unwrap();
    for (field, fill) in [("groupContextHash", 0x51_u8), ("confirmationTag", 0x52_u8)] {
        let mut mismatched = original_json.clone();
        mismatched[field] = json!({ "$bytes": STANDARD.encode([fill; 32]) });
        bob.db()
            .write_tx(|tx| {
                tx.put_account_meta(
                    &coordinate_key,
                    &serde_json::to_string(&mismatched).unwrap(),
                    chrono::Utc::now().timestamp_millis(),
                )
            })
            .unwrap();
        let ack_before = ds.inner.lock().unwrap().acked_watermarks.clone();
        let error = bob.sync().expect_err(field);
        let diagnostic = format!("{error:?}");
        assert!(diagnostic.contains("ForkDetected"), "{field}: {diagnostic}");
        assert!(!diagnostic.contains("AeadFailure"), "{field}: {diagnostic}");
        assert_eq!(last_seq(&bob, &cid), before_seq, "{field}");
        assert_eq!(
            bob.list_messages(&cid, None, 100).unwrap().len(),
            before_messages,
            "{field}"
        );
        assert_eq!(
            ds.inner.lock().unwrap().acked_watermarks,
            ack_before,
            "{field}"
        );
    }
    bob.db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &coordinate_key,
                &original,
                chrono::Utc::now().timestamp_millis(),
            )
        })
        .unwrap();
    bob.sync().expect("the matching coordinate applies");
    assert!(bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .iter()
        .any(|row| row.message_id == message_id));
}

/// Durable fork evidence is authenticated before it is written. A PDS-published outsider and a
/// current leaf with a forged I13 receipt are ordinary invalid entries: no marker, cursor, message
/// or ACK change. The same conflicting leaf entry with its genuine receipt still records and
/// reports `ForkDetected`; restoring the local coordinate then applies it.
///
/// The application receipt authenticates the conversation, seq, entry ID, sender and archive
/// commitment. It does not authenticate the signed-request digest or the prior hash/tag.
///
/// Fail-before: any PDS-authorized actor signature plus any receipt-shaped object wrote the marker.
#[test]
fn fork_marker_requires_a_current_leaf_and_valid_application_receipt() {
    let (tmp, ds, alice, bob, cid, _, _) = synced_group_pair();
    let outsider_device = new_id();
    let outsider = enrolled(&tmp, &ds, "fork-outsider", EVE_DID, &outsider_device);
    let message_id = new_id();
    alice
        .send_message(&cid, &message_id, "authenticated fork")
        .unwrap();
    let (at, genuine) = {
        let g = ds.inner.lock().unwrap();
        g.entries[&cid]
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry
                    .pointer("/signedRequest/body/messageId")
                    .and_then(Value::as_str)
                    == Some(message_id.as_str())
            })
            .map(|(at, entry)| (at, entry.clone()))
            .expect("sequenced application")
    };
    let coordinate_key = format!("conversation_coords:{cid}");
    let fork_key = chat_wire::fork_detected_key(&cid);
    let original = bob
        .db()
        .read_tx(|tx| tx.get_account_meta(&coordinate_key))
        .unwrap()
        .expect("local coordinate");
    let mut mismatched: Value = serde_json::from_str(&original).unwrap();
    mismatched["groupContextHash"] = json!({ "$bytes": STANDARD.encode([0x51_u8; 32]) });
    bob.db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &coordinate_key,
                &serde_json::to_string(&mismatched).unwrap(),
                chrono::Utc::now().timestamp_millis(),
            )
        })
        .unwrap();
    let before_seq = last_seq(&bob, &cid);
    let before_messages = bob.list_messages(&cid, None, 100).unwrap().len();
    let ack_before = ds.inner.lock().unwrap().acked_watermarks.clone();
    let serve = |entry: Value| {
        ds.inner.lock().unwrap().entries.get_mut(&cid).unwrap()[at] = entry;
    };
    let marker = || {
        bob.db()
            .read_tx(|tx| tx.get_account_meta(&fork_key))
            .unwrap()
    };

    let mut outsider_entry = genuine.clone();
    outsider_entry["signedRequest"] = signed_by(
        &enrolled_signer(&outsider),
        EVE_DID,
        &outsider_device,
        CanonicalOperation::SendMessage,
        &genuine["signedRequest"]["body"],
    );
    outsider_entry["sequencerReceipt"] = json!({ "arbitrary": true });
    let mut forged_receipt = genuine.clone();
    forged_receipt["sequencerReceipt"]["signature"] =
        json!({ "$bytes": STANDARD.encode([0_u8; 64]) });
    let mut violations = Vec::new();
    for (name, entry) in [
        ("PDS-published outsider", outsider_entry),
        ("leaf with forged receipt", forged_receipt),
    ] {
        serve(entry);
        let error = bob.sync().expect_err(name);
        if format!("{error:?}").contains("ForkDetected") {
            violations.push(format!("{name}: reported ForkDetected"));
        }
        if marker().is_some() {
            violations.push(format!("{name}: wrote a durable marker"));
        }
        assert_eq!(last_seq(&bob, &cid), before_seq, "{name}");
        assert_eq!(
            bob.list_messages(&cid, None, 100).unwrap().len(),
            before_messages,
            "{name}"
        );
        assert_eq!(
            ds.inner.lock().unwrap().acked_watermarks,
            ack_before,
            "{name}"
        );
        bob.db()
            .write_tx(|tx| tx.delete_account_meta(&fork_key))
            .unwrap();
    }

    serve(genuine);
    let error = bob
        .sync()
        .expect_err("the authenticated conflicting entry is a fork");
    assert!(format!("{error:?}").contains("ForkDetected"), "{error:?}");
    assert!(marker().is_some(), "authenticated fork evidence is durable");
    assert_eq!(last_seq(&bob, &cid), before_seq);
    assert_eq!(
        bob.list_messages(&cid, None, 100).unwrap().len(),
        before_messages
    );
    assert_eq!(ds.inner.lock().unwrap().acked_watermarks, ack_before);

    bob.db()
        .write_tx(|tx| {
            tx.put_account_meta(
                &coordinate_key,
                &original,
                chrono::Utc::now().timestamp_millis(),
            )
        })
        .unwrap();
    bob.sync()
        .expect("the genuine entry applies once coordinates match");
    assert!(bob
        .list_messages(&cid, None, 100)
        .unwrap()
        .iter()
        .any(|row| row.message_id == message_id));
    assert!(violations.is_empty(), "{violations:#?}");
}

/// Gap 4 regression. The production sync path initiates a real self-update once the configured
/// per-epoch durable-message threshold is exceeded, and the resulting Commit carries I13.
///
/// Fail-before: `self_update` was compiled only for `sim`, and production sync never advanced PCS.
#[test]
fn sync_automatically_self_updates_after_the_pcs_message_threshold() {
    use catbird_mls::sim_hooks::SimClientHooks;

    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let alice_device = new_id();
    let alice = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("pcs-alice").to_string_lossy().into_owned(),
            account_did: ALICE_DID.to_string(),
            device_id: alice_device.clone(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(ALICE_DID),
        None,
        SimClientHooks::default().with_pcs_policy(0, 1),
    )
    .expect("open PCS client");
    alice.enroll_device(&oauth_scopes()).unwrap();
    let bob = enrolled(&tmp, &ds, "pcs-bob", BOB_DID, &new_id());
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("PCS".into()),
            Some("group".into()),
        )
        .unwrap();
    bob.sync().unwrap();
    alice.sync().unwrap();
    bob.sync().unwrap();
    let before_epoch = alice
        .db()
        .read_tx(|tx| tx.get_conversation(&cid))
        .unwrap()
        .unwrap()
        .epoch;
    alice.send_message(&cid, &new_id(), "one").unwrap();
    alice.send_message(&cid, &new_id(), "two").unwrap();
    alice.sync().expect("sync performs automatic PCS");
    assert_eq!(
        alice
            .db()
            .read_tx(|tx| tx.get_conversation(&cid))
            .unwrap()
            .unwrap()
            .epoch,
        before_epoch + 1
    );
    let g = ds.inner.lock().unwrap();
    let commit = g.entries[&cid]
        .iter()
        .rev()
        .find(|entry| entry["$type"] == "blue.catbird.chat.defs#commitEntry")
        .expect("automatic PCS commit");
    assert!(commit["sequencerReceipt"].is_object(), "{commit}");
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

/// An exact close replay still needs its valid I13 receipt. A forged replay answer cannot consume
/// the journal or close locally; the next genuine replay applies the same terminal transition.
#[test]
fn close_replay_answer_requires_its_i13_receipt() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let (alice, cid) = open_group_for_close(&tmp, &ds);
    let before = close_state(&alice, &cid);

    ds.inner.lock().unwrap().lose_next_close_response = true;
    alice
        .close_conversation(&cid)
        .expect_err("the close response is lost");
    let journaled = close_state(&alice, &cid);
    assert_eq!(
        (journaled.0, journaled.1, &journaled.2, journaled.3),
        (false, before.1, &before.2, 1)
    );

    ds.inner.lock().unwrap().forge_next_close_replay_receipt = true;
    let error = alice
        .sync()
        .expect_err("a replay answer with a forged receipt is refused");
    assert!(
        error.to_string().contains("I13") || error.to_string().contains("receipt"),
        "{error}"
    );
    assert_eq!(
        close_state(&alice, &cid),
        journaled,
        "the unverified answer cannot consume the close journal"
    );

    alice.sync().expect("the next genuine replay closes");
    let (closed, seq, coords, journals) = close_state(&alice, &cid);
    assert!(closed);
    assert_eq!((seq, journals), (before.1 + 1, 0));
    assert_eq!(coords["lifecycle"], "superseded");
    let requests = close_requests(&ds);
    assert_eq!(requests.len(), 3);
    assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
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

/// Remove Bob's existing leaf, then create a real signed/I13-receipted re-invitation while
/// retaining his pinned conversation row. Only the inventory authority is replaced.
fn serve_bob_pending_again(f: &SendOrderFixture, inventory_sequencer: &str) {
    f.alice
        .remove_group_member(MemberRole::Admin, &f.cid, BOB_DID)
        .expect("remove Bob before re-inviting him");
    f.bob.sync().expect("Bob applies his removal");
    f.alice
        .add_group_members(&f.cid, vec![BOB_DID.to_string()])
        .expect("re-invite Bob without his old leaf");
    let invitation = {
        let mut g = f.ds.inner.lock().unwrap();
        let invitation = g.entries[&f.cid].last().unwrap().clone();
        let provenance = invitation["signedRequest"]["body"]["participantChanges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|change| change["userDid"] == BOB_DID)
            .unwrap()["invitationProvenance"]
            .clone();
        let state = g.conversations.get_mut(&f.cid).unwrap();
        state["sequencerDid"] = json!(inventory_sequencer);
        let participants = state["participants"].as_array_mut().unwrap();
        if let Some(bob) = participants
            .iter_mut()
            .find(|participant| participant["userDid"] == BOB_DID)
        {
            bob["status"] = json!("pending");
            bob["leafCount"] = json!(0);
            bob["invitationProvenance"] = provenance;
        } else {
            participants.push(json!({
                "userDid": BOB_DID,
                "role": "member",
                "status": "pending",
                "leafCount": 0,
                "invitationProvenance": provenance,
            }));
        }
        invitation
    };
    assert_eq!(
        chat_wire::signed_entry_kind(&invitation).unwrap(),
        SignedMutationKind::PolicyTransition
    );
    let seq = invitation["seq"].as_i64().unwrap();
    let body = &invitation["signedRequest"]["body"];
    let coordinates = chat_wire::canonicalize_wire_coordinate(&body["next"], Some(&f.cid))
        .unwrap()
        .to_string();
    f.bob
        .db()
        .write_tx(|tx| {
            tx.delete_account_meta(&chat_wire::invitation_closed_key(&f.cid, BOB_DID))?;
            let roster_key = chat_wire::conversation_roster_key(&f.cid);
            let mut roster: Value = serde_json::from_str(
                &tx.get_account_meta(&roster_key)?
                    .ok_or_else(|| MLSError::Internal("fixture roster missing".into()))?,
            )?;
            chat_wire::apply_roster_effects(
                &mut roster,
                SignedMutationKind::PolicyTransition,
                body,
            );
            let mut row = tx.get_conversation(&f.cid)?.unwrap();
            row.last_seq = seq;
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(&format!("conversation_coords:{}", f.cid), &coordinates, 0)?;
            tx.put_account_meta(&roster_key, &roster.to_string(), 0)
        })
        .unwrap();
}

fn own_recovery(client: &CatbirdMlsClient, cid: &str) -> Option<String> {
    client
        .db()
        .read_tx(|tx| tx.get_account_meta(&chat_wire::own_leaf_recovery_key(cid)))
        .unwrap()
}

fn own_acceptance_state(client: &CatbirdMlsClient, cid: &str) -> (i64, String, Option<String>) {
    client
        .db()
        .read_tx(|tx| {
            let row = tx.get_conversation(cid)?.unwrap();
            Ok((
                row.last_seq,
                tx.get_account_meta(&format!("conversation_coords:{cid}"))?
                    .unwrap(),
                tx.get_account_meta(&chat_wire::own_leaf_recovery_key(cid))?,
            ))
        })
        .unwrap()
}

/// A pending inventory row cannot replace Bob's retained sequencer pin for the receipt on his
/// own acceptance. A valid receipt from that unsigned substitute changes no local state; the
/// same inventory row with the pinned sequencer's receipt succeeds.
///
/// Fail-before: `accept_group_invitation` selected the inventory `sequencerDid`, accepted the
/// substitute receipt and persisted its recovery view.
#[test]
fn own_acceptance_prefers_the_existing_sequencer_pin() {
    let malicious = send_order_fixture(false);
    serve_bob_pending_again(&malicious, CROSS_HOME_DS_DID);
    malicious
        .ds
        .inner
        .lock()
        .unwrap()
        .next_group_acceptance_receipt_sequencer = Some(CROSS_HOME_DS_DID.to_owned());
    let before = own_acceptance_state(&malicious.bob, &malicious.cid);
    malicious
        .bob
        .sync()
        .expect_err("another sequencer's otherwise genuine receipt");
    assert_eq!(own_acceptance_state(&malicious.bob, &malicious.cid), before);
    assert_eq!(
        malicious
            .bob
            .db()
            .read_tx(|tx| Ok(tx.get_conversation(&malicious.cid)?.unwrap().sequencer_did))
            .unwrap(),
        DS_DID
    );

    let genuine = send_order_fixture(false);
    serve_bob_pending_again(&genuine, CROSS_HOME_DS_DID);
    genuine
        .bob
        .sync()
        .expect("the pinned sequencer's genuine receipt");
    assert!(own_recovery(&genuine.bob, &genuine.cid).is_some());
    assert_eq!(
        genuine
            .bob
            .db()
            .read_tx(|tx| Ok(tx.get_conversation(&genuine.cid)?.unwrap().sequencer_did))
            .unwrap(),
        DS_DID
    );
}

/// The receipt and recovery view returned for Bob's own acceptance must describe the request he
/// just submitted. An older genuinely signed and receipted acceptance beside the fresh recovery
/// view is refused without replacing the prior recovery metadata; an exact answer still succeeds.
///
/// Fail-before: the older entry verified independently and the fresh recovery view was persisted.
#[test]
fn own_acceptance_receipt_is_bound_to_the_submitted_request() {
    let replayed = send_order_fixture(false);
    serve_bob_pending_again(&replayed, DS_DID);
    replayed.bob.sync().expect("first exact acceptance");
    let old_entry = replayed.ds.inner.lock().unwrap().entries[&replayed.cid]
        .iter()
        .rev()
        .find(|entry| {
            entry["$type"] == "blue.catbird.chat.defs#participantAcceptanceEntry"
                && entry["signedRequest"]["body"]["actorDid"] == BOB_DID
        })
        .unwrap()
        .clone();
    serve_bob_pending_again(&replayed, DS_DID);
    replayed
        .ds
        .inner
        .lock()
        .unwrap()
        .next_group_acceptance_answer_entry = Some(old_entry);
    let before = own_recovery(&replayed.bob, &replayed.cid);
    let error = replayed
        .bob
        .sync()
        .expect_err("an older acceptance cannot authorize the fresh recovery")
        .to_string();
    assert!(error.contains("signed request"), "{error}");
    assert_eq!(own_recovery(&replayed.bob, &replayed.cid), before);

    let exact = send_order_fixture(false);
    serve_bob_pending_again(&exact, DS_DID);
    exact.bob.sync().expect("the exact acceptance answer");
    assert!(own_recovery(&exact.bob, &exact.cid).is_some());
}

/// An acceptance cannot make a never-invited account active when the sequencer withholds the
/// invitation history. Consequently no honest member fulfills that account's leaf request.
#[test]
fn withheld_invitation_never_admits_or_adds_the_never_invited_account() {
    let f = send_order_fixture(true);
    let (ds, cid, alice) = (&f.ds, f.cid.as_str(), &f.alice);
    f.eve.sync().expect("eve accepts");
    ds.inner.lock().unwrap().leaf_recoveries.remove(cid);
    let genuine = ds.inner.lock().unwrap().entries[cid]
        .last()
        .unwrap()
        .clone();
    let acceptance_seq = genuine["seq"].as_i64().unwrap();

    let carol_device = new_id();
    let carol = enrolled(&f.tmp, ds, "carol", CAROL_DID, &carol_device);
    let carol_signer = enrolled_signer(&carol);
    let mut forged_admission = genuine.clone();
    forged_admission["signedRequest"] = signed_by(
        &carol_signer,
        CAROL_DID,
        &carol_device,
        CanonicalOperation::AcceptConversation,
        &genuine["signedRequest"]["body"],
    );
    forged_admission
        .as_object_mut()
        .unwrap()
        .remove("sequencerReceipt");
    *ds.inner
        .lock()
        .unwrap()
        .entries
        .get_mut(cid)
        .unwrap()
        .last_mut()
        .unwrap() = forged_admission;
    ds.inner
        .lock()
        .unwrap()
        .readable_from
        .insert(f.alice_dev.clone(), acceptance_seq);

    let before_cursor = last_seq(alice, cid);
    let before_members = alice.list_members(cid).unwrap();
    let error = alice
        .sync()
        .expect_err("withheld invitation history leaves the acceptance pending");
    assert!(matches!(error, MLSError::SyncIncomplete { .. }), "{error}");
    assert_eq!(last_seq(alice, cid), before_cursor);
    assert_eq!(alice.list_members(cid).unwrap(), before_members);
    let roster: Value = serde_json::from_str(
        &alice
            .db()
            .read_tx(|tx| tx.get_account_meta(&chat_wire::conversation_roster_key(cid)))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(roster.get(CAROL_DID).is_none());

    ds.inner.lock().unwrap().conversations.get_mut(cid).unwrap()["participants"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "userDid": CAROL_DID,
            "status": "active",
            "role": "member",
            "leafCount": 0,
        }));
    let _ = carol.sync();
    let error = alice
        .sync()
        .expect_err("the never-invited acceptance remains refused");
    assert!(matches!(error, MLSError::SyncIncomplete { .. }));
    let _ = carol.sync();
    assert!(
        !alice
            .list_members(cid)
            .unwrap()
            .iter()
            .any(|did| did == CAROL_DID),
        "Carol never receives an MLS leaf"
    );
    {
        let mut state = ds.inner.lock().unwrap();
        *state.entries.get_mut(cid).unwrap().last_mut().unwrap() = genuine;
        state.readable_from.insert(f.alice_dev.clone(), 0);
        state
            .leaf_recoveries
            .get_mut(cid)
            .unwrap()
            .retain(|request| request["requesterDid"] != CAROL_DID);
    }
    alice
        .sync()
        .expect("honest contiguous invitation and acceptance recover");

    let secret_id = new_id();
    alice
        .send_message(cid, &secret_id, "invited members only")
        .expect("Alice sends to the unchanged group");
    let _ = carol.sync();
    assert!(
        !carol
            .list_messages(cid, None, 50)
            .map(|messages| messages
                .iter()
                .any(|message| message.message_id == secret_id))
            .unwrap_or(false),
        "Carol cannot decrypt the message"
    );
}

/// Alice invites Bob and Eve in the creation. Bob accepts and joins first; a second Alice
/// device joins from Alice's member-signed recovery Welcome before Eve accepts. Neither joined
/// device can read the creation entry, so both must carry Eve's pending admission proof from that
/// Welcome rather than demand the pre-join prefix.
#[test]
fn late_joiners_advance_and_can_fulfill_a_later_invitees_acceptance() {
    let f = send_order_fixture(true);
    let (ds, cid) = (&f.ds, f.cid.as_str());
    let alice_d_device = new_id();
    let alice_d = enrolled(&f.tmp, ds, "alice-d", ALICE_DID, &alice_d_device);
    alice_d.sync().expect("Alice D requests recovery");
    f.alice.sync().expect("Alice admits her later device");
    alice_d
        .sync()
        .expect("Alice D joins from the recovery Welcome");

    let bob_join_seq = last_seq(&f.bob, cid);
    let alice_d_join_seq = last_seq(&alice_d, cid);
    {
        let mut state = ds.inner.lock().unwrap();
        state.readable_from.insert(f.bob_dev.clone(), bob_join_seq);
        state
            .readable_from
            .insert(alice_d_device.clone(), alice_d_join_seq);
    }

    f.eve
        .sync()
        .expect("Eve accepts after Bob and Alice D joined");
    let acceptance_seq = ds.entry_count(cid);
    let acceptance_provenance = {
        let state = ds.inner.lock().unwrap();
        state.entries[cid].last().unwrap()["signedRequest"]["body"]["invitationProvenance"].clone()
    };
    let baseline = |client: &CatbirdMlsClient| -> Option<Value> {
        client
            .db()
            .read_tx(|tx| tx.get_account_meta(&chat_wire::conversation_roster_key(cid)))
            .unwrap()
            .map(|raw| serde_json::from_str(&raw).unwrap())
    };
    let bob_baseline = baseline(&f.bob);
    let alice_d_baseline = baseline(&alice_d);
    assert!(
        chat_wire::roster_has_pending_invitation(
            bob_baseline.as_ref(),
            EVE_DID,
            &acceptance_provenance
        ) && chat_wire::roster_has_pending_invitation(
            alice_d_baseline.as_ref(),
            EVE_DID,
            &acceptance_provenance
        ),
        "both member-authenticated baselines carry Eve's immutable pending provenance"
    );
    let bob_result = f.bob.sync();
    let alice_d_result = alice_d.sync();
    let (bob_cursor, alice_d_cursor, eve_has_leaf, fulfillment_count) = {
        let state = ds.inner.lock().unwrap();
        let leaves = state.conversations[cid]["leaves"]
            .as_array()
            .expect("server leaves");
        (
            last_seq(&f.bob, cid),
            last_seq(&alice_d, cid),
            leaves.iter().any(|leaf| leaf["userDid"] == EVE_DID),
            state.entries[cid]
                .iter()
                .filter(|entry| {
                    entry["$type"] == "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"
                        && entry["signedRequest"]["body"]["manifest"]["leafChanges"]
                            .as_array()
                            .is_some_and(|changes| {
                                changes.iter().any(|change| change["userDid"] == EVE_DID)
                            })
                })
                .count(),
        )
    };
    eprintln!(
        "late-join admission: bob={bob_result:?} cursor={bob_cursor}/{acceptance_seq}; \
         alice-d={alice_d_result:?} cursor={alice_d_cursor}/{acceptance_seq}; \
         eve_has_leaf={eve_has_leaf}; fulfillments={fulfillment_count}"
    );
    assert!(
        bob_result.is_ok()
            && alice_d_result.is_ok()
            && bob_cursor >= acceptance_seq
            && alice_d_cursor >= acceptance_seq
            && eve_has_leaf
            && fulfillment_count == 1,
        "member-attested pending admission must survive the unreadable pre-join prefix"
    );

    f.eve.sync().expect("Eve joins from Bob's fulfillment");
    let next_message = new_id();
    f.bob
        .send_message(cid, &next_message, "welcome after late acceptance")
        .expect("Bob sends after admitting Eve");
    f.eve.sync().expect("Eve reads the next message");
    assert!(f
        .eve
        .list_messages(cid, None, 100)
        .unwrap()
        .iter()
        .any(|message| message.message_id == next_message));

    let eve_second_device = new_id();
    let eve_second = live_client_homed(
        f.tmp.path(),
        ds,
        "eve-second",
        EVE_DID,
        &eve_second_device,
        &Arc::new(MemKeyStore::new()),
        CROSS_HOME_DS_DID,
    );
    eve_second
        .enroll_device(&oauth_scopes())
        .expect("enroll Eve's second device");
    eve_second
        .sync()
        .expect("Eve's second device requests recovery");
    alice_d
        .sync()
        .expect("the between-invitation Alice device can fulfill Eve's recovery");
    eve_second
        .sync()
        .expect("Eve's second device joins from Alice D's fulfillment");
    assert_eq!(
        ds.inner.lock().unwrap().entries[cid].last().unwrap()["signedRequest"]["body"]
            ["actorDeviceId"],
        alice_d_device,
        "Alice D authored the second honest fulfillment"
    );

    let alice_post_acceptance_device = new_id();
    let alice_post_acceptance = enrolled(
        &f.tmp,
        ds,
        "alice-post-acceptance",
        ALICE_DID,
        &alice_post_acceptance_device,
    );
    alice_post_acceptance
        .sync()
        .expect("post-acceptance device requests recovery");
    f.alice
        .sync()
        .expect("Alice admits her post-acceptance device");
    alice_post_acceptance
        .sync()
        .expect("post-acceptance device joins");
    assert!(
        alice_post_acceptance
            .db()
            .read_tx(|tx| {
                tx.get_account_meta(&chat_wire::verified_participant_admission_key(cid, EVE_DID))
            })
            .unwrap()
            .is_some(),
        "an active row in the member-signed Welcome grants admission authority"
    );
}

#[test]
fn nse_gap_defers_without_advancing_and_foreground_recovers_the_omitted_entry() {
    let fixture = NseReceiptFixture::new();
    let before = fixture.state();
    let omitted_id = new_id();
    fixture
        .alice
        .send_message(&fixture.cid, &omitted_id, "omitted from push")
        .expect("first message");
    fixture
        .alice
        .self_update(&fixture.cid)
        .expect("intervening commit");
    let later_id = new_id();
    fixture
        .alice
        .send_message(&fixture.cid, &later_id, "after the gap")
        .expect("later message");
    let mut bundle = fixture.bundle_after_bob_cursor();
    let omitted_seq = bundle.entries.remove(0).seq;

    let (preview, _) = fixture.process(bundle);
    assert!(preview.fallback_generic, "a gap defers to foreground sync");
    assert_eq!(
        fixture.state(),
        before,
        "the NSE advances no state across a gap"
    );
    fixture
        .bob
        .sync()
        .expect("foreground reads the complete contiguous page");
    let messages = fixture.bob.list_messages(&fixture.cid, None, 100).unwrap();
    assert!(messages
        .iter()
        .any(|message| message.message_id == omitted_id));
    assert!(messages
        .iter()
        .any(|message| message.message_id == later_id));
    assert!(fixture.state().1 > omitted_seq);
}

#[test]
fn nse_application_seq_must_match_its_receipt_before_any_cursor_advance() {
    let fixture = NseReceiptFixture::new();
    let before = fixture.state();
    let message_id = new_id();
    fixture
        .alice
        .send_message(&fixture.cid, &message_id, "receipt-bound sequence")
        .expect("message");
    let entry_seq = fixture.ds.entry_count(&fixture.cid);
    resign_receipt_seq(
        &fixture.ds,
        &fixture.cid,
        entry_seq,
        u64::try_from(entry_seq + 1_000).unwrap(),
    );
    let bundle = fixture.bundle_after_bob_cursor();
    resign_receipt_seq(
        &fixture.ds,
        &fixture.cid,
        entry_seq,
        u64::try_from(entry_seq).unwrap(),
    );
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].seq, entry_seq);

    let (preview, _) = fixture.process(bundle);
    assert!(
        preview.fallback_generic,
        "an outer sequence mismatch defers to foreground sync"
    );
    assert_eq!(
        fixture.state(),
        before,
        "the unauthenticated outer sequence changes nothing"
    );
    fixture
        .bob
        .sync()
        .expect("foreground applies the genuine sequenced entry");
    assert!(fixture
        .bob
        .list_messages(&fixture.cid, None, 100)
        .unwrap()
        .iter()
        .any(|message| message.message_id == message_id));
}

#[cfg(feature = "sim")]
#[test]
fn group_creation_signed_operation_expired_resigns_without_date_header_and_caps_at_eight_attempts()
{
    let (_tmp, ds, clock, alice, bob) = r4fix3_clocked_creation_fixture();
    let cid = new_id();
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        503,
        "CapacityUnavailable",
        None,
    ));
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.into()],
            Some("Server-authoritative expiry".into()),
            None,
        )
        .expect_err("initial create unavailable");
    let initial = staged_creation_fingerprint(&alice, &cid);
    assert_eq!(initial.attempts.len(), 1);

    // Even when the local clock has only advanced 10 s (far below the 360 s local safety bound),
    // server-side `400 SignedOperationExpired` proves the unclaimed attempt is past the server's
    // 300 s window and triggers re-signing over the identical staged genesis without `Date`.
    r4fix3_advance_server_and_client(&ds, &clock, 10_000);
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.createConversation",
        400,
        "SignedOperationExpired",
        None,
    ));
    let resigned_err = alice
        .sync()
        .expect_err("SignedOperationExpired appends a fresh signed attempt");
    assert!(
        matches!(&resigned_err, MLSError::SyncIncomplete { failures, .. }
            if matches!(failures.as_slice(), [failure]
                if failure.conversation_id == cid
                    && matches!(&*failure.error, MLSError::GroupCreationPending {
                        last_error_code, ..
                    } if last_error_code == "GroupCreationResigned"))),
        "{resigned_err:?}"
    );
    let second = staged_creation_fingerprint(&alice, &cid);
    assert_eq!(second.attempts.len(), 2);
    assert_eq!(second.attempts[0].0, initial.operation_id);

    // Push past GROUP_CREATION_MAX_ATTEMPTS (8): attempts[0] (the journal_id anchor) must stay
    // pinned at index 0 while total stored attempts never exceed 8.
    for _ in 0..9 {
        let current_len = staged_creation_fingerprint(&alice, &cid).attempts.len();
        r4fix3_advance_server_and_client(&ds, &clock, 1_000);
        {
            let mut state = ds.inner.lock().unwrap();
            for _ in 0..current_len {
                state.xrpc_failures.push((
                    "/blue.catbird.chat.createConversation",
                    400,
                    "SignedOperationExpired",
                    None,
                ));
            }
        }
        alice
            .retry_pending_group_creation(&cid)
            .expect_err("all attempts expired -> appends bounded fresh signature");
    }
    let capped = staged_creation_fingerprint(&alice, &cid);
    assert_eq!(
        capped.attempts.len(),
        chat_wire::GROUP_CREATION_MAX_ATTEMPTS
    );
    assert_eq!(
        capped.attempts[0].0, initial.operation_id,
        "attempts[0] must remain anchored to journal_id across evictions"
    );
    assert_eq!(capped.attempts[0].1, initial.request);
    assert_eq!(capped.group_id, initial.group_id);
    assert_eq!(capped.epoch_authenticator, initial.epoch_authenticator);

    // Now let the newest attempt succeed after the earlier 7 return SignedOperationExpired.
    {
        let mut state = ds.inner.lock().unwrap();
        for _ in 0..(chat_wire::GROUP_CREATION_MAX_ATTEMPTS - 1) {
            state.xrpc_failures.push((
                "/blue.catbird.chat.createConversation",
                400,
                "SignedOperationExpired",
                None,
            ));
        }
    }
    alice
        .retry_pending_group_creation(&cid)
        .expect("latest attempt commits")
        .expect("adopted conversation");
    assert_eq!(group_creation_journal_count(&alice), 0);
    assert_eq!(
        adopted_epoch_authenticator(&alice, &cid),
        initial.epoch_authenticator
    );
    finish_resumed_group(&alice, &bob, &cid);
}

#[test]
fn enroll_device_only_adopts_own_device_on_device_already_exists_refusal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes = oauth_scopes();
    let alice_dev = new_id();
    let alice_keys = Arc::new(MemKeyStore::new());
    let alice = live_client(
        tmp.path(),
        &ds,
        "alice-mut1145",
        ALICE_DID,
        &alice_dev,
        &alice_keys,
    );

    // First call registers on DS and persists signer, then loses the HTTP response before local
    // completion or PDS writes.
    ds.inner.lock().unwrap().lose_next_enroll_response = true;
    assert!(alice.enroll_device(&scopes).is_err());

    // A subsequent non-`DeviceAlreadyExists` refusal (e.g. `429 RateLimited`) MUST NOT fall into
    // `own_enrolled_device` adoption even though `getOwnDevices` would succeed!
    ds.inner.lock().unwrap().xrpc_failures.push((
        "/blue.catbird.chat.enrollDevice",
        429,
        "RateLimited",
        None,
    ));
    let err = alice
        .enroll_device(&scopes)
        .expect_err("non-DeviceAlreadyExists error must not adopt DS enrollment");
    assert!(
        matches!(&err, MLSError::InvalidState(code) if code == "RateLimited"),
        "expected RateLimited refusal, got {err:?}"
    );
    let pds_writes = ds
        .inner
        .lock()
        .unwrap()
        .http_log
        .iter()
        .filter(|(account, url, _)| {
            account == ALICE_DID
                && (url.ends_with("/xrpc/com.atproto.repo.putRecord")
                    || url.ends_with("/xrpc/com.atproto.repo.createRecord"))
        })
        .count();
    assert_eq!(
        pds_writes, 0,
        "no PDS write may occur on RateLimited refusal"
    );
}

struct ContendedDirectRequestTransport {
    inner: Arc<dyn PlatformTransport>,
    client: Mutex<Option<std::sync::Weak<CatbirdMlsClient>>>,
    peer_did: String,
    prepare_calls: std::sync::atomic::AtomicUsize,
}

impl PlatformTransport for ContendedDirectRequestTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let response = self.inner.execute_http(request.clone())?;
        if request
            .url
            .ends_with("/xrpc/blue.catbird.chat.prepareDirectRequest")
        {
            let call = self.prepare_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(client) = self
                .client
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
            {
                let peer_did = self.peer_did.clone();
                client
                    .db()
                    .write_tx(|tx| {
                        let raw = tx
                            .get_pending_op("direct_request_creation", &peer_did)?
                            .expect("pending direct request journal");
                        let mut value: Value = serde_json::from_str(&raw).unwrap();
                        value["intro_text"] = json!(format!("contended-{call}"));
                        let mutated = serde_json::to_string(&value).unwrap();
                        assert!(tx.compare_exchange_pending_op(
                            "direct_request_creation",
                            &peer_did,
                            Some(&raw),
                            &mutated,
                            call as i64,
                        )?);
                        Ok(())
                    })
                    .expect("mutate direct_request_creation CAS target");
            }
        }
        Ok(response)
    }

    fn connect_realtime_stream(&self, _url: String, _cursor: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

#[test]
fn direct_request_creation_cas_contention_terminates_after_four_attempts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let scopes = oauth_scopes();
    let transport = Arc::new(ContendedDirectRequestTransport {
        inner: ds.for_account(ALICE_DID),
        client: Mutex::new(None),
        peer_did: BOB_DID.to_string(),
        prepare_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("alice-u01").to_string_lossy().into(),
            account_did: ALICE_DID.into(),
            device_id: new_id(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        transport.clone(),
        None,
    )
    .expect("open alice");
    let bob = enrolled(&tmp, &ds, "bob-u01", BOB_DID, &new_id());
    alice.enroll_device(&scopes).expect("enroll alice");
    // Replenish enough Bob DR keys so 4 prepare calls never exhaust the pool before CAS bound triggers.
    let _ = &bob;
    {
        let mut g = ds.inner.lock().unwrap();
        let sample = g.dr_keys[BOB_DID][0].clone();
        while g.dr_keys[BOB_DID].len() < 8 {
            g.dr_keys.get_mut(BOB_DID).unwrap().push(sample.clone());
        }
    }
    *transport.client.lock().unwrap() = Some(Arc::downgrade(&alice));

    let err = alice
        .create_group(
            &new_id(),
            DS_DID,
            vec![BOB_DID.into()],
            None,
            Some("Hello under contention".into()),
        )
        .expect_err("persistent CAS contention must terminate cleanly");
    assert!(
        matches!(&err, MLSError::InvalidState(code) if code == "DirectRequestJournalContention"),
        "expected DirectRequestJournalContention, got {err:?}"
    );
    assert_eq!(
        transport.prepare_calls.load(Ordering::SeqCst),
        4,
        "CAS loop must execute at most 4 attempts"
    );
}

#[test]
fn live_remove_recovery_method_retires_old_bundle_and_preserves_replacement_code() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ds = SharedMockDs::new();
    let bob_orig_dev = new_id();
    let bob_orig = enrolled(&tmp, &ds, "bob-rot-orig", BOB_DID, &bob_orig_dev);

    // 1. Mint initial recovery code on Bob's original device and acknowledge its receipt.
    let initial = bob_orig
        .setup_recovery_code_with_receipt()
        .expect("setup initial recovery code");
    bob_orig
        .acknowledge_recovery_generation(initial.recovery_generation)
        .expect("acknowledge initial generation");

    let before_methods = bob_orig
        .list_recovery_methods()
        .expect("list initial recovery methods");
    assert_eq!(before_methods.len(), 1);
    let old_method = &before_methods[0];
    assert_eq!(old_method.mechanism, "code");
    assert!(!old_method.revoked);
    let old_vdevice_id = old_method.vdevice_id.clone();
    assert_eq!(old_vdevice_id.len(), 16);

    // Reject malformed vdevice_id lengths fail-closed before touching mailbox state.
    assert!(matches!(
        bob_orig.remove_recovery_method(vec![0u8; 15]),
        Err(MLSError::InvalidInput { .. })
    ));

    // 2. Mint fresh replacement recovery code BEFORE retiring the exposed code, keeping
    //    the replacement receipt unacknowledged during old-method removal.
    let replacement = bob_orig
        .setup_recovery_code_with_receipt()
        .expect("setup replacement recovery code");
    assert!(replacement.recovery_generation > initial.recovery_generation);
    assert_ne!(replacement.code, initial.code);

    let both_methods = bob_orig
        .list_recovery_methods()
        .expect("list both active recovery methods");
    assert_eq!(both_methods.len(), 2);
    let new_vdevice_id = both_methods
        .iter()
        .find(|m| m.vdevice_id != old_vdevice_id)
        .expect("distinct replacement method ID")
        .vdevice_id
        .clone();

    // 3. Retire the old method by exact verified vdevice_id.
    let epoch_before = bob_orig
        .labyrinth_status()
        .expect("status before")
        .epoch_seq;
    let outcome = bob_orig
        .remove_recovery_method(old_vdevice_id.clone())
        .expect("remove old recovery method");
    assert!(
        outcome.status.epoch_seq > epoch_before,
        "removing a recovery method must advance the mailbox epoch"
    );
    assert!(outcome.rekeyed_recovery_code.is_none());
    assert!(outcome.status.has_recovery_code);
    assert_eq!(
        outcome.status.recovery_generation,
        replacement.recovery_generation,
        "unacknowledged replacement receipt generation must remain intact across old-method removal"
    );
    assert!(outcome.status.recovery_needs_attention);

    // Replacement receipt can still be acknowledged cleanly at its recorded generation.
    let acked = bob_orig
        .acknowledge_recovery_generation(replacement.recovery_generation)
        .expect("acknowledge replacement generation after old-method removal");
    assert!(!acked.recovery_needs_attention);

    // 4. Verify only the replacement method remains active and the old bundle is gone.
    let after_methods = bob_orig
        .list_recovery_methods()
        .expect("list methods after removal");
    assert_eq!(after_methods.len(), 1);
    assert_eq!(after_methods[0].vdevice_id, new_vdevice_id);
    assert!(!after_methods[0].revoked);
    assert!(
        bob_orig.remove_recovery_method(old_vdevice_id).is_err(),
        "deleted virtual device bundle must not be removable a second time"
    );

    // 5. Verify a fresh device CANNOT restore with the retired code, and CAN restore with the replacement code.
    let bob_stale = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("bob-rot-stale").to_string_lossy().into(),
            account_did: BOB_DID.into(),
            device_id: new_id(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(BOB_DID),
        None,
    )
    .expect("open bob_stale");
    assert!(
        bob_stale.restore_with_recovery_code(&initial.code).is_err(),
        "retired recovery code must fail to restore after remove_recovery_method"
    );

    let bob_fresh = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join("bob-rot-fresh").to_string_lossy().into(),
            account_did: BOB_DID.into(),
            device_id: new_id(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: DS_URL.into(),
            pds_endpoint: PDS_URL.into(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(BOB_DID),
        None,
    )
    .expect("open bob_fresh");
    let restored = bob_fresh
        .restore_with_recovery_code(&replacement.code)
        .expect("replacement recovery code must restore cleanly");
    assert!(restored.backup_enabled);
    assert!(restored.epoch_seq > outcome.status.epoch_seq);
}

/// Reading a conversation clears its unread count down to the peer messages that arrived after
/// the newest message the reader saw, and an incoming message after that counts again.
///
/// Fail-before: nothing ever lowered `unread_count`. Opening a conversation only acknowledged
/// entries and advanced the archive read state, so the list kept showing every received
/// message as unread.
#[test]
fn mark_conversation_read_recounts_unread_above_read_point() {
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
            None,
            Some("opening".into()),
        )
        .expect("alice's request");
    bob.sync().expect("bob imports the request");
    let request = bob
        .list_requests(Some("incomingPending"))
        .unwrap()
        .remove(0);
    bob.accept_direct_request(&request.request_id)
        .expect("bob accepts");
    alice.sync().expect("alice syncs acceptance");

    fn unread(client: &CatbirdMlsClient, cid: &str) -> i64 {
        client
            .list_conversations(None, 20)
            .unwrap()
            .into_iter()
            .find(|row| row.conversation_id == cid)
            .expect("conversation listed")
            .unread_count
    }
    fn max_peer_seq(client: &CatbirdMlsClient, cid: &str) -> i64 {
        client
            .list_messages(cid, None, 50)
            .unwrap()
            .iter()
            .filter(|m| !m.is_own)
            .map(|m| m.seq)
            .max()
            .expect("peer messages stored")
    }

    for text in ["one", "two"] {
        alice.send_message(&cid, &new_id(), text).unwrap();
    }
    bob.sync().expect("bob receives two messages");
    let before = unread(&bob, &cid);
    assert!(before >= 2, "received messages count as unread, got {before}");

    let read_through = max_peer_seq(&bob, &cid);
    assert_eq!(bob.mark_conversation_read(&cid, read_through).unwrap(), 0);
    assert_eq!(unread(&bob, &cid), 0, "the list reflects the read");

    alice.send_message(&cid, &new_id(), "three").unwrap();
    bob.sync().expect("bob receives a later message");
    assert_eq!(unread(&bob, &cid), 1, "a message after the read point is unread");
    assert_eq!(
        bob.mark_conversation_read(&cid, read_through).unwrap(),
        1,
        "reading only through the earlier point leaves the newer message unread"
    );
    assert_eq!(
        bob.mark_conversation_read(&cid, max_peer_seq(&bob, &cid)).unwrap(),
        0
    );
}
