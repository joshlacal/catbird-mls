//! Clean-slate Labyrinth XRPC transport and verifying `mls-ds` directory client.
//!
//! `mls-ds` stores zero mailboxes, sender batches, MEKs, attachment references,
//! or ORF state (`G6`, `I14`, `2A`). This module drives the 6 zero-content
//! `blue.catbird.labyrinth.*` endpoints (`publishEpochHead`, `purgeMailbox`,
//! `deleteAccountData`, `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`)
//! plus `blue.catbird.chat.getConversationState`, with device-signed write and
//! read headers (`catbird-labyrinth-write*`, `catbird-labyrinth-read*`).

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use labyrinth::mailbox::EpochPublic;
use labyrinth::records::{ms_from_datetime, EpochPublicDef, MailboxKeysRecord};
use labyrinth::store::pds::PublicRepoBackend;
use labyrinth::store::{
    ChatDeviceKey, KeyPublisher, MailboxDirectory, MaybeSend, MaybeSync, MemberDeviceKey,
    SequencerReceiptKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::signer::ChatKeySigner;
use super::write_auth::{
    read_headers, write_headers, ReadClaim, WriteBody, KEY_PROOF_HEADER, REVOCATION_PROOF_HEADER,
};
use super::LabyrinthRequest;
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::canonical_transport::{
    encode_query, CanonicalOperation, GatewayResponse, PreparedRequest,
};

/// NSID prefix of every `mls-ds` Labyrinth endpoint.
pub const NSID_PREFIX: &str = "blue.catbird.labyrinth.";
const RECOVERY_SHARE_CAPABILITY_NSID: &str =
    "blue.catbird.labyrinth.getRecoveryShareCapabilities";

/// Transport-level error from a Labyrinth XRPC call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XrpcTransportError {
    pub status: u16,
    pub error: Option<String>,
    pub message: Option<String>,
}

/// Maps [`XrpcTransportError`] to [`labyrinth::Error`].
pub fn map_xrpc_error(e: XrpcTransportError) -> labyrinth::Error {
    let not_found_status = e.status == 404 || e.status == 400;
    match e.error.as_deref() {
        Some("EpochNotFound") if not_found_status => labyrinth::Error::NotFound("epoch"),
        Some("ConversationNotFound") if not_found_status => {
            labyrinth::Error::NotFound("conversation")
        }
        Some("EpochHeadConflict" | "RecordAlreadyExists" | "InvalidSwap") => {
            labyrinth::Error::Conflict
        }
        Some("InvalidEpochChain") if e.status == 400 || e.status == 409 => {
            labyrinth::Error::Conflict
        }
        // A kicked or never-joined device may not read live conversation state (exact
        // protocol errors, HTTP 400); callers fall back to saved placement / owner-mode
        // exactly as for HTTP 403.
        Some("NotEntitled" | "AccessOutsideMembershipInterval" | "ChatDeviceNotActive")
            if e.status == 400 =>
        {
            labyrinth::Error::Forbidden
        }
        _ if e.status == 401 || e.status == 403 => labyrinth::Error::Forbidden,
        name => labyrinth::Error::Backend(format!(
            "xrpc {}: {}: {}",
            e.status,
            name.unwrap_or("no error name"),
            e.message.as_deref().unwrap_or("")
        )),
    }
}

/// Async access to the platform gateway (`?Send` on `wasm32`, `Send + Sync` on native).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait LabyrinthGateway: MaybeSend + MaybeSync {
    /// A `blue.catbird.labyrinth.*` request.
    async fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String>;
    /// A clean-chat query through the canonical route, carrying the signed
    /// Labyrinth read headers unchanged.
    async fn submit_canonical(
        &self,
        request: PreparedRequest,
        headers: Vec<(String, String)>,
    ) -> Result<GatewayResponse, String>;
    /// Per-conversation `I13` P-256 ES256 receipt verifying key for `sequencer_did`.
    async fn resolve_sequencer_receipt_key_for(
        &self,
        _conversation_id: &str,
        _sequencer_did: Option<&str>,
    ) -> Option<(String, Vec<u8>)> {
        None
    }
    /// Resolve a DID document JSON payload (`did:web` / `did:plc`) for federated sequencer key discovery.
    async fn resolve_did_document(&self, _did: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

/// [`LabyrinthGateway`] over [`MLSAPIClient`].
pub struct ApiGateway<A> {
    api: Arc<A>,
}

impl<A> ApiGateway<A> {
    pub fn new(api: Arc<A>) -> Self {
        Self { api }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<A: MLSAPIClient + 'static> LabyrinthGateway for ApiGateway<A> {
    async fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String> {
        self.api
            .submit_labyrinth_request(request)
            .await
            .map_err(|e| e.to_string())
    }

    async fn submit_canonical(
        &self,
        request: PreparedRequest,
        headers: Vec<(String, String)>,
    ) -> Result<GatewayResponse, String> {
        self.api
            .submit_labyrinth_request(LabyrinthRequest {
                nsid: request.operation.nsid().to_owned(),
                method: request.method,
                path: request.path,
                body: request.body,
                headers,
            })
            .await
            .map_err(|e| e.to_string())
    }

    async fn resolve_sequencer_receipt_key_for(
        &self,
        conversation_id: &str,
        sequencer_did: Option<&str>,
    ) -> Option<(String, Vec<u8>)> {
        self.api
            .labyrinth_sequencer_receipt_key_for(conversation_id, sequencer_did)
            .await
    }

    async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        self.api
            .resolve_labyrinth_did_document(did)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<A: MLSAPIClient + 'static> super::space::LabyrinthSpaceGateway for ApiGateway<A> {
    async fn submit_space(
        &self,
        request: super::space::LabyrinthSpaceRequest,
    ) -> Result<GatewayResponse, String> {
        self.api
            .submit_labyrinth_space_request(request)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Maximum response payload accepted from a Labyrinth XRPC call (4 MiB).
pub const MAX_LABYRINTH_XRPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum size of a PDS `mailboxKeys` repository record (256 KiB).
pub const MAX_PDS_RECORD_BYTES: usize = 256 * 1024;

pub(crate) fn enforce_pds_record_cap(record: &[u8]) -> Result<(), String> {
    if record.len() > MAX_PDS_RECORD_BYTES {
        return Err(format!(
            "PDS record exceeds {} byte limit ({} bytes)",
            MAX_PDS_RECORD_BYTES,
            record.len()
        ));
    }
    Ok(())
}

/// Validates ATProto NSID syntax (`[A-Za-z0-9-]` segments separated by `.`,
/// >= 3 non-empty segments, no `/`, `?`, `#`, `%`, or `..`) before formatting `/xrpc/{nsid}`.
pub(crate) fn validate_nsid(nsid: &str) -> Result<(), XrpcTransportError> {
    if nsid.is_empty() || nsid.len() > 317 {
        return Err(transport_error(format!(
            "invalid XRPC NSID length: {}",
            nsid.len()
        )));
    }
    let mut segments = 0usize;
    for seg in nsid.split('.') {
        segments += 1;
        if seg.is_empty()
            || seg.len() > 63
            || seg.starts_with('-')
            || seg.ends_with('-')
            || !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(transport_error(format!("invalid XRPC NSID syntax: {nsid}")));
        }
    }
    if segments < 3 {
        return Err(transport_error(format!(
            "invalid XRPC NSID segments: {nsid}"
        )));
    }
    Ok(())
}

/// The PDS half of the Labyrinth directory ([CB-19], Gate 3) through
/// `MLSAPIClient`'s `*_labyrinth_mailbox_keys*` gateway methods.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<A: MLSAPIClient + 'static> PublicRepoBackend for ApiGateway<A> {
    async fn put_mailbox_keys(
        &self,
        _did: &str,
        rkey: &str,
        record: &[u8],
        swap_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        enforce_pds_record_cap(record).map_err(labyrinth::Error::Backend)?;
        self.api
            .put_labyrinth_mailbox_keys_cas(rkey, record, swap_cid)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("InvalidSwap") || msg.contains("Conflict") {
                    labyrinth::Error::Conflict
                } else {
                    labyrinth::Error::Backend(msg)
                }
            })
    }

    async fn get_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
        let out = self
            .api
            .get_labyrinth_mailbox_keys_with_cid(did, rkey)
            .await
            .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
        if let Some((ref bytes, _)) = out {
            enforce_pds_record_cap(bytes).map_err(labyrinth::Error::Backend)?;
        }
        Ok(out)
    }

    async fn delete_all_mailbox_keys(&self, _did: &str) -> labyrinth::Result<()> {
        self.api
            .delete_labyrinth_mailbox_keys()
            .await
            .map_err(|e| labyrinth::Error::Backend(e.to_string()))
    }
}

/// Device-signed async XRPC transport for `mls-ds` Labyrinth directory & chat state queries.
pub struct GatewayXrpcTransport {
    gateway: Arc<dyn LabyrinthGateway>,
    signer: Arc<dyn ChatKeySigner>,
    did: String,
    device_id: String,
    clock: Arc<dyn labyrinth::client::Clock>,
    home_ds_did: Option<String>,
}

impl GatewayXrpcTransport {
    pub fn new(
        gateway: Arc<dyn LabyrinthGateway>,
        signer: Arc<dyn ChatKeySigner>,
        did: String,
        device_id: String,
    ) -> Self {
        Self {
            gateway,
            signer,
            did,
            device_id,
            clock: Arc::new(labyrinth::client::SystemClock),
            home_ds_did: None,
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn labyrinth::client::Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The configured home delivery-service DID. Recovery-share calls also
    /// require an independently proven pin in the encrypted placement vault.
    pub fn with_home_ds_did(mut self, did: String) -> Self {
        self.home_ds_did = Some(did);
        self
    }

    pub(crate) fn home_ds_did(&self) -> Option<&str> {
        self.home_ds_did.as_deref()
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn wire_params<'a>(
        &self,
        nsid: &str,
        params: &[(&'a str, String)],
    ) -> Vec<(&'a str, String)> {
        let include_device = nsid != RECOVERY_SHARE_CAPABILITY_NSID;
        let mut all = Vec::with_capacity(params.len() + usize::from(include_device));
        if include_device {
            all.push(("actorDeviceId", self.device_id.clone()));
        }
        all.extend(params.iter().cloned());
        all
    }

    fn query_path(nsid: &str, params: &[(&str, String)]) -> String {
        let query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
            .collect();
        if query.is_empty() {
            format!("/xrpc/{nsid}")
        } else {
            format!("/xrpc/{nsid}?{}", query.join("&"))
        }
    }

    fn read_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<(String, String)>, XrpcTransportError> {
        let now = self.now_ms();
        let claim = ReadClaim::new(nsid, params, &self.did, &self.device_id, now);
        let json = claim.to_json();
        let signature = self
            .signer
            .sign(&ReadClaim::signing_input(&json))
            .map_err(signing_error)?;
        Ok(read_headers(&json, &signature))
    }

    pub async fn query(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<u8>, XrpcTransportError> {
        self.query_with_headers(nsid, params, &[]).await
    }

    pub async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcTransportError> {
        validate_nsid(nsid)?;
        let canonical = CanonicalOperation::ALL
            .iter()
            .copied()
            .find(|op| op.nsid() == nsid);
        if canonical.is_none() && !nsid.starts_with(NSID_PREFIX) {
            return Err(transport_error(format!(
                "refusing a non-Labyrinth query: {nsid}"
            )));
        }
        let params = self.wire_params(nsid, params);
        let path = Self::query_path(nsid, &params);
        let mut all = headers.to_vec();
        all.extend(self.read_headers(nsid, &params)?);
        let response = match canonical {
            Some(operation) => {
                self.gateway
                    .submit_canonical(
                        PreparedRequest {
                            operation,
                            method: "GET".into(),
                            path,
                            body: None,
                        },
                        all,
                    )
                    .await
            }
            None => {
                self.gateway
                    .submit_labyrinth(LabyrinthRequest {
                        nsid: nsid.to_owned(),
                        method: "GET".into(),
                        path,
                        body: None,
                        headers: all,
                    })
                    .await
            }
        };
        decode_response(response)
    }

    pub async fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
        operation_id: [u8; 16],
    ) -> Result<Vec<u8>, XrpcTransportError> {
        let signed_at =
            chrono::DateTime::from_timestamp_millis(self.now_ms().min(i64::MAX as u64) as i64)
                .ok_or_else(|| transport_error("invalid archive clock"))?;
        self.procedure_at_with_headers(nsid, payload, operation_id, signed_at, &[])
            .await
    }

    pub async fn procedure_at_with_headers(
        &self,
        nsid: &str,
        payload: &[u8],
        operation_id: [u8; 16],
        signed_at: chrono::DateTime<chrono::Utc>,
        extra_headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcTransportError> {
        validate_nsid(nsid)?;
        if !nsid.starts_with(NSID_PREFIX) {
            return Err(transport_error(format!(
                "refusing a non-Labyrinth procedure: {nsid}"
            )));
        }
        let body = WriteBody::new(nsid, payload, operation_id, &self.device_id, signed_at);
        let json = body.to_json();
        let signature = self
            .signer
            .sign(&WriteBody::signing_input(&json))
            .map_err(signing_error)?;
        let mut headers = write_headers(&json, &signature);
        headers.extend(extra_headers.iter().cloned());
        decode_response(
            self.gateway
                .submit_labyrinth(LabyrinthRequest {
                    nsid: nsid.to_owned(),
                    method: "POST".into(),
                    path: format!("/xrpc/{nsid}"),
                    body: Some(payload.to_vec()),
                    headers,
                })
                .await,
        )
    }

    pub async fn resolve_sequencer_receipt_key_for(
        &self,
        conversation_id: &str,
        sequencer_did: Option<&str>,
    ) -> Option<(String, Vec<u8>)> {
        self.gateway
            .resolve_sequencer_receipt_key_for(conversation_id, sequencer_did)
            .await
    }

    pub async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        self.gateway.resolve_did_document(did).await
    }
}

pub(crate) const SIGNING_FAILED: &str = "ChatKeySigningFailed";

fn signing_error(message: String) -> XrpcTransportError {
    XrpcTransportError {
        status: 0,
        error: Some(SIGNING_FAILED.into()),
        message: Some(message),
    }
}

pub(crate) fn transport_error(message: impl Into<String>) -> XrpcTransportError {
    XrpcTransportError {
        status: 0,
        error: None,
        message: Some(message.into()),
    }
}

/// Decodes a 2xx body up to `max_bytes`, or parses the ATProto error JSON `{"error","message"}`.
pub(crate) fn decode_response_bounded(
    response: Result<GatewayResponse, String>,
    max_bytes: usize,
) -> Result<Vec<u8>, XrpcTransportError> {
    let response = response.map_err(transport_error)?;
    if response.body.len() > max_bytes {
        return Err(transport_error(format!(
            "XRPC response body exceeds {} byte limit ({} bytes)",
            max_bytes,
            response.body.len()
        )));
    }
    if (200..300).contains(&response.status) {
        return Ok(response.body);
    }
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&response.body).ok();
    let field = |k: &str| {
        parsed
            .as_ref()
            .and_then(|v| v[k].as_str())
            .map(str::to_owned)
    };
    Err(XrpcTransportError {
        status: response.status,
        error: field("error"),
        message: field("message"),
    })
}

pub(crate) fn decode_response(
    response: Result<GatewayResponse, String>,
) -> Result<Vec<u8>, XrpcTransportError> {
    decode_response_bounded(response, MAX_LABYRINTH_XRPC_RESPONSE_BYTES)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetEpochHeadOut {
    epoch: EpochPublicDef,
    #[serde(default)]
    chain: Vec<EpochPublicDef>,
    #[serde(default)]
    floor_seq: Option<u64>,
}

#[derive(Deserialize)]
struct WireBytesField {
    #[serde(rename = "$bytes")]
    bytes: String,
}

impl WireBytesField {
    fn decode_32(&self) -> labyrinth::Result<[u8; 32]> {
        let raw = STANDARD_NO_PAD
            .decode(&self.bytes)
            .or_else(|_| STANDARD.decode(&self.bytes))
            .map_err(|_| labyrinth::Error::Malformed("$bytes base64"))?;
        raw.as_slice()
            .try_into()
            .map_err(|_| labyrinth::Error::Malformed("32-byte key length"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatDeviceKeyItem {
    signing_public_key: WireBytesField,
    #[serde(default)]
    revoked_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberDeviceItem {
    signing_public_key: WireBytesField,
    joined_seq: u64,
    #[serde(default)]
    removed_seq: Option<u64>,
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: serde::de::Deserialize<'de>"))]
struct PageOut<T> {
    #[serde(default)]
    items: Vec<T>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Serialize)]
struct PublishEpochHeadIn<'a> {
    epoch: &'a EpochPublicDef,
}

pub(crate) fn deterministic_op_id(tag: &str, payload: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0u8]);
    h.update(payload);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[derive(Clone, Default)]
struct ParsedSequencerKeys {
    receipt_keys: std::collections::BTreeMap<String, SequencerReceiptKey>,
}

impl ParsedSequencerKeys {
    fn current_receipt_key(&self) -> Option<SequencerReceiptKey> {
        self.receipt_keys
            .iter()
            .max_by_key(|(key_id, key)| {
                labyrinth::protocol::receipt_key_generation(&key.did, key_id).unwrap_or(0)
            })
            .map(|(_, key)| key.clone())
    }
}

fn normalize_sequencer_did(raw: &str) -> String {
    raw.split('#')
        .next()
        .unwrap_or(raw)
        .trim_end_matches('/')
        .to_owned()
}

fn parse_did_doc_sequencer_keys(
    expected_did: &str,
    doc_bytes: &[u8],
) -> labyrinth::Result<ParsedSequencerKeys> {
    enforce_pds_record_cap(doc_bytes).map_err(labyrinth::Error::Backend)?;
    let doc: serde_json::Value = serde_json::from_slice(doc_bytes)
        .map_err(|_| labyrinth::Error::Malformed("sequencer DID document JSON"))?;
    let base_did = normalize_sequencer_did(expected_did);
    if let Some(doc_id) = doc.get("id").and_then(|v| v.as_str()) {
        if normalize_sequencer_did(doc_id) != base_did {
            return Err(labyrinth::Error::Malformed(
                "sequencer DID document id mismatch",
            ));
        }
    }
    let mut parsed = ParsedSequencerKeys::default();
    if let Some(methods) = doc.get("verificationMethod").and_then(|v| v.as_array()) {
        for m in methods {
            let Some(id) = m.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(ctrl) = m.get("controller").and_then(|v| v.as_str()) {
                if normalize_sequencer_did(ctrl) != base_did {
                    continue;
                }
            }
            let Some(mb) = m.get("publicKeyMultibase").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok((_, raw)) = multibase::decode(mb) else {
                continue;
            };
            let full_id = if id.starts_with('#') {
                format!("{base_did}{id}")
            } else {
                id.to_owned()
            };
            if labyrinth::protocol::receipt_key_generation(&base_did, &full_id).is_ok()
                && raw.starts_with(&[0x80, 0x24])
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..]).is_ok()
            {
                let key = SequencerReceiptKey {
                    did: base_did.clone(),
                    public_key_sec1: raw[2..].to_vec(),
                };
                if parsed.receipt_keys.insert(full_id, key).is_some() {
                    return Err(labyrinth::Error::Malformed(
                        "duplicate receipt verification method",
                    ));
                }
            }
        }
    }
    let generations = parsed
        .receipt_keys
        .keys()
        .map(|key_id| {
            labyrinth::protocol::receipt_key_generation(&base_did, key_id)
                .expect("receipt key IDs were validated before insertion")
        })
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(newest) = generations.last().copied() {
        if (1..=newest).any(|generation| !generations.contains(&generation)) {
            return Err(labyrinth::Error::Malformed(
                "sequencer DID document omits receipt key history",
            ));
        }
    }
    Ok(parsed)
}

/// Resolves a federated sequencer DID (`did:web:...` or `did:plc:...`) into a
/// validated, SSRF-hardened `https://` DID document URL.
///
/// Delegates to [`crate::client::did_url::did_document_url`], the one URL builder every
/// resolver in this crate uses.
pub fn did_document_url(did: &str) -> Result<String, String> {
    crate::client::did_url::did_document_url(did)
}

/// Pre-built PDS evidence attached to `blue.catbird.labyrinth.deleteAccountData`
/// so peers can verify self-deletion after the deleted account's PDS is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAccountDeletion {
    pub operation_id: [u8; 16],
    pub signed_at: chrono::DateTime<chrono::Utc>,
    pub key_proof: Vec<u8>,
    pub revocation_proof: Vec<u8>,
}

/// Verifying `mls-ds` directory & epoch-head publisher over the 6 clean-slate endpoints.
pub struct DsDirectoryStore {
    transport: Arc<GatewayXrpcTransport>,
    sequencer_receipt_key: Option<SequencerReceiptKey>,
    placements: Option<(String, Arc<dyn super::state::StateVault>)>,
    prepared_deletion: Option<PreparedAccountDeletion>,
    thread_keys: std::sync::Mutex<std::collections::HashMap<String, SequencerReceiptKey>>,
    did_doc_keys: std::sync::Mutex<std::collections::HashMap<String, ParsedSequencerKeys>>,
}

impl DsDirectoryStore {
    pub fn new(
        transport: Arc<GatewayXrpcTransport>,
        sequencer_receipt_key: Option<SequencerReceiptKey>,
    ) -> Self {
        Self {
            transport,
            sequencer_receipt_key,
            placements: None,
            prepared_deletion: None,
            thread_keys: std::sync::Mutex::new(std::collections::HashMap::new()),
            did_doc_keys: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn with_placements(
        mut self,
        did: impl Into<String>,
        placements: Arc<dyn super::state::StateVault>,
    ) -> Self {
        self.placements = Some((did.into(), placements));
        self
    }

    pub fn with_prepared_deletion(mut self, prepared: PreparedAccountDeletion) -> Self {
        self.prepared_deletion = Some(prepared);
        self
    }

    fn saved_thread_authority(&self, thread_id: &str) -> labyrinth::Result<Option<String>> {
        let Some((ref did, ref vault)) = self.placements else {
            return Ok(None);
        };
        let key = super::space::thread_placement_key(did);
        let Some(raw) = vault
            .load(&key)
            .map_err(|e| labyrinth::Error::Backend(e.to_string()))?
        else {
            return Ok(None);
        };
        let pins: std::collections::BTreeMap<String, super::space::ThreadPlacement> =
            serde_json::from_slice(&raw)
                .map_err(|_| labyrinth::Error::Malformed("saved conversation placements"))?;
        let Some(pin) = pins.get(thread_id) else {
            return Ok(None);
        };
        pin.validate()?;
        let Some(ref space_uri) = pin.space else {
            return Ok(None);
        };
        let parsed = labyrinth::store::space::SpaceRef::parse(space_uri)?;
        Ok(Some(normalize_sequencer_did(&parsed.space_did)))
    }

    async fn resolve_did_doc_keys(
        &self,
        sequencer_did: &str,
    ) -> labyrinth::Result<ParsedSequencerKeys> {
        let _validated_url = did_document_url(sequencer_did).map_err(labyrinth::Error::Backend)?;
        if let Some(cached) = self
            .did_doc_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(sequencer_did)
            .cloned()
        {
            return Ok(cached);
        }
        let doc_opt = self
            .transport
            .resolve_did_document(sequencer_did)
            .await
            .map_err(labyrinth::Error::Backend)?;
        let Some(doc_bytes) = doc_opt else {
            return Ok(ParsedSequencerKeys::default());
        };
        let parsed = parse_did_doc_sequencer_keys(sequencer_did, &doc_bytes)?;
        if !parsed.receipt_keys.is_empty() {
            self.did_doc_keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(sequencer_did.to_owned(), parsed.clone());
        }
        Ok(parsed)
    }

    async fn resolve_thread_receipt_key(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        let mut sequencer_did = self.saved_thread_authority(thread_id)?;
        if let Some(cached) = self
            .thread_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(thread_id)
            .cloned()
        {
            if sequencer_did
                .as_deref()
                .is_some_and(|expected| cached.did != expected)
            {
                return Err(labyrinth::Error::Unattested);
            }
            return Ok(Some(cached));
        }

        let state_res = self
            .transport
            .query(
                "blue.catbird.chat.getConversationState",
                &[("conversationId", thread_id.to_owned())],
            )
            .await;

        match state_res {
            Ok(body) => {
                let parsed: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|_| labyrinth::Error::Malformed("getConversationState JSON"))?;
                // State may bootstrap an unpinned authority, never replace a pin
                // or supply verification keys. Key bytes come from trusted resolvers.
                let state_did = parsed["state"]["sequencerDid"]
                    .as_str()
                    .filter(|did| !did.is_empty())
                    .map(normalize_sequencer_did);
                let space_did = parsed["state"]["conversationSpace"]
                    .as_str()
                    .filter(|uri| !uri.is_empty())
                    .map(labyrinth::store::space::SpaceRef::parse)
                    .transpose()?
                    .map(|space| normalize_sequencer_did(&space.space_did));
                for candidate in [state_did, space_did].into_iter().flatten() {
                    if sequencer_did
                        .as_ref()
                        .is_some_and(|expected| expected != &candidate)
                    {
                        return Err(labyrinth::Error::Unattested);
                    }
                    sequencer_did = Some(candidate);
                }
            }
            Err(e) => {
                let mapped = map_xrpc_error(e);
                match mapped {
                    labyrinth::Error::Forbidden | labyrinth::Error::NotFound("conversation") => {}
                    other => return Err(other),
                }
            }
        }

        // Fail closed: NEVER match home DS keys when `sequencer_did` is unknown (`None`)
        // or belongs to a foreign federated authority.
        let matches_expected = |candidate_did: &str, target: Option<&str>| match target {
            Some(expected) => normalize_sequencer_did(candidate_did) == expected,
            None => false,
        };

        let mut receipt_key = None;
        if receipt_key.is_none() {
            if let Some(ref rk) = self.sequencer_receipt_key {
                if matches_expected(&rk.did, sequencer_did.as_deref())
                    && p256::ecdsa::VerifyingKey::from_sec1_bytes(&rk.public_key_sec1).is_ok()
                {
                    receipt_key = Some(SequencerReceiptKey {
                        did: normalize_sequencer_did(&rk.did),
                        public_key_sec1: rk.public_key_sec1.clone(),
                    });
                }
            }
        }
        if receipt_key.is_none() && sequencer_did.is_some() {
            if let Some((did, sec1)) = self
                .transport
                .resolve_sequencer_receipt_key_for(thread_id, sequencer_did.as_deref())
                .await
            {
                let norm = normalize_sequencer_did(&did);
                if matches_expected(&norm, sequencer_did.as_deref())
                    && p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).is_ok()
                {
                    receipt_key = Some(SequencerReceiptKey {
                        did: norm,
                        public_key_sec1: sec1,
                    });
                }
            }
        }

        if let Some(seq_did) = &sequencer_did {
            if receipt_key.is_none() {
                receipt_key = self
                    .resolve_did_doc_keys(seq_did)
                    .await?
                    .current_receipt_key();
            }
            if let Some(key) = &receipt_key {
                self.thread_keys
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(thread_id.to_owned(), key.clone());
            }
        }

        Ok(receipt_key)
    }

    pub async fn publish_epoch_head_public(&self, epoch: &EpochPublicDef) -> labyrinth::Result<()> {
        let payload = serde_json::to_vec(&PublishEpochHeadIn { epoch })
            .map_err(|e| labyrinth::Error::Backend(format!("serialize publishEpochHead: {e}")))?;
        let op_id = deterministic_op_id("publishEpochHead", &payload);
        self.transport
            .procedure("blue.catbird.labyrinth.publishEpochHead", &payload, op_id)
            .await
            .map(|_| ())
            .map_err(map_xrpc_error)
    }

    pub async fn purge_mailbox_heads(&self) -> labyrinth::Result<()> {
        let mut op_id = [0u8; 16];
        labyrinth::encoding::random(&mut op_id)?;
        self.transport
            .procedure("blue.catbird.labyrinth.purgeMailbox", b"{}", op_id)
            .await
            .map(|_| ())
            .map_err(map_xrpc_error)
    }

    pub async fn delete_account_data(&self) -> labyrinth::Result<()> {
        if let Some(ref prepared) = self.prepared_deletion {
            return self.delete_account_data_with_evidence(prepared).await;
        }
        let mut op_id = [0u8; 16];
        labyrinth::encoding::random(&mut op_id)?;
        self.transport
            .procedure("blue.catbird.labyrinth.deleteAccountData", b"{}", op_id)
            .await
            .map(|_| ())
            .map_err(map_xrpc_error)
    }

    pub async fn delete_account_data_with_evidence(
        &self,
        prepared: &PreparedAccountDeletion,
    ) -> labyrinth::Result<()> {
        let extra = [
            (
                KEY_PROOF_HEADER.to_owned(),
                URL_SAFE_NO_PAD.encode(&prepared.key_proof),
            ),
            (
                REVOCATION_PROOF_HEADER.to_owned(),
                URL_SAFE_NO_PAD.encode(&prepared.revocation_proof),
            ),
        ];
        self.transport
            .procedure_at_with_headers(
                "blue.catbird.labyrinth.deleteAccountData",
                b"{}",
                prepared.operation_id,
                prepared.signed_at,
                &extra,
            )
            .await
            .map(|_| ())
            .map_err(map_xrpc_error)
    }

    async fn fetch_head(
        &self,
        did: &str,
        seq: Option<u64>,
    ) -> labyrinth::Result<Option<GetEpochHeadOut>> {
        let mut params = vec![("did", did.to_owned())];
        if let Some(n) = seq {
            params.push(("epochNumber", n.to_string()));
        }
        match self
            .transport
            .query("blue.catbird.labyrinth.getEpochHead", &params)
            .await
            .map_err(map_xrpc_error)
        {
            Ok(body) => {
                let out: GetEpochHeadOut = serde_json::from_slice(&body)
                    .map_err(|_| labyrinth::Error::Malformed("getEpochHead response"))?;
                Ok(Some(out))
            }
            Err(labyrinth::Error::NotFound("epoch")) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for DsDirectoryStore {
    async fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        self.fetch_head(did, None)
            .await?
            .map(|o| o.epoch.to_public())
            .transpose()
    }

    async fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        let out = self
            .fetch_head(did, Some(seq))
            .await?
            .map(|o| o.epoch.to_public())
            .transpose()?;
        if out.as_ref().is_some_and(|e| e.seq != seq) {
            return Err(labyrinth::Error::Malformed(
                "mls-ds returned wrong epochNumber",
            ));
        }
        Ok(out)
    }

    async fn epoch_chain(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<(Vec<labyrinth_protocol::EpochPublicHeader>, u64)>> {
        let Some(out) = self.fetch_head(did, None).await? else {
            return Ok(None);
        };
        let floor_seq = out.floor_seq.unwrap_or(0);
        let headers = if out.chain.is_empty() {
            vec![out.epoch.to_public()?.to_protocol_header()]
        } else {
            out.chain
                .iter()
                .map(|item| Ok(item.to_public()?.to_protocol_header()))
                .collect::<labyrinth::Result<Vec<_>>>()?
        };
        Ok(Some((headers, floor_seq)))
    }

    async fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let mut params = vec![("did", did.to_owned()), ("limit", "100".to_owned())];
            if let Some(ref c) = cursor {
                params.push(("cursor", c.clone()));
            }
            let body = self
                .transport
                .query("blue.catbird.labyrinth.getChatDeviceKeys", &params)
                .await
                .map_err(map_xrpc_error)?;
            let page: PageOut<ChatDeviceKeyItem> = serde_json::from_slice(&body)
                .map_err(|_| labyrinth::Error::Malformed("getChatDeviceKeys response"))?;
            for item in page.items {
                let key = item.signing_public_key.decode_32()?;
                let removed_at = item
                    .revoked_at
                    .as_deref()
                    .map(ms_from_datetime)
                    .transpose()?;
                all.push(ChatDeviceKey { key, removed_at });
            }
            match page.cursor {
                None => {
                    #[cfg(feature = "sim")]
                    if crate::planted::is_planted_bug_active(
                        crate::planted::PlantedBug::P5WrapMekToUnverifiedDevice,
                    ) {
                        // Treat the candidate epoch's own attester as an authorized chat
                        // device. Epoch signatures/chain checks still run in Labyrinth;
                        // only the independent device authorization is bypassed.
                        if let Some(epoch) = self.latest(did).await? {
                            let key = epoch.attestation.transport_public_key;
                            if !all
                                .iter()
                                .any(|device| device.key == key && device.is_current())
                            {
                                all.push(ChatDeviceKey {
                                    key,
                                    removed_at: None,
                                });
                            }
                        }
                    }
                    return Ok(all);
                }
                Some(next) => {
                    if !seen_cursors.insert(next.clone()) {
                        return Err(labyrinth::Error::Malformed(
                            "repeated getChatDeviceKeys cursor",
                        ));
                    }
                    cursor = Some(next);
                }
            }
        }
        Err(labyrinth::Error::Backend(
            "getChatDeviceKeys exceeded 64 pages".into(),
        ))
    }

    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> labyrinth::Result<Option<Vec<MemberDeviceKey>>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let mut params = vec![
                ("threadId", thread_id.to_owned()),
                ("did", did.to_owned()),
                ("limit", "100".to_owned()),
            ];
            if let Some(ref c) = cursor {
                params.push(("cursor", c.clone()));
            }
            let body = match self
                .transport
                .query("blue.catbird.labyrinth.getMemberDevices", &params)
                .await
                .map_err(map_xrpc_error)
            {
                Ok(b) => b,
                Err(labyrinth::Error::NotFound("conversation")) => return Ok(None),
                Err(e) => return Err(e),
            };
            let page: PageOut<MemberDeviceItem> = serde_json::from_slice(&body)
                .map_err(|_| labyrinth::Error::Malformed("getMemberDevices response"))?;
            for item in page.items {
                all.push(MemberDeviceKey {
                    key: item.signing_public_key.decode_32()?,
                    joined_chat_seq: item.joined_seq,
                    removed_chat_seq: item.removed_seq,
                });
            }
            match page.cursor {
                None => return Ok(Some(all)),
                Some(next) => {
                    if !seen_cursors.insert(next.clone()) {
                        return Err(labyrinth::Error::Malformed(
                            "repeated getMemberDevices cursor",
                        ));
                    }
                    cursor = Some(next);
                }
            }
        }
        Err(labyrinth::Error::Backend(
            "getMemberDevices exceeded 64 pages".into(),
        ))
    }

    async fn sequencer_receipt_key(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        self.resolve_thread_receipt_key(thread_id).await
    }

    async fn sequencer_receipt_key_for_authority(
        &self,
        thread_id: &str,
        expected_authority: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        let authority = normalize_sequencer_did(expected_authority);
        if self
            .saved_thread_authority(thread_id)?
            .is_some_and(|pinned| pinned != authority)
        {
            return Err(labyrinth::Error::Unattested);
        }
        if let Some(key) = &self.sequencer_receipt_key {
            if normalize_sequencer_did(&key.did) == authority
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public_key_sec1).is_ok()
            {
                return Ok(Some(SequencerReceiptKey {
                    did: authority,
                    public_key_sec1: key.public_key_sec1.clone(),
                }));
            }
        }
        if let Some((did, public_key_sec1)) = self
            .transport
            .resolve_sequencer_receipt_key_for(thread_id, Some(&authority))
            .await
        {
            if normalize_sequencer_did(&did) == authority
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_sec1).is_ok()
            {
                return Ok(Some(SequencerReceiptKey {
                    did: authority,
                    public_key_sec1,
                }));
            }
        }
        Ok(self
            .resolve_did_doc_keys(&authority)
            .await?
            .current_receipt_key())
    }

    async fn sequencer_receipt_key_by_id(
        &self,
        thread_id: &str,
        expected_authority: &str,
        key_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        let authority = normalize_sequencer_did(expected_authority);
        labyrinth::protocol::receipt_key_generation(&authority, key_id)
            .map_err(|_| labyrinth::Error::Unattested)?;
        if self
            .saved_thread_authority(thread_id)?
            .is_some_and(|pinned| pinned != authority)
        {
            return Err(labyrinth::Error::Unattested);
        }
        let parsed = self.resolve_did_doc_keys(&authority).await?;
        if let Some(key) = parsed.receipt_keys.get(key_id) {
            return Ok(Some(key.clone()));
        }
        self.did_doc_keys
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&authority);
        if let Some(key) = self
            .resolve_did_doc_keys(&authority)
            .await?
            .receipt_keys
            .get(key_id)
        {
            return Ok(Some(key.clone()));
        }

        let first = labyrinth::protocol::expected_receipt_key_id(&authority);
        if key_id != first {
            return Ok(None);
        }
        if let Some(key) = &self.sequencer_receipt_key {
            if normalize_sequencer_did(&key.did) == authority
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public_key_sec1).is_ok()
            {
                return Ok(Some(SequencerReceiptKey {
                    did: authority,
                    public_key_sec1: key.public_key_sec1.clone(),
                }));
            }
        }
        if let Some((did, public_key_sec1)) = self
            .transport
            .resolve_sequencer_receipt_key_for(thread_id, Some(&authority))
            .await
        {
            if normalize_sequencer_did(&did) == authority
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_sec1).is_ok()
            {
                return Ok(Some(SequencerReceiptKey {
                    did: authority,
                    public_key_sec1,
                }));
            }
        }
        Ok(None)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for DsDirectoryStore {
    async fn publish(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.publish_epoch_head_public(&record.current).await
    }

    async fn retract(&self) -> labyrinth::Result<()> {
        self.purge_mailbox_heads().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use labyrinth::store::space::SpaceRpc;

    #[tokio::test]
    async fn sequencer_keys_require_pinned_authority_and_trusted_key_material() {
        use crate::labyrinth::state::StateVault;
        use crate::MLSError;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const AUTHORITY: &str = "did:web:sequencer.example";
        const ATTACKER: &str = "did:web:attacker.example";
        const OWNER: &str = "did:plc:alice";
        const THREAD: &str = "thread";

        struct Fixture {
            state: Vec<u8>,
            status: u16,
            state_queries: AtomicUsize,
            document: Option<Vec<u8>>,
            pins: Option<Vec<u8>>,
        }
        #[async_trait::async_trait]
        impl LabyrinthGateway for Fixture {
            async fn submit_labyrinth(
                &self,
                _request: LabyrinthRequest,
            ) -> Result<GatewayResponse, String> {
                panic!("expected canonical conversation-state query")
            }
            async fn submit_canonical(
                &self,
                _request: PreparedRequest,
                _headers: Vec<(String, String)>,
            ) -> Result<GatewayResponse, String> {
                self.state_queries.fetch_add(1, Ordering::SeqCst);
                Ok(GatewayResponse {
                    status: self.status,
                    content_type: Some("application/json".into()),
                    body: self.state.clone(),
                })
            }
            async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
                assert_eq!(
                    did, AUTHORITY,
                    "must resolve only the pinned/bootstrap authority"
                );
                Ok(self.document.clone())
            }
        }
        impl ChatKeySigner for Fixture {
            fn public_key(&self) -> [u8; 32] {
                [0; 32]
            }
            fn sign(&self, _message: &[u8]) -> Result<[u8; 64], String> {
                Ok([0; 64])
            }
        }
        impl StateVault for Fixture {
            fn load(&self, key: &str) -> Result<Option<Vec<u8>>, MLSError> {
                assert_eq!(key, super::super::space::thread_placement_key(OWNER));
                Ok(self.pins.clone())
            }
            fn compare_exchange(
                &self,
                _key: &str,
                _expected: Option<&[u8]>,
                _next: &[u8],
            ) -> Result<bool, MLSError> {
                panic!("directory reads must not rewrite authority pins")
            }
            fn delete(&self, _key: &str) -> Result<(), MLSError> {
                panic!("directory reads must not remove authority pins")
            }
        }

        let receipt_public = p256::ecdsa::SigningKey::from_bytes((&[0x42; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let inline_public = p256::ecdsa::SigningKey::from_bytes((&[0x43; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let document = serde_json::to_vec(&serde_json::json!({
            "id": AUTHORITY,
            "verificationMethod": [
                {
                    "id": format!("{AUTHORITY}#mls-receipt-1"),
                    "controller": AUTHORITY,
                    "publicKeyMultibase": multibase::encode(
                        multibase::Base::Base58Btc, [&[0x80, 0x24][..], &receipt_public].concat()
                    )
                }
            ]
        }))
        .unwrap();
        let pins = serde_json::to_vec(&std::collections::BTreeMap::from([(
            THREAD.to_owned(),
            super::super::space::ThreadPlacement {
                space: Some(
                    labyrinth::store::space::SpaceRef::conversation(AUTHORITY, THREAD).to_string(),
                ),
                generation: 1,
                group_id: None,
            },
        )]))
        .unwrap();

        for (reported, pinned, has_document, configured) in [
            (AUTHORITY, true, true, false),
            (ATTACKER, true, true, false),
            (AUTHORITY, false, true, false),
            (AUTHORITY, true, false, false),
            (AUTHORITY, true, false, true),
        ] {
            let fixture = Arc::new(Fixture {
                status: 200,
                state_queries: AtomicUsize::new(0),
                state: serde_json::to_vec(&serde_json::json!({"state": {
                    "sequencerDid": reported,
                    "sequencerPublicKey": {"$bytes": STANDARD.encode([9; 32])},
                    "sequencerReceiptPublicKey": {"$bytes": STANDARD.encode(&inline_public)}
                }}))
                .unwrap(),
                document: has_document.then(|| document.clone()),
                pins: pinned.then(|| pins.clone()),
            });
            let transport = Arc::new(GatewayXrpcTransport::new(
                fixture.clone(),
                fixture.clone(),
                OWNER.into(),
                "11111111-1111-4111-8111-111111111111".into(),
            ));
            let directory = DsDirectoryStore::new(
                transport,
                configured.then(|| SequencerReceiptKey {
                    did: AUTHORITY.into(),
                    public_key_sec1: receipt_public.clone(),
                }),
            )
            .with_placements(OWNER, fixture.clone());
            let result = directory.resolve_thread_receipt_key(THREAD).await;
            if reported == ATTACKER {
                assert_eq!(result.unwrap_err(), labyrinth::Error::Unattested);
            } else {
                let receipt = result.unwrap();
                if has_document || configured {
                    assert_eq!(receipt.unwrap().public_key_sec1, receipt_public);
                } else {
                    assert!(receipt.is_none(), "inline keys must not be trusted");
                }
            }
            let before = fixture.state_queries.load(Ordering::SeqCst);
            let authenticated = directory
                .sequencer_receipt_key_for_authority(THREAD, AUTHORITY)
                .await
                .unwrap();
            assert_eq!(
                fixture.state_queries.load(Ordering::SeqCst),
                before,
                "authenticated issuer lookup must not consult unsigned state"
            );
            if has_document || configured {
                assert_eq!(authenticated.unwrap().public_key_sec1, receipt_public);
            } else {
                assert!(authenticated.is_none());
            }
            if pinned {
                assert_eq!(
                    directory
                        .sequencer_receipt_key_for_authority(THREAD, ATTACKER)
                        .await
                        .unwrap_err(),
                    labyrinth::Error::Unattested,
                );
            }
        }

        let rotated_public = p256::ecdsa::SigningKey::from_bytes((&[0x44; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let rotated_document = serde_json::to_vec(&serde_json::json!({
            "id": AUTHORITY,
            "verificationMethod": [
                {
                    "id": format!("{AUTHORITY}#mls-receipt-1"),
                    "controller": AUTHORITY,
                    "publicKeyMultibase": multibase::encode(
                        multibase::Base::Base58Btc,
                        [&[0x80, 0x24][..], &receipt_public].concat(),
                    ),
                },
                {
                    "id": format!("{AUTHORITY}#mls-receipt-2"),
                    "controller": AUTHORITY,
                    "publicKeyMultibase": multibase::encode(
                        multibase::Base::Base58Btc,
                        [&[0x80, 0x24][..], &rotated_public].concat(),
                    ),
                },
            ],
        }))
        .unwrap();
        let parsed = parse_did_doc_sequencer_keys(AUTHORITY, &rotated_document).unwrap();
        assert_eq!(parsed.receipt_keys.len(), 2);
        assert_eq!(
            parsed.current_receipt_key().unwrap().public_key_sec1,
            rotated_public,
        );
        assert_eq!(
            parsed
                .receipt_keys
                .get(&format!("{AUTHORITY}#mls-receipt-1"))
                .unwrap()
                .public_key_sec1,
            receipt_public,
        );

        let missing_history = serde_json::to_vec(&serde_json::json!({
            "id": AUTHORITY,
            "verificationMethod": [{
                "id": format!("{AUTHORITY}#mls-receipt-2"),
                "controller": AUTHORITY,
                "publicKeyMultibase": multibase::encode(
                    multibase::Base::Base58Btc,
                    [&[0x80, 0x24][..], &rotated_public].concat(),
                ),
            }],
        }))
        .unwrap();
        assert!(parse_did_doc_sequencer_keys(AUTHORITY, &missing_history).is_err());

        // A fresh kicked device has neither a placement pin nor live state
        // access. Only its authenticated owner receipt can name this authority.
        let fixture = Arc::new(Fixture {
            state: br#"{"error":"NotEntitled"}"#.to_vec(),
            status: 403,
            state_queries: AtomicUsize::new(0),
            document: Some(document),
            pins: None,
        });
        let transport = Arc::new(GatewayXrpcTransport::new(
            fixture.clone(),
            fixture.clone(),
            OWNER.into(),
            "11111111-1111-4111-8111-111111111111".into(),
        ));
        let directory =
            DsDirectoryStore::new(transport, None).with_placements(OWNER, fixture.clone());
        assert!(directory
            .sequencer_receipt_key(THREAD)
            .await
            .unwrap()
            .is_none());
        assert_eq!(fixture.state_queries.load(Ordering::SeqCst), 1);
        let authenticated = directory
            .sequencer_receipt_key_for_authority(THREAD, AUTHORITY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.public_key_sec1, receipt_public);
        assert_eq!(fixture.state_queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn canonical_query_carries_exact_labyrinth_read_headers() {
        use std::sync::Mutex;

        #[derive(Default)]
        struct Capture(Mutex<Option<(PreparedRequest, Vec<(String, String)>)>>);
        #[async_trait::async_trait]
        impl LabyrinthGateway for Capture {
            async fn submit_labyrinth(
                &self,
                _request: LabyrinthRequest,
            ) -> Result<GatewayResponse, String> {
                panic!("canonical query must use the canonical route")
            }

            async fn submit_canonical(
                &self,
                request: PreparedRequest,
                headers: Vec<(String, String)>,
            ) -> Result<GatewayResponse, String> {
                *self.0.lock().unwrap() = Some((request, headers));
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
        }

        struct Signer;
        impl ChatKeySigner for Signer {
            fn public_key(&self) -> [u8; 32] {
                [7; 32]
            }

            fn sign(&self, _message: &[u8]) -> Result<[u8; 64], String> {
                Ok([9; 64])
            }
        }

        struct Clock;
        impl labyrinth::client::Clock for Clock {
            fn now_ms(&self) -> u64 {
                123_456
            }
        }

        let capture = Arc::new(Capture::default());
        let did = "did:plc:alice";
        let device = "11111111-1111-4111-8111-111111111111";
        let nsid = CanonicalOperation::GetConversationState.nsid();
        let params = [(
            "conversationId",
            "22222222-2222-4222-8222-222222222222".into(),
        )];
        let supplied = vec![("x-test".into(), "kept".into())];
        GatewayXrpcTransport::new(capture.clone(), Arc::new(Signer), did.into(), device.into())
            .with_clock(Arc::new(Clock))
            .query_with_headers(nsid, &params, &supplied)
            .await
            .unwrap();

        let (request, actual) = capture.0.lock().unwrap().take().unwrap();
        let wire_params = [
            ("actorDeviceId", device.into()),
            ("conversationId", params[0].1.clone()),
        ];
        let claim = ReadClaim::new(nsid, &wire_params, did, device, 123_456);
        let mut expected = supplied;
        expected.extend(read_headers(&claim.to_json(), &[9; 64]));
        assert_eq!(actual, expected);
        assert_eq!(request.operation, CanonicalOperation::GetConversationState);
        assert_eq!(
            request.path,
            format!(
                "/xrpc/{nsid}?actorDeviceId={device}&conversationId={}",
                params[0].1
            )
        );
    }

    #[test]
    fn destructive_directory_operation_ids_follow_scoped_entropy() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::Mutex;

        #[derive(Default)]
        struct Capture(Mutex<Vec<LabyrinthRequest>>);
        #[async_trait::async_trait]
        impl LabyrinthGateway for Capture {
            async fn submit_labyrinth(
                &self,
                request: LabyrinthRequest,
            ) -> Result<GatewayResponse, String> {
                self.0.lock().unwrap().push(request);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
            async fn submit_canonical(
                &self,
                _request: PreparedRequest,
                _headers: Vec<(String, String)>,
            ) -> Result<GatewayResponse, String> {
                panic!("directory mutations must use the Labyrinth route")
            }
        }
        impl ChatKeySigner for Capture {
            fn public_key(&self) -> [u8; 32] {
                [7; 32]
            }
            fn sign(&self, _msg: &[u8]) -> Result<[u8; 64], String> {
                Ok([0; 64])
            }
        }

        let capture = Arc::new(Capture::default());
        let transport = Arc::new(GatewayXrpcTransport::new(
            capture.clone(),
            capture.clone(),
            "did:plc:alice".into(),
            "11111111-1111-4111-8111-111111111111".into(),
        ));
        let directory = DsDirectoryStore::new(transport, None);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for _ in 0..2 {
            let next = AtomicU8::new(1);
            labyrinth::encoding::with_random_hook(
                Arc::new(move |out| {
                    out.fill(next.fetch_add(1, Ordering::Relaxed));
                    Ok(())
                }),
                || {
                    runtime.block_on(async {
                        directory.purge_mailbox_heads().await.unwrap();
                        directory.delete_account_data().await.unwrap();
                    })
                },
            );
        }

        let requests = capture.0.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for (i, request) in requests.iter().enumerate() {
            let nsid = if i % 2 == 0 {
                "blue.catbird.labyrinth.purgeMailbox"
            } else {
                "blue.catbird.labyrinth.deleteAccountData"
            };
            assert_eq!(request.nsid, nsid);
            let header = request
                .headers
                .iter()
                .find(|(name, _)| name == super::super::write_auth::WRITE_BODY_HEADER)
                .unwrap();
            let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&header.1)
                .unwrap();
            let body: WriteBody = serde_json::from_slice(&json).unwrap();
            assert_eq!(body.operation_id, hex::encode([1 + (i % 2) as u8; 16]));
        }
    }

    #[test]
    fn space_error_names_pass_through_decoding() {
        for name in ["SpaceNotFound", "SpaceDeleted", "RecordNotFound"] {
            let err = decode_response(Ok(GatewayResponse {
                status: 400,
                content_type: Some("application/json".into()),
                body: format!(r#"{{"error":"{name}","message":"m"}}"#).into_bytes(),
            }))
            .unwrap_err();
            assert_eq!(err.status, 400);
            assert_eq!(err.error.as_deref(), Some(name));
        }
    }

    #[test]
    fn f13_xrpc_and_pds_responses_exceeding_byte_caps_are_rejected_before_json_parse() {
        const FOUR_MIB: usize = 4 * 1024 * 1024;
        let err_200 = decode_response(Ok(GatewayResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body: vec![b'a'; FOUR_MIB + 1],
        }))
        .expect_err("200 response > 4 MiB must be rejected");
        assert_eq!(err_200.status, 0);

        let err_500 = decode_response(Ok(GatewayResponse {
            status: 500,
            content_type: Some("application/json".into()),
            body: vec![b' '; FOUR_MIB + 1],
        }))
        .expect_err("500 response > 4 MiB must be rejected");
        assert!(err_500.error.is_none());

        assert!(enforce_pds_record_cap(&vec![0u8; MAX_PDS_RECORD_BYTES]).is_ok());
        assert!(enforce_pds_record_cap(&vec![0u8; MAX_PDS_RECORD_BYTES + 1]).is_err());
    }

    #[tokio::test]
    async fn f13_invalid_nsid_syntax_is_rejected_before_path_formatting() {
        use crate::labyrinth::space::{
            LabyrinthSpaceGateway, LabyrinthSpaceRequest, SpaceXrpcTransport,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Default)]
        struct CountingGateway {
            calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl LabyrinthGateway for CountingGateway {
            async fn submit_labyrinth(
                &self,
                _req: LabyrinthRequest,
            ) -> Result<GatewayResponse, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
            async fn submit_canonical(
                &self,
                _req: PreparedRequest,
                _headers: Vec<(String, String)>,
            ) -> Result<GatewayResponse, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
        }
        #[async_trait::async_trait]
        impl LabyrinthSpaceGateway for CountingGateway {
            async fn submit_space(
                &self,
                _req: LabyrinthSpaceRequest,
            ) -> Result<GatewayResponse, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
        }

        struct DummySigner;
        impl ChatKeySigner for DummySigner {
            fn public_key(&self) -> [u8; 32] {
                [7u8; 32]
            }
            fn sign(&self, _msg: &[u8]) -> Result<[u8; 64], String> {
                Ok([0u8; 64])
            }
        }

        let gw = Arc::new(CountingGateway::default());
        let transport = GatewayXrpcTransport::new(
            gw.clone(),
            Arc::new(DummySigner),
            "did:plc:alice".into(),
            "11111111-1111-4111-8111-111111111111".into(),
        );
        let space_transport = SpaceXrpcTransport::new(gw.clone());

        for bad_lab_nsid in [
            "blue.catbird.labyrinth.foo/../bar",
            "blue.catbird.labyrinth.foo?admin=1",
            "blue.catbird.labyrinth.foo#frag",
            "blue.catbird.labyrinth..bad",
            "blue.catbird.labyrinth.-bad",
            "blue.catbird",
            "",
        ] {
            assert!(
                transport
                    .query_with_headers(bad_lab_nsid, &[], &[])
                    .await
                    .is_err(),
                "expected query error for malformed NSID {bad_lab_nsid:?}"
            );
            assert!(
                transport
                    .procedure(bad_lab_nsid, b"{}", [0u8; 16])
                    .await
                    .is_err(),
                "expected procedure error for malformed NSID {bad_lab_nsid:?}"
            );
        }

        for bad_space_nsid in [
            "com.atproto.space.getRecord/../deleteSpace",
            "com.atproto.space.getRecord?repo=did:plc:evil",
            "com.atproto.space.getRecord#frag",
            "com.atproto.space..getRecord",
        ] {
            assert!(
                space_transport.query(bad_space_nsid, &[]).await.is_err(),
                "expected Space query error for malformed NSID {bad_space_nsid:?}"
            );
            assert!(
                space_transport
                    .procedure(bad_space_nsid, b"{}")
                    .await
                    .is_err(),
                "expected Space procedure error for malformed NSID {bad_space_nsid:?}"
            );
        }

        assert_eq!(
            gw.calls.load(Ordering::SeqCst),
            0,
            "malformed NSIDs must be rejected before invoking any gateway"
        );
    }

    #[test]
    fn entitlement_denials_map_to_forbidden_only_as_exact_400s() {
        let err = |status: u16, name: &str| XrpcTransportError {
            status,
            error: Some(name.to_owned()),
            message: None,
        };
        for name in ["NotEntitled", "AccessOutsideMembershipInterval"] {
            assert_eq!(map_xrpc_error(err(400, name)), labyrinth::Error::Forbidden);
            assert!(matches!(
                map_xrpc_error(err(500, name)),
                labyrinth::Error::Backend(_)
            ));
        }
    }
}
