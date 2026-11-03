//! Clean-slate Labyrinth XRPC transport and verifying `mls-ds` directory client.
//!
//! `mls-ds` stores zero mailboxes, sender batches, MEKs, attachment references,
//! or ORF state (`G6`, `I14`, `2A`). This module drives the 6 zero-content
//! `blue.catbird.labyrinth.*` endpoints (`publishEpochHead`, `purgeMailbox`,
//! `deleteAccountData`, `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`)
//! plus `blue.catbird.chat.getConversationState`, with device-signed write and
//! read headers (`catbird-labyrinth-write*`, `catbird-labyrinth-read*`).

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use labyrinth::mailbox::EpochPublic;
use labyrinth::records::{ms_from_datetime, EpochPublicDef, MailboxKeysRecord};
use labyrinth::store::pds::PublicRepoBackend;
use labyrinth::store::{
    ChatDeviceKey, KeyPublisher, MailboxDirectory, MaybeSend, MaybeSync, MemberDeviceKey,
    SequencerKey, SequencerReceiptKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::signer::ChatKeySigner;
use super::write_auth::{read_headers, write_headers, ReadClaim, WriteBody};
use super::LabyrinthRequest;
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::canonical_transport::{
    encode_query, CanonicalOperation, GatewayResponse, PreparedRequest,
};

/// NSID prefix of every `mls-ds` Labyrinth endpoint.
pub const NSID_PREFIX: &str = "blue.catbird.labyrinth.";

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
        Some("NotEntitled" | "AccessOutsideMembershipInterval") if e.status == 400 => {
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
    /// A clean-chat query through the existing prepared-request route.
    async fn submit_canonical(&self, request: PreparedRequest) -> Result<GatewayResponse, String>;
    /// Per-conversation `[CB-38]` Ed25519 redaction verifying key for `sequencer_did`.
    async fn resolve_sequencer_key_for(
        &self,
        _conversation_id: &str,
        _sequencer_did: Option<&str>,
    ) -> Option<(String, [u8; 32])> {
        None
    }
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

    async fn submit_canonical(&self, request: PreparedRequest) -> Result<GatewayResponse, String> {
        self.api
            .submit_prepared_request(request)
            .await
            .map_err(|e| e.to_string())
    }

    async fn resolve_sequencer_key_for(
        &self,
        conversation_id: &str,
        sequencer_did: Option<&str>,
    ) -> Option<(String, [u8; 32])> {
        self.api
            .labyrinth_sequencer_key_for(conversation_id, sequencer_did)
            .await
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
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn labyrinth::client::Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn wire_params<'a>(&self, params: &[(&'a str, String)]) -> Vec<(&'a str, String)> {
        let mut all = Vec::with_capacity(params.len() + 1);
        all.push(("actorDeviceId", self.device_id.clone()));
        all.extend(params.iter().cloned());
        all
    }

    fn query_path(nsid: &str, params: &[(&str, String)]) -> String {
        let query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
            .collect();
        format!("/xrpc/{nsid}?{}", query.join("&"))
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
        let params = self.wire_params(params);
        let path = Self::query_path(nsid, &params);
        let response = match canonical {
            Some(operation) => {
                self.gateway
                    .submit_canonical(PreparedRequest {
                        operation,
                        method: "GET".into(),
                        path,
                        body: None,
                    })
                    .await
            }
            None => {
                let mut all = headers.to_vec();
                all.extend(self.read_headers(nsid, &params)?);
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
        validate_nsid(nsid)?;
        if !nsid.starts_with(NSID_PREFIX) {
            return Err(transport_error(format!(
                "refusing a non-Labyrinth procedure: {nsid}"
            )));
        }
        let body = WriteBody::new(
            nsid,
            payload,
            operation_id,
            &self.device_id,
            chrono::DateTime::from_timestamp_millis(self.now_ms().min(i64::MAX as u64) as i64)
                .ok_or_else(|| transport_error("invalid archive clock"))?,
        );
        let json = body.to_json();
        let signature = self
            .signer
            .sign(&WriteBody::signing_input(&json))
            .map_err(signing_error)?;
        decode_response(
            self.gateway
                .submit_labyrinth(LabyrinthRequest {
                    nsid: nsid.to_owned(),
                    method: "POST".into(),
                    path: format!("/xrpc/{nsid}"),
                    body: Some(payload.to_vec()),
                    headers: write_headers(&json, &signature),
                })
                .await,
        )
    }

    pub async fn resolve_sequencer_key_for(
        &self,
        conversation_id: &str,
        sequencer_did: Option<&str>,
    ) -> Option<(String, [u8; 32])> {
        self.gateway
            .resolve_sequencer_key_for(conversation_id, sequencer_did)
            .await
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

fn deterministic_op_id(tag: &str, payload: &[u8]) -> [u8; 16] {
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
struct CachedSequencerKeys {
    redaction_key: Option<SequencerKey>,
    receipt_key: Option<SequencerReceiptKey>,
}

fn normalize_sequencer_did(raw: &str) -> String {
    raw.split('#')
        .next()
        .unwrap_or(raw)
        .trim_end_matches('/')
        .to_owned()
}

fn decode_wire_bytes_any(v: &serde_json::Value) -> Option<Vec<u8>> {
    let encoded = v.as_str().or_else(|| v.get("$bytes")?.as_str())?;
    STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| STANDARD.decode(encoded))
        .ok()
}

fn parse_did_doc_sequencer_keys(
    expected_did: &str,
    doc_bytes: &[u8],
) -> labyrinth::Result<(Option<SequencerKey>, Option<SequencerReceiptKey>)> {
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
    let mut redaction: Option<SequencerKey> = None;
    let mut receipt: Option<SequencerReceiptKey> = None;
    if let Some(methods) = doc.get("verificationMethod").and_then(|v| v.as_array()) {
        let receipt_full_id = format!("{base_did}#mls-receipt-1");
        let redaction_full_id = format!("{base_did}#labyrinth-redaction-1");
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
            if (id == receipt_full_id || id == "#mls-receipt-1")
                && raw.starts_with(&[0x80, 0x24])
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..]).is_ok()
            {
                receipt = Some(SequencerReceiptKey {
                    did: base_did.clone(),
                    public_key_sec1: raw[2..].to_vec(),
                });
            } else if (id == redaction_full_id
                || id == "#labyrinth-redaction-1"
                || id == format!("{base_did}#labyrinth-1")
                || id == "#labyrinth-1")
                && raw.starts_with(&[0xed, 0x01])
                && raw[2..].len() == 32
            {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw[2..]);
                redaction = Some(SequencerKey {
                    did: base_did.clone(),
                    key,
                });
            }
        }
    }
    Ok((redaction, receipt))
}

/// Resolves a federated sequencer DID (`did:web:...` or `did:plc:...`) into a
/// validated, SSRF-hardened `https://` DID document URL.
///
/// Rejects single-label/local hosts (`localhost`, `.local`, `.internal`), IPv4/IPv6
/// literals, non-443 ports, userinfo (`@`), path traversal (`.` / `..` / `%2e` / `%2f`),
/// and malformed `did:plc` identifiers.
pub fn did_document_url(did: &str) -> Result<String, String> {
    let base = normalize_sequencer_did(did);
    if let Some(plc_id) = base.strip_prefix("did:plc:") {
        if plc_id.len() != 24
            || !plc_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(format!("invalid did:plc identifier: {did}"));
        }
        return Ok(format!("https://plc.directory/did:plc:{plc_id}"));
    }

    let Some(web_rest) = base.strip_prefix("did:web:") else {
        return Err(format!("unsupported sequencer DID method: {did}"));
    };
    if web_rest.is_empty() {
        return Err("empty did:web authority".into());
    }

    let mut segments = web_rest.split(':');
    let raw_host_seg = segments.next().unwrap_or("");
    let raw_host_decoded = if let Some(h) = raw_host_seg
        .strip_suffix("%3A443")
        .or_else(|| raw_host_seg.strip_suffix("%3a443"))
    {
        h
    } else if raw_host_seg.contains('%') {
        return Err(format!(
            "disallowed port or percent-encoding in did:web host: {did}"
        ));
    } else {
        raw_host_seg
    };

    if raw_host_decoded.is_empty()
        || raw_host_decoded.len() > 253
        || raw_host_decoded.contains('@')
        || raw_host_decoded.contains('/')
        || raw_host_decoded.contains('?')
        || raw_host_decoded.contains('#')
        || raw_host_decoded.starts_with('[')
        || raw_host_decoded.ends_with(']')
        || raw_host_decoded.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(format!("disallowed did:web host: {did}"));
    }

    let host_lower = raw_host_decoded.to_ascii_lowercase();
    let labels: Vec<&str> = host_lower.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("single-label did:web host rejected (SSRF): {did}"));
    }
    if matches!(
        labels.last().copied(),
        Some("localhost" | "local" | "internal" | "arpa")
    ) {
        return Err(format!("local/reserved did:web TLD rejected (SSRF): {did}"));
    }
    if labels
        .iter()
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("numeric IPv4 did:web host rejected (SSRF): {did}"));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("invalid DNS label in did:web host: {did}"));
        }
    }

    let mut path_parts: Vec<String> = Vec::new();
    for seg in segments {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.contains('/')
            || seg.contains('\\')
            || seg.contains('?')
            || seg.contains('#')
        {
            return Err(format!("invalid path segment in did:web: {did}"));
        }
        let bytes = seg.as_bytes();
        let mut i = 0;
        let mut decoded_ascii = String::with_capacity(bytes.len());
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%' {
                if i + 2 >= bytes.len() {
                    return Err(format!("truncated percent-escape in did:web path: {did}"));
                }
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                let (Some(h), Some(l)) = (hi, lo) else {
                    return Err(format!("invalid percent-escape in did:web path: {did}"));
                };
                let val = ((h << 4) | l) as u8;
                if matches!(val, 0x00..=0x1F | 0x7F | b'/' | b'\\' | b'?' | b'#') {
                    return Err(format!(
                        "encoded control/separator byte in did:web path: {did}"
                    ));
                }
                decoded_ascii.push(val as char);
                i += 3;
            } else if matches!(
                b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
            ) {
                decoded_ascii.push(b as char);
                i += 1;
            } else {
                return Err(format!("disallowed character in did:web path: {did}"));
            }
        }
        if decoded_ascii == "." || decoded_ascii == ".." {
            return Err(format!("encoded dot-segment in did:web path: {did}"));
        }
        path_parts.push(seg.to_owned());
    }

    if path_parts.is_empty() {
        Ok(format!("https://{host_lower}/.well-known/did.json"))
    } else {
        Ok(format!(
            "https://{host_lower}/{}/did.json",
            path_parts.join("/")
        ))
    }
}

/// Verifying `mls-ds` directory & epoch-head publisher over the 6 clean-slate endpoints.
pub struct DsDirectoryStore {
    transport: Arc<GatewayXrpcTransport>,
    sequencer_key: Option<SequencerKey>,
    sequencer_receipt_key: Option<SequencerReceiptKey>,
    placements: Option<(String, Arc<dyn super::state::StateVault>)>,
    thread_keys: std::sync::Mutex<std::collections::HashMap<String, CachedSequencerKeys>>,
    did_doc_keys: std::sync::Mutex<
        std::collections::HashMap<String, (Option<SequencerKey>, Option<SequencerReceiptKey>)>,
    >,
}

impl DsDirectoryStore {
    pub fn new(
        transport: Arc<GatewayXrpcTransport>,
        sequencer_key: Option<SequencerKey>,
        sequencer_receipt_key: Option<SequencerReceiptKey>,
    ) -> Self {
        Self {
            transport,
            sequencer_key,
            sequencer_receipt_key,
            placements: None,
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
    ) -> labyrinth::Result<(Option<SequencerKey>, Option<SequencerReceiptKey>)> {
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
            return Ok((None, None));
        };
        let parsed = parse_did_doc_sequencer_keys(sequencer_did, &doc_bytes)?;
        if parsed.0.is_some() || parsed.1.is_some() {
            self.did_doc_keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(sequencer_did.to_owned(), parsed.clone());
        }
        Ok(parsed)
    }

    async fn resolve_thread_sequencer_keys(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<(Option<SequencerKey>, Option<SequencerReceiptKey>)> {
        if let Some(cached) = self
            .thread_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(thread_id)
            .cloned()
        {
            return Ok((cached.redaction_key, cached.receipt_key));
        }

        let state_res = self
            .transport
            .query(
                "blue.catbird.chat.getConversationState",
                &[("conversationId", thread_id.to_owned())],
            )
            .await;

        let mut sequencer_did: Option<String> = None;
        let mut inline_redaction: Option<SequencerKey> = None;
        let mut inline_receipt: Option<SequencerReceiptKey> = None;

        match state_res {
            Ok(body) => {
                let parsed: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|_| labyrinth::Error::Malformed("getConversationState JSON"))?;
                if let Some(raw_ds) = parsed["state"]["sequencerDid"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                {
                    let norm_ds = normalize_sequencer_did(raw_ds);
                    if let Some(raw_ed) = parsed["state"]
                        .get("sequencerPublicKey")
                        .and_then(decode_wire_bytes_any)
                    {
                        if let Ok(key) = <[u8; 32]>::try_from(raw_ed.as_slice()) {
                            inline_redaction = Some(SequencerKey {
                                did: norm_ds.clone(),
                                key,
                            });
                        }
                    }
                    if let Some(raw_p256) = parsed["state"]
                        .get("sequencerReceiptPublicKey")
                        .and_then(decode_wire_bytes_any)
                    {
                        if p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw_p256).is_ok() {
                            inline_receipt = Some(SequencerReceiptKey {
                                did: norm_ds.clone(),
                                public_key_sec1: raw_p256,
                            });
                        }
                    }
                    sequencer_did = Some(norm_ds);
                } else if let Some(space_uri) = parsed["state"]["conversationSpace"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                {
                    let space_ref = labyrinth::store::space::SpaceRef::parse(space_uri)?;
                    sequencer_did = Some(normalize_sequencer_did(&space_ref.space_did));
                }
            }
            Err(e) => {
                let mapped = map_xrpc_error(e);
                match mapped {
                    labyrinth::Error::Forbidden | labyrinth::Error::NotFound("conversation") => {
                        sequencer_did = self.saved_thread_authority(thread_id)?;
                    }
                    other => return Err(other),
                }
            }
        }

        if sequencer_did.is_none() {
            sequencer_did = self.saved_thread_authority(thread_id)?;
        }

        // Fail closed: NEVER match home DS keys when `sequencer_did` is unknown (`None`)
        // or belongs to a foreign federated authority.
        let matches_expected = |candidate_did: &str, target: Option<&str>| match target {
            Some(expected) => normalize_sequencer_did(candidate_did) == expected,
            None => false,
        };

        let mut redaction_key = inline_redaction;
        if redaction_key.is_none() {
            if let Some(ref sk) = self.sequencer_key {
                if matches_expected(&sk.did, sequencer_did.as_deref()) {
                    redaction_key = Some(SequencerKey {
                        did: normalize_sequencer_did(&sk.did),
                        key: sk.key,
                    });
                }
            }
        }
        if redaction_key.is_none() {
            if let Some((did, key)) = self
                .transport
                .resolve_sequencer_key_for(thread_id, sequencer_did.as_deref())
                .await
            {
                let norm = normalize_sequencer_did(&did);
                if sequencer_did.as_deref().is_none_or(|exp| norm == exp) {
                    if sequencer_did.is_none() {
                        sequencer_did = Some(norm.clone());
                    }
                    redaction_key = Some(SequencerKey { did: norm, key });
                }
            }
        }

        let mut receipt_key = inline_receipt;
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
        if receipt_key.is_none() {
            if let Some((did, sec1)) = self
                .transport
                .resolve_sequencer_receipt_key_for(thread_id, sequencer_did.as_deref())
                .await
            {
                let norm = normalize_sequencer_did(&did);
                if sequencer_did.as_deref().is_none_or(|exp| norm == exp)
                    && p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).is_ok()
                {
                    if sequencer_did.is_none() {
                        sequencer_did = Some(norm.clone());
                    }
                    receipt_key = Some(SequencerReceiptKey {
                        did: norm,
                        public_key_sec1: sec1,
                    });
                }
            }
        }

        if let Some(ref seq_did) = sequencer_did {
            if redaction_key.is_none() || receipt_key.is_none() {
                let (doc_redaction, doc_receipt) = self.resolve_did_doc_keys(seq_did).await?;
                if redaction_key.is_none() {
                    redaction_key = doc_redaction;
                }
                if receipt_key.is_none() {
                    receipt_key = doc_receipt;
                }
            }
            if redaction_key.is_some() || receipt_key.is_some() {
                self.thread_keys
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        thread_id.to_owned(),
                        CachedSequencerKeys {
                            redaction_key: redaction_key.clone(),
                            receipt_key: receipt_key.clone(),
                        },
                    );
            }
        }

        Ok((redaction_key, receipt_key))
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
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut op_id);
        self.transport
            .procedure("blue.catbird.labyrinth.purgeMailbox", b"{}", op_id)
            .await
            .map(|_| ())
            .map_err(map_xrpc_error)
    }

    pub async fn delete_account_data(&self) -> labyrinth::Result<()> {
        let mut op_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut op_id);
        self.transport
            .procedure("blue.catbird.labyrinth.deleteAccountData", b"{}", op_id)
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

    async fn sequencer_key(&self, thread_id: &str) -> labyrinth::Result<Option<SequencerKey>> {
        let (redaction_key, _) = self.resolve_thread_sequencer_keys(thread_id).await?;
        Ok(redaction_key)
    }

    async fn sequencer_receipt_key(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        let (_, receipt_key) = self.resolve_thread_sequencer_keys(thread_id).await?;
        Ok(receipt_key)
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
