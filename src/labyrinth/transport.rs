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
        }
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
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
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
            chrono::Utc::now(),
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

/// Verifying `mls-ds` directory & epoch-head publisher over the 6 clean-slate endpoints.
pub struct DsDirectoryStore {
    transport: Arc<GatewayXrpcTransport>,
    sequencer_key: Option<SequencerKey>,
    sequencer_receipt_key: Option<SequencerReceiptKey>,
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
        }
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
                None => return Ok(all),
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

    async fn sequencer_key(&self, _thread_id: &str) -> labyrinth::Result<Option<SequencerKey>> {
        Ok(self.sequencer_key.clone())
    }

    async fn sequencer_receipt_key(
        &self,
        _thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        Ok(self.sequencer_receipt_key.clone())
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
}
