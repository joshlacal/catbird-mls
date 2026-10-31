//! [`XrpcTransport`] over the platform gateway (design
//! `docs/MLSDS_BACKEND.md` §3, §5 in the labyrinth repo).
//!
//! Every call names the calling chat device: queries carry
//! `actorDeviceId` as a query parameter, procedures carry it inside the
//! signed `labyrinthWriteBody` ([`super::write_auth`]). Every Labyrinth
//! query also carries the device-signed read headers
//! (`catbird-labyrinth-read`, `catbird-labyrinth-read-signature`; the
//! crate's `store::xrpc::read_auth`), signed by the same chat device key
//! over every query parameter on the wire. The gateway adds
//! the account's service-auth JWT (`lxm` = the NSID). The one non-Labyrinth
//! query the stores make, `blue.catbird.chat.getConversationState`, goes
//! through the existing clean-chat route so gateways need nothing new for
//! it.

use std::sync::Arc;

use labyrinth::store::xrpc::read_auth::{self, ReadClaim};
use labyrinth::store::xrpc::{XrpcError, XrpcTransport};
use tokio::runtime::Handle;

use super::signer::ChatKeySigner;
use super::write_auth::{write_headers, WriteBody};
use super::LabyrinthRequest;
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::canonical_transport::{
    encode_query, CanonicalOperation, GatewayResponse, PreparedRequest,
};

/// Blocking access to the platform gateway.
pub trait LabyrinthGateway: Send + Sync {
    /// A `blue.catbird.labyrinth.*` request.
    fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String>;
    /// A clean-chat query through the existing prepared-request route.
    fn submit_canonical(&self, request: PreparedRequest) -> Result<GatewayResponse, String>;
}

/// [`LabyrinthGateway`] over the orchestrator's [`MLSAPIClient`].
pub struct ApiGateway<A> {
    api: Arc<A>,
    runtime: Handle,
}

impl<A> ApiGateway<A> {
    pub fn new(api: Arc<A>, runtime: Handle) -> Self {
        Self { api, runtime }
    }
}

impl<A: MLSAPIClient + 'static> LabyrinthGateway for ApiGateway<A> {
    fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String> {
        self.runtime
            .block_on(self.api.submit_labyrinth_request(request))
            .map_err(|e| e.to_string())
    }

    fn submit_canonical(&self, request: PreparedRequest) -> Result<GatewayResponse, String> {
        self.runtime
            .block_on(self.api.submit_prepared_request(request))
            .map_err(|e| e.to_string())
    }
}

/// The account's PDS Space ([`super::space`]) through the platform's
/// `submit_labyrinth_space_request`.
impl<A: MLSAPIClient + 'static> super::space::LabyrinthSpaceGateway for ApiGateway<A> {
    fn submit_space(
        &self,
        request: super::space::LabyrinthSpaceRequest,
    ) -> Result<GatewayResponse, String> {
        self.runtime
            .block_on(self.api.submit_labyrinth_space_request(request))
            .map_err(|e| e.to_string())
    }
}

/// Maximum response payload accepted from a Labyrinth or Space XRPC call (4 MiB).
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
pub(crate) fn validate_nsid(nsid: &str) -> Result<(), XrpcError> {
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

/// The PDS half of the Labyrinth directory ([CB-19]) through the
/// platform's `*_labyrinth_mailbox_keys` gateway methods.
impl<A: MLSAPIClient + 'static> labyrinth::store::pds::PdsRecords for ApiGateway<A> {
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> Result<(), String> {
        enforce_pds_record_cap(record)?;
        self.runtime
            .block_on(self.api.put_labyrinth_mailbox_keys(rkey, record))
            .map_err(|e| e.to_string())
    }

    fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<Vec<u8>>, String> {
        let out = self
            .runtime
            .block_on(self.api.get_labyrinth_mailbox_keys(did, rkey))
            .map_err(|e| e.to_string())?;
        if let Some(ref bytes) = out {
            enforce_pds_record_cap(bytes)?;
        }
        Ok(out)
    }

    fn delete_all_mailbox_keys(&self) -> Result<(), String> {
        self.runtime
            .block_on(self.api.delete_labyrinth_mailbox_keys())
            .map_err(|e| e.to_string())
    }
}

/// The Labyrinth stores' transport for one chat device.
pub struct GatewayXrpcTransport {
    gateway: Arc<dyn LabyrinthGateway>,
    signer: Arc<dyn ChatKeySigner>,
    did: String,
    device_id: String,
}

impl GatewayXrpcTransport {
    /// The transport of chat device `device_id` (key `signer`) of `did`.
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

    /// Every query parameter on the wire: `actorDeviceId`, then `params`.
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

    /// The device-signed read headers for `GET nsid?params` (all wire
    /// parameters), issued now.
    fn read_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<(String, String)>, XrpcError> {
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
        let claim = ReadClaim::new(nsid, params, &self.did, &self.device_id, now);
        let json = claim.to_json();
        let signature = self
            .signer
            .sign(&ReadClaim::signing_input(&json))
            .map_err(signing_error)?;
        Ok(read_auth::read_headers(&json, &signature))
    }
}

/// The XRPC error name of a request this device could not sign: the chat
/// key is unavailable (for example a locked keychain). [`super::map_error`]
/// reports it as a credential error, like a failing Labyrinth signature.
pub(crate) const SIGNING_FAILED: &str = "ChatKeySigningFailed";

/// `status = 0`: the request was never sent because signing it failed.
fn signing_error(message: String) -> XrpcError {
    XrpcError {
        status: 0,
        error: Some(SIGNING_FAILED.into()),
        message: Some(message),
    }
}

/// `status = 0`: no response arrived.
fn transport_error(message: impl Into<String>) -> XrpcError {
    XrpcError {
        status: 0,
        error: None,
        message: Some(message.into()),
    }
}

/// A 2xx body, or the atproto error body (`{"error","message"}`).
pub(crate) fn decode_response(
    response: Result<GatewayResponse, String>,
) -> Result<Vec<u8>, XrpcError> {
    let response = response.map_err(transport_error)?;
    if response.body.len() > MAX_LABYRINTH_XRPC_RESPONSE_BYTES {
        return Err(transport_error(format!(
            "XRPC response body exceeds {} byte limit ({} bytes)",
            MAX_LABYRINTH_XRPC_RESPONSE_BYTES,
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
    Err(XrpcError {
        status: response.status,
        error: field("error"),
        message: field("message"),
    })
}

impl XrpcTransport for GatewayXrpcTransport {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcError> {
        validate_nsid(nsid)?;
        let canonical = CanonicalOperation::ALL
            .iter()
            .copied()
            .find(|op| op.nsid() == nsid);
        if canonical.is_none() && !nsid.starts_with(labyrinth::store::xrpc::NSID_PREFIX) {
            return Err(transport_error(format!(
                "refusing a non-Labyrinth query: {nsid}"
            )));
        }
        let params = self.wire_params(params);
        let path = Self::query_path(nsid, &params);
        let response = match canonical {
            Some(operation) => self.gateway.submit_canonical(PreparedRequest {
                operation,
                method: "GET".into(),
                path,
                body: None,
            }),
            None => {
                let mut all = headers.to_vec();
                all.extend(self.read_headers(nsid, &params)?);
                self.gateway.submit_labyrinth(LabyrinthRequest {
                    nsid: nsid.to_owned(),
                    method: "GET".into(),
                    path,
                    body: None,
                    headers: all,
                })
            }
        };
        decode_response(response)
    }

    fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
        operation_id: [u8; 16],
    ) -> Result<Vec<u8>, XrpcError> {
        validate_nsid(nsid)?;
        if !nsid.starts_with(labyrinth::store::xrpc::NSID_PREFIX) {
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
        decode_response(self.gateway.submit_labyrinth(LabyrinthRequest {
            nsid: nsid.to_owned(),
            method: "POST".into(),
            path: format!("/xrpc/{nsid}"),
            body: Some(payload.to_vec()),
            headers: write_headers(&json, &signature),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Platforms return Space errors raw; labyrinth decides what an error
    /// name means (a member-repo `SpaceNotFound` is a read refusal), so the
    /// name and status must survive decoding unchanged.
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
        // 2xx response exceeding 4 MiB must fail closed.
        let err_200 = decode_response(Ok(GatewayResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body: vec![b'a'; FOUR_MIB + 1],
        }))
        .expect_err("200 response > 4 MiB must be rejected");
        assert_eq!(err_200.status, 0);

        // Non-2xx response exceeding 4 MiB must also fail closed without serde_json parsing.
        let err_500 = decode_response(Ok(GatewayResponse {
            status: 500,
            content_type: Some("application/json".into()),
            body: vec![b' '; FOUR_MIB + 1],
        }))
        .expect_err("500 response > 4 MiB must be rejected");
        assert!(err_500.error.is_none());

        // PDS record cap (256 KiB) must accept exact bound and reject +1 byte.
        assert!(enforce_pds_record_cap(&vec![0u8; MAX_PDS_RECORD_BYTES]).is_ok());
        assert!(enforce_pds_record_cap(&vec![0u8; MAX_PDS_RECORD_BYTES + 1]).is_err());
    }

    #[test]
    fn f13_invalid_nsid_syntax_is_rejected_before_path_formatting() {
        use crate::labyrinth::space::{
            LabyrinthSpaceGateway, LabyrinthSpaceRequest, SpaceXrpcTransport,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Default)]
        struct CountingGateway {
            calls: AtomicUsize,
        }
        impl LabyrinthGateway for CountingGateway {
            fn submit_labyrinth(&self, _req: LabyrinthRequest) -> Result<GatewayResponse, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
            fn submit_canonical(&self, _req: PreparedRequest) -> Result<GatewayResponse, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: b"{}".to_vec(),
                })
            }
        }
        impl LabyrinthSpaceGateway for CountingGateway {
            fn submit_space(&self, _req: LabyrinthSpaceRequest) -> Result<GatewayResponse, String> {
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
                    .is_err(),
                "expected query error for malformed NSID {bad_lab_nsid:?}"
            );
            assert!(
                transport.procedure(bad_lab_nsid, b"{}", [0u8; 16]).is_err(),
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
                space_transport
                    .query_with_headers(bad_space_nsid, &[], &[])
                    .is_err(),
                "expected Space query error for malformed NSID {bad_space_nsid:?}"
            );
            assert!(
                space_transport
                    .procedure(bad_space_nsid, b"{}", [0u8; 16])
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
