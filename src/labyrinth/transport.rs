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

/// The PDS half of the Labyrinth directory ([CB-19]) through the
/// platform's `*_labyrinth_mailbox_keys` gateway methods.
impl<A: MLSAPIClient + 'static> labyrinth::store::pds::PdsRecords for ApiGateway<A> {
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> Result<(), String> {
        self.runtime
            .block_on(self.api.put_labyrinth_mailbox_keys(rkey, record))
            .map_err(|e| e.to_string())
    }

    fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<Vec<u8>>, String> {
        self.runtime
            .block_on(self.api.get_labyrinth_mailbox_keys(did, rkey))
            .map_err(|e| e.to_string())
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
        let params = self.wire_params(params);
        let path = Self::query_path(nsid, &params);
        let canonical = CanonicalOperation::ALL
            .iter()
            .copied()
            .find(|op| op.nsid() == nsid);
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
}
