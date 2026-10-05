//! [`XrpcTransport`] over the platform gateway (design
//! `docs/MLSDS_BACKEND.md` §3, §5 in the labyrinth repo).
//!
//! Every call names the calling chat device: queries carry
//! `actorDeviceId` as a query parameter, procedures carry it inside the
//! signed `labyrinthWriteBody` ([`super::write_auth`]). The gateway adds
//! the account's service-auth JWT (`lxm` = the NSID). The one non-Labyrinth
//! query the stores make, `blue.catbird.chat.getConversationState`, goes
//! through the existing clean-chat route so gateways need nothing new for
//! it.

use std::sync::Arc;

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

/// The Labyrinth stores' transport for one chat device.
pub struct GatewayXrpcTransport {
    gateway: Arc<dyn LabyrinthGateway>,
    signer: Arc<dyn ChatKeySigner>,
    device_id: String,
}

impl GatewayXrpcTransport {
    pub fn new(
        gateway: Arc<dyn LabyrinthGateway>,
        signer: Arc<dyn ChatKeySigner>,
        device_id: String,
    ) -> Self {
        Self {
            gateway,
            signer,
            device_id,
        }
    }

    fn query_path(&self, nsid: &str, params: &[(&str, String)]) -> String {
        let mut path = format!(
            "/xrpc/{nsid}?actorDeviceId={}",
            encode_query(&self.device_id)
        );
        for (k, v) in params {
            path.push('&');
            path.push_str(&encode_query(k));
            path.push('=');
            path.push_str(&encode_query(v));
        }
        path
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
    fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, XrpcError> {
        let path = self.query_path(nsid, params);
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
            None => self.gateway.submit_labyrinth(LabyrinthRequest {
                nsid: nsid.to_owned(),
                method: "GET".into(),
                path,
                body: None,
                headers: Vec::new(),
            }),
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
            .map_err(transport_error)?;
        decode_response(self.gateway.submit_labyrinth(LabyrinthRequest {
            nsid: nsid.to_owned(),
            method: "POST".into(),
            path: format!("/xrpc/{nsid}"),
            body: Some(payload.to_vec()),
            headers: write_headers(&json, &signature),
        }))
    }
}
