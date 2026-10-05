//! The signed `labyrinthWriteBody` mls-ds requires on every Labyrinth
//! procedure (mls-ds `server/src/labyrinth/auth.rs`, decision
//! "Labyrinth backend server build" item 1 in the labyrinth repo).
//!
//! The body is the JSON object
//! `{operationId, actorDeviceId, endpointNsid, payloadSha256, signedAt}`
//! (ids and digests as lowercase hex, `signedAt` RFC 3339). It travels as
//! `base64url(json)` in [`WRITE_BODY_HEADER`]; [`WRITE_SIGNATURE_HEADER`]
//! carries `base64url(Ed25519(chat device key, WRITE_DOMAIN || json))`.
//! Both are unpadded. The server checks the signature against the caller's
//! current chat device key, the digest against the exact request body, the
//! NSID against the route and `signedAt` within 300 s of its clock; the
//! operation id makes a retry replay the stored response.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Header carrying `base64url(labyrinthWriteBody JSON)`.
pub const WRITE_BODY_HEADER: &str = "catbird-labyrinth-write";
/// Header carrying `base64url(signature over WRITE_DOMAIN || body bytes)`.
pub const WRITE_SIGNATURE_HEADER: &str = "catbird-labyrinth-write-signature";
/// Signature domain of `labyrinthWriteBody`.
pub const WRITE_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-WRITE\0";

/// `labyrinthWriteBody`, field for field as mls-ds parses it
/// (`deny_unknown_fields`, camelCase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteBody {
    pub operation_id: String,
    pub actor_device_id: String,
    pub endpoint_nsid: String,
    pub payload_sha256: String,
    pub signed_at: String,
}

impl WriteBody {
    /// The body for one procedure call. `signed_at` is the caller's clock.
    pub fn new(
        nsid: &str,
        payload: &[u8],
        operation_id: [u8; 16],
        actor_device_id: &str,
        signed_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            operation_id: hex::encode(operation_id),
            actor_device_id: actor_device_id.to_owned(),
            endpoint_nsid: nsid.to_owned(),
            payload_sha256: hex::encode(Sha256::digest(payload)),
            signed_at: signed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }
    }

    /// The exact bytes that are signed (after [`WRITE_DOMAIN`]) and sent.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a struct of strings always serializes")
    }

    /// `WRITE_DOMAIN || json`: what the chat device key signs.
    pub fn signing_input(json: &[u8]) -> Vec<u8> {
        [WRITE_DOMAIN, json].concat()
    }
}

/// The two headers for a write body `json` and its signature.
pub fn write_headers(json: &[u8], signature: &[u8; 64]) -> Vec<(String, String)> {
    vec![
        (WRITE_BODY_HEADER.to_owned(), URL_SAFE_NO_PAD.encode(json)),
        (
            WRITE_SIGNATURE_HEADER.to_owned(),
            URL_SAFE_NO_PAD.encode(signature),
        ),
    ]
}
