//! Signed `labyrinthWriteBody` and `ReadClaim` headers verified by `mls-ds`
//! (`mls-ds/server/src/labyrinth/{auth.rs,read_auth.rs}`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Header carrying `base64url(labyrinthWriteBody JSON)`.
pub const WRITE_BODY_HEADER: &str = "catbird-labyrinth-write";
/// Header carrying `base64url(signature over WRITE_DOMAIN || body bytes)`.
pub const WRITE_SIGNATURE_HEADER: &str = "catbird-labyrinth-write-signature";
/// Header carrying `base64url` encoded `blue.catbird.chat.device` key proof.
pub const KEY_PROOF_HEADER: &str = "catbird-labyrinth-key-proof";
/// Header carrying `base64url` encoded `blue.catbird.chat.deviceRevocation` CARv1 proof.
pub const REVOCATION_PROOF_HEADER: &str = "catbird-labyrinth-revocation-proof";
/// Signature domain of `labyrinthWriteBody`.
pub const WRITE_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-WRITE\0";

/// Header carrying `base64url(ReadClaim JSON)`.
pub const READ_HEADER: &str = "catbird-labyrinth-read";
/// Header carrying `base64url(signature over READ_DOMAIN || claim bytes)`.
pub const READ_SIGNATURE_HEADER: &str = "catbird-labyrinth-read-signature";
/// Signature domain of `ReadClaim`.
pub const READ_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-READ\0";

/// `labyrinthWriteBody`, field for field as `mls-ds` parses it
/// (`deny_unknown_fields`, camelCase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

fn encode_rfc3986_component(value: &str, out: &mut String) {
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
}

/// Canonical query string matching `mls-ds` `canonical_query`.
pub fn canonical_query_params(params: &[(&str, String)]) -> String {
    let mut pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    pairs.sort_by(|a, b| (a.0.as_bytes(), a.1.as_bytes()).cmp(&(b.0.as_bytes(), b.1.as_bytes())));
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode_rfc3986_component(k, &mut out);
        out.push('=');
        encode_rfc3986_component(v, &mut out);
    }
    out
}

/// Device-signed read claim verified by `mls-ds` on `getEpochHead`,
/// `getChatDeviceKeys`, and `getMemberDevices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadClaim {
    pub v: u8,
    pub nsid: String,
    pub query: String,
    pub did: String,
    pub device_id: String,
    pub issued_at: i64,
}

impl ReadClaim {
    pub fn new(
        nsid: &str,
        params: &[(&str, String)],
        did: &str,
        device_id: &str,
        issued_at_ms: u64,
    ) -> Self {
        Self {
            v: 1,
            nsid: nsid.to_owned(),
            query: canonical_query_params(params),
            did: did.to_owned(),
            device_id: device_id.to_owned(),
            issued_at: i64::try_from(issued_at_ms).unwrap_or(i64::MAX),
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ReadClaim serializes")
    }

    pub fn signing_input(json: &[u8]) -> Vec<u8> {
        [READ_DOMAIN, json].concat()
    }
}

/// The two headers for a `ReadClaim` `json` and its Ed25519 signature.
pub fn read_headers(json: &[u8], signature: &[u8; 64]) -> Vec<(String, String)> {
    vec![
        (READ_HEADER.to_owned(), URL_SAFE_NO_PAD.encode(json)),
        (
            READ_SIGNATURE_HEADER.to_owned(),
            URL_SAFE_NO_PAD.encode(signature),
        ),
    ]
}
