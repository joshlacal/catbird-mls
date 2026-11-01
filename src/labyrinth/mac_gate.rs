//! Gate 7 `Atproto-Space-Mac` response authenticator (`atproto-space-record` &
//! `atproto-space-repo`) and `(conversation_id, group_id)`-bound `MEK` replay guard.

use std::sync::Arc;

use atproto_spaces::mac::{
    parse_space_mac_header, verify_commit_mac, verify_record_mac, SPACE_MAC_HEADER_NAME,
};
use base64::Engine as _;
use labyrinth::mek::Mek;
use labyrinth::store::{MaybeSend, MaybeSync};
use subtle::ConstantTimeEq;

use super::space::{LabyrinthSpaceRequest, LabyrinthSpaceResponse, SpaceResponseMacVerifier};
use crate::MLSError;

/// Resolves the 32-byte credentialed Space MAC secret negotiated for a given `space_uri`.
pub trait SharedSecretLookup: MaybeSend + MaybeSync {
    fn shared_secret_for_space(&self, space_uri: &str) -> Option<[u8; 32]>;
}

/// Gate 7 verifier rejecting any Space `getRecord` / `listRepoOps` / `getRepo` response whose
/// `Atproto-Space-Mac` header is missing, malformed, or fails constant-time HMAC verification
/// BEFORE any `MEK` or record ciphertext is inspected by Labyrinth.
pub struct AtprotoSpaceMacVerifier {
    secrets: Arc<dyn SharedSecretLookup>,
}

impl AtprotoSpaceMacVerifier {
    pub fn new(secrets: Arc<dyn SharedSecretLookup>) -> Self {
        Self { secrets }
    }
}

impl SpaceResponseMacVerifier for AtprotoSpaceMacVerifier {
    fn verify_space_response(
        &self,
        request: &LabyrinthSpaceRequest,
        response: &LabyrinthSpaceResponse,
    ) -> Result<(), String> {
        let mac_header = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(SPACE_MAC_HEADER_NAME))
            .map(|(_, v)| v.as_str());

        match request.nsid.as_str() {
            "com.atproto.space.getRecord" => {
                let header = mac_header
                    .ok_or_else(|| "Gate 7: missing Atproto-Space-Mac on getRecord".to_owned())?;
                let space_uri = query_param(&request.path, "space").ok_or_else(|| {
                    "Gate 7: getRecord request missing space query param".to_owned()
                })?;
                let secret = self
                    .secrets
                    .shared_secret_for_space(&space_uri)
                    .ok_or_else(|| format!("Gate 7: no Space MAC secret for {space_uri}"))?;

                let parsed: serde_json::Value = serde_json::from_slice(&response.body)
                    .map_err(|e| format!("Gate 7: getRecord invalid JSON: {e}"))?;
                let uri = parsed["uri"]
                    .as_str()
                    .ok_or_else(|| "Gate 7: getRecord response missing uri".to_owned())?;
                let cid_str = parsed["cid"]
                    .as_str()
                    .ok_or_else(|| "Gate 7: getRecord response missing cid".to_owned())?;
                let (_base, cid_bytes) = multibase::decode(cid_str)
                    .map_err(|e| format!("Gate 7: getRecord invalid multibase CID: {e}"))?;

                let record_uri_with_query = if uri.contains("?space=") {
                    uri.to_owned()
                } else {
                    format!("{uri}?space={space_uri}")
                };

                verify_record_mac(&secret, header, &record_uri_with_query, &cid_bytes)
                    .map_err(|e| format!("Gate 7: record MAC failed: {e}"))
            }
            "com.atproto.space.listRepoOps" | "com.atproto.space.getRepo" => {
                let header = mac_header.ok_or_else(|| {
                    format!("Gate 7: missing Atproto-Space-Mac on {}", request.nsid)
                })?;
                let space_uri = query_param(&request.path, "space")
                    .ok_or_else(|| format!("Gate 7: {} missing space query param", request.nsid))?;
                let repo_did = query_param(&request.path, "repo")
                    .or_else(|| query_param(&request.path, "did"))
                    .ok_or_else(|| {
                        format!("Gate 7: {} missing repo/did query param", request.nsid)
                    })?;
                let secret = self
                    .secrets
                    .shared_secret_for_space(&space_uri)
                    .ok_or_else(|| format!("Gate 7: no Space MAC secret for {space_uri}"))?;

                let parsed: serde_json::Value = serde_json::from_slice(&response.body)
                    .map_err(|e| format!("Gate 7: {} invalid JSON: {e}", request.nsid))?;
                let rev = parsed["rev"]
                    .as_str()
                    .ok_or_else(|| format!("Gate 7: {} response missing rev", request.nsid))?;
                let data_b64 = parsed["data"]["$bytes"].as_str().ok_or_else(|| {
                    format!("Gate 7: {} response missing data.$bytes", request.nsid)
                })?;
                let data_vec = base64::engine::general_purpose::STANDARD
                    .decode(data_b64)
                    .map_err(|e| format!("Gate 7: invalid commit data.$bytes base64: {e}"))?;
                let data_32: [u8; 32] = data_vec
                    .try_into()
                    .map_err(|_| "Gate 7: commit data.$bytes must be 32 bytes".to_owned())?;

                verify_commit_mac(&secret, header, &space_uri, &repo_did, rev, &data_32)
                    .map_err(|e| format!("Gate 7: commit MAC failed: {e}"))
            }
            _ => {
                if let Some(header) = mac_header {
                    parse_space_mac_header(header)
                        .map(|_| ())
                        .map_err(|e| format!("Gate 7: malformed Atproto-Space-Mac: {e}"))
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Expected conversation + MLS group coordinates to which a `MEK` must remain bound (`Gate 7`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundMekContext {
    pub conversation_id: String,
    pub group_id: Vec<u8>,
}

/// Reject any `MEK` envelope replayed across a different `conversation_id` or MLS `group_id`
/// (e.g., across a group reset generation or another conversation Space) (`Gate 7`).
pub fn verify_mek_conversation_binding(
    mek: &Mek,
    record_conversation_id: &str,
    record_group_id: &[u8],
    expected: &BoundMekContext,
) -> Result<(), MLSError> {
    if expected.conversation_id.is_empty() || expected.group_id.is_empty() {
        return Err(MLSError::invalid_input(
            "BoundMekContext conversation_id and group_id must be non-empty",
        ));
    }
    if bool::from(mek.secret().ct_eq(&[0u8; 32])) {
        return Err(MLSError::Cryptography(
            "Gate 7: all-zero MEK rejected".into(),
        ));
    }
    let convo_eq = record_conversation_id.len() == expected.conversation_id.len()
        && bool::from(
            record_conversation_id
                .as_bytes()
                .ct_eq(expected.conversation_id.as_bytes()),
        );
    let group_eq = record_group_id.len() == expected.group_id.len()
        && bool::from(record_group_id.ct_eq(expected.group_id.as_slice()));

    if convo_eq && group_eq {
        Ok(())
    } else {
        Err(MLSError::Cryptography(
            "Gate 7: MEK conversation_id or group_id binding mismatch".into(),
        ))
    }
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k) == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
