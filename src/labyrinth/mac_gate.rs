//! Gate 7 Nov-12 RFC 9421 / RFC 9651 Space MAC response authenticator
//! (`Atproto-Space-Record` & `Atproto-Space-Commit` + `Signature-Input` + `Signature`)
//! and `(conversation_id, group_id)`-bound `MEK` replay guard.

use std::sync::Arc;

use atproto_spaces::mac::{
    parse_accept_signature, verify_commit_mac, verify_record_mac, MacProfile,
    ACCEPT_SIGNATURE_HEADER, COMMIT_MAC_HEADER, RECORD_MAC_HEADER, SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
};
use base64::Engine as _;
use http::{HeaderMap, HeaderName, HeaderValue};
use labyrinth::mek::Mek;
use labyrinth::store::{MaybeSend, MaybeSync};
use subtle::ConstantTimeEq;

use super::space::{LabyrinthSpaceRequest, LabyrinthSpaceResponse, SpaceResponseMacVerifier};
use crate::MLSError;

/// Resolves the 32-byte credentialed Space MAC secret (and optional pinned ephemeral
/// `#atproto_kem` `did:key` share) negotiated for a given `space_uri`.
pub trait SharedSecretLookup: MaybeSend + MaybeSync {
    fn shared_secret_for_space(&self, space_uri: &str) -> Option<[u8; 32]>;

    fn key_share_for_space(&self, _space_uri: &str) -> Option<String> {
        None
    }
}

/// Gate 7 verifier rejecting any Space `getRecord` / `listRepoOps` / `getRepo` /
/// `getLatestCommit` / `listWriters` response whose Nov-12 `Atproto-Space-{Record,Commit}` +
/// `Signature-Input` + `Signature` headers are missing, malformed, or fail constant-time
/// HMAC verification BEFORE any `MEK` or record ciphertext is inspected by Labyrinth.
pub struct AtprotoSpaceMacVerifier {
    secrets: Arc<dyn SharedSecretLookup>,
}

impl AtprotoSpaceMacVerifier {
    pub fn new(secrets: Arc<dyn SharedSecretLookup>) -> Self {
        Self { secrets }
    }

    fn resolve_key_share(
        &self,
        request: &LabyrinthSpaceRequest,
        space_uri: &str,
        profile: MacProfile,
    ) -> Result<String, String> {
        let from_req = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(ACCEPT_SIGNATURE_HEADER))
            .map(|(_, v)| {
                parse_accept_signature(v, profile)
                    .map(|(_, ks)| ks)
                    .map_err(|e| format!("Gate 7: invalid request Accept-Signature: {e}"))
            })
            .transpose()?;
        let from_lookup = self.secrets.key_share_for_space(space_uri);
        match (from_req, from_lookup) {
            (Some(req_ks), Some(expected_ks)) if req_ks != expected_ks => {
                Err("Gate 7: request Accept-Signature keyid does not match pinned key share".into())
            }
            (Some(req_ks), _) => Ok(req_ks),
            (None, Some(expected_ks)) => Ok(expected_ks),
            (None, None) => Err(format!(
                "Gate 7: missing Accept-Signature / key share for {space_uri}"
            )),
        }
    }
}

fn build_mac_header_map(response: &LabyrinthSpaceResponse) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();
    for (name, val) in &response.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            COMMIT_MAC_HEADER | RECORD_MAC_HEADER | SIGNATURE_INPUT_HEADER | SIGNATURE_HEADER
        ) {
            let hdr_name = HeaderName::from_bytes(lower.as_bytes())
                .map_err(|e| format!("Gate 7: invalid MAC header name: {e}"))?;
            if map.contains_key(&hdr_name) {
                return Err(format!("Gate 7: duplicate MAC response header {lower}"));
            }
            let hdr_val = HeaderValue::from_str(val)
                .map_err(|e| format!("Gate 7: invalid MAC header value for {lower}: {e}"))?;
            map.insert(hdr_name, hdr_val);
        }
    }
    Ok(map)
}

impl SpaceResponseMacVerifier for AtprotoSpaceMacVerifier {
    fn verify_space_response(
        &self,
        request: &LabyrinthSpaceRequest,
        response: &LabyrinthSpaceResponse,
    ) -> Result<(), String> {
        let header_map = build_mac_header_map(response)?;

        match request.nsid.as_str() {
            "com.atproto.space.getRecord" => {
                if !header_map.contains_key(RECORD_MAC_HEADER) {
                    return Err("Gate 7: missing Atproto-Space-Record on getRecord".into());
                }
                let space_uri = query_param(&request.path, "space").ok_or_else(|| {
                    "Gate 7: getRecord request missing space query param".to_owned()
                })?;
                let secret = self
                    .secrets
                    .shared_secret_for_space(&space_uri)
                    .ok_or_else(|| format!("Gate 7: no Space MAC secret for {space_uri}"))?;
                let key_share = self.resolve_key_share(request, &space_uri, MacProfile::Record)?;

                let parsed: serde_json::Value = serde_json::from_slice(&response.body)
                    .map_err(|e| format!("Gate 7: getRecord invalid JSON: {e}"))?;
                let uri = parsed["uri"]
                    .as_str()
                    .ok_or_else(|| "Gate 7: getRecord response missing uri".to_owned())?;
                if !uri.starts_with(&format!("{space_uri}/")) {
                    return Err("Gate 7: getRecord response uri does not match space".into());
                }
                let cid_str = parsed["cid"]
                    .as_str()
                    .ok_or_else(|| "Gate 7: getRecord response missing cid".to_owned())?;
                multibase::decode(cid_str)
                    .map_err(|e| format!("Gate 7: getRecord invalid multibase CID: {e}"))?;

                verify_record_mac(&secret, &key_share, &header_map, uri, cid_str)
                    .map_err(|e| format!("Gate 7: record MAC failed: {e}"))
            }
            "com.atproto.space.listRepoOps"
            | "com.atproto.space.getRepo"
            | "com.atproto.space.getLatestCommit" => {
                if !header_map.contains_key(COMMIT_MAC_HEADER) {
                    return Err(format!(
                        "Gate 7: missing Atproto-Space-Commit on {}",
                        request.nsid
                    ));
                }
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
                let key_share = self.resolve_key_share(request, &space_uri, MacProfile::Commit)?;

                let (rev, data_32) = if request.nsid == "com.atproto.space.getRepo" {
                    let meta = atproto_spaces::star::read_star_metadata(
                        &response.body,
                        &space_uri,
                        &repo_did,
                    )
                    .map_err(|e| format!("Gate 7: getRepo invalid STAR metadata: {e}"))?;
                    (meta.rev, meta.data)
                } else {
                    let parsed: serde_json::Value = serde_json::from_slice(&response.body)
                        .map_err(|e| format!("Gate 7: {} invalid JSON: {e}", request.nsid))?;
                    let commit_obj = parsed.get("commit").unwrap_or(&parsed);
                    let rev = commit_obj["rev"]
                        .as_str()
                        .ok_or_else(|| format!("Gate 7: {} response missing rev", request.nsid))?
                        .to_owned();
                    let data_b64 = commit_obj["data"]["$bytes"].as_str().ok_or_else(|| {
                        format!("Gate 7: {} response missing data.$bytes", request.nsid)
                    })?;
                    let data_vec = base64::engine::general_purpose::STANDARD
                        .decode(data_b64)
                        .map_err(|e| format!("Gate 7: invalid commit data.$bytes base64: {e}"))?;
                    let data_32: [u8; 32] = data_vec
                        .try_into()
                        .map_err(|_| "Gate 7: commit data.$bytes must be 32 bytes".to_owned())?;
                    (rev, data_32)
                };

                verify_commit_mac(
                    &secret,
                    &key_share,
                    &header_map,
                    &space_uri,
                    &repo_did,
                    &rev,
                    &data_32,
                )
                .map_err(|e| format!("Gate 7: commit MAC failed: {e}"))
            }
            _ => {
                if (header_map.contains_key(COMMIT_MAC_HEADER)
                    || header_map.contains_key(RECORD_MAC_HEADER))
                    && (!header_map.contains_key(SIGNATURE_INPUT_HEADER)
                        || !header_map.contains_key(SIGNATURE_HEADER))
                {
                    return Err("Gate 7: incomplete Space MAC signature headers on response".into());
                }
                Ok(())
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
