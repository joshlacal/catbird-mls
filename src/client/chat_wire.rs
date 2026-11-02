//! Shared canonical `/xrpc/blue.catbird.chat.*`, `C33` direct-request, `I4` PDS key,
//! and `I13` ES256 receipt wire helpers for `CatbirdMlsClient` (native) and `WasmMlsClient` (`wasm32`).

use std::collections::BTreeMap;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer as _, storage::StorageProvider as _, OpenMlsProvider};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use tls_codec::Serialize as _;

use crate::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use crate::client::traits::PlatformHttpHeader;
use crate::error::MLSError;
use crate::metadata::{
    decrypt_metadata_snapshot, derive_metadata_key_from_group,
    encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use crate::orchestrator::canonical_transport::{
    derive_key_id, CanonicalOperation, CleanChatSigningContext, PreparedRequest,
};

pub const CHAT_READ_HEADER: &str = "catbird-chat-read";
pub const CHAT_READ_SIG_HEADER: &str = "catbird-chat-read-signature";
const CHAT_READ_DOMAIN: &[u8] = b"CATBIRD-CHAT-READ\0";
const ACK_ENTRIES_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACK-ENTRIES\0";

/// Decode a base64 field in either bare string or ATProto `{"$bytes": "..."}` JSON form.
pub fn json_bytes(v: &Value) -> Result<Vec<u8>, MLSError> {
    let raw = v
        .as_str()
        .or_else(|| v.get("$bytes").and_then(|b| b.as_str()))
        .ok_or_else(|| MLSError::invalid_input("expected base64 string or $bytes object"))?;
    STANDARD
        .decode(raw.trim())
        .map_err(|e| MLSError::invalid_input(format!("invalid base64 bytes: {e}")))
}

/// Format current UTC wall-clock time as canonical RFC 3339 milliseconds (`YYYY-MM-DDTHH:MM:SS.sssZ`).
pub fn now_rfc3339_millis() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Format a Unix timestamp in seconds as canonical RFC 3339 milliseconds.
pub fn unix_secs_rfc3339_millis(seconds: u64) -> Result<String, MLSError> {
    let secs_i64 =
        i64::try_from(seconds).map_err(|_| MLSError::invalid_input("timestamp overflow"))?;
    chrono::DateTime::from_timestamp(secs_i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .ok_or_else(|| MLSError::invalid_input("invalid unix timestamp"))
}

/// Encode a single component with `application/x-www-form-urlencoded` rules matching
/// `url::form_urlencoded::Serializer` (`mls-ds/server/src/chat_protocol/read_auth.rs`).
pub fn urlencode_form_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((byte >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((byte & 0x0f) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Build a canonical sorted query string matching `mls-ds` `canonical_query`.
pub fn canonical_query_string(pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<(&str, &str)> = pairs.to_vec();
    sorted.sort();
    let mut out = String::new();
    for (idx, (k, v)) in sorted.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&urlencode_form_component(k));
        out.push('=');
        out.push_str(&urlencode_form_component(v));
    }
    out
}

#[derive(Serialize)]
struct ReadClaimPayload<'a> {
    v: u8,
    nsid: &'a str,
    query: &'a str,
    did: &'a str,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
    #[serde(rename = "issuedAt")]
    issued_at: i64,
}

/// Sign `catbird-chat-read` + `catbird-chat-read-signature` headers (`M-F07`) for a GET query.
pub fn build_chat_read_headers(
    nsid: &str,
    canonical_query: &str,
    actor_did: &str,
    device_id: &str,
    signer: &SignatureKeyPair,
    now_ms: i64,
) -> Result<Vec<PlatformHttpHeader>, MLSError> {
    let claim = ReadClaimPayload {
        v: 1,
        nsid,
        query: canonical_query,
        did: actor_did,
        device_id,
        issued_at: now_ms,
    };
    let claim_bytes = serde_json::to_vec(&claim)
        .map_err(|e| MLSError::Internal(format!("serialize ReadClaim: {e}")))?;
    let mut transcript = Vec::with_capacity(CHAT_READ_DOMAIN.len() + claim_bytes.len());
    transcript.extend_from_slice(CHAT_READ_DOMAIN);
    transcript.extend_from_slice(&claim_bytes);
    let sig = signer
        .sign(&transcript)
        .map_err(|e| MLSError::Cryptography(format!("sign ReadClaim failed: {e:?}")))?;
    Ok(vec![
        PlatformHttpHeader {
            name: CHAT_READ_HEADER.to_string(),
            value: URL_SAFE_NO_PAD.encode(&claim_bytes),
        },
        PlatformHttpHeader {
            name: CHAT_READ_SIG_HEADER.to_string(),
            value: URL_SAFE_NO_PAD.encode(&sig),
        },
    ])
}

#[derive(Serialize)]
struct AckTranscriptPayload<'a> {
    #[serde(rename = "keyId")]
    key_id: &'a str,
    #[serde(rename = "upToSeq")]
    up_to_seq: i64,
    #[serde(rename = "signedAt")]
    signed_at: &'a str,
    generation: i64,
    #[serde(rename = "actorDeviceId")]
    actor_device_id: &'a str,
    #[serde(rename = "authGeneration")]
    auth_generation: i64,
    #[serde(rename = "conversationId")]
    conversation_id: &'a str,
}

/// Build a signed `POST /xrpc/blue.catbird.chat.acknowledgeEntries` JSON body (`I14`).
pub fn build_acknowledge_entries_request(
    conversation_id: &str,
    generation: i64,
    actor_device_id: &str,
    auth_generation: i64,
    up_to_seq: i64,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, MLSError> {
    let signed_at = now_rfc3339_millis();
    build_acknowledge_entries_request_at(
        conversation_id,
        generation,
        actor_device_id,
        auth_generation,
        up_to_seq,
        signer,
        &signed_at,
    )
}

/// Build a signed `POST /xrpc/blue.catbird.chat.acknowledgeEntries` JSON body (`I14`)
/// using a caller-supplied RFC 3339 millisecond timestamp (`signed_at`).
pub fn build_acknowledge_entries_request_at(
    conversation_id: &str,
    generation: i64,
    actor_device_id: &str,
    auth_generation: i64,
    up_to_seq: i64,
    signer: &SignatureKeyPair,
    signed_at: &str,
) -> Result<Vec<u8>, MLSError> {
    let key_id = derive_key_id(signer.public());
    let payload = AckTranscriptPayload {
        key_id: &key_id,
        up_to_seq,
        signed_at,
        generation,
        actor_device_id,
        auth_generation,
        conversation_id,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload)
        .map_err(|e| MLSError::Internal(format!("encode AckTranscriptPayload CBOR: {e}")))?;
    let mut transcript = Vec::with_capacity(ACK_ENTRIES_DOMAIN.len() + cbor.len());
    transcript.extend_from_slice(ACK_ENTRIES_DOMAIN);
    transcript.extend_from_slice(&cbor);
    let sig = signer
        .sign(&transcript)
        .map_err(|e| MLSError::Cryptography(format!("sign acknowledgeEntries failed: {e:?}")))?;
    serde_json::to_vec(&json!({
        "conversationId": conversation_id,
        "generation": generation,
        "actorDeviceId": actor_device_id,
        "keyId": key_id,
        "authGeneration": auth_generation,
        "upToSeq": up_to_seq,
        "signedAt": signed_at,
        "signature": { "$bytes": STANDARD.encode(&sig) }
    }))
    .map_err(|e| MLSError::Internal(format!("serialize acknowledgeEntries JSON: {e}")))
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.device/{device_id}` (`ADR-009`, `I4`).
pub fn build_pds_device_put_record_body(
    repo_did: &str,
    device_id: &str,
    mls_signature_public_key: &[u8],
) -> Result<Vec<u8>, MLSError> {
    let created_at = now_rfc3339_millis();
    build_pds_device_put_record_body_at(repo_did, device_id, mls_signature_public_key, &created_at)
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.device/{device_id}`
/// using a caller-supplied RFC 3339 millisecond timestamp (`created_at`).
pub fn build_pds_device_put_record_body_at(
    repo_did: &str,
    device_id: &str,
    mls_signature_public_key: &[u8],
    created_at: &str,
) -> Result<Vec<u8>, MLSError> {
    serde_json::to_vec(&json!({
        "repo": repo_did,
        "collection": "blue.catbird.chat.device",
        "rkey": device_id,
        "record": {
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(mls_signature_public_key) },
            "algorithm": "ed25519",
            "createdAt": created_at,
        }
    }))
    .map_err(|e| MLSError::Internal(format!("serialize blue.catbird.chat.device putRecord: {e}")))
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.declaration/self`.
pub fn build_pds_chat_declaration_put_record_body(
    repo_did: &str,
    delivery_service_did: &str,
) -> Result<Vec<u8>, MLSError> {
    let created_at = now_rfc3339_millis();
    build_pds_chat_declaration_put_record_body_at(repo_did, delivery_service_did, &created_at)
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.declaration/self`
/// using a caller-supplied RFC 3339 millisecond timestamp (`created_at`).
pub fn build_pds_chat_declaration_put_record_body_at(
    repo_did: &str,
    delivery_service_did: &str,
    created_at: &str,
) -> Result<Vec<u8>, MLSError> {
    serde_json::to_vec(&json!({
        "repo": repo_did,
        "collection": "blue.catbird.chat.declaration",
        "rkey": "self",
        "record": {
            "$type": "blue.catbird.chat.declaration",
            "allowIncoming": "all",
            "deliveryService": delivery_service_did,
            "protocolVersion": "2",
            "createdAt": created_at,
        }
    }))
    .map_err(|e| {
        MLSError::Internal(format!(
            "serialize blue.catbird.chat.declaration putRecord: {e}"
        ))
    })
}

/// Parse `com.atproto.repo.listRecords?collection=blue.catbird.chat.device` into `(device_id, pubkey_32)`.
pub fn parse_pds_device_list_records(
    did: &str,
    body_bytes: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, MLSError> {
    let val: Value = serde_json::from_slice(body_bytes)
        .map_err(|e| MLSError::Internal(format!("invalid listRecords JSON for `{did}`: {e}")))?;
    let Some(records) = val.get("records").and_then(|r| r.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for rec in records {
        let uri = rec.get("uri").and_then(|u| u.as_str()).unwrap_or("");
        let rkey = uri.rsplit('/').next().unwrap_or("").trim().to_string();
        if rkey.is_empty() {
            continue;
        }
        let Some(value) = rec.get("value") else {
            continue;
        };
        let alg = value
            .get("algorithm")
            .and_then(|a| a.as_str())
            .unwrap_or("ed25519");
        if !alg.eq_ignore_ascii_case("ed25519") {
            continue;
        }
        let Some(pk_val) = value.get("mlsSignaturePublicKey") else {
            continue;
        };
        if let Ok(pk_bytes) = json_bytes(pk_val) {
            if pk_bytes.len() == 32 {
                out.push((rkey, pk_bytes));
            }
        }
    }
    Ok(out)
}

/// Unwrap either `{ "didDoc": { ... } }` (`com.atproto.identity.resolveDid`) or a direct DID document.
pub fn extract_did_doc_from_resolve_response(body_bytes: &[u8]) -> Result<Vec<u8>, MLSError> {
    let val: Value = serde_json::from_slice(body_bytes)
        .map_err(|e| MLSError::Internal(format!("invalid DID document JSON: {e}")))?;
    if let Some(doc) = val.get("didDoc") {
        if doc.is_object() {
            return serde_json::to_vec(doc)
                .map_err(|e| MLSError::Internal(format!("re-serialize didDoc: {e}")));
        }
    }
    if val.get("id").and_then(|v| v.as_str()).is_some() {
        return Ok(body_bytes.to_vec());
    }
    Err(MLSError::Internal(
        "response did not contain a valid DID document".to_string(),
    ))
}

/// Extract `#atproto_pds` service endpoint URL from a DID document if present.
pub fn extract_pds_endpoint_from_did_doc(did_doc_bytes: &[u8]) -> Option<String> {
    let val: Value = serde_json::from_slice(did_doc_bytes).ok()?;
    let services = val.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let ty = svc.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if id.ends_with("#atproto_pds") || ty == "AtprotoPersonalDataServer" {
            if let Some(ep) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                let trimmed = ep.trim_end_matches('/').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }
    None
}

/// Derive a fallback `did:web:...` identifier from an HTTP(S) base URL when `/.well-known/did.json`
/// is not served (e.g. unit-test mock endpoints).
pub fn fallback_did_web_from_endpoint(endpoint: &str) -> String {
    let without_scheme = endpoint
        .trim()
        .strip_prefix("https://")
        .or_else(|| endpoint.trim().strip_prefix("http://"))
        .unwrap_or(endpoint.trim());
    let authority = without_scheme.split('/').next().unwrap_or("localhost");
    let encoded = authority.replace(':', "%3A");
    format!("did:web:{encoded}")
}

/// Decode a compressed P-256 SEC1 public key (`33` bytes) from a DID document's `verificationMethod`
/// matching `fragment_or_kid` (e.g. `#mls-receipt-1` or `{did}#mls-receipt-1`).
pub fn decode_p256_sec1_from_did_doc(
    did_doc_bytes: &[u8],
    expected_did: &str,
    fragment_or_kid: &str,
) -> Result<Vec<u8>, MLSError> {
    let doc: Value = serde_json::from_slice(did_doc_bytes)
        .map_err(|e| MLSError::Cryptography(format!("invalid DID document JSON: {e}")))?;
    if doc.get("id").and_then(|v| v.as_str()) != Some(expected_did) {
        return Err(MLSError::Cryptography(format!(
            "DID document id {:?} does not match expected `{expected_did}`",
            doc.get("id")
        )));
    }
    let fragment = if let Some((_, frag)) = fragment_or_kid.split_once('#') {
        format!("#{frag}")
    } else if fragment_or_kid.starts_with('#') {
        fragment_or_kid.to_string()
    } else {
        format!("#{fragment_or_kid}")
    };
    let full_id = format!("{expected_did}{fragment}");
    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MLSError::Cryptography("DID document missing verificationMethod".into()))?;
    for method in methods {
        let id = method.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id != full_id && id != fragment {
            continue;
        }
        if let Some(multibase_str) = method.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            let (_, raw) = multibase::decode(multibase_str).map_err(|e| {
                MLSError::Cryptography(format!("invalid publicKeyMultibase on `{id}`: {e}"))
            })?;
            // P-256 compressed multicodec prefix is `[0x80, 0x24]` + 33-byte SEC1 point.
            if raw.len() == 35 && raw[0] == 0x80 && raw[1] == 0x24 {
                return Ok(raw[2..].to_vec());
            }
            if raw.len() == 33 || raw.len() == 65 {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let pk = p256::PublicKey::from_sec1_bytes(&raw).map_err(|e| {
                    MLSError::Cryptography(format!("invalid P-256 SEC1 point on `{id}`: {e}"))
                })?;
                return Ok(pk.to_encoded_point(true).as_bytes().to_vec());
            }
            return Err(MLSError::Cryptography(format!(
                "unexpected multicodec key length {} on `{id}`",
                raw.len()
            )));
        }
        if let Some(jwk) = method.get("publicKeyJwk") {
            let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty != "EC" || crv != "P-256" {
                return Err(MLSError::Cryptography(format!(
                    "unsupported publicKeyJwk ({kty}/{crv}) on `{id}`"
                )));
            }
            let x_b64 = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MLSError::Cryptography(format!("JWK `{id}` missing x")))?;
            let y_b64 = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MLSError::Cryptography(format!("JWK `{id}` missing y")))?;
            let x = URL_SAFE_NO_PAD
                .decode(x_b64)
                .map_err(|e| MLSError::Cryptography(format!("JWK `{id}` invalid x: {e}")))?;
            let y = URL_SAFE_NO_PAD
                .decode(y_b64)
                .map_err(|e| MLSError::Cryptography(format!("JWK `{id}` invalid y: {e}")))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(MLSError::Cryptography(format!(
                    "JWK `{id}` P-256 x/y coordinates must be 32 bytes"
                )));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let pk = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| {
                MLSError::Cryptography(format!("JWK `{id}` invalid P-256 curve point: {e}"))
            })?;
            return Ok(pk.to_encoded_point(true).as_bytes().to_vec());
        }
        return Err(MLSError::Cryptography(format!(
            "verificationMethod `{id}` missing publicKeyMultibase and publicKeyJwk"
        )));
    }
    Err(MLSError::Cryptography(format!(
        "DID document for `{expected_did}` missing verificationMethod `{full_id}`"
    )))
}

/// Verify an `I13` ES256 `sequencerReceipt` wire JSON object against `{sequencer_did}#mls-receipt-1`
/// and return `(seq, generation, archived_receipt_json)` ready for `labyrinth::message::seal_sender_committed`.
#[allow(clippy::too_many_arguments)]
pub fn parse_and_verify_i13_sequencer_receipt(
    receipt_val: &Value,
    sec1_pubkey: &[u8],
    expected_sequencer_did: &str,
    expected_convo_id: &str,
    expected_group_id: &[u8],
    expected_epoch: u64,
    expected_entry_id: &str,
    expected_commitment: &[u8; 32],
) -> Result<(u64, u64, String), MLSError> {
    let conversation_id = receipt_val
        .get("conversationId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing conversationId".into()))?
        .to_string();
    let generation = receipt_val
        .get("generation")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let group_id = json_bytes(
        receipt_val
            .get("groupId")
            .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing groupId".into()))?,
    )?;
    let epoch = receipt_val
        .get("epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing epoch".into()))?;
    let entry_id = receipt_val
        .get("entryId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing entryId".into()))?
        .to_string();
    let seq = receipt_val
        .get("seq")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing seq".into()))?;
    let sender_did = receipt_val
        .get("senderDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing senderDid".into()))?;
    let sender_device_id = receipt_val
        .get("senderDeviceId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing senderDeviceId".into()))?;
    let commitment_vec = json_bytes(receipt_val.get("archiveCommitment").ok_or_else(|| {
        MLSError::Cryptography("sequencerReceipt missing archiveCommitment".into())
    })?)?;
    let archive_commitment: [u8; 32] = commitment_vec.as_slice().try_into().map_err(|_| {
        MLSError::Cryptography("sequencerReceipt archiveCommitment must be 32 bytes".into())
    })?;
    let issued_at_ms = receipt_val
        .get("issuedAtMs")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing issuedAtMs".into()))?;
    let sequencer_did = receipt_val
        .get("sequencerDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing sequencerDid".into()))?
        .to_string();
    let key_id = receipt_val
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing kid".into()))?
        .to_string();
    let sig_vec = json_bytes(
        receipt_val
            .get("signature")
            .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing signature".into()))?,
    )?;
    let signature: [u8; 64] = sig_vec.as_slice().try_into().map_err(|_| {
        MLSError::Cryptography("sequencerReceipt ES256 signature must be 64 bytes".into())
    })?;

    if conversation_id != expected_convo_id
        || group_id.as_slice() != expected_group_id
        || epoch != expected_epoch
        || entry_id != expected_entry_id
        || !bool::from(archive_commitment.ct_eq(expected_commitment))
    {
        return Err(MLSError::Cryptography(
            "I13 sequencerReceipt coordinates or archiveCommitment mismatch".to_string(),
        ));
    }

    let signed = labyrinth_protocol::receipt::SignedSequencerReceipt {
        payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
            sequencer_did,
            conversation_id,
            group_id,
            epoch,
            sender_device_did_url: format!("{sender_did}#{sender_device_id}"),
            entry_id,
            archive_commitment,
            seq,
            issued_at_ms,
        },
        key_id,
        signature,
    };

    labyrinth_protocol::receipt::verify_sequencer_receipt_sec1(
        sec1_pubkey,
        expected_sequencer_did,
        &signed,
    )
    .map_err(|e| MLSError::Cryptography(format!("I13 sequencerReceipt verify failed: {e}")))?;

    let stored = StoredArchivedReceipt {
        sequencer_did: signed.payload.sequencer_did,
        conversation_id: signed.payload.conversation_id,
        group_id: signed.payload.group_id,
        epoch: signed.payload.epoch,
        sender_device_did_url: signed.payload.sender_device_did_url,
        entry_id: signed.payload.entry_id,
        archive_commitment: signed.payload.archive_commitment.to_vec(),
        seq: signed.payload.seq,
        issued_at_ms: signed.payload.issued_at_ms,
        key_id: signed.key_id,
        signature: signed.signature.to_vec(),
        generation,
    };
    let archived_json = serde_json::to_string(&stored)
        .map_err(|e| MLSError::Internal(format!("serialize StoredArchivedReceipt JSON: {e}")))?;

    Ok((seq, generation, archived_json))
}

/// JSON-serializable persistence wrapper for a verified `I13` `ArchivedReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredArchivedReceipt {
    pub sequencer_did: String,
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_did_url: String,
    pub entry_id: String,
    pub archive_commitment: Vec<u8>,
    pub seq: u64,
    pub issued_at_ms: i64,
    pub key_id: String,
    pub signature: Vec<u8>,
    pub generation: u64,
}

impl StoredArchivedReceipt {
    #[cfg(feature = "labyrinth")]
    pub fn to_labyrinth_archived(&self) -> Result<labyrinth::message::ArchivedReceipt, MLSError> {
        let archive_commitment: [u8; 32] =
            self.archive_commitment.as_slice().try_into().map_err(|_| {
                MLSError::Internal("invalid stored archive_commitment length".into())
            })?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MLSError::Internal("invalid stored signature length".into()))?;
        Ok(labyrinth::message::ArchivedReceipt {
            signed: labyrinth_protocol::receipt::SignedSequencerReceipt {
                payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
                    sequencer_did: self.sequencer_did.clone(),
                    conversation_id: self.conversation_id.clone(),
                    group_id: self.group_id.clone(),
                    epoch: self.epoch,
                    sender_device_did_url: self.sender_device_did_url.clone(),
                    entry_id: self.entry_id.clone(),
                    archive_commitment,
                    seq: self.seq,
                    issued_at_ms: self.issued_at_ms,
                },
                key_id: self.key_id.clone(),
                signature,
            },
            generation: self.generation,
        })
    }
}

/// Extract `(group_context_hash_32, confirmation_tag_raw_32)` for an `MlsGroup`.
pub fn compute_group_context_hash_and_tag<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
) -> Result<([u8; 32], Vec<u8>), MLSError> {
    let context: GroupContext = provider
        .storage()
        .group_context(group.group_id())
        .map_err(|e| MLSError::OpenMLS(format!("load group_context: {e:?}")))?
        .ok_or(MLSError::StorageFailed)?;
    let context_bytes = context
        .tls_serialize_detached()
        .map_err(|e| MLSError::OpenMLS(format!("serialize group_context: {e:?}")))?;
    let gch: [u8; 32] = Sha256::digest(&context_bytes).into();
    let tag_tls = group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(|e| MLSError::OpenMLS(format!("serialize confirmation_tag: {e:?}")))?;
    let tag = if tag_tls.len() == 33 && tag_tls[0] == 32 {
        tag_tls[1..].to_vec()
    } else {
        tag_tls
    };
    Ok((gch, tag))
}

/// Extract a [`SpaceAvatarPointer`](crate::groups::metadata_v1::SpaceAvatarPointer) from a stored [`GroupMetadataRow`](crate::storage::GroupMetadataRow).
pub fn space_avatar_from_metadata_row(
    row: &crate::storage::GroupMetadataRow,
) -> Option<crate::groups::metadata_v1::SpaceAvatarPointer> {
    if let (Some(setter_did), Some(space_blob_cid), Some(sym_key), Some(sha256)) = (
        row.avatar_setter_did.as_ref(),
        row.avatar_blob_cid.as_ref(),
        row.avatar_sym_key.as_ref(),
        row.avatar_sha256.as_ref(),
    ) {
        return Some(crate::groups::metadata_v1::SpaceAvatarPointer {
            setter_did: setter_did.clone(),
            space_blob_cid: space_blob_cid.clone(),
            sym_key: sym_key.clone(),
            sha256: sha256.clone(),
            mime_type: row.avatar_mime_type.clone(),
        });
    }
    serde_json::from_str::<GroupMetadataV1>(&row.metadata_json)
        .ok()
        .and_then(|m| m.space_avatar)
}

/// Convert a decrypted [`GroupMetadataV1`] into a [`GroupMetadataRow`](crate::storage::GroupMetadataRow),
/// preserving all `SpaceAvatarPointer` columns (`1A`).
pub fn group_metadata_row_from_v1(
    conversation_id: &str,
    metadata_version: i64,
    epoch: i64,
    meta: &GroupMetadataV1,
    updated_at_ms: i64,
) -> Result<crate::storage::GroupMetadataRow, MLSError> {
    let avatar = meta.space_avatar.as_ref();
    Ok(crate::storage::GroupMetadataRow {
        conversation_id: conversation_id.to_string(),
        metadata_version,
        epoch,
        title: (!meta.title.is_empty()).then(|| meta.title.clone()),
        description: (!meta.description.is_empty()).then(|| meta.description.clone()),
        avatar_setter_did: avatar.map(|a| a.setter_did.clone()),
        avatar_blob_cid: avatar.map(|a| a.space_blob_cid.clone()),
        avatar_sym_key: avatar.map(|a| a.sym_key.clone()),
        avatar_sha256: avatar.map(|a| a.sha256.clone()),
        avatar_mime_type: avatar
            .and_then(|a| a.mime_type.clone())
            .or_else(|| meta.avatar_content_type.clone()),
        metadata_json: serde_json::to_string(meta)
            .map_err(|e| MLSError::Internal(e.to_string()))?,
        updated_at_ms,
    })
}

/// Build an encrypted `metadataSnapshot` JSON object for `creationBody`, `metadataTransitionBody`,
/// `commitTransitionBody`, or `leafRecoveryFulfillmentBody`.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_metadata_snapshot_json(
    metadata_key: &[u8; 32],
    group_id: &[u8],
    convo_uuid: &uuid::Uuid,
    generation: i64,
    target_epoch: u64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: &str,
    metadata_version: u64,
    origin_seq: u64,
    actor_did: &str,
    actor_device_id: &str,
    auth_generation: i64,
    public_key: &[u8],
    title: &str,
    description: &str,
    space_avatar: Option<crate::groups::metadata_v1::SpaceAvatarPointer>,
) -> Result<Value, MLSError> {
    let nonce: [u8; 12] = rand::random();
    build_encrypted_metadata_snapshot_json_with_nonce(
        metadata_key,
        group_id,
        convo_uuid,
        generation,
        target_epoch,
        group_context_hash,
        confirmation_tag,
        transition_id,
        metadata_version,
        origin_seq,
        actor_did,
        actor_device_id,
        auth_generation,
        public_key,
        title,
        description,
        space_avatar,
        nonce,
    )
}

/// Build an encrypted `metadataSnapshot` JSON object using an explicit 12-byte AEAD `nonce`.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_metadata_snapshot_json_with_nonce(
    metadata_key: &[u8; 32],
    group_id: &[u8],
    convo_uuid: &uuid::Uuid,
    generation: i64,
    target_epoch: u64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: &str,
    metadata_version: u64,
    origin_seq: u64,
    actor_did: &str,
    actor_device_id: &str,
    auth_generation: i64,
    public_key: &[u8],
    title: &str,
    description: &str,
    space_avatar: Option<crate::groups::metadata_v1::SpaceAvatarPointer>,
    nonce: [u8; 12],
) -> Result<Value, MLSError> {
    let payload = GroupMetadataV1 {
        version: 1,
        title: title.to_string(),
        description: description.to_string(),
        avatar_blob_locator: None,
        avatar_content_type: space_avatar.as_ref().and_then(|a| a.mime_type.clone()),
        space_avatar,
    };
    let ciphertext = encrypt_metadata_snapshot_with_nonce(
        metadata_key,
        group_id,
        target_epoch,
        metadata_version,
        &nonce,
        &payload,
    )?;
    let key_id = derive_key_id(public_key);
    Ok(json!({
        "authorProof": {
            "authGenerationAtOrigin": auth_generation,
            "authorDeviceId": actor_device_id,
            "authorDid": actor_did,
            "authorKeyId": key_id,
            "deviceStatusAtOrigin": "active",
            "originSeq": origin_seq,
            "originTransitionId": transition_id,
            "roleAtOrigin": "admin",
            "signaturePublicKey": { "$bytes": STANDARD.encode(public_key) }
        },
        "ciphertext": { "$bytes": STANDARD.encode(&ciphertext) },
        "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
        "ciphertextSize": ciphertext.len(),
        "coordinate": {
            "confirmationTag": { "$bytes": STANDARD.encode(confirmation_tag) },
            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
            "epoch": target_epoch,
            "generation": generation,
            "groupContextHash": { "$bytes": STANDARD.encode(group_context_hash) },
            "groupId": { "$bytes": STANDARD.encode(group_id) }
        },
        "metadataVersion": metadata_version,
        "nonce": { "$bytes": STANDARD.encode(nonce) },
        "originTransitionId": transition_id
    }))
}

/// Try decrypting a server `metadataSnapshot` JSON object at the current `MlsGroup` epoch.
pub fn try_decrypt_group_metadata_snapshot<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    snapshot_json: &Value,
) -> Option<(i64, i64, GroupMetadataV1)> {
    let coord = snapshot_json.get("coordinate")?;
    let snap_epoch = coord.get("epoch")?.as_u64()?;
    if group.epoch().as_u64() != snap_epoch {
        return None;
    }
    let metadata_version = snapshot_json.get("metadataVersion")?.as_u64()?;
    let nonce_vec = json_bytes(snapshot_json.get("nonce")?).ok()?;
    let nonce_12: [u8; 12] = nonce_vec.as_slice().try_into().ok()?;
    let ciphertext = json_bytes(snapshot_json.get("ciphertext")?).ok()?;
    let group_id = group.group_id().as_slice().to_vec();
    let meta_key = derive_metadata_key_from_group(
        group,
        provider.crypto(),
        provider.storage(),
        &group_id,
        snap_epoch,
    )
    .ok()?;
    let meta = decrypt_metadata_snapshot(
        &meta_key,
        &group_id,
        snap_epoch,
        metadata_version,
        &nonce_12,
        &ciphertext,
    )
    .ok()?;
    Some((snap_epoch as i64, metadata_version as i64, meta))
}

/// Sign a canonical `blue.catbird.chat.*` request body using `prepare_signed_request_with_signer`.
pub fn sign_clean_chat_mutation(
    actor_did: &str,
    device_id: &str,
    auth_generation: Option<i64>,
    operation: CanonicalOperation,
    body_value: &Value,
    signer: &SignatureKeyPair,
) -> Result<PreparedRequest, MLSError> {
    let binding = CleanChatSigningContext {
        actor_did: actor_did.to_string(),
        device_id: device_id.to_string(),
        auth_generation,
    };
    let raw_body = serde_json::to_vec(body_value)
        .map_err(|e| MLSError::Internal(format!("serialize signed body JSON: {e}")))?;
    crate::orchestrator::canonical_transport::prepare_signed_request_with_signer(
        &binding, operation, raw_body, signer,
    )
    .map_err(|e| {
        MLSError::Cryptography(format!(
            "prepare_signed_request_with_signer({operation:?}): {e}"
        ))
    })
}

/// Sign a `C33` direct-request body (`Prepare`, `Publish`, `Accept`, `Cancel`, `Keys`) and return
/// the signed wrapper JSON bytes (`{"body": ..., "signature": "..."}`).
pub fn sign_direct_request_wrapper(
    kind: DirectRequestKind,
    body_value: Value,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, MLSError> {
    let raw_body = serde_json::to_vec(&body_value)
        .map_err(|e| MLSError::Internal(format!("serialize direct-request body: {e}")))?;
    let signing_bytes =
        dr_transcript::direct_request_signing_bytes(kind, &raw_body).map_err(|e| {
            MLSError::Cryptography(format!("direct_request_signing_bytes({kind:?}): {e}"))
        })?;
    let signature = signer
        .sign(&signing_bytes)
        .map_err(|e| MLSError::Cryptography(format!("sign direct-request ({kind:?}): {e:?}")))?;
    let wrapper = serde_json::to_vec(&json!({
        "body": body_value,
        "signature": STANDARD.encode(&signature),
    }))
    .map_err(|e| MLSError::Internal(format!("serialize direct-request wrapper: {e}")))?;
    dr_transcript::verify_signed_request(kind, &wrapper, signer.public()).map_err(|e| {
        MLSError::Cryptography(format!("verify self-signed direct-request ({kind:?}): {e}"))
    })?;
    Ok(wrapper)
}

/// Normalize a JSON coordinate object so `$bytes` fields are consistently formatted for canonical
/// mutations (`prior` / `next` in `submitTransition` and `sendMessage`).
pub fn canonicalize_wire_coordinate(
    coord: &Value,
    convo_id_override: Option<&str>,
) -> Result<Value, MLSError> {
    let gch = json_bytes(
        coord
            .get("groupContextHash")
            .ok_or_else(|| MLSError::invalid_input("coordinate missing groupContextHash"))?,
    )?;
    let tag = json_bytes(
        coord
            .get("confirmationTag")
            .ok_or_else(|| MLSError::invalid_input("coordinate missing confirmationTag"))?,
    )?;
    let gid = json_bytes(
        coord
            .get("groupId")
            .ok_or_else(|| MLSError::invalid_input("coordinate missing groupId"))?,
    )?;
    let convo_id = convo_id_override
        .or_else(|| coord.get("conversationId").and_then(|v| v.as_str()))
        .ok_or_else(|| MLSError::invalid_input("coordinate missing conversationId"))?;
    let epoch = coord
        .get("epoch")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| MLSError::invalid_input("coordinate missing epoch"))?;
    let generation = coord
        .get("generation")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let state_version = coord
        .get("stateVersion")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let lifecycle = coord
        .get("lifecycle")
        .and_then(|v| v.as_str())
        .unwrap_or("active");
    Ok(json!({
        "confirmationTag": { "$bytes": STANDARD.encode(tag) },
        "conversationId": convo_id,
        "epoch": epoch,
        "generation": generation,
        "groupContextHash": { "$bytes": STANDARD.encode(gch) },
        "groupId": { "$bytes": STANDARD.encode(gid) },
        "lifecycle": lifecycle,
        "stateVersion": state_version,
    }))
}

/// Build the `aad.prior` coordinate object (with base64-encoded 16-byte UUID `conversationId`)
/// required inside `commitAad` and `applicationAad`.
pub fn build_aad_prior_coordinate(
    convo_uuid: &uuid::Uuid,
    group_id: &[u8],
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
) -> Value {
    json!({
        "confirmationTag": { "$bytes": STANDARD.encode(confirmation_tag) },
        "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
        "epoch": epoch,
        "generation": generation,
        "groupContextHash": { "$bytes": STANDARD.encode(group_context_hash) },
        "groupId": { "$bytes": STANDARD.encode(group_id) },
        "lifecycle": "active",
        "stateVersion": state_version,
    })
}

/// Extract unique participant `did:...` roots from a JSON value tree so `I4` PDS device keys
/// can be prefetched outside SQLite `write_tx` without contacting peer DS authorities (`D1`).
pub fn collect_dids_from_json(val: &Value, out: &mut BTreeMap<String, ()>) {
    match val {
        Value::String(s) => {
            if s.contains("#mls-receipt") || s.contains("#atproto_mls") {
                return;
            }
            let root = s.split('#').next().unwrap_or("").trim();
            if root.starts_with("did:plc:") || root.starts_with("did:web:") {
                out.insert(root.to_string(), ());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_dids_from_json(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                if matches!(
                    k.as_str(),
                    "sequencerReceipt"
                        | "sequencerDid"
                        | "authorityDid"
                        | "serviceDid"
                        | "coordinatorDid"
                        | "deliveryService"
                        | "homeDsDid"
                        | "recipientServiceDid"
                        | "senderServiceDid"
                        | "kid"
                        | "receiptKeyId"
                ) {
                    continue;
                }
                collect_dids_from_json(v, out);
            }
        }
        _ => {}
    }
}

/// Parse `<did>#<device_id>` (or `<did>`) from MLS `BasicCredential` bytes.
pub fn parse_scoped_credential_did_device(
    identity_bytes: &[u8],
) -> Result<(String, String), MLSError> {
    let raw = std::str::from_utf8(identity_bytes).map_err(|_| {
        MLSError::Cryptography("I4: MLS leaf credential is not valid UTF-8".to_string())
    })?;
    let trimmed = raw.trim();
    let (did, device_id) = match trimmed.split_once('#') {
        Some((d, dev)) => (d.trim(), dev.trim()),
        None => (trimmed, ""),
    };
    if !(did.starts_with("did:plc:") || did.starts_with("did:web:")) {
        return Err(MLSError::Cryptography(format!(
            "I4: invalid DID `{did}` in MLS leaf credential"
        )));
    }
    Ok((did.to_string(), device_id.to_string()))
}

/// Universal (native + WASM) `I4` verifier over `(did -> Vec<(device_id, pubkey_32)>)`.
pub fn verify_leaf_pds_map_i4(
    identity_bytes: &[u8],
    signature_key: &[u8],
    authorized_by_did: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
) -> Result<(String, String), MLSError> {
    let (root_did, device_id) = parse_scoped_credential_did_device(identity_bytes)?;
    let Some(pairs) = authorized_by_did.get(&root_did) else {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: no verified ATProto device keys found for sender DID `{root_did}`"
        )));
    };
    let matched = pairs.iter().any(|(dev_id, pk)| {
        pk.as_slice() == signature_key
            && (device_id.is_empty() || dev_id.is_empty() || dev_id == &device_id)
    });
    if !matched {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: unverified MLS leaf signature key for `{root_did}#{device_id}`"
        )));
    }
    Ok((root_did, device_id))
}

/// Universal (native + WASM) `I4` verifier for a `StagedCommit`, checking the Commit sender leaf,
/// all `AddProposal` leaves, and all `UpdateProposal` leaves against PDS `blue.catbird.chat.device` keys.
pub fn verify_staged_commit_pds_map_i4(
    group: &openmls::prelude::MlsGroup,
    sender: &openmls::prelude::Sender,
    staged: &openmls::prelude::StagedCommit,
    authorized_by_did: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
) -> Result<(), MLSError> {
    if let openmls::prelude::Sender::Member(leaf_idx) = sender {
        let sender_member = group
            .members()
            .find(|m| m.index == *leaf_idx)
            .ok_or_else(|| {
                MLSError::insufficient_permissions("I4/F-02: Commit sender leaf missing from group")
            })?;
        verify_leaf_pds_map_i4(
            sender_member.credential.serialized_content(),
            &sender_member.signature_key,
            authorized_by_did,
        )?;
    } else {
        return Err(MLSError::insufficient_permissions(
            "I4/F-02: external/non-member Commit rejected",
        ));
    }

    for queued in staged.add_proposals() {
        let ln = queued.add_proposal().key_package().leaf_node();
        verify_leaf_pds_map_i4(
            ln.credential().serialized_content(),
            ln.signature_key().as_slice(),
            authorized_by_did,
        )?;
    }

    for queued in staged.update_proposals() {
        let ln = queued.update_proposal().leaf_node();
        let new_id = ln.credential().serialized_content();
        if let openmls::prelude::Sender::Member(leaf_idx) = queued.sender() {
            let old_member = group
                .members()
                .find(|m| m.index == *leaf_idx)
                .ok_or(MLSError::InvalidCommit)?;
            if old_member.credential.serialized_content() != new_id {
                return Err(MLSError::InvalidCommit);
            }
        } else {
            return Err(MLSError::InvalidCommit);
        }
        verify_leaf_pds_map_i4(new_id, ln.signature_key().as_slice(), authorized_by_did)?;
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_leaf_slice_i4(
    identity_bytes: &[u8],
    signature_key: &[u8],
    keys: &[crate::push::AuthorizedPeerDeviceKey],
) -> Result<(String, String), MLSError> {
    let mut map: std::collections::HashMap<String, Vec<crate::push::AuthorizedPeerDeviceKey>> =
        std::collections::HashMap::new();
    for k in keys {
        map.entry(k.did.clone()).or_default().push(k.clone());
    }
    crate::push::verify_leaf_binding_i4(identity_bytes, signature_key, None, &map)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_staged_commit_slice_i4(
    group: &openmls::prelude::MlsGroup,
    sender: &openmls::prelude::Sender,
    staged: &openmls::prelude::StagedCommit,
    keys: &[crate::push::AuthorizedPeerDeviceKey],
) -> Result<(), MLSError> {
    let mut map: std::collections::HashMap<String, Vec<crate::push::AuthorizedPeerDeviceKey>> =
        std::collections::HashMap::new();
    for k in keys {
        map.entry(k.did.clone()).or_default().push(k.clone());
    }
    crate::push::verify_staged_commit_i4(group, sender, staged, None, &map)
}

/// Normalize plaintext JSON to canonical `MLSMessagePayload` JSON for Labyrinth archival.
pub fn canonical_labyrinth_frame_json(plaintext_json: &str) -> String {
    if serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(plaintext_json).is_ok() {
        return plaintext_json.to_string();
    }
    if let Ok(val) = serde_json::from_str::<Value>(plaintext_json) {
        if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
            if let Ok(encoded) =
                serde_json::to_string(&crate::orchestrator::MLSMessagePayload::text(text))
            {
                return encoded;
            }
        }
    }
    plaintext_json.to_string()
}

fn deterministic_tid_wire(timestamp_ms: i64, sub_seq: u64, discriminator: &str) -> String {
    const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let micros = (timestamp_ms.max(0) as u64)
        .saturating_mul(1_000)
        .saturating_add(sub_seq)
        & ((1u64 << 53) - 1);
    let digest = Sha256::digest(discriminator.as_bytes());
    let clock_id = (u16::from_be_bytes([digest[0], digest[1]]) as u64) & 0x3ff;
    let v = (micros << 10) | clock_id;
    (0..13)
        .rev()
        .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
        .collect()
}

/// Build `(convo_space_uri, apply_writes_json_bytes)` for `com.atproto.space.applyWrites`
/// using `labyrinth::message::seal_sender_committed` when a verified `sequencer_receipt_json`
/// and 32-byte `frame_nonce_b64` are present (`I13`, `D4`).
#[cfg(feature = "labyrinth")]
pub fn build_space_apply_writes_for_queue_payload(
    payload: &crate::client::QueuedLabyrinthArchivePayload,
    mek_secret_32: [u8; 32],
    signer: &SignatureKeyPair,
) -> Result<(String, Vec<u8>), MLSError> {
    use zeroize::Zeroizing;

    struct WireTransportSigner<'a>(&'a SignatureKeyPair, [u8; 32]);
    impl labyrinth::sign::TransportSigner for WireTransportSigner<'_> {
        fn transport_public_key(&self) -> [u8; 32] {
            self.1
        }
        fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
            let sig = self.0.sign(msg).unwrap_or_else(|_| vec![0u8; 64]);
            <[u8; 64]>::try_from(sig.as_slice()).unwrap_or([0u8; 64])
        }
    }

    let pub_key_32: [u8; 32] = signer
        .public()
        .try_into()
        .map_err(|_| MLSError::Cryptography("device signer pubkey must be 32 bytes".to_string()))?;
    let transport_signer = WireTransportSigner(signer, pub_key_32);

    let head = Sha256::digest(format!("catbird.convo.mek:{}", payload.conversation_id).as_bytes());
    let mut head_arr = [0u8; 32];
    head_arr.copy_from_slice(&head);
    let r_hash = labyrinth::mek::roster_hash(&[head_arr]);
    let mek = labyrinth::mek::Mek::from_secret(
        Zeroizing::new(mek_secret_32),
        r_hash,
        labyrinth::mek::MekProvenance::Transport {
            transport_pub: pub_key_32,
            created_here: true,
        },
    );

    let ts_ms = payload.created_at_ms.max(0) as u64;
    let decoded_nonce_32: Option<[u8; 32]> = payload
        .frame_nonce_b64
        .as_ref()
        .and_then(|b| STANDARD.decode(b.as_bytes()).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());
    let item_seq_u64 = payload.seq.max(0) as u64;
    let item_sub_seq = item_seq_u64 % 1_000;

    let sealed_msg = if let (Some(nonce_32), Some(ref receipt_json)) =
        (decoded_nonce_32, &payload.sequencer_receipt_json)
    {
        let stored_receipt: StoredArchivedReceipt = serde_json::from_str(receipt_json)
            .map_err(|e| MLSError::Internal(format!("parse StoredArchivedReceipt JSON: {e}")))?;
        let archived = stored_receipt.to_labyrinth_archived()?;
        labyrinth::message::seal_sender_committed(
            &mek,
            &payload.conversation_id,
            &payload.message_id,
            ts_ms,
            &nonce_32,
            payload.labyrinth_frame_json.as_bytes(),
            &archived,
            &transport_signer,
        )
        .map_err(|e| MLSError::Cryptography(format!("seal_sender_committed: {e}")))?
    } else {
        let sender_data: Zeroizing<Vec<u8>> = if let Some(nonce_32) = decoded_nonce_32 {
            let mut combined = Vec::with_capacity(32 + payload.labyrinth_frame_json.len());
            combined.extend_from_slice(&nonce_32);
            combined.extend_from_slice(payload.labyrinth_frame_json.as_bytes());
            Zeroizing::new(combined)
        } else {
            Zeroizing::new(payload.labyrinth_frame_json.as_bytes().to_vec())
        };
        let mut s = labyrinth::message::seal_sender(
            &mek,
            &payload.conversation_id,
            &payload.message_id,
            ts_ms,
            &sender_data,
            &transport_signer,
        )
        .map_err(|e| MLSError::Cryptography(format!("seal_sender: {e}")))?;
        s.seq = Some(item_seq_u64);
        s
    };

    let sender_batch = labyrinth::records::Batch::from_messages(
        &payload.conversation_id,
        &[sealed_msg],
        labyrinth::records::datetime_from_ms(ts_ms),
    )
    .map_err(|e| MLSError::Internal(format!("Batch::from_messages: {e}")))?;
    let batch_val = serde_json::to_value(&sender_batch)
        .map_err(|e| MLSError::Internal(format!("serialize Batch: {e}")))?;
    let tid = deterministic_tid_wire(
        payload.created_at_ms,
        item_sub_seq,
        &format!("batch:{}:{}", payload.conversation_id, payload.message_id),
    );
    let rkey = format!("{item_seq_u64:016x}-{tid}");
    let convo_space = payload.space_uri.clone().unwrap_or_else(|| {
        format!(
            "at://{}/space/blue.catbird.labyrinth.conversation/{}-0",
            payload.sequencer_did, payload.conversation_id
        )
    });
    let apply_body = serde_json::to_vec(&json!({
        "repo": convo_space,
        "writes": [{
            "$type": "com.atproto.space.applyWrites#create",
            "collection": labyrinth::records::nsid::BATCH,
            "rkey": rkey,
            "value": batch_val,
        }],
    }))
    .map_err(|e| MLSError::Internal(format!("serialize applyWrites JSON: {e}")))?;
    Ok((convo_space, apply_body))
}
