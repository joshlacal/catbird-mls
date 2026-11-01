//! Inbound MLS message verification (`I13` `archive_commitment` AAD) and `accountDeleted`
//! local database purge (`Spec §5 I13`).

use labyrinth_protocol::limits::{ARCHIVE_COMMITMENT_LEN, FRAME_NONCE_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::MLSError;

/// Domain-separation prefix for deterministic frame commitments when no separate nonce is supplied.
pub const ARCHIVE_COMMITMENT_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-ARCHIVE-COMMITMENT-V1\0";

/// OpenMLS `PrivateMessage` AAD envelope (`Spec §5 I13`):
/// carries **only** `archive_commitment = HMAC-SHA256(frame_nonce, canonical_payload_bytes)`
/// (never `frame_nonce` itself, which stays encrypted inside the `PrivateMessage` ciphertext
/// so `archive_commitment` remains cryptographically hiding to `mls-ds`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMessageAadEnvelope {
    pub version: u8,
    pub archive_commitment: [u8; ARCHIVE_COMMITMENT_LEN],
}

impl PrivateMessageAadEnvelope {
    pub fn for_payload(
        frame_nonce: &[u8; FRAME_NONCE_LEN],
        canonical_payload_bytes: &[u8],
    ) -> Self {
        Self {
            version: 1,
            archive_commitment: labyrinth_protocol::receipt::compute_archive_commitment(
                frame_nonce,
                canonical_payload_bytes,
            ),
        }
    }

    pub fn to_aad_bytes(&self) -> Result<Vec<u8>, MLSError> {
        serde_json::to_vec(self)
            .map_err(|e| MLSError::Internal(format!("serialize PrivateMessageAadEnvelope: {e}")))
    }

    pub fn from_aad_bytes(aad: &[u8]) -> Result<Self, MLSError> {
        let env: Self = serde_json::from_slice(aad).map_err(|e| {
            MLSError::Cryptography(format!("invalid I13 PrivateMessage AAD JSON: {e}"))
        })?;
        if env.version != 1 {
            return Err(MLSError::Cryptography(format!(
                "unsupported I13 PrivateMessage AAD version: {}",
                env.version
            )));
        }
        Ok(env)
    }

    pub fn verify_payload(
        &self,
        frame_nonce: &[u8; FRAME_NONCE_LEN],
        canonical_payload_bytes: &[u8],
    ) -> Result<(), MLSError> {
        let actual = labyrinth_protocol::receipt::compute_archive_commitment(
            frame_nonce,
            canonical_payload_bytes,
        );
        if bool::from(actual.ct_eq(&self.archive_commitment)) {
            Ok(())
        } else {
            Err(MLSError::Cryptography(
                "I13 PrivateMessage AAD archive_commitment mismatch".to_string(),
            ))
        }
    }
}

/// Encrypted inner payload envelope carrying the secret 32-byte `frame_nonce` alongside
/// `canonical_payload_bytes` inside OpenMLS `PrivateMessage` ciphertext (`Spec §5 I13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMessagePlaintextEnvelope {
    pub frame_nonce: [u8; FRAME_NONCE_LEN],
    pub canonical_payload_bytes: Vec<u8>,
}

impl PrivateMessagePlaintextEnvelope {
    pub fn seal_with_aad(
        frame_nonce: [u8; FRAME_NONCE_LEN],
        canonical_payload_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
        let aad = PrivateMessageAadEnvelope::for_payload(&frame_nonce, &canonical_payload_bytes)
            .to_aad_bytes()?;
        let inner = Self {
            frame_nonce,
            canonical_payload_bytes,
        };
        let plaintext = serde_json::to_vec(&inner).map_err(|e| {
            MLSError::Internal(format!("serialize PrivateMessagePlaintextEnvelope: {e}"))
        })?;
        Ok((plaintext, aad))
    }
}

/// Compute the 32-byte `I13` `archive_commitment` binding `(conversation_id, group_id,
/// message_id, plaintext_bytes, created_at_ms)` for local metadata commitment checks.
pub fn compute_archive_commitment(
    conversation_id: &str,
    group_id: &[u8],
    message_id: &str,
    plaintext_bytes: &[u8],
    created_at_ms: i64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ARCHIVE_COMMITMENT_DOMAIN);
    h.update((conversation_id.len() as u32).to_be_bytes());
    h.update(conversation_id.as_bytes());
    h.update((group_id.len() as u32).to_be_bytes());
    h.update(group_id);
    h.update((message_id.len() as u32).to_be_bytes());
    h.update(message_id.as_bytes());
    h.update((plaintext_bytes.len() as u32).to_be_bytes());
    h.update(plaintext_bytes);
    h.update(created_at_ms.to_be_bytes());
    h.finalize().into()
}

/// Constant-time verification of an archived message frame against its `I13` `archive_commitment`.
pub fn verify_archive_commitment(
    expected_commitment: &[u8; 32],
    conversation_id: &str,
    group_id: &[u8],
    message_id: &str,
    plaintext_bytes: &[u8],
    created_at_ms: i64,
) -> Result<(), MLSError> {
    let actual = compute_archive_commitment(
        conversation_id,
        group_id,
        message_id,
        plaintext_bytes,
        created_at_ms,
    );
    if bool::from(actual.ct_eq(expected_commitment)) {
        Ok(())
    } else {
        Err(MLSError::Cryptography(format!(
            "I13 archive_commitment mismatch for message {message_id} in conversation {conversation_id}"
        )))
    }
}

/// Parse a canonical message body (`{"text":...}` / `{"content":...}` or raw UTF-8) into
/// `(display_body, canonical_json_string)`.
pub fn parse_canonical_message_body(payload_bytes: &[u8]) -> Result<(String, String), MLSError> {
    let raw_str = std::str::from_utf8(payload_bytes)
        .map_err(|e| MLSError::invalid_input(format!("message payload is not UTF-8: {e}")))?;
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_str) {
        if let Some(text) = val
            .get("text")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("content").and_then(|v| v.as_str()))
        {
            return Ok((text.to_string(), raw_str.to_string()));
        }
    }
    let wrapped_json = serde_json::json!({ "text": raw_str }).to_string();
    Ok((raw_str.to_string(), wrapped_json))
}

struct CborBytesVisitor;

impl<'de> serde::de::Visitor<'de> for CborBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a CBOR byte string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v)
    }
}

#[derive(Debug, Clone)]
struct CborByteVec(Vec<u8>);

impl<'de> Deserialize<'de> for CborByteVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(CborBytesVisitor).map(Self)
    }
}

#[derive(Deserialize)]
struct CanonicalApplicationAadMap {
    #[serde(rename = "archiveCommitment", default)]
    archive_commitment: Option<CborByteVec>,
}

const CANONICAL_APP_AAD_PREFIX: &[u8] = b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0";
const DIRECT_REQUEST_APP_AAD_PREFIX: &[u8] = b"CATBIRD-DIRECT-REQUEST-APPLICATION-AAD\0";

/// Extract `(body, canonical_json, verified_archive_commitment)` from an OpenMLS
/// `ApplicationMessage` plaintext and its `PrivateMessage` AAD (`Spec §5 I13`, `C33`).
pub fn extract_plaintext_body_and_verify_aad(
    decrypted_bytes: &[u8],
    aad_bytes: &[u8],
) -> Result<(String, String, Option<[u8; 32]>), MLSError> {
    if let Some(cbor_aad) = aad_bytes.strip_prefix(CANONICAL_APP_AAD_PREFIX) {
        let parsed_aad: CanonicalApplicationAadMap = serde_ipld_dagcbor::from_slice(cbor_aad)
            .map_err(|e| {
                MLSError::Cryptography(format!("invalid canonical applicationAad CBOR: {e}"))
            })?;
        let expected_commitment: Option<[u8; ARCHIVE_COMMITMENT_LEN]> = match parsed_aad
            .archive_commitment
        {
            Some(CborByteVec(raw)) => Some(raw.as_slice().try_into().map_err(|_| {
                MLSError::Cryptography(
                    "I13 canonical applicationAad archiveCommitment must be 32 bytes".to_string(),
                )
            })?),
            None => None,
        };

        if let Ok(inner) =
            serde_json::from_slice::<PrivateMessagePlaintextEnvelope>(decrypted_bytes)
        {
            let verified = if let Some(expected) = expected_commitment {
                let actual = labyrinth_protocol::receipt::compute_archive_commitment(
                    &inner.frame_nonce,
                    &inner.canonical_payload_bytes,
                );
                if !bool::from(actual.ct_eq(&expected)) {
                    return Err(MLSError::Cryptography(
                        "I13 canonical applicationAad archiveCommitment mismatch".to_string(),
                    ));
                }
                Some(expected)
            } else {
                Some(labyrinth_protocol::receipt::compute_archive_commitment(
                    &inner.frame_nonce,
                    &inner.canonical_payload_bytes,
                ))
            };
            let (body, json_str) = parse_canonical_message_body(&inner.canonical_payload_bytes)?;
            return Ok((body, json_str, verified));
        }

        if expected_commitment.is_some() {
            return Err(MLSError::Cryptography(
                "I13: canonical applicationAad with archiveCommitment requires PrivateMessagePlaintextEnvelope"
                    .to_string(),
            ));
        }

        if let Ok(cbor_val) = serde_ipld_dagcbor::from_slice::<serde_json::Value>(decrypted_bytes) {
            if let Some(text) = cbor_val
                .get("text")
                .and_then(|v| v.as_str())
                .or_else(|| cbor_val.get("content").and_then(|v| v.as_str()))
            {
                let json_str = serde_json::to_string(&cbor_val)
                    .unwrap_or_else(|_| serde_json::json!({ "text": text }).to_string());
                return Ok((text.to_string(), json_str, None));
            }
        }
        let (body, json_str) = parse_canonical_message_body(decrypted_bytes)?;
        return Ok((body, json_str, None));
    }

    if aad_bytes.starts_with(DIRECT_REQUEST_APP_AAD_PREFIX) {
        let intro_val =
            crate::chat_v2::transcript::direct_request::decode_direct_request_introduction(
                decrypted_bytes,
            )
            .map_err(|e| MLSError::Cryptography(format!("invalid C33 introduction CBOR: {e}")))?;
        let text = intro_val
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::invalid_input("C33 introduction missing text"))?
            .to_string();
        let json_str = serde_json::to_string(&intro_val)
            .map_err(|e| MLSError::Internal(format!("serialize C33 introduction JSON: {e}")))?;
        return Ok((text, json_str, None));
    }

    // Support both PrivateMessagePlaintextEnvelope (carrying secret 32-byte frame_nonce)
    // and direct JSON/UTF-8 payloads when AAD is empty.
    if let Ok(inner) = serde_json::from_slice::<PrivateMessagePlaintextEnvelope>(decrypted_bytes) {
        let commitment = if !aad_bytes.is_empty() {
            let aad_env = PrivateMessageAadEnvelope::from_aad_bytes(aad_bytes)?;
            aad_env.verify_payload(&inner.frame_nonce, &inner.canonical_payload_bytes)?;
            Some(aad_env.archive_commitment)
        } else {
            None
        };
        let (body, json_str) = parse_canonical_message_body(&inner.canonical_payload_bytes)?;
        return Ok((body, json_str, commitment));
    }

    if !aad_bytes.is_empty() {
        return Err(MLSError::Cryptography(
            "I13: non-empty PrivateMessage AAD requires PrivateMessagePlaintextEnvelope with frame_nonce"
                .to_string(),
        ));
    }

    let (body, json_str) = parse_canonical_message_body(decrypted_bytes)?;
    Ok((body, json_str, None))
}

/// Purge all locally stored messages authored by `deleted_did` across `<did_hash>.db`
/// upon observing a sequenced `accountDeleted` entry (`Spec §5 I13`).
#[cfg(not(target_arch = "wasm32"))]
pub fn handle_account_deleted_event(
    db: &crate::storage::MlsAccountDb,
    deleted_did: &str,
) -> Result<usize, MLSError> {
    if deleted_did.trim().is_empty() {
        return Err(MLSError::invalid_input("deleted_did must not be empty"));
    }
    db.write_tx(|tx| tx.purge_messages_from_sender(None, deleted_did))
}
