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

/// Original sender device signature retained in both the encrypted MLS body
/// and its authenticated application AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginalSenderArchiveAttestationEnvelope {
    pub sender_did: String,
    pub sender_device_id: String,
    pub sender_transport_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl OriginalSenderArchiveAttestationEnvelope {
    pub fn verify(
        &self,
        thread_id: &str,
        message_id: &str,
        archive_commitment: &[u8; 32],
    ) -> Result<(), MLSError> {
        let public: [u8; 32] = self
            .sender_transport_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                MLSError::Cryptography("original sender archive public key must be 32 bytes".into())
            })?;
        let signature: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            MLSError::Cryptography("original sender archive signature must be 64 bytes".into())
        })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public).map_err(|_| {
            MLSError::Cryptography("invalid original sender archive public key".into())
        })?;
        let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
            thread_id,
            message_id,
            archive_commitment,
        );
        key.verify_strict(
            &transcript,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| MLSError::Cryptography("invalid original sender archive attestation".into()))
    }

    pub fn to_aad_json(&self) -> serde_json::Value {
        use base64::Engine as _;
        let base64 = &base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "senderDid": self.sender_did,
            "senderDeviceId": self.sender_device_id,
            "senderTransportPubkey": {
                "$bytes": base64.encode(&self.sender_transport_public_key)
            },
            "signature": {
                "$bytes": base64.encode(&self.signature)
            }
        })
    }

    pub fn from_aad_json(value: &serde_json::Value) -> Result<Self, MLSError> {
        let sender_did = value["senderDid"]
            .as_str()
            .ok_or_else(|| {
                MLSError::Cryptography("original sender attestation missing senderDid".into())
            })?
            .to_owned();
        let sender_device_id = value["senderDeviceId"]
            .as_str()
            .ok_or_else(|| {
                MLSError::Cryptography("original sender attestation missing senderDeviceId".into())
            })?
            .to_owned();
        Ok(Self {
            sender_did,
            sender_device_id,
            sender_transport_public_key: crate::client::chat_wire::json_bytes(
                value.get("senderTransportPubkey").ok_or_else(|| {
                    MLSError::Cryptography(
                        "original sender attestation missing senderTransportPubkey".into(),
                    )
                })?,
            )?,
            signature: crate::client::chat_wire::json_bytes(value.get("signature").ok_or_else(
                || MLSError::Cryptography("original sender attestation missing signature".into()),
            )?)?,
        })
    }

    #[cfg(feature = "labyrinth")]
    pub fn to_labyrinth(
        &self,
    ) -> Result<labyrinth::message::OriginalSenderArchiveAttestation, MLSError> {
        Ok(labyrinth::message::OriginalSenderArchiveAttestation {
            sender_did: self.sender_did.clone(),
            sender_device_id: self.sender_device_id.clone(),
            sender_transport_public_key: self
                .sender_transport_public_key
                .as_slice()
                .try_into()
                .map_err(|_| {
                    MLSError::Cryptography(
                        "original sender archive public key must be 32 bytes".into(),
                    )
                })?,
            signature: self.signature.as_slice().try_into().map_err(|_| {
                MLSError::Cryptography("original sender archive signature must be 64 bytes".into())
            })?,
        })
    }

    #[cfg(feature = "labyrinth")]
    pub fn from_labyrinth(value: &labyrinth::message::OriginalSenderArchiveAttestation) -> Self {
        Self {
            sender_did: value.sender_did.clone(),
            sender_device_id: value.sender_device_id.clone(),
            sender_transport_public_key: value.sender_transport_public_key.to_vec(),
            signature: value.signature.to_vec(),
        }
    }
}

/// Encrypted inner payload envelope carrying the secret 32-byte `frame_nonce` alongside
/// `canonical_payload_bytes` inside OpenMLS `PrivateMessage` ciphertext (`Spec §5 I13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMessagePlaintextEnvelope {
    pub frame_nonce: [u8; FRAME_NONCE_LEN],
    pub canonical_payload_bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_sender_attestation: Option<OriginalSenderArchiveAttestationEnvelope>,
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
            original_sender_attestation: None,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalOriginalSenderAttestationMap {
    sender_did: String,
    sender_device_id: CborByteVec,
    sender_transport_pubkey: CborByteVec,
    signature: CborByteVec,
}

impl TryFrom<CanonicalOriginalSenderAttestationMap> for OriginalSenderArchiveAttestationEnvelope {
    type Error = MLSError;

    fn try_from(value: CanonicalOriginalSenderAttestationMap) -> Result<Self, Self::Error> {
        let sender_device_id = uuid::Uuid::from_slice(&value.sender_device_id.0)
            .map_err(|_| {
                MLSError::Cryptography(
                    "original sender attestation device ID must be 16 bytes".into(),
                )
            })?
            .hyphenated()
            .to_string();
        Ok(Self {
            sender_did: value.sender_did,
            sender_device_id,
            sender_transport_public_key: value.sender_transport_pubkey.0,
            signature: value.signature.0,
        })
    }
}

#[derive(Deserialize)]
struct CanonicalApplicationAadMap {
    #[serde(rename = "conversationId", default)]
    conversation_id: Option<CborByteVec>,
    #[serde(rename = "messageId", default)]
    message_id: Option<CborByteVec>,
    #[serde(rename = "archiveCommitment", default)]
    archive_commitment: Option<CborByteVec>,
    #[serde(rename = "originalSenderAttestation", default)]
    original_sender_attestation: Option<CanonicalOriginalSenderAttestationMap>,
}

const CANONICAL_APP_AAD_PREFIX: &[u8] = b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0";
const DIRECT_REQUEST_APP_AAD_PREFIX: &[u8] = b"CATBIRD-DIRECT-REQUEST-APPLICATION-AAD\0";

/// Extract `(body, canonical_json, verified_archive_commitment,
/// original_sender_attestation)` from an OpenMLS `ApplicationMessage`
/// plaintext and its `PrivateMessage` AAD (`Spec §5 I13`, `C33`).
pub fn extract_plaintext_body_and_verify_aad(
    decrypted_bytes: &[u8],
    aad_bytes: &[u8],
) -> Result<
    (
        String,
        String,
        Option<[u8; 32]>,
        Option<OriginalSenderArchiveAttestationEnvelope>,
    ),
    MLSError,
> {
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
            let aad_attestation = parsed_aad
                .original_sender_attestation
                .map(OriginalSenderArchiveAttestationEnvelope::try_from)
                .transpose()?;
            let attestation = match (
                expected_commitment,
                aad_attestation,
                inner.original_sender_attestation,
            ) {
                (Some(commitment), Some(aad_attestation), Some(inner_attestation))
                    if aad_attestation == inner_attestation =>
                {
                    let thread_id = parsed_aad
                        .conversation_id
                        .as_ref()
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "original sender attestation missing AAD conversationId".into(),
                            )
                        })
                        .and_then(|value| {
                            uuid::Uuid::from_slice(&value.0)
                                .map(|id| id.hyphenated().to_string())
                                .map_err(|_| {
                                    MLSError::Cryptography(
                                        "applicationAad conversationId must be UUID bytes".into(),
                                    )
                                })
                        })?;
                    let message_id = parsed_aad
                        .message_id
                        .as_ref()
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "original sender attestation missing AAD messageId".into(),
                            )
                        })
                        .and_then(|value| {
                            uuid::Uuid::from_slice(&value.0)
                                .map(|id| id.hyphenated().to_string())
                                .map_err(|_| {
                                    MLSError::Cryptography(
                                        "applicationAad messageId must be UUID bytes".into(),
                                    )
                                })
                        })?;
                    aad_attestation.verify(&thread_id, &message_id, &commitment)?;
                    Some(aad_attestation)
                }
                (Some(_), _, _) => {
                    return Err(MLSError::Cryptography(
                        "original sender attestation missing or differs between MLS body and AAD"
                            .into(),
                    ));
                }
                (None, None, attestation) => attestation,
                (None, Some(_), _) => {
                    return Err(MLSError::Cryptography(
                        "original sender attestation without archive commitment".into(),
                    ));
                }
            };
            let (body, json_str) = parse_canonical_message_body(&inner.canonical_payload_bytes)?;
            return Ok((body, json_str, verified, attestation));
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
                return Ok((text.to_string(), json_str, None, None));
            }
        }
        let (body, json_str) = parse_canonical_message_body(decrypted_bytes)?;
        return Ok((body, json_str, None, None));
    }

    if let Some(cbor_aad) = aad_bytes.strip_prefix(DIRECT_REQUEST_APP_AAD_PREFIX) {
        let aad: CanonicalApplicationAadMap = serde_ipld_dagcbor::from_slice(cbor_aad)
            .map_err(|e| MLSError::Cryptography(format!("invalid C33 application AAD: {e}")))?;
        let commitment: [u8; 32] = aad
            .archive_commitment
            .ok_or_else(|| MLSError::Cryptography("C33 opening missing archiveCommitment".into()))?
            .0
            .try_into()
            .map_err(|_| {
                MLSError::Cryptography("C33 opening archiveCommitment must be 32 bytes".into())
            })?;
        let opening = crate::chat_v2::transcript::direct_request::decode_direct_request_opening(
            decrypted_bytes,
        )
        .map_err(|e| MLSError::Cryptography(format!("invalid committed C33 introduction: {e}")))?;
        opening.verify(&commitment).map_err(|e| {
            MLSError::Cryptography(format!("C33 introduction commitment mismatch: {e}"))
        })?;
        let (body, frame_json) = parse_canonical_message_body(&opening.canonical_payload_bytes)?;
        return Ok((body, frame_json, Some(commitment), None));
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
        return Ok((
            body,
            json_str,
            commitment,
            inner.original_sender_attestation,
        ));
    }

    if !aad_bytes.is_empty() {
        return Err(MLSError::Cryptography(
            "I13: non-empty PrivateMessage AAD requires PrivateMessagePlaintextEnvelope with frame_nonce"
                .to_string(),
        ));
    }

    let (body, json_str) = parse_canonical_message_body(decrypted_bytes)?;
    Ok((body, json_str, None, None))
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
    db.write_tx(|tx| {
        let purged = tx.purge_messages_from_sender(None, deleted_did)?;
        tx.purge_labyrinth_queue_from_sender(deleted_did)?;
        Ok(purged)
    })
}
