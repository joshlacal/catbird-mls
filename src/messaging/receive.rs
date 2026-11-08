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

/// `(conversation_id, message_id, archive_commitment, original_sender_attestation)` of a
/// canonical application AAD with its domain prefix stripped. Both archive fields are required,
/// and the attestation must verify over the AAD's own conversation and message IDs.
fn canonical_aad_archive_evidence(
    cbor_aad: &[u8],
) -> Result<
    (
        uuid::Uuid,
        uuid::Uuid,
        [u8; ARCHIVE_COMMITMENT_LEN],
        OriginalSenderArchiveAttestationEnvelope,
    ),
    MLSError,
> {
    let parsed: CanonicalApplicationAadMap =
        serde_ipld_dagcbor::from_slice(cbor_aad).map_err(|e| {
            MLSError::Cryptography(format!("invalid canonical applicationAad CBOR: {e}"))
        })?;
    let uuid = |value: Option<CborByteVec>, field: &str| {
        value
            .and_then(|value| uuid::Uuid::from_slice(&value.0).ok())
            .ok_or_else(|| {
                MLSError::Cryptography(format!("applicationAad {field} must be UUID bytes"))
            })
    };
    let conversation_id = uuid(parsed.conversation_id, "conversationId")?;
    let message_id = uuid(parsed.message_id, "messageId")?;
    let commitment: [u8; ARCHIVE_COMMITMENT_LEN] = parsed
        .archive_commitment
        .ok_or_else(|| {
            MLSError::Cryptography("I13: canonical applicationAad missing archiveCommitment".into())
        })?
        .0
        .as_slice()
        .try_into()
        .map_err(|_| {
            MLSError::Cryptography(
                "I13 canonical applicationAad archiveCommitment must be 32 bytes".into(),
            )
        })?;
    let attestation = OriginalSenderArchiveAttestationEnvelope::try_from(
        parsed.original_sender_attestation.ok_or_else(|| {
            MLSError::Cryptography(
                "canonical applicationAad missing original sender attestation".into(),
            )
        })?,
    )?;
    attestation.verify(
        &conversation_id.hyphenated().to_string(),
        &message_id.hyphenated().to_string(),
        &commitment,
    )?;
    Ok((conversation_id, message_id, commitment, attestation))
}

/// Authenticate the archive evidence a signed canonical application AAD carries for the entry
/// `(cid, msg_id)` without decrypting it: its `archiveCommitment` and the original sender's
/// attestation over exactly that conversation, message and commitment. An entry this device
/// can never decrypt is bound to its sender and receipt through this evidence alone.
pub fn verify_application_aad_archive_evidence(
    aad_bytes: &[u8],
    cid: &str,
    msg_id: &str,
) -> Result<
    (
        [u8; ARCHIVE_COMMITMENT_LEN],
        OriginalSenderArchiveAttestationEnvelope,
    ),
    MLSError,
> {
    let cbor_aad = aad_bytes
        .strip_prefix(CANONICAL_APP_AAD_PREFIX)
        .ok_or_else(|| MLSError::Cryptography("application AAD is not canonical".into()))?;
    let (conversation_id, message_id, commitment, attestation) =
        canonical_aad_archive_evidence(cbor_aad)?;
    if uuid::Uuid::parse_str(cid).ok() != Some(conversation_id)
        || uuid::Uuid::parse_str(msg_id).ok() != Some(message_id)
    {
        return Err(MLSError::Cryptography(
            "applicationAad names a different conversation or message".into(),
        ));
    }
    Ok((commitment, attestation))
}

/// Extract `(body, canonical_json, verified_archive_commitment,
/// original_sender_attestation)` from an OpenMLS `ApplicationMessage`
/// plaintext and its `PrivateMessage` AAD (`Spec §5 I13`, `C33`). A canonical application
/// AAD always carries a verified commitment and attestation, matched by the encrypted frame.
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
        let (_, _, commitment, attestation) = canonical_aad_archive_evidence(cbor_aad)?;
        let inner: PrivateMessagePlaintextEnvelope = serde_json::from_slice(decrypted_bytes)
            .map_err(|e| {
                MLSError::Cryptography(format!(
                    "I13: canonical applicationAad requires PrivateMessagePlaintextEnvelope: {e}"
                ))
            })?;
        let actual = labyrinth_protocol::receipt::compute_archive_commitment(
            &inner.frame_nonce,
            &inner.canonical_payload_bytes,
        );
        if !bool::from(actual.ct_eq(&commitment)) {
            return Err(MLSError::Cryptography(
                "I13 canonical applicationAad archiveCommitment mismatch".to_string(),
            ));
        }
        if inner.original_sender_attestation.as_ref() != Some(&attestation) {
            return Err(MLSError::Cryptography(
                "original sender attestation missing or differs between MLS body and AAD".into(),
            ));
        }
        let (body, json_str) = parse_canonical_message_body(&inner.canonical_payload_bytes)?;
        return Ok((body, json_str, Some(commitment), Some(attestation)));
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
        // Outside a canonical AAD an attestation is never authenticated: it is not returned.
        return Ok((body, json_str, commitment, None));
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

/// Purge locally stored messages authored by `deleted_did` after `conversation_id` sequenced an
/// `accountDeleted` entry (`Spec §5 I13`).
#[cfg(not(target_arch = "wasm32"))]
pub fn handle_account_deleted_event(
    db: &crate::storage::MlsAccountDb,
    conversation_id: &str,
    deleted_did: &str,
) -> Result<usize, MLSError> {
    if deleted_did.trim().is_empty() {
        return Err(MLSError::invalid_input("deleted_did must not be empty"));
    }
    db.write_tx(|tx| {
        let purged = tx.purge_messages_from_sender(Some(conversation_id), deleted_did)?;
        tx.purge_labyrinth_queue_from_sender(conversation_id, deleted_did)?;
        Ok(purged)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::Signer as _;

    const CID: &str = "a1234567-89ab-4cde-8123-456789abcdef";
    const MID: &str = "b2234567-89ab-4cde-8123-456789abcdef";
    const OTHER_MID: &str = "c3234567-89ab-4cde-8123-456789abcdef";
    const NONCE: [u8; FRAME_NONCE_LEN] = [9; FRAME_NONCE_LEN];
    const PAYLOAD: &[u8] = br#"{"text":"hello"}"#;

    /// `(decrypted envelope, canonical AAD)` for message `MID`, whose inner attestation is
    /// signed over `attested_mid`; the AAD binds the archive evidence only if `aad_evidence`.
    fn sealed(attested_mid: &str, aad_evidence: bool) -> (Vec<u8>, Vec<u8>) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let commitment = labyrinth_protocol::receipt::compute_archive_commitment(&NONCE, PAYLOAD);
        let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
            CID,
            attested_mid,
            &commitment,
        );
        let attestation = OriginalSenderArchiveAttestationEnvelope {
            sender_did: "did:plc:bob".into(),
            sender_device_id: "b0b00000-0000-4000-8000-000000000001".into(),
            sender_transport_public_key: key.verifying_key().to_bytes().to_vec(),
            signature: key.sign(&transcript).to_bytes().to_vec(),
        };
        let id = |id: &str| STANDARD.encode(uuid::Uuid::parse_str(id).unwrap().as_bytes());
        let mut aad = serde_json::json!({
            "protocolVersion": "1", "conversationId": id(CID), "generation": 0, "messageId": id(MID),
            "prior": {
                "conversationId": id(CID), "generation": 0, "stateVersion": 0, "epoch": 1,
                "groupId": { "$bytes": STANDARD.encode([3u8; 32]) },
                "groupContextHash": { "$bytes": STANDARD.encode([2u8; 32]) },
                "confirmationTag": { "$bytes": STANDARD.encode([1u8; 32]) }, "lifecycle": "active",
            },
        });
        if aad_evidence {
            aad["archiveCommitment"] = serde_json::json!({ "$bytes": STANDARD.encode(commitment) });
            aad["originalSenderAttestation"] = attestation.to_aad_json();
        }
        let envelope = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
            frame_nonce: NONCE,
            canonical_payload_bytes: PAYLOAD.to_vec(),
            original_sender_attestation: Some(attestation),
        })
        .unwrap();
        let aad = crate::orchestrator::canonical_transport::canonical_application_aad_bytes(&aad)
            .unwrap();
        (envelope, aad)
    }

    /// R4: a canonical AAD yields only the attestation it binds and that verifies for its own
    /// message; an unbound or forged inner attestation is an error, never returned.
    #[test]
    fn canonical_aad_returns_only_a_bound_verified_attestation() {
        let (envelope, aad) = sealed(MID, true);
        let (body, _, commitment, attestation) =
            extract_plaintext_body_and_verify_aad(&envelope, &aad).unwrap();
        assert_eq!(body, "hello");
        assert!(commitment.is_some() && attestation.is_some());
        for (attested_mid, aad_evidence) in [(MID, false), (OTHER_MID, false), (OTHER_MID, true)] {
            let (envelope, aad) = sealed(attested_mid, aad_evidence);
            let result = extract_plaintext_body_and_verify_aad(&envelope, &aad);
            assert!(
                result.is_err(),
                "{attested_mid} bound={aad_evidence}: {result:?}"
            );
        }
    }

    /// R4: outside a canonical AAD nothing authenticates the inner attestation, so even a valid
    /// one is never returned.
    #[test]
    fn non_canonical_aad_never_returns_an_attestation() {
        let (envelope, _) = sealed(MID, true);
        let legacy_aad = PrivateMessageAadEnvelope::for_payload(&NONCE, PAYLOAD)
            .to_aad_bytes()
            .unwrap();
        for aad in [Vec::new(), legacy_aad] {
            let (body, _, _, attestation) =
                extract_plaintext_body_and_verify_aad(&envelope, &aad).unwrap();
            assert_eq!(body, "hello");
            assert!(attestation.is_none(), "AAD {aad:?}");
        }
    }
}
