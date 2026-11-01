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
