//! Inbound MLS message verification (`I13` `archive_commitment` AAD) and `accountDeleted`
//! local database purge (`Spec §5 I13`).

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::MLSError;

/// Domain-separation prefix for `I13` OpenMLS `PrivateMessage` AAD `archive_commitment`.
pub const ARCHIVE_COMMITMENT_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-ARCHIVE-COMMITMENT-V1\0";

/// Compute the 32-byte `I13` `archive_commitment` carried inside OpenMLS `PrivateMessage` AAD,
/// binding `(conversation_id, group_id, message_id, plaintext_bytes, created_at_ms)` so any
/// Space-archived frame can be verified against the sequencer-receipted MLS AAD commitment.
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
