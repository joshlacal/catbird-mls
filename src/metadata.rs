//! Encrypted group metadata — epoch-bound, exporter-derived keys.
//!
//! Every group member can independently derive the metadata encryption key from
//! the MLS exporter (RFC 9420 §8). Metadata is stored as an opaque encrypted
//! blob on the server; a lightweight `MetadataReference` in the MLS group
//! context points to the blob by locator and integrity hash.

use crate::orchestrator::constants::SAFE_EXPORT_METADATA_KEY;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use openmls::prelude::*;
use openmls::storage::StorageProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// Error type
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("export secret failed: {0}")]
    ExportSecret(String),

    #[error("AEAD encryption failed: {0}")]
    Encryption(String),

    #[error("AEAD decryption failed: {0}")]
    Decryption(String),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("ciphertext too short (need at least nonce + tag)")]
    CiphertextTooShort,
}

// ═══════════════════════════════════════════════════════════════════════════
// Data types
// ═══════════════════════════════════════════════════════════════════════════

/// Lightweight reference stored in `app_data_dictionary` inside the MLS
/// GroupContext. Points to an encrypted blob on the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataReference {
    /// Schema identifier, e.g. `"blue.catbird/group-metadata/v1"`.
    pub schema: String,
    /// Monotonic counter incremented on each metadata content change.
    pub metadata_version: u64,
    /// Opaque UUIDv4 locator for the encrypted blob on the server.
    pub blob_locator: String,
    /// SHA-256 of the encrypted blob (nonce || ciphertext || tag) for
    /// integrity verification.
    pub ciphertext_hash: Vec<u8>,
}

/// Plaintext group metadata payload. Encrypted before storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMetadataV1 {
    /// Schema version (always 1 for this type).
    pub version: u32,
    /// Group display title (max 128 chars by convention).
    pub title: String,
    /// Group description (max 512 chars by convention).
    pub description: String,
    /// UUIDv4 locator for a separately-encrypted avatar blob, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_locator: Option<String>,
    /// MIME type of the avatar image, e.g. `"image/jpeg"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_content_type: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const EXPORTER_LABEL: &str = "blue.catbird/group-metadata/v1";
/// Private AppDataDictionary component ID used to store `MetadataReference`.
pub const METADATA_REFERENCE_COMPONENT_ID: u16 = 0x8001;
const EXPORTER_KEY_LENGTH: usize = 32;
/// ChaCha20-Poly1305 nonce size in bytes.
const NONCE_SIZE: usize = 12;
/// Poly1305 tag size in bytes.
const TAG_SIZE: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════
// Group state helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Read the current `MetadataReference` JSON from the group's
/// `AppDataDictionary`, if present.
pub fn current_metadata_reference_json(group: &MlsGroup) -> Option<Vec<u8>> {
    group
        .extensions()
        .app_data_dictionary()
        .and_then(|ext| ext.dictionary().get(&METADATA_REFERENCE_COMPONENT_ID))
        .map(|bytes| bytes.to_vec())
}

/// Read and decode the current `MetadataReference` from the group's
/// `AppDataDictionary`.
pub fn current_metadata_reference(group: &MlsGroup) -> Option<MetadataReference> {
    let json = current_metadata_reference_json(group)?;
    serde_json::from_slice(&json).ok()
}

/// Build the plaintext metadata payload that should be re-encrypted for the
/// next epoch, based on the current group-context metadata extension.
pub fn metadata_payload_from_group(group: &MlsGroup) -> Option<GroupMetadataV1> {
    let metadata = crate::group_metadata::GroupMetadata::from_group(group)?;
    Some(GroupMetadataV1 {
        version: 1,
        title: metadata.name.unwrap_or_default(),
        description: metadata.description.unwrap_or_default(),
        avatar_blob_locator: None,
        avatar_content_type: None,
    })
}

/// Compute the metadata version that should be used for the next epoch.
pub fn next_metadata_version(
    current_reference: Option<&MetadataReference>,
    had_metadata_before: bool,
    metadata_changed: bool,
) -> Option<u64> {
    match current_reference {
        Some(reference) => Some(if metadata_changed {
            reference.metadata_version.saturating_add(1)
        } else {
            reference.metadata_version
        }),
        None if metadata_changed && had_metadata_before => Some(2),
        None if metadata_changed || had_metadata_before => Some(1),
        None => None,
    }
}

/// Build the next epoch's `MetadataReference` JSON.
///
/// The ciphertext hash is intentionally left empty at commit-construction time.
/// The sender fills the referenced locator with the new blob later in the send
/// flow, but the locator and metadata version must already be stable so the
/// commit can persist them in the MLS state.
pub fn planned_metadata_reference_json(
    current_reference: Option<&MetadataReference>,
    had_metadata_before: bool,
    metadata_changed: bool,
) -> Result<Option<Vec<u8>>, MetadataError> {
    let Some(metadata_version) =
        next_metadata_version(current_reference, had_metadata_before, metadata_changed)
    else {
        return Ok(None);
    };

    let locator = Uuid::new_v4().to_string().to_lowercase();
    let reference = build_metadata_reference(metadata_version, &locator, &[]);
    Ok(Some(serde_json::to_vec(&reference)?))
}

// ═══════════════════════════════════════════════════════════════════════════
// Key derivation
// ═══════════════════════════════════════════════════════════════════════════

/// Derive the metadata encryption key from a staged commit's next-epoch
/// exporter secret.
///
/// The returned 32-byte key is suitable for ChaCha20-Poly1305 AEAD and is
/// identical for every group member that processes the same staged commit.
///
/// # Arguments
/// * `staged_commit` — the staged commit (pre-merge) exposing the next epoch's
///   exporter
/// * `crypto` — an OpenMLS crypto provider (e.g. `provider.crypto()`)
/// * `group_id` — raw MLS group ID bytes
/// * `epoch` — the **new** epoch the staged commit transitions to
pub fn derive_metadata_key(
    staged_commit: &StagedCommit,
    crypto: &impl OpenMlsCrypto,
    group_id: &[u8],
    epoch: u64,
) -> Result<[u8; 32], MetadataError> {
    let context = build_exporter_context(group_id, epoch);

    let secret = staged_commit
        .export_secret(crypto, EXPORTER_LABEL, &context, EXPORTER_KEY_LENGTH)
        .map_err(|e| MetadataError::ExportSecret(format!("{e:?}")))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&secret);
    Ok(key)
}

/// Derive the metadata encryption key from an existing `MlsGroup`'s current
/// epoch exporter secret.
///
/// Used for **initial group creation** where no `StagedCommit` exists — the
/// group is already at its initial epoch and we can call `export_secret`
/// directly on the group.
///
/// # Arguments
/// * `group` — the MLS group (already created, at its initial epoch)
/// * `crypto` — an OpenMLS crypto provider
/// * `group_id` — raw MLS group ID bytes
/// * `epoch` — the current epoch of the group
pub fn derive_metadata_key_from_group<Crypto: OpenMlsCrypto, Storage: StorageProvider>(
    group: &mut MlsGroup,
    crypto: &Crypto,
    storage: &Storage,
    group_id: &[u8],
    epoch: u64,
) -> Result<[u8; 32], MetadataError> {
    let secret = match group.safe_export_secret(crypto, storage, SAFE_EXPORT_METADATA_KEY) {
        Ok(s) => {
            crate::info_log!(
                "[METADATA] Used safe_export_secret (PPRF) for metadata key, epoch {}",
                epoch
            );
            s
        }
        Err(_) => {
            crate::info_log!(
                "[METADATA] safe_export_secret unavailable, falling back to export_secret for metadata key"
            );
            let context = build_exporter_context(group_id, epoch);
            group
                .export_secret(crypto, EXPORTER_LABEL, &context, EXPORTER_KEY_LENGTH)
                .map_err(|e| MetadataError::ExportSecret(format!("{e:?}")))?
        }
    };

    let mut key = [0u8; 32];
    key.copy_from_slice(&secret);
    Ok(key)
}

/// Build the exporter context bytes: `group_id || to_be_bytes(epoch)`.
fn build_exporter_context(group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut context = Vec::with_capacity(group_id.len() + 8);
    context.extend_from_slice(group_id);
    context.extend_from_slice(&epoch.to_be_bytes());
    context
}

// ═══════════════════════════════════════════════════════════════════════════
// AEAD encrypt / decrypt helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Build the additional authenticated data (AAD) for metadata blobs.
fn build_metadata_aad(group_id: &[u8], epoch: u64, metadata_version: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(group_id.len() + 16);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&metadata_version.to_be_bytes());
    aad
}

/// Build the additional authenticated data (AAD) for avatar blobs.
/// Identical to metadata AAD with `b"avatar"` appended for domain separation.
fn build_avatar_aad(group_id: &[u8], epoch: u64, metadata_version: u64) -> Vec<u8> {
    let mut aad = build_metadata_aad(group_id, epoch, metadata_version);
    aad.extend_from_slice(b"avatar");
    aad
}

/// Low-level AEAD encrypt: returns `nonce || ciphertext || tag`.
fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MetadataError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| MetadataError::Encryption(format!("{e}")))?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| MetadataError::Encryption(format!("{e}")))?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Low-level AEAD decrypt: expects `nonce || ciphertext || tag`.
fn aead_decrypt(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, MetadataError> {
    if blob.len() < NONCE_SIZE + TAG_SIZE {
        return Err(MetadataError::CiphertextTooShort);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_SIZE);
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| MetadataError::Decryption(format!("{e}")))?;
    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| MetadataError::Decryption(format!("{e}")))
}

// ═══════════════════════════════════════════════════════════════════════════
// Public encrypt / decrypt — metadata
// ═══════════════════════════════════════════════════════════════════════════

/// Encrypt a `GroupMetadataV1` into an opaque blob (`nonce || ciphertext || tag`).
pub fn encrypt_metadata_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    metadata: &GroupMetadataV1,
) -> Result<Vec<u8>, MetadataError> {
    let plaintext = serde_json::to_vec(metadata)?;
    let aad = build_metadata_aad(group_id, epoch, metadata_version);
    aead_encrypt(key, &plaintext, &aad)
}

/// Decrypt an opaque blob back into `GroupMetadataV1`.
pub fn decrypt_metadata_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    ciphertext: &[u8],
) -> Result<GroupMetadataV1, MetadataError> {
    let aad = build_metadata_aad(group_id, epoch, metadata_version);
    let plaintext = aead_decrypt(key, ciphertext, &aad)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

// ═══════════════════════════════════════════════════════════════════════════
// Public encrypt / decrypt — avatar
// ═══════════════════════════════════════════════════════════════════════════

/// Encrypt raw avatar image bytes into an opaque blob.
/// Uses domain-separated AAD (`|| b"avatar"`) to prevent confusion with
/// metadata blobs.
pub fn encrypt_avatar_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    avatar_bytes: &[u8],
) -> Result<Vec<u8>, MetadataError> {
    let aad = build_avatar_aad(group_id, epoch, metadata_version);
    aead_encrypt(key, avatar_bytes, &aad)
}

/// Decrypt an opaque avatar blob back into raw image bytes.
pub fn decrypt_avatar_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, MetadataError> {
    let aad = build_avatar_aad(group_id, epoch, metadata_version);
    aead_decrypt(key, ciphertext, &aad)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════════════════

/// Build a `MetadataReference` from its constituent parts.
///
/// Computes the `schema` field automatically as
/// `"blue.catbird/group-metadata/v1"`.
pub fn build_metadata_reference(
    metadata_version: u64,
    blob_locator: &str,
    ciphertext_hash: &[u8],
) -> MetadataReference {
    MetadataReference {
        schema: "blue.catbird/group-metadata/v1".to_string(),
        metadata_version,
        blob_locator: blob_locator.to_string(),
        ciphertext_hash: ciphertext_hash.to_vec(),
    }
}

/// Compute the SHA-256 hash of an encrypted blob for use in
/// `MetadataReference.ciphertext_hash`.
pub fn hash_ciphertext(ciphertext: &[u8]) -> Vec<u8> {
    Sha256::digest(ciphertext).to_vec()
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> GroupMetadataV1 {
        GroupMetadataV1 {
            version: 1,
            title: "Engineering".to_string(),
            description: "The engineering team chat".to_string(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        }
    }

    fn sample_metadata_with_avatar() -> GroupMetadataV1 {
        GroupMetadataV1 {
            version: 1,
            title: "Design Team".to_string(),
            description: "UI/UX design discussions".to_string(),
            avatar_blob_locator: Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string()),
            avatar_content_type: Some("image/jpeg".to_string()),
        }
    }

    #[test]
    fn metadata_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let group_id = b"test-group-001";
        let epoch = 7u64;
        let version = 3u64;
        let meta = sample_metadata();

        let blob = encrypt_metadata_blob(&key, group_id, epoch, version, &meta).unwrap();
        let decrypted = decrypt_metadata_blob(&key, group_id, epoch, version, &blob).unwrap();

        assert_eq!(decrypted, meta);
    }

    #[test]
    fn metadata_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let group_id = b"test-group";
        let meta = sample_metadata();

        let blob = encrypt_metadata_blob(&key, group_id, 1, 1, &meta).unwrap();
        let result = decrypt_metadata_blob(&wrong_key, group_id, 1, 1, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_wrong_epoch_fails() {
        let key = [42u8; 32];
        let group_id = b"test-group";
        let meta = sample_metadata();

        let blob = encrypt_metadata_blob(&key, group_id, 1, 1, &meta).unwrap();
        let result = decrypt_metadata_blob(&key, group_id, 2, 1, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_wrong_version_fails() {
        let key = [42u8; 32];
        let group_id = b"test-group";
        let meta = sample_metadata();

        let blob = encrypt_metadata_blob(&key, group_id, 1, 1, &meta).unwrap();
        let result = decrypt_metadata_blob(&key, group_id, 1, 2, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_wrong_group_id_fails() {
        let key = [42u8; 32];
        let meta = sample_metadata();

        let blob = encrypt_metadata_blob(&key, b"group-a", 1, 1, &meta).unwrap();
        let result = decrypt_metadata_blob(&key, b"group-b", 1, 1, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn avatar_encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let group_id = b"avatar-test-group";
        let epoch = 5u64;
        let version = 1u64;
        let avatar_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]; // fake JPEG header

        let blob = encrypt_avatar_blob(&key, group_id, epoch, version, &avatar_bytes).unwrap();
        let decrypted = decrypt_avatar_blob(&key, group_id, epoch, version, &blob).unwrap();

        assert_eq!(decrypted, avatar_bytes);
    }

    #[test]
    fn avatar_wrong_key_fails() {
        let key = [7u8; 32];
        let wrong_key = [8u8; 32];
        let avatar_bytes = b"image data";

        let blob = encrypt_avatar_blob(&key, b"g", 1, 1, avatar_bytes).unwrap();
        let result = decrypt_avatar_blob(&wrong_key, b"g", 1, 1, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_and_avatar_blobs_not_interchangeable() {
        let key = [42u8; 32];
        let group_id = b"cross-domain-test";
        let epoch = 1u64;
        let version = 1u64;

        // Encrypt metadata, try to decrypt as avatar
        let meta = sample_metadata();
        let meta_blob = encrypt_metadata_blob(&key, group_id, epoch, version, &meta).unwrap();
        let result = decrypt_avatar_blob(&key, group_id, epoch, version, &meta_blob);
        assert!(result.is_err(), "metadata blob must not decrypt as avatar");

        // Encrypt avatar, try to decrypt as metadata
        let avatar_blob = encrypt_avatar_blob(&key, group_id, epoch, version, b"png data").unwrap();
        let result = decrypt_metadata_blob(&key, group_id, epoch, version, &avatar_blob);
        assert!(result.is_err(), "avatar blob must not decrypt as metadata");
    }

    #[test]
    fn ciphertext_too_short_is_rejected() {
        let key = [42u8; 32];
        let short = vec![0u8; NONCE_SIZE + TAG_SIZE - 1];
        let result = decrypt_metadata_blob(&key, b"g", 1, 1, &short);
        assert!(matches!(result, Err(MetadataError::CiphertextTooShort)));
    }

    #[test]
    fn build_metadata_reference_populates_all_fields() {
        let hash = vec![0xAB; 32];
        let r = build_metadata_reference(5, "uuid-locator", &hash);

        assert_eq!(r.schema, "blue.catbird/group-metadata/v1");
        assert_eq!(r.metadata_version, 5);
        assert_eq!(r.blob_locator, "uuid-locator");
        assert_eq!(r.ciphertext_hash, hash);
    }

    #[test]
    fn metadata_reference_serde_roundtrip() {
        let r = build_metadata_reference(1, "loc-123", &[0xDE, 0xAD]);
        let json = serde_json::to_vec(&r).unwrap();
        let decoded: MetadataReference = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn group_metadata_v1_serde_roundtrip() {
        let meta = sample_metadata_with_avatar();
        let json = serde_json::to_vec(&meta).unwrap();
        let decoded: GroupMetadataV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn group_metadata_v1_omits_none_fields() {
        let meta = sample_metadata();
        let json = String::from_utf8(serde_json::to_vec(&meta).unwrap()).unwrap();
        assert!(!json.contains("avatar_blob_locator"));
        assert!(!json.contains("avatar_content_type"));
    }

    #[test]
    fn hash_ciphertext_produces_32_bytes() {
        let blob = vec![1, 2, 3, 4, 5];
        let hash = hash_ciphertext(&blob);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hash_ciphertext_is_deterministic() {
        let blob = vec![0xCA, 0xFE];
        assert_eq!(hash_ciphertext(&blob), hash_ciphertext(&blob));
    }

    #[test]
    fn different_encryptions_produce_different_nonces() {
        let key = [42u8; 32];
        let meta = sample_metadata();
        let blob1 = encrypt_metadata_blob(&key, b"g", 1, 1, &meta).unwrap();
        let blob2 = encrypt_metadata_blob(&key, b"g", 1, 1, &meta).unwrap();
        // Nonces (first 12 bytes) should differ with overwhelming probability
        assert_ne!(&blob1[..NONCE_SIZE], &blob2[..NONCE_SIZE]);
    }

    #[test]
    fn large_avatar_roundtrip() {
        let key = [55u8; 32];
        let group_id = b"large-avatar-group";
        let avatar = vec![0xAB; 512 * 1024]; // 512 KB

        let blob = encrypt_avatar_blob(&key, group_id, 10, 2, &avatar).unwrap();
        let decrypted = decrypt_avatar_blob(&key, group_id, 10, 2, &blob).unwrap();
        assert_eq!(decrypted, avatar);
    }
}
