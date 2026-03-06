use crate::error::MLSError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use openmls::prelude::*;
use openmls_traits::random::OpenMlsRand;
use serde::{Deserialize, Serialize};

/// Extension type ID for Catbird group metadata.
/// 0xff00 is in the private-use range per RFC 9420.
pub const CATBIRD_METADATA_EXTENSION_TYPE: u16 = 0xff00;

/// Encrypted group metadata stored in MLS group context extensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMetadata {
    /// Schema version (currently 1)
    pub v: u32,
    /// Group display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Group description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SHA-256 hash of the avatar image (hex-encoded), if set.
    /// Actual image bytes are stored/fetched separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_hash: Option<String>,
}

impl GroupMetadata {
    pub fn new(name: Option<String>, description: Option<String>) -> Self {
        Self {
            v: 1,
            name,
            description,
            avatar_hash: None,
        }
    }

    /// Serialize to JSON bytes for embedding in an MLS extension.
    pub fn to_extension_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from MLS extension bytes.
    pub fn from_extension_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Build an OpenMLS Extensions containing this metadata.
    pub(crate) fn to_extensions(&self) -> Result<Extensions<GroupContext>, MLSError> {
        let bytes = self.to_extension_bytes()?;
        Extensions::single(Extension::Unknown(
            CATBIRD_METADATA_EXTENSION_TYPE,
            UnknownExtension(bytes),
        ))
        .map_err(|e| MLSError::OpenMLS(format!("{:?}", e)))
    }

    /// Extract metadata from an MLS group's context extensions.
    /// Returns None if the extension is not present.
    pub fn from_group(group: &MlsGroup) -> Option<Self> {
        group
            .extensions()
            .unknown(CATBIRD_METADATA_EXTENSION_TYPE)
            .and_then(|ext| {
                Self::from_extension_bytes(&ext.0)
                    .map_err(|e| { crate::warn_log!("Failed to decode GroupMetadata extension: {:?}", e); })
                    .ok()
            })
    }
}

// ---------------------------------------------------------------------------
// Encrypted metadata envelope
// ---------------------------------------------------------------------------

/// MLS exporter label for deriving the metadata encryption key.
pub const METADATA_EXPORTER_LABEL: &str = "catbird/group-metadata/v1";

/// Encrypted envelope stored in the MLS group context extension.
/// The server sees only this structure (ciphertext), never plaintext metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMetadataEnvelope {
    /// Schema version
    pub v: u32,
    /// Epoch at which the encryption key was derived
    pub epoch: u64,
    /// AEAD nonce (12 bytes, base64-encoded for JSON)
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    /// AEAD ciphertext (base64-encoded for JSON)
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Base64 serde helper for byte arrays
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Derive the metadata encryption key from the MLS group's exporter secret.
/// Returns a 32-byte key for ChaCha20-Poly1305.
pub fn derive_metadata_key<C: openmls_traits::crypto::OpenMlsCrypto>(
    group: &MlsGroup,
    crypto: &C,
) -> Result<[u8; 32], String> {
    let exported = group
        .export_secret(crypto, METADATA_EXPORTER_LABEL, b"", 32)
        .map_err(|e| format!("export_secret failed: {:?}", e))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&exported);
    Ok(key)
}

/// Encrypt plaintext GroupMetadata into an EncryptedMetadataEnvelope.
pub fn encrypt_metadata<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    metadata: &GroupMetadata,
) -> Result<EncryptedMetadataEnvelope, String> {
    let key_bytes = derive_metadata_key(group, provider.crypto())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| format!("cipher init: {:?}", e))?;

    let plaintext = metadata
        .to_extension_bytes()
        .map_err(|e| format!("serialize: {:?}", e))?;

    // Generate random 12-byte nonce
    let random_bytes = provider
        .rand()
        .random_vec(12)
        .map_err(|e| format!("nonce generation: {:?}", e))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&random_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("encrypt: {:?}", e))?;

    let epoch = group.epoch().as_u64();

    Ok(EncryptedMetadataEnvelope {
        v: 1,
        epoch,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt an EncryptedMetadataEnvelope back to GroupMetadata.
/// `key` is the 32-byte ChaCha20-Poly1305 key (from derive_metadata_key).
pub fn decrypt_metadata(
    envelope: &EncryptedMetadataEnvelope,
    key: &[u8; 32],
) -> Result<GroupMetadata, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| format!("cipher init: {:?}", e))?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|e| format!("decrypt: {:?}", e))?;
    GroupMetadata::from_extension_bytes(&plaintext)
        .map_err(|e| format!("deserialize: {:?}", e))
}

/// Try to decrypt metadata from group extensions using the current epoch's key.
/// Returns None if no metadata extension is present or decryption fails.
pub fn decrypt_metadata_from_group<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
) -> Option<GroupMetadata> {
    let ext_data = group
        .extensions()
        .unknown(CATBIRD_METADATA_EXTENSION_TYPE)?;

    // Try to parse as encrypted envelope
    let envelope: EncryptedMetadataEnvelope = match serde_json::from_slice(&ext_data.0) {
        Ok(env) => env,
        Err(e) => {
            // Maybe it's old plaintext format -- try direct deserialization
            crate::warn_log!(
                "Metadata extension is not an encrypted envelope: {:?}",
                e
            );
            return GroupMetadata::from_extension_bytes(&ext_data.0).ok();
        }
    };

    // Derive key from current epoch and try to decrypt
    match derive_metadata_key(group, provider.crypto()) {
        Ok(key) => match decrypt_metadata(&envelope, &key) {
            Ok(meta) => Some(meta),
            Err(e) => {
                crate::warn_log!(
                    "Failed to decrypt metadata (epoch mismatch?): {:?}. Envelope epoch={}, current epoch={}",
                    e,
                    envelope.epoch,
                    group.epoch().as_u64()
                );
                None
            }
        },
        Err(e) => {
            crate::warn_log!("Failed to derive metadata key: {:?}", e);
            None
        }
    }
}

/// Build Extensions from raw encrypted envelope bytes.
pub(crate) fn encrypted_to_extensions(
    envelope_bytes: &[u8],
) -> Result<Extensions<GroupContext>, MLSError> {
    Extensions::single(Extension::Unknown(
        CATBIRD_METADATA_EXTENSION_TYPE,
        UnknownExtension(envelope_bytes.to_vec()),
    ))
    .map_err(|e| MLSError::OpenMLS(format!("{:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_serialize() {
        let meta = GroupMetadata {
            v: 1,
            name: Some("Team Chat".to_string()),
            description: Some("Our group".to_string()),
            avatar_hash: None,
        };
        let bytes = meta.to_extension_bytes().unwrap();
        let decoded = GroupMetadata::from_extension_bytes(&bytes).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn test_empty_metadata() {
        let meta = GroupMetadata::new(None, None);
        let bytes = meta.to_extension_bytes().unwrap();
        let decoded = GroupMetadata::from_extension_bytes(&bytes).unwrap();
        assert_eq!(decoded.v, 1);
        assert!(decoded.name.is_none());
    }

    #[test]
    fn test_to_extensions() {
        let meta = GroupMetadata::new(Some("Test".to_string()), None);
        let exts = meta.to_extensions().unwrap();
        // Should have exactly one extension
        assert_eq!(exts.iter().count(), 1);
    }

    #[test]
    fn test_skip_serializing_none() {
        let meta = GroupMetadata::new(Some("Test".to_string()), None);
        let json = String::from_utf8(meta.to_extension_bytes().unwrap()).unwrap();
        assert!(!json.contains("description"));
        assert!(!json.contains("avatar_hash"));
    }

    #[test]
    fn test_envelope_roundtrip() {
        let envelope = EncryptedMetadataEnvelope {
            v: 1,
            epoch: 5,
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: EncryptedMetadataEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.epoch, 5);
        assert_eq!(decoded.nonce.len(), 12);
        assert_eq!(decoded.ciphertext, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let meta =
            GroupMetadata::new(Some("Secret Group".to_string()), Some("Hidden desc".to_string()));
        let key = [42u8; 32];
        let nonce_bytes = [1u8; 12];

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = meta.to_extension_bytes().unwrap();
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let envelope = EncryptedMetadataEnvelope {
            v: 1,
            epoch: 0,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        let decrypted = decrypt_metadata(&envelope, &key).unwrap();
        assert_eq!(decrypted.name.as_deref(), Some("Secret Group"));
        assert_eq!(decrypted.description.as_deref(), Some("Hidden desc"));
    }

    #[test]
    fn test_wrong_key_fails() {
        let meta = GroupMetadata::new(Some("Secret".to_string()), None);
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let nonce_bytes = [1u8; 12];

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = meta.to_extension_bytes().unwrap();
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let envelope = EncryptedMetadataEnvelope {
            v: 1,
            epoch: 0,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        let result = decrypt_metadata(&envelope, &wrong_key);
        assert!(result.is_err());
    }
}
