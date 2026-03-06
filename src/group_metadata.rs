use crate::error::MLSError;
use openmls::prelude::*;
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
                    .map_err(|e| tracing::warn!("Failed to decode GroupMetadata extension: {e}"))
                    .ok()
            })
    }
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
}
