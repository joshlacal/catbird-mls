use async_trait::async_trait;

use super::error::Result;

#[cfg(not(target_arch = "wasm32"))]
pub trait CredentialStoreBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> CredentialStoreBounds for T {}

#[cfg(target_arch = "wasm32")]
pub trait CredentialStoreBounds {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> CredentialStoreBounds for T {}

/// Platform-agnostic credential/keychain access for MLS identity management.
///
/// On iOS this wraps Keychain; on desktop it can use OS keyring or encrypted file.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CredentialStore: CredentialStoreBounds {
    /// Store a signing key for a user DID.
    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()>;

    /// Retrieve the signing key for a user DID.
    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>>;

    /// Delete the signing key for a user DID.
    async fn delete_signing_key(&self, user_did: &str) -> Result<()>;

    /// Store the MLS DID (device-specific identity) for a user.
    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()>;

    /// Retrieve the MLS DID for a user.
    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>>;

    /// Store a device UUID.
    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()>;

    /// Retrieve the device UUID.
    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>>;

    /// Check if credentials exist for a user (device is registered).
    async fn has_credentials(&self, user_did: &str) -> Result<bool>;

    /// Clear all credentials for a user (used during recovery).
    async fn clear_all(&self, user_did: &str) -> Result<()>;
}
