//! In-memory mock implementation of `CredentialStore` for testing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::Result;

/// Per-user credential state.
#[derive(Debug, Clone, Default)]
struct UserCredentials {
    mls_did: Option<String>,
    device_uuid: Option<String>,
    signing_key: Option<Vec<u8>>,
}

/// In-memory `CredentialStore` with per-user isolation via `Arc<Mutex<...>>`.
#[derive(Debug, Clone)]
pub struct MockCredentials {
    state: Arc<Mutex<HashMap<String, UserCredentials>>>,
}

impl MockCredentials {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MockCredentials {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialStore for MockCredentials {
    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        let mut map = self.state.lock().unwrap();
        map.entry(user_did.to_string()).or_default().signing_key = Some(key_data.to_vec());
        Ok(())
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        let map = self.state.lock().unwrap();
        Ok(map.get(user_did).and_then(|c| c.signing_key.clone()))
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        let mut map = self.state.lock().unwrap();
        if let Some(creds) = map.get_mut(user_did) {
            creds.signing_key = None;
        }
        Ok(())
    }

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        let mut map = self.state.lock().unwrap();
        map.entry(user_did.to_string()).or_default().mls_did = Some(mls_did.to_string());
        Ok(())
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        let map = self.state.lock().unwrap();
        Ok(map.get(user_did).and_then(|c| c.mls_did.clone()))
    }

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        let mut map = self.state.lock().unwrap();
        map.entry(user_did.to_string()).or_default().device_uuid = Some(uuid.to_string());
        Ok(())
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        let map = self.state.lock().unwrap();
        Ok(map.get(user_did).and_then(|c| c.device_uuid.clone()))
    }

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        let map = self.state.lock().unwrap();
        Ok(map
            .get(user_did)
            .map_or(false, |c| c.mls_did.is_some() && c.device_uuid.is_some()))
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        let mut map = self.state.lock().unwrap();
        map.remove(user_did);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_and_retrieve() {
        let creds = MockCredentials::new();
        let did = "did:plc:test123";

        assert!(!creds.has_credentials(did).await.unwrap());

        creds.store_mls_did(did, "did:plc:mls456").await.unwrap();
        creds.store_device_uuid(did, "uuid-789").await.unwrap();
        creds.store_signing_key(did, b"secret-key").await.unwrap();

        assert!(creds.has_credentials(did).await.unwrap());
        assert_eq!(
            creds.get_mls_did(did).await.unwrap().as_deref(),
            Some("did:plc:mls456")
        );
        assert_eq!(
            creds.get_device_uuid(did).await.unwrap().as_deref(),
            Some("uuid-789")
        );
        assert_eq!(
            creds.get_signing_key(did).await.unwrap().as_deref(),
            Some(b"secret-key".as_slice())
        );
    }

    #[tokio::test]
    async fn clear_all_resets_state() {
        let creds = MockCredentials::new();
        let did = "did:plc:test";

        creds.store_mls_did(did, "mls").await.unwrap();
        creds.store_device_uuid(did, "uuid").await.unwrap();
        creds.store_signing_key(did, b"key").await.unwrap();
        assert!(creds.has_credentials(did).await.unwrap());

        creds.clear_all(did).await.unwrap();
        assert!(!creds.has_credentials(did).await.unwrap());
        assert!(creds.get_mls_did(did).await.unwrap().is_none());
        assert!(creds.get_signing_key(did).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn per_user_isolation() {
        let creds = MockCredentials::new();

        creds.store_mls_did("user-a", "mls-a").await.unwrap();
        creds.store_device_uuid("user-a", "uuid-a").await.unwrap();
        creds.store_mls_did("user-b", "mls-b").await.unwrap();

        assert!(creds.has_credentials("user-a").await.unwrap());
        assert!(!creds.has_credentials("user-b").await.unwrap());
        assert_eq!(
            creds.get_mls_did("user-a").await.unwrap().as_deref(),
            Some("mls-a")
        );
        assert_eq!(
            creds.get_mls_did("user-b").await.unwrap().as_deref(),
            Some("mls-b")
        );
    }

    #[tokio::test]
    async fn delete_signing_key() {
        let creds = MockCredentials::new();
        let did = "did:plc:test";

        creds.store_signing_key(did, b"key").await.unwrap();
        assert!(creds.get_signing_key(did).await.unwrap().is_some());

        creds.delete_signing_key(did).await.unwrap();
        assert!(creds.get_signing_key(did).await.unwrap().is_none());
    }
}
