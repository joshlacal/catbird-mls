//! In-memory mock implementation of `CredentialStore` for testing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use catbird_mls::orchestrator::credentials::{CleanChatSigningAuthority, CredentialStore};
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;

/// Per-user credential state.
#[derive(Debug, Clone, Default)]
struct UserCredentials {
    mls_did: Option<String>,
    device_uuid: Option<String>,
    signing_key: Option<Vec<u8>>,
    clean_chat_binding: Option<CleanChatBindingSnapshot>,
    clean_chat_authority: Option<CleanChatSigningAuthority>,
}

#[derive(Debug, Clone)]
struct CleanChatBindingSnapshot {
    device_id: String,
    dpop_jkt: String,
    auth_generation: Option<i64>,
}

/// In-memory `CredentialStore` with per-user isolation via `Arc<Mutex<...>>`.
#[derive(Debug, Clone)]
pub struct MockCredentials {
    state: Arc<Mutex<HashMap<String, UserCredentials>>>,
    /// WS-3 stage 2: configurable authorized-device-key sets per root DID.
    /// DID absent from the map → `get_authorized_device_keys` returns
    /// `Ok(None)` (the trait default: "no DID-resolution surface").
    authorized_device_keys: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
    /// Number of `get_authorized_device_keys` calls per DID — used by the
    /// ADR-009 D6 cache test to prove no repeat resolution within the TTL.
    device_key_lookup_counts: Arc<Mutex<HashMap<String, u32>>>,
    /// DIDs whose authorized-device resolver should fail closed. This models
    /// transient platform/network failures separately from `Ok(None)`, which
    /// means the resolver capability is unsupported.
    authorized_device_key_failures: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl MockCredentials {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            authorized_device_keys: Arc::new(Mutex::new(HashMap::new())),
            device_key_lookup_counts: Arc::new(Mutex::new(HashMap::new())),
            authorized_device_key_failures: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// WS-3 stage 2: declare the authorized MLS device signing keys for a
    /// root DID. Once set, lookups for that DID resolve (`Ok(Some(keys))`);
    /// DIDs without an entry still return the unsupported default.
    pub fn set_authorized_device_keys(&self, root_did: &str, keys: Vec<Vec<u8>>) {
        self.authorized_device_keys
            .lock()
            .unwrap()
            .insert(root_did.to_string(), keys);
    }

    /// Remove the resolver capability for one DID. Used to prove that the
    /// orchestrator fails closed when ADR-009 device-key authority is absent.
    pub fn clear_authorized_device_keys(&self, root_did: &str) {
        self.authorized_device_keys.lock().unwrap().remove(root_did);
    }

    /// Number of `get_authorized_device_keys` calls observed for a DID.
    pub fn device_key_lookup_count(&self, root_did: &str) -> u32 {
        self.device_key_lookup_counts
            .lock()
            .unwrap()
            .get(root_did)
            .copied()
            .unwrap_or(0)
    }
    /// Make authorized-device resolution return an infrastructure error for
    /// `root_did` until the test explicitly clears it.
    #[allow(dead_code)]
    pub fn set_authorized_device_key_resolution_failure(&self, root_did: &str, fail: bool) {
        let mut failures = self.authorized_device_key_failures.lock().unwrap();
        if fail {
            failures.insert(root_did.to_string());
        } else {
            failures.remove(root_did);
        }
    }

    /// Install an explicit authority snapshot for negative binding tests.
    /// The signing key itself remains in the Rust-only mock state and never
    /// participates in the callback-shaped authority record.
    #[allow(dead_code)]
    pub fn set_clean_chat_authority(&self, authority: CleanChatSigningAuthority) {
        let mut map = self.state.lock().unwrap();
        map.entry("__test_authority__".to_string())
            .or_default()
            .clean_chat_authority = Some(authority);
    }

    /// Install the trusted binding snapshot used by the Rust-only signer mock.
    #[allow(dead_code)]
    pub fn set_clean_chat_binding(
        &self,
        user_did: &str,
        device_id: &str,
        dpop_jkt: &str,
        auth_generation: Option<i64>,
    ) {
        let mut map = self.state.lock().unwrap();
        map.entry(user_did.to_string())
            .or_default()
            .clean_chat_binding = Some(CleanChatBindingSnapshot {
            device_id: device_id.to_owned(),
            dpop_jkt: dpop_jkt.to_owned(),
            auth_generation,
        });
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

    async fn sign_clean_chat_transcript(
        &self,
        user_did: &str,
        transcript: &[u8],
        _key_id: &str,
    ) -> Result<Option<CleanChatSigningAuthority>> {
        let (key_data, binding, explicit, device_uuid) = {
            let map = self.state.lock().unwrap();
            (
                map.get(user_did).and_then(|c| c.signing_key.clone()),
                map.get(user_did).and_then(|c| c.clean_chat_binding.clone()),
                map.get("__test_authority__")
                    .and_then(|c| c.clean_chat_authority.clone()),
                map.get(user_did).and_then(|c| c.device_uuid.clone()),
            )
        };
        if let Some(authority) = explicit {
            return Ok(Some(authority));
        }
        let Some(key_data) = key_data else {
            return Ok(None);
        };
        let (device_id, auth_generation) = if let Some(binding) = binding {
            (binding.device_id, binding.auth_generation)
        } else if let Some(uuid) = device_uuid {
            (uuid, Some(1))
        } else {
            return Ok(None);
        };
        let signer: SignatureKeyPair = serde_json::from_slice(&key_data).map_err(|_| {
            catbird_mls::orchestrator::error::OrchestratorError::Storage(
                "test signer is invalid".into(),
            )
        })?;
        let signature = signer.sign(transcript).map_err(|_| {
            catbird_mls::orchestrator::error::OrchestratorError::Storage(
                "test signer failed".into(),
            )
        })?;
        Ok(Some(CleanChatSigningAuthority {
            public_key: signer.public().to_vec(),
            signature,
            device_id,
            auth_generation,
        }))
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

    async fn get_authorized_device_keys(&self, root_did: &str) -> Result<Option<Vec<Vec<u8>>>> {
        *self
            .device_key_lookup_counts
            .lock()
            .unwrap()
            .entry(root_did.to_string())
            .or_default() += 1;
        if self
            .authorized_device_key_failures
            .lock()
            .unwrap()
            .contains(root_did)
        {
            return Err(OrchestratorError::Credential(format!(
                "authorized-device resolver failed for {root_did}"
            )));
        }
        Ok(self
            .authorized_device_keys
            .lock()
            .unwrap()
            .get(root_did)
            .cloned())
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
