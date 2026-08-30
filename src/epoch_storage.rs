// epoch_storage.rs
//
// Epoch secret storage and retrieval for forward secrecy with message history
//
// This module provides the bridge between Rust OpenMLS and Swift encrypted storage
// for retaining epoch secrets beyond OpenMLS's in-memory retention policy.

use crate::error::MLSError;
use crate::types::EpochSecretStorage;
use openmls::prelude::*;
use std::sync::{Arc, RwLock};

/// Epoch secret manager coordinating storage operations
pub struct EpochSecretManager {
    storage: Arc<RwLock<Option<Arc<dyn EpochSecretStorage>>>>,
}

impl EpochSecretManager {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the storage backend
    pub fn set_storage(&self, storage: Arc<dyn EpochSecretStorage>) -> Result<(), MLSError> {
        let mut lock = self
            .storage
            .write()
            .map_err(|_| MLSError::lock_poisoned("EpochSecretManager storage"))?;
        *lock = Some(storage);
        Ok(())
    }

    async fn persist_epoch_secret(
        &self,
        group_id_hex: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> Result<(), MLSError> {
        // Clone the storage Arc and release the lock before awaiting a host
        // callback. Absence is a configuration failure, not a best-effort
        // mode: callers rely on this method as their durable commit point.
        let storage = {
            let guard = self
                .storage
                .read()
                .map_err(|_| MLSError::lock_poisoned("EpochSecretManager storage"))?;
            guard.clone().ok_or(MLSError::StorageFailed)?
        };

        if !storage
            .store_epoch_secret(group_id_hex.clone(), epoch, secret_data)
            .await
        {
            crate::error_log!(
                "[EPOCH-STORAGE] Failed to durably store epoch secret: group={}, epoch={}",
                group_id_hex,
                epoch
            );
            return Err(MLSError::StorageFailed);
        }

        crate::info_log!(
            "[EPOCH-STORAGE] ✅ Stored epoch secret: group={}, epoch={}",
            group_id_hex,
            epoch
        );
        Ok(())
    }

    /// Export epoch secret for a group before epoch advance
    ///
    /// This should be called BEFORE processing a commit that advances the epoch.
    /// The exported secret allows decrypting messages from the current epoch
    /// even after the group has advanced to a new epoch.
    /// Uses the deterministic RFC 9420 exporter so retries produce the same
    /// durable value for a given group and epoch.
    pub async fn export_current_epoch_secret<Provider: OpenMlsProvider>(
        &self,
        group: &mut MlsGroup,
        provider: &Provider,
    ) -> Result<Vec<u8>, MLSError> {
        let group_id_hex = hex::encode(group.group_id().as_slice());
        let current_epoch = group.epoch().as_u64();

        crate::debug_log!(
            "[EPOCH-STORAGE] Exporting epoch secret for group {} epoch {}",
            group_id_hex,
            current_epoch
        );

        let label = format!("epoch_secret_{}", current_epoch);
        let context = group_id_hex.as_bytes();
        let secret = group
            .export_secret(provider.crypto(), &label, context, 32)
            .map_err(|e| {
                crate::error_log!(
                    "[EPOCH-STORAGE] ERROR: Failed to export epoch secret: {:?}",
                    e
                );
                MLSError::SecretExportFailed
            })?;

        crate::debug_log!(
            "[EPOCH-STORAGE] Exported {} bytes for epoch {}",
            secret.len(),
            current_epoch
        );

        self.persist_epoch_secret(group_id_hex, current_epoch, secret.clone())
            .await?;
        Ok(secret)
    }

    /// Delete epoch secrets older than the retention window.
    ///
    /// Call this after processing commits to enforce forward secrecy.
    /// The retention window allows decrypting delayed messages.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    /// * `current_epoch` - Current group epoch
    /// * `retention_epochs` - Number of past epochs to retain (default: 5)
    pub async fn cleanup_old_epochs(
        &self,
        group_id: &[u8],
        current_epoch: u64,
        retention_epochs: u64,
    ) -> Result<u32, MLSError> {
        let storage_clone = {
            match self.storage.read() {
                Ok(guard) => guard.clone(),
                Err(_) => {
                    crate::error_log!("[EPOCH-STORAGE] Lock poisoned in cleanup_old_epochs");
                    return Err(MLSError::lock_poisoned("EpochSecretManager storage"));
                }
            }
        };

        if let Some(storage) = storage_clone {
            let group_id_hex = hex::encode(group_id);
            let cutoff_epoch = current_epoch.saturating_sub(retention_epochs);

            let deleted = storage
                .delete_epochs_before(group_id_hex, cutoff_epoch)
                .await;

            if deleted > 0 {
                crate::info_log!(
                    "[EPOCH-CLEANUP] Deleted {} old epoch secrets for group (cutoff: epoch {})",
                    deleted,
                    cutoff_epoch
                );
            }

            Ok(deleted)
        } else {
            Err(MLSError::StorageFailed)
        }
    }

    /// Delete one exact externally stored epoch secret during compensating
    /// rollback. Welcome adoption exports before publishing the group, so any
    /// later failure must remove that Tier-0 secret rather than orphaning it.
    pub async fn delete_exact_epoch_secret(
        &self,
        group_id: &[u8],
        epoch: u64,
    ) -> Result<(), MLSError> {
        let storage = {
            let guard = self
                .storage
                .read()
                .map_err(|_| MLSError::lock_poisoned("EpochSecretManager storage"))?;
            guard.clone().ok_or(MLSError::StorageFailed)?
        };
        let group_id_hex = hex::encode(group_id);
        if !storage
            .delete_epoch_secret(group_id_hex.clone(), epoch)
            .await
        {
            crate::error_log!(
                "[EPOCH-STORAGE] Failed to delete exact rollback secret: group={}, epoch={}",
                group_id_hex,
                epoch
            );
            return Err(MLSError::StorageFailed);
        }
        crate::info_log!(
            "[EPOCH-STORAGE] Deleted exact rollback secret: group={}, epoch={}",
            group_id_hex,
            epoch
        );
        Ok(())
    }
}

impl Default for EpochSecretManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestEpochSecretStorage {
        store_result: bool,
        store_calls: AtomicUsize,
        delete_result: bool,
        delete_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl EpochSecretStorage for TestEpochSecretStorage {
        async fn store_epoch_secret(
            &self,
            _conversation_id: String,
            _epoch: u64,
            _secret_data: Vec<u8>,
        ) -> bool {
            self.store_calls.fetch_add(1, Ordering::SeqCst);
            self.store_result
        }

        async fn get_epoch_secret(&self, _conversation_id: String, _epoch: u64) -> Option<Vec<u8>> {
            None
        }

        async fn delete_epoch_secret(&self, _conversation_id: String, _epoch: u64) -> bool {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            self.delete_result
        }

        async fn delete_epochs_before(&self, _conversation_id: String, _cutoff_epoch: u64) -> u32 {
            0
        }
    }

    #[tokio::test]
    async fn missing_epoch_secret_storage_fails_closed() {
        let manager = EpochSecretManager::new();

        let error = manager
            .persist_epoch_secret("group".to_string(), 7, vec![1, 2, 3])
            .await
            .expect_err("an absent durable store must reject the epoch transition");

        assert!(matches!(error, MLSError::StorageFailed));
    }

    #[tokio::test]
    async fn false_epoch_secret_storage_result_fails_closed() {
        let manager = EpochSecretManager::new();
        let storage = Arc::new(TestEpochSecretStorage {
            store_result: false,
            store_calls: AtomicUsize::new(0),
            delete_result: false,
            delete_calls: AtomicUsize::new(0),
        });
        manager.set_storage(storage.clone()).unwrap();

        let error = manager
            .persist_epoch_secret("group".to_string(), 7, vec![1, 2, 3])
            .await
            .expect_err("a rejected durable write must reject the epoch transition");

        assert!(matches!(error, MLSError::StorageFailed));
        assert_eq!(storage.store_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn successful_epoch_secret_storage_result_is_accepted() {
        let manager = EpochSecretManager::new();
        let storage = Arc::new(TestEpochSecretStorage {
            store_result: true,
            store_calls: AtomicUsize::new(0),
            delete_result: true,
            delete_calls: AtomicUsize::new(0),
        });
        manager.set_storage(storage.clone()).unwrap();

        manager
            .persist_epoch_secret("group".to_string(), 7, vec![1, 2, 3])
            .await
            .expect("a confirmed durable write must remain supported");

        assert_eq!(storage.store_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_epoch_secret_delete_propagates_backend_result() {
        let manager = EpochSecretManager::new();
        let storage = Arc::new(TestEpochSecretStorage {
            store_result: true,
            store_calls: AtomicUsize::new(0),
            delete_result: true,
            delete_calls: AtomicUsize::new(0),
        });
        manager.set_storage(storage.clone()).unwrap();

        manager
            .delete_exact_epoch_secret(b"group", 7)
            .await
            .expect("confirmed exact delete must succeed");
        assert_eq!(storage.delete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn repeated_epoch_export_is_idempotent() {
        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("create signer");
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:epoch-export".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .capabilities(crate::mls_context::metadata_leaf_capabilities())
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(b"epoch-export-group"),
            credential_with_key,
        )
        .expect("create group");
        let manager = EpochSecretManager::new();
        let storage = Arc::new(TestEpochSecretStorage {
            store_result: true,
            store_calls: AtomicUsize::new(0),
            delete_result: true,
            delete_calls: AtomicUsize::new(0),
        });
        manager.set_storage(storage.clone()).unwrap();

        let first = manager
            .export_current_epoch_secret(&mut group, &provider)
            .await
            .expect("first export");
        let second = manager
            .export_current_epoch_secret(&mut group, &provider)
            .await
            .expect("repeated export must be accepted");

        assert_eq!(first, second);
        assert_eq!(storage.store_calls.load(Ordering::SeqCst), 2);
    }
}
