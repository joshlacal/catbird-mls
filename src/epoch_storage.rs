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

    /// Export epoch secret for a group before epoch advance
    ///
    /// This should be called BEFORE processing a commit that advances the epoch.
    /// The exported secret allows decrypting messages from the current epoch
    /// even after the group has advanced to a new epoch.
    pub async fn export_current_epoch_secret(
        &self,
        group: &MlsGroup,
        provider: &impl OpenMlsProvider,
    ) -> Result<Vec<u8>, MLSError> {
        let group_id_hex = hex::encode(group.group_id().as_slice());
        let current_epoch = group.epoch().as_u64();

        crate::debug_log!(
            "[EPOCH-STORAGE] Exporting epoch secret for group {} epoch {}",
            group_id_hex,
            current_epoch
        );

        // Export the epoch secret using OpenMLS export_secret API
        // This derives a secret from the current epoch's key schedule
        let label = format!("epoch_secret_{}", current_epoch);
        let context = group_id_hex.as_bytes();

        let secret = group
            .export_secret(provider.crypto(), &label, context, 32) // 32 bytes = 256 bits
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

        // Clone the storage Arc and release lock before awaiting
        let storage_clone = {
            let guard = self
                .storage
                .read()
                .map_err(|_| MLSError::lock_poisoned("EpochSecretManager storage"))?;
            guard.clone()
        }; // Lock released here

        // Now safe to await without holding the lock
        if let Some(storage) = storage_clone {
            let result = storage
                .store_epoch_secret(group_id_hex.clone(), current_epoch, secret.to_vec())
                .await;

            if result {
                crate::info_log!(
                    "[EPOCH-STORAGE] ✅ Stored epoch secret: group={}, epoch={}",
                    group_id_hex,
                    current_epoch
                );
            } else {
                crate::warn_log!("[EPOCH-STORAGE] ⚠️ Failed to store epoch secret");
            }
        }

        Ok(secret.to_vec())
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
}

impl Default for EpochSecretManager {
    fn default() -> Self {
        Self::new()
    }
}
