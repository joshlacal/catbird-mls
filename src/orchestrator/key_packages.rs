use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::Result;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Publish a single key package to the server.
    ///
    /// Creates a key package locally via FFI, then uploads it.
    pub async fn publish_key_package(&self) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::debug!("Publishing key package");

        // Create key package via FFI
        let device_uuid = self
            .credentials()
            .get_device_uuid(&user_did)
            .await?
            .ok_or_else(|| {
                super::error::OrchestratorError::Credential(
                    "cannot create a key package before verified device enrollment".into(),
                )
            })?;
        let identity_bytes = format!("{user_did}#{device_uuid}").into_bytes();
        let kp_result = self.mls_context().create_key_package(identity_bytes)?;

        // Calculate expiry (30 days from now)
        let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
        let expires_at_str = expires_at.to_rfc3339();

        // Scope the publish to this device. The UUID is generated and stored
        // during `ensure_device_registered`, so it is always present by the
        // time we replenish; without it the server cannot bind the package to
        // the device signature key and rejects an unscoped fresh device (403).
        // Upload to server
        self.api_client()
            .publish_key_package(
                &kp_result.key_package_data,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                &expires_at_str,
                Some(&device_uuid),
            )
            .await?;

        tracing::debug!("Key package published");
        Ok(())
    }

    /// Check key package count on server and replenish if needed.
    ///
    /// Mirrors the Swift `smartRefreshKeyPackages` logic:
    /// - Check server stats
    /// - If below threshold, publish enough to reach target count
    pub async fn replenish_if_needed(&self) -> Result<()> {
        self.check_shutdown().await?;

        // Before checking the count, reconcile the server's published pool
        // against what we actually hold locally. The server only learns a key
        // package was used when ITS OWN handler seals a Welcome to it; if we
        // drop a KP's private key for any other reason (consumed on a join the
        // server didn't broker, a local storage reset, a reinstall), the server
        // keeps serving it `available` and any recipient who fetches it fails
        // with `NoMatchingKeyPackage`. `syncKeyPackages` deletes server KPs that
        // are NOT in our live local set, draining those stale entries; the
        // count check below then republishes fresh ones if we dropped below
        // threshold. Best-effort: a failure here must not block replenishment.
        //
        // SAFETY: only sync when we have a non-empty local set. An empty list
        // would make the server treat its ENTIRE pool as orphaned and delete
        // it; an empty result here means "unknown" (uninitialized/locked
        // context), not "I hold nothing".
        match self.mls_context().list_key_package_hashes() {
            Ok(local_hashes) if !local_hashes.is_empty() => {
                match self.sync_key_package_hashes(&local_hashes).await {
                    Ok(result) => tracing::info!(
                        local = local_hashes.len(),
                        orphaned = result.orphaned_count,
                        deleted = result.deleted_count,
                        "Reconciled server key packages against local store"
                    ),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "key package orphan-drain (syncKeyPackages) failed; continuing to replenish"
                    ),
                }
            }
            Ok(_) => tracing::debug!(
                "Skipping key package orphan-drain: no local hashes (uninitialized?)"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "Could not list local key package hashes; skipping orphan-drain"
            ),
        }

        let stats = self.api_client().get_key_package_stats().await?;

        tracing::debug!(
            available = stats.available,
            threshold = self.config().key_package_replenish_threshold,
            target = self.config().target_key_package_count,
            "Checking key package levels"
        );

        if stats.available >= self.config().key_package_replenish_threshold {
            return Ok(());
        }

        let needed = self
            .config()
            .target_key_package_count
            .saturating_sub(stats.available);
        if needed == 0 {
            return Ok(());
        }
        tracing::info!(
            available = stats.available,
            needed,
            "Replenishing key packages"
        );

        // Generate the whole batch locally first, then publish it in a single
        // request. Each `create_key_package` call persists the bundle to local
        // storage as a side effect, so the KPs survive even if the upload
        // fails. Batching collapses what used to be `needed` SEQUENTIAL HTTP
        // POSTs (the single-KP callback) into one round-trip — that serial
        // publish ran on the startup/account-switch critical path and blocked
        // message loading.
        let user_did = self.require_user_did().await?;
        let device_uuid = self
            .credentials()
            .get_device_uuid(&user_did)
            .await?
            .ok_or_else(|| {
                super::error::OrchestratorError::Credential(
                    "cannot replenish key packages before verified device enrollment".into(),
                )
            })?;
        let identity_bytes = format!("{user_did}#{device_uuid}").into_bytes();
        let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(needed as usize);
        for i in 0..needed {
            match self
                .mls_context()
                .create_key_package(identity_bytes.clone())
            {
                Ok(kp) => batch.push(kp.key_package_data),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        generated = i,
                        "Failed to create key package during replenishment"
                    );
                    break;
                }
            }
        }

        // Respect the delivery service's MAX_BATCH_SIZE (100). `needed` is
        // bounded by the target (50 today), so this is a single chunk, but
        // chunk defensively in case the target ever grows.
        for chunk in batch.chunks(100) {
            if let Err(e) = self
                .api_client()
                .publish_key_packages(
                    chunk,
                    "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    &expires_at,
                    Some(device_uuid.as_str()),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    batch = chunk.len(),
                    "Failed to publish key package batch during replenishment"
                );
                break;
            }
        }

        Ok(())
    }

    /// Get current key package stats from the server.
    pub async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        self.api_client().get_key_package_stats().await
    }

    /// Sync local key package hashes with the server to clean up orphans.
    pub async fn sync_key_package_hashes(
        &self,
        local_hashes: &[String],
    ) -> Result<KeyPackageSyncResult> {
        let device_uuid = self
            .credentials()
            .get_device_uuid(&self.require_user_did().await?)
            .await?
            .unwrap_or_default();

        self.api_client()
            .sync_key_packages(local_hashes, &device_uuid)
            .await
    }
}
