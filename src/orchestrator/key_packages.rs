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
        let identity_bytes = user_did.as_bytes().to_vec();
        let kp_result = self.mls_context().create_key_package(identity_bytes)?;

        // Calculate expiry (30 days from now)
        let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
        let expires_at_str = expires_at.to_rfc3339();

        // Scope the publish to this device. The UUID is generated and stored
        // during `ensure_device_registered`, so it is always present by the
        // time we replenish; without it the server cannot bind the package to
        // the device signature key and rejects an unscoped fresh device (403).
        let device_uuid = self.credentials().get_device_uuid(&user_did).await?;

        // Upload to server
        self.api_client()
            .publish_key_package(
                &kp_result.key_package_data,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                &expires_at_str,
                device_uuid.as_deref(),
            )
            .await?;

        tracing::debug!("Key package published");
        Ok(())
    }

    /// Create and publish a reusable last-resort key package.
    ///
    /// A last-resort KP carries the MLS `last_resort` extension. The delivery
    /// service serves it only as a fallback — when a member has no regular
    /// single-use KP available — so it is the join floor: a recipient can
    /// always be invited even after its pool is drained by the orphan-reconcile
    /// or exhausted by failed joins. The bytes built here carry the extension,
    /// so the server detects it and marks the row `is_last_resort` (replacing
    /// the device's previous active last-resort); no wire flag is needed and
    /// the ordinary `publish_key_package` path is reused.
    ///
    /// `create_last_resort_key_package` is only available on crypto backends
    /// that support it (native `MLSContext`); the trait default returns
    /// `OperationNotSupported`, so callers should treat failures as best-effort.
    pub async fn publish_last_resort_key_package(&self) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::debug!("Publishing last-resort key package");

        let identity_bytes = user_did.as_bytes().to_vec();
        let kp_result = self
            .mls_context()
            .create_last_resort_key_package(identity_bytes)?;

        // Last-resort packages are long-lived by design; reuse the standard
        // 30-day expiry so the cleanup worker treats them like any other KP.
        let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
        let expires_at_str = expires_at.to_rfc3339();

        let device_uuid = self.credentials().get_device_uuid(&user_did).await?;

        self.api_client()
            .publish_key_package(
                &kp_result.key_package_data,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                &expires_at_str,
                device_uuid.as_deref(),
            )
            .await?;

        tracing::debug!("Last-resort key package published");
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

        for i in 0..needed {
            if let Err(e) = self.publish_key_package().await {
                tracing::error!(
                    error = %e,
                    published = i,
                    "Failed to publish key package during replenishment"
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
