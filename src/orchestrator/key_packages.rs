use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::Result;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

impl<S, A, C> MLSOrchestrator<S, A, C>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
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

        // Upload to server
        self.api_client()
            .publish_key_package(
                &kp_result.key_package_data,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                &expires_at_str,
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

        let needed = self.config().target_key_package_count - stats.available;
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
