use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
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

        // Publish key package using signed canonical request
        self.publish_key_packages_batch(&[kp_result]).await?;
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

        let mut batch: Vec<crate::types::KeyPackageResult> = Vec::with_capacity(needed as usize);
        for i in 0..needed {
            match self
                .mls_context()
                .create_key_package(identity_bytes.clone())
            {
                Ok(kp) => batch.push(kp),
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

        for chunk in batch.chunks(100) {
            if let Err(e) = self.publish_key_packages_batch(chunk).await {
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

    async fn publish_key_packages_batch(
        &self,
        key_packages: &[crate::types::KeyPackageResult],
    ) -> Result<()> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::{Digest, Sha256};
        let user_did = self.require_user_did().await?;
        let device_uuid = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        let identity_bytes = format!("{user_did}#{device_uuid}").into_bytes();
        let public_key = self.mls_context().identity_public_key(identity_bytes)?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);

        let mut sorted_packages = key_packages.to_vec();
        sorted_packages.sort_by(|a, b| a.hash_ref.cmp(&b.hash_ref));

        let mut packages_json = Vec::with_capacity(sorted_packages.len());
        for kp in &sorted_packages {
            packages_json.push(serde_json::json!({
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": { "$bytes": STANDARD.encode(&kp.key_package_data) },
                "sha256": STANDARD.encode(Sha256::digest(&kp.key_package_data)),
                "keyPackageRef": { "$bytes": STANDARD.encode(&kp.hash_ref) }
            }));
        }
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
            "actorDid": user_did,
            "actorDeviceId": device_uuid,
            "authGeneration": auth_generation,
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "keyPackages": packages_json,
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\0",
            "signaturePublicKey": { "$bytes": STANDARD.encode(&public_key) },
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });
        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::ReplenishKeyPackages,
                serde_json::to_vec(&body)
                    .map_err(|e| super::error::OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;
        if response.status != 200 {
            return Err(super::error::OrchestratorError::Api(format!(
                "replenish_key_packages failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }
        Ok(())
    }
}
