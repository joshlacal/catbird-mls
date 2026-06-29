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
    /// Ensure the current device is registered with the MLS service.
    ///
    /// If already registered, returns the existing MLS DID.
    /// If not registered, generates a new identity, registers with the server,
    /// and stores credentials.
    pub async fn ensure_device_registered(&self) -> Result<String> {
        let user_did = self.require_user_did().await?;
        let identity_bytes = user_did.as_bytes().to_vec();

        // Durable signer reuse (prevents signing-key churn / orphaned key
        // packages): if a previously-exported full keypair survives in the
        // credential store (keychain/keystore), import it into the local crypto
        // context FIRST — before any `create_key_package` and before the
        // already-registered early-return. After a local-storage wipe/reinstall
        // the OpenMLS signer store is empty but the keychain key persists; this
        // makes the device register, publish, and process Welcomes under the
        // SAME identity it used before. (`clear_all` in the 0-KP recovery path
        // below only clears the credential store, not the now-imported OpenMLS
        // signer, so `create_key_package` still reuses this key.)
        //
        // We also use the import result as a SIGNER-SYNC SIGNAL. The durable key
        // is what the device was last registered under (we persist the exported
        // keypair right after every successful registration). If the import
        // adopts it as the active signer, the local crypto context and the
        // server's device key agree. If it does NOT adopt (no stored key, a
        // legacy public-only blob, or a stale/mismatched key), the local signer
        // has DIVERGED from the last-registered key — and the early-return below
        // must not trust stale server state, or published key packages get
        // rejected (device key != KP leaf key) and members can never open the
        // Welcomes built from the now-stale server key packages.
        let mut durable_signer_in_sync = false;
        if let Some(stored_key) = self.credentials().get_signing_key(&user_did).await? {
            match self
                .mls_context()
                .import_identity_key(identity_bytes.clone(), stored_key)
            {
                Ok(()) => {
                    durable_signer_in_sync = true;
                    tracing::info!("Imported durable signing key from credential store");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Stored signing key could not be adopted as the active signer; will re-register to reconcile")
                }
            }
        }

        // Check if already registered via credential store
        if self.credentials().has_credentials(&user_did).await? {
            if let Some(mls_did) = self.credentials().get_mls_did(&user_did).await? {
                tracing::debug!(mls_did = %mls_did, "Device already registered");

                // Only short-circuit when the server has key packages AND the
                // local signer is in sync with the last-registered key. A signer
                // mismatch falls through to re-registration, which updates the
                // server device's signature key + publishes fresh matching key
                // packages, self-healing the divergence.
                let stats = self.api_client().get_key_package_stats().await?;
                if stats.available > 0 && durable_signer_in_sync {
                    return Ok(mls_did);
                }

                if !durable_signer_in_sync {
                    tracing::warn!(
                        "Local signer diverged from the registered device key - re-registering to reconcile"
                    );
                    // The stale server device is keyed to a signer we no longer
                    // use, and re-registration below mints a FRESH device_uuid
                    // (so the server can't match + update the old row in place).
                    // Remove the stale device first so its now-unusable key
                    // packages can't be served to adders — otherwise a member is
                    // handed a key package whose private key this device doesn't
                    // hold and can never open the Welcome. `removeDevice` deletes
                    // the device row + its key packages + welcome messages; group
                    // memberships are untouched.
                    if let Some(stale_device_id) =
                        self.credentials().get_device_uuid(&user_did).await?
                    {
                        if let Err(e) = self.api_client().remove_device(&stale_device_id).await {
                            tracing::warn!(error = %e, "Failed to remove stale device before re-registration (continuing)");
                        } else {
                            tracing::info!(
                                stale_device_id = %stale_device_id,
                                "Removed stale divergent device before re-registration"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Device registered locally but 0 key packages on server - re-registering"
                    );
                }
                // Fall through to re-register
                self.credentials().clear_all(&user_did).await?;
            }
        }

        tracing::info!("Registering new device");

        // Generate device UUID
        let device_uuid = uuid::Uuid::new_v4().to_string();

        // Create MLS identity via FFI. If the durable key was imported above,
        // this reuses it; otherwise it mints (and we persist the full keypair
        // below so the next registration can reuse it).
        let kp_result = self
            .mls_context()
            .create_key_package(identity_bytes.clone())?;

        // The MLS credential identity uses the bare DID (matches iOS behavior).
        // The device UUID is tracked server-side via register_device, not in the credential.
        let mls_did = user_did.clone();

        // Register with server (include initial key package)
        let device_info = self
            .api_client()
            .register_device(
                &device_uuid,
                &get_device_name(),
                &mls_did,
                &kp_result.signature_public_key,
                std::slice::from_ref(&kp_result.key_package_data),
            )
            .await
            .map_err(|e| {
                // Check for device limit
                if let OrchestratorError::ServerError { status, .. } = &e {
                    if *status == 429 {
                        return OrchestratorError::DeviceLimitReached {
                            current: 10, // approximate
                            max: self.config().max_devices,
                        };
                    }
                }
                e
            })?;

        // Store credentials.
        //
        // The delivery service MINTS its own `device_id` and ignores the
        // client-supplied `device_uuid`, returning the minted id in
        // `device_info.device_id`. Every device-scoped call (publish, sync)
        // must reference that minted id, so persist it — not the throwaway
        // `device_uuid` we sent as the registration input. Storing the client
        // UUID here is what stranded fresh devices: publishes carried an id the
        // server never created and were rejected (403).
        self.credentials()
            .store_mls_did(&user_did, &mls_did)
            .await?;
        self.credentials()
            .store_device_uuid(&user_did, &device_info.device_id)
            .await?;
        // Persist the FULL signing keypair (not just the public key) so it can
        // be reimported after an app reinstall / local-storage wipe and reused
        // as the durable identity — see the import at the top of this fn. If
        // the crypto context can't export (platform hasn't wired the FFI), fall
        // back to the legacy public-key-only store (no durable reuse there).
        let signing_key_blob = match self
            .mls_context()
            .export_identity_key(identity_bytes.clone())
        {
            Ok(full_keypair) => full_keypair,
            Err(e) => {
                tracing::warn!(error = %e, "export_identity_key unavailable; storing public key only (durable reuse disabled on this platform)");
                kp_result.signature_public_key.clone()
            }
        };
        self.credentials()
            .store_signing_key(&user_did, &signing_key_blob)
            .await?;

        // Publish initial key packages
        tracing::info!("Publishing initial key packages");
        for _ in 0..self.config().target_key_package_count.min(20) {
            if let Err(e) = self.publish_key_package().await {
                tracing::warn!(error = %e, "Failed to publish initial key package");
                break;
            }
        }

        tracing::info!(
            device_id = %device_info.device_id,
            mls_did = %mls_did,
            "Device registered successfully"
        );
        Ok(mls_did)
    }

    /// List all registered devices for the current user.
    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        self.api_client().list_devices().await
    }

    /// Remove a device by ID.
    pub async fn remove_device(&self, device_id: &str) -> Result<()> {
        tracing::info!(device_id, "Removing device");
        self.api_client().remove_device(device_id).await
    }
}

/// Get a human-readable device name based on the platform.
fn get_device_name() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        "Catbird Web".to_string()
    }
    #[cfg(all(target_os = "macos", not(target_arch = "wasm32")))]
    {
        format!("Catmos Desktop ({})", hostname())
    }
    #[cfg(all(target_os = "ios", not(target_arch = "wasm32")))]
    {
        "Catbird iOS".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_arch = "wasm32")))]
    {
        format!("Catbird ({})", std::env::consts::OS)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "Unknown".to_string())
}
