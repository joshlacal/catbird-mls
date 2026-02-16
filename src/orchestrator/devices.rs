use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

impl<S, A, C> MLSOrchestrator<S, A, C>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
{
    /// Ensure the current device is registered with the MLS service.
    ///
    /// If already registered, returns the existing MLS DID.
    /// If not registered, generates a new identity, registers with the server,
    /// and stores credentials.
    pub async fn ensure_device_registered(&self) -> Result<String> {
        let user_did = self.require_user_did().await?;

        // Check if already registered via credential store
        if self.credentials().has_credentials(&user_did).await? {
            if let Some(mls_did) = self.credentials().get_mls_did(&user_did).await? {
                tracing::debug!(mls_did = %mls_did, "Device already registered");

                // Verify key packages exist on server
                let stats = self.api_client().get_key_package_stats().await?;
                if stats.available > 0 {
                    return Ok(mls_did);
                }

                tracing::warn!(
                    "Device registered locally but 0 key packages on server - re-registering"
                );
                // Fall through to re-register
                self.credentials().clear_all(&user_did).await?;
            }
        }

        tracing::info!("Registering new device");

        // Generate device UUID
        let device_uuid = uuid::Uuid::new_v4().to_string();

        // Create MLS identity via FFI
        let identity_bytes = user_did.as_bytes().to_vec();
        let kp_result = self.mls_context().create_key_package(identity_bytes)?;

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
                &kp_result.hash_ref,
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

        // Store credentials
        self.credentials()
            .store_mls_did(&user_did, &mls_did)
            .await?;
        self.credentials()
            .store_device_uuid(&user_did, &device_uuid)
            .await?;
        self.credentials()
            .store_signing_key(&user_did, &kp_result.hash_ref)
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
    #[cfg(target_os = "macos")]
    {
        format!("Catmos Desktop ({})", hostname())
    }
    #[cfg(target_os = "ios")]
    {
        "Catbird iOS".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        format!("Catbird ({})", std::env::consts::OS)
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "Unknown".to_string())
}
