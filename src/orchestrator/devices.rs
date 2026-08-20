use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Reconcile the local MLS signer with the durable signer last persisted
    /// after successful device registration.
    ///
    /// This helper intentionally performs only credential-store access and
    /// local signer import. Callers that merely need proof-of-possession must
    /// not trigger device removal, registration, or key-package publication.
    /// The result preserves all three security-relevant states: `None` means
    /// no durable signer exists, `Some(true)` means it was adopted, and
    /// `Some(false)` means durable material existed but could not be adopted.
    pub(crate) async fn reconcile_durable_signer(&self, user_did: &str) -> Result<Option<bool>> {
        let Some(stored_key) = self.credentials().get_signing_key(user_did).await? else {
            return Ok(None);
        };

        match self
            .mls_context()
            .import_identity_key(user_did.as_bytes().to_vec(), stored_key)
        {
            Ok(()) => {
                tracing::info!("Imported durable signing key from credential store");
                Ok(Some(true))
            }
            Err(error) => {
                tracing::warn!(error = %error, "Stored signing key could not be adopted as the active signer; reconciliation required");
                Ok(Some(false))
            }
        }
    }

    /// Ensure the current device is registered with the MLS service.
    ///
    /// If already registered, returns the existing MLS DID.
    /// If not registered, generates a new identity, registers with the server,
    /// and stores credentials.
    pub async fn ensure_device_registered(&self) -> Result<String> {
        let user_did = self.require_user_did().await?;

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
        let durable_signer_in_sync = self
            .reconcile_durable_signer(&user_did)
            .await?
            .unwrap_or(false);

        // Local custody is never sufficient readiness evidence. Always ask the
        // server for this account's devices before taking the fast path.
        if self.credentials().has_credentials(&user_did).await? {
            if let Some(mls_did) = self.credentials().get_mls_did(&user_did).await? {
                let local_device_id = self.credentials().get_device_uuid(&user_did).await?;
                let local_public_key = self
                    .mls_context()
                    .identity_public_key(mls_did.as_bytes().to_vec())
                    .ok();
                let server_device = match local_device_id.as_deref() {
                    Some(device_id) => self
                        .api_client()
                        .list_devices(device_id)
                        .await?
                        .into_iter()
                        .find(|device| device.device_id == device_id),
                    None => None,
                };
                let server_matches_custody = server_device.as_ref().is_some_and(|device| {
                    device.status.as_deref() == Some("active")
                        && device
                            .auth_generation
                            .is_some_and(|generation| generation >= 1)
                        && device
                            .available_package_count
                            .is_some_and(|count| count > 0)
                        && device.signature_public_key.as_ref() == local_public_key.as_ref()
                        && device.key_id.as_deref().is_some_and(|key_id| {
                            local_public_key.as_ref().is_some_and(|public_key| {
                                super::canonical_transport::derive_key_id(public_key) == key_id
                            })
                        })
                });
                if server_matches_custody && durable_signer_in_sync {
                    return Ok(mls_did);
                }

                if !durable_signer_in_sync {
                    tracing::warn!(
                        "Local signer diverged from the registered device key - re-registering to reconcile"
                    );
                    // Never overwrite or delete the mismatched server identity
                    // silently. Enrollment below uses a new UUID and signer.
                } else {
                    tracing::warn!(
                        "Server device projection does not match local custody - enrolling a fresh device"
                    );
                }
                // Fall through to re-register
                self.credentials().clear_all(&user_did).await?;
            }
        }

        tracing::info!("Registering new device");

        // Generate device UUID
        let device_uuid = uuid::Uuid::new_v4().to_string();
        let mls_did = format!("{user_did}#{device_uuid}");
        let identity_bytes = mls_did.as_bytes().to_vec();

        // Create MLS identity via FFI. If the durable key was imported above,
        // this reuses it; otherwise it mints (and we persist the full keypair
        // below so the next registration can reuse it).
        let kp_result = self
            .mls_context()
            .create_key_package(identity_bytes.clone())?;

        let key_id = super::canonical_transport::derive_key_id(&kp_result.signature_public_key);
        let signed_at = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": super::canonical_transport::DEVICE_ENROLL_SIGNATURE_DOMAIN,
            "actorDid": user_did,
            "deviceId": device_uuid,
            "deviceName": get_device_name(),
            "keyId": key_id,
            "signaturePublicKey": B64.encode(&kp_result.signature_public_key),
            "expectedAuthGeneration": 0,
            "capability": {
                "protocolVersion": "1",
                "mlsVersion": "1.0",
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "credentialType": "basic",
                "addByValue": "supported",
                "updatePath": "supported",
                "removeByValue": "supported",
                "ratchetTreeGroupInfo": "supported",
                "externalPubGroupInfo": "presentButExternalCommitsForbidden",
                "applicationFrameProfile": "dagCborApplication1",
                "controlProfile": "publicGroup1",
                "attachmentProfile": "aes256GcmBlob1",
                "metadataProfile": "exporterAes256Gcm1",
                "typingProfile": "signedClearEphemeral1"
            },
            "keyPackages": [{
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": B64.encode(&kp_result.key_package_data),
                "sha256": B64.encode(Sha256::digest(&kp_result.key_package_data)),
                "keyPackageRef": B64.encode(&kp_result.hash_ref)
            }],
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "signedAt": signed_at
        });
        let binding = super::canonical_transport::CleanChatSigningContext {
            actor_did: user_did.clone(),
            device_id: device_uuid.clone(),
            auth_generation: None,
        };
        let prepared = super::canonical_transport::prepare_signed_request_with(
            &binding,
            super::canonical_transport::CanonicalOperation::EnrollDevice,
            serde_json::to_vec(&body).map_err(|error| {
                OrchestratorError::Credential(format!("serialize enrollment: {error}"))
            })?,
            |transcript| {
                self.mls_context()
                    .sign_with_identity_key(identity_bytes.clone(), transcript.to_vec())
                    .map_err(|_| super::canonical_transport::TransportError::Signing)
            },
        )
        .map_err(|error| OrchestratorError::Credential(error.to_string()))?;
        let prepared_request_body = prepared.body.ok_or_else(|| {
            OrchestratorError::Credential("prepared enrollment has no body".into())
        })?;

        // Register with server (include initial key package)
        let device_info = self
            .api_client()
            .register_device(
                &device_uuid,
                &get_device_name(),
                &mls_did,
                &kp_result.signature_public_key,
                std::slice::from_ref(&kp_result.key_package_data),
                &prepared_request_body,
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

        if device_info.device_id != device_uuid {
            return Err(OrchestratorError::Credential(format!(
                "server substituted device ID {} for client ID {}",
                device_info.device_id, device_uuid
            )));
        }

        // Persist the signer receipt and authoritative client UUID only after
        // successful (or exact-idempotent) enrollment.
        self.credentials()
            .store_mls_did(&user_did, &mls_did)
            .await?;
        self.credentials()
            .store_device_uuid(&user_did, &device_uuid)
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
        let user_did = self.require_user_did().await?;
        let device_id = self
            .credentials()
            .get_device_uuid(&user_did)
            .await?
            .ok_or_else(|| {
                OrchestratorError::Credential(
                    "cannot read devices before verified device enrollment".into(),
                )
            })?;
        self.api_client().list_devices(&device_id).await
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
