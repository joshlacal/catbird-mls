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
        let identity = if let Some(mls_did) = self.credentials().get_mls_did(user_did).await? {
            mls_did
        } else if let Some(device_uuid) = self.credentials().get_device_uuid(user_did).await? {
            format!("{user_did}#{device_uuid}")
        } else {
            user_did.to_string()
        };

        let stored_key = match self.credentials().get_signing_key(user_did).await? {
            Some(key) => key,
            None => match self
                .mls_context()
                .export_identity_key(identity.as_bytes().to_vec())
            {
                Ok(candidate) => {
                    self.credentials()
                        .store_signing_key(user_did, &candidate)
                        .await?;
                    self.credentials()
                        .get_signing_key(user_did)
                        .await?
                        .ok_or_else(|| {
                            OrchestratorError::Credential(
                                "durable signing key missing after store".into(),
                            )
                        })?
                }
                Err(_) => return Ok(None),
            },
        };
        let identity_import = self
            .mls_context()
            .import_identity_key(identity.into_bytes(), stored_key.clone());
        let user_did_import = self
            .mls_context()
            .import_identity_key(user_did.as_bytes().to_vec(), stored_key);
        if let Err(error) = identity_import.and(user_did_import) {
            tracing::warn!(
                error = %error,
                "Stored signing key could not be adopted as the active signer; reconciliation required"
            );
            return Ok(Some(false));
        }
        tracing::info!("Imported durable signing key from credential store");
        Ok(Some(true))
    }

    /// Ensure the current device is registered with the MLS service.
    ///
    /// If already registered and all durable/server state matches, returns
    /// the existing MLS DID.
    /// If not registered (all-absent first-use state), generates a new
    /// identity, registers with the server, and stores credentials.
    /// Any projection or signer mismatch returns an error without clearing
    /// or minting a replacement.
    pub async fn ensure_device_registered(&self) -> Result<String> {
        let user_did = self.require_user_did().await?;

        let has_creds = self.credentials().has_credentials(&user_did).await?;
        let stored_mls_did = self.credentials().get_mls_did(&user_did).await?;
        let stored_device_uuid = self.credentials().get_device_uuid(&user_did).await?;
        let stored_signing_key = self.credentials().get_signing_key(&user_did).await?;

        match evaluate_credential_tuple(
            has_creds,
            stored_mls_did,
            stored_device_uuid,
            stored_signing_key,
        ) {
            CredentialTupleState::AllAbsent => {
                // Truly all-absent first-use state: proceed to enrollment below.
            }
            CredentialTupleState::Partial {
                has_mls_did,
                has_device_uuid,
                has_signing_key,
            } => {
                tracing::warn!(
                    has_mls_did,
                    has_device_uuid,
                    has_signing_key,
                    "Incomplete local credential tuple - reconciliation required"
                );
                return Err(OrchestratorError::Credential(
                    "incomplete local credential tuple".into(),
                ));
            }
            CredentialTupleState::Complete {
                mls_did,
                device_uuid,
            } => {
                let durable_signer_state = self.reconcile_durable_signer(&user_did).await?;
                if durable_signer_state == Some(false) {
                    tracing::warn!(
                        "Durable registered signer could not be adopted into local context - reconciliation required"
                    );
                    return Err(OrchestratorError::Credential(
                        "durable registered signer could not be reconciled".into(),
                    ));
                }
                let durable_signer_in_sync = matches!(durable_signer_state, Some(true));

                let local_public_key = self
                    .mls_context()
                    .identity_public_key(mls_did.as_bytes().to_vec())
                    .map_err(|e| {
                        OrchestratorError::Credential(format!(
                            "local public key not found for existing credential: {e}"
                        ))
                    })?;

                let server_device = match self.api_client().list_devices(&device_uuid).await {
                    Ok(devices) => devices
                        .into_iter()
                        .find(|device| device.device_id == device_uuid),
                    Err(error) if error.is_device_not_registered() => {
                        tracing::warn!(
                            "Device-readiness probe reports device is not registered on server while local custody exists"
                        );
                        return Err(OrchestratorError::Credential(
                            "server device projection does not match local custody: device not registered on server"
                                .into(),
                        ));
                    }
                    Err(error) => return Err(error),
                };

                evaluate_server_device_projection(
                    server_device.as_ref(),
                    &local_public_key,
                    durable_signer_in_sync,
                )?;

                return Ok(mls_did);
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
            "signaturePublicKey": { "$bytes": B64.encode(&kp_result.signature_public_key) },
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
                "bytes": { "$bytes": B64.encode(&kp_result.key_package_data) },
                "sha256": B64.encode(Sha256::digest(&kp_result.key_package_data)),
                "keyPackageRef": { "$bytes": B64.encode(&kp_result.hash_ref) }
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
        if prepared.body.is_none() {
            return Err(OrchestratorError::Credential(
                "prepared enrollment has no body".into(),
            ));
        }

        // Register with server (include initial key package)
        let response = self
            .api_client()
            .submit_prepared_request(prepared)
            .await
            .map_err(|e| {
                if let OrchestratorError::ServerError { status, .. } = &e {
                    if *status == 429 {
                        return OrchestratorError::DeviceLimitReached {
                            current: 10,
                            max: self.config().max_devices,
                        };
                    }
                }
                e
            })?;
        if response.status != 200 {
            if response.status == 429 {
                return Err(OrchestratorError::DeviceLimitReached {
                    current: 10,
                    max: self.config().max_devices,
                });
            }
            return Err(OrchestratorError::Api(format!(
                "device registration failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }
        let output: crate::atproto::blue_catbird::chat::enroll_device::EnrollDeviceOutput<String> =
            serde_json::from_slice(&response.body).map_err(|e| {
                OrchestratorError::Serialization(format!("enroll_device response: {e}"))
            })?;
        let device_info = DeviceInfo {
            device_id: output.device.device_id.to_string(),
            mls_did: mls_did.clone(),
            device_uuid: device_uuid.clone(),
            created_at: Some(chrono::Utc::now()),
            key_id: Some(output.device.key_id.to_string()),
            signature_public_key: Some(output.device.signature_public_key.to_vec()),
            auth_generation: Some(output.device.auth_generation),
            status: Some("active".into()),
            available_package_count: Some(output.device.available_package_count as u32),
            reserved_package_count: Some(output.device.reserved_package_count as u32),
        };
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
    pub async fn remove_device(&self, target_device_id: &str) -> Result<()> {
        tracing::info!(target_device_id, "Removing device");
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        let key_id = {
            let identity_bytes = format!("{user_did}#{actor_device_id}").into_bytes();
            let pk = self.mls_context().identity_public_key(identity_bytes)?;
            super::canonical_transport::derive_key_id(&pk)
        };
        let target_auth_generation = self
            .api_client()
            .list_devices(&actor_device_id)
            .await?
            .into_iter()
            .find(|d| d.device_id == target_device_id || d.device_uuid == target_device_id)
            .and_then(|d| d.auth_generation)
            .ok_or_else(|| {
                OrchestratorError::InvalidInput("target device auth generation unavailable".into())
            })?;
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#deviceRevocationBody",
            "actorDid": user_did,
            "actorDeviceId": actor_device_id,
            "authGeneration": auth_generation,
            "targetDeviceId": target_device_id,
            "targetAuthGeneration": target_auth_generation,
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "keyId": key_id,
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });
        let response = self
            .submit_signed_clean_chat_request(
                super::canonical_transport::CanonicalOperation::RevokeDevice,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "remove_device failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }
        Ok(())
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CredentialTupleState {
    AllAbsent,
    Partial {
        has_mls_did: bool,
        has_device_uuid: bool,
        has_signing_key: bool,
    },
    Complete {
        mls_did: String,
        device_uuid: String,
    },
}

pub(crate) fn evaluate_credential_tuple(
    has_creds: bool,
    mls_did: Option<String>,
    device_uuid: Option<String>,
    signing_key: Option<Vec<u8>>,
) -> CredentialTupleState {
    let has_mls_did = mls_did.is_some();
    let has_device_uuid = device_uuid.is_some();
    let has_signing_key = signing_key.is_some();

    if !has_creds && !has_mls_did && !has_device_uuid && !has_signing_key {
        CredentialTupleState::AllAbsent
    } else if let (Some(mls_did), Some(device_uuid), Some(_)) = (mls_did, device_uuid, signing_key)
    {
        CredentialTupleState::Complete {
            mls_did,
            device_uuid,
        }
    } else {
        CredentialTupleState::Partial {
            has_mls_did,
            has_device_uuid,
            has_signing_key,
        }
    }
}

pub(crate) fn evaluate_server_device_projection(
    server_device: Option<&DeviceInfo>,
    local_public_key: &[u8],
    durable_signer_in_sync: bool,
) -> Result<()> {
    let server_matches_custody = server_device.is_some_and(|device| {
        device.status.as_deref() == Some("active")
            && device
                .auth_generation
                .is_some_and(|generation| generation >= 1)
            && device.signature_public_key.as_deref() == Some(local_public_key)
            && device.key_id.as_deref().is_some_and(|key_id| {
                super::canonical_transport::derive_key_id(local_public_key) == key_id
            })
    });

    if server_matches_custody && durable_signer_in_sync {
        Ok(())
    } else if !durable_signer_in_sync {
        Err(OrchestratorError::Credential(
            "local signer diverged from registered device key".into(),
        ))
    } else {
        Err(OrchestratorError::Credential(
            "server device projection does not match local custody".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_absent_evaluates_to_enrollment_path() {
        let state = evaluate_credential_tuple(false, None, None, None);
        assert_eq!(state, CredentialTupleState::AllAbsent);
    }

    #[test]
    fn test_partial_credential_tuple_evaluates_to_partial_mismatch() {
        let state =
            evaluate_credential_tuple(true, Some("did:plc:alice#uuid-1".to_string()), None, None);
        assert!(matches!(
            state,
            CredentialTupleState::Partial {
                has_mls_did: true,
                has_device_uuid: false,
                has_signing_key: false
            }
        ));

        let state2 =
            evaluate_credential_tuple(false, None, Some("uuid-1".to_string()), Some(vec![1, 2, 3]));
        assert!(matches!(
            state2,
            CredentialTupleState::Partial {
                has_mls_did: false,
                has_device_uuid: true,
                has_signing_key: true
            }
        ));
    }

    #[test]
    fn test_complete_matching_server_projection_succeeds() {
        let pubkey = b"test-public-key-32-bytes-long!".to_vec();
        let key_id = super::super::canonical_transport::derive_key_id(&pubkey);
        let device = DeviceInfo {
            device_id: "uuid-1".to_string(),
            mls_did: "did:plc:alice#uuid-1".to_string(),
            device_uuid: "uuid-1".to_string(),
            created_at: Some(chrono::Utc::now()),
            key_id: Some(key_id),
            signature_public_key: Some(pubkey.clone()),
            auth_generation: Some(1),
            status: Some("active".to_string()),
            available_package_count: Some(10),
            reserved_package_count: Some(0),
        };

        assert!(evaluate_server_device_projection(Some(&device), &pubkey, true).is_ok());
    }

    #[test]
    fn test_server_projection_and_signer_mismatch_fail_without_mutation() {
        let pubkey = b"test-public-key-32-bytes-long!".to_vec();
        let wrong_pubkey = b"wrong-public-key-32-bytes-long!".to_vec();
        let key_id = super::super::canonical_transport::derive_key_id(&pubkey);

        let device = DeviceInfo {
            device_id: "uuid-1".to_string(),
            mls_did: "did:plc:alice#uuid-1".to_string(),
            device_uuid: "uuid-1".to_string(),
            created_at: Some(chrono::Utc::now()),
            key_id: Some(key_id),
            signature_public_key: Some(pubkey.clone()),
            auth_generation: Some(1),
            status: Some("active".to_string()),
            available_package_count: Some(10),
            reserved_package_count: Some(0),
        };

        // Missing device on server
        let err = evaluate_server_device_projection(None, &pubkey, true).unwrap_err();
        assert!(err
            .to_string()
            .contains("server device projection does not match local custody"));

        // Inactive device
        let mut inactive_device = device.clone();
        inactive_device.status = Some("revoked".to_string());
        let err =
            evaluate_server_device_projection(Some(&inactive_device), &pubkey, true).unwrap_err();
        assert!(err
            .to_string()
            .contains("server device projection does not match local custody"));

        // Public key mismatch
        let err =
            evaluate_server_device_projection(Some(&device), &wrong_pubkey, true).unwrap_err();
        assert!(err
            .to_string()
            .contains("server device projection does not match local custody"));

        // Signer not in sync
        let err = evaluate_server_device_projection(Some(&device), &pubkey, false).unwrap_err();
        assert!(err
            .to_string()
            .contains("local signer diverged from registered device key"));
    }
}
