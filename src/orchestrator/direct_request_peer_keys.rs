//! An exact historical key is a signature candidate, never consent authority.
use crate::orchestrator::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn request_historical_device_key(
        &self,
        owner: &str,
        actor_device: &str,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        let invalid =
            || OrchestratorError::InvalidInput("Historical device key binding mismatch".into());
        crate::chat_v2::ids::BareDid::parse(owner).map_err(|_| invalid())?;
        crate::chat_v2::ids::CanonicalUuid::parse(actor_device).map_err(|_| invalid())?;
        crate::chat_v2::ids::KeyId::parse(key_id).map_err(|_| invalid())?;
        let current_owner = self.require_user_did().await?;
        let caller_device = self.require_actor_device_id().await?;
        if owner == current_owner && actor_device == caller_device {
            let key = self
                .mls_context()
                .identity_public_key(format!("{owner}#{actor_device}").into_bytes())?;
            if canonical_transport::derive_key_id(&key) == key_id {
                return Ok(key);
            }
        }
        let encode = canonical_transport::encode_query;
        let response = self
            .request_query(
                CanonicalOperation::GetDeviceKey,
                format!(
                    "actorDeviceId={}&ownerDid={}&deviceId={}&keyId={}",
                    encode(&caller_device),
                    encode(owner),
                    encode(actor_device),
                    encode(key_id)
                ),
            )
            .await?;
        if response.as_object().is_none_or(|v| v.len() != 4)
            || response["ownerDid"] != owner
            || response["deviceId"] != actor_device
            || response["keyId"] != key_id
        {
            return Err(invalid());
        }
        let key = STANDARD
            .decode(
                response["signaturePublicKey"]
                    .as_str()
                    .or_else(|| response["signaturePublicKey"]["$bytes"].as_str())
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
        if key.len() != 32 || canonical_transport::derive_key_id(&key) != key_id {
            return Err(invalid());
        }
        Ok(key)
    }
}
