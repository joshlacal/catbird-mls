//! First-contact device authority comes only from repository-published keys.
use crate::orchestrator::*;
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// A thumbprint selects an independently authorized repository key. Neither
    /// a DS key row nor a local signer proves account authorization. Historical
    /// replay uses only versioned, protected projections verified at first use.
    pub(crate) async fn request_authorized_device_key(
        &self,
        owner: &str,
        actor_device: &str,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        use super::super::credential_binding::DeviceKeyLookup;
        let invalid = || {
            OrchestratorError::InvalidInput(
                "Request device key is not repository authorized".into(),
            )
        };
        crate::chat_v2::ids::BareDid::parse(owner).map_err(|_| invalid())?;
        crate::chat_v2::ids::CanonicalUuid::parse(actor_device).map_err(|_| invalid())?;
        crate::chat_v2::ids::KeyId::parse(key_id).map_err(|_| invalid())?;
        let matches =
            |key: &[u8]| key.len() == 32 && canonical_transport::derive_key_id(key) == key_id;
        let (mut lookup, cached) = self
            .lookup_authorized_device_keys_with_origin(owner, false)
            .await?;
        if cached
            && matches!(&lookup, DeviceKeyLookup::Keys(keys)
            if !keys.iter().any(|key| matches(key)))
        {
            lookup = self.refresh_authorized_device_keys(owner).await?;
        }
        match lookup {
            DeviceKeyLookup::Keys(keys) => keys
                .iter()
                .find(|key| matches(key))
                .cloned()
                .ok_or_else(invalid),
            DeviceKeyLookup::Unsupported => Err(invalid()),
        }
    }
}
