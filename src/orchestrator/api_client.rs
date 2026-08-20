use async_trait::async_trait;

use super::canonical_transport::{GatewayResponse, PreparedRequest};
use super::error::Result;
use super::types::*;

#[cfg(not(target_arch = "wasm32"))]
pub trait MLSAPIClientBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> MLSAPIClientBounds for T {}

#[cfg(target_arch = "wasm32")]
pub trait MLSAPIClientBounds {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MLSAPIClientBounds for T {}

/// Generic API gateway client for communicating with the MLS delivery service.
///
/// Implementations handle network transport for prepared XRPC requests and
/// canonical read endpoints.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait MLSAPIClient: MLSAPIClientBounds {
    // -- Authentication --

    /// Check if the client is authenticated as the given DID.
    async fn is_authenticated_as(&self, did: &str) -> bool;

    /// Get the currently authenticated DID, if any.
    async fn current_did(&self) -> Option<String>;

    // -- Prepared Request Submission --

    /// Submit a prepared, device-signed XRPC request to the delivery service.
    async fn submit_prepared_request(&self, request: PreparedRequest) -> Result<GatewayResponse>;

    // -- Canonical Reads --

    /// Fetch conversations from the server with pagination.
    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage>;

    /// Fetch new messages for a conversation since a cursor.
    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)>;

    /// Get key packages for a set of DIDs.
    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRef>>;

    /// Get key package stats for the current user.
    async fn get_key_package_stats(&self) -> Result<KeyPackageStats>;

    /// Sync local key package hashes with the server to detect orphans.
    async fn sync_key_packages(
        &self,
        local_hashes: &[String],
        device_id: &str,
    ) -> Result<KeyPackageSyncResult>;

    /// List registered devices through the device-scoped v2 query.
    async fn list_devices(&self, actor_device_id: &str) -> Result<Vec<DeviceInfo>>;

    /// Fetch GroupInfo for an external join.
    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>>;

    /// Publish group info (used by tests or platform wrappers).
    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        let _ = (convo_id, group_info);
        Ok(())
    }

    /// Fetch a Welcome message for joining a conversation.
    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let _ = convo_id;
        Err(crate::orchestrator::error::OrchestratorError::Api(
            "get_welcome not implemented".into(),
        ))
    }

    /// Publish a Welcome message for new members (used by tests / local delivery).
    async fn publish_welcome(&self, convo_id: &str, welcome_data: &[u8]) -> Result<()> {
        let _ = (convo_id, welcome_data);
        Ok(())
    }

    /// Fetch delivery status for messages in a conversation.
    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        let _ = (convo_id, message_ids);
        Ok(vec![])
    }

    /// Download an encrypted metadata blob from the DS via `blue.catbird.chat.getBlob`.
    async fn get_group_metadata_blob(
        &self,
        convo_id: &str,
        group_id_hex: &str,
        blob_locator: &str,
    ) -> Result<Vec<u8>> {
        let _ = (convo_id, group_id_hex, blob_locator);
        Err(crate::orchestrator::error::OrchestratorError::Api(
            "get_group_metadata_blob not implemented".into(),
        ))
    }
}
