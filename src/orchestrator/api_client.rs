use async_trait::async_trait;

use super::error::Result;
use super::types::*;

/// Platform-agnostic API client for communicating with the MLS delivery service.
///
/// Implementations handle authentication, network transport, and serialization.
/// On iOS this wraps the ATProtoClient/MLSAPIClient; on desktop it can use reqwest directly.
#[async_trait]
pub trait MLSAPIClient: Send + Sync {
    // -- Authentication --

    /// Check if the client is authenticated as the given DID.
    async fn is_authenticated_as(&self, did: &str) -> bool;

    /// Get the currently authenticated DID, if any.
    async fn current_did(&self) -> Option<String>;

    // -- Conversations --

    /// Fetch conversations from the server with pagination.
    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage>;

    /// Create a new conversation on the server.
    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult>;

    /// Leave a conversation on the server.
    async fn leave_conversation(&self, convo_id: &str) -> Result<()>;

    /// Add members to a conversation on the server.
    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> Result<AddMembersServerResult>;

    /// Remove members from a conversation on the server.
    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> Result<()>;

    // -- Messages --

    /// Send an encrypted MLS message to the delivery service.
    async fn send_message(&self, convo_id: &str, ciphertext: &[u8], epoch: u64) -> Result<()>;

    /// Send an encrypted MLS message with an explicit client-generated message ID.
    ///
    /// Backends that do not support explicit message IDs can ignore `msg_id` and
    /// fall back to `send_message`.
    async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<()> {
        let _ = msg_id;
        self.send_message(convo_id, ciphertext, epoch).await
    }

    /// Fetch new messages for a conversation since a cursor.
    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)>;

    // -- Key Packages --

    /// Publish a key package to the server.
    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> Result<()>;

    /// Get key packages for a set of DIDs.
    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>>;

    /// Get key package stats for the current user.
    async fn get_key_package_stats(&self) -> Result<KeyPackageStats>;

    /// Sync local key package hashes with the server to detect orphans.
    async fn sync_key_packages(
        &self,
        local_hashes: &[String],
        device_id: &str,
    ) -> Result<KeyPackageSyncResult>;

    // -- Devices --

    /// Register a device with the MLS service.
    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<DeviceInfo>;

    /// List registered devices.
    async fn list_devices(&self) -> Result<Vec<DeviceInfo>>;

    /// Remove a device by ID.
    async fn remove_device(&self, device_id: &str) -> Result<()>;

    // -- Group Info --

    /// Publish GroupInfo for external joins.
    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()>;

    /// Fetch GroupInfo for an external join.
    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>>;

    // -- Welcome / External Commit --

    /// Fetch a Welcome message for joining a conversation.
    /// Returns the raw Welcome bytes, or an error (404 = no Welcome available).
    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let _ = convo_id;
        Err(crate::orchestrator::error::OrchestratorError::Api(
            "get_welcome not implemented".into(),
        ))
    }

    /// Request sequencer failover for a conversation.
    ///
    /// Called when the current sequencer is unreachable after consecutive failures.
    /// Not all backends support this; the default returns an error.
    async fn request_failover(&self, convo_id: &str) -> Result<RequestFailoverResponse> {
        let _ = convo_id;
        Err(crate::orchestrator::error::OrchestratorError::Api(
            "request_failover not implemented".into(),
        ))
    }

    /// Fetch delivery status for messages in a conversation.
    ///
    /// Returns `(message_id, DeliveryStatus)` pairs. Default stub returns empty
    /// for backends that don't support federated delivery tracking.
    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        let _ = (convo_id, message_ids);
        Ok(vec![])
    }

    /// Send an External Commit to the processExternalCommit endpoint.
    /// This is the correct endpoint for External Commits (NOT sendMessage).
    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
    ) -> Result<ProcessExternalCommitResult> {
        let _ = (convo_id, commit_data, group_info);
        Err(crate::orchestrator::error::OrchestratorError::Api(
            "process_external_commit not implemented".into(),
        ))
    }
}
