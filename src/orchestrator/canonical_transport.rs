//! Transport for the generated clean-chat XRPC surface.
//!
//! This is intentionally a transport seam, not a second protocol
//! implementation. The platform owns OAuth/DPoP proof construction and the
//! clean-chat transcript projector. We consume those exact values, bind them
//! to the generated request, and serialize the generated DTO without routing
//! through the legacy `blue.catbird.mlsChat.*` surface.

use crate::atproto::blue_catbird::chat::{
    accept_conversation::AcceptConversationRequest,
    acknowledge_welcome::AcknowledgeWelcomeRequest,
    activate_reset::ActivateResetRequest,
    cancel_leaf_recovery::CancelLeafRecoveryRequest,
    cancel_leave::CancelLeaveRequest,
    close_conversation::CloseConversationRequest,
    create_conversation::CreateConversationRequest,
    delete_blob::DeleteBlobRequest,
    enroll_device::EnrollDeviceRequest,
    get_blob::GetBlobRequest,
    get_blob_usage::GetBlobUsageRequest,
    get_conversation_state::GetConversationStateRequest,
    get_conversations::{GetConversations, GetConversationsRequest},
    get_devices::GetDevicesRequest,
    get_entries::{GetEntries, GetEntriesRequest},
    get_leaf_recovery_inbox::GetLeafRecoveryInboxRequest,
    get_own_devices::GetOwnDevicesRequest,
    get_pending_welcomes::GetPendingWelcomesRequest,
    get_subscription_ticket::GetSubscriptionTicketRequest,
    prepare_blob_upload::PrepareBlobUploadRequest,
    publish_typing::PublishTypingRequest,
    rebind_device_authentication::RebindDeviceAuthenticationRequest,
    reject_welcome::RejectWelcomeRequest,
    replenish_key_packages::{ReplenishKeyPackages, ReplenishKeyPackagesRequest},
    request_leaf_recovery::RequestLeafRecoveryRequest,
    request_leave::RequestLeaveRequest,
    request_reset::RequestResetRequest,
    revoke_device::RevokeDeviceRequest,
    send_message::SendMessageRequest,
    submit_transition::SubmitTransitionRequest,
    subscribe_events::SubscribeEventsEndpoint,
    upload_blob::UploadBlobRequest,
};
use crate::atproto::jacquard_common::deps::bytes::Bytes;
use crate::atproto::jacquard_common::xrpc::{SubscriptionEndpoint, XrpcEndpoint};
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::Serialize;
use std::{collections::BTreeMap, str::FromStr};
use uuid::{Uuid, Variant, Version};

const REPLENISH_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-REPLENISH\0";

/// The already-authenticated transport material supplied by the platform.
///
/// `authorization` and `dpop_proof` are opaque on purpose: Nest/DPoP owns
/// their construction and refresh/nonce policy. The Rust orchestrator only
/// ensures that both are present and that the signed mutation's JKT/device
/// agree with the same authenticated device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransportAuth {
    pub(crate) authorization: String,
    pub(crate) dpop_proof: String,
    pub(crate) dpop_jkt: String,
    pub(crate) device_id: String,
}

/// Authenticated transport context supplied by a platform adapter.
///
/// The access token and DPoP proof remain opaque: Nest owns their issuance,
/// refresh, nonce, and proof policy. Rust binds the generated signed request
/// to the same authenticated device/JKT and refuses to prepare a request with
/// missing authentication material. This is deliberately a small transport
/// context rather than a second token or credential schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanChatAuthContext {
    pub authorization: String,
    pub dpop_proof: String,
    pub dpop_jkt: String,
    pub device_id: String,
    /// Optional generation binding for signed mutation requests.
    pub auth_generation: Option<i64>,
}

impl CleanChatAuthContext {
    pub fn new(
        authorization: String,
        dpop_proof: String,
        dpop_jkt: String,
        device_id: String,
    ) -> Self {
        Self {
            authorization,
            dpop_proof,
            dpop_jkt,
            device_id,
            auth_generation: None,
        }
    }

    pub fn with_auth_generation(mut self, auth_generation: i64) -> Self {
        self.auth_generation = Some(auth_generation);
        self
    }

    fn as_internal(&self) -> TransportAuth {
        TransportAuth {
            authorization: self.authorization.clone(),
            dpop_proof: self.dpop_proof.clone(),
            dpop_jkt: self.dpop_jkt.clone(),
            device_id: self.device_id.clone(),
        }
    }
}

impl TransportAuth {
    fn validate(&self) -> Result<(), TransportError> {
        if self.authorization.trim().is_empty() || self.dpop_proof.trim().is_empty() {
            return Err(TransportError::MissingAuthentication);
        }
        if self.dpop_jkt.trim().is_empty() || self.device_id.trim().is_empty() {
            return Err(TransportError::MissingDeviceBinding);
        }
        validate_uuid(&self.device_id, "deviceId")?;
        validate_jkt(&self.dpop_jkt)?;
        Ok(())
    }
}

/// A serialized request ready for the platform's HTTP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub operation: CanonicalOperation,
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub dpop: String,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("clean-chat transport authentication is missing")]
    MissingAuthentication,
    #[error("clean-chat transport device binding is missing")]
    MissingDeviceBinding,
    #[error("signed body device {body} does not match authenticated device {authenticated}")]
    DeviceBindingMismatch { body: String, authenticated: String },
    #[error("signed body DPoP JKT does not match authenticated DPoP JKT")]
    DpopBindingMismatch,
    #[error("signed clean-chat mutations require an authenticated authGeneration")]
    MissingAuthGeneration,
    #[error(
        "signed body authGeneration {actual} does not match authenticated generation {expected}"
    )]
    AuthGenerationMismatch { expected: i64, actual: i64 },
    #[error("device enrollment expectedAuthGeneration must be zero (actual {actual})")]
    InvalidEnrollmentGeneration { actual: i64 },
    #[error("clean-chat {operation:?} is not representable by this JSON transport: {reason}")]
    UnsupportedOperation {
        operation: CanonicalOperation,
        reason: &'static str,
    },
    #[error("signed body domain is not the canonical key-package replenishment domain")]
    InvalidSignatureDomain,
    #[error("canonical signing transcript is empty")]
    EmptySigningTranscript,
    #[error("generated clean-chat request serialization failed: {0}")]
    Serialization(String),
    #[error("generated clean-chat response decoding failed: {0}")]
    Decoding(String),
    #[error("device signing failed")]
    Signing,
    #[error("clean-chat signed mutations require an Ed25519 device key")]
    UnsupportedSigningScheme,
    #[error("clean-chat {operation:?} failed with {code} (retryable={retryable})")]
    Remote {
        operation: CanonicalOperation,
        code: String,
        retryable: bool,
    },
}

/// One generated clean-chat request.
///
/// Each variant is the generated Jacquard DTO for that endpoint. Keeping the
/// variants here avoids a hand-maintained parallel wire schema while giving
/// native Rust and WASM callers one route-typed request surface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum CleanChatRequest {
    AcceptConversation(AcceptConversationRequestBody),
    AcknowledgeWelcome(AcknowledgeWelcomeRequestBody),
    ActivateReset(ActivateResetRequestBody),
    CancelLeafRecovery(CancelLeafRecoveryRequestBody),
    CancelLeave(CancelLeaveRequestBody),
    CloseConversation(CloseConversationRequestBody),
    GetConversations(GetConversations<String>),
    CreateConversation(CreateConversationRequestBody),
    DeleteBlob(DeleteBlobRequestBody),
    SendMessage(SendMessageRequestBody),
    GetBlob(GetBlobRequestBody),
    GetBlobUsage(GetBlobUsageRequestBody),
    GetConversationState(GetConversationStateRequestBody),
    GetDevices(GetDevicesRequestBody),
    GetEntries(GetEntries<String>),
    GetLeafRecoveryInbox(GetLeafRecoveryInboxRequestBody),
    GetOwnDevices(GetOwnDevicesRequestBody),
    GetPendingWelcomes(GetPendingWelcomesRequestBody),
    GetSubscriptionTicket(GetSubscriptionTicketRequestBody),
    PrepareBlobUpload(PrepareBlobUploadRequestBody),
    PublishTyping(PublishTypingRequestBody),
    RebindDeviceAuthentication(RebindDeviceAuthenticationRequestBody),
    RejectWelcome(RejectWelcomeRequestBody),
    ReplenishKeyPackages(ReplenishKeyPackagesRequestBody),
    RequestLeafRecovery(RequestLeafRecoveryRequestBody),
    EnrollDevice(EnrollDeviceRequestBody),
    RequestLeave(RequestLeaveRequestBody),
    RequestReset(RequestResetRequestBody),
    RevokeDevice(RevokeDeviceRequestBody),
    SubmitTransition(SubmitTransitionRequestBody),
    SubscribeEvents(SubscribeEventsRequestBody),
    UploadBlob(UploadBlobRequestBody),
}

pub type AcceptConversationRequestBody =
    crate::atproto::blue_catbird::chat::accept_conversation::AcceptConversation<String>;
pub type AcknowledgeWelcomeRequestBody =
    crate::atproto::blue_catbird::chat::acknowledge_welcome::AcknowledgeWelcome<String>;
pub type ActivateResetRequestBody =
    crate::atproto::blue_catbird::chat::activate_reset::ActivateReset<String>;
pub type CancelLeafRecoveryRequestBody =
    crate::atproto::blue_catbird::chat::cancel_leaf_recovery::CancelLeafRecovery<String>;
pub type CancelLeaveRequestBody =
    crate::atproto::blue_catbird::chat::cancel_leave::CancelLeave<String>;
pub type CloseConversationRequestBody =
    crate::atproto::blue_catbird::chat::close_conversation::CloseConversation<String>;
pub type CreateConversationRequestBody =
    crate::atproto::blue_catbird::chat::create_conversation::CreateConversation<String>;
pub type DeleteBlobRequestBody =
    crate::atproto::blue_catbird::chat::delete_blob::DeleteBlob<String>;
pub type SendMessageRequestBody =
    crate::atproto::blue_catbird::chat::send_message::SendMessage<String>;
pub type GetBlobRequestBody = crate::atproto::blue_catbird::chat::get_blob::GetBlob<String>;
pub type GetBlobUsageRequestBody = crate::atproto::blue_catbird::chat::get_blob_usage::GetBlobUsage;
pub type GetConversationStateRequestBody =
    crate::atproto::blue_catbird::chat::get_conversation_state::GetConversationState<String>;
pub type GetDevicesRequestBody =
    crate::atproto::blue_catbird::chat::get_devices::GetDevices<String>;
pub type GetLeafRecoveryInboxRequestBody =
    crate::atproto::blue_catbird::chat::get_leaf_recovery_inbox::GetLeafRecoveryInbox<String>;
pub type GetOwnDevicesRequestBody =
    crate::atproto::blue_catbird::chat::get_own_devices::GetOwnDevices<String>;
pub type GetPendingWelcomesRequestBody =
    crate::atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomes<String>;
pub type GetSubscriptionTicketRequestBody =
    crate::atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicket<String>;
pub type PrepareBlobUploadRequestBody =
    crate::atproto::blue_catbird::chat::prepare_blob_upload::PrepareBlobUpload<String>;
pub type PublishTypingRequestBody =
    crate::atproto::blue_catbird::chat::publish_typing::PublishTyping<String>;
pub type RebindDeviceAuthenticationRequestBody =
    crate::atproto::blue_catbird::chat::rebind_device_authentication::RebindDeviceAuthentication<
        String,
    >;
pub type RejectWelcomeRequestBody =
    crate::atproto::blue_catbird::chat::reject_welcome::RejectWelcome<String>;
pub type ReplenishKeyPackagesRequestBody =
    crate::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackages<String>;
pub type RequestLeafRecoveryRequestBody =
    crate::atproto::blue_catbird::chat::request_leaf_recovery::RequestLeafRecovery<String>;
pub type EnrollDeviceRequestBody =
    crate::atproto::blue_catbird::chat::enroll_device::EnrollDevice<String>;
pub type RequestLeaveRequestBody =
    crate::atproto::blue_catbird::chat::request_leave::RequestLeave<String>;
pub type RequestResetRequestBody =
    crate::atproto::blue_catbird::chat::request_reset::RequestReset<String>;
pub type RevokeDeviceRequestBody =
    crate::atproto::blue_catbird::chat::revoke_device::RevokeDevice<String>;
pub type SubmitTransitionRequestBody =
    crate::atproto::blue_catbird::chat::submit_transition::SubmitTransition<String>;
pub type SubscribeEventsRequestBody =
    crate::atproto::blue_catbird::chat::subscribe_events::SubscribeEvents<String>;
pub type UploadBlobRequestBody = crate::atproto::blue_catbird::chat::upload_blob::UploadBlob;

/// A generated clean-chat success body, selected by the canonical operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum CleanChatResponse {
    AcceptConversation(crate::atproto::blue_catbird::chat::accept_conversation::AcceptConversationOutput<String>),
    AcknowledgeWelcome(crate::atproto::blue_catbird::chat::acknowledge_welcome::AcknowledgeWelcomeOutput<String>),
    ActivateReset(crate::atproto::blue_catbird::chat::activate_reset::ActivateResetOutput<String>),
    CancelLeafRecovery(crate::atproto::blue_catbird::chat::cancel_leaf_recovery::CancelLeafRecoveryOutput<String>),
    CancelLeave(crate::atproto::blue_catbird::chat::cancel_leave::CancelLeaveOutput<String>),
    CloseConversation(crate::atproto::blue_catbird::chat::close_conversation::CloseConversationOutput<String>),
    GetConversations(
        crate::atproto::blue_catbird::chat::get_conversations::GetConversationsOutput<String>,
    ),
    CreateConversation(
        crate::atproto::blue_catbird::chat::create_conversation::CreateConversationOutput<String>,
    ),
    DeleteBlob(crate::atproto::blue_catbird::chat::delete_blob::DeleteBlobOutput<String>),
    SendMessage(crate::atproto::blue_catbird::chat::send_message::SendMessageOutput<String>),
    GetBlob(crate::atproto::blue_catbird::chat::get_blob::GetBlobOutput),
    GetBlobUsage(crate::atproto::blue_catbird::chat::get_blob_usage::GetBlobUsageOutput<String>),
    GetConversationState(crate::atproto::blue_catbird::chat::get_conversation_state::GetConversationStateOutput<String>),
    GetDevices(crate::atproto::blue_catbird::chat::get_devices::GetDevicesOutput<String>),
    GetEntries(crate::atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String>),
    GetLeafRecoveryInbox(crate::atproto::blue_catbird::chat::get_leaf_recovery_inbox::GetLeafRecoveryInboxOutput<String>),
    GetOwnDevices(crate::atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<String>),
    GetPendingWelcomes(crate::atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesOutput<String>),
    GetSubscriptionTicket(crate::atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicketOutput<String>),
    PrepareBlobUpload(crate::atproto::blue_catbird::chat::prepare_blob_upload::PrepareBlobUploadOutput<String>),
    PublishTyping(crate::atproto::blue_catbird::chat::publish_typing::PublishTypingOutput<String>),
    RebindDeviceAuthentication(crate::atproto::blue_catbird::chat::rebind_device_authentication::RebindDeviceAuthenticationOutput<String>),
    RejectWelcome(crate::atproto::blue_catbird::chat::reject_welcome::RejectWelcomeOutput<String>),
    ReplenishKeyPackages(
        crate::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackagesOutput<
            String,
        >,
    ),
    RequestLeafRecovery(crate::atproto::blue_catbird::chat::request_leaf_recovery::RequestLeafRecoveryOutput<String>),
    EnrollDevice(crate::atproto::blue_catbird::chat::enroll_device::EnrollDeviceOutput<String>),
    RequestLeave(crate::atproto::blue_catbird::chat::request_leave::RequestLeaveOutput<String>),
    RequestReset(crate::atproto::blue_catbird::chat::request_reset::RequestResetOutput<String>),
    RevokeDevice(crate::atproto::blue_catbird::chat::revoke_device::RevokeDeviceOutput<String>),
    SubmitTransition(
        crate::atproto::blue_catbird::chat::submit_transition::SubmitTransitionOutput<String>,
    ),
    SubscribeEvents(crate::atproto::blue_catbird::chat::subscribe_events::SubscribeEventsMessage<String>),
    UploadBlob(crate::atproto::blue_catbird::chat::upload_blob::UploadBlobOutput<String>),
}

/// A generated clean-chat error body, selected by the canonical operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanChatError {
    AcceptConversation(crate::atproto::blue_catbird::chat::accept_conversation::AcceptConversationError),
    AcknowledgeWelcome(crate::atproto::blue_catbird::chat::acknowledge_welcome::AcknowledgeWelcomeError),
    ActivateReset(crate::atproto::blue_catbird::chat::activate_reset::ActivateResetError),
    CancelLeafRecovery(crate::atproto::blue_catbird::chat::cancel_leaf_recovery::CancelLeafRecoveryError),
    CancelLeave(crate::atproto::blue_catbird::chat::cancel_leave::CancelLeaveError),
    CloseConversation(crate::atproto::blue_catbird::chat::close_conversation::CloseConversationError),
    GetConversations(crate::atproto::blue_catbird::chat::get_conversations::GetConversationsError),
    CreateConversation(
        crate::atproto::blue_catbird::chat::create_conversation::CreateConversationError,
    ),
    DeleteBlob(crate::atproto::blue_catbird::chat::delete_blob::DeleteBlobError),
    SendMessage(crate::atproto::blue_catbird::chat::send_message::SendMessageError),
    GetBlob(crate::atproto::blue_catbird::chat::get_blob::GetBlobError),
    GetBlobUsage(crate::atproto::blue_catbird::chat::get_blob_usage::GetBlobUsageError),
    GetConversationState(crate::atproto::blue_catbird::chat::get_conversation_state::GetConversationStateError),
    GetDevices(crate::atproto::blue_catbird::chat::get_devices::GetDevicesError),
    GetEntries(crate::atproto::blue_catbird::chat::get_entries::GetEntriesError),
    GetLeafRecoveryInbox(crate::atproto::blue_catbird::chat::get_leaf_recovery_inbox::GetLeafRecoveryInboxError),
    GetOwnDevices(crate::atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesError),
    GetPendingWelcomes(crate::atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesError),
    GetSubscriptionTicket(crate::atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicketError),
    PrepareBlobUpload(crate::atproto::blue_catbird::chat::prepare_blob_upload::PrepareBlobUploadError),
    PublishTyping(crate::atproto::blue_catbird::chat::publish_typing::PublishTypingError),
    RebindDeviceAuthentication(crate::atproto::blue_catbird::chat::rebind_device_authentication::RebindDeviceAuthenticationError),
    RejectWelcome(crate::atproto::blue_catbird::chat::reject_welcome::RejectWelcomeError),
    ReplenishKeyPackages(
        crate::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackagesError,
    ),
    RequestLeafRecovery(crate::atproto::blue_catbird::chat::request_leaf_recovery::RequestLeafRecoveryError),
    EnrollDevice(crate::atproto::blue_catbird::chat::enroll_device::EnrollDeviceError),
    RequestLeave(crate::atproto::blue_catbird::chat::request_leave::RequestLeaveError),
    RequestReset(crate::atproto::blue_catbird::chat::request_reset::RequestResetError),
    RevokeDevice(crate::atproto::blue_catbird::chat::revoke_device::RevokeDeviceError),
    SubmitTransition(crate::atproto::blue_catbird::chat::submit_transition::SubmitTransitionError),
    SubscribeEvents(crate::atproto::blue_catbird::chat::subscribe_events::SubscribeEventsError),
    UploadBlob(crate::atproto::blue_catbird::chat::upload_blob::UploadBlobError),
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanChatOperationFfi {
    AcceptConversation,
    AcknowledgeWelcome,
    ActivateReset,
    CancelLeafRecovery,
    CancelLeave,
    CloseConversation,
    GetConversations,
    CreateConversation,
    DeleteBlob,
    SendMessage,
    GetBlob,
    GetBlobUsage,
    GetConversationState,
    GetDevices,
    GetEntries,
    GetLeafRecoveryInbox,
    GetOwnDevices,
    GetPendingWelcomes,
    GetSubscriptionTicket,
    PrepareBlobUpload,
    PublishTyping,
    RebindDeviceAuthentication,
    RejectWelcome,
    ReplenishKeyPackages,
    RequestLeafRecovery,
    EnrollDevice,
    RequestLeave,
    RequestReset,
    RevokeDevice,
    SubmitTransition,
    SubscribeEvents,
    UploadBlob,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<CleanChatOperationFfi> for CanonicalOperation {
    fn from(operation: CleanChatOperationFfi) -> Self {
        match operation {
            CleanChatOperationFfi::AcceptConversation => Self::AcceptConversation,
            CleanChatOperationFfi::AcknowledgeWelcome => Self::AcknowledgeWelcome,
            CleanChatOperationFfi::ActivateReset => Self::ActivateReset,
            CleanChatOperationFfi::CancelLeafRecovery => Self::CancelLeafRecovery,
            CleanChatOperationFfi::CancelLeave => Self::CancelLeave,
            CleanChatOperationFfi::CloseConversation => Self::CloseConversation,
            CleanChatOperationFfi::GetConversations => Self::GetConversations,
            CleanChatOperationFfi::CreateConversation => Self::CreateConversation,
            CleanChatOperationFfi::DeleteBlob => Self::DeleteBlob,
            CleanChatOperationFfi::SendMessage => Self::SendMessage,
            CleanChatOperationFfi::GetBlob => Self::GetBlob,
            CleanChatOperationFfi::GetBlobUsage => Self::GetBlobUsage,
            CleanChatOperationFfi::GetConversationState => Self::GetConversationState,
            CleanChatOperationFfi::GetDevices => Self::GetDevices,
            CleanChatOperationFfi::GetEntries => Self::GetEntries,
            CleanChatOperationFfi::GetLeafRecoveryInbox => Self::GetLeafRecoveryInbox,
            CleanChatOperationFfi::GetOwnDevices => Self::GetOwnDevices,
            CleanChatOperationFfi::GetPendingWelcomes => Self::GetPendingWelcomes,
            CleanChatOperationFfi::GetSubscriptionTicket => Self::GetSubscriptionTicket,
            CleanChatOperationFfi::PrepareBlobUpload => Self::PrepareBlobUpload,
            CleanChatOperationFfi::PublishTyping => Self::PublishTyping,
            CleanChatOperationFfi::RebindDeviceAuthentication => Self::RebindDeviceAuthentication,
            CleanChatOperationFfi::RejectWelcome => Self::RejectWelcome,
            CleanChatOperationFfi::ReplenishKeyPackages => Self::ReplenishKeyPackages,
            CleanChatOperationFfi::RequestLeafRecovery => Self::RequestLeafRecovery,
            CleanChatOperationFfi::EnrollDevice => Self::EnrollDevice,
            CleanChatOperationFfi::RequestLeave => Self::RequestLeave,
            CleanChatOperationFfi::RequestReset => Self::RequestReset,
            CleanChatOperationFfi::RevokeDevice => Self::RevokeDevice,
            CleanChatOperationFfi::SubmitTransition => Self::SubmitTransition,
            CleanChatOperationFfi::SubscribeEvents => Self::SubscribeEvents,
            CleanChatOperationFfi::UploadBlob => Self::UploadBlob,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<CanonicalOperation> for CleanChatOperationFfi {
    fn from(operation: CanonicalOperation) -> Self {
        match operation {
            CanonicalOperation::AcceptConversation => Self::AcceptConversation,
            CanonicalOperation::AcknowledgeWelcome => Self::AcknowledgeWelcome,
            CanonicalOperation::ActivateReset => Self::ActivateReset,
            CanonicalOperation::CancelLeafRecovery => Self::CancelLeafRecovery,
            CanonicalOperation::CancelLeave => Self::CancelLeave,
            CanonicalOperation::CloseConversation => Self::CloseConversation,
            CanonicalOperation::GetConversations => Self::GetConversations,
            CanonicalOperation::CreateConversation => Self::CreateConversation,
            CanonicalOperation::DeleteBlob => Self::DeleteBlob,
            CanonicalOperation::SendMessage => Self::SendMessage,
            CanonicalOperation::GetBlob => Self::GetBlob,
            CanonicalOperation::GetBlobUsage => Self::GetBlobUsage,
            CanonicalOperation::GetConversationState => Self::GetConversationState,
            CanonicalOperation::GetDevices => Self::GetDevices,
            CanonicalOperation::GetEntries => Self::GetEntries,
            CanonicalOperation::GetLeafRecoveryInbox => Self::GetLeafRecoveryInbox,
            CanonicalOperation::GetOwnDevices => Self::GetOwnDevices,
            CanonicalOperation::GetPendingWelcomes => Self::GetPendingWelcomes,
            CanonicalOperation::GetSubscriptionTicket => Self::GetSubscriptionTicket,
            CanonicalOperation::PrepareBlobUpload => Self::PrepareBlobUpload,
            CanonicalOperation::PublishTyping => Self::PublishTyping,
            CanonicalOperation::RebindDeviceAuthentication => Self::RebindDeviceAuthentication,
            CanonicalOperation::RejectWelcome => Self::RejectWelcome,
            CanonicalOperation::ReplenishKeyPackages => Self::ReplenishKeyPackages,
            CanonicalOperation::RequestLeafRecovery => Self::RequestLeafRecovery,
            CanonicalOperation::EnrollDevice => Self::EnrollDevice,
            CanonicalOperation::RequestLeave => Self::RequestLeave,
            CanonicalOperation::RequestReset => Self::RequestReset,
            CanonicalOperation::RevokeDevice => Self::RevokeDevice,
            CanonicalOperation::SubmitTransition => Self::SubmitTransition,
            CanonicalOperation::SubscribeEvents => Self::SubscribeEvents,
            CanonicalOperation::UploadBlob => Self::UploadBlob,
        }
    }
}

/// UniFFI-safe authenticated transport context. Token/proof contents remain
/// opaque to Rust; the device/JKT/generation are checked against signed bodies.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct CleanChatAuthContextFfi {
    pub authorization: String,
    pub dpop_proof: String,
    pub dpop_jkt: String,
    pub device_id: String,
    pub auth_generation: Option<i64>,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<CleanChatAuthContextFfi> for CleanChatAuthContext {
    fn from(context: CleanChatAuthContextFfi) -> Self {
        Self {
            authorization: context.authorization,
            dpop_proof: context.dpop_proof,
            dpop_jkt: context.dpop_jkt,
            device_id: context.device_id,
            auth_generation: context.auth_generation,
        }
    }
}

/// UniFFI-safe prepared request. The request body is the generated DTO's JSON
/// bytes; platform clients own the actual HTTP execution.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct CleanChatPreparedRequestFfi {
    pub operation: CleanChatOperationFfi,
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub dpop: String,
    pub body: Option<Vec<u8>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Error, Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CleanChatTransportFfiError {
    #[error("invalid clean-chat transport request: {message}")]
    InvalidRequest { message: String },
}

#[cfg(not(target_arch = "wasm32"))]
fn ffi_error(error: impl std::fmt::Display) -> CleanChatTransportFfiError {
    CleanChatTransportFfiError::InvalidRequest {
        message: error.to_string(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_ffi_request(
    operation: CanonicalOperation,
    body: &[u8],
) -> Result<CleanChatRequest, CleanChatTransportFfiError> {
    macro_rules! parse {
        ($ty:path, $variant:ident) => {
            serde_json::from_slice::<$ty>(body)
                .map(CleanChatRequest::$variant)
                .map_err(ffi_error)
        };
    }
    match operation {
        CanonicalOperation::AcceptConversation => {
            parse!(AcceptConversationRequestBody, AcceptConversation)
        }
        CanonicalOperation::AcknowledgeWelcome => {
            parse!(AcknowledgeWelcomeRequestBody, AcknowledgeWelcome)
        }
        CanonicalOperation::ActivateReset => parse!(ActivateResetRequestBody, ActivateReset),
        CanonicalOperation::CancelLeafRecovery => {
            parse!(CancelLeafRecoveryRequestBody, CancelLeafRecovery)
        }
        CanonicalOperation::CancelLeave => parse!(CancelLeaveRequestBody, CancelLeave),
        CanonicalOperation::CloseConversation => {
            parse!(CloseConversationRequestBody, CloseConversation)
        }
        CanonicalOperation::GetConversations => parse!(GetConversations<String>, GetConversations),
        CanonicalOperation::CreateConversation => {
            parse!(CreateConversationRequestBody, CreateConversation)
        }
        CanonicalOperation::DeleteBlob => parse!(DeleteBlobRequestBody, DeleteBlob),
        CanonicalOperation::SendMessage => parse!(SendMessageRequestBody, SendMessage),
        CanonicalOperation::GetBlob => parse!(GetBlobRequestBody, GetBlob),
        CanonicalOperation::GetBlobUsage => parse!(GetBlobUsageRequestBody, GetBlobUsage),
        CanonicalOperation::GetConversationState => {
            parse!(GetConversationStateRequestBody, GetConversationState)
        }
        CanonicalOperation::GetDevices => parse!(GetDevicesRequestBody, GetDevices),
        CanonicalOperation::GetEntries => parse!(GetEntries<String>, GetEntries),
        CanonicalOperation::GetLeafRecoveryInbox => {
            parse!(GetLeafRecoveryInboxRequestBody, GetLeafRecoveryInbox)
        }
        CanonicalOperation::GetOwnDevices => parse!(GetOwnDevicesRequestBody, GetOwnDevices),
        CanonicalOperation::GetPendingWelcomes => {
            parse!(GetPendingWelcomesRequestBody, GetPendingWelcomes)
        }
        CanonicalOperation::GetSubscriptionTicket => {
            parse!(GetSubscriptionTicketRequestBody, GetSubscriptionTicket)
        }
        CanonicalOperation::PrepareBlobUpload => {
            parse!(PrepareBlobUploadRequestBody, PrepareBlobUpload)
        }
        CanonicalOperation::PublishTyping => parse!(PublishTypingRequestBody, PublishTyping),
        CanonicalOperation::RebindDeviceAuthentication => parse!(
            RebindDeviceAuthenticationRequestBody,
            RebindDeviceAuthentication
        ),
        CanonicalOperation::RejectWelcome => parse!(RejectWelcomeRequestBody, RejectWelcome),
        CanonicalOperation::ReplenishKeyPackages => {
            parse!(ReplenishKeyPackagesRequestBody, ReplenishKeyPackages)
        }
        CanonicalOperation::RequestLeafRecovery => {
            parse!(RequestLeafRecoveryRequestBody, RequestLeafRecovery)
        }
        CanonicalOperation::EnrollDevice => parse!(EnrollDeviceRequestBody, EnrollDevice),
        CanonicalOperation::RequestLeave => parse!(RequestLeaveRequestBody, RequestLeave),
        CanonicalOperation::RequestReset => parse!(RequestResetRequestBody, RequestReset),
        CanonicalOperation::RevokeDevice => parse!(RevokeDeviceRequestBody, RevokeDevice),
        CanonicalOperation::SubmitTransition => {
            parse!(SubmitTransitionRequestBody, SubmitTransition)
        }
        CanonicalOperation::SubscribeEvents => parse!(SubscribeEventsRequestBody, SubscribeEvents),
        CanonicalOperation::UploadBlob => parse!(UploadBlobRequestBody, UploadBlob),
    }
}

/// Prepare one generated clean-chat route for iOS/Android. `request_json` must
/// be the platform's generated DTO JSON, not a hand-maintained wire schema.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn prepare_clean_chat_request(
    auth: CleanChatAuthContextFfi,
    operation: CleanChatOperationFfi,
    request_json: Vec<u8>,
) -> Result<CleanChatPreparedRequestFfi, CleanChatTransportFfiError> {
    let operation = operation.into();
    let request = parse_ffi_request(operation, &request_json)?;
    let prepared = request.prepare(&auth.into()).map_err(ffi_error)?;
    Ok(CleanChatPreparedRequestFfi {
        operation: prepared.operation.into(),
        method: prepared.method,
        path: prepared.path,
        authorization: prepared.authorization,
        dpop: prepared.dpop,
        body: prepared.body,
    })
}

/// Preserve an `getBlob` octet-stream response without attempting JSON or
/// UTF-8 decoding. Blob ciphertext is opaque to this transport layer.
pub fn decode_clean_chat_blob_response(body: &[u8]) -> Result<Vec<u8>, TransportError> {
    Ok(body.to_vec())
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn decode_clean_chat_blob(
    response_bytes: Vec<u8>,
) -> Result<Vec<u8>, CleanChatTransportFfiError> {
    decode_clean_chat_blob_response(&response_bytes).map_err(ffi_error)
}

/// Strictly decode a successful clean-chat response through its generated
/// output type and return canonical generated JSON for the platform adapter.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn decode_clean_chat_response(
    operation: CleanChatOperationFfi,
    response_json: Vec<u8>,
) -> Result<Vec<u8>, CleanChatTransportFfiError> {
    let response =
        CleanChatResponse::decode(operation.into(), &response_json).map_err(ffi_error)?;
    match response {
        CleanChatResponse::AcceptConversation(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::AcknowledgeWelcome(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::ActivateReset(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::CancelLeafRecovery(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::CancelLeave(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::CloseConversation(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::GetConversations(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::CreateConversation(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::DeleteBlob(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::SendMessage(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::GetBlob(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::GetBlobUsage(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::GetConversationState(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::GetDevices(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::GetEntries(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::GetLeafRecoveryInbox(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::GetOwnDevices(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::GetPendingWelcomes(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::GetSubscriptionTicket(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::PrepareBlobUpload(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::PublishTyping(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::RebindDeviceAuthentication(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::RejectWelcome(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::ReplenishKeyPackages(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::RequestLeafRecovery(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatResponse::EnrollDevice(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::RequestLeave(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::RequestReset(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::RevokeDevice(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::SubmitTransition(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::SubscribeEvents(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatResponse::UploadBlob(value) => serde_json::to_vec(&value).map_err(ffi_error),
    }
}

/// Strictly decode one generated clean-chat XRPC error body and return its
/// canonical generated JSON for the platform adapter.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn decode_clean_chat_error(
    operation: CleanChatOperationFfi,
    error_json: Vec<u8>,
) -> Result<Vec<u8>, CleanChatTransportFfiError> {
    let error = CleanChatError::decode(operation.into(), &error_json).map_err(ffi_error)?;
    match error {
        CleanChatError::AcceptConversation(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::AcknowledgeWelcome(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::ActivateReset(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::CancelLeafRecovery(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::CancelLeave(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::CloseConversation(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetConversations(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::CreateConversation(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::DeleteBlob(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::SendMessage(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetBlob(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetBlobUsage(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetConversationState(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatError::GetDevices(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetEntries(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetLeafRecoveryInbox(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatError::GetOwnDevices(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetPendingWelcomes(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::GetSubscriptionTicket(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatError::PrepareBlobUpload(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::PublishTyping(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::RebindDeviceAuthentication(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatError::RejectWelcome(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::ReplenishKeyPackages(value) => {
            serde_json::to_vec(&value).map_err(ffi_error)
        }
        CleanChatError::RequestLeafRecovery(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::EnrollDevice(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::RequestLeave(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::RequestReset(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::RevokeDevice(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::SubmitTransition(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::SubscribeEvents(value) => serde_json::to_vec(&value).map_err(ffi_error),
        CleanChatError::UploadBlob(value) => serde_json::to_vec(&value).map_err(ffi_error),
    }
}

impl CleanChatRequest {
    pub fn operation(&self) -> CanonicalOperation {
        match self {
            Self::AcceptConversation(_) => CanonicalOperation::AcceptConversation,
            Self::AcknowledgeWelcome(_) => CanonicalOperation::AcknowledgeWelcome,
            Self::ActivateReset(_) => CanonicalOperation::ActivateReset,
            Self::CancelLeafRecovery(_) => CanonicalOperation::CancelLeafRecovery,
            Self::CancelLeave(_) => CanonicalOperation::CancelLeave,
            Self::CloseConversation(_) => CanonicalOperation::CloseConversation,
            Self::GetConversations(_) => CanonicalOperation::GetConversations,
            Self::CreateConversation(_) => CanonicalOperation::CreateConversation,
            Self::DeleteBlob(_) => CanonicalOperation::DeleteBlob,
            Self::SendMessage(_) => CanonicalOperation::SendMessage,
            Self::GetBlob(_) => CanonicalOperation::GetBlob,
            Self::GetBlobUsage(_) => CanonicalOperation::GetBlobUsage,
            Self::GetConversationState(_) => CanonicalOperation::GetConversationState,
            Self::GetDevices(_) => CanonicalOperation::GetDevices,
            Self::GetEntries(_) => CanonicalOperation::GetEntries,
            Self::GetLeafRecoveryInbox(_) => CanonicalOperation::GetLeafRecoveryInbox,
            Self::GetOwnDevices(_) => CanonicalOperation::GetOwnDevices,
            Self::GetPendingWelcomes(_) => CanonicalOperation::GetPendingWelcomes,
            Self::GetSubscriptionTicket(_) => CanonicalOperation::GetSubscriptionTicket,
            Self::PrepareBlobUpload(_) => CanonicalOperation::PrepareBlobUpload,
            Self::PublishTyping(_) => CanonicalOperation::PublishTyping,
            Self::RebindDeviceAuthentication(_) => CanonicalOperation::RebindDeviceAuthentication,
            Self::RejectWelcome(_) => CanonicalOperation::RejectWelcome,
            Self::ReplenishKeyPackages(_) => CanonicalOperation::ReplenishKeyPackages,
            Self::RequestLeafRecovery(_) => CanonicalOperation::RequestLeafRecovery,
            Self::EnrollDevice(_) => CanonicalOperation::EnrollDevice,
            Self::RequestLeave(_) => CanonicalOperation::RequestLeave,
            Self::RequestReset(_) => CanonicalOperation::RequestReset,
            Self::RevokeDevice(_) => CanonicalOperation::RevokeDevice,
            Self::SubmitTransition(_) => CanonicalOperation::SubmitTransition,
            Self::SubscribeEvents(_) => CanonicalOperation::SubscribeEvents,
            Self::UploadBlob(_) => CanonicalOperation::UploadBlob,
        }
    }

    /// Serialize the generated request and attach the authenticated transport
    /// context. GET query parameters use the generated field names exactly.
    pub fn prepare(&self, auth: &CleanChatAuthContext) -> Result<PreparedRequest, TransportError> {
        let internal = auth.as_internal();
        match self {
            Self::GetConversations(request) => query_request(&internal, self.operation(), request),
            Self::GetBlob(request) => query_request(&internal, self.operation(), request),
            Self::GetBlobUsage(request) => query_request(&internal, self.operation(), request),
            Self::GetConversationState(request) => query_request(&internal, self.operation(), request),
            Self::GetDevices(request) => query_request(&internal, self.operation(), request),
            Self::GetEntries(request) => query_request(&internal, self.operation(), request),
            Self::GetLeafRecoveryInbox(request) => query_request(&internal, self.operation(), request),
            Self::GetOwnDevices(request) => query_request(&internal, self.operation(), request),
            Self::GetPendingWelcomes(request) => query_request(&internal, self.operation(), request),
            Self::UploadBlob(_) => Err(TransportError::UnsupportedOperation {
                operation: self.operation(),
                reason: "uploadBlob uses an octet-stream body and upload-ticket query; use the platform blob transport",
            }),
            Self::SubscribeEvents(_) => Err(TransportError::UnsupportedOperation {
                operation: self.operation(),
                reason: "subscribeEvents is a WebSocket subscription; use the platform streaming adapter",
            }),
            Self::AcceptConversation(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::AcknowledgeWelcome(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::ActivateReset(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::CancelLeafRecovery(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::CancelLeave(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::CloseConversation(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::CreateConversation(request) => {
                prepare_json_request(&internal, auth.auth_generation, self.operation(), request)
            }
            Self::DeleteBlob(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::SendMessage(request) => {
                prepare_json_request(&internal, auth.auth_generation, self.operation(), request)
            }
            Self::PrepareBlobUpload(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::PublishTyping(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::GetSubscriptionTicket(request) => prepare_unsigned_json_request(&internal, self.operation(), request),
            Self::RebindDeviceAuthentication(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::RejectWelcome(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::ReplenishKeyPackages(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::RequestLeafRecovery(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::EnrollDevice(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::RequestLeave(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::RequestReset(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::RevokeDevice(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
            Self::SubmitTransition(request) => prepare_json_request(&internal, auth.auth_generation, self.operation(), request),
        }
    }
}

impl CleanChatResponse {
    /// Decode a successful endpoint response with its generated output type.
    pub fn decode(operation: CanonicalOperation, body: &[u8]) -> Result<Self, TransportError> {
        macro_rules! decode {
            ($ty:path, $variant:ident) => {
                serde_json::from_slice::<$ty>(body)
                    .map(Self::$variant)
                    .map_err(|error| TransportError::Decoding(error.to_string()))
            };
        }
        match operation {
            CanonicalOperation::AcceptConversation => decode!(crate::atproto::blue_catbird::chat::accept_conversation::AcceptConversationOutput<String>, AcceptConversation),
            CanonicalOperation::AcknowledgeWelcome => decode!(crate::atproto::blue_catbird::chat::acknowledge_welcome::AcknowledgeWelcomeOutput<String>, AcknowledgeWelcome),
            CanonicalOperation::ActivateReset => decode!(crate::atproto::blue_catbird::chat::activate_reset::ActivateResetOutput<String>, ActivateReset),
            CanonicalOperation::CancelLeafRecovery => decode!(crate::atproto::blue_catbird::chat::cancel_leaf_recovery::CancelLeafRecoveryOutput<String>, CancelLeafRecovery),
            CanonicalOperation::CancelLeave => decode!(crate::atproto::blue_catbird::chat::cancel_leave::CancelLeaveOutput<String>, CancelLeave),
            CanonicalOperation::CloseConversation => decode!(crate::atproto::blue_catbird::chat::close_conversation::CloseConversationOutput<String>, CloseConversation),
            CanonicalOperation::GetConversations => decode!(
                crate::atproto::blue_catbird::chat::get_conversations::GetConversationsOutput<
                    String
                >,
                GetConversations
            ),
            CanonicalOperation::CreateConversation => decode!(
                crate::atproto::blue_catbird::chat::create_conversation::CreateConversationOutput<
                    String
                >,
                CreateConversation
            ),
            CanonicalOperation::DeleteBlob => decode!(crate::atproto::blue_catbird::chat::delete_blob::DeleteBlobOutput<String>, DeleteBlob),
            CanonicalOperation::SendMessage => decode!(
                crate::atproto::blue_catbird::chat::send_message::SendMessageOutput<String>,
                SendMessage
            ),
            CanonicalOperation::GetBlob => Err(TransportError::UnsupportedOperation {
                operation: CanonicalOperation::GetBlob,
                reason: "getBlob returns an octet-stream; use decode_clean_chat_blob_response",
            }),
            CanonicalOperation::GetBlobUsage => decode!(crate::atproto::blue_catbird::chat::get_blob_usage::GetBlobUsageOutput<String>, GetBlobUsage),
            CanonicalOperation::GetConversationState => decode!(crate::atproto::blue_catbird::chat::get_conversation_state::GetConversationStateOutput<String>, GetConversationState),
            CanonicalOperation::GetDevices => decode!(crate::atproto::blue_catbird::chat::get_devices::GetDevicesOutput<String>, GetDevices),
            CanonicalOperation::GetEntries => decode!(
                crate::atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String>,
                GetEntries
            ),
            CanonicalOperation::GetLeafRecoveryInbox => decode!(crate::atproto::blue_catbird::chat::get_leaf_recovery_inbox::GetLeafRecoveryInboxOutput<String>, GetLeafRecoveryInbox),
            CanonicalOperation::GetOwnDevices => decode!(crate::atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<String>, GetOwnDevices),
            CanonicalOperation::GetPendingWelcomes => decode!(crate::atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesOutput<String>, GetPendingWelcomes),
            CanonicalOperation::GetSubscriptionTicket => decode!(crate::atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicketOutput<String>, GetSubscriptionTicket),
            CanonicalOperation::PrepareBlobUpload => decode!(crate::atproto::blue_catbird::chat::prepare_blob_upload::PrepareBlobUploadOutput<String>, PrepareBlobUpload),
            CanonicalOperation::PublishTyping => decode!(crate::atproto::blue_catbird::chat::publish_typing::PublishTypingOutput<String>, PublishTyping),
            CanonicalOperation::RebindDeviceAuthentication => decode!(crate::atproto::blue_catbird::chat::rebind_device_authentication::RebindDeviceAuthenticationOutput<String>, RebindDeviceAuthentication),
            CanonicalOperation::RejectWelcome => decode!(crate::atproto::blue_catbird::chat::reject_welcome::RejectWelcomeOutput<String>, RejectWelcome),
            CanonicalOperation::ReplenishKeyPackages => decode!(
                crate::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackagesOutput<
                    String
                >,
                ReplenishKeyPackages
            ),
            CanonicalOperation::RequestLeafRecovery => decode!(crate::atproto::blue_catbird::chat::request_leaf_recovery::RequestLeafRecoveryOutput<String>, RequestLeafRecovery),
            CanonicalOperation::EnrollDevice => decode!(
                crate::atproto::blue_catbird::chat::enroll_device::EnrollDeviceOutput<String>,
                EnrollDevice
            ),
            CanonicalOperation::RequestLeave => decode!(
                crate::atproto::blue_catbird::chat::request_leave::RequestLeaveOutput<String>,
                RequestLeave
            ),
            CanonicalOperation::RequestReset => decode!(crate::atproto::blue_catbird::chat::request_reset::RequestResetOutput<String>, RequestReset),
            CanonicalOperation::RevokeDevice => decode!(crate::atproto::blue_catbird::chat::revoke_device::RevokeDeviceOutput<String>, RevokeDevice),
            CanonicalOperation::SubmitTransition => decode!(
                crate::atproto::blue_catbird::chat::submit_transition::SubmitTransitionOutput<
                    String
                >,
                SubmitTransition
            ),
            CanonicalOperation::SubscribeEvents => decode!(crate::atproto::blue_catbird::chat::subscribe_events::SubscribeEventsMessage<String>, SubscribeEvents),
            CanonicalOperation::UploadBlob => decode!(crate::atproto::blue_catbird::chat::upload_blob::UploadBlobOutput<String>, UploadBlob),
        }
    }
}

impl CleanChatError {
    /// Decode a typed generated XRPC error body for the selected endpoint.
    pub fn decode(operation: CanonicalOperation, body: &[u8]) -> Result<Self, TransportError> {
        macro_rules! decode {
            ($ty:path, $variant:ident) => {
                serde_json::from_slice::<$ty>(body)
                    .map(Self::$variant)
                    .map_err(|error| TransportError::Decoding(error.to_string()))
            };
        }
        match operation {
            CanonicalOperation::AcceptConversation => decode!(crate::atproto::blue_catbird::chat::accept_conversation::AcceptConversationError, AcceptConversation),
            CanonicalOperation::AcknowledgeWelcome => decode!(crate::atproto::blue_catbird::chat::acknowledge_welcome::AcknowledgeWelcomeError, AcknowledgeWelcome),
            CanonicalOperation::ActivateReset => decode!(crate::atproto::blue_catbird::chat::activate_reset::ActivateResetError, ActivateReset),
            CanonicalOperation::CancelLeafRecovery => decode!(crate::atproto::blue_catbird::chat::cancel_leaf_recovery::CancelLeafRecoveryError, CancelLeafRecovery),
            CanonicalOperation::CancelLeave => decode!(crate::atproto::blue_catbird::chat::cancel_leave::CancelLeaveError, CancelLeave),
            CanonicalOperation::CloseConversation => decode!(crate::atproto::blue_catbird::chat::close_conversation::CloseConversationError, CloseConversation),
            CanonicalOperation::GetConversations => decode!(
                crate::atproto::blue_catbird::chat::get_conversations::GetConversationsError,
                GetConversations
            ),
            CanonicalOperation::CreateConversation => decode!(
                crate::atproto::blue_catbird::chat::create_conversation::CreateConversationError,
                CreateConversation
            ),
            CanonicalOperation::DeleteBlob => decode!(crate::atproto::blue_catbird::chat::delete_blob::DeleteBlobError, DeleteBlob),
            CanonicalOperation::SendMessage => decode!(
                crate::atproto::blue_catbird::chat::send_message::SendMessageError,
                SendMessage
            ),
            CanonicalOperation::GetBlob => decode!(crate::atproto::blue_catbird::chat::get_blob::GetBlobError, GetBlob),
            CanonicalOperation::GetBlobUsage => decode!(crate::atproto::blue_catbird::chat::get_blob_usage::GetBlobUsageError, GetBlobUsage),
            CanonicalOperation::GetConversationState => decode!(crate::atproto::blue_catbird::chat::get_conversation_state::GetConversationStateError, GetConversationState),
            CanonicalOperation::GetDevices => decode!(crate::atproto::blue_catbird::chat::get_devices::GetDevicesError, GetDevices),
            CanonicalOperation::GetEntries => decode!(
                crate::atproto::blue_catbird::chat::get_entries::GetEntriesError,
                GetEntries
            ),
            CanonicalOperation::GetLeafRecoveryInbox => decode!(crate::atproto::blue_catbird::chat::get_leaf_recovery_inbox::GetLeafRecoveryInboxError, GetLeafRecoveryInbox),
            CanonicalOperation::GetOwnDevices => decode!(crate::atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesError, GetOwnDevices),
            CanonicalOperation::GetPendingWelcomes => decode!(crate::atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesError, GetPendingWelcomes),
            CanonicalOperation::GetSubscriptionTicket => decode!(crate::atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicketError, GetSubscriptionTicket),
            CanonicalOperation::PrepareBlobUpload => decode!(crate::atproto::blue_catbird::chat::prepare_blob_upload::PrepareBlobUploadError, PrepareBlobUpload),
            CanonicalOperation::PublishTyping => decode!(crate::atproto::blue_catbird::chat::publish_typing::PublishTypingError, PublishTyping),
            CanonicalOperation::RebindDeviceAuthentication => decode!(crate::atproto::blue_catbird::chat::rebind_device_authentication::RebindDeviceAuthenticationError, RebindDeviceAuthentication),
            CanonicalOperation::RejectWelcome => decode!(crate::atproto::blue_catbird::chat::reject_welcome::RejectWelcomeError, RejectWelcome),
            CanonicalOperation::ReplenishKeyPackages => decode!(
                crate::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackagesError,
                ReplenishKeyPackages
            ),
            CanonicalOperation::RequestLeafRecovery => decode!(crate::atproto::blue_catbird::chat::request_leaf_recovery::RequestLeafRecoveryError, RequestLeafRecovery),
            CanonicalOperation::EnrollDevice => decode!(
                crate::atproto::blue_catbird::chat::enroll_device::EnrollDeviceError,
                EnrollDevice
            ),
            CanonicalOperation::RequestLeave => decode!(
                crate::atproto::blue_catbird::chat::request_leave::RequestLeaveError,
                RequestLeave
            ),
            CanonicalOperation::RequestReset => decode!(crate::atproto::blue_catbird::chat::request_reset::RequestResetError, RequestReset),
            CanonicalOperation::RevokeDevice => decode!(crate::atproto::blue_catbird::chat::revoke_device::RevokeDeviceError, RevokeDevice),
            CanonicalOperation::SubmitTransition => decode!(
                crate::atproto::blue_catbird::chat::submit_transition::SubmitTransitionError,
                SubmitTransition
            ),
            CanonicalOperation::SubscribeEvents => decode!(crate::atproto::blue_catbird::chat::subscribe_events::SubscribeEventsError, SubscribeEvents),
            CanonicalOperation::UploadBlob => decode!(crate::atproto::blue_catbird::chat::upload_blob::UploadBlobError, UploadBlob),
        }
    }
}

/// Map a generated clean-chat wire error without collapsing it into a legacy
/// API error. Unknown codes remain visible and non-retryable until their
/// lexicon contract is explicitly added.
pub fn map_wire_error(operation: CanonicalOperation, code: &str) -> TransportError {
    // A generation conflict means the caller's device/auth binding is stale.
    // Replaying the same signed mutation would be unsafe; the platform must
    // rebind or refresh its authenticated context before constructing a new
    // Both generation conflicts and cursor expiry require a fresh operation
    // context. Replaying the unchanged request is never a safe retry.
    let retryable = false;
    TransportError::Remote {
        operation,
        code: code.to_owned(),
        retryable,
    }
}

/// Inputs needed to construct `blue.catbird.chat.replenishKeyPackages`.
///
/// The body fields are the sole source of truth for the signed transcript.
/// Callers cannot supply an arbitrary byte string to sign.
pub struct ReplenishKeyPackagesInput {
    pub actor_did: String,
    pub actor_device_id: String,
    pub auth_generation: i64,
    pub idempotency_key: String,
    pub key_id: String,
    pub dpop_jkt: String,
    pub signature_domain: String,
    pub key_packages: Vec<crate::atproto::blue_catbird::chat::KeyPackageArtifact<String>>,
    pub signed_at: String,
}

/// Construct and serialize one canonical key-package replenishment request.
///
/// The returned wrapper uses the generated `SignedKeyPackageReplenishment` and
/// `ReplenishKeyPackages` types, so the wire shape cannot silently drift from
/// the lexicon. No public FFI is introduced; a platform can call this from an
/// existing internal adapter once its transcript and DPoP facilities are
/// available.
pub(crate) fn replenish_key_packages(
    auth: &TransportAuth,
    signer: &SignatureKeyPair,
    input: ReplenishKeyPackagesInput,
) -> Result<PreparedRequest, TransportError> {
    auth.validate()?;
    validate_bare_did(&input.actor_did)?;
    validate_uuid(&input.actor_device_id, "actorDeviceId")?;
    validate_uuid(&input.idempotency_key, "idempotencyKey")?;
    validate_auth_generation(input.auth_generation)?;
    validate_jkt(&input.dpop_jkt)?;
    validate_key_packages(&input.key_packages)?;
    if input.actor_device_id != auth.device_id {
        return Err(TransportError::DeviceBindingMismatch {
            body: input.actor_device_id,
            authenticated: auth.device_id.clone(),
        });
    }
    if input.dpop_jkt != auth.dpop_jkt {
        return Err(TransportError::DpopBindingMismatch);
    }
    if input.signature_domain != REPLENISH_SIGNATURE_DOMAIN {
        return Err(TransportError::InvalidSignatureDomain);
    }
    if signer.signature_scheme() != SignatureScheme::ED25519 || signer.public().len() != 32 {
        return Err(TransportError::UnsupportedSigningScheme);
    }
    let public_key = signer.public().to_vec();
    let derived_key_id = derive_key_id(&public_key);
    if input.key_id != derived_key_id {
        return Err(TransportError::Serialization(
            "keyId does not match the Ed25519 public-key thumbprint".into(),
        ));
    }
    validate_datetime(&input.signed_at)?;
    let signed_at = parse_datetime(input.signed_at.clone())?;
    let transcript =
        canonical_replenishment_transcript(&input, &public_key, &signed_at, &derived_key_id)?;
    let signature = signer
        .sign(&transcript)
        .map_err(|_| TransportError::Signing)?;
    let body = crate::atproto::blue_catbird::chat::KeyPackageReplenishmentBody::<String> {
        actor_device_id: input.actor_device_id,
        actor_did: crate::atproto::jacquard_common::types::string::Did::<String>::from_str(
            &input.actor_did,
        )
        .map_err(|_| TransportError::Serialization("actorDid is not a valid DID".into()))?,
        auth_generation: input.auth_generation,
        dpop_jkt: input.dpop_jkt,
        idempotency_key: input.idempotency_key,
        key_id: input.key_id,
        key_packages: input.key_packages,
        signature_domain: REPLENISH_SIGNATURE_DOMAIN.to_owned(),
        signature_public_key: Bytes::from(signer.public().to_vec()),
        signed_at,
        extra_data: None,
    };
    let signed = crate::atproto::blue_catbird::chat::SignedKeyPackageReplenishment::<String> {
        body,
        signature: Bytes::from(signature),
        extra_data: None,
    };
    let request = ReplenishKeyPackages::<String> {
        signed_request: signed,
        extra_data: None,
    };
    Ok(PreparedRequest {
        operation: CanonicalOperation::ReplenishKeyPackages,
        method: "POST".into(),
        path: ReplenishKeyPackagesRequest::PATH.to_owned(),
        authorization: auth.authorization.clone(),
        dpop: auth.dpop_proof.clone(),
        body: Some(serialize_json(&request)?),
    })
}

/// Sign and prepare the generated key-package replenishment request using a
/// platform-owned authenticated context.
pub fn prepare_replenishment(
    auth: &CleanChatAuthContext,
    signer: &SignatureKeyPair,
    input: ReplenishKeyPackagesInput,
) -> Result<PreparedRequest, TransportError> {
    let expected = auth
        .auth_generation
        .ok_or(TransportError::MissingAuthGeneration)?;
    if expected != input.auth_generation {
        return Err(TransportError::AuthGenerationMismatch {
            expected,
            actual: input.auth_generation,
        });
    }
    if input.dpop_jkt != auth.dpop_jkt || input.actor_device_id != auth.device_id {
        return Err(if input.dpop_jkt != auth.dpop_jkt {
            TransportError::DpopBindingMismatch
        } else {
            TransportError::DeviceBindingMismatch {
                body: input.actor_device_id,
                authenticated: auth.device_id.clone(),
            }
        });
    }
    replenish_key_packages(&auth.as_internal(), signer, input)
}

pub(crate) fn derive_key_id(public_key: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

#[derive(Debug)]
enum CanonicalValue {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Array(Vec<CanonicalValue>),
    Map(BTreeMap<String, CanonicalValue>),
}

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

pub(crate) fn canonical_replenishment_transcript(
    input: &ReplenishKeyPackagesInput,
    public_key: &[u8],
    signed_at: &crate::atproto::blue_catbird::chat::CanonicalDatetime,
    key_id: &str,
) -> Result<Vec<u8>, TransportError> {
    let device_id = canonical_uuid_bytes(&input.actor_device_id, "actorDeviceId")?;
    let idempotency_key = canonical_uuid_bytes(&input.idempotency_key, "idempotencyKey")?;
    let auth_generation = u64::try_from(input.auth_generation)
        .map_err(|_| TransportError::Serialization("authGeneration must be non-negative".into()))?;
    let mut body = BTreeMap::new();
    body.insert(
        "$type".into(),
        CanonicalValue::Text("blue.catbird.chat.defs#keyPackageReplenishmentBody".into()),
    );
    body.insert("actorDeviceId".into(), CanonicalValue::Bytes(device_id));
    body.insert(
        "actorDid".into(),
        CanonicalValue::Text(input.actor_did.clone()),
    );
    body.insert(
        "authGeneration".into(),
        CanonicalValue::Integer(auth_generation),
    );
    body.insert(
        "dpopJkt".into(),
        CanonicalValue::Text(input.dpop_jkt.clone()),
    );
    body.insert(
        "idempotencyKey".into(),
        CanonicalValue::Bytes(idempotency_key),
    );
    body.insert("keyId".into(), CanonicalValue::Text(key_id.into()));
    let packages = input
        .key_packages
        .iter()
        .map(|package| {
            let mut value = BTreeMap::new();
            value.insert(
                "bytes".into(),
                CanonicalValue::Bytes(package.bytes.to_vec()),
            );
            value.insert(
                "contentType".into(),
                CanonicalValue::Text(package.content_type.clone()),
            );
            value.insert(
                "framing".into(),
                CanonicalValue::Text(package.framing.clone()),
            );
            value.insert(
                "keyPackageRef".into(),
                CanonicalValue::Bytes(package.key_package_ref.to_vec()),
            );
            value.insert(
                "sha256".into(),
                CanonicalValue::Bytes(package.sha256.to_vec()),
            );
            CanonicalValue::Map(value)
        })
        .collect();
    body.insert("keyPackages".into(), CanonicalValue::Array(packages));
    body.insert(
        "signatureDomain".into(),
        CanonicalValue::Text(REPLENISH_SIGNATURE_DOMAIN.into()),
    );
    body.insert(
        "signaturePublicKey".into(),
        CanonicalValue::Bytes(public_key.to_vec()),
    );
    body.insert(
        "signedAt".into(),
        CanonicalValue::Text(signed_at.to_string()),
    );
    let projection = serde_ipld_dagcbor::to_vec(&CanonicalValue::Map(body))
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let mut transcript = REPLENISH_SIGNATURE_DOMAIN.as_bytes().to_vec();
    transcript.extend_from_slice(&projection);
    if transcript.is_empty() {
        return Err(TransportError::EmptySigningTranscript);
    }
    Ok(transcript)
}

fn canonical_uuid_bytes(value: &str, field: &str) -> Result<Vec<u8>, TransportError> {
    let uuid = validate_uuid(value, field)?;
    Ok(uuid.as_bytes().to_vec())
}

pub(crate) fn validate_uuid(value: &str, field: &str) -> Result<Uuid, TransportError> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| TransportError::Serialization(format!("{field} is not a UUID")))?;
    if uuid.get_version() != Some(Version::Random)
        || uuid.get_variant() != Variant::RFC4122
        || uuid.to_string() != value
    {
        return Err(TransportError::Serialization(format!(
            "{field} is not canonical lowercase UUIDv4"
        )));
    }
    Ok(uuid)
}

pub(crate) fn validate_jkt(value: &str) -> Result<(), TransportError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    if value.len() != 43
        || URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .is_none_or(|bytes| bytes.len() != 32)
        || URL_SAFE_NO_PAD.encode(URL_SAFE_NO_PAD.decode(value).unwrap()) != value
    {
        return Err(TransportError::Serialization(
            "dpopJkt is not canonical 43-character base64url".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_auth_generation(value: i64) -> Result<(), TransportError> {
    if !(1..=9_007_199_254_740_991).contains(&value) {
        return Err(TransportError::Serialization(
            "authGeneration is outside the canonical safe integer range".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_bare_did(value: &str) -> Result<(), TransportError> {
    let valid = value.is_ascii()
        && (12..=261).contains(&value.len())
        && if let Some(plc) = value.strip_prefix("did:plc:") {
            plc.len() == 24
                && plc
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        } else if let Some(host) = value.strip_prefix("did:web:") {
            validate_hostname(host)
        } else {
            false
        };
    if !valid {
        return Err(TransportError::Serialization(
            "actorDid is not a production bare DID".into(),
        ));
    }
    Ok(())
}

fn validate_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.ends_with('.') || host.eq("localhost") {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            !(!label.is_empty() && label.len() <= 63 && label.is_ascii())
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return false;
    }
    let tld = labels.last().unwrap();
    !tld.as_bytes()[0].is_ascii_digit()
        && !matches!(
            *tld,
            "alt"
                | "arpa"
                | "example"
                | "internal"
                | "invalid"
                | "local"
                | "localhost"
                | "onion"
                | "test"
        )
}

pub(crate) fn validate_key_packages(
    packages: &[crate::atproto::blue_catbird::chat::KeyPackageArtifact<String>],
) -> Result<(), TransportError> {
    if !(1..=100).contains(&packages.len()) {
        return Err(TransportError::Serialization(
            "keyPackages count is outside 1..=100".into(),
        ));
    }
    let mut previous: Option<&[u8]> = None;
    for package in packages {
        if !(8..=65_536).contains(&package.bytes.len())
            || package.sha256.len() != 32
            || package.key_package_ref.len() != 32
            || package.content_type != "keyPackage"
            || package.framing != "mlsMessage"
        {
            return Err(TransportError::Serialization(
                "keyPackageArtifact violates canonical bounds".into(),
            ));
        }
        if previous.is_some_and(|prior| prior >= package.key_package_ref.as_ref()) {
            return Err(TransportError::Serialization(
                "keyPackageRef values must be strictly increasing".into(),
            ));
        }
        previous = Some(package.key_package_ref.as_ref());
    }
    Ok(())
}

fn parse_datetime(
    value: String,
) -> Result<crate::atproto::blue_catbird::chat::CanonicalDatetime, TransportError> {
    crate::atproto::blue_catbird::chat::CanonicalDatetime::from_str(&value)
        .map_err(|_| TransportError::Serialization("signedAt is not a canonical datetime".into()))
}

pub(crate) fn validate_datetime(value: &str) -> Result<(), TransportError> {
    let bytes = value.as_bytes();
    let punctuation = [4, 7, 10, 13, 16, 19, 23];
    if bytes.len() != 24
        || !punctuation.iter().enumerate().all(|(index, position)| {
            let expected = b"--T::.Z"[index];
            bytes[*position] == expected
        })
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !punctuation.contains(&index) && !byte.is_ascii_digit())
    {
        return Err(TransportError::Serialization(
            "signedAt is not exact UTC milliseconds".into(),
        ));
    }
    Ok(())
}

fn serialize_json(value: &impl Serialize) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(value).map_err(|error| TransportError::Serialization(error.to_string()))
}

fn prepare_json_request<T: Serialize>(
    auth: &TransportAuth,
    auth_generation: Option<i64>,
    operation: CanonicalOperation,
    request: &T,
) -> Result<PreparedRequest, TransportError> {
    auth.validate()?;
    let body = serialize_json(request)?;
    validate_signed_request_context(
        auth,
        auth_generation,
        operation,
        &serde_json::from_slice(&body)
            .map_err(|error| TransportError::Serialization(error.to_string()))?,
    )?;
    Ok(PreparedRequest {
        operation,
        method: "POST".into(),
        path: canonical_route(operation).path.to_owned(),
        authorization: auth.authorization.clone(),
        dpop: auth.dpop_proof.clone(),
        body: Some(body),
    })
}

fn prepare_unsigned_json_request<T: Serialize>(
    auth: &TransportAuth,
    operation: CanonicalOperation,
    request: &T,
) -> Result<PreparedRequest, TransportError> {
    auth.validate()?;
    Ok(PreparedRequest {
        operation,
        method: "POST".into(),
        path: canonical_route(operation).path.to_owned(),
        authorization: auth.authorization.clone(),
        dpop: auth.dpop_proof.clone(),
        body: Some(serialize_json(request)?),
    })
}

pub(crate) fn validate_signed_request_context(
    auth: &TransportAuth,
    auth_generation: Option<i64>,
    operation: CanonicalOperation,
    value: &serde_json::Value,
) -> Result<(), TransportError> {
    let Some(body) = value
        .get("signedRequest")
        .and_then(|value| value.get("body"))
    else {
        return Err(TransportError::Serialization(
            "clean-chat signed request is missing signedRequest.body".into(),
        ));
    };
    if operation == CanonicalOperation::EnrollDevice {
        let device = body
            .get("deviceId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                TransportError::Serialization("enrollment body is missing deviceId".into())
            })?;
        if device != auth.device_id {
            return Err(TransportError::DeviceBindingMismatch {
                body: device.to_owned(),
                authenticated: auth.device_id.clone(),
            });
        }
        let jkt = body
            .get("dpopJkt")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                TransportError::Serialization("enrollment body is missing dpopJkt".into())
            })?;
        if jkt != auth.dpop_jkt {
            return Err(TransportError::DpopBindingMismatch);
        }
        let expected = body
            .get("expectedAuthGeneration")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                TransportError::Serialization(
                    "enrollment body is missing expectedAuthGeneration".into(),
                )
            })?;
        if expected != 0 {
            return Err(TransportError::InvalidEnrollmentGeneration { actual: expected });
        }
        return Ok(());
    }
    if operation == CanonicalOperation::RebindDeviceAuthentication {
        let device = body
            .get("actorDeviceId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                TransportError::Serialization("rebind body is missing actorDeviceId".into())
            })?;
        if device != auth.device_id {
            return Err(TransportError::DeviceBindingMismatch {
                body: device.to_owned(),
                authenticated: auth.device_id.clone(),
            });
        }
        let current_jkt = body
            .get("currentDpopJkt")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                TransportError::Serialization("rebind body is missing currentDpopJkt".into())
            })?;
        validate_jkt(current_jkt)?;
        let new_jkt = body
            .get("newDpopJkt")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                TransportError::Serialization("rebind body is missing newDpopJkt".into())
            })?;
        validate_jkt(new_jkt)?;
        if new_jkt != auth.dpop_jkt {
            return Err(TransportError::DpopBindingMismatch);
        }
        let actual = body
            .get("expectedAuthGeneration")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                TransportError::Serialization(
                    "rebind body is missing expectedAuthGeneration".into(),
                )
            })?;
        let expected = auth_generation.ok_or(TransportError::MissingAuthGeneration)?;
        if expected != actual {
            return Err(TransportError::AuthGenerationMismatch { expected, actual });
        }
        return Ok(());
    }
    if let Some(device) = body
        .get("actorDeviceId")
        .or_else(|| body.get("deviceId"))
        .and_then(serde_json::Value::as_str)
    {
        if device != auth.device_id {
            return Err(TransportError::DeviceBindingMismatch {
                body: device.to_owned(),
                authenticated: auth.device_id.clone(),
            });
        }
    }
    if let Some(jkt) = body.get("dpopJkt").and_then(serde_json::Value::as_str) {
        if jkt != auth.dpop_jkt {
            return Err(TransportError::DpopBindingMismatch);
        }
    }
    let actual = body
        .get("authGeneration")
        .and_then(serde_json::Value::as_i64)
        .ok_or(TransportError::MissingAuthGeneration)?;
    let expected = auth_generation.ok_or(TransportError::MissingAuthGeneration)?;
    if expected != actual {
        return Err(TransportError::AuthGenerationMismatch { expected, actual });
    }
    Ok(())
}

fn encode_query(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn query_request<T: Serialize>(
    auth: &TransportAuth,
    operation: CanonicalOperation,
    request: &T,
) -> Result<PreparedRequest, TransportError> {
    let value = serde_json::to_value(request)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let Some(object) = value.as_object() else {
        if value.is_null() {
            return read_request(auth, operation, String::new());
        }
        return Err(TransportError::Serialization(
            "generated query request is not an object".into(),
        ));
    };
    let mut fields = Vec::new();
    for (key, value) in object {
        if key == "$type" {
            continue;
        }
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    fields.push(format_query_field(key, value));
                }
            }
            serde_json::Value::Null => {}
            value => fields.push(format_query_field(key, value)),
        }
    }
    read_request(auth, operation, fields.join("&"))
}

fn format_query_field(key: &str, value: &serde_json::Value) -> String {
    let value = match value {
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    };
    format!("{}={}", encode_query(key), encode_query(&value))
}

fn read_request(
    auth: &TransportAuth,
    operation: CanonicalOperation,
    query: String,
) -> Result<PreparedRequest, TransportError> {
    auth.validate()?;
    let route = canonical_route(operation);
    let path = if query.is_empty() {
        route.path.to_owned()
    } else {
        format!("{}?{}", route.path, query)
    };
    Ok(PreparedRequest {
        operation,
        method: "GET".into(),
        path,
        authorization: auth.authorization.clone(),
        dpop: auth.dpop_proof.clone(),
        body: None,
    })
}

/// Build the generated `getConversations` query, retaining `pageCursor` (the
/// generated field) rather than reviving the legacy `cursor` spelling.
pub(crate) fn get_conversations(
    auth: &TransportAuth,
    limit: i64,
    page_cursor: Option<&str>,
) -> Result<PreparedRequest, TransportError> {
    let request = GetConversations {
        limit,
        page_cursor: page_cursor.map(ToOwned::to_owned),
    };
    let value = serde_json::to_value(request)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let mut query = format!("limit={}", value["limit"]);
    if let Some(cursor) = value["pageCursor"].as_str() {
        query.push_str("&pageCursor=");
        query.push_str(&encode_query(cursor));
    }
    read_request(auth, CanonicalOperation::GetConversations, query)
}

/// Prepare the canonical generated `getConversations` query for a platform
/// HTTP client.
pub fn prepare_get_conversations(
    auth: &CleanChatAuthContext,
    limit: i64,
    page_cursor: Option<&str>,
) -> Result<PreparedRequest, TransportError> {
    get_conversations(&auth.as_internal(), limit, page_cursor)
}

/// Build the generated `getEntries` transport-auth query.
pub(crate) fn get_entries(
    auth: &TransportAuth,
    conversation_id: &str,
    after_seq: i64,
    limit: i64,
) -> Result<PreparedRequest, TransportError> {
    let request = GetEntries {
        after_seq,
        conversation_id: conversation_id.to_owned(),
        limit,
    };
    let value = serde_json::to_value(request)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let query = format!(
        "afterSeq={}&conversationId={}&limit={}",
        value["afterSeq"],
        encode_query(value["conversationId"].as_str().unwrap_or_default()),
        value["limit"]
    );
    read_request(auth, CanonicalOperation::GetEntries, query)
}

/// Prepare the canonical generated `getEntries` query for a platform HTTP
/// client.
pub fn prepare_get_entries(
    auth: &CleanChatAuthContext,
    conversation_id: &str,
    after_seq: i64,
    limit: i64,
) -> Result<PreparedRequest, TransportError> {
    get_entries(&auth.as_internal(), conversation_id, after_seq, limit)
}

/// Canonical operations with a generated `blue.catbird.chat.*` endpoint.
///
/// This inventory mirrors every generated `blue_catbird::chat` endpoint,
/// including the feature-gated subscription endpoint. `subscribeEvents` and
/// `uploadBlob` are represented and decoded through generated DTOs, but their
/// actual streaming/octet-stream exchange is intentionally returned as a
/// typed `UnsupportedOperation` by [`CleanChatRequest::prepare`]. Platform
/// adapters must execute those two media-specific transports themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalOperation {
    AcceptConversation,
    AcknowledgeWelcome,
    ActivateReset,
    CancelLeafRecovery,
    CancelLeave,
    CloseConversation,
    GetConversations,
    CreateConversation,
    DeleteBlob,
    SendMessage,
    GetBlob,
    GetBlobUsage,
    GetConversationState,
    GetDevices,
    GetEntries,
    GetLeafRecoveryInbox,
    GetOwnDevices,
    GetPendingWelcomes,
    GetSubscriptionTicket,
    PrepareBlobUpload,
    PublishTyping,
    RebindDeviceAuthentication,
    RejectWelcome,
    ReplenishKeyPackages,
    RequestLeafRecovery,
    EnrollDevice,
    RequestLeave,
    RequestReset,
    RevokeDevice,
    SubmitTransition,
    SubscribeEvents,
    UploadBlob,
}

impl CanonicalOperation {
    /// Every operation in the route inventory.
    pub const ALL: &'static [Self] = &[
        Self::AcceptConversation,
        Self::AcknowledgeWelcome,
        Self::ActivateReset,
        Self::CancelLeafRecovery,
        Self::CancelLeave,
        Self::CloseConversation,
        Self::GetConversations,
        Self::CreateConversation,
        Self::DeleteBlob,
        Self::SendMessage,
        Self::GetBlob,
        Self::GetBlobUsage,
        Self::GetConversationState,
        Self::GetDevices,
        Self::GetEntries,
        Self::GetLeafRecoveryInbox,
        Self::GetOwnDevices,
        Self::GetPendingWelcomes,
        Self::GetSubscriptionTicket,
        Self::PrepareBlobUpload,
        Self::PublishTyping,
        Self::RebindDeviceAuthentication,
        Self::RejectWelcome,
        Self::ReplenishKeyPackages,
        Self::RequestLeafRecovery,
        Self::EnrollDevice,
        Self::RequestLeave,
        Self::RequestReset,
        Self::RevokeDevice,
        Self::SubmitTransition,
        Self::SubscribeEvents,
        Self::UploadBlob,
    ];

    pub fn route(self) -> CanonicalRoute {
        canonical_route(self)
    }

    pub fn nsid(self) -> &'static str {
        self.route().nsid
    }

    pub fn path(self) -> &'static str {
        self.route().path
    }
}

/// The generated NSID and path for one canonical operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalRoute {
    pub nsid: &'static str,
    pub path: &'static str,
}

fn route(path: &'static str) -> CanonicalRoute {
    let nsid = path
        .strip_prefix("/xrpc/")
        .expect("generated XRPC endpoint paths have /xrpc/ prefix");
    CanonicalRoute { nsid, path }
}

/// Resolve an operation through the generated canonical endpoint marker.
pub fn canonical_route(operation: CanonicalOperation) -> CanonicalRoute {
    match operation {
        CanonicalOperation::AcceptConversation => route(AcceptConversationRequest::PATH),
        CanonicalOperation::AcknowledgeWelcome => route(AcknowledgeWelcomeRequest::PATH),
        CanonicalOperation::ActivateReset => route(ActivateResetRequest::PATH),
        CanonicalOperation::CancelLeafRecovery => route(CancelLeafRecoveryRequest::PATH),
        CanonicalOperation::CancelLeave => route(CancelLeaveRequest::PATH),
        CanonicalOperation::CloseConversation => route(CloseConversationRequest::PATH),
        CanonicalOperation::GetConversations => route(GetConversationsRequest::PATH),
        CanonicalOperation::CreateConversation => route(CreateConversationRequest::PATH),
        CanonicalOperation::DeleteBlob => route(DeleteBlobRequest::PATH),
        CanonicalOperation::SendMessage => route(SendMessageRequest::PATH),
        CanonicalOperation::GetBlob => route(GetBlobRequest::PATH),
        CanonicalOperation::GetBlobUsage => route(GetBlobUsageRequest::PATH),
        CanonicalOperation::GetConversationState => route(GetConversationStateRequest::PATH),
        CanonicalOperation::GetDevices => route(GetDevicesRequest::PATH),
        CanonicalOperation::GetEntries => route(GetEntriesRequest::PATH),
        CanonicalOperation::GetLeafRecoveryInbox => route(GetLeafRecoveryInboxRequest::PATH),
        CanonicalOperation::GetOwnDevices => route(GetOwnDevicesRequest::PATH),
        CanonicalOperation::GetPendingWelcomes => route(GetPendingWelcomesRequest::PATH),
        CanonicalOperation::GetSubscriptionTicket => route(GetSubscriptionTicketRequest::PATH),
        CanonicalOperation::PrepareBlobUpload => route(PrepareBlobUploadRequest::PATH),
        CanonicalOperation::PublishTyping => route(PublishTypingRequest::PATH),
        CanonicalOperation::RebindDeviceAuthentication => {
            route(RebindDeviceAuthenticationRequest::PATH)
        }
        CanonicalOperation::RejectWelcome => route(RejectWelcomeRequest::PATH),
        CanonicalOperation::ReplenishKeyPackages => route(ReplenishKeyPackagesRequest::PATH),
        CanonicalOperation::RequestLeafRecovery => route(RequestLeafRecoveryRequest::PATH),
        CanonicalOperation::EnrollDevice => route(EnrollDeviceRequest::PATH),
        CanonicalOperation::RequestLeave => route(RequestLeaveRequest::PATH),
        CanonicalOperation::RequestReset => route(RequestResetRequest::PATH),
        CanonicalOperation::RevokeDevice => route(RevokeDeviceRequest::PATH),
        CanonicalOperation::SubmitTransition => route(SubmitTransitionRequest::PATH),
        CanonicalOperation::SubscribeEvents => route(SubscribeEventsEndpoint::PATH),
        CanonicalOperation::UploadBlob => route(UploadBlobRequest::PATH),
    }
}

/// Resolve only a canonical generated NSID. Legacy `mlsChat` names are
/// intentionally not aliases: accepting one here would make it possible for a
/// platform adapter to silently downgrade a clean-chat request.
pub fn route_for_nsid(nsid: &str) -> Option<CanonicalRoute> {
    CanonicalOperation::ALL
        .iter()
        .copied()
        .map(canonical_route)
        .find(|route| route.nsid == nsid)
}
