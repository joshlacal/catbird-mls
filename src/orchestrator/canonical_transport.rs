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
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr, sync::OnceLock};
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

/// The binding material used while constructing a clean-chat signature.
///
/// This deliberately contains no access token or DPoP proof. Those values are
/// transport credentials owned by the caller's selected gateway (direct DS or
/// Nest proxy); signing must not require, mint, or export either value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanChatSigningContext {
    pub actor_did: String,
    pub device_id: String,
    pub dpop_jkt: String,
    pub auth_generation: Option<i64>,
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
    #[error("clean-chat signed request has no configured Ed25519 device key")]
    MissingSigningKey,
    #[error("clean-chat credential store failed: {0}")]
    Credential(String),
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
    #[error("clean-chat signing authority {field} does not match the requested binding")]
    SigningAuthorityMismatch { field: &'static str },
    #[error("clean-chat signing authority returned an invalid public key or signature")]
    InvalidSigningAuthority,
    #[error("clean-chat signing authority signature verification failed")]
    SignatureVerification,
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
/// bytes; platform clients own the actual HTTP execution. Unsigned requests
/// carry their already-authenticated transport headers as `Some`; signed
/// requests deliberately return `None` so the selected direct-DS or Nest
/// adapter can attach its own transport credentials.
#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct CleanChatPreparedRequestFfi {
    pub operation: CleanChatOperationFfi,
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub dpop: Option<String>,
    pub body: Option<Vec<u8>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct CleanChatSigningContextFfi {
    pub actor_did: String,
    pub device_id: String,
    pub dpop_jkt: String,
    pub auth_generation: Option<i64>,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<CleanChatSigningContextFfi> for CleanChatSigningContext {
    fn from(context: CleanChatSigningContextFfi) -> Self {
        Self {
            actor_did: context.actor_did,
            device_id: context.device_id,
            dpop_jkt: context.dpop_jkt,
            auth_generation: context.auth_generation,
        }
    }
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
        authorization: Some(prepared.authorization),
        dpop: Some(prepared.dpop),
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

#[cfg(not(target_arch = "wasm32"))]
const DEVICE_ENROLL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-ENROLL\0";
#[cfg(not(target_arch = "wasm32"))]
const DEVICE_REBIND_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-REBIND\0";
#[cfg(not(target_arch = "wasm32"))]
const DEVICE_REVOKE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-REVOKE\0";
#[cfg(not(target_arch = "wasm32"))]
const CREATE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-CREATE\0";
#[cfg(not(target_arch = "wasm32"))]
const COMMIT_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-COMMIT\0";
#[cfg(not(target_arch = "wasm32"))]
const POLICY_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-POLICY\0";
#[cfg(not(target_arch = "wasm32"))]
const ACCEPT_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-ACCEPT\0";
#[cfg(not(target_arch = "wasm32"))]
const MESSAGE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-MESSAGE\0";
#[cfg(not(target_arch = "wasm32"))]
const METADATA_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-METADATA\0";
#[cfg(not(target_arch = "wasm32"))]
const TYPING_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-TYPING\0";
#[cfg(not(target_arch = "wasm32"))]
const BLOB_PREPARE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-BLOB-PREPARE\0";
#[cfg(not(target_arch = "wasm32"))]
const BLOB_DELETE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-BLOB-DELETE\0";
#[cfg(not(target_arch = "wasm32"))]
const RESET_REQUEST_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-RESET-REQUEST\0";
#[cfg(not(target_arch = "wasm32"))]
const RESET_ACTIVATE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-RESET-ACTIVATE\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAF_RECOVERY_REQUEST_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAF_RECOVERY_CANCEL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAF_RECOVERY_FULFILL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0";
#[cfg(not(target_arch = "wasm32"))]
const CLOSE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-CLOSE\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAVE_REQUEST_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-REQUEST\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAVE_ZERO_LEAF_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAVE_CANCEL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-CANCEL\0";
#[cfg(not(target_arch = "wasm32"))]
const LEAVE_FULFILL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0";
#[cfg(not(target_arch = "wasm32"))]
const WELCOME_ACK_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-WELCOME-ACK\0";
#[cfg(not(target_arch = "wasm32"))]
const WELCOME_REJECT_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-WELCOME-REJECT\0";

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy)]
struct SignedRequestSpec {
    domain: &'static str,
    body_type: &'static str,
    variant: Option<&'static str>,
}

#[cfg(not(target_arch = "wasm32"))]
fn signed_request_spec(
    operation: CanonicalOperation,
    variant: Option<&str>,
) -> Result<SignedRequestSpec, TransportError> {
    let spec = match operation {
        CanonicalOperation::AcceptConversation => SignedRequestSpec {
            domain: ACCEPT_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#participantAcceptanceBody",
            variant: None,
        },
        CanonicalOperation::AcknowledgeWelcome => SignedRequestSpec {
            domain: WELCOME_ACK_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#welcomeAcknowledgementBody",
            variant: None,
        },
        CanonicalOperation::ActivateReset => SignedRequestSpec {
            domain: RESET_ACTIVATE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#resetActivationBody",
            variant: None,
        },
        CanonicalOperation::CancelLeafRecovery => SignedRequestSpec {
            domain: LEAF_RECOVERY_CANCEL_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#leafRecoveryCancellationBody",
            variant: None,
        },
        CanonicalOperation::CancelLeave => SignedRequestSpec {
            domain: LEAVE_CANCEL_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#leaveCancellationBody",
            variant: None,
        },
        CanonicalOperation::CloseConversation => SignedRequestSpec {
            domain: CLOSE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#conversationCloseBody",
            variant: None,
        },
        CanonicalOperation::CreateConversation => SignedRequestSpec {
            domain: CREATE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#creationBody",
            variant: None,
        },
        CanonicalOperation::DeleteBlob => SignedRequestSpec {
            domain: BLOB_DELETE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#blobDeletionBody",
            variant: None,
        },
        CanonicalOperation::SendMessage => SignedRequestSpec {
            domain: MESSAGE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#applicationSendBody",
            variant: None,
        },
        CanonicalOperation::PrepareBlobUpload => SignedRequestSpec {
            domain: BLOB_PREPARE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#blobUploadPreparationBody",
            variant: None,
        },
        CanonicalOperation::PublishTyping => SignedRequestSpec {
            domain: TYPING_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#typingBody",
            variant: None,
        },
        CanonicalOperation::RebindDeviceAuthentication => SignedRequestSpec {
            domain: DEVICE_REBIND_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
            variant: None,
        },
        CanonicalOperation::RejectWelcome => SignedRequestSpec {
            domain: WELCOME_REJECT_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#welcomeRejectionBody",
            variant: None,
        },
        CanonicalOperation::ReplenishKeyPackages => SignedRequestSpec {
            domain: REPLENISH_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#keyPackageReplenishmentBody",
            variant: None,
        },
        CanonicalOperation::RequestLeafRecovery => SignedRequestSpec {
            domain: LEAF_RECOVERY_REQUEST_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#leafRecoveryRequestBody",
            variant: None,
        },
        CanonicalOperation::EnrollDevice => SignedRequestSpec {
            domain: DEVICE_ENROLL_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#deviceEnrollmentBody",
            variant: None,
        },
        CanonicalOperation::RequestReset => SignedRequestSpec {
            domain: RESET_REQUEST_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#resetRequestBody",
            variant: None,
        },
        CanonicalOperation::RevokeDevice => SignedRequestSpec {
            domain: DEVICE_REVOKE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#deviceRevocationBody",
            variant: None,
        },
        CanonicalOperation::RequestLeave => match variant {
            Some("blue.catbird.chat.defs#signedLeaveRequest") => SignedRequestSpec {
                domain: LEAVE_REQUEST_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#leaveRequestBody",
                variant: Some("blue.catbird.chat.defs#signedLeaveRequest"),
            },
            Some("blue.catbird.chat.defs#signedZeroLeafLeave") => SignedRequestSpec {
                domain: LEAVE_ZERO_LEAF_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#zeroLeafLeaveBody",
                variant: Some("blue.catbird.chat.defs#signedZeroLeafLeave"),
            },
            _ => {
                return Err(TransportError::Serialization(
                    "requestLeave signedRequest requires a known union $type".into(),
                ))
            }
        },
        CanonicalOperation::SubmitTransition => match variant {
            Some("blue.catbird.chat.defs#signedCommitTransition") => SignedRequestSpec {
                domain: COMMIT_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#commitTransitionBody",
                variant: Some("blue.catbird.chat.defs#signedCommitTransition"),
            },
            Some("blue.catbird.chat.defs#signedPolicyTransition") => SignedRequestSpec {
                domain: POLICY_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#policyTransitionBody",
                variant: Some("blue.catbird.chat.defs#signedPolicyTransition"),
            },
            Some("blue.catbird.chat.defs#signedLeafRecoveryFulfillment") => SignedRequestSpec {
                domain: LEAF_RECOVERY_FULFILL_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
                variant: Some("blue.catbird.chat.defs#signedLeafRecoveryFulfillment"),
            },
            Some("blue.catbird.chat.defs#signedMetadataTransition") => SignedRequestSpec {
                domain: METADATA_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#metadataTransitionBody",
                variant: Some("blue.catbird.chat.defs#signedMetadataTransition"),
            },
            Some("blue.catbird.chat.defs#signedLeaveCommitFulfillment") => SignedRequestSpec {
                domain: LEAVE_FULFILL_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
                variant: Some("blue.catbird.chat.defs#signedLeaveCommitFulfillment"),
            },
            _ => {
                return Err(TransportError::Serialization(
                    "submitTransition signedRequest requires a known union $type".into(),
                ))
            }
        },
        operation => {
            return Err(TransportError::UnsupportedOperation {
                operation,
                reason: "only generated signed mutation endpoints may use the signed orchestrator",
            })
        }
    };
    Ok(spec)
}

#[cfg(not(target_arch = "wasm32"))]
const TYPE_PREFIX: &str = "blue.catbird.chat.defs#";
#[cfg(not(target_arch = "wasm32"))]
const SIGNED_JSON_MAX_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(target_arch = "wasm32"))]
const SIGNED_JSON_MAX_DEPTH: usize = 64;
#[cfg(not(target_arch = "wasm32"))]
const CHAT_DEFS_JSON: &str = include_str!("generated/blue.catbird.chat.defs.json");

/// A duplicate-detecting, null-free JSON tree. `serde_json::Value` is not
/// suitable at this boundary because it silently keeps the last duplicate
/// member and permits `null`/floating-point forms that are outside the signed
/// clean-chat profile.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
enum StrictSignedJson {
    String(String),
    Integer(u64),
    Bool(bool),
    Array(Vec<StrictSignedJson>),
    Object(BTreeMap<String, StrictSignedJson>),
}

#[cfg(not(target_arch = "wasm32"))]
struct StrictSignedJsonVisitor;

#[cfg(not(target_arch = "wasm32"))]
impl<'de> Visitor<'de> for StrictSignedJsonVisitor {
    type Value = StrictSignedJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict non-null clean-chat JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(StrictSignedJson::Integer)
            .map_err(|_| de::Error::custom("negative integers are forbidden"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom("floating-point values are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom("null values are forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom("null values are forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictSignedJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(StrictSignedJson::Object(values))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<'de> Deserialize<'de> for StrictSignedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictSignedJsonVisitor)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_strict_signed_json(raw: &[u8]) -> Result<StrictSignedJson, TransportError> {
    if raw.is_empty()
        || raw.len() > SIGNED_JSON_MAX_BYTES
        || !matches!(raw.first(), Some(b'{' | b'['))
        || !matches!(raw.last(), Some(b'}' | b']'))
    {
        return Err(TransportError::Serialization(
            "signed JSON has an invalid root or insignificant whitespace".into(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSignedJson::deserialize(&mut deserializer)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    deserializer
        .end()
        .map_err(|_| TransportError::Serialization("trailing signed JSON data".into()))?;
    validate_strict_json_depth(&value, 0)?;
    Ok(value)
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_strict_json_depth(
    value: &StrictSignedJson,
    depth: usize,
) -> Result<(), TransportError> {
    if depth > SIGNED_JSON_MAX_DEPTH {
        return Err(TransportError::Serialization(
            "signed JSON schema depth exceeds the strict limit".into(),
        ));
    }
    match value {
        StrictSignedJson::Array(values) => values
            .iter()
            .try_for_each(|value| validate_strict_json_depth(value, depth + 1)),
        StrictSignedJson::Object(values) => values
            .values()
            .try_for_each(|value| validate_strict_json_depth(value, depth + 1)),
        StrictSignedJson::String(_) | StrictSignedJson::Integer(_) | StrictSignedJson::Bool(_) => {
            Ok(())
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn chat_contract() -> &'static serde_json::Value {
    static CONTRACT: OnceLock<serde_json::Value> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        serde_json::from_str(CHAT_DEFS_JSON).expect("canonical chat lexicon must be valid JSON")
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn chat_schema_provenance() -> &'static serde_json::Value {
    chat_contract()
        .get("_catbird_mls_provenance")
        .expect("generated chat schema provenance must be present")
}

#[cfg(not(target_arch = "wasm32"))]
fn chat_definition(name: &str) -> Result<&'static serde_json::Value, TransportError> {
    chat_contract()["defs"]
        .get(name)
        .ok_or_else(|| TransportError::Serialization(format!("unknown chat definition {name}")))
}

#[cfg(not(target_arch = "wasm32"))]
fn strict_text<'a>(value: &'a StrictSignedJson, field: &str) -> Result<&'a str, TransportError> {
    match value {
        StrictSignedJson::String(value) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "{field} must be a string"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn schema_ref_name(schema: &serde_json::Value) -> Result<&str, TransportError> {
    schema["ref"]
        .as_str()
        .and_then(|value| value.strip_prefix('#'))
        .ok_or_else(|| TransportError::Serialization("invalid clean-chat schema reference".into()))
}

#[cfg(not(target_arch = "wasm32"))]
fn project_schema_ref(
    name: &str,
    input: &StrictSignedJson,
    tagged: bool,
) -> Result<CanonicalValue, TransportError> {
    match name {
        "operationId" | "deviceId" => {
            let text = strict_text(input, name)?;
            Ok(CanonicalValue::Bytes(canonical_uuid_bytes(text, name)?))
        }
        "bareDid" => {
            let text = strict_text(input, name)?;
            validate_bare_did(text)?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        "keyId" => {
            let text = strict_text(input, name)?;
            validate_key_id(text)?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        "canonicalDatetime" => {
            let text = strict_text(input, name)?;
            validate_datetime(text)?;
            parse_datetime(text.to_owned())?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        _ => project_schema(chat_definition(name)?, input, Some(name), tagged),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn project_schema(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    field_name: Option<&str>,
    tagged: bool,
) -> Result<CanonicalValue, TransportError> {
    match schema["type"].as_str() {
        Some("ref") => project_schema_ref(schema_ref_name(schema)?, input, false),
        Some("union") => project_union(schema, input),
        Some("object") => project_object(schema, input, field_name, tagged),
        Some("string") => project_string(schema, input, field_name),
        Some("bytes") => project_bytes(schema, input),
        Some("integer") => project_integer(schema, input),
        Some("boolean") => project_boolean(schema, input),
        Some("array") => project_array(schema, input, field_name),
        _ => Err(TransportError::Serialization(
            "unsupported clean-chat schema type".into(),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn project_union(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Object(values) = input else {
        return Err(TransportError::Serialization(
            "closed clean-chat union must be an object".into(),
        ));
    };
    let type_id = strict_text(
        values
            .get("$type")
            .ok_or_else(|| TransportError::Serialization("union is missing $type".into()))?,
        "$type",
    )?;
    let variant = type_id
        .strip_prefix(TYPE_PREFIX)
        .ok_or_else(|| TransportError::Serialization("union $type namespace is invalid".into()))?;
    let allowed = schema["refs"]
        .as_array()
        .ok_or_else(|| TransportError::Serialization("union refs are invalid".into()))?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|value| value.strip_prefix('#'))
        .any(|candidate| candidate == variant);
    if !allowed {
        return Err(TransportError::Serialization(
            "unknown closed union $type".into(),
        ));
    }
    project_schema_ref(variant, input, true)
}

#[cfg(not(target_arch = "wasm32"))]
fn project_object(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    definition_name: Option<&str>,
    tagged: bool,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Object(values) = input else {
        return Err(TransportError::Serialization(
            "clean-chat object has the wrong JSON type".into(),
        ));
    };
    let properties = schema["properties"].as_object().ok_or_else(|| {
        TransportError::Serialization("object schema properties are invalid".into())
    })?;
    let mut output = BTreeMap::new();
    for (name, value) in values {
        if name == "$type" {
            if !tagged {
                return Err(TransportError::Serialization(
                    "unexpected object $type".into(),
                ));
            }
            let expected = format!("{}{}", TYPE_PREFIX, definition_name.unwrap_or_default());
            if strict_text(value, "$type")? != expected {
                return Err(TransportError::Serialization(
                    "wrong closed object $type".into(),
                ));
            }
            output.insert(name.clone(), CanonicalValue::Text(expected));
            continue;
        }
        let property = properties.get(name).ok_or_else(|| {
            TransportError::Serialization(format!("unknown closed clean-chat field {name}"))
        })?;
        let projected = project_schema(property, value, Some(name), false)
            .map_err(|error| TransportError::Serialization(format!("field {name}: {error}")))?;
        output.insert(name.clone(), projected);
    }
    if tagged && !output.contains_key("$type") {
        return Err(TransportError::Serialization(
            "closed object is missing $type".into(),
        ));
    }
    if let Some(required) = schema["required"].as_array() {
        for field in required.iter().filter_map(serde_json::Value::as_str) {
            if !output.contains_key(field) {
                return Err(TransportError::Serialization(format!(
                    "required clean-chat field {field} is missing"
                )));
            }
        }
    }
    enforce_contract_order(definition_name.unwrap_or_default(), &output)?;
    Ok(CanonicalValue::Map(output))
}

#[cfg(not(target_arch = "wasm32"))]
fn project_string(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    field_name: Option<&str>,
) -> Result<CanonicalValue, TransportError> {
    let value = strict_text(input, field_name.unwrap_or("string"))?;
    if let Some(expected) = schema["const"].as_str() {
        if value != expected {
            return Err(TransportError::Serialization(
                "wrong clean-chat string constant".into(),
            ));
        }
    }
    for key in ["enum", "knownValues"] {
        if let Some(values) = schema[key].as_array() {
            if !values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|candidate| candidate == value)
            {
                return Err(TransportError::Serialization(
                    "string is outside the closed clean-chat vocabulary".into(),
                ));
            }
        }
    }
    let length = value.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
        || schema["minGraphemes"]
            .as_u64()
            .is_some_and(|min| value.chars().count() < min as usize)
        || schema["maxGraphemes"]
            .as_u64()
            .is_some_and(|max| value.chars().count() > max as usize)
    {
        return Err(TransportError::Serialization(
            "string is outside the clean-chat length bound".into(),
        ));
    }
    if schema["format"].as_str() == Some("datetime") {
        validate_datetime(value)?;
        parse_datetime(value.to_owned())?;
    }
    if matches!(
        field_name,
        Some("dpopJkt" | "currentDpopJkt" | "newDpopJkt")
    ) {
        validate_jkt(value)?;
    }
    Ok(CanonicalValue::Text(value.to_owned()))
}

#[cfg(not(target_arch = "wasm32"))]
fn strict_base64(value: &str) -> Result<Vec<u8>, TransportError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| TransportError::Serialization("invalid standard base64 bytes".into()))?;
    if STANDARD.encode(&decoded) != value {
        return Err(TransportError::Serialization(
            "non-canonical standard base64 bytes".into(),
        ));
    }
    Ok(decoded)
}

#[cfg(not(target_arch = "wasm32"))]
fn project_bytes(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let bytes = match input {
        StrictSignedJson::String(value) => strict_base64(value)?,
        StrictSignedJson::Object(values) if values.len() == 1 => {
            let encoded = strict_text(
                values
                    .get("$bytes")
                    .ok_or_else(|| TransportError::Serialization("invalid byte object".into()))?,
                "$bytes",
            )?;
            strict_base64(encoded)?
        }
        StrictSignedJson::Array(values) => values
            .iter()
            .map(|value| match value {
                StrictSignedJson::Integer(value) => u8::try_from(*value).map_err(|_| {
                    TransportError::Serialization("byte array member is outside 0..=255".into())
                }),
                _ => Err(TransportError::Serialization(
                    "byte array member is not an integer".into(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(TransportError::Serialization(
                "clean-chat bytes have the wrong JSON type".into(),
            ))
        }
    };
    let length = bytes.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(TransportError::Serialization(
            "bytes are outside the clean-chat length bound".into(),
        ));
    }
    Ok(CanonicalValue::Bytes(bytes))
}

#[cfg(not(target_arch = "wasm32"))]
fn project_integer(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Integer(value) = input else {
        return Err(TransportError::Serialization(
            "clean-chat integer has the wrong JSON type".into(),
        ));
    };
    if *value > 9_007_199_254_740_991
        || schema["minimum"]
            .as_i64()
            .is_some_and(|min| *value < min as u64)
        || schema["maximum"]
            .as_i64()
            .is_some_and(|max| *value > max as u64)
        || schema["const"]
            .as_i64()
            .is_some_and(|constant| *value != constant as u64)
    {
        return Err(TransportError::Serialization(
            "integer is outside the clean-chat bound".into(),
        ));
    }
    Ok(CanonicalValue::Integer(*value))
}

#[cfg(not(target_arch = "wasm32"))]
fn project_boolean(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Bool(value) = input else {
        return Err(TransportError::Serialization(
            "clean-chat boolean has the wrong JSON type".into(),
        ));
    };
    if schema["const"]
        .as_bool()
        .is_some_and(|constant| *value != constant)
    {
        return Err(TransportError::Serialization(
            "boolean violates the clean-chat constant".into(),
        ));
    }
    Ok(CanonicalValue::Bool(*value))
}

#[cfg(not(target_arch = "wasm32"))]
fn project_array(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    field_name: Option<&str>,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Array(values) = input else {
        return Err(TransportError::Serialization(
            "clean-chat array has the wrong JSON type".into(),
        ));
    };
    let length = values.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(TransportError::Serialization(
            "array is outside the clean-chat length bound".into(),
        ));
    }
    let items = schema
        .get("items")
        .ok_or_else(|| TransportError::Serialization("array items schema is missing".into()))?;
    values
        .iter()
        .map(|value| project_schema(items, value, field_name, false))
        .collect::<Result<Vec<_>, _>>()
        .map(CanonicalValue::Array)
}

#[cfg(not(target_arch = "wasm32"))]
fn enforce_contract_order(
    definition_name: &str,
    object: &BTreeMap<String, CanonicalValue>,
) -> Result<(), TransportError> {
    if matches!(
        definition_name,
        "deviceEnrollmentBody" | "keyPackageReplenishmentBody"
    ) {
        let values = canonical_array(object, "keyPackages")?;
        let mut previous: Option<&[u8]> = None;
        for value in values {
            let item = canonical_map(value, "keyPackages item")?;
            let key_package_ref = canonical_bytes(item, "keyPackageRef")?;
            if previous.is_some_and(|prior| prior >= key_package_ref) {
                return Err(TransportError::Serialization(
                    "keyPackageRef values must be strictly increasing".into(),
                ));
            }
            previous = Some(key_package_ref);
        }
    }
    if matches!(
        definition_name,
        "creationManifest" | "resetActivationManifest"
    ) {
        enforce_did_order(object, "participants", "userDid")?;
    }
    if matches!(
        definition_name,
        "transitionManifest" | "policyTransitionBody"
    ) {
        enforce_did_order(object, "participantChanges", "userDid")?;
    }
    if definition_name == "transitionManifest" {
        let values = canonical_array(object, "leafChanges")?;
        let mut previous: Option<(&[u8], &[u8], u8)> = None;
        for value in values {
            let item = canonical_map(value, "leafChanges item")?;
            let did = canonical_text(item, "userDid")?.as_bytes();
            let device = canonical_bytes(item, "deviceId")?;
            let operation_rank = match canonical_text(item, "$type")? {
                "blue.catbird.chat.defs#removeLeaf" => 0,
                "blue.catbird.chat.defs#addLeafByRecovery" => 1,
                _ => {
                    return Err(TransportError::Serialization(
                        "unknown leaf change operation".into(),
                    ))
                }
            };
            if previous
                .is_some_and(|prior| (prior.0, prior.1, prior.2) >= (did, device, operation_rank))
            {
                return Err(TransportError::Serialization(
                    "leaf changes must be strictly ordered".into(),
                ));
            }
            previous = Some((did, device, operation_rank));
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_map<'a>(
    value: &'a CanonicalValue,
    field: &str,
) -> Result<&'a BTreeMap<String, CanonicalValue>, TransportError> {
    match value {
        CanonicalValue::Map(value) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "{field} is not an object"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_array<'a>(
    object: &'a BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<&'a [CanonicalValue], TransportError> {
    match object.get(field) {
        Some(CanonicalValue::Array(value)) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not an array"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn enforce_did_order(
    object: &BTreeMap<String, CanonicalValue>,
    array_name: &str,
    did_name: &str,
) -> Result<(), TransportError> {
    let values = canonical_array(object, array_name)?;
    let mut previous: Option<&[u8]> = None;
    for value in values {
        let item = canonical_map(value, array_name)?;
        let did = canonical_text(item, did_name)?.as_bytes();
        if previous.is_some_and(|prior| prior >= did) {
            return Err(TransportError::Serialization(format!(
                "{array_name} values must be strictly ordered"
            )));
        }
        previous = Some(did);
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_text<'a>(
    map: &'a BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<&'a str, TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Text(value)) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not text"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_integer(
    map: &BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<i64, TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Integer(value)) => i64::try_from(*value).map_err(|_| {
            TransportError::Serialization(format!("signed body field {field} is too large"))
        }),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not an integer"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_uuid(
    map: &BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<Uuid, TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Bytes(value)) if value.len() == 16 => {
            Uuid::from_slice(value).map_err(|_| {
                TransportError::Serialization(format!("signed body field {field} is not a UUID"))
            })
        }
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not a UUID"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_bytes<'a>(
    map: &'a BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<&'a [u8], TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Bytes(value)) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not bytes"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_projected_binding(
    binding: &CleanChatSigningContext,
    operation: CanonicalOperation,
    body: &BTreeMap<String, CanonicalValue>,
    spec: SignedRequestSpec,
) -> Result<(String, Option<Vec<u8>>), TransportError> {
    validate_bare_did(&binding.actor_did)?;
    if canonical_text(body, "actorDid")? != binding.actor_did {
        return Err(TransportError::Serialization(
            "signed body actorDid does not match authenticated actor".into(),
        ));
    }
    let device_field = if operation == CanonicalOperation::EnrollDevice {
        "deviceId"
    } else {
        "actorDeviceId"
    };
    let body_device = canonical_uuid(body, device_field)?;
    let expected_device = validate_uuid(&binding.device_id, device_field)?;
    if body_device != expected_device {
        return Err(TransportError::DeviceBindingMismatch {
            body: body_device.hyphenated().to_string(),
            authenticated: binding.device_id.clone(),
        });
    }
    validate_jkt(&binding.dpop_jkt)?;

    match operation {
        CanonicalOperation::EnrollDevice => {
            let body_jkt = canonical_text(body, "dpopJkt")?;
            if body_jkt != binding.dpop_jkt {
                return Err(TransportError::DpopBindingMismatch);
            }
            let expected = canonical_integer(body, "expectedAuthGeneration")?;
            if expected != 0 {
                return Err(TransportError::InvalidEnrollmentGeneration { actual: expected });
            }
        }
        CanonicalOperation::RebindDeviceAuthentication => {
            validate_jkt(canonical_text(body, "currentDpopJkt")?)?;
            if canonical_text(body, "newDpopJkt")? != binding.dpop_jkt {
                return Err(TransportError::DpopBindingMismatch);
            }
            let actual = canonical_integer(body, "expectedAuthGeneration")?;
            validate_auth_generation(actual)?;
            let expected = binding
                .auth_generation
                .ok_or(TransportError::MissingAuthGeneration)?;
            if actual != expected {
                return Err(TransportError::AuthGenerationMismatch { expected, actual });
            }
        }
        _ => {
            if let Some(CanonicalValue::Text(jkt)) = body.get("dpopJkt") {
                validate_jkt(jkt)?;
                if *jkt != binding.dpop_jkt {
                    return Err(TransportError::DpopBindingMismatch);
                }
            }
            let actual = canonical_integer(body, "authGeneration")?;
            validate_auth_generation(actual)?;
            let expected = binding
                .auth_generation
                .ok_or(TransportError::MissingAuthGeneration)?;
            if actual != expected {
                return Err(TransportError::AuthGenerationMismatch { expected, actual });
            }
        }
    }

    if canonical_text(body, "signatureDomain")? != spec.domain {
        return Err(TransportError::InvalidSignatureDomain);
    }
    let key_id = canonical_text(body, "keyId")?.to_owned();
    validate_key_id(&key_id)?;
    let body_public_key = body
        .get("signaturePublicKey")
        .map(|_| canonical_bytes(body, "signaturePublicKey").map(|value| value.to_vec()))
        .transpose()?;
    if let Some(public_key) = &body_public_key {
        if public_key.len() != 32 || derive_key_id(public_key) != key_id {
            return Err(TransportError::Serialization(
                "signaturePublicKey does not match body keyId".into(),
            ));
        }
    }
    Ok((key_id, body_public_key))
}

#[cfg(not(target_arch = "wasm32"))]
fn canonical_json_value(value: &CanonicalValue) -> serde_json::Value {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    match value {
        CanonicalValue::Text(value) => serde_json::Value::String(value.clone()),
        CanonicalValue::Bytes(value) => serde_json::Value::String(STANDARD.encode(value)),
        CanonicalValue::Integer(value) => serde_json::json!(*value),
        CanonicalValue::Bool(value) => serde_json::Value::Bool(*value),
        CanonicalValue::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json_value).collect())
        }
        CanonicalValue::Map(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json_value(value)))
                .collect(),
        ),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn wire_json_ref(
    name: &str,
    value: &CanonicalValue,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match name {
        "operationId" | "deviceId" => match value {
            CanonicalValue::Bytes(value) if value.len() == 16 => Ok(serde_json::Value::String(
                Uuid::from_slice(value)
                    .map_err(|_| TransportError::Serialization("invalid wire UUID".into()))?
                    .hyphenated()
                    .to_string(),
            )),
            _ => Err(TransportError::Serialization(
                "invalid wire UUID value".into(),
            )),
        },
        "bareDid" | "keyId" | "canonicalDatetime" => Ok(canonical_json_value(value)),
        "artifactHash" | "identifierBytes" => Ok(canonical_json_value(value)),
        _ => wire_json_schema(chat_definition(name)?, value, Some(name), tagged),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn wire_json_schema(
    schema: &serde_json::Value,
    value: &CanonicalValue,
    field_name: Option<&str>,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match schema["type"].as_str() {
        Some("ref") => wire_json_ref(schema_ref_name(schema)?, value, false),
        Some("union") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization("invalid wire union".into()));
            };
            let tag = canonical_text(values, "$type")?;
            let variant = tag
                .strip_prefix(TYPE_PREFIX)
                .ok_or_else(|| TransportError::Serialization("invalid wire union tag".into()))?;
            wire_json_ref(variant, value, true)
        }
        Some("object") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization("invalid wire object".into()));
            };
            let properties = schema["properties"].as_object().ok_or_else(|| {
                TransportError::Serialization("invalid wire object properties".into())
            })?;
            let mut output = serde_json::Map::new();
            for (name, value) in values {
                if name == "$type" {
                    if tagged {
                        output.insert(name.clone(), canonical_json_value(value));
                    }
                    continue;
                }
                let property = properties.get(name).ok_or_else(|| {
                    TransportError::Serialization("unknown wire object field".into())
                })?;
                output.insert(
                    name.clone(),
                    wire_json_schema(property, value, Some(name), false)?,
                );
            }
            Ok(serde_json::Value::Object(output))
        }
        Some("bytes") | Some("string") | Some("integer") | Some("boolean") => {
            let _ = field_name;
            Ok(canonical_json_value(value))
        }
        Some("array") => match value {
            CanonicalValue::Array(values) => {
                let items = schema.get("items").ok_or_else(|| {
                    TransportError::Serialization("invalid wire array items".into())
                })?;
                Ok(serde_json::Value::Array(
                    values
                        .iter()
                        .map(|value| wire_json_schema(items, value, field_name, false))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            _ => Err(TransportError::Serialization("invalid wire array".into())),
        },
        _ => Err(TransportError::Serialization(
            "unsupported wire schema".into(),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn generated_json_ref(
    name: &str,
    value: &CanonicalValue,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match name {
        "operationId" | "deviceId" => match value {
            CanonicalValue::Bytes(value) if value.len() == 16 => Ok(serde_json::Value::String(
                Uuid::from_slice(value)
                    .map_err(|_| TransportError::Serialization("invalid generated UUID".into()))?
                    .hyphenated()
                    .to_string(),
            )),
            _ => Err(TransportError::Serialization(
                "invalid generated UUID value".into(),
            )),
        },
        "bareDid" | "keyId" | "canonicalDatetime" => Ok(canonical_json_value(value)),
        "artifactHash" | "identifierBytes" => match value {
            CanonicalValue::Bytes(value) => Ok(serde_json::Value::Array(
                value.iter().map(|byte| serde_json::json!(*byte)).collect(),
            )),
            _ => Err(TransportError::Serialization(
                "invalid generated byte alias".into(),
            )),
        },
        _ => generated_json_schema(chat_definition(name)?, value, tagged),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn generated_json_schema(
    schema: &serde_json::Value,
    value: &CanonicalValue,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match schema["type"].as_str() {
        Some("ref") => generated_json_ref(schema_ref_name(schema)?, value, false),
        Some("union") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization(
                    "invalid generated union".into(),
                ));
            };
            let tag = canonical_text(values, "$type")?;
            let variant = tag.strip_prefix(TYPE_PREFIX).ok_or_else(|| {
                TransportError::Serialization("invalid generated union tag".into())
            })?;
            generated_json_ref(variant, value, true)
        }
        Some("object") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization(
                    "invalid generated object".into(),
                ));
            };
            let properties = schema["properties"].as_object().ok_or_else(|| {
                TransportError::Serialization("invalid generated object properties".into())
            })?;
            let mut output = serde_json::Map::new();
            for (name, value) in values {
                if name == "$type" {
                    if tagged {
                        output.insert(name.clone(), canonical_json_value(value));
                    }
                    continue;
                }
                let property = properties.get(name).ok_or_else(|| {
                    TransportError::Serialization("unknown generated object field".into())
                })?;
                output.insert(name.clone(), generated_json_schema(property, value, false)?);
            }
            Ok(serde_json::Value::Object(output))
        }
        Some("bytes") => match value {
            CanonicalValue::Bytes(value) => {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                Ok(serde_json::json!({"$bytes": STANDARD.encode(value)}))
            }
            _ => Err(TransportError::Serialization(
                "invalid generated bytes".into(),
            )),
        },
        Some("array") => match value {
            CanonicalValue::Array(values) => {
                let items = schema.get("items").ok_or_else(|| {
                    TransportError::Serialization("invalid generated array items".into())
                })?;
                Ok(serde_json::Value::Array(
                    values
                        .iter()
                        .map(|value| generated_json_schema(items, value, false))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            _ => Err(TransportError::Serialization(
                "invalid generated array".into(),
            )),
        },
        Some("string") | Some("integer") | Some("boolean") => Ok(canonical_json_value(value)),
        _ => Err(TransportError::Serialization(
            "unsupported generated schema".into(),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub(crate) struct SignedBodyProjection {
    operation: CanonicalOperation,
    spec: SignedRequestSpec,
    pub(crate) transcript: Vec<u8>,
    pub(crate) key_id: String,
    body_public_key: Option<Vec<u8>>,
    body_json: serde_json::Value,
    generated_body_json: serde_json::Value,
    expected_device_id: String,
    expected_dpop_jkt: String,
    expected_auth_generation: Option<i64>,
}

#[cfg(not(target_arch = "wasm32"))]
fn signed_spec_for_body(
    operation: CanonicalOperation,
    body_type: &str,
    outer_variant: Option<&str>,
) -> Result<SignedRequestSpec, TransportError> {
    let variant = match operation {
        CanonicalOperation::RequestLeave => match body_type {
            "blue.catbird.chat.defs#leaveRequestBody" => {
                "blue.catbird.chat.defs#signedLeaveRequest"
            }
            "blue.catbird.chat.defs#zeroLeafLeaveBody" => {
                "blue.catbird.chat.defs#signedZeroLeafLeave"
            }
            _ => {
                return Err(TransportError::Serialization(
                    "requestLeave body type is invalid".into(),
                ))
            }
        },
        CanonicalOperation::SubmitTransition => match body_type {
            "blue.catbird.chat.defs#commitTransitionBody" => {
                "blue.catbird.chat.defs#signedCommitTransition"
            }
            "blue.catbird.chat.defs#policyTransitionBody" => {
                "blue.catbird.chat.defs#signedPolicyTransition"
            }
            "blue.catbird.chat.defs#leafRecoveryFulfillmentBody" => {
                "blue.catbird.chat.defs#signedLeafRecoveryFulfillment"
            }
            "blue.catbird.chat.defs#metadataTransitionBody" => {
                "blue.catbird.chat.defs#signedMetadataTransition"
            }
            "blue.catbird.chat.defs#leaveCommitFulfillmentBody" => {
                "blue.catbird.chat.defs#signedLeaveCommitFulfillment"
            }
            _ => {
                return Err(TransportError::Serialization(
                    "submitTransition body type is invalid".into(),
                ))
            }
        },
        _ => {
            if outer_variant.is_some() {
                return Err(TransportError::Serialization(
                    "signed wrapper tag is not allowed for non-union operation".into(),
                ));
            }
            return signed_request_spec(operation, None);
        }
    };
    if outer_variant.is_some_and(|outer| outer != variant) {
        return Err(TransportError::Serialization(
            "signed wrapper variant does not match body type".into(),
        ));
    }
    signed_request_spec(operation, Some(variant))
}

#[cfg(not(target_arch = "wasm32"))]
fn extract_strict_signed_body(
    value: StrictSignedJson,
) -> Result<(StrictSignedJson, Option<String>, Option<String>), TransportError> {
    let StrictSignedJson::Object(mut root) = value else {
        return Err(TransportError::Serialization(
            "signed request body must be a JSON object".into(),
        ));
    };
    if let Some(signed_request) = root.remove("signedRequest") {
        let root_variant = root
            .remove("$type")
            .map(|value| strict_text(&value, "$type").map(str::to_owned))
            .transpose()?;
        if !root.is_empty() {
            return Err(TransportError::Serialization(
                "signed request wrapper has unknown fields".into(),
            ));
        }
        let StrictSignedJson::Object(mut wrapper) = signed_request else {
            return Err(TransportError::Serialization(
                "signedRequest must be an object".into(),
            ));
        };
        let outer_variant = wrapper
            .remove("$type")
            .map(|value| strict_text(&value, "signedRequest.$type").map(str::to_owned))
            .transpose()?;
        let body = wrapper
            .remove("body")
            .ok_or_else(|| TransportError::Serialization("signedRequest is missing body".into()))?;
        if !wrapper.is_empty() {
            return Err(TransportError::Serialization(
                "signedRequest body input has unknown fields".into(),
            ));
        }
        return Ok((body, root_variant, outer_variant));
    }
    Ok((StrictSignedJson::Object(root), None, None))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn prepare_signed_body(
    binding: &CleanChatSigningContext,
    operation: CanonicalOperation,
    body_json: &[u8],
) -> Result<SignedBodyProjection, TransportError> {
    let value = parse_strict_signed_json(body_json)?;
    let (body, root_variant, wrapper_variant) = extract_strict_signed_body(value)?;
    let outer_variant = match (root_variant, wrapper_variant) {
        (Some(root), Some(wrapper)) if root != wrapper => {
            return Err(TransportError::Serialization(
                "signed wrapper tags do not match".into(),
            ))
        }
        (Some(root), _) | (_, Some(root)) => Some(root),
        (None, None) => None,
    };
    let body_type = match &body {
        StrictSignedJson::Object(values) => strict_text(
            values.get("$type").ok_or_else(|| {
                TransportError::Serialization("signed body is missing $type".into())
            })?,
            "$type",
        )?,
        _ => {
            return Err(TransportError::Serialization(
                "signed body must be an object".into(),
            ))
        }
    };
    let spec = signed_spec_for_body(operation, body_type, outer_variant.as_deref())?;
    let definition_name = spec
        .body_type
        .strip_prefix(TYPE_PREFIX)
        .ok_or_else(|| TransportError::Serialization("invalid signed body definition".into()))?;
    let projected = project_schema_ref(definition_name, &body, true)?;
    let CanonicalValue::Map(body_map) = &projected else {
        return Err(TransportError::Serialization(
            "signed body projection is not an object".into(),
        ));
    };
    let (key_id, body_public_key) = validate_projected_binding(binding, operation, body_map, spec)?;
    let cbor = serde_ipld_dagcbor::to_vec(&projected)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let mut transcript = spec.domain.as_bytes().to_vec();
    transcript.extend_from_slice(&cbor);
    if transcript.is_empty() {
        return Err(TransportError::EmptySigningTranscript);
    }
    let generated_body_json = generated_json_ref(definition_name, &projected, true)?;
    Ok(SignedBodyProjection {
        operation,
        spec,
        transcript,
        key_id,
        body_public_key,
        body_json: wire_json_ref(definition_name, &projected, true)?,
        generated_body_json,
        expected_device_id: binding.device_id.clone(),
        expected_dpop_jkt: binding.dpop_jkt.clone(),
        expected_auth_generation: binding.auth_generation,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn finish_signed_request(
    prepared: SignedBodyProjection,
    signature: Vec<u8>,
) -> Result<PreparedRequest, TransportError> {
    if signature.len() != 64 {
        return Err(TransportError::InvalidSigningAuthority);
    }
    let mut generated_body = prepared.generated_body_json.clone();
    if let serde_json::Value::Object(values) = &mut generated_body {
        values.remove("$type");
    }
    let mut wrapper = serde_json::Map::new();
    if let Some(variant) = prepared.spec.variant {
        wrapper.insert("$type".into(), serde_json::Value::String(variant.into()));
    }
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    wrapper.insert("body".into(), generated_body);
    wrapper.insert(
        "signature".into(),
        serde_json::json!({"$bytes": STANDARD.encode(&signature)}),
    );
    let endpoint = serde_json::json!({"signedRequest": wrapper});
    let endpoint_bytes = serde_json::to_vec(&endpoint)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    parse_ffi_request(prepared.operation, &endpoint_bytes)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;

    let wire = serde_json::json!({
        "signedRequest": {
            "body": prepared.body_json,
            "signature": STANDARD.encode(&signature),
        }
    });
    Ok(PreparedRequest {
        operation: prepared.operation,
        method: "POST".into(),
        path: canonical_route(prepared.operation).path.to_owned(),
        authorization: String::new(),
        dpop: String::new(),
        body: Some(
            serde_json::to_vec(&wire)
                .map_err(|error| TransportError::Serialization(error.to_string()))?,
        ),
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_authority(
    prepared: &SignedBodyProjection,
    authority: &crate::orchestrator::credentials::CleanChatSigningAuthority,
) -> Result<(), TransportError> {
    if authority.public_key.len() != 32 || authority.signature.len() != 64 {
        return Err(TransportError::InvalidSigningAuthority);
    }
    if authority.device_id != prepared.expected_device_id {
        return Err(TransportError::SigningAuthorityMismatch { field: "deviceId" });
    }
    if authority.dpop_jkt != prepared.expected_dpop_jkt {
        return Err(TransportError::SigningAuthorityMismatch { field: "dpopJkt" });
    }
    if authority.auth_generation != prepared.expected_auth_generation {
        return Err(TransportError::SigningAuthorityMismatch {
            field: "authGeneration",
        });
    }
    if derive_key_id(&authority.public_key) != prepared.key_id {
        return Err(TransportError::SigningAuthorityMismatch { field: "keyId" });
    }
    if prepared
        .body_public_key
        .as_deref()
        .is_some_and(|value| value != authority.public_key.as_slice())
    {
        return Err(TransportError::SigningAuthorityMismatch {
            field: "signaturePublicKey",
        });
    }
    use ed25519_dalek::{Signature, VerifyingKey};
    let public_key = VerifyingKey::from_bytes(
        authority
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::InvalidSigningAuthority)?,
    )
    .map_err(|_| TransportError::InvalidSigningAuthority)?;
    let signature = Signature::from_slice(&authority.signature)
        .map_err(|_| TransportError::InvalidSigningAuthority)?;
    public_key
        .verify_strict(&prepared.transcript, &signature)
        .map_err(|_| TransportError::SignatureVerification)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn prepare_signed_request_with_authority(
    prepared: SignedBodyProjection,
    authority: crate::orchestrator::credentials::CleanChatSigningAuthority,
) -> Result<PreparedRequest, TransportError> {
    verify_authority(&prepared, &authority)?;
    finish_signed_request(prepared, authority.signature)
}

/// Rust-only test/legacy helper. The public orchestrator uses the
/// non-exporting authority path above; this helper never crosses UniFFI.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub(crate) fn prepare_signed_request_with_signer(
    binding: &CleanChatSigningContext,
    operation: CanonicalOperation,
    body_json: Vec<u8>,
    signer: &SignatureKeyPair,
) -> Result<PreparedRequest, TransportError> {
    if signer.signature_scheme() != SignatureScheme::ED25519 || signer.public().len() != 32 {
        return Err(TransportError::UnsupportedSigningScheme);
    }
    let prepared = prepare_signed_body(binding, operation, &body_json)?;
    if derive_key_id(signer.public()) != prepared.key_id {
        return Err(TransportError::SigningAuthorityMismatch { field: "keyId" });
    }
    let signature = signer
        .sign(&prepared.transcript)
        .map_err(|_| TransportError::Signing)?;
    let authority = crate::orchestrator::credentials::CleanChatSigningAuthority {
        public_key: signer.public().to_vec(),
        signature,
        device_id: binding.device_id.clone(),
        dpop_jkt: binding.dpop_jkt.clone(),
        auth_generation: binding.auth_generation,
    };
    prepare_signed_request_with_authority(prepared, authority)
}

#[derive(Debug)]
enum CanonicalValue {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
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
            Self::Bool(value) => serializer.serialize_bool(*value),
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

pub(crate) fn validate_key_id(value: &str) -> Result<(), TransportError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TransportError::Serialization("keyId is not canonical base64url".into()))?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(TransportError::Serialization(
            "keyId is not a canonical Ed25519 thumbprint".into(),
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
