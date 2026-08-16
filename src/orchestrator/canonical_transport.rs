//! Canonical clean-chat XRPC route inventory.
//!
//! The orchestrator deliberately keeps MLS bytes and recovery state behind the
//! existing [`MLSAPIClient`](super::api_client::MLSAPIClient) trait. Canonical
//! `blue.catbird.chat.*` procedures carry signed generated envelopes, so this
//! module exposes only the generated route markers that a platform transport
//! must use. It does not synthesize a signed request or reinterpret legacy
//! callback arguments as a clean-chat request.

#![allow(dead_code)]

use crate::atproto::blue_catbird::chat::{
    create_conversation::CreateConversationRequest, enroll_device::EnrollDeviceRequest,
    get_conversations::GetConversationsRequest, get_entries::GetEntriesRequest,
    replenish_key_packages::ReplenishKeyPackagesRequest, request_leave::RequestLeaveRequest,
    send_message::SendMessageRequest, submit_transition::SubmitTransitionRequest,
};
use crate::atproto::jacquard_common::xrpc::XrpcEndpoint;

/// Canonical operations with a generated `blue.catbird.chat.*` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalOperation {
    GetConversations,
    CreateConversation,
    SendMessage,
    GetEntries,
    ReplenishKeyPackages,
    EnrollDevice,
    RequestLeave,
    SubmitTransition,
}

impl CanonicalOperation {
    /// Every operation in the route inventory.
    pub(crate) const ALL: &'static [Self] = &[
        Self::GetConversations,
        Self::CreateConversation,
        Self::SendMessage,
        Self::GetEntries,
        Self::ReplenishKeyPackages,
        Self::EnrollDevice,
        Self::RequestLeave,
        Self::SubmitTransition,
    ];
}

/// The generated NSID and path for one canonical operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalRoute {
    pub(crate) nsid: &'static str,
    pub(crate) path: &'static str,
}

fn route(path: &'static str) -> CanonicalRoute {
    let nsid = path
        .strip_prefix("/xrpc/")
        .expect("generated XRPC endpoint paths have /xrpc/ prefix");
    CanonicalRoute { nsid, path }
}

/// Resolve an operation through the generated canonical endpoint marker.
pub(crate) fn canonical_route(operation: CanonicalOperation) -> CanonicalRoute {
    match operation {
        CanonicalOperation::GetConversations => route(GetConversationsRequest::PATH),
        CanonicalOperation::CreateConversation => route(CreateConversationRequest::PATH),
        CanonicalOperation::SendMessage => route(SendMessageRequest::PATH),
        CanonicalOperation::GetEntries => route(GetEntriesRequest::PATH),
        CanonicalOperation::ReplenishKeyPackages => route(ReplenishKeyPackagesRequest::PATH),
        CanonicalOperation::EnrollDevice => route(EnrollDeviceRequest::PATH),
        CanonicalOperation::RequestLeave => route(RequestLeaveRequest::PATH),
        CanonicalOperation::SubmitTransition => route(SubmitTransitionRequest::PATH),
    }
}

/// Resolve only a canonical generated NSID. Legacy `mlsChat` names are
/// intentionally not aliases: accepting one here would make it possible for a
/// platform adapter to silently downgrade a clean-chat request.
pub(crate) fn route_for_nsid(nsid: &str) -> Option<CanonicalRoute> {
    CanonicalOperation::ALL
        .iter()
        .copied()
        .map(canonical_route)
        .find(|route| route.nsid == nsid)
}
