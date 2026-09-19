//! Shared request UI contract. These values are projections, never consent authority.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct DirectRequestInput {
    pub draft_id: String,
    pub recipient_did: String,
    pub text: String,
    pub invitation: Option<GroupInvitationReference>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct GroupInvitationReference {
    pub authority_did: String,
    pub conversation_id: String,
    pub invitation_transition_id: String,
    pub invited_by_did: String,
    pub invited_by_device_id: String,
    pub recipient_did: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum DirectRequestOutcome {
    RequestSent {
        conversation_id: String,
        message_id: String,
        request_id: String,
    },
    OutcomeUnknown {
        request_id: String,
    },
    ExistingDirect {
        conversation_id: String,
        requires_acceptance: bool,
    },
    Retryable {
        code: String,
    },
    TerminalNotPublished {
        request_id: String,
        code: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum RequestConsent {
    IncomingPending,
    OutgoingPending,
    Accepted,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum RequestCrypto {
    WelcomeAvailable,
    Importing,
    Ready,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct RequestCapabilities {
    pub can_preview: bool,
    pub can_accept: bool,
    pub can_close: bool,
    pub can_send: bool,
    pub can_emit_receipts: bool,
    pub can_administer: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum RequestPreview {
    Ready { text: String },
    Unavailable { code: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct DirectRequestView {
    pub conversation_id: String,
    pub first_message_id: Option<String>,
    pub consent: RequestConsent,
    pub crypto: RequestCrypto,
    pub preview: Option<RequestPreview>,
    pub capabilities: RequestCapabilities,
    pub state_version: u64,
    pub generation: u64,
}

impl RequestCapabilities {
    /// Derive effects from verified consent and exact-device readiness. Native
    /// membership, a Welcome receipt, or successful preview decryption cannot
    /// promote either pending direction to accepted.
    pub fn derive(consent: RequestConsent, crypto: RequestCrypto, has_preview: bool) -> Self {
        let open = consent != RequestConsent::Closed;
        let ordinary = consent == RequestConsent::Accepted && crypto == RequestCrypto::Ready;
        Self {
            can_preview: has_preview,
            can_accept: consent == RequestConsent::IncomingPending,
            can_close: open,
            can_send: ordinary,
            can_emit_receipts: ordinary,
            can_administer: ordinary,
        }
    }
}
