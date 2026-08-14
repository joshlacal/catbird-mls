//! Platform binding surface for the clean chat protocol.
//!
//! This is deliberately the *small* surface: only things whose shape is already
//! settled by sealed slices. It exists so the iOS and Android lanes can start
//! their binding plumbing — regeneration, error plumbing, module wiring —
//! without waiting on the reducer, which is the largest remaining piece and the
//! one whose types would churn if published early.
//!
//! Three things are exposed, all backed by implemented code:
//!
//! 1. **Typed endpoint errors.** Platforms receive an XRPC error code off the
//!    wire and need it classified. [`chat_v2_classify_endpoint_error`] returns
//!    the classification *and* the policy answers as precomputed fields, so a
//!    platform cannot recompute them differently. Rust owns the only
//!    synchronization and recovery policy, and precomputing is what makes that
//!    structural instead of a convention.
//! 2. **Identifier validation.** The DID, UUID, keyId, and timestamp grammars
//!    are frozen and byte-exact. Five clients hand-rolling them is five chances
//!    to diverge, so they are validated here once.
//! 3. **A readiness probe.** [`chat_v2_status`] reports `is_operational =
//!    false` until the envelope and reducer layers land. The types are
//!    bindable now; the protocol is not usable yet, and this makes that
//!    impossible to mistake.
//!
//! # Not exposed yet, on purpose
//!
//! Reducer state, interval provenance, schedule terminal proofs, and the
//! append-log sink are absent because their shapes are not settled. Publishing
//! them now would hand the platform lanes a surface that is guaranteed to
//! break.
//!
//! # WASM
//!
//! This module is compiled out on `wasm32`, matching the crate's existing
//! layout where `uniffi::setup_scaffolding!` is itself gated off wasm. The web
//! client consumes the Rust core through the domain traits rather than through
//! a UniFFI facade, so it needs no counterpart here; the `chat_v2` domain
//! modules it does use all build for wasm.

use super::endpoint_error::{ChatErrorClass, ChatErrorCode, EndpointError};
use super::ids::uuid::{ConversationId, EntryId, MessageId, TransitionId};
use super::ids::{BareDid, BasicCredential, CanonicalTimestamp, DeviceId, KeyId};

/// What a chat error means for synchronization and recovery policy.
///
/// Mirrors [`ChatErrorClass`] across the FFI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum ChatV2ErrorClass {
    /// The device credential, DPoP binding, or authentication generation is no
    /// longer valid.
    Authentication,
    /// Authenticated but not permitted in this state.
    Authorization,
    /// A relationship or declaration policy denied the operation.
    RelationshipPolicy,
    /// A peer is not yet in a state where the operation can succeed.
    Readiness,
    /// The request was built against a coordinate the server has moved past.
    StaleCoordinate,
    /// Another writer won, or this operation identity carries different bytes.
    Conflict,
    /// The named resource does not exist.
    NotFound,
    /// A time-bounded resource lapsed.
    Expired,
    /// A protocol quota or cap was reached.
    LimitReached,
    /// The request was structurally or cryptographically invalid.
    MalformedRequest,
    /// A checked increment would pass the safe-integer ceiling.
    Overflow,
    /// A temporary server-side condition.
    Transient,
    /// The client is speaking the superseded protocol and must be upgraded.
    CutoverRequired,
    /// A code this build does not recognize.
    Unknown,
}

impl From<ChatErrorClass> for ChatV2ErrorClass {
    fn from(class: ChatErrorClass) -> Self {
        match class {
            ChatErrorClass::Authentication => Self::Authentication,
            ChatErrorClass::Authorization => Self::Authorization,
            ChatErrorClass::RelationshipPolicy => Self::RelationshipPolicy,
            ChatErrorClass::Readiness => Self::Readiness,
            ChatErrorClass::StaleCoordinate => Self::StaleCoordinate,
            ChatErrorClass::Conflict => Self::Conflict,
            ChatErrorClass::NotFound => Self::NotFound,
            ChatErrorClass::Expired => Self::Expired,
            ChatErrorClass::LimitReached => Self::LimitReached,
            ChatErrorClass::MalformedRequest => Self::MalformedRequest,
            ChatErrorClass::Overflow => Self::Overflow,
            ChatErrorClass::Transient => Self::Transient,
            ChatErrorClass::CutoverRequired => Self::CutoverRequired,
            ChatErrorClass::Unknown => Self::Unknown,
        }
    }
}

/// A classified `blue.catbird.chat.*` endpoint failure.
///
/// The three policy answers are carried as precomputed fields rather than left
/// to the platform to derive from `class`. Deriving them per platform is how
/// five clients end up with five retry policies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct ChatV2EndpointError {
    /// The NSID of the endpoint that failed.
    pub endpoint: String,
    /// The exact wire error code, preserved even when unrecognized.
    pub code: String,
    /// Whether this build recognizes the code.
    pub is_known_code: bool,
    /// The server's human-readable detail, if any. Never a policy input.
    ///
    /// Named `detail` rather than `message` on purpose: the Android build
    /// post-processes generated Kotlin to rename error `message` members that
    /// collide with `Throwable.message`, against a hardcoded type list.
    pub detail: Option<String>,
    /// The policy classification.
    pub class: ChatV2ErrorClass,
    /// Whether the same request may be retried after a backoff delay.
    pub is_retryable_after_backoff: bool,
    /// Whether local state must be refetched and the request rebuilt.
    pub requires_state_resync: bool,
    /// Whether the device's authentication must be repaired first.
    pub requires_reauthentication: bool,
    /// Whether no automatic action can advance this attempt.
    pub is_terminal_for_request: bool,
}

impl From<EndpointError> for ChatV2EndpointError {
    fn from(error: EndpointError) -> Self {
        let class = error.class();
        Self {
            endpoint: error.endpoint.to_owned(),
            code: error.code.as_str().to_owned(),
            is_known_code: error.code.is_known(),
            detail: error.detail.clone(),
            class: class.into(),
            is_retryable_after_backoff: class.is_retryable_after_backoff(),
            requires_state_resync: class.requires_state_resync(),
            requires_reauthentication: class.requires_reauthentication(),
            is_terminal_for_request: class.is_terminal_for_request(),
        }
    }
}

/// Which frozen grammar a value should be checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum ChatV2IdentifierKind {
    /// Canonical lowercase hyphenated RFC 4122 variant UUIDv4.
    ConversationId,
    /// Append-row replay identity. Never substitutes for a transition ID.
    EntryId,
    /// Signed control transition identity.
    TransitionId,
    /// Send idempotency identity.
    MessageId,
    /// Registered device identity.
    DeviceId,
    /// Production canonical bare ATProto DID, 12-261 ASCII bytes.
    BareDid,
    /// 43-character base64url SHA-256 thumbprint of a raw Ed25519 key.
    KeyId,
    /// Exactly `YYYY-MM-DDTHH:MM:SS.sssZ`.
    Timestamp,
}

/// A value failed a frozen protocol grammar.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Error))]
pub enum ChatV2ValidationError {
    /// The value did not satisfy its grammar. `reason` names the exact
    /// predicate that rejected it.
    #[error("invalid {kind}: {reason}")]
    Invalid {
        /// The grammar that was applied.
        kind: String,
        /// The exact predicate that rejected the value.
        reason: String,
    },
}

impl ChatV2ValidationError {
    fn of(kind: ChatV2IdentifierKind, reason: impl core::fmt::Display) -> Self {
        Self::Invalid {
            kind: format!("{kind:?}"),
            reason: reason.to_string(),
        }
    }
}

/// Readiness of the clean chat protocol implementation in this build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct ChatV2Status {
    /// The protocol version this build implements.
    pub protocol_version: String,
    /// Whether the protocol can actually be used end to end.
    ///
    /// False until envelope verification and the context reducer land. The
    /// types are bindable well before the protocol is usable, and conflating
    /// the two is how a half-built protocol reaches a release.
    pub is_operational: bool,
    /// Capabilities this build implements, for lane coordination.
    pub implemented_capabilities: Vec<String>,
    /// Capabilities still outstanding before `is_operational` can be true.
    pub outstanding_capabilities: Vec<String>,
}

/// Classifies a `blue.catbird.chat.*` error code received off the wire.
///
/// Unknown codes are preserved verbatim and classified conservatively: not
/// retryable, not resync, terminal.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn chat_v2_classify_endpoint_error(
    endpoint: String,
    code: String,
    detail: Option<String>,
) -> ChatV2EndpointError {
    // `endpoint` is caller-supplied here rather than a &'static str, so the
    // typed error is built directly instead of via EndpointError::new.
    let parsed = ChatErrorCode::parse(&code);
    let class = parsed.classify();
    ChatV2EndpointError {
        endpoint,
        code: parsed.as_str().to_owned(),
        is_known_code: parsed.is_known(),
        detail,
        class: class.into(),
        is_retryable_after_backoff: class.is_retryable_after_backoff(),
        requires_state_resync: class.requires_state_resync(),
        requires_reauthentication: class.requires_reauthentication(),
        is_terminal_for_request: class.is_terminal_for_request(),
    }
}

/// Validates a value against one of the protocol's frozen grammars.
///
/// Values are rejected, never normalized: a near-miss spelling is an error, not
/// something to repair.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn chat_v2_validate_identifier(
    kind: ChatV2IdentifierKind,
    value: String,
) -> Result<(), ChatV2ValidationError> {
    match kind {
        ChatV2IdentifierKind::ConversationId => ConversationId::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::EntryId => EntryId::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::TransitionId => TransitionId::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::MessageId => MessageId::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::DeviceId => DeviceId::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::BareDid => BareDid::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::KeyId => KeyId::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
        ChatV2IdentifierKind::Timestamp => CanonicalTimestamp::parse(&value)
            .map(|_| ())
            .map_err(|err| ChatV2ValidationError::of(kind, err)),
    }
}

/// Builds the exact MLS BasicCredential identity for a DID and device.
///
/// Exposed so no platform hand-concatenates it. The identity is compared
/// byte-for-byte against the authenticated MLS sender leaf before attribution,
/// so a platform that assembled it slightly differently would fail
/// attribution in a way that looks like a crypto bug.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn chat_v2_basic_credential(
    actor_did: String,
    device_id: String,
) -> Result<String, ChatV2ValidationError> {
    let did = BareDid::parse(&actor_did)
        .map_err(|err| ChatV2ValidationError::of(ChatV2IdentifierKind::BareDid, err))?;
    let device = DeviceId::parse(&device_id)
        .map_err(|err| ChatV2ValidationError::of(ChatV2IdentifierKind::DeviceId, err))?;
    Ok(BasicCredential::new(did, device).to_string())
}

/// Reports what this build of the clean chat protocol can do.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub fn chat_v2_status() -> ChatV2Status {
    ChatV2Status {
        protocol_version: "1".to_owned(),
        // Deliberately false: the types below are bindable, the protocol is
        // not yet usable. Flip this only when the outstanding list is empty.
        is_operational: false,
        implemented_capabilities: vec![
            "identifiers".to_owned(),
            "typed-endpoint-errors".to_owned(),
            "cursors".to_owned(),
            "append-log-pull".to_owned(),
        ],
        outstanding_capabilities: vec![
            "pending-transition-journal".to_owned(),
            "context-reducer".to_owned(),
            "envelope-verification".to_owned(),
            "application-content-predicates".to_owned(),
            "recovery-ladder".to_owned(),
            "storage".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_a_known_code_with_precomputed_policy() {
        let error = chat_v2_classify_endpoint_error(
            "blue.catbird.chat.sendMessage".to_owned(),
            "RelationshipPolicyUnavailable".to_owned(),
            Some("evidence stale".to_owned()),
        );

        assert!(error.is_known_code);
        assert_eq!(error.class, ChatV2ErrorClass::Transient);
        assert!(error.is_retryable_after_backoff);
        assert!(!error.is_terminal_for_request);
        assert_eq!(error.detail.as_deref(), Some("evidence stale"));
    }

    #[test]
    fn a_block_denial_crosses_the_boundary_as_non_retryable() {
        let error = chat_v2_classify_endpoint_error(
            "blue.catbird.chat.sendMessage".to_owned(),
            "BlockedRelationship".to_owned(),
            None,
        );
        assert_eq!(error.class, ChatV2ErrorClass::RelationshipPolicy);
        assert!(
            !error.is_retryable_after_backoff,
            "a platform must not be able to read this as retryable"
        );
        assert!(error.is_terminal_for_request);
    }

    #[test]
    fn unknown_codes_survive_the_boundary_and_fail_closed() {
        let error = chat_v2_classify_endpoint_error(
            "blue.catbird.chat.getEntries".to_owned(),
            "SomeFutureServerCode".to_owned(),
            None,
        );
        assert!(!error.is_known_code);
        assert_eq!(
            error.code, "SomeFutureServerCode",
            "the exact code must reach platform telemetry"
        );
        assert_eq!(error.class, ChatV2ErrorClass::Unknown);
        assert!(!error.is_retryable_after_backoff);
        assert!(error.is_terminal_for_request);
    }

    #[test]
    fn the_precomputed_flags_agree_with_the_rust_classification() {
        // The point of precomputing is that platforms cannot derive these
        // differently. That only holds if the fields match the source of truth
        // for every code.
        for spelling in ChatErrorCode::KNOWN {
            let error = chat_v2_classify_endpoint_error(
                "blue.catbird.chat.submitTransition".to_owned(),
                (*spelling).to_owned(),
                None,
            );
            let class = ChatErrorCode::parse(spelling).classify();
            assert_eq!(error.class, class.into(), "{spelling} class");
            assert_eq!(
                error.is_retryable_after_backoff,
                class.is_retryable_after_backoff(),
                "{spelling} retry"
            );
            assert_eq!(
                error.requires_state_resync,
                class.requires_state_resync(),
                "{spelling} resync"
            );
            assert_eq!(
                error.requires_reauthentication,
                class.requires_reauthentication(),
                "{spelling} reauth"
            );
            assert_eq!(
                error.is_terminal_for_request,
                class.is_terminal_for_request(),
                "{spelling} terminal"
            );
        }
    }

    #[test]
    fn endpoint_error_converts_from_the_domain_type() {
        let domain = EndpointError::new(
            "blue.catbird.chat.getEntries",
            ChatErrorCode::DeviceRevoked,
            None,
        );
        let ffi: ChatV2EndpointError = domain.into();
        assert_eq!(ffi.code, "DeviceRevoked");
        assert!(ffi.requires_reauthentication);
    }

    #[test]
    fn validates_each_identifier_grammar() {
        let uuid = "70707070-7070-4070-b070-707070707070".to_owned();
        for kind in [
            ChatV2IdentifierKind::ConversationId,
            ChatV2IdentifierKind::EntryId,
            ChatV2IdentifierKind::TransitionId,
            ChatV2IdentifierKind::MessageId,
            ChatV2IdentifierKind::DeviceId,
        ] {
            assert!(
                chat_v2_validate_identifier(kind, uuid.clone()).is_ok(),
                "{kind:?}"
            );
            assert!(
                chat_v2_validate_identifier(kind, uuid.to_uppercase()).is_err(),
                "{kind:?} must reject uppercase"
            );
        }

        assert!(chat_v2_validate_identifier(
            ChatV2IdentifierKind::BareDid,
            "did:plc:z72i7hdynmk6r22z27h6tvur".to_owned()
        )
        .is_ok());
        assert!(chat_v2_validate_identifier(
            ChatV2IdentifierKind::Timestamp,
            "2026-08-14T12:34:56.789Z".to_owned()
        )
        .is_ok());
        assert!(chat_v2_validate_identifier(
            ChatV2IdentifierKind::Timestamp,
            "2026-08-14T12:34:56Z".to_owned()
        )
        .is_err());
    }

    #[test]
    fn validation_errors_name_the_failing_predicate() {
        let err = chat_v2_validate_identifier(
            ChatV2IdentifierKind::BareDid,
            "did:web:handle.invalid".to_owned(),
        )
        .unwrap_err();
        let ChatV2ValidationError::Invalid { kind, reason } = err;
        assert_eq!(kind, "BareDid");
        assert!(
            reason.contains("reserved"),
            "the platform must learn which predicate fired, got {reason:?}"
        );
    }

    #[test]
    fn builds_the_exact_basic_credential() {
        let credential = chat_v2_basic_credential(
            "did:plc:z72i7hdynmk6r22z27h6tvur".to_owned(),
            "70707070-7070-4070-b070-707070707070".to_owned(),
        )
        .unwrap();
        assert_eq!(
            credential,
            "did:plc:z72i7hdynmk6r22z27h6tvur#70707070-7070-4070-b070-707070707070"
        );
        assert_eq!(credential.len(), 69);
    }

    #[test]
    fn basic_credential_rejects_a_malformed_half() {
        assert!(chat_v2_basic_credential(
            "did:web:a.b".to_owned(),
            "70707070-7070-4070-b070-707070707070".to_owned()
        )
        .is_err());
        assert!(chat_v2_basic_credential(
            "did:plc:z72i7hdynmk6r22z27h6tvur".to_owned(),
            "not-a-uuid".to_owned()
        )
        .is_err());
    }

    #[test]
    fn the_build_reports_itself_as_not_operational() {
        let status = chat_v2_status();
        assert_eq!(status.protocol_version, "1");
        assert!(
            !status.is_operational,
            "the reducer and envelope layers are not built; \
             this must not read as usable"
        );
        assert!(!status.outstanding_capabilities.is_empty());
        assert!(
            status
                .outstanding_capabilities
                .contains(&"context-reducer".to_owned()),
            "the largest outstanding piece must be named"
        );
    }

    #[test]
    fn operational_and_outstanding_stay_consistent() {
        // Guards the one way this probe could lie: reporting operational while
        // work remains, or listing a capability as both done and outstanding.
        let status = chat_v2_status();
        for capability in &status.implemented_capabilities {
            assert!(
                !status.outstanding_capabilities.contains(capability),
                "{capability} is listed as both implemented and outstanding"
            );
        }
        assert_eq!(
            status.is_operational,
            status.outstanding_capabilities.is_empty(),
            "operational must mean exactly that nothing is outstanding"
        );
    }
}
