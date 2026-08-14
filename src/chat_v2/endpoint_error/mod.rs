//! Typed endpoint-error mapping for the clean chat protocol.
//!
//! Every generated endpoint declares its own `*Error` enum. Rather than write
//! 32 hand-maintained `From` impls that must be revisited on every lexicon
//! change, this module reads the discriminant through serde's own adjacent
//! tagging — the exact mechanism the wire format uses — and resolves it against
//! the closed [`ChatErrorCode`] set.
//!
//! That is a structural extraction, not string inspection: it reads the `error`
//! tag serde emits from the variant's `#[serde(rename = ...)]`, which is by
//! construction the wire spelling. Nothing here parses a rendered message, and
//! nothing downstream is given the opportunity to.

pub mod class;
pub mod code;

pub use class::ChatErrorClass;
pub use code::ChatErrorCode;

use core::fmt;

/// The JSON member carrying the error code, per the generated `#[serde(tag)]`.
const TAG_FIELD: &str = "error";
/// The JSON member carrying the human-readable detail, per `#[serde(content)]`.
const CONTENT_FIELD: &str = "message";

/// A typed failure returned by a `blue.catbird.chat.*` endpoint.
///
/// The detail field is named `detail` rather than `message` deliberately: the
/// Android build post-processes generated Kotlin to rename error `message`
/// members that collide with `Throwable.message`, and that script is hardcoded
/// to a fixed list of types. Avoiding the name keeps v2 types off that list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointError {
    /// The NSID of the endpoint that failed.
    pub endpoint: &'static str,
    /// The typed error code.
    pub code: ChatErrorCode,
    /// The server's human-readable detail, if it sent one. Never used to make
    /// a policy decision.
    pub detail: Option<String>,
}

impl EndpointError {
    /// Builds a typed error directly.
    pub fn new(endpoint: &'static str, code: ChatErrorCode, detail: Option<String>) -> Self {
        Self {
            endpoint,
            code,
            detail,
        }
    }

    /// Extracts the typed code from any generated endpoint error enum.
    ///
    /// Generated error enums are adjacently tagged as
    /// `#[serde(tag = "error", content = "message")]`, so serializing yields
    /// the variant's wire spelling under `error`. The untagged `Other` arm
    /// carries the same two members, so unknown server codes flow through the
    /// same path and land in [`ChatErrorCode::Unknown`].
    pub fn from_generated<E: serde::Serialize>(endpoint: &'static str, error: &E) -> Self {
        let value = match serde_json::to_value(error) {
            Ok(value) => value,
            Err(err) => {
                // The generated enums are plain derives over owned data, so
                // this is unreachable in practice. Failing closed with an
                // unknown code is still better than a panic on an error path.
                return Self::new(
                    endpoint,
                    ChatErrorCode::Unknown(format!("UnserializableError({err})")),
                    None,
                );
            }
        };

        let code = value
            .get(TAG_FIELD)
            .and_then(serde_json::Value::as_str)
            .map(ChatErrorCode::parse)
            .unwrap_or_else(|| ChatErrorCode::Unknown("MissingErrorTag".to_owned()));

        let detail = value
            .get(CONTENT_FIELD)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        Self::new(endpoint, code, detail)
    }

    /// The policy classification of this error.
    pub fn class(&self) -> ChatErrorClass {
        self.code.classify()
    }

    /// Whether the same request may be retried after a backoff delay.
    pub fn is_retryable_after_backoff(&self) -> bool {
        self.class().is_retryable_after_backoff()
    }

    /// Whether local state must be refetched and the request rebuilt.
    pub fn requires_state_resync(&self) -> bool {
        self.class().requires_state_resync()
    }

    /// Whether the device's authentication must be repaired first.
    pub fn requires_reauthentication(&self) -> bool {
        self.class().requires_reauthentication()
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.endpoint, self.code)?;
        if let Some(detail) = &self.detail {
            write!(f, " ({detail})")?;
        }
        Ok(())
    }
}

impl core::error::Error for EndpointError {}

#[cfg(test)]
mod tests {
    use super::*;
    use catbird_atproto::blue_catbird::chat;

    #[test]
    fn extracts_a_known_code_and_detail() {
        let generated = chat::send_message::SendMessageError::RecipientNotReady(Some(
            "peer has no leaf".into(),
        ));
        let typed = EndpointError::from_generated("blue.catbird.chat.sendMessage", &generated);

        assert_eq!(typed.code, ChatErrorCode::RecipientNotReady);
        assert_eq!(typed.detail.as_deref(), Some("peer has no leaf"));
        assert_eq!(typed.class(), ChatErrorClass::Readiness);
    }

    #[test]
    fn extracts_a_code_with_no_detail() {
        let generated = chat::send_message::SendMessageError::StaleCoordinates(None);
        let typed = EndpointError::from_generated("blue.catbird.chat.sendMessage", &generated);

        assert_eq!(typed.code, ChatErrorCode::StaleCoordinates);
        assert_eq!(typed.detail, None);
        assert!(typed.requires_state_resync());
    }

    #[test]
    fn works_across_different_endpoint_enums() {
        // One extraction path serves every endpoint; there are no per-endpoint
        // From impls to fall out of date when a lexicon changes.
        let entries = chat::get_entries::GetEntriesError::NotEntitled(None);
        assert_eq!(
            EndpointError::from_generated("blue.catbird.chat.getEntries", &entries).code,
            ChatErrorCode::NotEntitled
        );

        let recovery =
            chat::request_leaf_recovery::RequestLeafRecoveryError::LeafRecoveryAlreadyOpen(None);
        assert_eq!(
            EndpointError::from_generated("blue.catbird.chat.requestLeafRecovery", &recovery).code,
            ChatErrorCode::LeafRecoveryAlreadyOpen
        );

        let transition = chat::submit_transition::SubmitTransitionError::CoordinateOverflow(None);
        assert_eq!(
            EndpointError::from_generated("blue.catbird.chat.submitTransition", &transition).code,
            ChatErrorCode::CoordinateOverflow
        );
    }

    #[test]
    fn preserves_the_invalid_dpop_spelling_exactly() {
        // `InvalidDPoP` keeps its irregular casing on the wire. A mapping that
        // normalized case would silently fail to match it.
        let generated = chat::get_entries::GetEntriesError::InvalidDPoP(None);
        let typed = EndpointError::from_generated("blue.catbird.chat.getEntries", &generated);
        assert_eq!(typed.code, ChatErrorCode::InvalidDPoP);
        assert_eq!(typed.code.as_str(), "InvalidDPoP");
        assert!(typed.requires_reauthentication());
    }

    #[test]
    fn unknown_server_codes_flow_through_the_other_arm() {
        // A server ahead of this client sends a code we do not know. It must
        // survive intact for telemetry and must classify conservatively.
        let generated = chat::get_entries::GetEntriesError::Other {
            error: "SomeFutureServerCode".into(),
            message: Some("from a newer server".into()),
        };
        let typed = EndpointError::from_generated("blue.catbird.chat.getEntries", &generated);

        assert_eq!(
            typed.code,
            ChatErrorCode::Unknown("SomeFutureServerCode".to_owned())
        );
        assert_eq!(typed.detail.as_deref(), Some("from a newer server"));
        assert!(!typed.is_retryable_after_backoff());
        assert!(typed.class().is_terminal_for_request());
    }

    #[test]
    fn every_generated_variant_of_one_endpoint_resolves() {
        // A drift guard: if the generator changed its tagging strategy, this
        // extraction would silently start returning MissingErrorTag for
        // everything. Sweeping one endpoint's full variant set catches that.
        let all = [
            chat::get_entries::GetEntriesError::AccessOutsideMembershipInterval(None),
            chat::get_entries::GetEntriesError::ConversationNotFound(None),
            chat::get_entries::GetEntriesError::CutoverRequired(None),
            chat::get_entries::GetEntriesError::DeviceNotRegistered(None),
            chat::get_entries::GetEntriesError::DeviceRevoked(None),
            chat::get_entries::GetEntriesError::InvalidDPoP(None),
            chat::get_entries::GetEntriesError::InvalidRequest(None),
            chat::get_entries::GetEntriesError::NotEntitled(None),
        ];
        for generated in &all {
            let typed = EndpointError::from_generated("blue.catbird.chat.getEntries", generated);
            assert!(
                typed.code.is_known(),
                "{typed} failed to resolve to a known code"
            );
        }
    }

    #[test]
    fn display_names_the_endpoint_and_code() {
        let typed = EndpointError::new(
            "blue.catbird.chat.sendMessage",
            ChatErrorCode::BlockedRelationship,
            Some("blocked".to_owned()),
        );
        assert_eq!(
            typed.to_string(),
            "blue.catbird.chat.sendMessage: BlockedRelationship (blocked)"
        );

        let without_detail = EndpointError::new(
            "blue.catbird.chat.sendMessage",
            ChatErrorCode::BlockedRelationship,
            None,
        );
        assert_eq!(
            without_detail.to_string(),
            "blue.catbird.chat.sendMessage: BlockedRelationship"
        );
    }

    #[test]
    fn detail_never_influences_classification() {
        // The whole point of this layer: policy reads the code, never the
        // prose. Two errors with the same code classify identically no matter
        // what the server wrote in the message.
        let misleading = EndpointError::new(
            "blue.catbird.chat.getEntries",
            ChatErrorCode::NotEntitled,
            Some("404 not found, please retry".to_owned()),
        );
        let plain = EndpointError::new(
            "blue.catbird.chat.getEntries",
            ChatErrorCode::NotEntitled,
            None,
        );
        assert_eq!(misleading.class(), plain.class());
        assert!(
            !misleading.is_retryable_after_backoff(),
            "text saying 'retry' must not make an error retryable"
        );
    }
}
