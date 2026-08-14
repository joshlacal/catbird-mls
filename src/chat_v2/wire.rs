//! Bridges the generated `blue.catbird.chat` transport types to the v2 domain.
//!
//! This is the only place that knows the shape of the generated
//! `ConversationEntry` union. Keeping it in one module means the rest of
//! `chat_v2` works against domain traits and never pattern-matches wire types,
//! and it gives regeneration a single blast radius.
//!
//! Nothing here interprets an entry. It reads the two routing fields the pull
//! layer needs — sequence and conversation — plus the entry kind. Signature,
//! transcript, and fingerprint verification are a separate layer, and no caller
//! may treat an entry as trustworthy on the strength of this module.

use super::append_log::AppendLogEntry;
use catbird_atproto::blue_catbird::chat::ConversationEntry;
use catbird_atproto::jacquard_common::BosStr;

/// Applies `$body` to the inner entry of any `ConversationEntry` arm.
///
/// The match is exhaustive with no wildcard, so adding a fifteenth arm to the
/// closed union breaks this build rather than silently routing a new kind
/// through a default. That is the drift guard for the union's shape.
macro_rules! with_entry {
    ($value:expr, |$entry:ident| $body:expr) => {
        match $value {
            ConversationEntry::ApplicationEntry($entry) => $body,
            ConversationEntry::CommitEntry($entry) => $body,
            ConversationEntry::PolicyEntry($entry) => $body,
            ConversationEntry::MetadataEntry($entry) => $body,
            ConversationEntry::CreationEntry($entry) => $body,
            ConversationEntry::ParticipantAcceptanceEntry($entry) => $body,
            ConversationEntry::ConversationCloseEntry($entry) => $body,
            ConversationEntry::ResetRequestEntry($entry) => $body,
            ConversationEntry::ResetActivationEntry($entry) => $body,
            ConversationEntry::LeafRecoveryFulfillmentEntry($entry) => $body,
            ConversationEntry::LeaveRequestEntry($entry) => $body,
            ConversationEntry::ZeroLeafLeaveEntry($entry) => $body,
            ConversationEntry::LeaveCancellationEntry($entry) => $body,
            ConversationEntry::LeaveCommitFulfillmentEntry($entry) => $body,
        }
    };
}

// The exact full lexicon type IDs of the append-log entry arms.
//
// For the thirteen control arms this is the `entryKind` that the control-entry
// fingerprint commits, so these are load-bearing bytes rather than labels. A
// typo here would be a silent cross-client fingerprint mismatch, not a build
// failure, which is why they are named constants used both by `entry_kind` and
// by [`ENTRY_KINDS`] rather than repeated string literals.

/// `#applicationEntry` — the one arm that is not a control kind.
pub const APPLICATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#applicationEntry";
/// `#commitEntry`, signed by `#signedCommitTransition`.
pub const COMMIT_ENTRY_KIND: &str = "blue.catbird.chat.defs#commitEntry";
/// `#policyEntry`, signed by `#signedPolicyTransition`.
pub const POLICY_ENTRY_KIND: &str = "blue.catbird.chat.defs#policyEntry";
/// `#metadataEntry`, signed by `#signedMetadataTransition`.
pub const METADATA_ENTRY_KIND: &str = "blue.catbird.chat.defs#metadataEntry";
/// `#creationEntry`, signed by `#signedCreation`.
pub const CREATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#creationEntry";
/// `#participantAcceptanceEntry`. Carries `serverFields.recovery`.
pub const PARTICIPANT_ACCEPTANCE_ENTRY_KIND: &str =
    "blue.catbird.chat.defs#participantAcceptanceEntry";
/// `#conversationCloseEntry`. Carries `serverFields.tombstone`.
pub const CONVERSATION_CLOSE_ENTRY_KIND: &str = "blue.catbird.chat.defs#conversationCloseEntry";
/// `#resetRequestEntry`, signed by `#signedResetRequest`.
pub const RESET_REQUEST_ENTRY_KIND: &str = "blue.catbird.chat.defs#resetRequestEntry";
/// `#resetActivationEntry`, signed by `#signedResetActivation`.
pub const RESET_ACTIVATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#resetActivationEntry";
/// `#leafRecoveryFulfillmentEntry`, the only arm that may carry an MLS Add.
pub const LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND: &str =
    "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry";
/// `#leaveRequestEntry`, signed by `#signedLeaveRequest`.
pub const LEAVE_REQUEST_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveRequestEntry";
/// `#zeroLeafLeaveEntry`, signed by `#signedZeroLeafLeave`.
pub const ZERO_LEAF_LEAVE_ENTRY_KIND: &str = "blue.catbird.chat.defs#zeroLeafLeaveEntry";
/// `#leaveCancellationEntry`, signed by `#signedLeaveCancellation`.
pub const LEAVE_CANCELLATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveCancellationEntry";
/// `#leaveCommitFulfillmentEntry`, signed by `#signedLeaveCommitFulfillment`.
pub const LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND: &str =
    "blue.catbird.chat.defs#leaveCommitFulfillmentEntry";

/// Every arm of the closed `#conversationEntry` union: the application entry
/// plus the thirteen control kinds.
pub const ENTRY_KINDS: [&str; 14] = [
    APPLICATION_ENTRY_KIND,
    COMMIT_ENTRY_KIND,
    POLICY_ENTRY_KIND,
    METADATA_ENTRY_KIND,
    CREATION_ENTRY_KIND,
    PARTICIPANT_ACCEPTANCE_ENTRY_KIND,
    CONVERSATION_CLOSE_ENTRY_KIND,
    RESET_REQUEST_ENTRY_KIND,
    RESET_ACTIVATION_ENTRY_KIND,
    LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
    LEAVE_REQUEST_ENTRY_KIND,
    ZERO_LEAF_LEAVE_ENTRY_KIND,
    LEAVE_CANCELLATION_ENTRY_KIND,
    LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
];

/// The two control arms whose mandatory `serverFields` is not `{}`.
///
/// Acceptance carries `{recovery}` and close carries `{tombstone}`; every other
/// control arm carries exactly `{}`. The fingerprint projection depends on this
/// pairing, so it is declared rather than rediscovered at each call site.
pub const ENTRY_KINDS_WITH_SERVER_FIELDS: [&str; 2] = [
    PARTICIPANT_ACCEPTANCE_ENTRY_KIND,
    CONVERSATION_CLOSE_ENTRY_KIND,
];

/// Reads the kind of a wire entry.
pub trait WireEntry {
    /// The exact full lexicon type ID of this arm.
    fn entry_kind(&self) -> &'static str;

    /// Whether this arm is the application entry rather than one of the
    /// thirteen control kinds. The two use different fingerprint domains.
    fn is_application(&self) -> bool {
        self.entry_kind() == APPLICATION_ENTRY_KIND
    }
}

impl<S: BosStr> WireEntry for ConversationEntry<S> {
    fn entry_kind(&self) -> &'static str {
        match self {
            Self::ApplicationEntry(_) => APPLICATION_ENTRY_KIND,
            Self::CommitEntry(_) => COMMIT_ENTRY_KIND,
            Self::PolicyEntry(_) => POLICY_ENTRY_KIND,
            Self::MetadataEntry(_) => METADATA_ENTRY_KIND,
            Self::CreationEntry(_) => CREATION_ENTRY_KIND,
            Self::ParticipantAcceptanceEntry(_) => PARTICIPANT_ACCEPTANCE_ENTRY_KIND,
            Self::ConversationCloseEntry(_) => CONVERSATION_CLOSE_ENTRY_KIND,
            Self::ResetRequestEntry(_) => RESET_REQUEST_ENTRY_KIND,
            Self::ResetActivationEntry(_) => RESET_ACTIVATION_ENTRY_KIND,
            Self::LeafRecoveryFulfillmentEntry(_) => LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
            Self::LeaveRequestEntry(_) => LEAVE_REQUEST_ENTRY_KIND,
            Self::ZeroLeafLeaveEntry(_) => ZERO_LEAF_LEAVE_ENTRY_KIND,
            Self::LeaveCancellationEntry(_) => LEAVE_CANCELLATION_ENTRY_KIND,
            Self::LeaveCommitFulfillmentEntry(_) => LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
        }
    }
}

impl<S: BosStr> AppendLogEntry for ConversationEntry<S> {
    fn raw_seq(&self) -> i64 {
        with_entry!(self, |entry| entry.seq)
    }

    fn raw_conversation_id(&self) -> &str {
        with_entry!(self, |entry| entry.conversation_id.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_union_has_the_application_arm_plus_thirteen_control_kinds() {
        assert_eq!(ENTRY_KINDS.len(), 14);
        let control_kinds = ENTRY_KINDS
            .iter()
            .filter(|kind| **kind != APPLICATION_ENTRY_KIND)
            .count();
        assert_eq!(control_kinds, 13);
    }

    #[test]
    fn entry_kinds_are_distinct() {
        let mut sorted = ENTRY_KINDS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "no kind may be declared twice");
    }

    #[test]
    fn entry_kinds_use_the_exact_defs_namespace_and_lower_camel_fragment() {
        for kind in ENTRY_KINDS {
            let fragment = kind
                .strip_prefix("blue.catbird.chat.defs#")
                .unwrap_or_else(|| panic!("{kind} must be a blue.catbird.chat.defs fragment"));
            assert!(
                fragment.starts_with(|c: char| c.is_ascii_lowercase()),
                "{kind} fragment must be lowerCamelCase"
            );
            assert!(
                fragment.ends_with("Entry"),
                "{kind} fragment must name an entry"
            );
        }
    }

    #[test]
    fn only_acceptance_and_close_carry_server_fields() {
        // Every other control arm's mandatory serverFields is exactly `{}`.
        assert_eq!(ENTRY_KINDS_WITH_SERVER_FIELDS.len(), 2);
        for kind in ENTRY_KINDS_WITH_SERVER_FIELDS {
            assert!(
                ENTRY_KINDS.contains(&kind),
                "{kind} must be an arm of the union"
            );
            assert_ne!(
                kind, APPLICATION_ENTRY_KIND,
                "serverFields is a control-entry concept"
            );
        }
    }

    #[test]
    fn the_application_kind_is_a_member_of_the_union() {
        assert!(ENTRY_KINDS.contains(&APPLICATION_ENTRY_KIND));
    }

    // Per-arm verification against real signed fixtures belongs with the
    // envelope layer, which consumes the Task 1 OpenMLS wire corpus. Building
    // partial fixtures here would assert nothing about the bytes that matter,
    // so the completeness guarantee for this module is the exhaustive match in
    // `with_entry!` and `entry_kind`: a fifteenth arm fails to compile.
}
