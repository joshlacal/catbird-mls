//! Policy classification for typed chat error codes.
//!
//! The sync loop and the bounded recovery ladder need three decisions and no
//! more: may this be retried on a timer, must local state be resynchronized
//! first, and must the device re-authenticate. Everything else is terminal for
//! the attempt and belongs to the caller or the user.
//!
//! The classification match below is deliberately exhaustive with no wildcard.
//! A lexicon change that adds an error code will fail to compile here until
//! someone decides what the ladder should do about it — which is the point.
//! Silently defaulting a new code to "retry" is how a client ends up hammering
//! an endpoint that will never succeed.

use super::code::ChatErrorCode;

/// What a chat error code means for synchronization and recovery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatErrorClass {
    /// The device's credential, DPoP binding, or authentication generation is
    /// no longer valid. Requires rebind, re-enrollment, or a new device — never
    /// a blind retry.
    Authentication,
    /// The principal is authenticated but not permitted to perform this
    /// operation in this state.
    Authorization,
    /// A relationship or declaration policy denied the operation. Surfaced to
    /// the user; never auto-retried, because retrying cannot change a block.
    RelationshipPolicy,
    /// A peer is not yet in a state where the operation can succeed. Resolved
    /// by a future state change, not by elapsed time.
    Readiness,
    /// The request was built against a coordinate the server has moved past.
    /// The client must refetch state and rebuild against the new coordinate.
    StaleCoordinate,
    /// Another writer won a race, or the same operation identity already
    /// carries different bytes. The stored winner must be read; resubmitting
    /// the same bytes cannot succeed.
    Conflict,
    /// The named resource does not exist.
    NotFound,
    /// A time-bounded resource lapsed and must be re-established.
    Expired,
    /// A protocol quota or cap was reached.
    LimitReached,
    /// The request was structurally or cryptographically invalid. This is a
    /// client defect: the same bytes will never be accepted.
    MalformedRequest,
    /// A checked increment would pass the safe-integer ceiling.
    Overflow,
    /// A temporary server-side condition. The only class that may be retried
    /// on a backoff timer.
    Transient,
    /// The client is speaking the superseded protocol and must be upgraded.
    CutoverRequired,
    /// A code this build does not recognize. Classified conservatively.
    Unknown,
}

impl ChatErrorClass {
    /// Whether an unchanged request may be retried after a backoff delay.
    ///
    /// Only [`Self::Transient`] qualifies. In particular an unknown code does
    /// not: a client that retries codes it cannot interpret will hammer an
    /// endpoint that may never succeed.
    pub fn is_retryable_after_backoff(&self) -> bool {
        matches!(self, Self::Transient)
    }

    /// Whether the client must refetch conversation state and rebuild the
    /// request before any further attempt.
    pub fn requires_state_resync(&self) -> bool {
        matches!(self, Self::StaleCoordinate | Self::Conflict)
    }

    /// Whether the device's authentication must be repaired before retrying.
    pub fn requires_reauthentication(&self) -> bool {
        matches!(self, Self::Authentication)
    }

    /// Whether this attempt is over and no automatic action can advance it.
    pub fn is_terminal_for_request(&self) -> bool {
        !self.is_retryable_after_backoff()
            && !self.requires_state_resync()
            && !self.requires_reauthentication()
    }
}

impl ChatErrorCode {
    /// Classifies this code for synchronization and recovery policy.
    pub fn classify(&self) -> ChatErrorClass {
        use ChatErrorClass as C;
        match self {
            // Authentication: the device credential itself is the problem.
            Self::InvalidDPoP
            | Self::DeviceNotRegistered
            | Self::DeviceRevoked
            | Self::DeviceTombstoned
            | Self::DeviceNotFound
            | Self::AuthenticationGenerationConflict => C::Authentication,

            // Authorization: authenticated, but not permitted here and now.
            Self::NotAuthorized
            | Self::NotMember
            | Self::NotParticipant
            | Self::NotEntitled
            | Self::AdminRequired
            | Self::LastAdminRequired
            | Self::DeviceNotLeaf
            | Self::AccessOutsideMembershipInterval
            | Self::ConversationCloseNotAllowed
            | Self::DirectParticipantMutationForbidden
            | Self::CommitterSelfRemovalForbidden
            | Self::ExternalCommitForbidden
            | Self::StandaloneProposalForbidden
            | Self::InvitationNotPending => C::Authorization,

            // Relationship policy. Two independent reasons these are never put
            // on a timer. First, retrying cannot change a block or a
            // declaration, so the retry can only ever fail. Second — and this
            // is the one that makes it a safety rule rather than an efficiency
            // one — a client that re-attempts delivery on a schedule keeps
            // generating requests against a party who has blocked the actor,
            // leaking continued activity and presence to exactly the person who
            // asked not to receive it. Backing off is not enough; the correct
            // behaviour is to stop and surface it.
            Self::BlockedRelationship
            | Self::MessagesDisabled
            | Self::GroupInvitesDisabled
            | Self::NotFollowedByRecipient => C::RelationshipPolicy,

            // Readiness: resolved by a state change, not by waiting.
            Self::RecipientNotReady | Self::ConversationNotAccepted => C::Readiness,

            // Stale coordinate: rebuild against the server's current coordinate.
            Self::StaleCoordinates
            | Self::LeaveRequestStale
            | Self::ResetRequestStale
            | Self::LeafRecoverySuperseded
            | Self::WelcomeSuperseded => C::StaleCoordinate,

            // Conflict: another writer won, or this operation identity already
            // carries different bytes. Read the winner; do not resubmit.
            Self::IdempotencyConflict
            | Self::AcknowledgementConflict
            | Self::CancellationConflict
            | Self::RejectionConflict
            | Self::BlobConflict
            | Self::BlobBindingConflict
            | Self::BlobBound
            | Self::BlobAlreadyExists
            | Self::ConversationAlreadyExists
            | Self::DeviceAlreadyExists
            | Self::DuplicateDeviceLeaf
            | Self::LeafRecoveryAlreadyOpen
            | Self::LeaveAlreadyPending
            | Self::ResetAlreadyPending
            | Self::MetadataNonceReuse => C::Conflict,

            Self::ConversationNotFound
            | Self::BlobNotFound
            | Self::WelcomeNotFound
            | Self::InvitationNotFound
            | Self::LeafRecoveryNotFound
            | Self::LeaveRequestNotFound
            | Self::ResetRequestNotFound
            | Self::UploadTicketNotFound => C::NotFound,

            Self::WelcomeExpired
            | Self::LeafRecoveryExpired
            | Self::LeaveRequestExpired
            | Self::CursorExpired
            | Self::InventorySessionExpired
            | Self::UploadTicketExpired => C::Expired,

            Self::DeviceLimitReached
            | Self::InvitationLimitReached
            | Self::BlobQuotaExceeded
            | Self::ConversationLeafLimitReached
            | Self::ParticipantLeafLimitReached
            | Self::ParticipantLimitReached
            | Self::KeyPackageInventoryLimitReached
            | Self::KeyPackageUnavailable => C::LimitReached,

            // Client defects. The same bytes will never be accepted, so these
            // must never be retried, with or without a delay.
            Self::InvalidRequest
            | Self::InvalidSignature
            | Self::InvalidCommit
            | Self::InvalidApplicationMessage
            | Self::InvalidGenesisGroupInfo
            | Self::InvalidKeyPackage
            | Self::InvalidLeaveManifest
            | Self::InvalidMetadataSnapshot
            | Self::InvalidMlsArtifact
            | Self::InvalidWelcomeMapping
            | Self::InvalidTicket
            | Self::MissingMetadataSnapshot
            | Self::UnsupportedMlsProfile
            | Self::BlobHashMismatch
            | Self::BlobSizeMismatch
            | Self::InvitationProvenanceMismatch
            | Self::InventorySessionMismatch
            | Self::InventoryIncomplete => C::MalformedRequest,

            Self::CoordinateOverflow | Self::MetadataVersionOverflow => C::Overflow,

            // The only auto-retryable class. `RelationshipPolicyUnavailable` is
            // explicitly documented as retryable: it signals unavailable,
            // incomplete, or stale evidence rather than a denial.
            Self::RelationshipPolicyUnavailable | Self::RateLimited => C::Transient,

            Self::CutoverRequired => C::CutoverRequired,

            Self::Unknown(_) => C::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_code_classifies() {
        for spelling in ChatErrorCode::KNOWN {
            let code = ChatErrorCode::parse(spelling);
            assert_ne!(
                code.classify(),
                ChatErrorClass::Unknown,
                "{spelling} is a known code and must not classify as Unknown"
            );
        }
    }

    #[test]
    fn only_transient_codes_are_auto_retryable() {
        let retryable: Vec<&str> = ChatErrorCode::KNOWN
            .iter()
            .filter(|spelling| {
                ChatErrorCode::parse(spelling)
                    .classify()
                    .is_retryable_after_backoff()
            })
            .copied()
            .collect();
        assert_eq!(
            retryable,
            vec!["RateLimited", "RelationshipPolicyUnavailable"],
            "widening the auto-retry set is a policy change and must be deliberate"
        );
    }

    #[test]
    fn unknown_codes_fail_closed() {
        let class = ChatErrorCode::parse("SomeFutureServerCode").classify();
        assert_eq!(class, ChatErrorClass::Unknown);
        assert!(
            !class.is_retryable_after_backoff(),
            "an uninterpretable code must never be retried on a timer"
        );
        assert!(!class.requires_state_resync());
        assert!(!class.requires_reauthentication());
        assert!(class.is_terminal_for_request());
    }

    #[test]
    fn relationship_denials_are_never_retried() {
        // A block cannot be cleared by waiting, so putting these on a backoff
        // timer would produce an endless loop that also leaks activity to the
        // blocking party.
        for spelling in [
            "BlockedRelationship",
            "MessagesDisabled",
            "GroupInvitesDisabled",
            "NotFollowedByRecipient",
        ] {
            let class = ChatErrorCode::parse(spelling).classify();
            assert_eq!(class, ChatErrorClass::RelationshipPolicy);
            assert!(!class.is_retryable_after_backoff(), "{spelling}");
        }

        // Its unavailable counterpart is the opposite: evidence was missing or
        // stale, not denied, so it is the retryable one.
        let unavailable = ChatErrorCode::RelationshipPolicyUnavailable.classify();
        assert_eq!(unavailable, ChatErrorClass::Transient);
        assert!(unavailable.is_retryable_after_backoff());
    }

    #[test]
    fn client_defects_are_never_retried() {
        for spelling in ["InvalidSignature", "InvalidRequest", "InvalidCommit"] {
            let class = ChatErrorCode::parse(spelling).classify();
            assert!(
                !class.is_retryable_after_backoff() && !class.requires_state_resync(),
                "{spelling} will never be accepted with the same bytes"
            );
            assert!(class.is_terminal_for_request());
        }
    }

    #[test]
    fn stale_and_conflict_codes_demand_a_resync_not_a_retry() {
        for spelling in [
            "StaleCoordinates",
            "IdempotencyConflict",
            "MetadataNonceReuse",
        ] {
            let class = ChatErrorCode::parse(spelling).classify();
            assert!(class.requires_state_resync(), "{spelling}");
            assert!(
                !class.is_retryable_after_backoff(),
                "{spelling} must not be resubmitted unchanged"
            );
            assert!(!class.is_terminal_for_request());
        }
    }

    #[test]
    fn credential_failures_demand_reauthentication() {
        for spelling in ["InvalidDPoP", "DeviceRevoked", "DeviceNotRegistered"] {
            let class = ChatErrorCode::parse(spelling).classify();
            assert!(class.requires_reauthentication(), "{spelling}");
            assert!(!class.is_retryable_after_backoff());
            assert!(!class.is_terminal_for_request());
        }
    }

    #[test]
    fn the_three_policy_predicates_are_mutually_exclusive() {
        // A caller reads these in sequence; overlapping answers would make the
        // order of the checks change the behaviour.
        for spelling in ChatErrorCode::KNOWN {
            let class = ChatErrorCode::parse(spelling).classify();
            let set = [
                class.is_retryable_after_backoff(),
                class.requires_state_resync(),
                class.requires_reauthentication(),
            ];
            assert!(
                set.iter().filter(|answered| **answered).count() <= 1,
                "{spelling} answered more than one policy predicate"
            );
            assert_eq!(
                class.is_terminal_for_request(),
                !set.iter().any(|answered| *answered),
                "{spelling}: terminal must be exactly the absence of an action"
            );
        }
    }

    #[test]
    fn cutover_is_terminal_rather_than_retryable() {
        // A client that retries CutoverRequired is a client that never
        // discovers it needs upgrading.
        let class = ChatErrorCode::CutoverRequired.classify();
        assert_eq!(class, ChatErrorClass::CutoverRequired);
        assert!(class.is_terminal_for_request());
    }
}
