//! The closed set of `blue.catbird.chat.*` XRPC error codes.
//!
//! This is the union of every typed error across the 32 protocol endpoints.
//! Modelling it as one enum rather than 32 per-endpoint enums lets the sync and
//! recovery policy match on a code once, instead of re-deriving the same
//! decision per call site.
//!
//! The v1 orchestrator classified server failures by substring-matching
//! rendered error strings — `err.to_string().contains("404")` gated its
//! recovery circuit breaker, and OpenMLS error text was grepped to decide
//! whether to quarantine a conversation. That is what this module replaces:
//! nothing downstream of here ever inspects a message string to decide policy.

/// Declares the code enum and its string mapping from a single list, so a
/// variant and its wire spelling cannot drift apart.
macro_rules! chat_error_codes {
    ($($(#[$meta:meta])* $variant:ident),* $(,)?) => {
        /// A typed `blue.catbird.chat.*` error code.
        ///
        /// [`ChatErrorCode::Unknown`] carries a code this build does not know.
        /// It is deliberately not an error in itself — a server may legitimately
        /// be ahead of a client — but it always classifies conservatively.
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum ChatErrorCode {
            $($(#[$meta])* $variant,)*
            /// A code absent from this build's known set.
            Unknown(String),
        }

        impl ChatErrorCode {
            /// Every code spelling this build recognizes.
            pub const KNOWN: &'static [&'static str] = &[$(stringify!($variant),)*];

            /// The exact wire spelling.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => stringify!($variant),)*
                    Self::Unknown(code) => code.as_str(),
                }
            }

            /// Resolves a wire spelling, falling back to [`Self::Unknown`].
            ///
            /// Matching is exact and case-sensitive: the protocol spells codes
            /// in a fixed PascalCase, and accepting a variant spelling would
            /// reintroduce exactly the fuzziness this type exists to remove.
            pub fn parse(code: &str) -> Self {
                match code {
                    $(c if c == stringify!($variant) => Self::$variant,)*
                    other => Self::Unknown(other.to_owned()),
                }
            }

            /// Whether this build recognizes the code.
            pub fn is_known(&self) -> bool {
                !matches!(self, Self::Unknown(_))
            }
        }
    };
}

chat_error_codes! {
    AccountSessionExpired,
    /// The requested scan position lies outside the caller's membership interval.
    AccessOutsideMembershipInterval,
    AcknowledgementConflict,
    AdminRequired,
    AuthenticationGenerationConflict,
    BlobAlreadyExists,
    BlobBindingConflict,
    BlobBound,
    BlobConflict,
    BlobHashMismatch,
    BlobNotFound,
    BlobQuotaExceeded,
    BlobSizeMismatch,
    BlockedRelationship,
    CancellationConflict,
    CommitterSelfRemovalForbidden,
    ConversationAlreadyExists,
    ConversationCloseNotAllowed,
    ConversationLeafLimitReached,
    ConversationNotAccepted,
    ConversationNotFound,
    /// A checked coordinate increment would have passed the safe-integer ceiling.
    CoordinateOverflow,
    CursorExpired,
    /// The caller is speaking the superseded protocol and must upgrade.
    CutoverRequired,
    DeviceAlreadyExists,
    DeviceBindingMismatch,
    DeviceLimitReached,
    DeviceNotFound,
    DeviceNotLeaf,
    DeviceNotRegistered,
    DeviceRevoked,
    DeviceTombstoned,
    DirectParticipantMutationForbidden,
    DuplicateDeviceLeaf,
    ExternalCommitForbidden,
    GroupInvitesDisabled,
    IdempotencyConflict,
    InvalidApplicationMessage,
    InvalidCommit,
    InvalidGenesisGroupInfo,
    InvalidKeyPackage,
    InvalidLeaveManifest,
    InvalidMetadataSnapshot,
    InvalidMlsArtifact,
    InvalidRequest,
    InvalidSignature,
    InvalidTicket,
    InvalidWelcomeMapping,
    InventoryIncomplete,
    InventorySessionExpired,
    InventorySessionMismatch,
    InvitationLimitReached,
    InvitationNotFound,
    InvitationNotPending,
    InvitationProvenanceMismatch,
    KeyPackageInventoryLimitReached,
    KeyPackageUnavailable,
    LastAdminRequired,
    /// A different open request already exists for this exact
    /// `(conversation, generation, requester DID, requester device)`.
    LeafRecoveryAlreadyOpen,
    LeafRecoveryExpired,
    LeafRecoveryNotFound,
    LeafRecoverySuperseded,
    LeaveAlreadyPending,
    LeaveRequestExpired,
    LeaveRequestNotFound,
    LeaveRequestStale,
    MessagesDisabled,
    MetadataNonceReuse,
    MetadataVersionOverflow,
    MissingMetadataSnapshot,
    NotAuthorized,
    NotEntitled,
    NotFollowedByRecipient,
    NotMember,
    NotParticipant,
    ParticipantLeafLimitReached,
    ParticipantLimitReached,
    ProtocolUpgradeRequired,
    RateLimited,
    /// A direct peer is active but currently has no MLS leaf, i.e. an
    /// acceptance, recovery, or reset gap.
    RecipientNotReady,
    RejectionConflict,
    /// Relationship evidence was unavailable, incomplete, malformed, stale, or
    /// over a deadline or capacity cap. Retryable.
    RelationshipPolicyUnavailable,
    ResetAlreadyPending,
    ResetRequestNotFound,
    ResetRequestStale,
    StaleCoordinates,
    StandaloneProposalForbidden,
    UnsupportedMlsProfile,
    UploadTicketExpired,
    UploadTicketNotFound,
    WelcomeExpired,
    WelcomeNotFound,
    WelcomeSuperseded,
}

impl core::fmt::Display for ChatErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_round_trip() {
        for spelling in ChatErrorCode::KNOWN {
            let code = ChatErrorCode::parse(spelling);
            assert!(
                code.is_known(),
                "{spelling} must resolve to a known variant"
            );
            assert_eq!(
                code.as_str(),
                *spelling,
                "{spelling} must round-trip to its exact wire spelling"
            );
        }
    }

    #[test]
    fn the_known_set_covers_the_whole_protocol_surface() {
        // Extracted from every generated `*Error` enum across the 32 endpoint
        // modules. If a lexicon change adds a code, this count moves and the
        // classification match below stops compiling until it is triaged.
        assert_eq!(
            ChatErrorCode::KNOWN.len(),
            93,
            "the union of typed codes across all 32 endpoints"
        );
    }

    #[test]
    fn known_codes_are_unique() {
        let mut sorted = ChatErrorCode::KNOWN.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "no code may be declared twice");
    }

    #[test]
    fn unknown_codes_are_preserved_verbatim() {
        let code = ChatErrorCode::parse("SomeFutureServerCode");
        assert_eq!(code, ChatErrorCode::Unknown("SomeFutureServerCode".into()));
        assert!(!code.is_known());
        assert_eq!(
            code.as_str(),
            "SomeFutureServerCode",
            "an unknown code must survive intact for logging and telemetry"
        );
    }

    #[test]
    fn matching_is_exact_and_case_sensitive() {
        // A near-miss must not silently resolve to the real code. v1's
        // substring matching is precisely what made near-misses dangerous.
        for near_miss in [
            "staleCoordinates",
            "STALECOORDINATES",
            "StaleCoordinate",
            "StaleCoordinatesX",
            " StaleCoordinates",
        ] {
            assert!(
                !ChatErrorCode::parse(near_miss).is_known(),
                "{near_miss:?} must not resolve to StaleCoordinates"
            );
        }
        assert_eq!(
            ChatErrorCode::parse("StaleCoordinates"),
            ChatErrorCode::StaleCoordinates
        );
    }

    #[test]
    fn a_substring_of_a_code_never_matches() {
        // The specific v1 failure mode: `body.contains("404")` and
        // `contains("not found")` tripped a circuit breaker on any error whose
        // text happened to include those bytes. Exact matching removes it.
        assert!(!ChatErrorCode::parse("NotFound").is_known());
        assert!(!ChatErrorCode::parse("Conversation").is_known());
        assert_eq!(
            ChatErrorCode::parse("ConversationNotFound"),
            ChatErrorCode::ConversationNotFound
        );
    }
}
