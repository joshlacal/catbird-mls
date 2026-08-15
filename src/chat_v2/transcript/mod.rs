//! The canonical signing transcript.
//!
//! This is the client half of the bytes the server signs and verifies, and its
//! only requirement is **byte-identity** with
//! `mls-ds server/src/chat_protocol/transcript.rs`. Everything here is anchored
//! on that implementation rather than derived independently, and pinned by
//! golden vectors lifted from the server's own fixtures.
//!
//! # The transcript is DAG-CBOR, not JSON
//!
//! Worth stating plainly, because the shape of the wire format invites the
//! opposite conclusion. A signed request body travels as JSON, and within that
//! JSON a bytes field is bare STANDARD base64 — never jacquard's
//! `{"$bytes": …}` DAG-JSON, which is authoritative only for responses and
//! unsigned params. But the bytes that are actually signed are:
//!
//! ```text
//! transcript = domain || DAG-CBOR(canonical body)
//! digest     = SHA-256(transcript)
//! ```
//!
//! Base64 never appears in the signed bytes at all; it is only how bytes
//! arrive before projection. A client that signed a canonical *JSON* form would
//! produce valid-looking signatures that every server rejects.
//!
//! # Three details that silently break byte-identity
//!
//! 1. **Domains end in a NUL byte, and the domain appears twice.** The prefix
//!    is `b"CATBIRD-CHAT-BLOB-DELETE\0"` including the terminator, and the same
//!    string — NUL and all — is also carried inside the body as
//!    `signatureDomain`.
//! 2. **UUIDs are sixteen raw bytes in the transcript**, while DIDs, key
//!    thumbprints, and timestamps stay text. See [`value::CanonicalValue`].
//! 3. **Map keys are ordered length-first**, not byte-lexicographically. That
//!    is `serde_ipld_dagcbor`'s doing, which is exactly why the crate is shared
//!    with the server rather than reimplemented.

pub mod fingerprint;
pub mod signed;
pub mod strict_json;
pub mod value;

pub use fingerprint::{
    application_entry_fingerprint, control_entry_fingerprint, ControlEntryKind,
    ControlServerFields, EntryRow, FingerprintError, FingerprintProducts,
    APPLICATION_FINGERPRINT_DOMAIN, CONTROL_FINGERPRINT_DOMAIN,
};
pub use signed::{
    verify_ed25519_strict, SignedMutationError, SignedWrapper, VerifiedMutation,
    ED25519_SIGNATURE_LEN,
};
pub use strict_json::{
    decode_standard_base64, decode_strict_json, encode_standard_base64, StrictJson,
    StrictJsonError, MAX_SIGNED_JSON_BYTES,
};
pub use value::{CanonicalBody, CanonicalValue};

use core::fmt;
use sha2::{Digest, Sha256};
use value::BodyRef;

/// Every signed mutation kind, with its body name and signing domain.
///
/// Transcribed mechanically from the server's `signed_mutation_kinds!` table so
/// that no domain string is retyped by hand. A single wrong byte here produces
/// signatures that verify locally and nowhere else.
macro_rules! signed_mutation_kinds {
    ($(($variant:ident, $body:literal, $domain:literal)),+ $(,)?) => {
        /// One of the closed set of signed mutation kinds.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SignedMutationKind { $($variant),+ }

        impl SignedMutationKind {
            /// Every kind, for exhaustive sweeps.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The fully qualified `$type` value, as it appears in a body.
            pub const fn type_id(self) -> &'static str {
                match self { $(Self::$variant => concat!("blue.catbird.chat.defs#", $body)),+ }
            }

            /// The lexicon definition name of this kind's body.
            pub const fn body_name(self) -> &'static str {
                match self { $(Self::$variant => $body),+ }
            }

            /// The signing domain, **including its trailing NUL byte**.
            pub const fn domain(self) -> &'static [u8] {
                match self { $(Self::$variant => $domain.as_bytes()),+ }
            }

            /// Resolves a `$type` value to its kind.
            ///
            /// Returns `None` for anything unrecognized rather than guessing:
            /// an unknown type ID must fail closed, exactly as an unknown
            /// endpoint error code does.
            pub fn from_type_id(value: &str) -> Option<Self> {
                match value {
                    $(concat!("blue.catbird.chat.defs#", $body) => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

signed_mutation_kinds!(
    (
        DeviceEnrollment,
        "deviceEnrollmentBody",
        "CATBIRD-CHAT-DEVICE-ENROLL\0"
    ),
    (
        KeyPackageReplenishment,
        "keyPackageReplenishmentBody",
        "CATBIRD-CHAT-DEVICE-REPLENISH\0"
    ),
    (
        DeviceAuthenticationRebind,
        "deviceAuthenticationRebindBody",
        "CATBIRD-CHAT-DEVICE-REBIND\0"
    ),
    (
        DeviceRevocation,
        "deviceRevocationBody",
        "CATBIRD-CHAT-DEVICE-REVOKE\0"
    ),
    (
        BlobUploadPreparation,
        "blobUploadPreparationBody",
        "CATBIRD-CHAT-BLOB-PREPARE\0"
    ),
    (
        BlobDeletion,
        "blobDeletionBody",
        "CATBIRD-CHAT-BLOB-DELETE\0"
    ),
    (Creation, "creationBody", "CATBIRD-CHAT-CREATE\0"),
    (
        CommitTransition,
        "commitTransitionBody",
        "CATBIRD-CHAT-COMMIT\0"
    ),
    (
        PolicyTransition,
        "policyTransitionBody",
        "CATBIRD-CHAT-POLICY\0"
    ),
    (
        ParticipantAcceptance,
        "participantAcceptanceBody",
        "CATBIRD-CHAT-ACCEPT\0"
    ),
    (
        ApplicationSend,
        "applicationSendBody",
        "CATBIRD-CHAT-MESSAGE\0"
    ),
    (Typing, "typingBody", "CATBIRD-CHAT-TYPING\0"),
    (
        MetadataTransition,
        "metadataTransitionBody",
        "CATBIRD-CHAT-METADATA\0"
    ),
    (
        ResetRequest,
        "resetRequestBody",
        "CATBIRD-CHAT-RESET-REQUEST\0"
    ),
    (
        ResetActivation,
        "resetActivationBody",
        "CATBIRD-CHAT-RESET-ACTIVATE\0"
    ),
    (
        LeafRecoveryRequest,
        "leafRecoveryRequestBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0"
    ),
    (
        LeafRecoveryCancellation,
        "leafRecoveryCancellationBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0"
    ),
    (
        LeafRecoveryFulfillment,
        "leafRecoveryFulfillmentBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0"
    ),
    (
        ConversationClose,
        "conversationCloseBody",
        "CATBIRD-CHAT-CLOSE\0"
    ),
    (
        LeaveRequest,
        "leaveRequestBody",
        "CATBIRD-CHAT-LEAVE-REQUEST\0"
    ),
    (
        ZeroLeafLeave,
        "zeroLeafLeaveBody",
        "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0"
    ),
    (
        LeaveCancellation,
        "leaveCancellationBody",
        "CATBIRD-CHAT-LEAVE-CANCEL\0"
    ),
    (
        LeaveCommitFulfillment,
        "leaveCommitFulfillmentBody",
        "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0"
    ),
    (
        WelcomeAcknowledgement,
        "welcomeAcknowledgementBody",
        "CATBIRD-CHAT-WELCOME-ACK\0"
    ),
    (
        WelcomeRejection,
        "welcomeRejectionBody",
        "CATBIRD-CHAT-WELCOME-REJECT\0"
    ),
);

/// Why a transcript could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    /// The body could not be encoded as DAG-CBOR.
    Encoding,
    /// The body's `$type` was absent, not text, or not a known kind.
    ///
    /// Unknown type IDs fail closed. Guessing a kind would pick a signing
    /// domain, and the domain is what stops a signature for one operation being
    /// replayed as another.
    UnknownType,
    /// The body's `signatureDomain` did not equal the kind's domain.
    ///
    /// The domain is bound twice — as the transcript prefix and as a body
    /// field — and a body claiming one operation while carrying another's domain
    /// is exactly the confusion that binding exists to prevent.
    DomainMismatch,
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => f.write_str("body is not encodable as DAG-CBOR"),
            Self::UnknownType => f.write_str("signed body $type is absent or unknown"),
            Self::DomainMismatch => {
                f.write_str("signed body signatureDomain does not match its $type")
            }
        }
    }
}

impl core::error::Error for TranscriptError {}

/// The exact bytes a signed mutation's signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningTranscript {
    kind: SignedMutationKind,
    canonical_projection: Vec<u8>,
    bytes: Vec<u8>,
    request_digest: [u8; 32],
}

impl SigningTranscript {
    /// Builds the transcript for an already-projected canonical body.
    ///
    /// Confirms the body's `$type` and `signatureDomain` agree before encoding.
    /// Both are inside the signed bytes, so a mismatch is not merely
    /// inconsistent — it is a body that would be signed as one operation and
    /// read as another.
    pub fn build(body: &CanonicalBody) -> Result<Self, TranscriptError> {
        let kind = match body.get("$type") {
            Some(CanonicalValue::Text(value)) => {
                SignedMutationKind::from_type_id(value).ok_or(TranscriptError::UnknownType)?
            }
            _ => return Err(TranscriptError::UnknownType),
        };
        match body.get("signatureDomain") {
            Some(CanonicalValue::Text(value)) if value.as_bytes() == kind.domain() => {}
            _ => return Err(TranscriptError::DomainMismatch),
        }
        Self::build_for(kind, body)
    }

    /// Builds the transcript for a known kind, without re-deriving it.
    ///
    /// Skips only the `$type` lookup; the `signatureDomain` binding is still the
    /// caller's to have established. [`Self::build`] is the entry point that
    /// checks both and should be preferred.
    pub fn build_for(
        kind: SignedMutationKind,
        body: &CanonicalBody,
    ) -> Result<Self, TranscriptError> {
        let canonical_projection =
            serde_ipld_dagcbor::to_vec(&BodyRef(body)).map_err(|_| TranscriptError::Encoding)?;
        let mut bytes = Vec::with_capacity(kind.domain().len() + canonical_projection.len());
        bytes.extend_from_slice(kind.domain());
        bytes.extend_from_slice(&canonical_projection);
        let request_digest = Sha256::digest(&bytes).into();
        Ok(Self {
            kind,
            canonical_projection,
            bytes,
            request_digest,
        })
    }

    /// The kind this transcript was built for.
    pub fn kind(&self) -> SignedMutationKind {
        self.kind
    }

    /// The DAG-CBOR encoding of the body, without the domain prefix.
    pub fn canonical_projection(&self) -> &[u8] {
        &self.canonical_projection
    }

    /// The full signed bytes: domain followed by the canonical projection.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of [`Self::bytes`]. This is the request digest that the outer
    /// entry fingerprint takes as one of its inputs.
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

#[cfg(test)]
mod fingerprint_tests;
#[cfg(test)]
mod signed_tests;
#[cfg(test)]
mod tests;
