//! The two outer entry fingerprint domains.
//!
//! An entry's outer fingerprint is what the reducer records as interval
//! provenance, and [`OuterEntryFingerprint`] deliberately has no constructor
//! outside envelope verification. **This module is that layer.** Everything
//! upstream of here is a hint; everything downstream may be treated as
//! authority.
//!
//! Two domains, frozen as byte constants on the server and copied verbatim:
//!
//! ```text
//! application: SHA-256(APPLICATION_FINGERPRINT_DOMAIN || DAG-CBOR(6-field projection))
//! control:     SHA-256(CONTROL_FINGERPRINT_DOMAIN     || DAG-CBOR(8-field projection))
//! ```
//!
//! Like the signing domains, both end in a NUL byte.
//!
//! # The two projections are not the same shape, and must not be made so
//!
//! The application projection has **six** fields. The control projection has
//! **eight** — the same six plus `entryKind` and `serverFields`. An application
//! entry has no kind field to bind because there is only one application entry
//! kind, and no server-authored fields at all.
//!
//! That asymmetry is load-bearing. `entryKind` inside the control projection is
//! what stops a fingerprint computed for one control kind being presented as
//! another's, and adding it to the application projection — or dropping it from
//! the control one to "unify" them — changes every fingerprint on that side.
//!
//! # `serverFields` is closed per kind
//!
//! Eleven of the thirteen control kinds carry **no** server-authored fields, and
//! for them `serverFields` must be an empty map rather than absent. Exactly two
//! carry one field each: `participantAcceptanceEntry` carries `recovery`, and
//! `conversationCloseEntry` carries `tombstone`.
//!
//! [`ControlServerFields`] holds a private map with no public constructor that
//! takes arbitrary content, mirroring the server's own non-`Clone`,
//! private-field design. The reason is stated in the server source and worth
//! repeating: callers must not be able to splice unvalidated fields into a
//! fingerprint. A fingerprint is only as trustworthy as the narrowest path that
//! can produce one.

use super::value::BodyRef;
use super::witness::EnvelopeVerification;
use super::{CanonicalBody, CanonicalValue};
use crate::chat_v2::ids::MAX_SAFE_INTEGER;
use crate::chat_v2::provenance::OuterEntryFingerprint;
use core::fmt;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The application entry fingerprint domain, including its trailing NUL.
pub const APPLICATION_FINGERPRINT_DOMAIN: &[u8] = b"CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\0";

/// The control entry fingerprint domain, including its trailing NUL.
pub const CONTROL_FINGERPRINT_DOMAIN: &[u8] = b"CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\0";

/// Every control entry kind, with its type ID and server-authored field.
macro_rules! control_entry_kinds {
    ($(($variant:ident, $entry:literal, $server_field:expr)),+ $(,)?) => {
        /// One of the thirteen control entry kinds.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ControlEntryKind { $($variant),+ }

        impl ControlEntryKind {
            /// Every kind, for exhaustive sweeps.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The fully qualified `$type` of this entry kind.
            pub const fn type_id(self) -> &'static str {
                match self { $(Self::$variant => concat!("blue.catbird.chat.defs#", $entry)),+ }
            }

            /// The single server-authored field this kind carries, if any.
            ///
            /// `None` means `serverFields` must be an **empty map** — not
            /// absent, and not populated.
            pub const fn server_field(self) -> Option<&'static str> {
                match self { $(Self::$variant => $server_field),+ }
            }

            /// Resolves a type ID to its kind, failing closed on anything else.
            pub fn from_type_id(value: &str) -> Option<Self> {
                match value {
                    $(concat!("blue.catbird.chat.defs#", $entry) => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

control_entry_kinds!(
    (Commit, "commitEntry", None),
    (Policy, "policyEntry", None),
    (Metadata, "metadataEntry", None),
    (Creation, "creationEntry", None),
    (
        ParticipantAcceptance,
        "participantAcceptanceEntry",
        Some("recovery")
    ),
    (
        ConversationClose,
        "conversationCloseEntry",
        Some("tombstone")
    ),
    (ResetRequest, "resetRequestEntry", None),
    (ResetActivation, "resetActivationEntry", None),
    (
        LeafRecoveryFulfillment,
        "leafRecoveryFulfillmentEntry",
        None
    ),
    (LeaveRequest, "leaveRequestEntry", None),
    (ZeroLeafLeave, "zeroLeafLeaveEntry", None),
    (LeaveCancellation, "leaveCancellationEntry", None),
    (LeaveCommitFulfillment, "leaveCommitFulfillmentEntry", None),
);

/// Why a fingerprint could not be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    /// The projection could not be encoded as DAG-CBOR.
    Encoding,
    /// The sequence was outside `1..=MAX_SAFE_INTEGER`.
    ///
    /// Zero is not a valid append sequence, and anything above the safe-integer
    /// ceiling cannot survive a round trip through a JSON consumer.
    Seq { found: u64 },
    /// An ordinary control kind was given non-empty `serverFields`.
    OrdinaryServerFieldsMustBeEmpty { kind: ControlEntryKind },
    /// A special control kind was given the wrong `serverFields` set.
    ///
    /// Exactly one field, exactly the one its kind declares.
    SpecialServerFieldsSet {
        kind: ControlEntryKind,
        expected: &'static str,
    },
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => f.write_str("fingerprint projection is not encodable as DAG-CBOR"),
            Self::Seq { found } => {
                write!(f, "entry seq {found} is outside 1..={MAX_SAFE_INTEGER}")
            }
            Self::OrdinaryServerFieldsMustBeEmpty { kind } => {
                write!(f, "{kind:?} carries no server-authored fields")
            }
            Self::SpecialServerFieldsSet { kind, expected } => {
                write!(f, "{kind:?} requires exactly one field, {expected}")
            }
        }
    }
}

impl core::error::Error for FingerprintError {}

/// The server-authored row fields both fingerprints bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRow {
    // The fields are public and this type is deliberately *not* gated: it is
    // the input to a pure function, and the golden vectors are assembled from
    // the server's fixture exactly this way. Computing a fingerprint over a row
    // a caller invented is therefore possible — and meaningless, because it is
    // a fingerprint of that invented row and of nothing else. What carries
    // authority is not the fingerprint's existence but where it came from: on
    // the application path, `SenderBoundApplicationEntry` is the only holder of
    // one, and it exists only after shape, binding, signature, and sender
    // identity have all been checked.
    /// The append row's replay identity. Never the signed transition ID.
    pub entry_id: [u8; 16],
    /// The conversation this row belongs to.
    pub conversation_id: [u8; 16],
    /// The append sequence.
    pub seq: u64,
    /// SHA-256 of the signing transcript.
    pub request_digest: [u8; 32],
    /// The Ed25519 signature over that transcript.
    pub signature: [u8; 64],
    /// The server's canonical receipt timestamp.
    pub received_at: String,
}

impl EntryRow {
    /// The six fields common to both projections, in a map.
    fn common_projection(&self) -> Result<CanonicalBody, FingerprintError> {
        if !(1..=MAX_SAFE_INTEGER as u64).contains(&self.seq) {
            return Err(FingerprintError::Seq { found: self.seq });
        }
        Ok(BTreeMap::from([
            ("entryId".to_owned(), CanonicalValue::Uuid(self.entry_id)),
            (
                "conversationId".to_owned(),
                CanonicalValue::Uuid(self.conversation_id),
            ),
            ("seq".to_owned(), CanonicalValue::Integer(self.seq)),
            (
                "requestDigest".to_owned(),
                CanonicalValue::Bytes(self.request_digest.to_vec()),
            ),
            (
                "signature".to_owned(),
                CanonicalValue::Bytes(self.signature.to_vec()),
            ),
            (
                "receivedAt".to_owned(),
                CanonicalValue::Timestamp(self.received_at.clone()),
            ),
        ]))
    }
}

/// The closed, per-kind `serverFields` object of a control entry.
///
/// The map is private and there is no constructor that accepts arbitrary
/// content for an arbitrary kind, so a caller holding unvalidated fields cannot
/// route them into a fingerprint.
#[derive(Debug)]
pub struct ControlServerFields {
    kind: ControlEntryKind,
    fields: CanonicalBody,
}

impl ControlServerFields {
    /// The empty `serverFields` of an ordinary control kind.
    ///
    /// Refuses the two kinds that require content, so "I forgot to attach the
    /// tombstone" cannot silently produce a well-formed fingerprint over the
    /// wrong bytes.
    pub fn empty(kind: ControlEntryKind) -> Result<Self, FingerprintError> {
        match kind.server_field() {
            None => Ok(Self {
                kind,
                fields: BTreeMap::new(),
            }),
            Some(expected) => Err(FingerprintError::SpecialServerFieldsSet { kind, expected }),
        }
    }

    /// The single server-authored field of one of the two special kinds.
    ///
    /// Refuses ordinary kinds, and refuses a field name its kind does not
    /// declare.
    ///
    /// The **value** is not checked and cannot be: a tombstone or recovery
    /// object is server-authored content this layer has no schema opinion
    /// about. So the gate here is "the right kind carries the right field
    /// name", which is what stops an acceptance's `recovery` being presented as
    /// a close's `tombstone`. It is not "this content is genuine", and the
    /// caller — the wire projection that decoded the row — is what that rests
    /// on.
    pub fn single(
        kind: ControlEntryKind,
        field: &str,
        value: CanonicalValue,
    ) -> Result<Self, FingerprintError> {
        match kind.server_field() {
            None => Err(FingerprintError::OrdinaryServerFieldsMustBeEmpty { kind }),
            Some(expected) if expected == field => Ok(Self {
                kind,
                fields: BTreeMap::from([(expected.to_owned(), value)]),
            }),
            Some(expected) => Err(FingerprintError::SpecialServerFieldsSet { kind, expected }),
        }
    }

    /// The kind these fields were closed for.
    pub fn kind(&self) -> ControlEntryKind {
        self.kind
    }
}

/// A computed outer fingerprint and the exact bytes it was taken over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintProducts {
    canonical_projection: Vec<u8>,
    fingerprint: OuterEntryFingerprint,
}

impl FingerprintProducts {
    /// The DAG-CBOR projection, without the domain prefix.
    pub fn canonical_projection(&self) -> &[u8] {
        &self.canonical_projection
    }

    /// The fingerprint, ready to be recorded as reducer provenance.
    pub fn fingerprint(&self) -> OuterEntryFingerprint {
        self.fingerprint
    }
}

fn finish(
    domain: &[u8],
    projection: &CanonicalBody,
) -> Result<FingerprintProducts, FingerprintError> {
    let canonical_projection =
        serde_ipld_dagcbor::to_vec(&BodyRef(projection)).map_err(|_| FingerprintError::Encoding)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(&canonical_projection);
    Ok(FingerprintProducts {
        canonical_projection,
        // The one place in the crate that can mint one of these, and it does so
        // over bytes it has just computed itself.
        fingerprint: OuterEntryFingerprint::from_verified(
            digest.finalize().into(),
            EnvelopeVerification::by_this_layer(),
        ),
    })
}

/// Computes an application entry's outer fingerprint over its six-field
/// projection.
pub fn application_entry_fingerprint(
    row: &EntryRow,
) -> Result<FingerprintProducts, FingerprintError> {
    finish(APPLICATION_FINGERPRINT_DOMAIN, &row.common_projection()?)
}

/// Computes a control entry's outer fingerprint over its eight-field
/// projection.
///
/// The `server_fields` argument carries its own kind, and it must be the kind
/// being fingerprinted — passing an acceptance's `recovery` object while
/// claiming a close would otherwise produce a valid-looking fingerprint over
/// mismatched content.
pub fn control_entry_fingerprint(
    kind: ControlEntryKind,
    row: &EntryRow,
    server_fields: &ControlServerFields,
) -> Result<FingerprintProducts, FingerprintError> {
    if server_fields.kind != kind {
        return Err(match kind.server_field() {
            Some(expected) => FingerprintError::SpecialServerFieldsSet { kind, expected },
            None => FingerprintError::OrdinaryServerFieldsMustBeEmpty { kind },
        });
    }
    let mut projection = row.common_projection()?;
    projection.insert(
        "entryKind".to_owned(),
        CanonicalValue::Text(kind.type_id().to_owned()),
    );
    projection.insert(
        "serverFields".to_owned(),
        CanonicalValue::Map(server_fields.fields.clone()),
    );
    finish(CONTROL_FINGERPRINT_DOMAIN, &projection)
}
