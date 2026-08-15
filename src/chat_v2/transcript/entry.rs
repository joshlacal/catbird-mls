//! Application entry verification and sender identity binding.
//!
//! Two of the checks here are **security events when they fail, not format
//! errors**, and their names say so. Everything else in this module can fail
//! because a peer sent something malformed; these two fail because someone is
//! claiming a conversation or an identity that is not theirs:
//!
//! - [`EntryError::ConversationBindingViolated`] — the row says one
//!   conversation and the bytes the signature actually covers say another. A
//!   signature is only meaningful for the conversation it was signed against,
//!   so accepting the row would let an entry legitimately signed in one
//!   conversation be replayed into a different one.
//! - [`EntryError::SenderIdentityMismatch`] — the authenticated MLS sender leaf
//!   is not the actor the verified outer signature names. The outer identity is
//!   never display authority by itself; this comparison is what ties "who signed
//!   the request" to "who the group cryptographically believes spoke".
//!
//! # Where the conversation binding reads from is kind-dependent
//!
//! Worth stating because the obvious implementation is wrong for two kinds. The
//! binding compares the row's `conversationId` against the signed body's, and
//! the signed body carries it in one of two places:
//!
//! - `creationBody` and `leaveCancellationBody` carry `conversationId`
//!   directly — a creation has no prior coordinate to reference.
//! - **Every other conversation-scoped kind** carries it as
//!   `prior.conversationId`.
//!
//! Those two are exactly the `*Body` definitions in the contract that declare
//! `conversationId` and no `prior`, which a test checks against the contract
//! rather than trusting this list.

use super::contract::{project_ref, ProjectionError};
use super::fingerprint::{
    application_entry_fingerprint, EntryRow, FingerprintError, FingerprintProducts,
};
use super::signed::{SignedMutationError, VerifiedMutation, ED25519_SIGNATURE_LEN};
use super::strict_json::StrictJson;
use super::{CanonicalBody, CanonicalValue, SignedMutationKind};
use crate::chat_v2::ids::{BareDid, BasicCredential, DeviceId};
use core::fmt;

/// Why an application entry was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// The row did not project through the contract.
    Projection(ProjectionError),
    /// The signed mutation did not verify.
    Signed(SignedMutationError),
    /// The fingerprint could not be computed.
    Fingerprint(FingerprintError),
    /// A row field was absent or had the wrong canonical shape.
    RowField { name: &'static str },
    /// The row carried a field beyond the five an application entry has.
    ///
    /// The contract already refuses undeclared fields; this catches the case
    /// where the contract grows a sixth and this code has not been told what it
    /// means.
    ExtraRowField,
    /// The signed wrapper carried something beyond `body` and `signature`.
    ExtraSignedWrapperField,
    /// The row's signed body was not an application send.
    ///
    /// An application row carrying a control body would be a control operation
    /// wearing an application row's clothes.
    NotAnApplicationSend { found: SignedMutationKind },
    /// A conversation-scoped body carried its conversation in neither place.
    NoConversationBinding { kind: SignedMutationKind },
    /// **Security event.** The row's conversation and the signed body's
    /// conversation disagree.
    ///
    /// A signature is only meaningful for the conversation it was signed
    /// against. Accepting this would let an entry legitimately signed in one
    /// conversation be replayed into another.
    ConversationBindingViolated { row: [u8; 16], signed: [u8; 16] },
    /// **Security event.** The authenticated MLS sender leaf is not the actor
    /// the verified outer signature names.
    ///
    /// The outer identity is never display authority by itself. This is the
    /// comparison that ties the signer of the request to the member the group
    /// cryptographically believes spoke.
    SenderIdentityMismatch {
        outer: Box<BasicCredential>,
        authenticated: Box<BasicCredential>,
    },
    /// The signed body's actor fields were absent or malformed.
    MalformedActor,
}

impl From<ProjectionError> for EntryError {
    fn from(err: ProjectionError) -> Self {
        Self::Projection(err)
    }
}

impl From<SignedMutationError> for EntryError {
    fn from(err: SignedMutationError) -> Self {
        Self::Signed(err)
    }
}

impl From<FingerprintError> for EntryError {
    fn from(err: FingerprintError) -> Self {
        Self::Fingerprint(err)
    }
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Projection(err) => write!(f, "{err}"),
            Self::Signed(err) => write!(f, "{err}"),
            Self::Fingerprint(err) => write!(f, "{err}"),
            Self::RowField { name } => write!(f, "application row field {name}"),
            Self::ExtraRowField => f.write_str("application row carries more than its five fields"),
            Self::ExtraSignedWrapperField => {
                f.write_str("signed wrapper carries more than body and signature")
            }
            Self::NotAnApplicationSend { found } => {
                write!(f, "application row carries a {found:?} body")
            }
            Self::NoConversationBinding { kind } => {
                write!(f, "{kind:?} carries no conversation to bind against")
            }
            Self::ConversationBindingViolated { .. } => f.write_str(
                "SECURITY: the row's conversation is not the conversation the signature covers",
            ),
            Self::SenderIdentityMismatch { .. } => f.write_str(
                "SECURITY: the authenticated MLS sender is not the verified outer actor",
            ),
            Self::MalformedActor => f.write_str("signed body actor identity"),
        }
    }
}

impl core::error::Error for EntryError {}

/// An application entry whose signature, binding, and shape have all been
/// verified.
///
/// Constructible only through [`Self::verify`].
#[derive(Debug)]
pub struct VerifiedApplicationEntry {
    entry_id: [u8; 16],
    conversation_id: [u8; 16],
    seq: u64,
    received_at: String,
    mutation: VerifiedMutation,
    fingerprint: FingerprintProducts,
}

impl VerifiedApplicationEntry {
    /// Verifies an application entry row arriving as strict wire JSON.
    ///
    /// The order is deliberate and matches the server: shape, then conversation
    /// binding, then signature, then fingerprint. Validation precedes
    /// fingerprinting, which precedes any use of the row as reducer provenance.
    pub fn verify(row: &StrictJson, historical_public_key: &[u8]) -> Result<Self, EntryError> {
        let CanonicalValue::Map(mut row) = project_ref("applicationEntry", row, false)? else {
            return Err(EntryError::RowField { name: "row" });
        };

        let entry_id = take_uuid(&mut row, "entryId")?;
        let conversation_id = take_uuid(&mut row, "conversationId")?;
        let seq = take_integer(&mut row, "seq")?;
        let received_at = take_timestamp(&mut row, "receivedAt")?;
        let CanonicalValue::Map(mut signed) =
            row.remove("signedRequest").ok_or(EntryError::RowField {
                name: "signedRequest",
            })?
        else {
            return Err(EntryError::RowField {
                name: "signedRequest",
            });
        };
        if !row.is_empty() {
            return Err(EntryError::ExtraRowField);
        }

        let CanonicalValue::Map(body) = signed
            .remove("body")
            .ok_or(EntryError::RowField { name: "body" })?
        else {
            return Err(EntryError::RowField { name: "body" });
        };
        let signature: [u8; ED25519_SIGNATURE_LEN] = match signed.remove("signature") {
            Some(CanonicalValue::Bytes(value)) => value
                .try_into()
                .map_err(|_| EntryError::Signed(SignedMutationError::SignatureLength))?,
            _ => return Err(EntryError::RowField { name: "signature" }),
        };
        if !signed.is_empty() {
            return Err(EntryError::ExtraSignedWrapperField);
        }

        let kind = body_kind(&body)?;
        if kind != SignedMutationKind::ApplicationSend {
            return Err(EntryError::NotAnApplicationSend { found: kind });
        }

        // The binding, before any signature work: a signature is only
        // meaningful for the conversation it was signed against.
        let signed_conversation = signed_body_conversation_id(kind, &body)?;
        if signed_conversation != conversation_id {
            return Err(EntryError::ConversationBindingViolated {
                row: conversation_id,
                signed: signed_conversation,
            });
        }

        let mutation = VerifiedMutation::verify(body, signature, historical_public_key)?;
        let fingerprint = application_entry_fingerprint(&EntryRow {
            entry_id,
            conversation_id,
            seq,
            request_digest: *mutation.request_digest(),
            signature,
            received_at: received_at.clone(),
        })?;

        Ok(Self {
            entry_id,
            conversation_id,
            seq,
            received_at,
            mutation,
            fingerprint,
        })
    }

    /// Requires the authenticated MLS sender leaf to be the verified outer
    /// actor.
    ///
    /// **This is the check that makes the outer identity usable.** Until it
    /// passes, the outer signature says only "someone holding this key signed a
    /// request"; afterwards it says "the group member who spoke is that actor".
    /// The spec requires it after decryption, and it is a hard refusal rather
    /// than a warning because a mismatch means a real member's leaf is being
    /// presented alongside a different actor's signature.
    pub fn require_sender_is_outer_actor(
        &self,
        mls_leaf_identity: &[u8],
    ) -> Result<BasicCredential, EntryError> {
        let outer = self.outer_actor()?;
        let authenticated =
            BasicCredential::parse(mls_leaf_identity).map_err(|_| EntryError::MalformedActor)?;
        if authenticated != outer {
            return Err(EntryError::SenderIdentityMismatch {
                outer: Box::new(outer),
                authenticated: Box::new(authenticated),
            });
        }
        Ok(authenticated)
    }

    /// The actor the verified outer signature names, as a credential.
    pub fn outer_actor(&self) -> Result<BasicCredential, EntryError> {
        outer_actor_of(self.mutation.body())
    }

    /// The append row's replay identity.
    pub fn entry_id(&self) -> [u8; 16] {
        self.entry_id
    }

    /// The conversation this row belongs to, agreed by row and signature.
    pub fn conversation_id(&self) -> [u8; 16] {
        self.conversation_id
    }

    /// The append sequence.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The server's canonical receipt timestamp.
    pub fn received_at(&self) -> &str {
        &self.received_at
    }

    /// The verified signed mutation this row carries.
    pub fn mutation(&self) -> &VerifiedMutation {
        &self.mutation
    }

    /// The outer fingerprint, ready to be recorded as reducer provenance.
    pub fn fingerprint(&self) -> &FingerprintProducts {
        &self.fingerprint
    }
}

/// The actor a signed body names, as an MLS BasicCredential.
///
/// Public because control entries need the same comparison; the application
/// path is only the first consumer.
pub fn outer_actor_of(body: &CanonicalBody) -> Result<BasicCredential, EntryError> {
    let CanonicalValue::Did(did) = body.get("actorDid").ok_or(EntryError::MalformedActor)? else {
        return Err(EntryError::MalformedActor);
    };
    let CanonicalValue::Uuid(device) = body
        .get("actorDeviceId")
        .ok_or(EntryError::MalformedActor)?
    else {
        return Err(EntryError::MalformedActor);
    };
    let did = BareDid::parse(did).map_err(|_| EntryError::MalformedActor)?;
    let device = DeviceId::from_bytes(*device).map_err(|_| EntryError::MalformedActor)?;
    Ok(BasicCredential::new(did, device))
}

/// Kinds that carry `conversationId` directly rather than under `prior`.
///
/// A creation has no prior coordinate to reference, and a leave cancellation
/// names its conversation without binding to one.
pub const DIRECT_CONVERSATION_KINDS: [SignedMutationKind; 2] = [
    SignedMutationKind::Creation,
    SignedMutationKind::LeaveCancellation,
];

/// The conversation a signed body is bound to.
pub fn signed_body_conversation_id(
    kind: SignedMutationKind,
    body: &CanonicalBody,
) -> Result<[u8; 16], EntryError> {
    let source = if DIRECT_CONVERSATION_KINDS.contains(&kind) {
        body.get("conversationId")
    } else {
        match body.get("prior") {
            Some(CanonicalValue::Map(prior)) => prior.get("conversationId"),
            _ => None,
        }
    };
    match source {
        Some(CanonicalValue::Uuid(raw)) => Ok(*raw),
        _ => Err(EntryError::NoConversationBinding { kind }),
    }
}

fn body_kind(body: &CanonicalBody) -> Result<SignedMutationKind, EntryError> {
    match body.get("$type") {
        Some(CanonicalValue::Text(value)) => {
            SignedMutationKind::from_type_id(value).ok_or(EntryError::Signed(
                SignedMutationError::Transcript(super::TranscriptError::UnknownType),
            ))
        }
        _ => Err(EntryError::Signed(SignedMutationError::Transcript(
            super::TranscriptError::UnknownType,
        ))),
    }
}

fn take_uuid(row: &mut CanonicalBody, name: &'static str) -> Result<[u8; 16], EntryError> {
    match row.remove(name) {
        Some(CanonicalValue::Uuid(raw)) => Ok(raw),
        _ => Err(EntryError::RowField { name }),
    }
}

fn take_integer(row: &mut CanonicalBody, name: &'static str) -> Result<u64, EntryError> {
    match row.remove(name) {
        Some(CanonicalValue::Integer(value)) => Ok(value),
        _ => Err(EntryError::RowField { name }),
    }
}

fn take_timestamp(row: &mut CanonicalBody, name: &'static str) -> Result<String, EntryError> {
    match row.remove(name) {
        Some(CanonicalValue::Timestamp(value)) => Ok(value),
        _ => Err(EntryError::RowField { name }),
    }
}
