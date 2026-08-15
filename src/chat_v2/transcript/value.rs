//! The canonical value model that signing transcripts are built from.
//!
//! Every value that can appear in a signed body has exactly one representation
//! here, and each variant fixes how it reaches the wire. That is the whole
//! purpose of the type: the encoding of a field is decided by its *declared
//! kind*, not by what its JSON happened to look like, so two implementations
//! cannot disagree about it.
//!
//! Two of these choices are the ones a reimplementer gets wrong, and both are
//! pinned by golden vectors lifted from the server:
//!
//! - **A UUID is sixteen raw bytes, not a string.** `blobId`,
//!   `actorDeviceId`, and `idempotencyKey` all reach the transcript as CBOR byte
//!   strings. Emitting the hyphenated ASCII form instead produces a structurally
//!   valid transcript with entirely different bytes, and therefore a signature
//!   the server will reject without explaining why.
//! - **A DID, key thumbprint, and timestamp stay text.** They look like the
//!   same class of thing as a UUID and are not.
//!
//! # Never build a transcript from a generated DTO
//!
//! Generated DTOs emit their fields alphabetically and carry a flattened
//! `extra_data` catch-all. The protocol forbids DTO bytes as transcript or
//! fingerprint input, so `chat_v2` owns this encoder outright.

use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize, Serializer,
};
use std::collections::BTreeMap;

/// A value in a canonical signed body.
///
/// The variants deliberately distinguish kinds that share a JSON
/// representation, because they do not share a transcript representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalValue {
    /// Free text, and the fallback for any string-shaped field that is not one
    /// of the more specific kinds below.
    Text(String),
    /// A canonical UUIDv4. Reaches the transcript as **sixteen raw bytes**.
    Uuid([u8; 16]),
    /// A bare DID. Stays text.
    Did(String),
    /// An Ed25519 key thumbprint. Stays text.
    Thumbprint(String),
    /// A canonical RFC 3339 timestamp. Stays text.
    Timestamp(String),
    /// A byte string. On the wire it arrives as bare STANDARD base64; in the
    /// transcript it is a CBOR byte string.
    Bytes(Vec<u8>),
    /// A non-negative integer within the safe-integer range.
    Integer(u64),
    /// A boolean.
    Bool(bool),
    /// An ordered array.
    Array(Vec<CanonicalValue>),
    /// A map. See [`CanonicalBody`] for why the key order here is not the order
    /// that reaches the wire.
    Map(CanonicalBody),
}

/// The field map of a canonical signed body.
///
/// Held as a `BTreeMap` for deterministic iteration, but **that is not the
/// canonical order**. DAG-CBOR sorts map keys length-first and only then
/// bytewise, whereas a `BTreeMap<String, _>` iterates in plain byte-lexicographic
/// order. The two disagree whenever a shorter key sorts after a longer one — the
/// server's own golden body emits `$type`, `keyId`, `blobId`, `actorDid`, which
/// byte-lexicographic order would have emitted as `$type`, `actorDid`, `blobId`,
/// `keyId`.
///
/// Reconciling that is `serde_ipld_dagcbor`'s job, not this type's, and sharing
/// the exact crate the server uses is what makes the agreement structural rather
/// than a rule someone has to remember.
pub type CanonicalBody = BTreeMap<String, CanonicalValue>;

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            // The three text-shaped identity kinds. Spelled out separately
            // rather than folded into `Text` so that adding a fourth forces a
            // decision about which side of the bytes/text line it falls on.
            Self::Did(value) => serializer.serialize_str(value),
            Self::Thumbprint(value) => serializer.serialize_str(value),
            Self::Timestamp(value) => serializer.serialize_str(value),
            // Sixteen raw bytes, never the hyphenated ASCII form.
            Self::Uuid(value) => serializer.serialize_bytes(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Map(values) => serialize_body(values, serializer),
        }
    }
}

/// Serializes a body map without cloning it.
///
/// `serde_ipld_dagcbor::to_vec` takes its argument by value, so the transcript
/// builder needs a borrowed serializable view rather than a copy of
/// authority-bearing values.
pub(crate) fn serialize_body<S>(body: &CanonicalBody, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(body.len()))?;
    for (key, value) in body {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

/// A borrowed body, serializable without a clone.
pub(crate) struct BodyRef<'a>(pub(crate) &'a CanonicalBody);

impl Serialize for BodyRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_body(self.0, serializer)
    }
}
