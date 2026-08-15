//! The strict JSON profile a signed body must arrive in.
//!
//! Mirrors the server's `RawJson` decode. It is deliberately *not* a general
//! JSON value type: the clean-chat profile excludes several things ordinary
//! JSON permits, and excluding them at the decoder rather than downstream is
//! what stops a value existing that later code has to remember to reject.
//!
//! Refused outright, each for its own reason:
//!
//! - **Floats.** No field in the contract is fractional, and a float that
//!   round-trips through a decimal representation is a byte-identity hazard by
//!   construction.
//! - **Negative integers.** Every integer in the profile is a count, a
//!   sequence, or a generation.
//! - **`null`.** Absent and present-but-null would otherwise be two encodings
//!   of the same state, and only one of them can be canonical.
//! - **Duplicate object keys.** A parser that keeps the last wins; one that
//!   keeps the first wins differently. Two implementations disagreeing about
//!   which is authoritative is a signature-splitting bug.
//! - **Trailing data.** Bytes after the value are unsigned bytes riding along
//!   with a signed request.
//!
//! # Bytes are bare STANDARD base64 here
//!
//! This is the wire half of program invariant I-1. A bytes field arrives as a
//! bare STANDARD-alphabet, padded base64 string — never jacquard's
//! `{"$bytes": …}` DAG-JSON, which is authoritative only for responses and
//! unsigned params. [`decode_standard_base64`] additionally re-encodes and
//! compares, so a non-canonical encoding of the same bytes is refused rather
//! than silently normalized.

use base64::{engine::general_purpose::STANDARD, Engine};
use core::fmt;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::collections::BTreeMap;

/// The server's pre-deserialization transport cap, matched exactly.
///
/// The frozen contract permits 100 maximum-size 64-KiB KeyPackages, whose
/// base64 JSON form is under 9 MiB; 16 MiB admits that maximum batch while
/// still being a hard bound.
pub const MAX_SIGNED_JSON_BYTES: usize = 16 * 1024 * 1024;

/// A value in the strict clean-chat JSON profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictJson {
    /// A string. Bytes fields also arrive as strings and are decoded later,
    /// once the contract says which fields are bytes.
    String(String),
    /// A non-negative integer.
    Integer(u64),
    /// A boolean.
    Bool(bool),
    /// An array.
    Array(Vec<StrictJson>),
    /// An object with unique keys.
    Object(BTreeMap<String, StrictJson>),
}

/// Why a value was not in the strict profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictJsonError {
    /// The input was empty or exceeded [`MAX_SIGNED_JSON_BYTES`].
    Size,
    /// The input was not valid JSON, or used something the profile excludes.
    Invalid,
    /// Bytes followed the JSON value.
    TrailingData,
    /// A base64 string was not decodable.
    Base64,
    /// A base64 string decoded, but was not the canonical encoding of its own
    /// bytes.
    NoncanonicalBase64,
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size => f.write_str("signed JSON size out of bounds"),
            Self::Invalid => f.write_str("invalid strict signed JSON"),
            Self::TrailingData => f.write_str("trailing signed JSON data"),
            Self::Base64 => f.write_str("invalid standard base64 bytes"),
            Self::NoncanonicalBase64 => f.write_str("noncanonical standard base64 bytes"),
        }
    }
}

impl core::error::Error for StrictJsonError {}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("closed non-null clean-chat JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(StrictJson::Integer)
            .map_err(|_| E::custom("negative integers are not in the clean-chat profile"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floats are not in the clean-chat profile"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJson::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            // Rejected rather than resolved: "last wins" and "first wins" are
            // both defensible, and two implementations picking differently is a
            // signature-splitting bug.
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(StrictJson::Object(values))
    }
}

/// Decodes strict clean-chat JSON, rejecting anything outside the profile.
pub fn decode_strict_json(raw: &[u8]) -> Result<StrictJson, StrictJsonError> {
    if raw.is_empty() || raw.len() > MAX_SIGNED_JSON_BYTES {
        return Err(StrictJsonError::Size);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJson::deserialize(&mut deserializer).map_err(|_| StrictJsonError::Invalid)?;
    deserializer
        .end()
        .map_err(|_| StrictJsonError::TrailingData)?;
    Ok(value)
}

/// Decodes a bare STANDARD base64 string, requiring the canonical encoding.
///
/// The re-encode comparison is the point. Several distinct base64 strings can
/// decode to the same bytes (non-zero padding bits, missing padding under a
/// permissive engine), and accepting more than one of them means a signed body
/// has more than one byte representation.
pub fn decode_standard_base64(value: &str) -> Result<Vec<u8>, StrictJsonError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| StrictJsonError::Base64)?;
    if STANDARD.encode(&decoded) != value {
        return Err(StrictJsonError::NoncanonicalBase64);
    }
    Ok(decoded)
}

/// Encodes bytes as the bare STANDARD base64 a signed body carries.
pub fn encode_standard_base64(value: &[u8]) -> String {
    STANDARD.encode(value)
}
