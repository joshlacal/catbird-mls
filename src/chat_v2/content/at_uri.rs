//! The restricted canonical AT URI used by record embeds.
//!
//! §8 defines a **deliberately unescaped** subset, not general AT URI syntax:
//!
//! > Record embeds require a deliberately unescaped restricted canonical AT URI
//! > of at most exactly 1,097 ASCII bytes (`5 + 261 + 1 + 317 + 1 + 512`):
//! > exact lowercase `at://`; no percent sign/escape anywhere; exact supported
//! > `did:plc`, hostname-level `did:web` using the same normalized lowercase
//! > production handle-shaped hostname, or a normalized lowercase production
//! > handle; exactly one collection and record key; lowercase collection domain
//! > authority with case-sensitive terminal name and rkey; and no query,
//! > fragment, trailing or duplicate slash, record key equal to `.` or `..`, or
//! > extra path segment.
//!
//! and, crucially:
//!
//! > **Parser acceptance or round-trip alone is not canonicality proof.**
//!
//! # Why a general URI parser is the wrong tool
//!
//! That last sentence is the design constraint. A general parser accepts
//! `at://EXAMPLE.com/...`, `at://example.com//x`, and percent-escaped forms, and
//! will happily round-trip several of them — two distinct byte strings both
//! "valid" and both naming the same record. This grammar is restricted precisely
//! so that **one record has exactly one spelling**, and the check is therefore
//! written as a byte-level acceptance test rather than a parse-and-compare.
//!
//! Percent signs are refused *anywhere* in the URI, not decoded. Once escaping
//! is admitted, two spellings exist again.
//!
//! The authority reuses [`validate_handle_hostname`] rather than restating the
//! hostname grammar. Two grammars for one production is how they drift, and this
//! one already carries the two-label rule and the reserved-TLD list — including
//! `.invalid`, which is what rejects the ATProto `handle.invalid` sentinel.
//!
//! # The URI has two dotted names in it, and they run in opposite directions
//!
//! The authority is a hostname, written leaf-first: `alice.example.net` has TLD
//! `net`, its **last** label. The collection is an NSID, whose authority is the
//! same kind of domain written **backwards**: `app.bsky.feed.post` belongs to
//! `bsky.app`, so its TLD is `app`, its **first** segment.
//!
//! Sharing one grammar is still right — see [`validate_collection`] for the four
//! wrong answers that came from reading the collection forwards — but sharing it
//! means splitting "which labels are legal" from "which label is the TLD", and
//! letting each caller say where its TLD is.

use crate::chat_v2::ids::{
    validate_domain_labels, validate_handle_hostname, validate_tld_label, BareDid,
};
use core::fmt;

/// The `at://` scheme, lowercase and exact.
pub const SCHEME: &str = "at://";

/// Maximum NSID (collection) length.
pub const NSID_MAX_LEN: usize = 317;
/// Maximum record key length.
pub const RKEY_MAX_LEN: usize = 512;
/// Maximum length of one dot-separated NSID segment.
///
/// The same 63-byte bound the domain grammar puts on a label, applied to the
/// terminal name too: the 317-byte NSID total comes from that grammar, and
/// adopting one bound from it without the other would be arbitrary.
pub const NSID_SEGMENT_MAX_LEN: usize = crate::chat_v2::ids::LABEL_MAX_LEN;

/// The derived maximum, `5 + 261 + 1 + 317 + 1 + 512`.
///
/// Derived rather than asserted, so the parts and the whole cannot disagree.
pub const AT_URI_MAX_LEN: usize =
    SCHEME.len() + crate::chat_v2::ids::BARE_DID_MAX_LEN + 1 + NSID_MAX_LEN + 1 + RKEY_MAX_LEN;

/// Why an AT URI was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtUriError {
    /// Beyond the derived 1,097-byte cap, or empty.
    Length { actual: usize },
    /// Not exactly the lowercase `at://` scheme.
    Scheme,
    /// A byte outside printable ASCII.
    NonAscii { index: usize },
    /// A percent sign anywhere in the URI.
    ///
    /// Not decoded — admitted escaping would give one record two spellings.
    PercentSign { index: usize },
    /// A query string, which this subset does not have.
    HasQuery,
    /// A fragment, which this subset does not have.
    HasFragment,
    /// An empty path segment: a duplicate or trailing slash.
    EmptySegment,
    /// The path did not have exactly a collection and a record key.
    SegmentCount { found: usize },
    /// The authority was neither a supported DID nor a production handle.
    Authority,
    /// The collection was not a valid lowercase-authority NSID.
    Collection,
    /// The record key was empty, over-long, `.`, or `..`.
    RecordKey,
}

impl fmt::Display for AtUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => {
                write!(
                    f,
                    "AT URI is {actual} bytes, at most {AT_URI_MAX_LEN} allowed"
                )
            }
            Self::Scheme => write!(f, "AT URI must begin with exactly {SCHEME:?}"),
            Self::NonAscii { index } => {
                write!(f, "AT URI byte {index} is outside printable ASCII")
            }
            Self::PercentSign { index } => write!(
                f,
                "AT URI contains a percent sign at byte {index}; this subset is unescaped"
            ),
            Self::HasQuery => f.write_str("AT URI must not carry a query"),
            Self::HasFragment => f.write_str("AT URI must not carry a fragment"),
            Self::EmptySegment => {
                f.write_str("AT URI must not contain a duplicate or trailing slash")
            }
            Self::SegmentCount { found } => write!(
                f,
                "AT URI must have exactly one collection and one record key, found {found} segments"
            ),
            Self::Authority => f.write_str("AT URI authority is not a supported DID or handle"),
            Self::Collection => f.write_str("AT URI collection is not a canonical NSID"),
            Self::RecordKey => f.write_str("AT URI record key is empty, over-long, or a dot form"),
        }
    }
}

impl core::error::Error for AtUriError {}

/// A validated restricted canonical AT URI.
///
/// Holds the original bytes. There is deliberately no normalizing constructor:
/// this grammar accepts one spelling per record, so there is nothing to
/// normalize *to* — a value that needed normalizing was simply not canonical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RestrictedAtUri {
    text: String,
    authority_end: usize,
    collection_end: usize,
}

impl RestrictedAtUri {
    /// Validates a restricted canonical AT URI.
    pub fn parse(value: &str) -> Result<Self, AtUriError> {
        let len = value.len();
        if len == 0 || len > AT_URI_MAX_LEN {
            return Err(AtUriError::Length { actual: len });
        }

        // Printable ASCII only. Checked before anything structural so that a
        // multi-byte character cannot confuse the byte offsets below.
        for (index, byte) in value.bytes().enumerate() {
            if !(0x21..=0x7E).contains(&byte) {
                return Err(AtUriError::NonAscii { index });
            }
            if byte == b'%' {
                return Err(AtUriError::PercentSign { index });
            }
        }

        let rest = value.strip_prefix(SCHEME).ok_or(AtUriError::Scheme)?;
        if rest.contains('?') {
            return Err(AtUriError::HasQuery);
        }
        if rest.contains('#') {
            return Err(AtUriError::HasFragment);
        }

        let segments: Vec<&str> = rest.split('/').collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            // Catches a duplicate slash, a trailing slash, and an empty
            // authority, all of which are second spellings of something else.
            return Err(AtUriError::EmptySegment);
        }
        if segments.len() != 3 {
            return Err(AtUriError::SegmentCount {
                found: segments.len(),
            });
        }

        let (authority, collection, rkey) = (segments[0], segments[1], segments[2]);
        validate_authority(authority)?;
        validate_collection(collection)?;
        validate_record_key(rkey)?;

        let authority_end = SCHEME.len() + authority.len();
        let collection_end = authority_end + 1 + collection.len();
        Ok(Self {
            text: value.to_owned(),
            authority_end,
            collection_end,
        })
    }

    /// The exact canonical bytes.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The authority: a supported DID or a production handle.
    pub fn authority(&self) -> &str {
        &self.text[SCHEME.len()..self.authority_end]
    }

    /// The collection NSID.
    pub fn collection(&self) -> &str {
        &self.text[self.authority_end + 1..self.collection_end]
    }

    /// The record key, which is case-sensitive.
    pub fn record_key(&self) -> &str {
        &self.text[self.collection_end + 1..]
    }
}

impl fmt::Display for RestrictedAtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// The authority is a supported DID or a normalized lowercase handle.
///
/// `did:web` is accepted only at hostname level, and its hostname must satisfy
/// the *same* production-handle grammar a bare handle does — which is why both
/// arms end in [`validate_handle_hostname`] rather than in two similar checks.
fn validate_authority(authority: &str) -> Result<(), AtUriError> {
    if authority.starts_with("did:") {
        // Reuses the bare-DID grammar, which carries the cumulative length rule
        // and the did:web hostname production.
        BareDid::parse(authority).map_err(|_| AtUriError::Authority)?;
        return Ok(());
    }
    // A production handle: the same hostname grammar, lowercase, at least two
    // labels, no reserved TLD.
    validate_handle_hostname(authority).map_err(|_| AtUriError::Authority)?;
    if authority != authority.to_ascii_lowercase() {
        return Err(AtUriError::Authority);
    }
    Ok(())
}

/// A canonical NSID: lowercase domain authority, case-sensitive terminal name.
///
/// The split is the point. `app.bsky.feed.Post` is canonical — the authority
/// labels are lowercase and only the terminal name carries case — while
/// `App.Bsky.feed.post` is not.
///
/// # The authority is a **reversed** domain, and that changes which label is
/// the TLD
///
/// An NSID's authority is the owner's domain written backwards: the collection
/// `app.bsky.feed.post` belongs to `bsky.app`, so its TLD is `app` — the
/// **first** segment. This module originally validated the authority as a
/// forward hostname, which put both TLD rules on the last segment and got four
/// classes of answer wrong:
///
/// - `org.4chan.post` was rejected because `4chan` was read as a digit-leading
///   TLD. It is an ordinary domain label, where a leading digit is legal, and
///   the real TLD is `org`.
/// - `app.bsky.test.record` was rejected because `test` was read as a reserved
///   TLD. It is a middle label of `test.bsky.app`, and the TLD is `app`.
/// - `test.foo.record` was accepted, though its TLD really is `test`, which is
///   reserved in production.
/// - `3ao.thing.foo` was accepted, though its TLD really is `3ao`, which begins
///   with a digit.
///
/// The two halves now come from [`validate_domain_labels`] and
/// [`validate_tld_label`], the same pair a forward handle uses — one grammar,
/// read in two directions, rather than two grammars that can drift.
///
/// # What is adopted from the NSID grammar, and what is left loose
///
/// Adopted: the per-segment 63-byte bound, applied to the terminal name as well
/// as to the authority labels, because the 317-byte total this module already
/// enforces comes from the same upstream grammar and taking one bound without
/// the other is arbitrary.
///
/// Left loose, deliberately: the record key's character set. §8 enumerates its
/// rkey restrictions — no percent sign, no query, fragment, or extra segment,
/// not `.` or `..`, at most 512 bytes, case-sensitive — and a charset is not
/// among them. The surrounding printable-ASCII and no-percent rules already
/// exclude most of what a tighter set would, and a client that rejected a
/// record key a server considers valid would silently drop legitimate embeds.
fn validate_collection(collection: &str) -> Result<(), AtUriError> {
    if collection.is_empty() || collection.len() > NSID_MAX_LEN {
        return Err(AtUriError::Collection);
    }
    let (authority, name) = collection.rsplit_once('.').ok_or(AtUriError::Collection)?;

    // The domain authority must be lowercase and domain-shaped.
    if authority != authority.to_ascii_lowercase() {
        return Err(AtUriError::Collection);
    }
    let labels = validate_domain_labels(authority).map_err(|_| AtUriError::Collection)?;
    // Reversed, so the TLD is the first segment. `labels` has at least two
    // entries, so this cannot be empty.
    validate_tld_label(labels[0]).map_err(|_| AtUriError::Collection)?;

    // The terminal name is case-sensitive but still ASCII-alphabetic, and is a
    // segment like any other for the purposes of the length bound.
    if name.is_empty()
        || name.len() > NSID_SEGMENT_MAX_LEN
        || !name.chars().all(|ch| ch.is_ascii_alphabetic())
        || !name.starts_with(|ch: char| ch.is_ascii_alphabetic())
    {
        return Err(AtUriError::Collection);
    }
    Ok(())
}

/// A record key: nonempty, within bounds, and not a dot form.
///
/// `.` and `..` are refused because they are path-traversal spellings, not
/// record keys, and admitting them would let one URI name a different record
/// depending on who resolved it.
fn validate_record_key(rkey: &str) -> Result<(), AtUriError> {
    if rkey.is_empty() || rkey.len() > RKEY_MAX_LEN || rkey == "." || rkey == ".." {
        return Err(AtUriError::RecordKey);
    }
    Ok(())
}
