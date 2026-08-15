//! The storage error taxonomy.
//!
//! Every failure this layer can produce is a named variant. That is a deliberate
//! contrast with the seam it replaces: v1's backend defaults twenty of its
//! thirty-four methods to no-ops, so a platform that never implemented one loses
//! the state silently and reports success. Nothing here can report success
//! without having stored something, and nothing here can fail without saying
//! which record and which operation failed.
//!
//! Two variants deserve their existence explained, because both would otherwise
//! be tempting to fold into a neighbour:
//!
//! - [`StorageError::CrossDidAccess`] is not a [`StorageError::NotFound`]. One
//!   principal's store asked for another principal's state has been misrouted,
//!   and a miss is something callers retry, repair, or create through.
//! - [`StorageError::Corrupt`] is not a [`StorageError::NotFound`] either.
//!   Bytes that will not decode are a fault to surface, and treating them as
//!   absence is how a client silently discards durable state it still holds —
//!   which for the journal means re-signing an operation and burning its
//!   identity permanently.

use crate::chat_v2::cursor::AfterSeq;
use crate::chat_v2::ids::BareDid;
use crate::chat_v2::interval::RecipientBinding;
use core::fmt;

/// Which family of record a storage failure concerns.
///
/// Named rather than free-text so a failure can be routed and counted without
/// parsing a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// The per-conversation scan position.
    Cursor,
    /// A persisted append-log entry or its durable rejection.
    Entry,
    /// A journalled mutation awaiting a conclusive outcome.
    Journal,
    /// One exact-device application access schedule.
    Schedule,
    /// The opaque MLS ratchet checkpoint accompanying a page.
    RatchetCheckpoint,
}

impl RecordKind {
    /// The record family's name, as it appears in a message.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::Entry => "entry",
            Self::Journal => "journal entry",
            Self::Schedule => "schedule",
            Self::RatchetCheckpoint => "ratchet checkpoint",
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a storage operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// A store opened for one principal was asked for another principal's
    /// state.
    ///
    /// The per-DID contract is one store per DID. Reaching this means a store
    /// handle was routed to the wrong principal, which no downstream check
    /// corrects.
    CrossDidAccess {
        /// The principal this store was opened for.
        owner: BareDid,
        /// The principal the access named.
        requested: BareDid,
    },
    /// The named record does not exist.
    ///
    /// An ordinary, expected outcome: a fresh conversation has no cursor, and an
    /// unknown operation identity has no journal entry.
    NotFound {
        /// Which record family was searched.
        record: RecordKind,
        /// The key that was searched for.
        key: String,
    },
    /// Stored bytes did not decode into the record they claim to be.
    ///
    /// Surfaced rather than swallowed. A caller that treated this as absence
    /// would rebuild the record from scratch — and for a journal entry that
    /// means re-signing, which changes `signedAt`, the transcript, and the
    /// digest, converting a recoverable ambiguity into a permanent conflict.
    Corrupt {
        /// Which record family failed to decode.
        record: RecordKind,
        /// The key whose bytes failed.
        key: String,
        /// What the decoder objected to.
        detail: String,
    },
    /// A page commit did not build on the stored scan position.
    ///
    /// The compare-and-set refusal. Two commits racing on one device would
    /// otherwise silently lose one another's effects: the loser's entries land,
    /// the winner's cursor stands, and the difference is skipped forever because
    /// `afterSeq` is exclusive and those entries are never returned again.
    ///
    /// Distinct from a [`StorageError::NotFound`] cursor, which means the page
    /// continued from a position this store never held — a misrouted store
    /// rather than a lost race, and a different thing to go and fix.
    CursorMismatch {
        /// The exact device whose position was contested.
        binding: RecipientBinding,
        /// The position the page was fetched against.
        page_built_on: AfterSeq,
        /// The position the store actually holds.
        stored: AfterSeq,
    },
    /// The underlying platform store failed.
    ///
    /// The one variant carrying an opaque platform message, because the platform
    /// layer owns the I/O and its errors are not this crate's to enumerate. It
    /// still names the operation, so a failure is attributable without reading
    /// the detail string.
    Backend {
        /// The trait operation that failed.
        operation: &'static str,
        /// The platform's own description.
        detail: String,
    },
}

impl StorageError {
    /// Whether this failure means state crossed a principal boundary.
    ///
    /// Exposed so a caller can escalate a containment breach differently from an
    /// ordinary fault without matching on the variant and getting it wrong.
    pub fn is_isolation_breach(&self) -> bool {
        matches!(self, Self::CrossDidAccess { .. })
    }

    /// The record family this failure concerns, when it names one.
    pub fn record(&self) -> Option<RecordKind> {
        match self {
            Self::NotFound { record, .. } | Self::Corrupt { record, .. } => Some(*record),
            Self::CursorMismatch { .. } => Some(RecordKind::Cursor),
            Self::CrossDidAccess { .. } | Self::Backend { .. } => None,
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossDidAccess { owner, requested } => write!(
                f,
                "store belongs to {owner} and was asked for {requested}; \
                 per-DID isolation means one store per DID"
            ),
            Self::NotFound { record, key } => write!(f, "no {record} for {key}"),
            Self::Corrupt {
                record,
                key,
                detail,
            } => write!(f, "stored {record} for {key} did not decode: {detail}"),
            Self::CursorMismatch {
                binding,
                page_built_on,
                stored,
            } => write!(
                f,
                "page for {binding} was fetched at {page_built_on} but the store holds {stored}; \
                 committing it would discard the effects that advanced it"
            ),
            Self::Backend { operation, detail } => {
                write!(f, "{operation} failed in the platform store: {detail}")
            }
        }
    }
}

impl core::error::Error for StorageError {}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const STRANGER: &str = "did:plc:44ybard66vv44zksje25o7dz";

    fn did(value: &str) -> BareDid {
        BareDid::parse(value).unwrap()
    }

    #[test]
    fn a_cross_did_access_names_both_principals() {
        // Naming only one leaves an operator unable to tell which side is
        // wrong: the store that was opened, or the access that was routed.
        let err = StorageError::CrossDidAccess {
            owner: did(OWNER),
            requested: did(STRANGER),
        };
        let rendered = err.to_string();
        assert!(rendered.contains(OWNER), "{rendered}");
        assert!(rendered.contains(STRANGER), "{rendered}");
        assert!(err.is_isolation_breach());
    }

    #[test]
    fn corruption_is_distinguishable_from_absence() {
        // The distinction the journal depends on. Absence means "prepare a new
        // operation"; corruption means "stop, something durable is damaged".
        // Collapsing them would have a client re-sign an operation whose
        // original bytes may already have committed.
        let missing = StorageError::NotFound {
            record: RecordKind::Journal,
            key: "op-1".to_owned(),
        };
        let damaged = StorageError::Corrupt {
            record: RecordKind::Journal,
            key: "op-1".to_owned(),
            detail: "truncated signature".to_owned(),
        };
        assert_ne!(missing, damaged);
        assert_eq!(missing.record(), damaged.record());
        assert!(damaged.to_string().contains("truncated signature"));
    }

    #[test]
    fn a_backend_failure_names_the_operation_it_failed() {
        // The detail string is the platform's, but attribution is ours: a bare
        // platform message with no operation name is unattributable in a log.
        let err = StorageError::Backend {
            operation: "commit_page",
            detail: "disk full".to_owned(),
        };
        assert!(err.to_string().contains("commit_page"));
        assert!(err.to_string().contains("disk full"));
        assert!(!err.is_isolation_breach());
        assert_eq!(err.record(), None);
    }

    #[test]
    fn every_record_kind_renders_a_distinct_name() {
        // A shared or empty label would make failures indistinguishable in the
        // one place they are read: a log line during an incident.
        let kinds = [
            RecordKind::Cursor,
            RecordKind::Entry,
            RecordKind::Journal,
            RecordKind::Schedule,
            RecordKind::RatchetCheckpoint,
        ];
        let mut seen = Vec::new();
        for kind in kinds {
            let name = kind.as_str();
            assert!(!name.is_empty());
            assert!(!seen.contains(&name), "{name} is used twice");
            seen.push(name);
            assert_eq!(kind.to_string(), name);
        }
        assert_eq!(seen.len(), kinds.len());
    }
}
