//! Cursor and position types for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §9 defines three things that are all integers or opaque
//! strings on the wire and are trivially confusable, yet mean entirely
//! different things. Giving each its own type is not decoration: two of the
//! three confusions are security bugs rather than merely wrong behaviour.
//!
//! - [`AfterSeq`] is a scan position for one authenticated device. It need not
//!   fall inside any access interval and may legitimately be zero.
//! - [`SnapshotSeq`] is the greatest committed global seq included in a
//!   transactionally observed public-state snapshot. The spec states outright
//!   that it "is neither an entry cursor nor an application-entitlement
//!   grant". Treating it as a scan position would skip entries; treating it as
//!   an entitlement would grant history the device never had.
//! - [`EventCursor`] is an opaque global hint. Opaque cursors are never
//!   numerically compared or maxed, so this type deliberately implements
//!   neither `Ord` nor `PartialOrd`.

use super::ids::seq::{IntegerError, Seq, MAX_SAFE_INTEGER};
use core::fmt;

/// A per-conversation scan position for `getEntries.afterSeq`.
///
/// Deliberately a different type from [`Seq`]: an entry sequence is a
/// positive-safe-integer identifying a row that exists, whereas a scan position
/// is a lower bound that may be zero and need not correspond to any row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AfterSeq(i64);

impl AfterSeq {
    /// The position that scans a conversation from its first entry.
    pub const START: Self = Self(0);

    /// Adopts a scan position in `0..=9007199254740991`.
    pub fn new(value: i64) -> Result<Self, IntegerError> {
        if value < 0 {
            return Err(IntegerError::BelowMinimum { value, minimum: 0 });
        }
        if value > MAX_SAFE_INTEGER {
            return Err(IntegerError::AboveSafeInteger { value });
        }
        Ok(Self(value))
    }

    /// The position immediately after a given entry.
    pub fn after(seq: Seq) -> Self {
        // A Seq is already within the safe-integer range and is positive, so
        // reusing its value as a scan position cannot go out of bounds.
        Self(seq.get())
    }

    /// The underlying value, as sent in `getEntries.afterSeq`.
    pub fn get(&self) -> i64 {
        self.0
    }

    /// Whether an entry at `seq` lies above this scan position, i.e. whether it
    /// is a legitimate member of the next page.
    pub fn admits(&self, seq: Seq) -> bool {
        seq.get() > self.0
    }
}

impl fmt::Display for AfterSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The greatest committed global seq included in an observed public-state
/// snapshot.
///
/// This type intentionally offers no conversion to [`AfterSeq`]. The protocol
/// states that `conversationState.snapshotSeq` is neither an entry cursor nor
/// an application-entitlement grant, and the only way to be sure a future
/// change does not quietly use it as one is to make the conversion unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SnapshotSeq(i64);

impl SnapshotSeq {
    /// Adopts a snapshot position in `0..=9007199254740991`.
    pub fn new(value: i64) -> Result<Self, IntegerError> {
        if value < 0 {
            return Err(IntegerError::BelowMinimum { value, minimum: 0 });
        }
        if value > MAX_SAFE_INTEGER {
            return Err(IntegerError::AboveSafeInteger { value });
        }
        Ok(Self(value))
    }

    /// The underlying value, for display and telemetry only.
    pub fn get(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for SnapshotSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An opaque database-global event cursor.
///
/// CHAT_PROTOCOL.md §9: opaque cursors are never numerically compared or maxed,
/// and `eventCursor` is never a page cursor. Accordingly this type implements
/// only equality — there is no ordering to accidentally rely on, and no way to
/// pick "the greater of two cursors", which for an opaque value is meaningless
/// even when both happen to parse as numbers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventCursor(String);

impl EventCursor {
    /// Adopts an opaque cursor exactly as the server sent it.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The exact bytes, to be echoed back unmodified.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(value: i64) -> Seq {
        Seq::new(value).expect("test sequence must be valid")
    }

    #[test]
    fn after_seq_starts_at_zero_and_admits_the_first_entry() {
        assert_eq!(AfterSeq::START.get(), 0);
        assert!(
            AfterSeq::START.admits(Seq::FIRST),
            "a fresh scan must admit entry 1"
        );
    }

    #[test]
    fn after_seq_admits_only_strictly_greater_entries() {
        let position = AfterSeq::new(10).unwrap();
        assert!(!position.admits(seq(9)));
        assert!(
            !position.admits(seq(10)),
            "afterSeq is exclusive: entry 10 was already delivered"
        );
        assert!(position.admits(seq(11)));
    }

    #[test]
    fn after_seq_advances_to_sit_exactly_on_the_last_delivered_entry() {
        let advanced = AfterSeq::after(seq(42));
        assert_eq!(advanced.get(), 42);
        assert!(
            !advanced.admits(seq(42)),
            "entry 42 must not be redelivered"
        );
        assert!(advanced.admits(seq(43)));
    }

    #[test]
    fn after_seq_rejects_negative_and_oversize() {
        assert_eq!(
            AfterSeq::new(-1).unwrap_err(),
            IntegerError::BelowMinimum {
                value: -1,
                minimum: 0
            }
        );
        assert!(AfterSeq::new(MAX_SAFE_INTEGER).is_ok());
        assert_eq!(
            AfterSeq::new(MAX_SAFE_INTEGER + 1).unwrap_err(),
            IntegerError::AboveSafeInteger {
                value: MAX_SAFE_INTEGER + 1
            }
        );
    }

    #[test]
    fn snapshot_seq_is_not_convertible_to_a_scan_position() {
        // There is deliberately no From/Into between these, and no constructor
        // on AfterSeq that takes a SnapshotSeq. This test documents the intent;
        // the compiler is what enforces it. Using snapshotSeq as afterSeq would
        // skip every entry between the last pull and the snapshot.
        let snapshot = SnapshotSeq::new(500).unwrap();
        let scan = AfterSeq::new(120).unwrap();
        assert_ne!(snapshot.get(), scan.get());
        // Reaching the raw value still requires an explicit, visible call.
        assert_eq!(snapshot.get(), 500);
    }

    #[test]
    fn snapshot_seq_shares_the_safe_integer_bound() {
        assert!(SnapshotSeq::new(0).is_ok());
        assert!(SnapshotSeq::new(MAX_SAFE_INTEGER).is_ok());
        assert!(SnapshotSeq::new(MAX_SAFE_INTEGER + 1).is_err());
        assert!(SnapshotSeq::new(-1).is_err());
    }

    #[test]
    fn event_cursors_compare_only_by_equality() {
        let first = EventCursor::new("opaque-aaa");
        let same = EventCursor::new("opaque-aaa");
        let other = EventCursor::new("opaque-bbb");
        assert_eq!(first, same);
        assert_ne!(first, other);
        // EventCursor implements neither Ord nor PartialOrd, so `first < other`
        // does not compile. That is the point: the protocol forbids numerically
        // comparing or maxing opaque cursors, and a cursor that looks numeric
        // is exactly the case where someone would try.
    }

    #[test]
    fn event_cursors_are_echoed_byte_for_byte() {
        let raw = "eyJmZW5jZSI6MTIzfQ";
        let cursor = EventCursor::new(raw);
        assert_eq!(cursor.as_str(), raw, "a cursor is never reinterpreted");
        assert_eq!(cursor.to_string(), raw);
    }
}
