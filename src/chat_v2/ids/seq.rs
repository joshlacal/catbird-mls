//! Bounded integers for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §2: integer fields never exceed `9007199254740991`. §4
//! additionally requires that any checked increment past that bound rejects
//! atomically with `CoordinateOverflow` and never wraps, so every arithmetic
//! operation here is checked and returns an error rather than saturating.

use core::fmt;

/// The largest integer any protocol field may carry, i.e. JavaScript's
/// `Number.MAX_SAFE_INTEGER`. The wire format is JSON, so values above this
/// cannot survive a round trip through a conforming client.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Why an integer was not acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerError {
    /// Below the field's minimum. Negative values and, for [`Seq`], zero.
    BelowMinimum { value: i64, minimum: i64 },
    /// Above `9007199254740991`.
    AboveSafeInteger { value: i64 },
    /// A checked increment would have exceeded the safe-integer ceiling.
    Overflow { current: i64 },
}

impl fmt::Display for IntegerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowMinimum { value, minimum } => {
                write!(f, "{value} is below the minimum {minimum}")
            }
            Self::AboveSafeInteger { value } => {
                write!(
                    f,
                    "{value} exceeds the safe-integer ceiling {MAX_SAFE_INTEGER}"
                )
            }
            Self::Overflow { current } => {
                write!(f, "incrementing {current} would exceed {MAX_SAFE_INTEGER}")
            }
        }
    }
}

impl core::error::Error for IntegerError {}

/// A non-negative integer within the safe-integer ceiling.
///
/// Used for `generation`, `stateVersion`, `epoch`, and `metadataVersion`, all
/// of which legitimately start at zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeInteger(i64);

impl SafeInteger {
    /// Zero, the creation value for generation, stateVersion, and epoch.
    pub const ZERO: Self = Self(0);

    /// Adopts a value in `0..=9007199254740991`.
    pub fn new(value: i64) -> Result<Self, IntegerError> {
        if value < 0 {
            return Err(IntegerError::BelowMinimum { value, minimum: 0 });
        }
        if value > MAX_SAFE_INTEGER {
            return Err(IntegerError::AboveSafeInteger { value });
        }
        Ok(Self(value))
    }

    /// The underlying value.
    pub fn get(&self) -> i64 {
        self.0
    }

    /// Increments by exactly one, rejecting rather than wrapping at the
    /// ceiling. This is the `CoordinateOverflow` boundary.
    pub fn checked_increment(&self) -> Result<Self, IntegerError> {
        if self.0 >= MAX_SAFE_INTEGER {
            return Err(IntegerError::Overflow { current: self.0 });
        }
        Ok(Self(self.0 + 1))
    }
}

impl fmt::Display for SafeInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A conversation append-log sequence number.
///
/// The control-entry fingerprint projection declares `seq` as a
/// positive-safe-integer, so an entry sequence is always at least 1. This is
/// deliberately a different type from a scan position: `getEntries.afterSeq`
/// may legitimately be zero and need not fall inside any interval, so it is
/// modelled separately in the cursor module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seq(i64);

impl Seq {
    /// The first possible entry sequence.
    pub const FIRST: Self = Self(1);

    /// Adopts a value in `1..=9007199254740991`.
    pub fn new(value: i64) -> Result<Self, IntegerError> {
        if value < 1 {
            return Err(IntegerError::BelowMinimum { value, minimum: 1 });
        }
        if value > MAX_SAFE_INTEGER {
            return Err(IntegerError::AboveSafeInteger { value });
        }
        Ok(Self(value))
    }

    /// The underlying value.
    pub fn get(&self) -> i64 {
        self.0
    }

    /// Whether this sequence is strictly greater than `other`.
    ///
    /// Named rather than inlined because the protocol distinguishes a strict
    /// gap (`Remove`) from permitted equality at a touching boundary, and the
    /// call sites read better when the comparison says which rule it enforces.
    pub fn is_strictly_after(&self, other: Seq) -> bool {
        self.0 > other.0
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_integer_accepts_zero_and_the_ceiling() {
        assert_eq!(SafeInteger::new(0).unwrap().get(), 0);
        assert_eq!(
            SafeInteger::new(MAX_SAFE_INTEGER).unwrap().get(),
            MAX_SAFE_INTEGER
        );
    }

    #[test]
    fn safe_integer_rejects_negative_and_oversize() {
        assert_eq!(
            SafeInteger::new(-1).unwrap_err(),
            IntegerError::BelowMinimum {
                value: -1,
                minimum: 0
            }
        );
        assert_eq!(
            SafeInteger::new(MAX_SAFE_INTEGER + 1).unwrap_err(),
            IntegerError::AboveSafeInteger {
                value: MAX_SAFE_INTEGER + 1
            }
        );
    }

    #[test]
    fn increment_rejects_at_the_ceiling_instead_of_wrapping() {
        let below = SafeInteger::new(MAX_SAFE_INTEGER - 1).unwrap();
        assert_eq!(below.checked_increment().unwrap().get(), MAX_SAFE_INTEGER);

        let at_ceiling = SafeInteger::new(MAX_SAFE_INTEGER).unwrap();
        assert_eq!(
            at_ceiling.checked_increment().unwrap_err(),
            IntegerError::Overflow {
                current: MAX_SAFE_INTEGER
            },
            "this is the CoordinateOverflow boundary and must never wrap"
        );
    }

    #[test]
    fn seq_is_positive_only() {
        assert_eq!(Seq::new(1).unwrap(), Seq::FIRST);
        assert_eq!(
            Seq::new(0).unwrap_err(),
            IntegerError::BelowMinimum {
                value: 0,
                minimum: 1
            },
            "the control fingerprint projection declares seq positive"
        );
        assert_eq!(
            Seq::new(-1).unwrap_err(),
            IntegerError::BelowMinimum {
                value: -1,
                minimum: 1
            }
        );
    }

    #[test]
    fn seq_honours_the_safe_integer_ceiling() {
        assert!(Seq::new(MAX_SAFE_INTEGER).is_ok());
        assert_eq!(
            Seq::new(MAX_SAFE_INTEGER + 1).unwrap_err(),
            IntegerError::AboveSafeInteger {
                value: MAX_SAFE_INTEGER + 1
            }
        );
    }

    #[test]
    fn strict_ordering_distinguishes_gap_from_equality() {
        let three = Seq::new(3).unwrap();
        let ten = Seq::new(10).unwrap();
        assert!(ten.is_strictly_after(three));
        assert!(!three.is_strictly_after(ten));
        // Equality is not "after". A touching boundary permits equality; a
        // Remove requires a strict gap. Both call sites depend on this.
        assert!(!three.is_strictly_after(three));
    }
}
