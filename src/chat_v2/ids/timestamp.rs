//! Canonical timestamp spelling for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §2: timestamps are exactly `YYYY-MM-DDTHH:MM:SS.sssZ` —
//! uppercase UTC `Z`, exactly three fractional digits, valid Gregorian
//! calendar/time fields, and no leap second. Offsets, lowercase, missing or
//! variable fractions, and invalid dates are rejected.
//!
//! The exact bytes matter: a canonical timestamp is an input to both the
//! application-entry and control-entry fingerprints as canonical text, so this
//! type retains the original spelling and never reformats it.

use core::fmt;

/// A canonical timestamp is exactly this many ASCII bytes.
pub const CANONICAL_TIMESTAMP_LEN: usize = 24;

/// Why a string was not a canonical protocol timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    /// Not exactly 24 bytes.
    Length { actual: usize },
    /// A structural delimiter was wrong. Lowercase `t`/`z` and `+00:00`
    /// offsets land here.
    Delimiter { index: usize, expected: char },
    /// A digit was expected at this offset.
    NonDigit { index: usize },
    /// Month outside 1–12.
    Month { found: u32 },
    /// Day outside 1..=days-in-month for the given Gregorian year.
    Day { year: u32, month: u32, found: u32 },
    /// Hour outside 0–23.
    Hour { found: u32 },
    /// Minute outside 0–59.
    Minute { found: u32 },
    /// Second outside 0–59. A `60` leap second lands here.
    Second { found: u32 },
    /// Year zero is not a valid Gregorian year.
    Year { found: u32 },
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                f,
                "timestamp must be exactly {CANONICAL_TIMESTAMP_LEN} bytes, found {actual}"
            ),
            Self::Delimiter { index, expected } => {
                write!(f, "expected '{expected}' at byte {index}")
            }
            Self::NonDigit { index } => write!(f, "expected a digit at byte {index}"),
            Self::Month { found } => write!(f, "month {found} outside 1-12"),
            Self::Day { year, month, found } => {
                write!(f, "day {found} outside range for {year}-{month:02}")
            }
            Self::Hour { found } => write!(f, "hour {found} outside 0-23"),
            Self::Minute { found } => write!(f, "minute {found} outside 0-59"),
            Self::Second { found } => write!(f, "second {found} outside 0-59 (no leap second)"),
            Self::Year { found } => write!(f, "year {found} is not a valid Gregorian year"),
        }
    }
}

impl core::error::Error for TimestampError {}

/// A timestamp in the frozen canonical spelling `YYYY-MM-DDTHH:MM:SS.sssZ`.
///
/// Ordering is lexicographic over the canonical bytes, which for this fixed
/// -width UTC spelling is also chronological order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalTimestamp {
    text: String,
}

impl CanonicalTimestamp {
    /// Validates and adopts a canonical timestamp. Inputs are rejected, never
    /// normalized.
    pub fn parse(input: &str) -> Result<Self, TimestampError> {
        let bytes = input.as_bytes();
        if bytes.len() != CANONICAL_TIMESTAMP_LEN {
            return Err(TimestampError::Length {
                actual: bytes.len(),
            });
        }

        for (index, expected) in [
            (4, '-'),
            (7, '-'),
            (10, 'T'),
            (13, ':'),
            (16, ':'),
            (19, '.'),
        ] {
            if bytes[index] != expected as u8 {
                return Err(TimestampError::Delimiter { index, expected });
            }
        }
        if bytes[23] != b'Z' {
            return Err(TimestampError::Delimiter {
                index: 23,
                expected: 'Z',
            });
        }

        for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22] {
            if !bytes[index].is_ascii_digit() {
                return Err(TimestampError::NonDigit { index });
            }
        }

        let year = digits(bytes, 0, 4);
        let month = digits(bytes, 5, 2);
        let day = digits(bytes, 8, 2);
        let hour = digits(bytes, 11, 2);
        let minute = digits(bytes, 14, 2);
        let second = digits(bytes, 17, 2);
        // Milliseconds are three digits by construction, so every value 000-999
        // is in range and needs no further check.

        if year == 0 {
            return Err(TimestampError::Year { found: year });
        }
        if !(1..=12).contains(&month) {
            return Err(TimestampError::Month { found: month });
        }
        let max_day = days_in_month(year, month);
        if day < 1 || day > max_day {
            return Err(TimestampError::Day {
                year,
                month,
                found: day,
            });
        }
        if hour > 23 {
            return Err(TimestampError::Hour { found: hour });
        }
        if minute > 59 {
            return Err(TimestampError::Minute { found: minute });
        }
        if second > 59 {
            return Err(TimestampError::Second { found: second });
        }

        Ok(Self {
            text: input.to_owned(),
        })
    }

    /// The exact canonical bytes, as fed to fingerprint projections.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for CanonicalTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn digits(bytes: &[u8], offset: usize, count: usize) -> u32 {
    let mut value = 0u32;
    for byte in &bytes[offset..offset + count] {
        value = value * 10 + u32::from(byte - b'0');
    }
    value
}

/// Proleptic Gregorian leap year rule.
fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "2026-08-14T12:34:56.789Z";

    #[test]
    fn accepts_canonical_spelling() {
        let parsed = CanonicalTimestamp::parse(VALID).unwrap();
        assert_eq!(parsed.as_str(), VALID);
        assert_eq!(VALID.len(), CANONICAL_TIMESTAMP_LEN);
    }

    #[test]
    fn rejects_lowercase_designators() {
        assert_eq!(
            CanonicalTimestamp::parse("2026-08-14t12:34:56.789Z").unwrap_err(),
            TimestampError::Delimiter {
                index: 10,
                expected: 'T'
            }
        );
        assert_eq!(
            CanonicalTimestamp::parse("2026-08-14T12:34:56.789z").unwrap_err(),
            TimestampError::Delimiter {
                index: 23,
                expected: 'Z'
            }
        );
    }

    #[test]
    fn rejects_numeric_offset() {
        // "2026-08-14T12:34:56+00:00" is 25 bytes, so it fails on length first.
        assert!(matches!(
            CanonicalTimestamp::parse("2026-08-14T12:34:56+00:00").unwrap_err(),
            TimestampError::Length { .. }
        ));
        // A same-length offset spelling still fails at the fraction delimiter.
        assert_eq!(
            CanonicalTimestamp::parse("2026-08-14T12:34:56+00:00Z").unwrap_err(),
            TimestampError::Length { actual: 26 }
        );
    }

    #[test]
    fn rejects_missing_or_variable_fraction() {
        // No fraction at all: 20 bytes.
        assert!(matches!(
            CanonicalTimestamp::parse("2026-08-14T12:34:56Z").unwrap_err(),
            TimestampError::Length { actual: 20 }
        ));
        // Six fractional digits: 27 bytes.
        assert!(matches!(
            CanonicalTimestamp::parse("2026-08-14T12:34:56.789012Z").unwrap_err(),
            TimestampError::Length { actual: 27 }
        ));
        // Exactly one fractional digit: 22 bytes.
        assert!(matches!(
            CanonicalTimestamp::parse("2026-08-14T12:34:56.7Z").unwrap_err(),
            TimestampError::Length { actual: 22 }
        ));
    }

    #[test]
    fn rejects_leap_second() {
        assert_eq!(
            CanonicalTimestamp::parse("2016-12-31T23:59:60.000Z").unwrap_err(),
            TimestampError::Second { found: 60 }
        );
    }

    #[test]
    fn rejects_out_of_range_fields() {
        assert_eq!(
            CanonicalTimestamp::parse("2026-13-01T00:00:00.000Z").unwrap_err(),
            TimestampError::Month { found: 13 }
        );
        assert_eq!(
            CanonicalTimestamp::parse("2026-00-01T00:00:00.000Z").unwrap_err(),
            TimestampError::Month { found: 0 }
        );
        assert_eq!(
            CanonicalTimestamp::parse("2026-08-14T24:00:00.000Z").unwrap_err(),
            TimestampError::Hour { found: 24 }
        );
        assert_eq!(
            CanonicalTimestamp::parse("2026-08-14T12:60:00.000Z").unwrap_err(),
            TimestampError::Minute { found: 60 }
        );
        assert_eq!(
            CanonicalTimestamp::parse("0000-01-01T00:00:00.000Z").unwrap_err(),
            TimestampError::Year { found: 0 }
        );
    }

    #[test]
    fn enforces_gregorian_month_lengths() {
        assert!(CanonicalTimestamp::parse("2026-01-31T00:00:00.000Z").is_ok());
        assert_eq!(
            CanonicalTimestamp::parse("2026-04-31T00:00:00.000Z").unwrap_err(),
            TimestampError::Day {
                year: 2026,
                month: 4,
                found: 31
            }
        );
        assert_eq!(
            CanonicalTimestamp::parse("2026-08-00T00:00:00.000Z").unwrap_err(),
            TimestampError::Day {
                year: 2026,
                month: 8,
                found: 0
            }
        );
    }

    #[test]
    fn applies_the_full_gregorian_leap_rule() {
        // 2024 is a leap year: divisible by 4, not by 100.
        assert!(CanonicalTimestamp::parse("2024-02-29T00:00:00.000Z").is_ok());
        // 2026 is not.
        assert!(CanonicalTimestamp::parse("2026-02-29T00:00:00.000Z").is_err());
        // 2000 is: divisible by 400.
        assert!(CanonicalTimestamp::parse("2000-02-29T00:00:00.000Z").is_ok());
        // 1900 is not: divisible by 100 but not 400. This is the case a naive
        // `year % 4` rule gets wrong.
        assert_eq!(
            CanonicalTimestamp::parse("1900-02-29T00:00:00.000Z").unwrap_err(),
            TimestampError::Day {
                year: 1900,
                month: 2,
                found: 29
            }
        );
    }

    #[test]
    fn accepts_millisecond_range_boundaries() {
        assert!(CanonicalTimestamp::parse("2026-08-14T12:34:56.000Z").is_ok());
        assert!(CanonicalTimestamp::parse("2026-08-14T12:34:56.999Z").is_ok());
    }

    #[test]
    fn lexicographic_order_is_chronological() {
        let earlier = CanonicalTimestamp::parse("2026-08-14T12:34:56.788Z").unwrap();
        let later = CanonicalTimestamp::parse("2026-08-14T12:34:56.789Z").unwrap();
        assert!(earlier < later);

        let next_year = CanonicalTimestamp::parse("2027-01-01T00:00:00.000Z").unwrap();
        assert!(later < next_year);
    }
}
