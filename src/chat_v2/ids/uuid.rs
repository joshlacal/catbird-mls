//! Canonical UUID identity for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §2: every client-generated conversation, transition, reset,
//! recovery, Welcome, message, blob, typing, device, and idempotency ID is a
//! lowercase hyphenated UUIDv4 with the RFC 4122 variant. Braces, uppercase,
//! compact UUIDs, other versions, and other variants are rejected. UUIDs
//! embedded in DAG-CBOR are their exact 16 raw bytes.
//!
//! The `uuid` crate's parser accepts braces, uppercase, and compact forms, so
//! it is deliberately not used here. Inputs are rejected, never normalized.

use core::fmt;

/// Byte offsets of the four hyphens in a canonical UUID string.
const SEPARATORS: [usize; 4] = [8, 13, 18, 23];
/// Byte offset of the version nibble.
const VERSION_INDEX: usize = 14;
/// Byte offset of the variant nibble.
const VARIANT_INDEX: usize = 19;
/// Canonical lowercase hyphenated UUIDs are exactly this many ASCII bytes.
pub const CANONICAL_UUID_LEN: usize = 36;

/// Why a string was not a canonical protocol UUID.
///
/// Each arm names a distinct rejection reason so callers and test vectors can
/// assert on the exact predicate that fired rather than on a rendered string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UuidError {
    /// Not exactly 36 bytes. Compact (32) and braced (38) forms land here.
    Length { actual: usize },
    /// A hyphen was expected at this offset and something else was found.
    MissingSeparator { index: usize },
    /// A hex digit was expected at this offset and something else was found.
    NonHexDigit { index: usize },
    /// An uppercase hex digit appeared. Canonical form is lowercase only.
    UppercaseHex { index: usize },
    /// The version nibble was not `4`.
    UnsupportedVersion { found: char },
    /// The variant nibble was not one of `8`, `9`, `a`, `b`.
    UnsupportedVariant { found: char },
}

impl fmt::Display for UuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => {
                write!(f, "expected {CANONICAL_UUID_LEN} bytes, found {actual}")
            }
            Self::MissingSeparator { index } => write!(f, "missing '-' at byte {index}"),
            Self::NonHexDigit { index } => write!(f, "non-hex digit at byte {index}"),
            Self::UppercaseHex { index } => {
                write!(
                    f,
                    "uppercase hex at byte {index}; canonical form is lowercase"
                )
            }
            Self::UnsupportedVersion { found } => {
                write!(f, "expected UUID version 4, found '{found}'")
            }
            Self::UnsupportedVariant { found } => {
                write!(f, "expected RFC 4122 variant, found '{found}'")
            }
        }
    }
}

impl core::error::Error for UuidError {}

/// A canonical lowercase hyphenated RFC 4122 variant UUIDv4.
///
/// Stored as the exact 16 raw bytes, which is also the DAG-CBOR encoding. The
/// canonical text form is reproduced by [`fmt::Display`] and is guaranteed to
/// round-trip: parsing the output of `to_string` yields an equal value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalUuid([u8; 16]);

impl CanonicalUuid {
    /// Parses the canonical form, rejecting every non-canonical spelling.
    pub fn parse(input: &str) -> Result<Self, UuidError> {
        let bytes = input.as_bytes();
        if bytes.len() != CANONICAL_UUID_LEN {
            return Err(UuidError::Length {
                actual: bytes.len(),
            });
        }

        for (index, byte) in bytes.iter().enumerate() {
            if SEPARATORS.contains(&index) {
                if *byte != b'-' {
                    return Err(UuidError::MissingSeparator { index });
                }
                continue;
            }
            match byte {
                b'0'..=b'9' | b'a'..=b'f' => {}
                b'A'..=b'F' => return Err(UuidError::UppercaseHex { index }),
                _ => return Err(UuidError::NonHexDigit { index }),
            }
        }

        // Both nibbles are known-valid lowercase hex by the loop above.
        let version = bytes[VERSION_INDEX] as char;
        if version != '4' {
            return Err(UuidError::UnsupportedVersion { found: version });
        }
        let variant = bytes[VARIANT_INDEX] as char;
        if !matches!(variant, '8' | '9' | 'a' | 'b') {
            return Err(UuidError::UnsupportedVariant { found: variant });
        }

        let mut raw = [0u8; 16];
        let mut out = 0usize;
        let mut cursor = 0usize;
        while cursor < CANONICAL_UUID_LEN {
            if SEPARATORS.contains(&cursor) {
                cursor += 1;
                continue;
            }
            raw[out] = (hex_value(bytes[cursor]) << 4) | hex_value(bytes[cursor + 1]);
            out += 1;
            cursor += 2;
        }
        Ok(Self(raw))
    }

    /// The exact 16 raw bytes, as embedded in DAG-CBOR signing projections.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Rebuilds a value from raw bytes that are already known to be a v4/RFC
    /// 4122 UUID — for example after decoding a DAG-CBOR byte string.
    ///
    /// The version and variant bits are still checked, because raw bytes off
    /// the wire are not trusted.
    pub fn from_bytes(raw: [u8; 16]) -> Result<Self, UuidError> {
        let version = raw[6] >> 4;
        if version != 4 {
            return Err(UuidError::UnsupportedVersion {
                found: nibble_to_hex(version),
            });
        }
        let variant = raw[8] >> 4;
        if !matches!(variant, 0x8..=0xb) {
            return Err(UuidError::UnsupportedVariant {
                found: nibble_to_hex(variant),
            });
        }
        Ok(Self(raw))
    }
}

impl fmt::Display for CanonicalUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("charset validated before decode"),
    }
}

fn nibble_to_hex(nibble: u8) -> char {
    char::from_digit(u32::from(nibble), 16).unwrap_or('?')
}

/// Declares a distinct identifier newtype over [`CanonicalUuid`].
///
/// The protocol repeatedly requires that one identifier never substitutes for
/// another — an append row's `entryId` is not its signed `transitionId`, and a
/// recipient device is not a same-DID sibling. The generated transport types
/// make all of these the same Rust type, so the separation is reintroduced
/// here and enforced by the compiler.
macro_rules! uuid_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(CanonicalUuid);

        impl $name {
            /// Parses the canonical lowercase hyphenated UUIDv4 form.
            pub fn parse(input: &str) -> Result<Self, UuidError> {
                CanonicalUuid::parse(input).map($name)
            }

            /// The exact 16 raw bytes used in DAG-CBOR signing projections.
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Rechecks raw bytes decoded from the wire.
            pub fn from_bytes(raw: [u8; 16]) -> Result<Self, UuidError> {
                CanonicalUuid::from_bytes(raw).map($name)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_newtype!(
    /// Stable identity of a conversation. Immutable across generations, resets,
    /// and terminal close.
    ConversationId
);
uuid_newtype!(
    /// Append-log row identity. CHAT_PROTOCOL.md §6: this is a *replay*
    /// identity only and can never substitute for a signed `transitionId` or an
    /// outer entry fingerprint as reducer provenance.
    EntryId
);
uuid_newtype!(
    /// Identity of a signed conversation transition. This is what an interval
    /// opening and closing binds — never the append row's [`EntryId`].
    TransitionId
);
uuid_newtype!(
    /// Send idempotency identity, unique by `(conversationId, messageId)`.
    MessageId
);
uuid_newtype!(
    /// A registered device. Distinct from its owning DID: application
    /// visibility is per exact `(DID, deviceId)` leaf, never DID-aggregate.
    DeviceId
);
uuid_newtype!(
    /// Identity of a target-device-signed leaf recovery request.
    RecoveryRequestId
);
uuid_newtype!(
    /// Identity of a durable group leave request.
    LeaveRequestId
);
uuid_newtype!(
    /// Identity of a durable reset request.
    ResetRequestId
);
uuid_newtype!(
    /// Identity of a Welcome delivery addressed to an immutable recipient device.
    WelcomeId
);
uuid_newtype!(
    /// Identity of a blob.
    BlobId
);
uuid_newtype!(
    /// Server-authored recovery-work advisory identity.
    RecoveryWorkId
);
uuid_newtype!(
    /// Caller-supplied idempotency key.
    IdempotencyKey
);
uuid_newtype!(
    /// Typing notification idempotency identity.
    TypingId
);

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical v4/RFC-4122 UUID used as the base for mutation tests.
    const VALID: &str = "70707070-7070-4070-b070-707070707070";

    #[test]
    fn accepts_canonical_form() {
        let parsed = CanonicalUuid::parse(VALID).expect("canonical UUID must parse");
        assert_eq!(parsed.to_string(), VALID, "display must round-trip");
    }

    #[test]
    fn accepts_every_rfc4122_variant_nibble() {
        for variant in ['8', '9', 'a', 'b'] {
            let mut text: Vec<char> = VALID.chars().collect();
            text[VARIANT_INDEX] = variant;
            let text: String = text.into_iter().collect();
            assert!(
                CanonicalUuid::parse(&text).is_ok(),
                "variant nibble '{variant}' is RFC 4122 and must be accepted"
            );
        }
    }

    #[test]
    fn rejects_uppercase() {
        let err = CanonicalUuid::parse(&VALID.to_uppercase()).unwrap_err();
        assert_eq!(err, UuidError::UppercaseHex { index: 19 });
    }

    #[test]
    fn rejects_braces() {
        let braced = format!("{{{VALID}}}");
        assert_eq!(
            CanonicalUuid::parse(&braced).unwrap_err(),
            UuidError::Length { actual: 38 }
        );
    }

    #[test]
    fn rejects_compact() {
        let compact: String = VALID.chars().filter(|c| *c != '-').collect();
        assert_eq!(
            CanonicalUuid::parse(&compact).unwrap_err(),
            UuidError::Length { actual: 32 }
        );
    }

    #[test]
    fn rejects_non_v4_versions() {
        for version in ['0', '1', '2', '3', '5', '6', '7', '8'] {
            let mut text: Vec<char> = VALID.chars().collect();
            text[VERSION_INDEX] = version;
            let text: String = text.into_iter().collect();
            assert_eq!(
                CanonicalUuid::parse(&text).unwrap_err(),
                UuidError::UnsupportedVersion { found: version },
                "version '{version}' must be rejected"
            );
        }
    }

    #[test]
    fn rejects_non_rfc4122_variants() {
        for variant in ['0', '1', '7', 'c', 'd', 'e', 'f'] {
            let mut text: Vec<char> = VALID.chars().collect();
            text[VARIANT_INDEX] = variant;
            let text: String = text.into_iter().collect();
            assert_eq!(
                CanonicalUuid::parse(&text).unwrap_err(),
                UuidError::UnsupportedVariant { found: variant },
                "variant '{variant}' must be rejected"
            );
        }
    }

    #[test]
    fn rejects_misplaced_separator() {
        let text = "707070707-070-4070-b070-707070707070";
        assert_eq!(
            CanonicalUuid::parse(text).unwrap_err(),
            UuidError::MissingSeparator { index: 8 }
        );
    }

    #[test]
    fn rejects_non_hex() {
        let text = "7070707g-7070-4070-b070-707070707070";
        assert_eq!(
            CanonicalUuid::parse(text).unwrap_err(),
            UuidError::NonHexDigit { index: 7 }
        );
    }

    #[test]
    fn raw_bytes_match_canonical_text() {
        let parsed = CanonicalUuid::parse(VALID).unwrap();
        // 0x70 repeated, with the version nibble at byte 6 and the variant
        // nibble at byte 8 carrying 0x40.. and 0xb0.. respectively.
        assert_eq!(parsed.as_bytes()[6] >> 4, 4, "version nibble");
        assert_eq!(parsed.as_bytes()[8] >> 4, 0xb, "variant nibble");
        assert_eq!(parsed.as_bytes()[0], 0x70);
    }

    #[test]
    fn from_bytes_rechecks_version_and_variant() {
        let good = *CanonicalUuid::parse(VALID).unwrap().as_bytes();
        assert!(CanonicalUuid::from_bytes(good).is_ok());

        let mut bad_version = good;
        bad_version[6] = 0x10;
        assert!(matches!(
            CanonicalUuid::from_bytes(bad_version),
            Err(UuidError::UnsupportedVersion { .. })
        ));

        let mut bad_variant = good;
        bad_variant[8] = 0xc0;
        assert!(matches!(
            CanonicalUuid::from_bytes(bad_variant),
            Err(UuidError::UnsupportedVariant { .. })
        ));
    }

    #[test]
    fn from_bytes_round_trips_through_display() {
        let parsed = CanonicalUuid::parse(VALID).unwrap();
        let rebuilt = CanonicalUuid::from_bytes(*parsed.as_bytes()).unwrap();
        assert_eq!(rebuilt.to_string(), VALID);
    }

    #[test]
    fn newtypes_are_distinct_but_parse_identically() {
        let entry = EntryId::parse(VALID).unwrap();
        let transition = TransitionId::parse(VALID).unwrap();
        // The protocol requires these never substitute for one another. They
        // hold identical bytes here yet cannot be compared or assigned across
        // types — that is the invariant this module exists to enforce, and it
        // is checked by the compiler rather than at runtime.
        assert_eq!(entry.as_bytes(), transition.as_bytes());
        assert_eq!(entry.to_string(), transition.to_string());
    }
}
