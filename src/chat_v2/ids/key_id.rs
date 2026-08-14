//! Device signing-key identity for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §2: `keyId` is the 43-character base64url-without-padding
//! SHA-256 thumbprint of the exact raw 32-byte Ed25519 key.
//!
//! 43 base64url characters carry 258 bits but a SHA-256 digest is 256, so the
//! final character's low two bits are padding and must be zero. Accepting a
//! non-canonical final character would admit 4 distinct spellings of the same
//! digest, which would break the byte-equality comparisons the protocol relies
//! on, so it is rejected.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use core::fmt;
use sha2::{Digest, Sha256};

/// A key ID is exactly this many base64url characters.
pub const KEY_ID_LEN: usize = 43;
/// Ed25519 public keys are exactly this many raw bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Why a string was not a canonical key ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyIdError {
    /// Not exactly 43 characters.
    Length { actual: usize },
    /// A character outside the base64url alphabet `[A-Za-z0-9_-]`. Standard
    /// base64's `+` and `/`, and any `=` padding, land here.
    Charset { index: usize, found: char },
    /// The final character carried non-zero padding bits, so the encoding is
    /// not canonical for a 32-byte digest.
    NonCanonicalTrailingBits { found: char },
}

impl fmt::Display for KeyIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => {
                write!(
                    f,
                    "keyId must be exactly {KEY_ID_LEN} characters, found {actual}"
                )
            }
            Self::Charset { index, found } => {
                write!(f, "character '{found}' at {index} is outside base64url")
            }
            Self::NonCanonicalTrailingBits { found } => write!(
                f,
                "final character '{found}' carries non-zero padding bits; \
                 the encoding is not canonical for a 32-byte digest"
            ),
        }
    }
}

impl core::error::Error for KeyIdError {}

/// The base64url SHA-256 thumbprint of a device's raw Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId {
    text: String,
}

impl KeyId {
    /// Validates and adopts a key ID in its canonical spelling.
    pub fn parse(input: &str) -> Result<Self, KeyIdError> {
        let bytes = input.as_bytes();
        if bytes.len() != KEY_ID_LEN {
            return Err(KeyIdError::Length {
                actual: bytes.len(),
            });
        }
        for (index, byte) in bytes.iter().enumerate() {
            if !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') {
                return Err(KeyIdError::Charset {
                    index,
                    found: *byte as char,
                });
            }
        }

        // The 43rd character encodes bits 252..258. Only bits 252..256 are
        // digest data, so the low two bits of its 6-bit value must be zero.
        let last = bytes[KEY_ID_LEN - 1];
        let sextet = base64url_value(last);
        if sextet & 0b11 != 0 {
            return Err(KeyIdError::NonCanonicalTrailingBits {
                found: last as char,
            });
        }

        Ok(Self {
            text: input.to_owned(),
        })
    }

    /// Derives the key ID for an Ed25519 public key.
    pub fn from_public_key(public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        let digest = Sha256::digest(public_key);
        Self {
            text: URL_SAFE_NO_PAD.encode(digest),
        }
    }

    /// Whether this key ID is the thumbprint of the given public key.
    ///
    /// Derives and compares rather than trusting a caller-supplied pairing,
    /// because a device's claimed key ID and its actual key are separate wire
    /// fields that an attacker controls independently.
    pub fn matches_public_key(&self, public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> bool {
        Self::from_public_key(public_key).text == self.text
    }

    /// The exact canonical characters.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn base64url_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => unreachable!("charset validated before decode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; ED25519_PUBLIC_KEY_LEN] {
        // The historical seed 0x91 device from the master plan's executable
        // positive; the exact bytes are irrelevant here, only that they are a
        // fixed 32-byte key.
        [0x91; ED25519_PUBLIC_KEY_LEN]
    }

    #[test]
    fn derived_key_id_is_canonical_and_reparses() {
        let key_id = KeyId::from_public_key(&sample_key());
        assert_eq!(key_id.as_str().len(), KEY_ID_LEN);
        let reparsed = KeyId::parse(key_id.as_str()).expect("derived form must be canonical");
        assert_eq!(reparsed, key_id);
    }

    #[test]
    fn derivation_is_deterministic_and_key_dependent() {
        assert_eq!(
            KeyId::from_public_key(&sample_key()),
            KeyId::from_public_key(&sample_key())
        );

        let mut other = sample_key();
        other[0] ^= 0x01;
        assert_ne!(
            KeyId::from_public_key(&sample_key()),
            KeyId::from_public_key(&other),
            "a one-bit key change must change the thumbprint"
        );
    }

    #[test]
    fn matches_public_key_rejects_a_mismatched_pairing() {
        let key_id = KeyId::from_public_key(&sample_key());
        assert!(key_id.matches_public_key(&sample_key()));

        let mut impostor = sample_key();
        impostor[31] ^= 0x80;
        assert!(
            !key_id.matches_public_key(&impostor),
            "a claimed keyId must not validate against a different key"
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let key_id = KeyId::from_public_key(&sample_key());
        let short = &key_id.as_str()[..KEY_ID_LEN - 1];
        assert_eq!(
            KeyId::parse(short).unwrap_err(),
            KeyIdError::Length {
                actual: KEY_ID_LEN - 1
            }
        );

        let padded = format!("{}=", key_id.as_str());
        assert_eq!(
            KeyId::parse(&padded).unwrap_err(),
            KeyIdError::Length {
                actual: KEY_ID_LEN + 1
            },
            "base64url without padding means '=' is never present"
        );
    }

    #[test]
    fn rejects_standard_base64_alphabet() {
        let mut text: Vec<char> = KeyId::from_public_key(&sample_key())
            .as_str()
            .chars()
            .collect();
        text[0] = '+';
        let with_plus: String = text.iter().collect();
        assert_eq!(
            KeyId::parse(&with_plus).unwrap_err(),
            KeyIdError::Charset {
                index: 0,
                found: '+'
            }
        );

        text[0] = '/';
        let with_slash: String = text.into_iter().collect();
        assert_eq!(
            KeyId::parse(&with_slash).unwrap_err(),
            KeyIdError::Charset {
                index: 0,
                found: '/'
            }
        );
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        let key_id = KeyId::from_public_key(&sample_key());
        let canonical_last = key_id.as_str().chars().last().unwrap();
        assert_eq!(
            base64url_value(canonical_last as u8) & 0b11,
            0,
            "a derived keyId always ends on a canonical sextet"
        );

        // Flipping the lowest padding bit yields a spelling that decodes to the
        // same 32 bytes but is not canonical. Accepting it would give one
        // digest four valid spellings and break byte-equality comparison.
        let mut text: Vec<char> = key_id.as_str().chars().collect();
        let bumped = base64url_char(base64url_value(canonical_last as u8) | 0b01);
        text[KEY_ID_LEN - 1] = bumped;
        let non_canonical: String = text.into_iter().collect();
        assert_eq!(
            KeyId::parse(&non_canonical).unwrap_err(),
            KeyIdError::NonCanonicalTrailingBits { found: bumped }
        );
    }

    fn base64url_char(value: u8) -> char {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        ALPHABET[value as usize] as char
    }
}
