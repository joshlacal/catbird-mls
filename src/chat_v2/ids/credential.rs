//! MLS BasicCredential identity for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §2: the MLS BasicCredential identity is exactly UTF-8
//! `actorDid + "#" + deviceId` and is therefore exactly 49–298 bytes. The
//! bounds are derived, not independent: a bare DID is 12–261 bytes, the
//! separator is 1, and a canonical UUID device ID is 36.
//!
//! After decryption every client must require the authenticated MLS sender
//! leaf's credential to equal the verified signed outer actor DID and device.
//! [`BasicCredential::parse`] exists so that comparison operates on a
//! structurally validated pair rather than on raw bytes.

use super::did::{BareDid, DidError, BARE_DID_MAX_LEN, BARE_DID_MIN_LEN};
use super::uuid::{DeviceId, UuidError, CANONICAL_UUID_LEN};
use core::fmt;

/// Minimum BasicCredential length, derived as `12 + 1 + 36`.
pub const BASIC_CREDENTIAL_MIN_LEN: usize = BARE_DID_MIN_LEN + 1 + CANONICAL_UUID_LEN;
/// Maximum BasicCredential length, derived as `261 + 1 + 36`.
pub const BASIC_CREDENTIAL_MAX_LEN: usize = BARE_DID_MAX_LEN + 1 + CANONICAL_UUID_LEN;

/// Why a byte string was not a valid BasicCredential identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// Outside the derived 49–298 byte bound.
    Length { actual: usize },
    /// Not valid UTF-8.
    NotUtf8,
    /// No `#` separator, so the DID and device cannot be split.
    MissingSeparator,
    /// More than one `#`. A bare DID carries no fragment, so a second `#`
    /// means the identity is ambiguous.
    MultipleSeparators { count: usize },
    /// The DID half failed the bare-DID grammar.
    Did(DidError),
    /// The device half failed the canonical UUID grammar.
    Device(UuidError),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                f,
                "BasicCredential must be {BASIC_CREDENTIAL_MIN_LEN}-{BASIC_CREDENTIAL_MAX_LEN} bytes, found {actual}"
            ),
            Self::NotUtf8 => f.write_str("BasicCredential is not valid UTF-8"),
            Self::MissingSeparator => f.write_str("BasicCredential is missing its '#' separator"),
            Self::MultipleSeparators { count } => {
                write!(f, "BasicCredential has {count} '#' separators; exactly one is allowed")
            }
            Self::Did(err) => write!(f, "BasicCredential DID: {err}"),
            Self::Device(err) => write!(f, "BasicCredential device: {err}"),
        }
    }
}

impl core::error::Error for CredentialError {}

/// A validated MLS BasicCredential identity.
///
/// Equality is over the parsed pair, so two credentials compare equal exactly
/// when they name the same DID and the same device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicCredential {
    did: BareDid,
    device_id: DeviceId,
}

impl BasicCredential {
    /// Builds a credential from an already-validated DID and device.
    ///
    /// The derived bounds cannot be violated by construction, since the two
    /// components carry their own bounds.
    pub fn new(did: BareDid, device_id: DeviceId) -> Self {
        Self { did, device_id }
    }

    /// Parses the exact UTF-8 identity bytes carried by an MLS leaf.
    pub fn parse(identity: &[u8]) -> Result<Self, CredentialError> {
        if identity.len() < BASIC_CREDENTIAL_MIN_LEN || identity.len() > BASIC_CREDENTIAL_MAX_LEN {
            return Err(CredentialError::Length {
                actual: identity.len(),
            });
        }
        let text = core::str::from_utf8(identity).map_err(|_| CredentialError::NotUtf8)?;

        let separators = text.matches('#').count();
        match separators {
            0 => return Err(CredentialError::MissingSeparator),
            1 => {}
            count => return Err(CredentialError::MultipleSeparators { count }),
        }

        // Exactly one separator, so the split is unambiguous.
        let (did_text, device_text) = text.split_once('#').expect("one separator counted above");
        let did = BareDid::parse(did_text).map_err(CredentialError::Did)?;
        let device_id = DeviceId::parse(device_text).map_err(CredentialError::Device)?;
        Ok(Self { did, device_id })
    }

    /// The DID half.
    pub fn did(&self) -> &BareDid {
        &self.did
    }

    /// The device half. Application visibility is per exact `(DID, deviceId)`,
    /// so a sibling device of the same DID is a different credential.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The exact UTF-8 identity bytes to place in an MLS leaf.
    pub fn to_identity_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

impl fmt::Display for BasicCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.did, self.device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLC: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";

    fn credential_text() -> String {
        format!("{PLC}#{DEVICE}")
    }

    #[test]
    fn round_trips_through_identity_bytes() {
        let text = credential_text();
        let parsed = BasicCredential::parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.did().as_str(), PLC);
        assert_eq!(parsed.device_id().to_string(), DEVICE);
        assert_eq!(parsed.to_identity_bytes(), text.as_bytes());
    }

    #[test]
    fn derived_bounds_match_the_frozen_constants() {
        assert_eq!(BASIC_CREDENTIAL_MIN_LEN, 49);
        assert_eq!(BASIC_CREDENTIAL_MAX_LEN, 298);
    }

    #[test]
    fn accepts_the_49_byte_minimum() {
        // The shortest legal DID is 12 bytes, so 12 + 1 + 36 = 49.
        let text = format!("did:web:a.bc#{DEVICE}");
        assert_eq!(text.len(), BASIC_CREDENTIAL_MIN_LEN);
        let parsed = BasicCredential::parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.did().as_str(), "did:web:a.bc");
    }

    #[test]
    fn rejects_one_byte_below_the_minimum() {
        // "did:web:a.b" is 11 bytes, giving a 48-byte credential.
        let text = format!("did:web:a.b#{DEVICE}");
        assert_eq!(text.len(), BASIC_CREDENTIAL_MIN_LEN - 1);
        assert_eq!(
            BasicCredential::parse(text.as_bytes()).unwrap_err(),
            CredentialError::Length {
                actual: BASIC_CREDENTIAL_MIN_LEN - 1
            }
        );
    }

    #[test]
    fn accepts_the_298_byte_maximum() {
        let label = "a".repeat(63);
        let mut hostname = format!("{label}.{label}.{label}");
        let remaining = 253 - hostname.len() - 1;
        hostname.push('.');
        hostname.push_str(&"z".repeat(remaining));
        let text = format!("did:web:{hostname}#{DEVICE}");
        assert_eq!(text.len(), BASIC_CREDENTIAL_MAX_LEN);
        assert!(BasicCredential::parse(text.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_one_byte_above_the_maximum() {
        let label = "a".repeat(63);
        let mut hostname = format!("{label}.{label}.{label}");
        let remaining = 253 - hostname.len() - 1;
        hostname.push('.');
        hostname.push_str(&"z".repeat(remaining));
        let text = format!("did:web:{hostname}z#{DEVICE}");
        assert_eq!(text.len(), BASIC_CREDENTIAL_MAX_LEN + 1);
        assert_eq!(
            BasicCredential::parse(text.as_bytes()).unwrap_err(),
            CredentialError::Length {
                actual: BASIC_CREDENTIAL_MAX_LEN + 1
            }
        );
    }

    #[test]
    fn rejects_a_missing_separator() {
        // Pad to a legal length so the separator check is what fires.
        let text = format!("{PLC}{DEVICE}00000000000000000");
        assert!(text.len() >= BASIC_CREDENTIAL_MIN_LEN);
        assert_eq!(
            BasicCredential::parse(text.as_bytes()).unwrap_err(),
            CredentialError::MissingSeparator
        );
    }

    #[test]
    fn rejects_multiple_separators() {
        let text = format!("{PLC}#{DEVICE}#extra");
        assert_eq!(
            BasicCredential::parse(text.as_bytes()).unwrap_err(),
            CredentialError::MultipleSeparators { count: 2 }
        );
    }

    #[test]
    fn rejects_a_malformed_half() {
        let bad_did = format!("did:plc:NOTBASE32NOTBASE32NOTBA#{DEVICE}");
        assert!(matches!(
            BasicCredential::parse(bad_did.as_bytes()).unwrap_err(),
            CredentialError::Did(_)
        ));

        let bad_device = format!("{PLC}#{}", DEVICE.to_uppercase());
        assert!(matches!(
            BasicCredential::parse(bad_device.as_bytes()).unwrap_err(),
            CredentialError::Device(_)
        ));
    }

    #[test]
    fn rejects_non_utf8() {
        let mut bytes = credential_text().into_bytes();
        bytes[0] = 0xff;
        assert_eq!(
            BasicCredential::parse(&bytes).unwrap_err(),
            CredentialError::NotUtf8
        );
    }

    #[test]
    fn sibling_devices_are_distinct_credentials() {
        // Application visibility is per exact (DID, deviceId), never
        // DID-aggregate, so two devices of one DID must never compare equal.
        let first = BasicCredential::parse(credential_text().as_bytes()).unwrap();
        let sibling_text = format!("{PLC}#72727272-7272-4272-b272-727272727272");
        let sibling = BasicCredential::parse(sibling_text.as_bytes()).unwrap();
        assert_eq!(first.did(), sibling.did());
        assert_ne!(
            first, sibling,
            "a same-DID sibling device must not satisfy an exact-device check"
        );
    }
}
