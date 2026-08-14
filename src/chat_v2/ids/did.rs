//! Bare ATProto DID identity for the clean chat protocol.
//!
//! CHAT_PROTOCOL.md §2 freezes a deliberately narrower grammar than a generic
//! DID parser: exactly 12–261 ASCII bytes, no DID URL query or fragment, and
//! either `did:plc:[a-z2-7]{24}` or hostname-level `did:web:` followed by a
//! normalized lowercase handle-shaped hostname. It applies the official ATProto
//! DID hostname-only rule and handle syntax *without* their local-development
//! exceptions, so production additionally rejects the reserved TLDs.
//!
//! The same hostname grammar is reused by the restricted AT-URI authority, so
//! [`validate_handle_hostname`] is public.

use core::fmt;

/// Minimum bare DID length in ASCII bytes, per CHAT_PROTOCOL.md §2.
pub const BARE_DID_MIN_LEN: usize = 12;
/// Maximum bare DID length in ASCII bytes, per CHAT_PROTOCOL.md §2.
pub const BARE_DID_MAX_LEN: usize = 261;
/// Maximum hostname length for a `did:web` authority or a handle.
pub const HOSTNAME_MAX_LEN: usize = 253;
/// Maximum length of a single dot-separated hostname label.
pub const LABEL_MAX_LEN: usize = 63;

const DID_PLC_PREFIX: &str = "did:plc:";
const DID_WEB_PREFIX: &str = "did:web:";
/// Length of the method-specific identifier of a `did:plc`.
const PLC_IDENT_LEN: usize = 24;

/// TLDs that production rejects, per CHAT_PROTOCOL.md §2.
///
/// `.invalid` is in this list, which is what rejects the ATProto sentinel
/// `handle.invalid`.
pub const RESERVED_TLDS: [&str; 9] = [
    "alt",
    "arpa",
    "example",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
    "test",
];

/// Why a string was not a valid production bare DID or handle-shaped hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidError {
    /// Outside the 12–261 byte bound.
    Length { actual: usize },
    /// Contained a byte outside printable ASCII.
    NonAscii { index: usize },
    /// Carried a DID URL query or fragment.
    DidUrlComponent { found: char },
    /// Used a DID method other than `plc` or `web`.
    UnsupportedMethod,
    /// A `did:plc` identifier was not exactly 24 base32 `[a-z2-7]` characters.
    MalformedPlcIdentifier,
    /// A percent sign appeared. No escape is permitted anywhere.
    PercentEncoding { index: usize },
    /// A colon appeared inside a `did:web` authority, i.e. a path DID or a port.
    HostnameHasColon,
    /// The hostname was outside 1–253 bytes.
    HostnameLength { actual: usize },
    /// The hostname had fewer than two dot-separated labels.
    SingleLabelHostname,
    /// The hostname ended in a dot.
    TrailingDot,
    /// A label was empty or longer than 63 bytes.
    LabelLength { label: String, actual: usize },
    /// A label contained something outside lowercase `[a-z0-9-]`.
    LabelCharset { label: String },
    /// A label began or ended with a hyphen.
    LabelHyphenBoundary { label: String },
    /// The final label did not begin with a letter, i.e. an IP-address shape.
    TldNotAlphabetic { tld: String },
    /// The final label is reserved in production.
    ReservedTld { tld: String },
}

impl fmt::Display for DidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                f,
                "bare DID must be {BARE_DID_MIN_LEN}-{BARE_DID_MAX_LEN} bytes, found {actual}"
            ),
            Self::NonAscii { index } => write!(f, "non-ASCII byte at {index}"),
            Self::DidUrlComponent { found } => {
                write!(f, "bare DID must not carry a DID URL '{found}' component")
            }
            Self::UnsupportedMethod => f.write_str("only did:plc and did:web are supported"),
            Self::MalformedPlcIdentifier => {
                write!(
                    f,
                    "did:plc identifier must be {PLC_IDENT_LEN} chars of [a-z2-7]"
                )
            }
            Self::PercentEncoding { index } => {
                write!(f, "percent sign at {index} is never allowed")
            }
            Self::HostnameHasColon => {
                f.write_str("did:web authority must be hostname-level: no port and no path")
            }
            Self::HostnameLength { actual } => {
                write!(
                    f,
                    "hostname must be 1-{HOSTNAME_MAX_LEN} bytes, found {actual}"
                )
            }
            Self::SingleLabelHostname => {
                f.write_str("hostname needs at least two dot-separated labels")
            }
            Self::TrailingDot => f.write_str("hostname must not end in a dot"),
            Self::LabelLength { label, actual } => {
                write!(
                    f,
                    "label {label:?} must be 1-{LABEL_MAX_LEN} bytes, found {actual}"
                )
            }
            Self::LabelCharset { label } => {
                write!(f, "label {label:?} must be lowercase [a-z0-9-]")
            }
            Self::LabelHyphenBoundary { label } => {
                write!(f, "label {label:?} must start and end alphanumeric")
            }
            Self::TldNotAlphabetic { tld } => {
                write!(f, "final label {tld:?} must begin with a letter")
            }
            Self::ReservedTld { tld } => write!(f, "TLD {tld:?} is reserved in production"),
        }
    }
}

impl core::error::Error for DidError {}

/// Which DID method a validated [`BareDid`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DidMethod {
    /// `did:plc:<24 base32 chars>`.
    Plc,
    /// `did:web:<handle-shaped hostname>`.
    Web,
}

/// A production canonical bare ATProto DID.
///
/// These exact bytes are what the access token subject, the signed projection,
/// the ordering comparator, and the MLS BasicCredential identity all use, so
/// the value stores the original string rather than a decomposed form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BareDid {
    text: String,
}

impl BareDid {
    /// Validates and adopts a bare DID. Inputs are rejected, never normalized.
    pub fn parse(input: &str) -> Result<Self, DidError> {
        let bytes = input.as_bytes();
        if bytes.len() < BARE_DID_MIN_LEN || bytes.len() > BARE_DID_MAX_LEN {
            return Err(DidError::Length {
                actual: bytes.len(),
            });
        }
        for (index, byte) in bytes.iter().enumerate() {
            if !byte.is_ascii() {
                return Err(DidError::NonAscii { index });
            }
            match byte {
                b'?' | b'#' => {
                    return Err(DidError::DidUrlComponent {
                        found: *byte as char,
                    })
                }
                b'%' => return Err(DidError::PercentEncoding { index }),
                _ => {}
            }
        }

        if let Some(identifier) = input.strip_prefix(DID_PLC_PREFIX) {
            if identifier.len() != PLC_IDENT_LEN
                || !identifier
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
            {
                return Err(DidError::MalformedPlcIdentifier);
            }
            return Ok(Self {
                text: input.to_owned(),
            });
        }

        if let Some(hostname) = input.strip_prefix(DID_WEB_PREFIX) {
            // A `did:web` whose method-specific id contains a colon is either a
            // path DID (`did:web:host:path`) or carries a port. Both are
            // rejected before the hostname grammar runs, so the error names the
            // real cause instead of a confusing label-charset failure.
            if hostname.contains(':') {
                return Err(DidError::HostnameHasColon);
            }
            validate_handle_hostname(hostname)?;
            return Ok(Self {
                text: input.to_owned(),
            });
        }

        Err(DidError::UnsupportedMethod)
    }

    /// The exact DID bytes, as used by the signing projection and MLS credential.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Which method this DID uses.
    pub fn method(&self) -> DidMethod {
        if self.text.starts_with(DID_PLC_PREFIX) {
            DidMethod::Plc
        } else {
            DidMethod::Web
        }
    }
}

impl fmt::Display for BareDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Validates the normalized lowercase production handle-shaped hostname shared
/// by `did:web` authorities, AT-URI handle authorities, and AT-URI `did:web`
/// authorities.
///
/// Rejects ports, paths, percent escapes, IP literals, single-label names
/// including `localhost`, trailing dots, uppercase, and reserved TLDs.
pub fn validate_handle_hostname(hostname: &str) -> Result<(), DidError> {
    let len = hostname.len();
    if len == 0 || len > HOSTNAME_MAX_LEN {
        return Err(DidError::HostnameLength { actual: len });
    }
    if hostname.contains(':') {
        return Err(DidError::HostnameHasColon);
    }
    if let Some(index) = hostname.find('%') {
        return Err(DidError::PercentEncoding { index });
    }
    if hostname.ends_with('.') {
        return Err(DidError::TrailingDot);
    }

    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 {
        return Err(DidError::SingleLabelHostname);
    }

    for label in &labels {
        let label_len = label.len();
        if label_len == 0 || label_len > LABEL_MAX_LEN {
            return Err(DidError::LabelLength {
                label: (*label).to_owned(),
                actual: label_len,
            });
        }
        if !label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        {
            return Err(DidError::LabelCharset {
                label: (*label).to_owned(),
            });
        }
        // Endpoints must be alphanumeric; the charset check above already
        // excluded everything except a hyphen at a boundary.
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DidError::LabelHyphenBoundary {
                label: (*label).to_owned(),
            });
        }
    }

    // `labels` has at least two entries, so the final label exists.
    let tld = labels[labels.len() - 1];
    if !tld.starts_with(|c: char| c.is_ascii_lowercase()) {
        // This is also what rejects a dotted-quad IPv4 literal, whose final
        // label is numeric.
        return Err(DidError::TldNotAlphabetic {
            tld: tld.to_owned(),
        });
    }
    if RESERVED_TLDS.contains(&tld) {
        return Err(DidError::ReservedTld {
            tld: tld.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLC: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";

    #[test]
    fn accepts_did_plc() {
        let did = BareDid::parse(PLC).expect("canonical did:plc must parse");
        assert_eq!(did.method(), DidMethod::Plc);
        assert_eq!(did.as_str(), PLC);
        assert_eq!(PLC.len(), 32, "did:plc is always 32 bytes");
    }

    #[test]
    fn accepts_lowercase_did_web_hostname() {
        // Named positive from the master plan's parity vectors.
        let did = BareDid::parse("did:web:alice.example.net").unwrap();
        assert_eq!(did.method(), DidMethod::Web);
    }

    #[test]
    fn rejects_uppercase_plc_method_specific_id() {
        // Named negative: atRecordDidPlcUppercaseMethodSpecificRejected.
        let upper = "did:plc:Z72I7HDYNMK6R22Z27H6TVUR";
        assert_eq!(
            BareDid::parse(upper).unwrap_err(),
            DidError::MalformedPlcIdentifier
        );
    }

    #[test]
    fn rejects_plc_identifier_outside_base32_alphabet() {
        // '1', '8', '9' and '0' are not in [a-z2-7].
        for bad in ['0', '1', '8', '9'] {
            let mut ident: Vec<char> = "z72i7hdynmk6r22z27h6tvur".chars().collect();
            ident[0] = bad;
            let text = format!("did:plc:{}", ident.into_iter().collect::<String>());
            assert_eq!(
                BareDid::parse(&text).unwrap_err(),
                DidError::MalformedPlcIdentifier,
                "'{bad}' is outside the base32 alphabet"
            );
        }
    }

    #[test]
    fn rejects_plc_identifier_of_wrong_length() {
        assert_eq!(
            BareDid::parse("did:plc:z72i7hdynmk6r22z27h6tvu").unwrap_err(),
            DidError::MalformedPlcIdentifier
        );
        assert_eq!(
            BareDid::parse("did:plc:z72i7hdynmk6r22z27h6tvurx").unwrap_err(),
            DidError::MalformedPlcIdentifier
        );
    }

    #[test]
    fn rejects_uppercase_did_web_host() {
        // Named negative: atRecordDidWebUppercaseHostRejected.
        assert!(matches!(
            BareDid::parse("did:web:Alice.Example.Net").unwrap_err(),
            DidError::LabelCharset { .. }
        ));
    }

    #[test]
    fn rejects_did_web_path() {
        // Named negative: atRecordDidWebPathRejected.
        assert_eq!(
            BareDid::parse("did:web:alice.example.net:users:alice").unwrap_err(),
            DidError::HostnameHasColon
        );
    }

    #[test]
    fn rejects_did_web_port() {
        // Named negative: atRecordDidWebPortRejected. A percent-escaped colon
        // is caught by the no-escape rule at the '%' offset, not by the
        // hostname grammar, so the port never reaches label validation.
        assert_eq!(
            BareDid::parse("did:web:alice.example.net%3A8443").unwrap_err(),
            DidError::PercentEncoding { index: 25 }
        );
        assert_eq!(
            BareDid::parse("did:web:alice.example.net:8443").unwrap_err(),
            DidError::HostnameHasColon
        );
    }

    #[test]
    fn rejects_did_web_percent_escape() {
        // Named negative: atRecordDidWebPercentRejected.
        assert!(matches!(
            BareDid::parse("did:web:alice%2eexample.net").unwrap_err(),
            DidError::PercentEncoding { .. }
        ));
    }

    #[test]
    fn rejects_did_web_ip_literal() {
        // Named negative: atRecordDidWebIpRejected. The final label is numeric,
        // so the TLD-must-begin-with-a-letter rule is what rejects it.
        assert_eq!(
            BareDid::parse("did:web:192.168.1.1").unwrap_err(),
            DidError::TldNotAlphabetic {
                tld: "1".to_owned()
            }
        );
    }

    #[test]
    fn rejects_did_web_single_label() {
        // Named negative: atRecordDidWebSingleLabelRejected.
        assert_eq!(
            BareDid::parse("did:web:examplehost").unwrap_err(),
            DidError::SingleLabelHostname
        );
    }

    #[test]
    fn rejects_did_web_localhost() {
        // Named negative: atRecordDidWebLocalhostRejected. Bare `localhost` is a
        // single label; `x.localhost` is caught by the reserved TLD list.
        assert_eq!(
            BareDid::parse("did:web:localhost").unwrap_err(),
            DidError::SingleLabelHostname
        );
        assert_eq!(
            BareDid::parse("did:web:api.localhost").unwrap_err(),
            DidError::ReservedTld {
                tld: "localhost".to_owned()
            }
        );
    }

    #[test]
    fn rejects_every_production_reserved_tld() {
        // Named negative: atRecordReservedTldRejected, covering all nine.
        for tld in RESERVED_TLDS {
            let text = format!("did:web:alice.{tld}");
            assert_eq!(
                BareDid::parse(&text).unwrap_err(),
                DidError::ReservedTld {
                    tld: tld.to_owned()
                },
                "TLD .{tld} must be rejected in production"
            );
        }
    }

    #[test]
    fn rejects_handle_invalid_sentinel() {
        // Named negative: atRecordHandleInvalidRejected.
        assert_eq!(
            BareDid::parse("did:web:handle.invalid").unwrap_err(),
            DidError::ReservedTld {
                tld: "invalid".to_owned()
            }
        );
    }

    #[test]
    fn rejects_trailing_dot() {
        assert_eq!(
            BareDid::parse("did:web:alice.example.net.").unwrap_err(),
            DidError::TrailingDot
        );
    }

    #[test]
    fn rejects_hyphen_at_label_boundary() {
        assert!(matches!(
            BareDid::parse("did:web:-alice.example.net").unwrap_err(),
            DidError::LabelHyphenBoundary { .. }
        ));
        assert!(matches!(
            BareDid::parse("did:web:alice-.example.net").unwrap_err(),
            DidError::LabelHyphenBoundary { .. }
        ));
    }

    #[test]
    fn rejects_did_url_query_and_fragment() {
        assert_eq!(
            BareDid::parse("did:web:alice.example.net?x=1").unwrap_err(),
            DidError::DidUrlComponent { found: '?' }
        );
        assert_eq!(
            BareDid::parse("did:web:alice.example.net#atproto_pds").unwrap_err(),
            DidError::DidUrlComponent { found: '#' }
        );
    }

    #[test]
    fn rejects_unsupported_methods() {
        assert_eq!(
            BareDid::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2Q").unwrap_err(),
            DidError::UnsupportedMethod
        );
    }

    #[test]
    fn enforces_the_261_byte_ceiling() {
        // The longest DID that fits: "did:web:" plus a 253-byte hostname is 261.
        let label = "a".repeat(LABEL_MAX_LEN);
        // 3 * 63 + 2 dots = 191, then a final label sized to reach exactly 253.
        let mut hostname = format!("{label}.{label}.{label}");
        let remaining = HOSTNAME_MAX_LEN - hostname.len() - 1;
        hostname.push('.');
        hostname.push_str(&"z".repeat(remaining));
        assert_eq!(hostname.len(), HOSTNAME_MAX_LEN);

        let at_max = format!("did:web:{hostname}");
        assert_eq!(at_max.len(), BARE_DID_MAX_LEN);
        assert!(
            BareDid::parse(&at_max).is_ok(),
            "exactly {BARE_DID_MAX_LEN} bytes must be accepted"
        );

        let over_max = format!("{at_max}z");
        assert_eq!(
            BareDid::parse(&over_max).unwrap_err(),
            DidError::Length {
                actual: BARE_DID_MAX_LEN + 1
            },
            "one byte over must be rejected"
        );
    }

    #[test]
    fn enforces_the_12_byte_floor() {
        // "did:web:a.bc" is exactly 12 bytes and satisfies both the length bound
        // and the hostname grammar.
        let at_min = "did:web:a.bc";
        assert_eq!(at_min.len(), BARE_DID_MIN_LEN);
        assert!(BareDid::parse(at_min).is_ok());

        // "did:web:a.b" is 11 bytes. It satisfies the hostname grammar but
        // fails the jointly-normative length bound, so the length predicate is
        // what rejects the shortest grammatically-legal did:web. Flagged to
        // Josh as an open reading of CHAT_PROTOCOL.md §2.
        let under_min = "did:web:a.b";
        assert_eq!(under_min.len(), BARE_DID_MIN_LEN - 1);
        assert!(
            validate_handle_hostname("a.b").is_ok(),
            "the hostname alone is grammatically valid"
        );
        assert_eq!(
            BareDid::parse(under_min).unwrap_err(),
            DidError::Length {
                actual: BARE_DID_MIN_LEN - 1
            },
            "the length bound is what rejects it"
        );
    }

    #[test]
    fn hostname_validator_accepts_bare_handles() {
        // Named positive: atRecordHandleLowercaseHostnameAccepted.
        assert!(validate_handle_hostname("alice.example.net").is_ok());
    }

    #[test]
    fn hostname_validator_rejects_oversized_label() {
        let long = "a".repeat(LABEL_MAX_LEN + 1);
        let hostname = format!("{long}.net");
        assert!(matches!(
            validate_handle_hostname(&hostname).unwrap_err(),
            DidError::LabelLength { .. }
        ));
    }

    #[test]
    fn hostname_validator_rejects_empty_label() {
        assert!(matches!(
            validate_handle_hostname("alice..net").unwrap_err(),
            DidError::LabelLength { actual: 0, .. }
        ));
    }
}
