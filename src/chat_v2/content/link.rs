//! External link predicates.
//!
//! §8: external links "retain their separate 2,048-byte cap and require an
//! absolute HTTPS URI with nonempty host, no userinfo, backslash,
//! whitespace/control character, invalid port, or invalid percent encoding;
//! title/description are optional."
//!
//! # Unlike the AT URI, percent encoding is permitted here — but must be valid
//!
//! These two grammars sit next to each other and differ on exactly this point,
//! which is worth stating so nobody "harmonizes" them. A restricted AT URI
//! refuses percent signs outright because it must have one spelling per record.
//! An external link is a real web URL where percent encoding is ordinary, so it
//! is permitted and *checked*: `%` must be followed by two hex digits.
//! A malformed escape is refused rather than passed through, because what a
//! renderer does with a truncated escape is not something this layer should be
//! guessing about.
//!
//! # Why userinfo and backslashes are refused
//!
//! Both are display-spoofing tools. `https://trusted.example@evil.example/`
//! reads as the trusted host to a person and resolves to the attacker's, and
//! backslashes are normalized to forward slashes by some URL parsers and not
//! others — so a link can point at two different places depending on the
//! client. Refusing both is cheaper than reasoning about every renderer.

use core::fmt;

/// The external-link byte cap, separate from the AT URI's.
pub const EXTERNAL_LINK_MAX_BYTES: usize = 2_048;

/// The only permitted scheme, lowercase and exact.
pub const HTTPS_SCHEME: &str = "https://";

/// Why an external link was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// Empty or beyond the 2,048-byte cap.
    Length { actual: usize },
    /// Not an absolute lowercase `https://` URI.
    ///
    /// Absolute and HTTPS: a relative link has no meaning in a message, and
    /// `http://` would silently downgrade the transport.
    NotAbsoluteHttps,
    /// The host was empty.
    EmptyHost,
    /// The authority carried userinfo before an `@`.
    Userinfo,
    /// A backslash appeared anywhere.
    Backslash { index: usize },
    /// Whitespace or a control character appeared anywhere.
    WhitespaceOrControl { index: usize },
    /// A port was empty, non-numeric, or out of range.
    InvalidPort,
    /// A percent escape was not followed by two hex digits.
    InvalidPercentEncoding { index: usize },
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                f,
                "external link is {actual} bytes, at most {EXTERNAL_LINK_MAX_BYTES} allowed"
            ),
            Self::NotAbsoluteHttps => {
                write!(f, "external link must begin with exactly {HTTPS_SCHEME:?}")
            }
            Self::EmptyHost => f.write_str("external link host is empty"),
            Self::Userinfo => {
                f.write_str("external link carries userinfo, which can spoof the host")
            }
            Self::Backslash { index } => {
                write!(f, "external link has a backslash at byte {index}")
            }
            Self::WhitespaceOrControl { index } => write!(
                f,
                "external link has whitespace or a control character at byte {index}"
            ),
            Self::InvalidPort => f.write_str("external link port is empty or out of range"),
            Self::InvalidPercentEncoding { index } => write!(
                f,
                "external link has a malformed percent escape at byte {index}"
            ),
        }
    }
}

impl core::error::Error for LinkError {}

/// Validates an external link URI.
pub fn require_external_link(value: &str) -> Result<(), LinkError> {
    let len = value.len();
    if len == 0 || len > EXTERNAL_LINK_MAX_BYTES {
        return Err(LinkError::Length { actual: len });
    }

    for (index, ch) in value.char_indices() {
        if ch == '\\' {
            return Err(LinkError::Backslash { index });
        }
        if ch.is_whitespace() || ch.is_control() {
            return Err(LinkError::WhitespaceOrControl { index });
        }
    }
    require_valid_percent_encoding(value)?;

    let rest = value
        .strip_prefix(HTTPS_SCHEME)
        .ok_or(LinkError::NotAbsoluteHttps)?;

    // The authority runs to the first path, query, or fragment delimiter.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(LinkError::EmptyHost);
    }
    if authority.contains('@') {
        return Err(LinkError::Userinfo);
    }

    // A port, if present, is the part after the last colon — but a bare IPv6
    // literal also contains colons, so only split outside brackets.
    if let Some(host_end) = authority.rfind(']') {
        // IPv6 literal: a port may follow the closing bracket.
        let after = &authority[host_end + 1..];
        if let Some(port) = after.strip_prefix(':') {
            require_valid_port(port)?;
        } else if !after.is_empty() {
            return Err(LinkError::InvalidPort);
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(LinkError::EmptyHost);
        }
        require_valid_port(port)?;
    }

    Ok(())
}

/// A port is one to five digits naming a value within `1..=65535`.
fn require_valid_port(port: &str) -> Result<(), LinkError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LinkError::InvalidPort);
    }
    match port.parse::<u32>() {
        Ok(value) if (1..=65_535).contains(&value) => Ok(()),
        _ => Err(LinkError::InvalidPort),
    }
}

/// Every `%` must introduce two hex digits.
///
/// Checked rather than decoded. This layer decides whether the link is
/// well-formed; what it points at is somebody else's question.
fn require_valid_percent_encoding(value: &str) -> Result<(), LinkError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3);
            let valid = hex.is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit));
            if !valid {
                return Err(LinkError::InvalidPercentEncoding { index });
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}
