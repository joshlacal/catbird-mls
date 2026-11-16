//! The one place a DID becomes a document URL.
//!
//! `did:plc` documents come only from the PLC directory and `did:web` documents only from the
//! named host's `did.json`. Nothing here ever names an account PDS, so no PDS can answer for
//! another identity. Hosts that could reach a private network (IP literals, single-label and
//! reserved names, non-default ports) and malformed paths are refused before any request exists.
//! This module has no native dependencies, so native, push and WASM builds share it.

/// Strip a `#fragment` and trailing `/` from a DID.
pub fn bare_did(raw: &str) -> &str {
    raw.split('#')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches('/')
}

/// Validated `https://` URL for `did`'s DID document.
///
/// * `did:plc:<24 base32>` → `https://plc.directory/did:plc:<id>`
/// * `did:web:<host>` → `https://<host>/.well-known/did.json`
/// * `did:web:<host>:<a>:<b>` → `https://<host>/<a>/<b>/did.json`
///
/// Rejects IPv4/IPv6 literals (including all-numeric dotted labels), single-label hosts,
/// `localhost`/`.local`/`.internal`/`.arpa`, any port other than an explicit `%3A443`, userinfo,
/// percent-encoded separators or control bytes, and dot-segments.
pub fn did_document_url(did: &str) -> Result<String, String> {
    let base = bare_did(did);
    if let Some(plc_id) = base.strip_prefix("did:plc:") {
        if plc_id.len() != 24
            || !plc_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(format!("invalid did:plc identifier: {did}"));
        }
        return Ok(format!("https://plc.directory/did:plc:{plc_id}"));
    }

    let Some(web_rest) = base.strip_prefix("did:web:") else {
        return Err(format!("unsupported DID method: {did}"));
    };
    if web_rest.is_empty() {
        return Err("empty did:web authority".into());
    }

    let mut segments = web_rest.split(':');
    let raw_host_seg = segments.next().unwrap_or("");
    let raw_host_decoded = if let Some(h) = raw_host_seg
        .strip_suffix("%3A443")
        .or_else(|| raw_host_seg.strip_suffix("%3a443"))
    {
        h
    } else if raw_host_seg.contains('%') {
        return Err(format!(
            "disallowed port or percent-encoding in did:web host: {did}"
        ));
    } else {
        raw_host_seg
    };

    if raw_host_decoded.is_empty()
        || raw_host_decoded.len() > 253
        || raw_host_decoded.contains('@')
        || raw_host_decoded.contains('/')
        || raw_host_decoded.contains('?')
        || raw_host_decoded.contains('#')
        || raw_host_decoded.starts_with('[')
        || raw_host_decoded.ends_with(']')
        || raw_host_decoded.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(format!("disallowed did:web host: {did}"));
    }

    let host_lower = raw_host_decoded.to_ascii_lowercase();
    let labels: Vec<&str> = host_lower.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("single-label did:web host rejected: {did}"));
    }
    if matches!(
        labels.last().copied(),
        Some("localhost" | "local" | "internal" | "arpa" | "home" | "lan" | "intranet")
    ) || labels.first().copied() == Some("localhost")
    {
        return Err(format!("local or reserved did:web host rejected: {did}"));
    }
    if labels
        .iter()
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("numeric did:web host rejected: {did}"));
    }
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("numeric did:web top-level label rejected: {did}"));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("invalid DNS label in did:web host: {did}"));
        }
    }

    let mut path_parts: Vec<String> = Vec::new();
    for seg in segments {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.contains('/')
            || seg.contains('\\')
            || seg.contains('?')
            || seg.contains('#')
        {
            return Err(format!("invalid path segment in did:web: {did}"));
        }
        let bytes = seg.as_bytes();
        let mut i = 0;
        let mut decoded_ascii = String::with_capacity(bytes.len());
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%' {
                if i + 2 >= bytes.len() {
                    return Err(format!("truncated percent-escape in did:web path: {did}"));
                }
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                let (Some(h), Some(l)) = (hi, lo) else {
                    return Err(format!("invalid percent-escape in did:web path: {did}"));
                };
                let val = ((h << 4) | l) as u8;
                if matches!(val, 0x00..=0x1F | 0x7F | b'/' | b'\\' | b'?' | b'#' | b'%') {
                    return Err(format!(
                        "encoded control or separator byte in did:web path: {did}"
                    ));
                }
                decoded_ascii.push(val as char);
                i += 3;
            } else if matches!(
                b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
            ) {
                decoded_ascii.push(b as char);
                i += 1;
            } else {
                return Err(format!("disallowed character in did:web path: {did}"));
            }
        }
        if decoded_ascii == "." || decoded_ascii == ".." {
            return Err(format!("encoded dot-segment in did:web path: {did}"));
        }
        path_parts.push(seg.to_owned());
    }

    if path_parts.is_empty() {
        Ok(format!("https://{host_lower}/.well-known/did.json"))
    } else {
        Ok(format!(
            "https://{host_lower}/{}/did.json",
            path_parts.join("/")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plc_resolves_only_from_the_plc_directory() {
        assert_eq!(
            did_document_url("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap(),
            "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur"
        );
        assert_eq!(
            did_document_url("did:plc:z72i7hdynmk6r22z27h6tvur#atproto").unwrap(),
            "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur"
        );
        for bad in [
            "did:plc:",
            "did:plc:short",
            "did:plc:Z72I7HDYNMK6R22Z27H6TVUR",
            "did:plc:z72i7hdynmk6r22z27h6tvu1",
            "did:plc:z72i7hdynmk6r22z27h6tvurz",
            "did:plc:z72i7hdynmk6r22z27h6t/ur",
        ] {
            assert!(did_document_url(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn web_maps_host_and_path_forms_to_https_did_json() {
        assert_eq!(
            did_document_url("did:web:mlschat.catbird.blue").unwrap(),
            "https://mlschat.catbird.blue/.well-known/did.json"
        );
        assert_eq!(
            did_document_url("did:web:Example.COM%3A443").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_document_url("did:web:example.com:user:alice").unwrap(),
            "https://example.com/user/alice/did.json"
        );
    }

    #[test]
    fn web_refuses_hosts_that_can_reach_private_networks() {
        for bad in [
            "did:web:localhost",
            "did:web:localhost%3A3001",
            "did:web:localhost.example",
            "did:web:127.0.0.1",
            "did:web:10.0.0.7",
            "did:web:169.254.169.254",
            "did:web:192.168.1.1",
            "did:web:%5B%3A%3A1%5D",
            "did:web:[::1]",
            "did:web:printer",
            "did:web:router.local",
            "did:web:db.internal",
            "did:web:1.1.1.1.in-addr.arpa",
            "did:web:nas.lan",
            "did:web:nas.home",
            "did:web:0x7f.1",
            "did:web:example.com%3A8080",
            "did:web:example.com%3A80",
            "did:web:user@example.com",
            "did:web:example.com:..",
            "did:web:example.com:%2e%2e",
            "did:web:example.com:a%2fb",
            "did:web:example.com:a%00b",
            "did:web:example.com:",
            "did:web:",
            "did:key:z6Mkexample",
            "https://example.com",
        ] {
            assert!(did_document_url(bad).is_err(), "{bad} must be refused");
        }
    }
}
