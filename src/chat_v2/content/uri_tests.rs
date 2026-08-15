//! AT URI and external link tests.
//!
//! The AT URI cases lean on the spec's own warning that "parser acceptance or
//! round-trip alone is not canonicality proof": several of the negatives below
//! are strings a general URI parser accepts and round-trips happily, and which
//! must still be refused because they are a *second spelling* of a record that
//! already has one.

use super::at_uri::*;
use super::link::*;
use crate::chat_v2::ids::{BARE_DID_MAX_LEN, RESERVED_TLDS};

const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
const COLLECTION: &str = "app.bsky.feed.post";
const RKEY: &str = "3jui7kd54zh2y";

fn uri(authority: &str, collection: &str, rkey: &str) -> String {
    format!("at://{authority}/{collection}/{rkey}")
}

fn canonical() -> String {
    uri(DID, COLLECTION, RKEY)
}

// ---- the derived cap --------------------------------------------------------

#[test]
fn the_length_cap_is_derived_from_its_parts() {
    // 5 + 261 + 1 + 317 + 1 + 512. Derived rather than restated, so the parts
    // and the whole cannot disagree.
    assert_eq!(AT_URI_MAX_LEN, 1_097);
    assert_eq!(
        AT_URI_MAX_LEN,
        SCHEME.len() + BARE_DID_MAX_LEN + 1 + NSID_MAX_LEN + 1 + RKEY_MAX_LEN
    );
    assert_eq!(SCHEME.len(), 5);
    assert_eq!(BARE_DID_MAX_LEN, 261);
    assert_eq!(NSID_MAX_LEN, 317);
    assert_eq!(RKEY_MAX_LEN, 512);
}

#[test]
fn an_over_long_uri_is_refused() {
    let long_rkey = "a".repeat(RKEY_MAX_LEN + 1);
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, COLLECTION, &long_rkey)),
        Err(AtUriError::RecordKey)
    );

    // And the whole-URI cap, reached with a legal-length rkey.
    let padding = "a".repeat(RKEY_MAX_LEN);
    let at_rkey_cap = uri(DID, COLLECTION, &padding);
    assert!(at_rkey_cap.len() <= AT_URI_MAX_LEN);
    assert!(RestrictedAtUri::parse(&at_rkey_cap).is_ok());
}

// ---- the happy path and accessors --------------------------------------------

#[test]
fn a_canonical_uri_parses_and_exposes_its_parts() {
    let parsed = RestrictedAtUri::parse(&canonical()).expect("canonical URI must parse");
    assert_eq!(parsed.as_str(), canonical());
    assert_eq!(parsed.authority(), DID);
    assert_eq!(parsed.collection(), COLLECTION);
    assert_eq!(parsed.record_key(), RKEY);
    assert_eq!(parsed.to_string(), canonical());
}

#[test]
fn a_production_handle_authority_is_accepted() {
    let parsed = RestrictedAtUri::parse(&uri("alice.example.com", COLLECTION, RKEY)).unwrap();
    assert_eq!(parsed.authority(), "alice.example.com");
}

#[test]
fn a_hostname_level_did_web_authority_is_accepted() {
    let parsed = RestrictedAtUri::parse(&uri("did:web:example.com", COLLECTION, RKEY)).unwrap();
    assert_eq!(parsed.authority(), "did:web:example.com");
}

// ---- second spellings a general parser would accept ---------------------------

#[test]
fn an_uppercase_authority_is_refused_even_though_a_parser_accepts_it() {
    // The canonicality point. A general parser takes this and round-trips it,
    // and it names the same record as the lowercase form — which is exactly why
    // it must be refused.
    for authority in [
        "Alice.Example.com",
        "ALICE.EXAMPLE.COM",
        "alice.Example.com",
    ] {
        assert_eq!(
            RestrictedAtUri::parse(&uri(authority, COLLECTION, RKEY)),
            Err(AtUriError::Authority),
            "{authority}"
        );
    }
}

#[test]
fn duplicate_and_trailing_slashes_are_refused() {
    for value in [
        format!("at://{DID}//{COLLECTION}/{RKEY}"),
        format!("at://{DID}/{COLLECTION}//{RKEY}"),
        format!("at://{DID}/{COLLECTION}/{RKEY}/"),
        format!("at:///{COLLECTION}/{RKEY}"),
    ] {
        assert_eq!(
            RestrictedAtUri::parse(&value),
            Err(AtUriError::EmptySegment),
            "{value}"
        );
    }
}

#[test]
fn a_percent_sign_anywhere_is_refused_and_never_decoded() {
    // Admitting escaping gives one record two spellings. `%2F` is a slash to a
    // decoder and a literal to this grammar; refusing outright avoids the
    // question.
    for value in [
        format!("at://{DID}/{COLLECTION}/%2E"),
        format!("at://{DID}/app.bsky.feed%2Epost/{RKEY}"),
        format!("at://exa%6Dple.com/{COLLECTION}/{RKEY}"),
    ] {
        assert!(
            matches!(
                RestrictedAtUri::parse(&value),
                Err(AtUriError::PercentSign { .. })
            ),
            "{value}"
        );
    }
}

#[test]
fn queries_and_fragments_are_refused() {
    assert_eq!(
        RestrictedAtUri::parse(&format!("at://{DID}/{COLLECTION}/{RKEY}?x=1")),
        Err(AtUriError::HasQuery)
    );
    assert_eq!(
        RestrictedAtUri::parse(&format!("at://{DID}/{COLLECTION}/{RKEY}#frag")),
        Err(AtUriError::HasFragment)
    );
}

#[test]
fn the_path_must_be_exactly_a_collection_and_a_record_key() {
    for (value, found) in [
        (format!("at://{DID}"), 1),
        (format!("at://{DID}/{COLLECTION}"), 2),
        (format!("at://{DID}/{COLLECTION}/{RKEY}/extra"), 4),
    ] {
        assert_eq!(
            RestrictedAtUri::parse(&value),
            Err(AtUriError::SegmentCount { found }),
            "{value}"
        );
    }
}

#[test]
fn dot_record_keys_are_refused() {
    // Path-traversal spellings, not record keys. Admitting them would let one
    // URI name different records depending on who resolved it.
    for rkey in [".", ".."] {
        assert_eq!(
            RestrictedAtUri::parse(&uri(DID, COLLECTION, rkey)),
            Err(AtUriError::RecordKey),
            "{rkey}"
        );
    }
    // But a key merely containing dots is fine.
    assert!(RestrictedAtUri::parse(&uri(DID, COLLECTION, "a.b")).is_ok());
    assert!(RestrictedAtUri::parse(&uri(DID, COLLECTION, "...")).is_ok());
}

#[test]
fn the_scheme_is_exact_and_lowercase() {
    for value in [
        format!("AT://{DID}/{COLLECTION}/{RKEY}"),
        format!("at:/{DID}/{COLLECTION}/{RKEY}"),
        format!("https://{DID}/{COLLECTION}/{RKEY}"),
        format!("at:{DID}/{COLLECTION}/{RKEY}"),
    ] {
        assert!(
            matches!(
                RestrictedAtUri::parse(&value),
                Err(AtUriError::Scheme | AtUriError::NonAscii { .. })
            ),
            "{value}"
        );
    }
}

// ---- the collection grammar ----------------------------------------------------

#[test]
fn the_collection_authority_is_lowercase_but_the_terminal_name_is_not() {
    // The split that makes this grammar unusual, and the reason a single
    // lowercase check over the whole NSID would be wrong.
    assert!(RestrictedAtUri::parse(&uri(DID, "app.bsky.feed.Post", RKEY)).is_ok());
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, "App.Bsky.feed.post", RKEY)),
        Err(AtUriError::Collection)
    );
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, "app.Bsky.feed.post", RKEY)),
        Err(AtUriError::Collection)
    );
}

#[test]
fn a_collection_needs_an_authority_and_a_name() {
    for collection in ["post", "app.", ".post", "app.bsky.feed.p0st"] {
        assert_eq!(
            RestrictedAtUri::parse(&uri(DID, collection, RKEY)),
            Err(AtUriError::Collection),
            "{collection}"
        );
    }

    // An empty collection is caught earlier, as an empty path segment. That is
    // the more accurate diagnosis — the problem is the `//`, not the NSID
    // grammar — so the earlier check is left to own it.
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, "", RKEY)),
        Err(AtUriError::EmptySegment)
    );
}

// ---- the collection authority is a REVERSED domain -------------------------------

#[test]
fn the_collection_tld_is_its_first_segment_not_its_last() {
    // An NSID's authority is the owner's domain written backwards, so
    // `app.bsky.feed.post` belongs to `bsky.app` and its TLD is `app`. Reading
    // it forwards puts the TLD rules on the wrong label, and each of these four
    // is a different consequence of that.

    // A digit-leading label is legal domain syntax; only a digit-leading TLD is
    // not. `org.4chan.post` is `4chan.org`, whose TLD is `org`.
    assert!(
        RestrictedAtUri::parse(&uri(DID, "org.4chan.post", RKEY)).is_ok(),
        "a digit-leading second label is a legal domain label"
    );

    // `test` is reserved as a TLD. Here it is a middle label of `test.bsky.app`,
    // whose TLD is `app`, so the collection is fine.
    assert!(
        RestrictedAtUri::parse(&uri(DID, "app.bsky.test.record", RKEY)).is_ok(),
        "a reserved word is only reserved in TLD position"
    );

    // And the two that must now be refused, which the forward reading accepted:
    // `test.foo.record` really does have TLD `test`, which is reserved.
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, "test.foo.record", RKEY)),
        Err(AtUriError::Collection),
        "a reserved TLD in first position must be refused"
    );
    // `3ao.thing.foo` really does have TLD `3ao`, which begins with a digit.
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, "3ao.thing.foo", RKEY)),
        Err(AtUriError::Collection),
        "a digit-leading TLD must be refused"
    );
}

#[test]
fn every_reserved_tld_is_refused_in_first_position_and_allowed_in_the_middle() {
    // The sweep behind the two named cases, so the rule is checked against the
    // whole list rather than the one entry that came to mind.
    for tld in RESERVED_TLDS {
        let reserved_first = format!("{tld}.example.record");
        assert_eq!(
            RestrictedAtUri::parse(&uri(DID, &reserved_first, RKEY)),
            Err(AtUriError::Collection),
            "{reserved_first}"
        );

        let reserved_middle = format!("com.example.{tld}.record");
        assert!(
            RestrictedAtUri::parse(&uri(DID, &reserved_middle, RKEY)).is_ok(),
            "{reserved_middle} has TLD `com`, so the reserved word is an ordinary label"
        );
    }
}

#[test]
fn the_handle_authority_still_reads_forwards() {
    // The direction is a property of the position, not of the grammar, and the
    // two positions must not have been swapped wholesale. A handle is
    // leaf-first, so `example.test` is reserved and `test.example` is not.
    assert_eq!(
        RestrictedAtUri::parse(&uri("example.test", COLLECTION, RKEY)),
        Err(AtUriError::Authority),
        "a handle's TLD is its last label"
    );
    assert!(RestrictedAtUri::parse(&uri("test.example.com", COLLECTION, RKEY)).is_ok());
}

#[test]
fn an_nsid_segment_is_bounded_at_sixty_three_bytes() {
    // Adopted from the NSID grammar the 317-byte total already comes from.
    // Applied to the terminal name as well as to the authority labels, since
    // taking one bound from that grammar and not the other is arbitrary.
    let longest = "a".repeat(NSID_SEGMENT_MAX_LEN);
    assert!(RestrictedAtUri::parse(&uri(DID, &format!("com.example.{longest}"), RKEY)).is_ok());
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, &format!("com.example.{longest}a"), RKEY)),
        Err(AtUriError::Collection),
        "a 64-byte terminal name must be refused"
    );
    assert_eq!(
        RestrictedAtUri::parse(&uri(DID, &format!("com.{longest}a.record"), RKEY)),
        Err(AtUriError::Collection),
        "a 64-byte authority label must be refused"
    );
}

#[test]
fn the_record_key_charset_is_deliberately_left_loose() {
    // §8 enumerates the rkey restrictions and a character set is not among
    // them, so this does not adopt the upstream record-key charset. Recorded as
    // a decision rather than left to be rediscovered: a client refusing a key a
    // server considers valid silently drops legitimate embeds, and the
    // printable-ASCII and no-percent rules already exclude most of the range.
    for rkey in ["3jui7kd54zh2y", "self", "a!b", "x~y", "a$b"] {
        assert!(
            RestrictedAtUri::parse(&uri(DID, COLLECTION, rkey)).is_ok(),
            "{rkey}"
        );
    }
    // What §8 does say about record keys is still enforced.
    for rkey in [".", ".."] {
        assert_eq!(
            RestrictedAtUri::parse(&uri(DID, COLLECTION, rkey)),
            Err(AtUriError::RecordKey),
            "{rkey}"
        );
    }
}

// ---- the shared hostname grammar -------------------------------------------------

#[test]
fn the_authority_reuses_the_production_handle_rules() {
    // Reserved TLDs, single labels, and localhost are rejected because the
    // authority routes through validate_handle_hostname rather than a second
    // grammar written here.
    for tld in RESERVED_TLDS {
        let authority = format!("example.{tld}");
        assert_eq!(
            RestrictedAtUri::parse(&uri(&authority, COLLECTION, RKEY)),
            Err(AtUriError::Authority),
            "{authority}"
        );
    }
    for authority in ["localhost", "example", "example.com."] {
        assert_eq!(
            RestrictedAtUri::parse(&uri(authority, COLLECTION, RKEY)),
            Err(AtUriError::Authority),
            "{authority}"
        );
    }
}

#[test]
fn the_handle_invalid_sentinel_is_not_accepted_here() {
    // Called out by the spec by name; it falls out of the `.invalid` reserved
    // TLD, which is why this reuses that list rather than restating it.
    assert!(RESERVED_TLDS.contains(&"invalid"));
    assert_eq!(
        RestrictedAtUri::parse(&uri("handle.invalid", COLLECTION, RKEY)),
        Err(AtUriError::Authority)
    );
}

// ---- external links ---------------------------------------------------------------

#[test]
fn an_ordinary_https_link_is_accepted() {
    for value in [
        "https://example.com",
        "https://example.com/",
        "https://example.com/path/to/page",
        "https://example.com:8443/page",
        "https://example.com/page?query=1#frag",
        "https://sub.example.com/a%20b",
    ] {
        assert_eq!(require_external_link(value), Ok(()), "{value}");
    }
}

#[test]
fn only_absolute_https_is_accepted() {
    for value in [
        "http://example.com",
        "//example.com",
        "/relative/path",
        "example.com",
        "ftp://example.com",
        "HTTPS://example.com",
    ] {
        assert_eq!(
            require_external_link(value),
            Err(LinkError::NotAbsoluteHttps),
            "{value}"
        );
    }
}

#[test]
fn userinfo_is_refused_because_it_spoofs_the_host() {
    // Reads as the trusted host to a person, resolves to the attacker's.
    for value in [
        "https://trusted.example@evil.example/",
        "https://user:pass@evil.example/",
        "https://@evil.example/",
    ] {
        assert_eq!(
            require_external_link(value),
            Err(LinkError::Userinfo),
            "{value}"
        );
    }
}

#[test]
fn backslashes_whitespace_and_controls_are_refused() {
    assert!(matches!(
        require_external_link("https://example.com\\@evil.example"),
        Err(LinkError::Backslash { .. })
    ));
    for value in [
        "https://example.com/a b",
        "https://example.com/a\tb",
        "https://example.com/a\nb",
        "https://exa mple.com",
    ] {
        assert!(
            matches!(
                require_external_link(value),
                Err(LinkError::WhitespaceOrControl { .. })
            ),
            "{value:?}"
        );
    }
    assert!(matches!(
        require_external_link("https://example.com/a\u{7}b"),
        Err(LinkError::WhitespaceOrControl { .. })
    ));
}

#[test]
fn an_empty_host_is_refused() {
    for value in ["https://", "https:///path", "https://:8443/"] {
        assert_eq!(
            require_external_link(value),
            Err(LinkError::EmptyHost),
            "{value}"
        );
    }
}

#[test]
fn invalid_ports_are_refused_and_valid_ones_accepted() {
    for value in [
        "https://example.com:/",
        "https://example.com:abc/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:999999/",
    ] {
        assert_eq!(
            require_external_link(value),
            Err(LinkError::InvalidPort),
            "{value}"
        );
    }
    for value in ["https://example.com:1/", "https://example.com:65535/"] {
        assert_eq!(require_external_link(value), Ok(()), "{value}");
    }
}

#[test]
fn percent_encoding_is_permitted_here_but_must_be_well_formed() {
    // The deliberate difference from the AT URI grammar, which refuses percent
    // signs outright. Here they are ordinary and are checked, not decoded.
    assert_eq!(require_external_link("https://example.com/a%20b"), Ok(()));
    assert_eq!(require_external_link("https://example.com/%FF"), Ok(()));
    for value in [
        "https://example.com/%",
        "https://example.com/%2",
        "https://example.com/%zz",
        "https://example.com/%2z",
    ] {
        assert!(
            matches!(
                require_external_link(value),
                Err(LinkError::InvalidPercentEncoding { .. })
            ),
            "{value}"
        );
    }
}

#[test]
fn the_external_link_cap_is_separate_from_the_at_uri_cap() {
    assert_eq!(EXTERNAL_LINK_MAX_BYTES, 2_048);
    assert_ne!(EXTERNAL_LINK_MAX_BYTES, AT_URI_MAX_LEN);

    let prefix = "https://example.com/";
    let at_cap = format!(
        "{prefix}{}",
        "a".repeat(EXTERNAL_LINK_MAX_BYTES - prefix.len())
    );
    assert_eq!(at_cap.len(), EXTERNAL_LINK_MAX_BYTES);
    assert_eq!(require_external_link(&at_cap), Ok(()));

    let over = format!("{at_cap}a");
    assert_eq!(
        require_external_link(&over),
        Err(LinkError::Length {
            actual: EXTERNAL_LINK_MAX_BYTES + 1
        })
    );
    assert_eq!(
        require_external_link(""),
        Err(LinkError::Length { actual: 0 })
    );
}

#[test]
fn the_two_grammars_disagree_about_percent_signs_on_purpose() {
    // Recorded so nobody harmonizes them. One record has one spelling; a web
    // URL does not have that property and never could.
    let escaped_link = "https://example.com/a%20b";
    assert_eq!(require_external_link(escaped_link), Ok(()));

    let escaped_at_uri = format!("at://{DID}/{COLLECTION}/a%20b");
    assert!(matches!(
        RestrictedAtUri::parse(&escaped_at_uri),
        Err(AtUriError::PercentSign { .. })
    ));
}
