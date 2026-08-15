//! Fingerprint byte-identity tests against the server's golden vectors.
//!
//! Verbatim from `mls-ds server/tests/fixtures/mls_chat_contract_vectors.json`
//! at the revision recorded in `vectors/PROVENANCE.md`. Each case ships its own
//! `uuidBytePaths` and `base64BytePaths`, which is what lets the projection be
//! rebuilt exactly without reimplementing the lexicon contract — the fixture
//! declares which fields are raw UUID bytes and which are base64 byte strings,
//! at every depth, including inside `serverFields`.

use super::fingerprint::*;
use super::{CanonicalValue, SignedMutationKind};
use crate::chat_v2::ids::CanonicalUuid;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("vectors/mls_ds_fingerprint_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vendored fingerprint vectors must parse")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector hex must decode")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("path is a string").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Rebuilds a JSON subtree as canonical values, honouring the fixture's
/// declared dotted paths for UUID and base64 fields.
///
/// `prefix` tracks the dotted path so nested `serverFields` entries resolve
/// against the same lists the server used.
fn canonical_from_json(
    value: &Value,
    prefix: &str,
    uuid_paths: &[String],
    bytes_paths: &[String],
) -> CanonicalValue {
    if uuid_paths.iter().any(|path| path == prefix) {
        let text = value
            .as_str()
            .expect("a declared UUID path must be a string");
        return CanonicalValue::Uuid(
            *CanonicalUuid::parse(text)
                .expect("fixture UUIDs must be canonical")
                .as_bytes(),
        );
    }
    if bytes_paths.iter().any(|path| path == prefix) {
        let text = value
            .as_str()
            .expect("a declared bytes path must be a string");
        return CanonicalValue::Bytes(STANDARD.decode(text).expect("fixture base64 must decode"));
    }
    match value {
        Value::String(text) => CanonicalValue::Text(text.clone()),
        Value::Bool(flag) => CanonicalValue::Bool(*flag),
        Value::Number(number) => {
            CanonicalValue::Integer(number.as_u64().expect("fixture integers are non-negative"))
        }
        Value::Array(items) => CanonicalValue::Array(
            items
                .iter()
                .map(|item| canonical_from_json(item, prefix, uuid_paths, bytes_paths))
                .collect(),
        ),
        Value::Object(fields) => {
            let mut map = BTreeMap::new();
            for (key, item) in fields {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                map.insert(
                    key.clone(),
                    canonical_from_json(item, &path, uuid_paths, bytes_paths),
                );
            }
            CanonicalValue::Map(map)
        }
        Value::Null => panic!("the clean-chat profile has no null"),
    }
}

fn row_from_case(case: &Value) -> EntryRow {
    EntryRow {
        entry_id: *CanonicalUuid::parse(case["entryId"].as_str().unwrap())
            .unwrap()
            .as_bytes(),
        conversation_id: *CanonicalUuid::parse(case["conversationId"].as_str().unwrap())
            .unwrap()
            .as_bytes(),
        seq: case["seq"].as_u64().unwrap(),
        request_digest: STANDARD
            .decode(case["requestDigest"].as_str().unwrap())
            .unwrap()
            .try_into()
            .expect("request digest is 32 bytes"),
        signature: STANDARD
            .decode(case["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .expect("signature is 64 bytes"),
        received_at: case["receivedAt"].as_str().unwrap().to_owned(),
    }
}

fn server_fields_from_case(kind: ControlEntryKind, case: &Value) -> ControlServerFields {
    let uuid_paths = strings(&case["uuidBytePaths"]);
    let bytes_paths = strings(&case["base64BytePaths"]);
    let declared = case["serverFields"]
        .as_object()
        .expect("serverFields is an object");
    match kind.server_field() {
        None => {
            assert!(
                declared.is_empty(),
                "{kind:?} must declare empty serverFields"
            );
            ControlServerFields::empty(kind).expect("an ordinary kind takes empty fields")
        }
        Some(field) => {
            let value = canonical_from_json(
                &case["serverFields"][field],
                &format!("serverFields.{field}"),
                &uuid_paths,
                &bytes_paths,
            );
            ControlServerFields::single(kind, field, value).expect("the declared special field")
        }
    }
}

// ---- the application fingerprint -------------------------------------------

#[test]
fn the_application_fingerprint_vector_reproduces_exactly() {
    let vectors = vectors();
    let case = &vectors["applicationEntryFingerprint"];
    let products = application_entry_fingerprint(&row_from_case(case)).unwrap();

    assert_eq!(
        hex::encode(products.canonical_projection()),
        case["canonicalDagCborHex"].as_str().unwrap(),
        "the six-field projection must match the server byte for byte"
    );
    assert_eq!(
        hex::encode(products.fingerprint().as_bytes()),
        case["fingerprintSha256Hex"].as_str().unwrap()
    );
}

#[test]
fn the_application_projection_has_exactly_six_fields() {
    // `a6` is a six-entry CBOR map header. The control projection has eight,
    // and unifying the two shapes would change every fingerprint on one side.
    let vectors = vectors();
    let products =
        application_entry_fingerprint(&row_from_case(&vectors["applicationEntryFingerprint"]))
            .unwrap();
    assert_eq!(products.canonical_projection()[0], 0xa6);
}

// ---- all thirteen control fingerprints --------------------------------------

#[test]
fn every_control_fingerprint_vector_reproduces_exactly() {
    let vectors = vectors();
    let cases = vectors["controlEntryFingerprints"]["cases"]
        .as_array()
        .expect("cases array");
    assert_eq!(
        cases.len(),
        13,
        "all thirteen control kinds must be covered"
    );

    let mut seen = Vec::new();
    for case in cases {
        let type_id = case["entryKind"].as_str().unwrap();
        let kind = ControlEntryKind::from_type_id(type_id)
            .unwrap_or_else(|| panic!("unknown control kind in fixture: {type_id}"));
        let products = control_entry_fingerprint(
            kind,
            &row_from_case(case),
            &server_fields_from_case(kind, case),
        )
        .unwrap_or_else(|err| panic!("{type_id} must fingerprint: {err}"));

        assert_eq!(
            hex::encode(products.canonical_projection()),
            case["canonicalDagCborHex"].as_str().unwrap(),
            "{type_id} projection"
        );
        assert_eq!(
            hex::encode(products.fingerprint().as_bytes()),
            case["fingerprintSha256Hex"].as_str().unwrap(),
            "{type_id} fingerprint"
        );
        seen.push(kind);
    }

    // Every declared kind was actually exercised, so the sweep cannot pass by
    // covering the same kind thirteen times.
    for kind in ControlEntryKind::ALL {
        assert!(seen.contains(kind), "{kind:?} was never exercised");
    }
}

// ---- the signing domains the server actually used ---------------------------

#[test]
fn every_control_case_pins_a_signing_domain_this_crate_spells_identically() {
    // The domain table is transcribed from the server's macro, and a single
    // wrong byte produces signatures that verify locally and nowhere else. Until
    // the `signingDomain` and `signingTranscriptHex` keys were re-lifted, only
    // BLOB-DELETE was pinned against server bytes and the other twenty-four
    // rested on the transcription being right.
    //
    // No entryKind-to-domain table is written here on purpose. The case's
    // domain is looked up *in this crate's own set*, so the assertion is "the
    // server used a domain we have, spelled to the byte" rather than a second
    // mapping that could drift from the first.
    let vectors = vectors();
    let cases = vectors["controlEntryFingerprints"]["cases"]
        .as_array()
        .expect("cases array");

    let mut pinned: Vec<&[u8]> = Vec::new();
    for case in cases {
        let entry_kind = case["entryKind"].as_str().unwrap();
        let declared = case["signingDomain"]
            .as_str()
            .unwrap_or_else(|| panic!("{entry_kind} must carry its signing domain"));
        assert!(
            declared.ends_with('\0'),
            "{entry_kind}: the server's domain includes its terminal NUL"
        );

        let matching: Vec<&SignedMutationKind> = SignedMutationKind::ALL
            .iter()
            .filter(|kind| kind.domain() == declared.as_bytes())
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "{entry_kind}: exactly one of this crate's domains must be {declared:?}"
        );

        // And the domain really is the transcript's prefix, NUL included, which
        // is the property the constant exists to serve.
        let transcript = case["signingTranscriptHex"]
            .as_str()
            .unwrap_or_else(|| panic!("{entry_kind} must carry its signing transcript"));
        assert!(
            transcript.starts_with(&hex::encode(declared.as_bytes())),
            "{entry_kind}: the transcript must begin with the domain bytes"
        );

        assert!(
            !pinned.contains(&declared.as_bytes()),
            "{entry_kind}: two cases pinned the same domain"
        );
        pinned.push(declared.as_bytes());
    }
    assert_eq!(pinned.len(), 13);
}

#[test]
fn this_fixture_pins_fourteen_of_the_twenty_five_domains_and_names_the_rest() {
    // What *this* fixture covers, kept exact so its scope is never overstated:
    // the thirteen control entries plus BLOB-DELETE from the signed-mutator
    // vector. The other eleven were once pinned only by the transcribed
    // constant table; they now have their own server vectors in
    // `mls_ds_signing_domain_vectors.json`, and
    // [`super::domain_vector_tests::every_signing_domain_is_now_pinned_by_a_server_vector`]
    // is what proves the two fixtures together leave nothing unpinned.
    let vectors = vectors();
    let mut pinned: Vec<String> = vectors["controlEntryFingerprints"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["signingDomain"].as_str().unwrap().to_owned())
        .collect();
    pinned.push(
        String::from_utf8(SignedMutationKind::BlobDeletion.domain().to_vec())
            .expect("a domain is ASCII plus its NUL"),
    );

    let elsewhere: Vec<&str> = SignedMutationKind::ALL
        .iter()
        .filter(|kind| {
            !pinned
                .iter()
                .any(|domain| domain.as_bytes() == kind.domain())
        })
        .map(|kind| kind.body_name())
        .collect();

    assert_eq!(pinned.len(), 14, "domains this fixture pins");
    assert_eq!(
        elsewhere,
        vec![
            "deviceEnrollmentBody",
            "keyPackageReplenishmentBody",
            "deviceAuthenticationRebindBody",
            "deviceRevocationBody",
            "blobUploadPreparationBody",
            "applicationSendBody",
            "typingBody",
            "leafRecoveryRequestBody",
            "leafRecoveryCancellationBody",
            "welcomeAcknowledgementBody",
            "welcomeRejectionBody",
        ],
        "these eleven are pinned by the signing-domain vectors, not this fixture"
    );
    assert_eq!(
        pinned.len() + elsewhere.len(),
        SignedMutationKind::ALL.len()
    );
}

#[test]
fn the_control_projection_has_exactly_eight_fields() {
    let vectors = vectors();
    let case = &vectors["controlEntryFingerprints"]["cases"][0];
    let kind = ControlEntryKind::from_type_id(case["entryKind"].as_str().unwrap()).unwrap();
    let products = control_entry_fingerprint(
        kind,
        &row_from_case(case),
        &server_fields_from_case(kind, case),
    )
    .unwrap();
    assert_eq!(products.canonical_projection()[0], 0xa8);

    // And the fixture agrees on which eight.
    let declared = strings(&vectors["controlEntryFingerprints"]["projectionFields"]);
    assert_eq!(declared.len(), 8);
    for field in [
        "entryKind",
        "entryId",
        "conversationId",
        "seq",
        "requestDigest",
        "signature",
        "serverFields",
        "receivedAt",
    ] {
        assert!(declared.iter().any(|name| name == field), "{field}");
    }
}

#[test]
fn the_two_fingerprint_domains_differ_and_are_nul_terminated() {
    let vectors = vectors();
    assert_eq!(
        vectors["applicationEntryFingerprint"]["domain"]
            .as_str()
            .unwrap()
            .as_bytes(),
        APPLICATION_FINGERPRINT_DOMAIN
    );
    assert_eq!(
        vectors["controlEntryFingerprints"]["domain"]
            .as_str()
            .unwrap()
            .as_bytes(),
        CONTROL_FINGERPRINT_DOMAIN
    );
    for domain in [APPLICATION_FINGERPRINT_DOMAIN, CONTROL_FINGERPRINT_DOMAIN] {
        assert_eq!(domain.last(), Some(&0u8));
    }
    assert_ne!(APPLICATION_FINGERPRINT_DOMAIN, CONTROL_FINGERPRINT_DOMAIN);
}

// ---- the serverFields rules --------------------------------------------------

#[test]
fn exactly_two_kinds_carry_server_fields_and_the_fixture_agrees() {
    let vectors = vectors();
    let declared = vectors["controlEntryFingerprints"]["nonemptyServerFields"]
        .as_object()
        .expect("nonemptyServerFields map");
    assert_eq!(declared.len(), 2);

    let mut special = Vec::new();
    for kind in ControlEntryKind::ALL {
        match kind.server_field() {
            Some(field) => {
                let listed = declared
                    .get(kind.type_id())
                    .unwrap_or_else(|| panic!("{kind:?} missing from the fixture"));
                assert_eq!(strings(listed), vec![field.to_owned()]);
                special.push(*kind);
            }
            None => assert!(
                !declared.contains_key(kind.type_id()),
                "{kind:?} must carry no server fields"
            ),
        }
    }
    assert_eq!(
        special,
        vec![
            ControlEntryKind::ParticipantAcceptance,
            ControlEntryKind::ConversationClose
        ]
    );
}

#[test]
fn an_ordinary_kind_refuses_server_fields_and_a_special_kind_refuses_emptiness() {
    // Both directions. "I forgot to attach the tombstone" must not silently
    // produce a well-formed fingerprint over the wrong bytes, and neither must
    // "I attached one where none belongs".
    assert_eq!(
        ControlServerFields::single(
            ControlEntryKind::Commit,
            "recovery",
            CanonicalValue::Map(BTreeMap::new())
        )
        .unwrap_err(),
        FingerprintError::OrdinaryServerFieldsMustBeEmpty {
            kind: ControlEntryKind::Commit
        }
    );
    assert_eq!(
        ControlServerFields::empty(ControlEntryKind::ConversationClose).unwrap_err(),
        FingerprintError::SpecialServerFieldsSet {
            kind: ControlEntryKind::ConversationClose,
            expected: "tombstone"
        }
    );
}

#[test]
fn a_special_kind_refuses_the_other_kinds_field_name() {
    // An acceptance carrying a tombstone, or a close carrying a recovery, would
    // otherwise fingerprint cleanly over content that belongs to a different
    // entry entirely.
    assert_eq!(
        ControlServerFields::single(
            ControlEntryKind::ParticipantAcceptance,
            "tombstone",
            CanonicalValue::Map(BTreeMap::new())
        )
        .unwrap_err(),
        FingerprintError::SpecialServerFieldsSet {
            kind: ControlEntryKind::ParticipantAcceptance,
            expected: "recovery"
        }
    );
}

#[test]
fn server_fields_closed_for_one_kind_cannot_fingerprint_another() {
    // The fields carry their own kind, so a caller cannot hold a validated
    // acceptance object and present it while claiming a different entry.
    let vectors = vectors();
    let acceptance = vectors["controlEntryFingerprints"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["entryKind"].as_str().unwrap() == ControlEntryKind::ParticipantAcceptance.type_id()
        })
        .expect("the acceptance case");
    let fields = server_fields_from_case(ControlEntryKind::ParticipantAcceptance, acceptance);

    assert!(control_entry_fingerprint(
        ControlEntryKind::ConversationClose,
        &row_from_case(acceptance),
        &fields
    )
    .is_err());
    assert!(control_entry_fingerprint(
        ControlEntryKind::Commit,
        &row_from_case(acceptance),
        &fields
    )
    .is_err());
}

// ---- sequence bounds ----------------------------------------------------------

#[test]
fn a_seq_outside_the_safe_range_is_refused_on_both_paths() {
    let vectors = vectors();
    let case = &vectors["applicationEntryFingerprint"];
    for bad in [0u64, (crate::chat_v2::ids::MAX_SAFE_INTEGER as u64) + 1] {
        let mut row = row_from_case(case);
        row.seq = bad;
        assert_eq!(
            application_entry_fingerprint(&row).unwrap_err(),
            FingerprintError::Seq { found: bad }
        );
        assert_eq!(
            control_entry_fingerprint(
                ControlEntryKind::Commit,
                &row,
                &ControlServerFields::empty(ControlEntryKind::Commit).unwrap()
            )
            .unwrap_err(),
            FingerprintError::Seq { found: bad }
        );
    }
}

// ---- kind identity ------------------------------------------------------------

#[test]
fn control_type_ids_round_trip_and_fail_closed() {
    let mut seen = Vec::new();
    for kind in ControlEntryKind::ALL {
        assert_eq!(ControlEntryKind::from_type_id(kind.type_id()), Some(*kind));
        assert!(kind.type_id().starts_with("blue.catbird.chat.defs#"));
        assert!(!seen.contains(&kind.type_id()), "duplicate type ID");
        seen.push(kind.type_id());
    }
    assert_eq!(seen.len(), 13);
    for unknown in [
        "blue.catbird.chat.defs#applicationEntry",
        "blue.catbird.mlsChat.defs#commitEntry",
        "commitEntry",
        "",
    ] {
        assert_eq!(ControlEntryKind::from_type_id(unknown), None);
    }
}

#[test]
fn the_entry_kind_actually_participates_in_the_control_fingerprint() {
    // If it did not, one kind's fingerprint could be presented as another's.
    let vectors = vectors();
    let cases = vectors["controlEntryFingerprints"]["cases"]
        .as_array()
        .unwrap();
    let commit = &cases[0];
    let row = row_from_case(commit);

    let as_commit = control_entry_fingerprint(
        ControlEntryKind::Commit,
        &row,
        &ControlServerFields::empty(ControlEntryKind::Commit).unwrap(),
    )
    .unwrap();
    let as_policy = control_entry_fingerprint(
        ControlEntryKind::Policy,
        &row,
        &ControlServerFields::empty(ControlEntryKind::Policy).unwrap(),
    )
    .unwrap();
    assert_ne!(as_commit.fingerprint(), as_policy.fingerprint());
}

#[test]
fn the_kind_table_agrees_with_the_wire_module() {
    // `wire.rs` already names these thirteen kinds plus the application arm,
    // and this module now names them again because it needs their server-field
    // rule. Two tables of the same strings drift; tying them together here
    // means a change to either one fails a test rather than producing
    // fingerprints over a kind set the wire layer does not recognise.
    use crate::chat_v2::wire::{
        APPLICATION_ENTRY_KIND, ENTRY_KINDS, ENTRY_KINDS_WITH_SERVER_FIELDS,
    };

    let mut from_fingerprints: Vec<&str> =
        ControlEntryKind::ALL.iter().map(|k| k.type_id()).collect();
    from_fingerprints.push(APPLICATION_ENTRY_KIND);
    from_fingerprints.sort_unstable();

    let mut from_wire: Vec<&str> = ENTRY_KINDS.to_vec();
    from_wire.sort_unstable();

    assert_eq!(
        from_fingerprints, from_wire,
        "the control kind table and the wire union must name the same entries"
    );

    let mut special: Vec<&str> = ControlEntryKind::ALL
        .iter()
        .filter(|k| k.server_field().is_some())
        .map(|k| k.type_id())
        .collect();
    special.sort_unstable();
    let mut wire_special: Vec<&str> = ENTRY_KINDS_WITH_SERVER_FIELDS.to_vec();
    wire_special.sort_unstable();
    assert_eq!(special, wire_special);
}

#[test]
fn the_vendored_fingerprint_vectors_are_actually_loaded() {
    // Positive control: every test above reads this fixture, so a truncated
    // file would make the suite pass vacuously.
    let vectors = vectors();
    assert!(vectors["applicationEntryFingerprint"].is_object());
    assert_eq!(
        vectors["controlEntryFingerprints"]["cases"]
            .as_array()
            .map(Vec::len),
        Some(13)
    );
    assert_eq!(
        hex_bytes(
            vectors["applicationEntryFingerprint"]["fingerprintSha256Hex"]
                .as_str()
                .unwrap()
        )
        .len(),
        32
    );
}
