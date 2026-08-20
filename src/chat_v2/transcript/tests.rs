//! Byte-identity tests against golden vectors lifted from the mls-ds server.
//!
//! The vectors are **not fabricated here**. They are a verbatim subset of
//! `mls-ds server/tests/fixtures/mls_chat_contract_vectors.json` at branch
//! `main`, vendored into this repo rather than referenced by a relative path
//! that escapes it — reaching out of the repo for a corpus is a known way for
//! these suites to become unbuildable somewhere else.
//!
//! If a vector ever fails, the client encoder is wrong until proven otherwise.
//! The server is the authority for these bytes, and re-deriving an expectation
//! to make a test pass would defeat the only thing these tests are for.

use super::*;
use crate::chat_v2::ids::CanonicalUuid;
use serde_json::Value;
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("vectors/mls_ds_transcript_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vendored server vectors must parse")
}

fn hex_to_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector hex must decode")
}

/// Rebuilds a canonical body from a fixture's JSON body plus its declared
/// UUID-valued fields.
///
/// The fixture lists `uuidByteFields` precisely because that mapping is the
/// thing an implementation gets wrong, so honouring it here is the point rather
/// than a shortcut.
fn body_from_fixture(body: &Value, uuid_fields: &[String]) -> CanonicalBody {
    let object = body.as_object().expect("fixture body must be an object");
    let mut canonical = BTreeMap::new();
    for (key, value) in object {
        let converted = if uuid_fields.iter().any(|field| field == key) {
            let text = value.as_str().expect("a UUID field must be a string");
            CanonicalValue::Uuid(
                *CanonicalUuid::parse(text)
                    .expect("fixture UUIDs must be canonical")
                    .as_bytes(),
            )
        } else {
            match value {
                Value::String(text) => CanonicalValue::Text(text.clone()),
                Value::Bool(flag) => CanonicalValue::Bool(*flag),
                Value::Number(number) => CanonicalValue::Integer(
                    number.as_u64().expect("fixture integers are non-negative"),
                ),
                other => panic!("unexpected fixture value shape: {other}"),
            }
        };
        canonical.insert(key.clone(), converted);
    }
    canonical
}

fn signed_mutator_body() -> (CanonicalBody, Value) {
    let vectors = vectors();
    let section = vectors["signedMutator"].clone();
    let uuid_fields: Vec<String> = section["uuidByteFields"]
        .as_array()
        .expect("uuidByteFields must be an array")
        .iter()
        .map(|value| value.as_str().expect("field names are strings").to_owned())
        .collect();
    (body_from_fixture(&section["body"], &uuid_fields), section)
}

// ---- the encoder against the server's own bytes --------------------------

#[test]
fn the_signed_mutator_vector_reproduces_the_server_bytes_exactly() {
    let (body, section) = signed_mutator_body();
    let transcript = SigningTranscript::build(&body).expect("the golden body must build");

    assert_eq!(
        hex::encode(transcript.canonical_projection()),
        section["canonicalUnsignedDagCborHex"]
            .as_str()
            .expect("hex vector"),
        "the DAG-CBOR projection must match the server byte for byte"
    );
    assert_eq!(
        hex::encode(transcript.bytes()),
        section["transcriptHex"].as_str().expect("hex vector"),
        "the domain-prefixed transcript must match the server byte for byte"
    );
    assert_eq!(
        hex::encode(transcript.request_digest()),
        section["canonicalRequestDigestHex"]
            .as_str()
            .expect("hex vector")
    );
    assert_eq!(transcript.kind(), SignedMutationKind::BlobDeletion);
}

#[test]
fn the_transcript_is_exactly_the_domain_followed_by_the_projection() {
    let (body, _) = signed_mutator_body();
    let transcript = SigningTranscript::build(&body).unwrap();
    let domain = SignedMutationKind::BlobDeletion.domain();

    assert!(transcript.bytes().starts_with(domain));
    assert_eq!(
        &transcript.bytes()[domain.len()..],
        transcript.canonical_projection()
    );
    assert_eq!(
        transcript.bytes().len(),
        domain.len() + transcript.canonical_projection().len(),
        "nothing separates or pads the two halves"
    );
}

#[test]
fn mutating_one_field_changes_the_transcript_and_the_digest() {
    // The fixture carries its own mutation and the bytes it must produce, so
    // this checks that the encoder is sensitive in the same place the server is
    // — not merely that some change produces some difference.
    let (mut body, section) = signed_mutator_body();
    let mutation = &section["mutation"];
    let field = mutation["field"].as_str().expect("mutated field name");
    let replacement = mutation["value"].as_str().expect("mutated value");

    body.insert(
        field.to_owned(),
        CanonicalValue::Uuid(*CanonicalUuid::parse(replacement).unwrap().as_bytes()),
    );
    let mutated = SigningTranscript::build(&body).unwrap();

    assert_eq!(
        hex::encode(mutated.bytes()),
        section["mutatedTranscriptHex"]
            .as_str()
            .expect("hex vector")
    );
    assert_eq!(
        hex::encode(mutated.request_digest()),
        section["mutatedRequestDigestHex"]
            .as_str()
            .expect("hex vector")
    );
    assert_ne!(
        hex::encode(mutated.request_digest()),
        section["canonicalRequestDigestHex"].as_str().unwrap(),
        "a one-field change must not leave the digest untouched"
    );
}

#[test]
fn the_standalone_dag_cbor_vector_reproduces_exactly() {
    // A tiny two-key map whose canonical form is short enough to read: `a2`
    // (map of 2), then "a": 1, then "bb": "x". The server's own vector.
    let vectors = vectors();
    let section = &vectors["dagCbor"];
    let mut body = BTreeMap::new();
    body.insert("bb".to_owned(), CanonicalValue::Text("x".to_owned()));
    body.insert("a".to_owned(), CanonicalValue::Integer(1));

    let encoded = serde_ipld_dagcbor::to_vec(&value::BodyRef(&body)).unwrap();
    assert_eq!(
        hex::encode(&encoded),
        section["canonicalHex"].as_str().expect("hex vector")
    );

    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    assert_eq!(
        hex::encode(digest),
        section["sha256Hex"].as_str().expect("hex vector")
    );
}

// ---- the three details that silently break identity ----------------------

#[test]
fn map_keys_are_ordered_length_first_not_byte_lexicographically() {
    // The single most consequential encoding fact. The golden body's keys reach
    // the wire as $type, keyId, blobId, actorDid — shortest first — whereas the
    // BTreeMap the body is held in iterates actorDid, blobId, keyId, $type
    // order. If these two ever agreed by accident the test would prove nothing,
    // so it asserts they genuinely disagree.
    let (body, _) = signed_mutator_body();

    let mut by_length: Vec<&String> = body.keys().collect();
    by_length.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    let lexicographic: Vec<&String> = body.keys().collect();
    assert_ne!(
        by_length, lexicographic,
        "this fixture must actually distinguish the two orderings"
    );

    // And the wire agrees with length-first: the first key emitted after the
    // map header is `$type` (5 bytes), not `actorDid` (8).
    let transcript = SigningTranscript::build(&body).unwrap();
    let projection = transcript.canonical_projection();
    assert_eq!(projection[0], 0xa9, "a nine-entry CBOR map header");
    assert_eq!(projection[1], 0x65, "a five-byte text key follows");
    assert_eq!(&projection[2..7], b"$type");
}

#[test]
fn a_uuid_reaches_the_transcript_as_sixteen_bytes_not_text() {
    let (body, section) = signed_mutator_body();
    let raw = *CanonicalUuid::parse(
        section["body"]["blobId"]
            .as_str()
            .expect("the fixture blobId"),
    )
    .unwrap()
    .as_bytes();

    // The canonical projection carries a 16-byte CBOR byte string (`0x50`)
    // holding the raw UUID, and never its hyphenated ASCII form.
    let projection = SigningTranscript::build(&body).unwrap();
    let projection = projection.canonical_projection();
    let mut expected = vec![0x50u8];
    expected.extend_from_slice(&raw);
    assert!(
        projection
            .windows(expected.len())
            .any(|window| window == expected),
        "the raw 16 bytes must appear as a CBOR byte string"
    );
    assert!(
        !projection
            .windows(36)
            .any(|window| window == b"018f3f6a-7b2c-4d91-8a5e-0f123456789a"),
        "the hyphenated ASCII form must never appear"
    );

    // Encoding the same field as text produces different bytes — which is the
    // failure this variant distinction exists to prevent.
    let mut as_text = body.clone();
    as_text.insert(
        "blobId".to_owned(),
        CanonicalValue::Text("018f3f6a-7b2c-4d91-8a5e-0f123456789a".to_owned()),
    );
    assert_ne!(
        SigningTranscript::build(&as_text)
            .unwrap()
            .canonical_projection(),
        projection
    );
}

#[test]
fn the_text_shaped_identity_kinds_encode_identically_to_text() {
    // Did, Thumbprint, and Timestamp are separate variants for meaning, not for
    // encoding. Pinning that they emit identical bytes stops someone "fixing"
    // an apparent inconsistency by making one of them bytes.
    for value in [
        CanonicalValue::Did("did:plc:ewvi7nxzyoun6zhxrhs64oiz".to_owned()),
        CanonicalValue::Thumbprint("If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk".to_owned()),
        CanonicalValue::Timestamp("2026-07-22T14:05:09.123Z".to_owned()),
    ] {
        let text = match &value {
            CanonicalValue::Did(inner)
            | CanonicalValue::Thumbprint(inner)
            | CanonicalValue::Timestamp(inner) => CanonicalValue::Text(inner.clone()),
            _ => unreachable!(),
        };
        let mut typed = BTreeMap::new();
        typed.insert("f".to_owned(), value);
        let mut plain = BTreeMap::new();
        plain.insert("f".to_owned(), text);
        assert_eq!(
            serde_ipld_dagcbor::to_vec(&value::BodyRef(&typed)).unwrap(),
            serde_ipld_dagcbor::to_vec(&value::BodyRef(&plain)).unwrap()
        );
    }
}

// ---- domains ---------------------------------------------------------------

#[test]
fn every_domain_is_nul_terminated_and_unique() {
    // The trailing NUL is inside the signed bytes. Dropping it — the natural
    // thing to do when retyping a domain as a Rust string — changes every
    // signature that kind ever produces.
    let mut seen = Vec::new();
    for kind in SignedMutationKind::ALL {
        let domain = kind.domain();
        assert_eq!(domain.last(), Some(&0u8), "{kind:?} domain must end in NUL");
        assert!(
            domain[..domain.len() - 1].iter().all(|byte| *byte != 0),
            "{kind:?} domain must contain exactly one NUL"
        );
        assert!(
            !seen.contains(&domain),
            "{kind:?} shares a domain with another kind"
        );
        seen.push(domain);
    }
    assert_eq!(seen.len(), 24, "the closed set is twenty-four kinds");
}

#[test]
fn the_golden_body_carries_its_domain_nul_and_all() {
    // The domain is bound twice: as the transcript prefix and as a body field.
    // The fixture's JSON really does contain the NUL, and this records it,
    // because a reader would otherwise assume the escape was an artefact.
    let vectors = vectors();
    let declared = vectors["signedMutator"]["body"]["signatureDomain"]
        .as_str()
        .expect("signatureDomain");
    assert!(declared.ends_with('\0'));
    assert_eq!(
        declared.as_bytes(),
        SignedMutationKind::BlobDeletion.domain()
    );
}

#[test]
fn type_ids_round_trip_and_an_unknown_one_fails_closed() {
    for kind in SignedMutationKind::ALL {
        assert_eq!(
            SignedMutationKind::from_type_id(kind.type_id()),
            Some(*kind)
        );
        assert!(kind.type_id().ends_with(kind.body_name()));
        assert!(kind.type_id().starts_with("blue.catbird.chat.defs#"));
    }
    // Guessing a kind would pick a signing domain, and the domain is what stops
    // one operation's signature being replayed as another's.
    for unknown in [
        "blue.catbird.chat.defs#somethingNewBody",
        "blue.catbird.mlsChat.defs#blobDeletionBody",
        "blobDeletionBody",
        "",
    ] {
        assert_eq!(SignedMutationKind::from_type_id(unknown), None);
    }
}

// ---- refusals ---------------------------------------------------------------

#[test]
fn a_body_whose_domain_disagrees_with_its_type_is_refused() {
    let (mut body, _) = signed_mutator_body();
    body.insert(
        "signatureDomain".to_owned(),
        CanonicalValue::Text(
            String::from_utf8(SignedMutationKind::ApplicationSend.domain().to_vec()).unwrap(),
        ),
    );
    assert_eq!(
        SigningTranscript::build(&body),
        Err(TranscriptError::DomainMismatch)
    );
}

#[test]
fn a_domain_missing_its_nul_is_refused() {
    // The exact mistake retyping a domain produces.
    let (mut body, _) = signed_mutator_body();
    body.insert(
        "signatureDomain".to_owned(),
        CanonicalValue::Text("CATBIRD-CHAT-BLOB-DELETE".to_owned()),
    );
    assert_eq!(
        SigningTranscript::build(&body),
        Err(TranscriptError::DomainMismatch)
    );
}

#[test]
fn an_absent_or_unknown_type_is_refused() {
    let (body, _) = signed_mutator_body();

    let mut missing = body.clone();
    missing.remove("$type");
    assert_eq!(
        SigningTranscript::build(&missing),
        Err(TranscriptError::UnknownType)
    );

    let mut unknown = body.clone();
    unknown.insert(
        "$type".to_owned(),
        CanonicalValue::Text("blue.catbird.chat.defs#inventedBody".to_owned()),
    );
    assert_eq!(
        SigningTranscript::build(&unknown),
        Err(TranscriptError::UnknownType)
    );

    // A non-text `$type` must not be coerced.
    let mut wrong_shape = body;
    wrong_shape.insert("$type".to_owned(), CanonicalValue::Integer(1));
    assert_eq!(
        SigningTranscript::build(&wrong_shape),
        Err(TranscriptError::UnknownType)
    );
}

// ---- canonical ordering of array values ------------------------------------

#[test]
fn canonical_ordering_matches_the_server_for_strings_and_bytes() {
    // The contract requires some arrays (DID arrays especially) to be strictly
    // ordered. These vectors pin that the ordering is over UTF-8 bytes and
    // unsigned byte values, which is what Rust's own Ord already gives — the
    // test exists to catch a future "helpful" switch to a collation-aware or
    // signed comparison.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let vectors = vectors();
    let section = &vectors["canonicalOrdering"];

    let mut strings: Vec<String> = section["strings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    strings.sort();
    let expected: Vec<String> = section["expectedStrings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(strings, expected);

    let mut bytes: Vec<Vec<u8>> = section["bytesBase64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| STANDARD.decode(value.as_str().unwrap()).unwrap())
        .collect();
    bytes.sort();
    let expected: Vec<Vec<u8>> = section["expectedBytesBase64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| STANDARD.decode(value.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(bytes, expected, "byte ordering is unsigned, not signed");
}

#[test]
fn the_vendored_vectors_are_actually_loaded() {
    // A positive control. Every test above reads from this fixture, so an empty
    // or truncated vendored file would make them all pass vacuously.
    let vectors = vectors();
    for section in ["canonicalOrdering", "dagCbor", "ed25519", "signedMutator"] {
        assert!(
            vectors[section].is_object(),
            "vendored vector section {section} is missing"
        );
    }
    assert_eq!(
        hex_to_bytes(vectors["ed25519"]["publicKeyHex"].as_str().unwrap()).len(),
        32
    );
    assert_eq!(
        hex_to_bytes(vectors["ed25519"]["signatureHex"].as_str().unwrap()).len(),
        64
    );
}
