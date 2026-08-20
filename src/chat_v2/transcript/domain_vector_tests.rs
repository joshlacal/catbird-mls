//! The ten signing domains that the fingerprint corpus never covered.
//!
//! Until these vectors existed, fourteen of the twenty-four domains were pinned
//! against server bytes — the thirteen control entries plus
//! `CATBIRD-CHAT-BLOB-DELETE` — and the other ten rested entirely on the
//! constant table in [`super`] being transcribed correctly. That included
//! `CATBIRD-CHAT-MESSAGE`, the domain every application send signs under. A
//! single wrong byte in a domain produces signatures that verify locally and
//! nowhere else, which is exactly the failure a transcription cannot detect.
//!
//! Each case here is a server product: mls-ds built the transcript with its own
//! `chat_protocol::transcript` code and signed it, and this module rebuilds the
//! same bytes from the wire body alone — strict JSON in, lexicon projection,
//! transcript out — then verifies the server's signature over the result. The
//! standing rule applies: a vector that fails against this encoder is a finding
//! to report, never a vector to adjust.

use super::contract::*;
use super::strict_json::decode_strict_json;
use super::*;
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/mls_ds_signing_domain_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vendored signing-domain vectors must parse")
}

fn cases() -> Vec<Value> {
    vectors()["cases"]
        .as_array()
        .expect("the fixture carries a case array")
        .clone()
}

fn kind_of(case: &Value) -> SignedMutationKind {
    let name = case["bodyName"]
        .as_str()
        .expect("every case names its body");
    *SignedMutationKind::ALL
        .iter()
        .find(|kind| kind.body_name() == name)
        .unwrap_or_else(|| panic!("{name} is not a live signed-mutation kind"))
}

/// Wire JSON in, projected canonical body out — no fixture scaffold.
fn projected(case: &Value, body: &Value) -> CanonicalBody {
    let raw = serde_json::to_vec(body).expect("re-serializing a fixture body");
    let strict = decode_strict_json(&raw)
        .unwrap_or_else(|error| panic!("{} must be strict JSON: {error:?}", case["bodyName"]));
    project_signed_body(kind_of(case), &strict)
        .unwrap_or_else(|error| panic!("{} must project: {error:?}", case["bodyName"]))
}

fn public_key(case: &Value) -> Vec<u8> {
    hex::decode(case["publicKeyHex"].as_str().unwrap()).expect("public key is hex")
}

fn signature(case: &Value) -> [u8; ED25519_SIGNATURE_LEN] {
    hex::decode(case["signatureHex"].as_str().unwrap())
        .expect("signature is hex")
        .try_into()
        .expect("a signature is sixty-four bytes")
}

// ---- the eleven domains, pinned against server bytes ------------------------

/// The domains the fingerprint corpus already pinned: thirteen control entries
/// plus blob deletion. Read from the vendored server data rather than from a
/// local kind mapping, so the two fixtures are compared on the server's own
/// terms.
fn previously_pinned_domains() -> Vec<String> {
    let fingerprints: Value =
        serde_json::from_str(include_str!("vectors/mls_ds_fingerprint_vectors.json"))
            .expect("the fingerprint vectors must parse");
    let mut domains: Vec<String> = fingerprints["controlEntryFingerprints"]["cases"]
        .as_array()
        .expect("thirteen control cases")
        .iter()
        .map(|case| case["signingDomain"].as_str().unwrap().to_owned())
        .collect();
    domains.push(
        String::from_utf8(SignedMutationKind::BlobDeletion.domain().to_vec())
            .expect("a domain is ASCII plus its NUL"),
    );
    assert_eq!(domains.len(), 14);
    domains
}

#[test]
fn every_signing_domain_is_now_pinned_by_a_server_vector() {
    // The accounting this file exists to change. Thirteen control domains and
    // blob deletion came from the fingerprint corpus; these ten are the rest,
    // and together they are the whole enum. Nothing is left resting on the
    // transcribed table alone.
    let mut pinned = previously_pinned_domains();
    for case in cases() {
        pinned.push(case["signingDomain"].as_str().unwrap().to_owned());
    }
    pinned.sort();
    pinned.dedup();

    assert_eq!(pinned.len(), 24, "one vector per kind, none counted twice");
    let unpinned: Vec<&str> = SignedMutationKind::ALL
        .iter()
        .filter(|kind| {
            !pinned
                .iter()
                .any(|domain| domain.as_bytes() == kind.domain())
        })
        .map(|kind| kind.body_name())
        .collect();
    assert!(
        unpinned.is_empty(),
        "every signing domain must have a server vector; unpinned: {unpinned:?}"
    );
    assert_eq!(pinned.len(), SignedMutationKind::ALL.len());
}

#[test]
fn the_ten_cases_are_exactly_the_kinds_no_other_fixture_covers() {
    let already = previously_pinned_domains();
    let expected: Vec<&str> = SignedMutationKind::ALL
        .iter()
        .filter(|kind| {
            !already
                .iter()
                .any(|domain| domain.as_bytes() == kind.domain())
        })
        .map(|kind| kind.body_name())
        .collect();
    let actual: Vec<String> = cases()
        .iter()
        .map(|case| case["bodyName"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 10);
}

#[test]
fn each_case_declares_the_domain_this_crate_holds_for_its_kind() {
    // The decisive comparison: the fixture's domain string is the server's, and
    // this crate's constant must equal it byte for byte, terminal NUL included.
    for case in cases() {
        let kind = kind_of(&case);
        let declared = case["signingDomain"].as_str().unwrap();
        assert_eq!(
            kind.domain(),
            declared.as_bytes(),
            "{}: transcribed domain differs from the server's",
            case["bodyName"]
        );
        assert_eq!(declared.as_bytes().last(), Some(&0));
    }
}

#[test]
fn the_projection_reproduces_every_servers_transcript_and_digest() {
    for case in cases() {
        let name = case["bodyName"].as_str().unwrap().to_owned();
        let body = projected(&case, &case["body"]);
        let transcript = SigningTranscript::build(&body)
            .unwrap_or_else(|error| panic!("{name} must build a transcript: {error:?}"));

        assert_eq!(
            hex::encode(transcript.canonical_projection()),
            case["canonicalUnsignedDagCborHex"].as_str().unwrap(),
            "{name}: projected body must encode to the server's exact bytes"
        );
        assert_eq!(
            hex::encode(transcript.bytes()),
            case["transcriptHex"].as_str().unwrap(),
            "{name}: transcript bytes"
        );
        assert_eq!(
            hex::encode(transcript.request_digest()),
            case["canonicalRequestDigestHex"].as_str().unwrap(),
            "{name}: request digest"
        );
        assert_eq!(transcript.kind(), kind_of(&case));
    }
}

#[test]
fn the_servers_signature_verifies_over_every_locally_rebuilt_transcript() {
    for case in cases() {
        let name = case["bodyName"].as_str().unwrap().to_owned();
        let body = projected(&case, &case["body"]);
        let verified = VerifiedMutation::verify(body, signature(&case), &public_key(&case))
            .unwrap_or_else(|error| panic!("{name} must verify from wire JSON alone: {error:?}"));
        assert_eq!(verified.kind(), kind_of(&case));
    }
}

#[test]
fn the_declared_one_field_mutation_moves_the_transcript_and_breaks_the_signature() {
    for case in cases() {
        let name = case["bodyName"].as_str().unwrap().to_owned();
        let field = case["mutation"]["field"].as_str().unwrap();
        let mut mutated_json = case["body"].clone();
        mutated_json[field] = case["mutation"]["value"].clone();
        assert_ne!(
            mutated_json[field], case["body"][field],
            "{name}: the mutation must change the field"
        );

        let mutated = projected(&case, &mutated_json);
        let transcript = SigningTranscript::build(&mutated)
            .unwrap_or_else(|error| panic!("{name}: the mutated body still builds: {error:?}"));
        assert_eq!(
            hex::encode(transcript.bytes()),
            case["mutatedTranscriptHex"].as_str().unwrap(),
            "{name}: mutated transcript"
        );
        assert_eq!(
            hex::encode(transcript.request_digest()),
            case["mutatedRequestDigestHex"].as_str().unwrap(),
            "{name}: mutated request digest"
        );
        assert!(
            VerifiedMutation::verify(mutated, signature(&case), &public_key(&case)).is_err(),
            "{name}: a one-field mutation must break the signature"
        );
    }
}

// ---- the independent-sources cross-check ------------------------------------

#[test]
fn the_lexicon_projection_agrees_with_every_cases_uuid_byte_paths() {
    // Two independent sources for one fact, as in [`super::contract_tests`]: the
    // server derived `uuidByteFields` by reading sixteen-byte strings back out
    // of the canonical CBOR it produced; this crate decides it structurally,
    // from a ref to `#operationId` or `#deviceId`. Neither consults the other.
    for case in cases() {
        let name = case["bodyName"].as_str().unwrap().to_owned();
        let body = projected(&case, &case["body"]);

        let mut derived: Vec<String> = body
            .iter()
            .filter(|(_, value)| matches!(value, CanonicalValue::Uuid(_)))
            .map(|(field, _)| field.clone())
            .collect();
        derived.sort_unstable();

        let mut declared: Vec<String> = case["uuidByteFields"]
            .as_array()
            .expect("every case declares its UUID byte fields")
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        declared.sort_unstable();

        assert_eq!(
            derived, declared,
            "{name}: contract-derived UUID fields and the server's declared list must agree; \
             a disagreement is a finding to report, not a list to edit"
        );
        assert!(
            !declared.is_empty(),
            "{name}: a vacuous agreement proves nothing"
        );
    }
}

#[test]
fn the_vendored_signing_domain_vectors_are_actually_loaded() {
    // A positive control on the include: an empty or renamed fixture would make
    // every loop above pass vacuously.
    let vectors = vectors();
    assert_eq!(vectors["schemaVersion"], 1);
    assert_eq!(vectors["signatureAlgorithm"], "Ed25519");
    assert_eq!(cases().len(), 10);
    assert!(VECTORS.len() > 10_000, "the fixture is not a stub");
}
