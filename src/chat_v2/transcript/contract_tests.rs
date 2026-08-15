//! Contract-projection tests.
//!
//! The decisive one is [`the_lexicon_projection_agrees_with_the_fixtures_byte_paths`]:
//! it takes the server's golden signed body, projects it through the embedded
//! contract with **no knowledge of the fixture's `uuidByteFields` list**, and
//! then checks the result against that list. The fixture and the lexicon are
//! independent sources for the same fact, and the standing rule is that a
//! disagreement is a finding to report rather than something to resolve
//! silently. They agree.

use super::contract::*;
use super::strict_json::decode_strict_json;
use super::*;
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/mls_ds_transcript_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vendored vectors must parse")
}

/// The golden signed body as raw wire JSON, exactly as it would arrive.
fn golden_body_json() -> Vec<u8> {
    let vectors = vectors();
    serde_json::to_vec(&vectors["signedMutator"]["body"]).expect("re-serializing the fixture body")
}

// ---- the projection reproduces the server's bytes ---------------------------

#[test]
fn the_contract_projection_reproduces_the_golden_transcript() {
    // End to end without any fixture scaffold: wire JSON in, canonical body
    // out, transcript bytes identical to the server's.
    let raw = golden_body_json();
    let body = decode_strict_json(&raw).expect("the golden body is strict JSON");
    let projected = project_signed_body(SignedMutationKind::BlobDeletion, &body)
        .expect("the golden body must project");

    let transcript = SigningTranscript::build(&projected).expect("and must build a transcript");
    let vectors = vectors();
    assert_eq!(
        hex::encode(transcript.canonical_projection()),
        vectors["signedMutator"]["canonicalUnsignedDagCborHex"]
            .as_str()
            .unwrap(),
        "the contract-projected body must encode to the server's exact bytes"
    );
    assert_eq!(
        hex::encode(transcript.bytes()),
        vectors["signedMutator"]["transcriptHex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(transcript.request_digest()),
        vectors["signedMutator"]["canonicalRequestDigestHex"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn the_servers_signature_verifies_over_the_contract_projected_transcript() {
    // The scaffold is gone and the signature still verifies, which is the whole
    // point of this slice.
    let raw = golden_body_json();
    let body = decode_strict_json(&raw).unwrap();
    let projected = project_signed_body(SignedMutationKind::BlobDeletion, &body).unwrap();

    let vectors = vectors();
    let public_key =
        hex::decode(vectors["signedMutator"]["publicKeyHex"].as_str().unwrap()).unwrap();
    let signature: [u8; ED25519_SIGNATURE_LEN] =
        hex::decode(vectors["signedMutator"]["signatureHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();

    let verified = VerifiedMutation::verify(projected, signature, &public_key)
        .expect("the golden mutation must verify from wire JSON alone");
    assert_eq!(verified.kind(), SignedMutationKind::BlobDeletion);
}

// ---- the independent-sources cross-check ------------------------------------

#[test]
fn the_lexicon_projection_agrees_with_the_fixtures_byte_paths() {
    // Two independent sources for one fact. The fixture declares which fields
    // are raw UUID bytes; the contract decides it structurally, via a ref to
    // #operationId or #deviceId. Neither consults the other.
    let raw = golden_body_json();
    let body = decode_strict_json(&raw).unwrap();
    let projected = project_signed_body(SignedMutationKind::BlobDeletion, &body).unwrap();

    let mut projected_as_uuid: Vec<&String> = projected
        .iter()
        .filter(|(_, value)| matches!(value, CanonicalValue::Uuid(_)))
        .map(|(name, _)| name)
        .collect();
    projected_as_uuid.sort_unstable();

    let vectors = vectors();
    let mut declared: Vec<String> = vectors["signedMutator"]["uuidByteFields"]
        .as_array()
        .expect("the fixture declares uuidByteFields")
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    declared.sort_unstable();

    let projected_names: Vec<String> = projected_as_uuid.into_iter().cloned().collect();
    assert_eq!(
        projected_names, declared,
        "the contract-derived UUID fields and the fixture's declared list must agree; \
         a disagreement is a finding to report, not a list to edit"
    );
    assert!(
        !declared.is_empty(),
        "a vacuous agreement would prove nothing"
    );
}

#[test]
fn the_uuid_ref_names_are_not_derivable_from_the_contract() {
    // Recorded because it is the trap this module exists to document: the two
    // ref names that become sixteen raw bytes are declared in the lexicon as
    // ordinary strings. An implementer deriving the rule from the schema would
    // encode them as text and produce signatures that verify nowhere.
    let contract: Value =
        serde_json::from_str(include_str!("vectors/blue.catbird.chat.defs.json")).unwrap();
    for name in UUID_REF_NAMES {
        let definition = &contract["defs"][name];
        assert_eq!(
            definition["type"].as_str(),
            Some("string"),
            "{name} is declared as a plain string in the contract"
        );
        assert!(
            definition.get("format").is_none(),
            "{name} carries no format that could mark it as bytes"
        );
    }
    assert_eq!(UUID_REF_NAMES, ["operationId", "deviceId"]);
}

// ---- closedness --------------------------------------------------------------

#[test]
fn an_undeclared_field_is_refused_rather_than_dropped() {
    // A dropped field is data the signature does not cover, riding inside a
    // signed request — the two-field wrapper rule, one level down.
    let mut body: Value = vectors()["signedMutator"]["body"].clone();
    body["somethingExtra"] = Value::String("unsigned".to_owned());
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).unwrap();

    assert_eq!(
        project_signed_body(SignedMutationKind::BlobDeletion, &strict),
        Err(ProjectionError::UnknownField {
            name: "somethingExtra".to_owned()
        })
    );
}

#[test]
fn a_missing_required_field_is_refused_by_name() {
    let mut body: Value = vectors()["signedMutator"]["body"].clone();
    body.as_object_mut().unwrap().remove("blobId");
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).unwrap();

    assert_eq!(
        project_signed_body(SignedMutationKind::BlobDeletion, &strict),
        Err(ProjectionError::MissingRequiredField {
            name: "blobId".to_owned()
        })
    );
}

#[test]
fn the_body_type_tag_must_match_its_definition() {
    let mut body: Value = vectors()["signedMutator"]["body"].clone();
    body["$type"] = Value::String("blue.catbird.chat.defs#creationBody".to_owned());
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).unwrap();

    assert_eq!(
        project_signed_body(SignedMutationKind::BlobDeletion, &strict),
        Err(ProjectionError::WrongTypeTag {
            expected: "blue.catbird.chat.defs#blobDeletionBody".to_owned()
        })
    );
}

#[test]
fn a_body_projected_as_the_wrong_kind_is_refused() {
    // Projecting the blob-deletion body as a creation would otherwise silently
    // produce a body signed under the wrong domain.
    let raw = golden_body_json();
    let strict = decode_strict_json(&raw).unwrap();
    assert!(project_signed_body(SignedMutationKind::Creation, &strict).is_err());
}

// ---- per-type constraints ------------------------------------------------------

#[test]
fn an_identifier_that_fails_its_grammar_is_refused() {
    for (path, replacement, kind) in [
        ("blobId", "not-a-uuid", "UUID"),
        ("actorDid", "did:web:a.b", "DID"),
        ("keyId", "short", "key thumbprint"),
        ("signedAt", "2026-07-22T14:05:09Z", "timestamp"),
    ] {
        let mut body: Value = vectors()["signedMutator"]["body"].clone();
        body[path] = Value::String(replacement.to_owned());
        let raw = serde_json::to_vec(&body).unwrap();
        let strict = decode_strict_json(&raw).unwrap();
        assert_eq!(
            project_signed_body(SignedMutationKind::BlobDeletion, &strict),
            Err(ProjectionError::Identifier { kind }),
            "{path} = {replacement}"
        );
    }
}

#[test]
fn the_cumulative_bare_did_rule_survives_the_projection() {
    // The ratified reading: a DID must satisfy the global 12-261 byte bound in
    // addition to its method grammar, so did:web:a.b is invalid despite
    // satisfying the did:web hostname production. Checked here because the
    // projection is where a wire DID first becomes authority.
    let mut body: Value = vectors()["signedMutator"]["body"].clone();
    body["actorDid"] = Value::String("did:web:a.b".to_owned());
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).unwrap();
    assert_eq!(
        project_signed_body(SignedMutationKind::BlobDeletion, &strict),
        Err(ProjectionError::Identifier { kind: "DID" })
    );
}

#[test]
fn a_field_of_the_wrong_json_shape_is_refused() {
    let mut body: Value = vectors()["signedMutator"]["body"].clone();
    body["authGeneration"] = Value::String("1".to_owned());
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).unwrap();
    assert_eq!(
        project_signed_body(SignedMutationKind::BlobDeletion, &strict),
        Err(ProjectionError::FieldType {
            expected: "integer"
        })
    );
}

#[test]
fn the_signature_domain_constant_is_enforced_by_the_contract() {
    // signatureDomain is a const string in the lexicon, so a wrong one is
    // refused during projection — before the transcript builder gets a chance
    // to compare it. Two independent gates on the same field.
    let mut body: Value = vectors()["signedMutator"]["body"].clone();
    body["signatureDomain"] = Value::String("CATBIRD-CHAT-MESSAGE\u{0}".to_owned());
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).unwrap();
    assert_eq!(
        project_signed_body(SignedMutationKind::BlobDeletion, &strict),
        Err(ProjectionError::StringValue)
    );
}

// ---- the contract itself ---------------------------------------------------------

#[test]
fn every_signed_mutation_kind_has_a_body_definition() {
    // If a kind's body name were wrong, its projection would fail only when
    // that kind was first exercised. This fails immediately instead.
    let contract: Value =
        serde_json::from_str(include_str!("vectors/blue.catbird.chat.defs.json")).unwrap();
    for kind in SignedMutationKind::ALL {
        let definition = &contract["defs"][kind.body_name()];
        assert!(
            definition.is_object(),
            "{kind:?} names a body definition the contract does not have: {}",
            kind.body_name()
        );
        assert_eq!(
            definition["type"].as_str(),
            Some("object"),
            "{kind:?} body must be an object"
        );
    }
}

#[test]
fn every_control_entry_kind_has_a_definition_too() {
    let contract: Value =
        serde_json::from_str(include_str!("vectors/blue.catbird.chat.defs.json")).unwrap();
    for kind in ControlEntryKind::ALL {
        let name = kind
            .type_id()
            .strip_prefix(TYPE_PREFIX)
            .expect("control type IDs live in the contract namespace");
        assert!(
            contract["defs"][name].is_object(),
            "{kind:?} names a definition the contract does not have: {name}"
        );
    }
}

#[test]
fn the_embedded_contract_is_actually_loaded() {
    // Positive control: a truncated or empty contract would make the closedness
    // tests pass for the wrong reason.
    let contract: Value =
        serde_json::from_str(include_str!("vectors/blue.catbird.chat.defs.json")).unwrap();
    assert_eq!(contract["id"].as_str(), Some("blue.catbird.chat.defs"));
    assert!(
        contract["defs"].as_object().map(|defs| defs.len()) > Some(150),
        "the contract should carry its full definition set"
    );
    assert!(contract["defs"]["blobDeletionBody"].is_object());
}

#[test]
fn an_unknown_definition_name_fails_closed() {
    let raw = golden_body_json();
    let strict = decode_strict_json(&raw).unwrap();
    assert_eq!(
        project_ref("noSuchDefinition", &strict, true),
        Err(ProjectionError::UnknownDefinition {
            name: "noSuchDefinition".to_owned()
        })
    );
}
