//! Strict-decode and Ed25519 tests against the server's golden vectors.
//!
//! The `ed25519` section is a standalone RFC 8032 vector plus a one-bit
//! mutation; the `signedMutator` section carries a real key and signature over
//! the transcript this crate builds, so the end-to-end test below proves the
//! client encoder and the server's signer agree on the exact bytes rather than
//! merely on a format.

use super::signed::*;
use super::strict_json::*;
use super::*;
use crate::chat_v2::ids::{CanonicalUuid, KeyId};
use serde_json::Value;
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("vectors/mls_ds_transcript_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vendored vectors must parse")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector hex must decode")
}

fn signed_mutator_body() -> (CanonicalBody, Value) {
    let vectors = vectors();
    let section = vectors["signedMutator"].clone();
    let uuid_fields: Vec<String> = section["uuidByteFields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let object = section["body"].as_object().unwrap();
    let mut body = BTreeMap::new();
    for (key, value) in object {
        let converted = if uuid_fields.iter().any(|field| field == key) {
            CanonicalValue::Uuid(
                *CanonicalUuid::parse(value.as_str().unwrap())
                    .unwrap()
                    .as_bytes(),
            )
        } else {
            match value {
                Value::String(text) => CanonicalValue::Text(text.clone()),
                Value::Bool(flag) => CanonicalValue::Bool(*flag),
                Value::Number(number) => CanonicalValue::Integer(number.as_u64().unwrap()),
                other => panic!("unexpected fixture shape: {other}"),
            }
        };
        body.insert(key.clone(), converted);
    }
    (body, section)
}

// ---- end to end ------------------------------------------------------------

#[test]
fn the_servers_signature_verifies_over_the_transcript_this_crate_builds() {
    // The strongest statement available: the server signed these exact bytes
    // with this key, and the client rebuilt them from the body and accepted
    // the signature. Format agreement would not be enough to pass this.
    let (body, section) = signed_mutator_body();
    let public_key = hex_bytes(section["publicKeyHex"].as_str().unwrap());
    let signature: [u8; ED25519_SIGNATURE_LEN] =
        hex_bytes(section["signatureHex"].as_str().unwrap())
            .try_into()
            .unwrap();

    let transcript = SigningTranscript::build(&body).unwrap();
    verify_ed25519_strict(&public_key, transcript.bytes(), &signature)
        .expect("the server's own signature must verify over our transcript");
}

#[test]
fn a_transcript_from_a_mutated_body_no_longer_verifies() {
    let (mut body, section) = signed_mutator_body();
    let public_key = hex_bytes(section["publicKeyHex"].as_str().unwrap());
    let signature = hex_bytes(section["signatureHex"].as_str().unwrap());

    let mutation = &section["mutation"];
    body.insert(
        mutation["field"].as_str().unwrap().to_owned(),
        CanonicalValue::Uuid(
            *CanonicalUuid::parse(mutation["value"].as_str().unwrap())
                .unwrap()
                .as_bytes(),
        ),
    );
    let mutated = SigningTranscript::build(&body).unwrap();
    assert_eq!(
        verify_ed25519_strict(&public_key, mutated.bytes(), &signature),
        Err(SignedMutationError::Signature)
    );
}

// ---- the standalone Ed25519 vector ----------------------------------------

#[test]
fn the_ed25519_vector_verifies_and_its_mutation_does_not() {
    let vectors = vectors();
    let section = &vectors["ed25519"];
    let public_key = hex_bytes(section["publicKeyHex"].as_str().unwrap());
    let message = hex_bytes(section["messageHex"].as_str().unwrap());
    let signature = hex_bytes(section["signatureHex"].as_str().unwrap());
    let mutated = hex_bytes(section["mutatedSignatureHex"].as_str().unwrap());

    verify_ed25519_strict(&public_key, &message, &signature).expect("the golden signature");
    assert_eq!(
        verify_ed25519_strict(&public_key, &message, &mutated),
        Err(SignedMutationError::Signature),
        "a one-byte signature change must not verify"
    );
    // The vector really is a one-byte difference, so the negative is tight
    // rather than incidentally true.
    let differing = signature
        .iter()
        .zip(&mutated)
        .filter(|(left, right)| left != right)
        .count();
    assert_eq!(differing, 1);
}

#[test]
fn a_wrong_length_key_or_signature_is_refused_by_name() {
    let vectors = vectors();
    let section = &vectors["ed25519"];
    let public_key = hex_bytes(section["publicKeyHex"].as_str().unwrap());
    let signature = hex_bytes(section["signatureHex"].as_str().unwrap());

    assert_eq!(
        verify_ed25519_strict(&public_key[..31], &[], &signature),
        Err(SignedMutationError::PublicKeyLength)
    );
    assert_eq!(
        verify_ed25519_strict(&public_key, &[], &signature[..63]),
        Err(SignedMutationError::SignatureLength)
    );
}

// ---- the signed wrapper ----------------------------------------------------

fn wrapper_json(body: &str, signature_base64: &str) -> Vec<u8> {
    format!(r#"{{"body":{body},"signature":"{signature_base64}"}}"#).into_bytes()
}

fn golden_signature_base64() -> String {
    let vectors = vectors();
    encode_standard_base64(&hex_bytes(
        vectors["signedMutator"]["signatureHex"].as_str().unwrap(),
    ))
}

#[test]
fn a_wrapper_carries_exactly_a_body_and_a_signature() {
    let raw = wrapper_json(r#"{"$type":"x"}"#, &golden_signature_base64());
    let wrapper = SignedWrapper::decode(&raw).expect("a two-field wrapper must decode");
    assert_eq!(wrapper.signature.len(), 64);
    assert!(matches!(wrapper.body, StrictJson::Object(_)));
}

#[test]
fn a_third_wrapper_field_is_refused() {
    // Unsigned data riding inside a signed request. Ignoring it is how a
    // signature comes to cover less than the request it travelled with.
    let signature = golden_signature_base64();
    let raw = format!(r#"{{"body":{{"$type":"x"}},"signature":"{signature}","extra":"unsigned"}}"#);
    assert_eq!(
        SignedWrapper::decode(raw.as_bytes()),
        Err(SignedMutationError::WrapperFieldSet)
    );
}

#[test]
fn a_wrapper_missing_either_field_is_refused() {
    let signature = golden_signature_base64();
    for raw in [
        format!(r#"{{"signature":"{signature}","other":"x"}}"#),
        r#"{"body":{"$type":"x"},"other":"y"}"#.to_owned(),
        r#"{"body":{"$type":"x"}}"#.to_owned(),
    ] {
        assert_eq!(
            SignedWrapper::decode(raw.as_bytes()),
            Err(SignedMutationError::WrapperFieldSet),
            "{raw}"
        );
    }
}

#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let raw = wrapper_json(r#"{"$type":"x"}"#, &encode_standard_base64(&[0u8; 63]));
    assert_eq!(
        SignedWrapper::decode(&raw),
        Err(SignedMutationError::SignatureLength)
    );
}

#[test]
fn a_wrapper_body_must_be_an_object() {
    let raw = wrapper_json(r#""not an object""#, &golden_signature_base64());
    assert_eq!(
        SignedWrapper::decode(&raw),
        Err(SignedMutationError::BodyNotObject)
    );
}

#[test]
fn the_wrapper_reports_a_known_kind_and_fails_closed_otherwise() {
    let signature = golden_signature_base64();
    let known = wrapper_json(
        r#"{"$type":"blue.catbird.chat.defs#blobDeletionBody"}"#,
        &signature,
    );
    assert_eq!(
        SignedWrapper::decode(&known).unwrap().kind(),
        Some(SignedMutationKind::BlobDeletion)
    );

    let unknown = wrapper_json(r#"{"$type":"blue.catbird.chat.defs#nope"}"#, &signature);
    assert_eq!(SignedWrapper::decode(&unknown).unwrap().kind(), None);

    let absent = wrapper_json(r#"{"other":"x"}"#, &signature);
    assert_eq!(SignedWrapper::decode(&absent).unwrap().kind(), None);
}

// ---- the strict JSON profile ------------------------------------------------

#[test]
fn the_profile_refuses_what_it_excludes() {
    for raw in [
        r#"{"a":1.5}"#,       // float
        r#"{"a":-1}"#,        // negative integer
        r#"{"a":null}"#,      // null
        r#"{"a":1,"a":2}"#,   // duplicate key
        r#"{"a":1}trailing"#, // trailing data
        r#"{"a":1"#,          // truncated
    ] {
        assert!(
            decode_strict_json(raw.as_bytes()).is_err(),
            "must refuse: {raw}"
        );
    }
}

#[test]
fn the_profile_accepts_what_it_permits() {
    // A positive control: the refusals above would be meaningless if the
    // decoder rejected everything.
    let raw = r#"{"s":"text","i":9007199254740991,"b":true,"a":[1,2],"o":{"k":"v"}}"#;
    let StrictJson::Object(fields) = decode_strict_json(raw.as_bytes()).expect("must accept")
    else {
        panic!("expected an object");
    };
    assert_eq!(fields.len(), 5);
    assert_eq!(
        fields["i"],
        StrictJson::Integer(9_007_199_254_740_991),
        "the safe-integer ceiling must survive the decoder"
    );
}

#[test]
fn empty_and_oversized_input_is_refused_by_size() {
    assert_eq!(decode_strict_json(&[]), Err(StrictJsonError::Size));
    let oversized = vec![b' '; MAX_SIGNED_JSON_BYTES + 1];
    assert_eq!(decode_strict_json(&oversized), Err(StrictJsonError::Size));
}

// ---- standard base64 --------------------------------------------------------

#[test]
fn standard_base64_round_trips_and_rejects_noncanonical_forms() {
    let bytes = b"clean chat".to_vec();
    let encoded = encode_standard_base64(&bytes);
    assert_eq!(decode_standard_base64(&encoded).unwrap(), bytes);

    // Unpadded is a different string for the same bytes. Accepting both would
    // give a signed body more than one byte representation.
    assert_eq!(
        decode_standard_base64(encoded.trim_end_matches('=')),
        Err(StrictJsonError::Base64)
    );
    // URL-safe alphabet is not the standard alphabet.
    assert_eq!(decode_standard_base64("_w=="), Err(StrictJsonError::Base64));
    assert_eq!(decode_standard_base64("/w==").unwrap(), vec![0xff]);
}

#[test]
fn noncanonical_padding_bits_are_refused() {
    // "AR==" and "AQ==" both decode to [0x01] under a permissive decoder; only
    // one of them re-encodes to itself.
    assert_eq!(decode_standard_base64("AQ==").unwrap(), vec![0x01]);
    assert!(matches!(
        decode_standard_base64("AR=="),
        Err(StrictJsonError::Base64 | StrictJsonError::NoncanonicalBase64)
    ));
}

// ---- key ID binding ----------------------------------------------------------

#[test]
fn verification_requires_the_body_key_id_to_match_the_supplied_key() {
    let (body, section) = signed_mutator_body();
    let public_key = hex_bytes(section["publicKeyHex"].as_str().unwrap());
    let signature: [u8; ED25519_SIGNATURE_LEN] =
        hex_bytes(section["signatureHex"].as_str().unwrap())
            .try_into()
            .unwrap();

    // The golden body's keyId is the thumbprint of the golden key, so the whole
    // verification succeeds.
    let verified = VerifiedMutation::verify(body.clone(), signature, &public_key)
        .expect("the golden mutation must verify end to end");
    assert_eq!(verified.kind(), SignedMutationKind::BlobDeletion);
    assert_eq!(
        hex::encode(verified.request_digest()),
        section["canonicalRequestDigestHex"].as_str().unwrap()
    );

    // Swapping in a different key must fail on the key ID, BEFORE the signature
    // is consulted — the body never claimed that key.
    let mut other_key = public_key.clone();
    other_key[0] ^= 0x01;
    assert_eq!(
        VerifiedMutation::verify(body.clone(), signature, &other_key),
        Err(SignedMutationError::KeyIdMismatch)
    );

    // And a body claiming some other thumbprint fails the same way.
    let mut relabelled = body;
    relabelled.insert(
        "keyId".to_owned(),
        CanonicalValue::Thumbprint(KeyId::from_public_key(&[7u8; 32]).as_str().to_owned()),
    );
    assert_eq!(
        VerifiedMutation::verify(relabelled, signature, &public_key),
        Err(SignedMutationError::KeyIdMismatch)
    );
}

#[test]
fn the_golden_key_id_is_derived_not_asserted() {
    // Proves the client's thumbprint derivation agrees with the server's,
    // rather than the body and the key merely having been shipped together.
    let (body, section) = signed_mutator_body();
    let public_key: [u8; 32] = hex_bytes(section["publicKeyHex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let CanonicalValue::Text(claimed) = &body["keyId"] else {
        panic!("the fixture keyId is a string");
    };
    assert_eq!(KeyId::from_public_key(&public_key).as_str(), claimed);
}
