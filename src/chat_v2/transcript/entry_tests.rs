//! Application entry verification tests.
//!
//! These build and **actually sign** a complete application entry with a
//! deterministic key, rather than asserting against a canned blob. That matters
//! here: the point of the slice is that the row's shape, its conversation
//! binding, and its signature all agree, and a fixture that could not be
//! re-signed would not let the negatives move one field at a time and observe
//! the signature stop verifying.

use super::contract::project_signed_body;
use super::entry::*;
use super::strict_json::{decode_strict_json, encode_standard_base64};
use super::*;
use crate::chat_v2::ids::{BareDid, BasicCredential, CanonicalUuid, DeviceId, KeyId};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

const CONVERSATION: &str = "11111111-1111-4111-9111-111111111111";
const OTHER_CONVERSATION: &str = "22222222-2222-4222-a222-222222222222";
const ENTRY: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const MESSAGE: &str = "51515151-5151-4151-9151-515151515151";
const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
const SIBLING: &str = "72727272-7272-4272-b272-727272727272";
const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
const OTHER_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const RECEIVED_AT: &str = "2026-07-22T14:05:09.123Z";

fn signing_key() -> SigningKey {
    // Deterministic so the tests are reproducible; never a real key.
    SigningKey::from_bytes(&[7u8; 32])
}

fn public_key() -> [u8; 32] {
    signing_key().verifying_key().to_bytes()
}

fn uuid_bytes_b64(text: &str) -> String {
    encode_standard_base64(CanonicalUuid::parse(text).unwrap().as_bytes())
}

/// The MLS AAD prior context, which mirrors the coordinate in byte form.
fn aad_prior() -> Value {
    json!({
        "conversationId": uuid_bytes_b64(CONVERSATION),
        "generation": 0,
        "stateVersion": 3,
        "groupId": encode_standard_base64(&[0x22u8; 32]),
        "epoch": 1,
        "groupContextHash": encode_standard_base64(&[0x33u8; 32]),
        "confirmationTag": encode_standard_base64(&[0x44u8; 32]),
        "lifecycle": "active"
    })
}

/// The signed coordinate the row builds on.
fn prior(conversation: &str) -> Value {
    json!({
        "conversationId": conversation,
        "generation": 0,
        "stateVersion": 3,
        "groupId": encode_standard_base64(&[0x22u8; 32]),
        "epoch": 1,
        "groupContextHash": encode_standard_base64(&[0x33u8; 32]),
        "confirmationTag": encode_standard_base64(&[0x44u8; 32]),
        "lifecycle": "active"
    })
}

/// A complete `applicationSendBody`, parameterised where the negatives need it.
fn send_body(prior_conversation: &str, actor_did: &str, actor_device: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
        "messageId": MESSAGE,
        "actorDid": actor_did,
        "actorDeviceId": actor_device,
        "keyId": KeyId::from_public_key(&public_key()).as_str(),
        "authGeneration": 1,
        "prior": prior(prior_conversation),
        "aad": {
            "protocolVersion": "1",
            "conversationId": uuid_bytes_b64(CONVERSATION),
            "generation": 0,
            "messageId": uuid_bytes_b64(MESSAGE),
            "prior": aad_prior()
        },
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": encode_standard_base64(&[0xAAu8; 64]),
            "sha256": encode_standard_base64(&[0x55u8; 32])
        },
        "blobBindings": [],
        "signedAt": RECEIVED_AT
    })
}

/// Signs a body and assembles the full entry row as it arrives on the wire.
fn entry_row(body: Value, row_conversation: &str) -> Value {
    let raw = serde_json::to_vec(&body).unwrap();
    let strict = decode_strict_json(&raw).expect("the body must be strict JSON");
    let projected = project_signed_body(SignedMutationKind::ApplicationSend, &strict)
        .expect("the body must project through the contract");
    let transcript = SigningTranscript::build(&projected).expect("and build a transcript");
    let signature = signing_key().sign(transcript.bytes());

    json!({
        "entryId": ENTRY,
        "conversationId": row_conversation,
        "seq": 42,
        "signedRequest": {
            "body": body,
            "signature": encode_standard_base64(&signature.to_bytes())
        },
        "receivedAt": RECEIVED_AT
    })
}

fn strict(value: &Value) -> StrictJson {
    decode_strict_json(&serde_json::to_vec(value).unwrap()).expect("strict JSON")
}

fn good_row() -> Value {
    entry_row(send_body(CONVERSATION, DID, DEVICE), CONVERSATION)
}

// ---- the happy path ---------------------------------------------------------

#[test]
fn a_well_formed_signed_entry_verifies_end_to_end() {
    let entry = VerifiedApplicationEntry::verify(&strict(&good_row()), &public_key())
        .expect("a correctly signed entry must verify");

    assert_eq!(
        entry.entry_id(),
        *CanonicalUuid::parse(ENTRY).unwrap().as_bytes()
    );
    assert_eq!(
        entry.conversation_id(),
        *CanonicalUuid::parse(CONVERSATION).unwrap().as_bytes()
    );
    assert_eq!(entry.seq(), 42);
    assert_eq!(entry.received_at(), RECEIVED_AT);
    assert_eq!(entry.mutation().kind(), SignedMutationKind::ApplicationSend);

    // The fingerprint is produced as part of verification, so provenance can
    // never be recorded for a row whose signature was not checked.
    assert_eq!(entry.fingerprint().fingerprint().as_bytes().len(), 32);
}

#[test]
fn verification_fails_if_any_signed_field_is_altered() {
    // Re-signing is what makes this meaningful: the body really is signed, and
    // changing a field without re-signing must break it.
    let mut row = good_row();
    row["signedRequest"]["body"]["authGeneration"] = json!(2);
    assert_eq!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap_err(),
        EntryError::Signed(SignedMutationError::Signature)
    );
}

#[test]
fn a_row_signed_by_a_different_key_does_not_verify() {
    let row = good_row();
    let other = SigningKey::from_bytes(&[9u8; 32])
        .verifying_key()
        .to_bytes();
    // The key ID in the body names our key, so this fails on the binding before
    // the signature is even consulted.
    assert_eq!(
        VerifiedApplicationEntry::verify(&strict(&row), &other).unwrap_err(),
        EntryError::Signed(SignedMutationError::KeyIdMismatch)
    );
}

// ---- SECURITY: the conversation binding -------------------------------------

#[test]
fn a_row_whose_conversation_differs_from_the_signature_is_a_security_refusal() {
    // The entry is legitimately signed — for a different conversation. Replaying
    // it under another conversation's row is exactly what this check exists to
    // stop, and the refusal is named as a security event rather than a shape
    // error.
    let row = entry_row(send_body(CONVERSATION, DID, DEVICE), OTHER_CONVERSATION);
    let err = VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap_err();

    assert_eq!(
        err,
        EntryError::ConversationBindingViolated {
            row: *CanonicalUuid::parse(OTHER_CONVERSATION).unwrap().as_bytes(),
            signed: *CanonicalUuid::parse(CONVERSATION).unwrap().as_bytes(),
        }
    );
    assert!(
        err.to_string().starts_with("SECURITY:"),
        "the message must read as a security event, got {err}"
    );
}

#[test]
fn the_binding_is_checked_before_the_signature() {
    // A row with a mismatched conversation must be refused on the binding even
    // when its signature would also have failed. Reporting "bad signature" for a
    // replay attempt would hide what actually happened.
    let mut row = entry_row(send_body(CONVERSATION, DID, DEVICE), OTHER_CONVERSATION);
    row["signedRequest"]["signature"] = json!(encode_standard_base64(&[0u8; 64]));
    assert!(matches!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap_err(),
        EntryError::ConversationBindingViolated { .. }
    ));
}

#[test]
fn the_binding_reads_from_prior_for_kinds_that_have_one() {
    // The obvious implementation — always read body.conversationId — would find
    // nothing here, since an application send carries it only under `prior`.
    let raw = serde_json::to_vec(&send_body(CONVERSATION, DID, DEVICE)).unwrap();
    let projected = project_signed_body(
        SignedMutationKind::ApplicationSend,
        &decode_strict_json(&raw).unwrap(),
    )
    .unwrap();
    assert!(
        !projected.contains_key("conversationId"),
        "an application send has no top-level conversationId"
    );
    assert_eq!(
        signed_body_conversation_id(SignedMutationKind::ApplicationSend, &projected).unwrap(),
        *CanonicalUuid::parse(CONVERSATION).unwrap().as_bytes()
    );
}

#[test]
fn the_direct_conversation_kinds_are_exactly_the_ones_the_contract_declares() {
    // Rather than trusting the hardcoded pair, derive it: the kinds that carry
    // `conversationId` and no `prior` in the contract must be exactly the two
    // this module reads directly.
    let contract: Value =
        serde_json::from_str(include_str!("vectors/blue.catbird.chat.defs.json")).unwrap();
    let defs = contract["defs"].as_object().unwrap();

    let mut derived: Vec<SignedMutationKind> = Vec::new();
    for kind in SignedMutationKind::ALL {
        let properties = &defs[kind.body_name()]["properties"];
        let has_direct = properties.get("conversationId").is_some();
        let has_prior = properties.get("prior").is_some();
        if has_direct && !has_prior {
            derived.push(*kind);
        }
    }
    assert_eq!(derived, DIRECT_CONVERSATION_KINDS.to_vec());
}

// ---- SECURITY: the sender identity comparison --------------------------------

#[test]
fn the_authenticated_sender_must_be_the_verified_outer_actor() {
    let entry = VerifiedApplicationEntry::verify(&strict(&good_row()), &public_key()).unwrap();
    let expected = BasicCredential::new(
        BareDid::parse(DID).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
    );
    assert_eq!(entry.outer_actor().unwrap(), expected);

    // The matching leaf is accepted and returned.
    assert_eq!(
        entry
            .require_sender_is_outer_actor(&expected.to_identity_bytes())
            .unwrap(),
        expected
    );
}

#[test]
fn a_sibling_device_leaf_is_a_security_refusal_not_a_near_miss() {
    // Same DID, different device. The outer signature names one leaf and the
    // group authenticated another; DID-level agreement is not enough, because
    // application visibility is per exact (DID, deviceId).
    let entry = VerifiedApplicationEntry::verify(&strict(&good_row()), &public_key()).unwrap();
    let sibling = BasicCredential::new(
        BareDid::parse(DID).unwrap(),
        DeviceId::parse(SIBLING).unwrap(),
    );
    let err = entry
        .require_sender_is_outer_actor(&sibling.to_identity_bytes())
        .unwrap_err();

    assert!(matches!(err, EntryError::SenderIdentityMismatch { .. }));
    assert!(err.to_string().starts_with("SECURITY:"), "got {err}");
}

#[test]
fn a_different_did_leaf_is_refused_too() {
    let entry = VerifiedApplicationEntry::verify(&strict(&good_row()), &public_key()).unwrap();
    let impostor = BasicCredential::new(
        BareDid::parse(OTHER_DID).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
    );
    assert!(matches!(
        entry
            .require_sender_is_outer_actor(&impostor.to_identity_bytes())
            .unwrap_err(),
        EntryError::SenderIdentityMismatch { .. }
    ));
}

#[test]
fn a_malformed_leaf_identity_is_refused_rather_than_compared_loosely() {
    let entry = VerifiedApplicationEntry::verify(&strict(&good_row()), &public_key()).unwrap();
    for identity in [
        b"not-a-credential".to_vec(),
        b"".to_vec(),
        format!("{DID}#{DEVICE}#extra").into_bytes(),
        DID.as_bytes().to_vec(),
    ] {
        assert_eq!(
            entry.require_sender_is_outer_actor(&identity),
            Err(EntryError::MalformedActor),
            "identity {identity:?}"
        );
    }
}

#[test]
fn the_outer_actor_tracks_the_signed_body_not_the_row() {
    // Signing as a different actor changes the credential the leaf must match,
    // which is the property that makes the comparison meaningful at all.
    let row = entry_row(send_body(CONVERSATION, OTHER_DID, SIBLING), CONVERSATION);
    let entry = VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap();
    assert_eq!(
        entry.outer_actor().unwrap(),
        BasicCredential::new(
            BareDid::parse(OTHER_DID).unwrap(),
            DeviceId::parse(SIBLING).unwrap(),
        )
    );
}

// ---- row shape ----------------------------------------------------------------

#[test]
fn the_row_carries_exactly_its_five_fields() {
    let mut row = good_row();
    row["extra"] = json!("unsigned");
    // The contract refuses the undeclared field before the row shape check even
    // runs, which is the stronger of the two gates.
    assert!(matches!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap_err(),
        EntryError::Projection(ProjectionError::UnknownField { .. })
    ));

    for field in [
        "entryId",
        "conversationId",
        "seq",
        "signedRequest",
        "receivedAt",
    ] {
        let mut row = good_row();
        row.as_object_mut().unwrap().remove(field);
        assert!(
            VerifiedApplicationEntry::verify(&strict(&row), &public_key()).is_err(),
            "removing {field} must refuse"
        );
    }
}

#[test]
fn the_signed_wrapper_inside_the_row_is_also_exactly_two_fields() {
    let mut row = good_row();
    row["signedRequest"]["extra"] = json!("unsigned");
    assert!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).is_err(),
        "a third wrapper field must refuse"
    );
}

#[test]
fn an_application_row_carrying_a_control_body_is_refused_by_name() {
    // A control operation wearing an application row's clothes. The contract
    // refuses it first, because applicationEntry's signedRequest is a closed
    // union with exactly one member.
    let mut row = good_row();
    row["signedRequest"]["body"]["$type"] = json!("blue.catbird.chat.defs#creationBody");
    assert!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).is_err(),
        "a non-application body must refuse"
    );
}

#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let mut row = good_row();
    row["signedRequest"]["signature"] = json!(encode_standard_base64(&[0u8; 63]));
    assert!(matches!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap_err(),
        EntryError::Projection(ProjectionError::BytesLength)
    ));
}

#[test]
fn a_seq_of_zero_is_refused_by_the_contract() {
    let mut row = good_row();
    row["seq"] = json!(0);
    assert!(matches!(
        VerifiedApplicationEntry::verify(&strict(&row), &public_key()).unwrap_err(),
        EntryError::Projection(ProjectionError::IntegerBound)
    ));
}

#[test]
fn the_test_fixture_really_signs_and_would_notice_if_it_did_not() {
    // Positive control on the harness itself. If `entry_row` ever stopped
    // signing the transcript it builds, every negative above would still
    // "pass" for the wrong reason.
    let row = good_row();
    let signature = row["signedRequest"]["signature"].as_str().unwrap();
    assert_ne!(
        signature,
        encode_standard_base64(&[0u8; 64]),
        "the harness must produce a real signature"
    );
    assert!(VerifiedApplicationEntry::verify(&strict(&row), &public_key()).is_ok());

    let mut tampered = row;
    tampered["signedRequest"]["signature"] = json!(encode_standard_base64(&[0u8; 64]));
    assert!(VerifiedApplicationEntry::verify(&strict(&tampered), &public_key()).is_err());
}
