//! Standing consumer tests for the sealed OpenMLS 0.9 wire corpus.
//!
//! Validates that the checked-in `crypto-wire-v09` artifacts are consumable by
//! real OpenMLS 0.9 state machines and `MlsGroup` instances:
//! - Creation signed request is verified with `VerifiedMutation::verify`
//! - `PublicGroup` processes and merges all commit messages across epochs 0 -> 1 -> 2 -> 3 -> 4
//! - `GroupInfo`, `Welcome`, `KeyPackage`, `ApplicationMessage`, `AppDataUpdate`, and `Snapshots` are parsed and validated
//! - Bob joins through `welcome.mls`, decrypts `application-private.mls`, Alice verifies own-private echo,
//!   and Bob resolves the metadata AppData commit via `resolve_app_data_commit`.

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use openmls::component::ComponentData;
use openmls::framing::MlsMessageBodyIn;
use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use catbird_mls::chat_v2::coordinate::{Coordinate, CoordinateError, Lifecycle, TransitionKind};
use catbird_mls::chat_v2::ids::{
    BareDid, ConversationId, DeviceId, SafeInteger, Seq, TransitionId,
};
use catbird_mls::chat_v2::interval::{IntervalOpening, RecipientBinding};
use catbird_mls::chat_v2::provenance::{OpeningKind, OuterEntryFingerprint};
use catbird_mls::chat_v2::reducer::{ApplicationReducer, ReducerError, SequentialControl};
use catbird_mls::chat_v2::transcript::{
    control_entry_fingerprint, project_signed_body, ControlEntryKind, ControlServerFields,
    EntryRow, SignedMutationError, SignedMutationKind, SignedWrapper, StrictJson, VerifiedMutation,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

const ALICE_ACTOR_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
const BOB_ACTOR_DID: &str = "did:plc:bobterminalccccccccccccc";
const ALICE_DEVICE_ID: &str = "2f93a82d-b061-4c75-8f61-57f23146b910";
const BOB_DEVICE_ID: &str = "b40c12d9-b1ff-4b24-94e5-15742d9ea6cf";

const ALICE_SIGNING_SEED: [u8; 32] = [
    0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55, 0xa6,
    0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b, 0x12, 0x8d,
];
const BOB_SIGNING_SEED: [u8; 32] = [
    0xd4, 0xa1, 0xc4, 0x8e, 0x33, 0x92, 0x40, 0x8e, 0x24, 0x40, 0x90, 0x3f, 0xc5, 0x67, 0x8d, 0xa5,
    0x69, 0x98, 0xeb, 0x66, 0xeb, 0xb8, 0xa9, 0x64, 0xa7, 0xe4, 0xe4, 0xc2, 0xad, 0x82, 0xe9, 0xb5,
];

fn fixed_signer(seed: [u8; 32]) -> (SignatureKeyPair, Vec<u8>) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pk = verifying_key.to_bytes().to_vec();
    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        signing_key.to_bytes().to_vec(),
        pk.clone(),
    );
    (signer, pk)
}
fn coordinate_from_json(val: &serde_json::Value) -> Coordinate {
    let convo_id = match &val["conversationId"] {
        serde_json::Value::String(s) => ConversationId::parse(s).expect("parse convo id"),
        other => panic!("expected string convo id, got {other:?}"),
    };
    let gen = SafeInteger::new(val["generation"].as_i64().expect("generation")).expect("safe gen");
    let sv =
        SafeInteger::new(val["stateVersion"].as_i64().expect("stateVersion")).expect("safe sv");
    let epoch = SafeInteger::new(val["epoch"].as_i64().expect("epoch")).expect("safe epoch");
    let group_id: [u8; 32] = match &val["groupId"] {
        serde_json::Value::String(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap()
            .try_into()
            .unwrap(),
        serde_json::Value::Object(m) => {
            let b64 = m.get("$bytes").and_then(|v| v.as_str()).unwrap();
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap()
                .try_into()
                .unwrap()
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        other => panic!("expected groupId bytes/string, got {other:?}"),
    };
    let gch: [u8; 32] = match &val["groupContextHash"] {
        serde_json::Value::String(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap()
            .try_into()
            .unwrap(),
        serde_json::Value::Object(m) => {
            let b64 = m.get("$bytes").and_then(|v| v.as_str()).unwrap();
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap()
                .try_into()
                .unwrap()
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        other => panic!("expected groupContextHash bytes/string, got {other:?}"),
    };
    let ctag: [u8; 32] = match &val["confirmationTag"] {
        serde_json::Value::String(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap()
            .try_into()
            .unwrap(),
        serde_json::Value::Object(m) => {
            let b64 = m.get("$bytes").and_then(|v| v.as_str()).unwrap();
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap()
                .try_into()
                .unwrap()
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        other => panic!("expected confirmationTag bytes/string, got {other:?}"),
    };
    let lifecycle = match val["lifecycle"].as_str().expect("lifecycle") {
        "active" => Lifecycle::Active,
        "superseded" => Lifecycle::Superseded,
        other => panic!("unknown lifecycle {other}"),
    };
    Coordinate {
        conversation_id: convo_id,
        generation: gen,
        state_version: sv,
        group_id,
        epoch,
        group_context_hash: gch,
        confirmation_tag: ctag,
        lifecycle,
    }
}
#[derive(Debug, Clone)]
enum RawCbor {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
    Array(Vec<RawCbor>),
    Map(std::collections::BTreeMap<String, RawCbor>),
}

impl<'de> serde::Deserialize<'de> for RawCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RawCborVisitor)
    }
}

struct RawCborVisitor;

impl<'de> serde::de::Visitor<'de> for RawCborVisitor {
    type Value = RawCbor;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("closed canonical clean-chat DAG-CBOR")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(RawCbor::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(RawCbor::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u64::try_from(value)
            .map(RawCbor::Integer)
            .map_err(|_| E::custom("negative integers are not in the clean-chat profile"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floats are not in the clean-chat profile"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RawCbor::Text(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(RawCbor::Text(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(RawCbor::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(RawCbor::Bytes(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(RawCbor::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut values = std::collections::BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom("duplicate DAG-CBOR map key"));
            }
        }
        Ok(RawCbor::Map(values))
    }
}

const UUID_KEY_NAMES: &[&str] = &[
    "conversationId",
    "transitionId",
    "actorDeviceId",
    "authorDeviceId",
    "deviceId",
    "closedByDeviceId",
    "messageId",
    "typingId",
    "blobId",
    "idempotencyKey",
    "resetRequestId",
    "recoveryRequestId",
    "leaveRequestId",
    "originTransitionId",
    "recoveryWorkId",
    "welcomeId",
    "entryId",
    "membershipIntervalId",
];
fn cbor_to_strict_json(
    val: &RawCbor,
    parent_key: Option<&str>,
    key_name: Option<&str>,
) -> StrictJson {
    match val {
        RawCbor::Text(s) => StrictJson::String(s.clone()),
        RawCbor::Integer(i) => StrictJson::Integer(*i),
        RawCbor::Bool(b) => StrictJson::Bool(*b),
        RawCbor::Bytes(b) => {
            let is_identifier_bytes =
                parent_key == Some("coordinate") && key_name == Some("conversationId");
            if b.len() == 16
                && !is_identifier_bytes
                && key_name.is_some_and(|k| UUID_KEY_NAMES.contains(&k))
            {
                if let Ok(u) = uuid::Uuid::from_slice(b) {
                    StrictJson::String(u.to_string())
                } else {
                    StrictJson::String(base64::engine::general_purpose::STANDARD.encode(b))
                }
            } else {
                StrictJson::String(base64::engine::general_purpose::STANDARD.encode(b))
            }
        }
        RawCbor::Array(arr) => StrictJson::Array(
            arr.iter()
                .map(|item| cbor_to_strict_json(item, key_name, None))
                .collect(),
        ),
        RawCbor::Map(m) => {
            let mut obj = std::collections::BTreeMap::new();
            for (k, v) in m {
                obj.insert(k.clone(), cbor_to_strict_json(v, key_name, Some(k)));
            }
            StrictJson::Object(obj)
        }
    }
}

fn strict_json_to_serde_value(val: &StrictJson) -> serde_json::Value {
    match val {
        StrictJson::String(s) => serde_json::Value::String(s.clone()),
        StrictJson::Integer(i) => serde_json::json!(i),
        StrictJson::Bool(b) => serde_json::Value::Bool(*b),
        StrictJson::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(strict_json_to_serde_value).collect())
        }
        StrictJson::Object(obj) => {
            let mut m = serde_json::Map::new();
            for (k, v) in obj {
                m.insert(k.clone(), strict_json_to_serde_value(v));
            }
            serde_json::Value::Object(m)
        }
    }
}

fn test_creation_fingerprint(
    convo_id: &ConversationId,
    signature: [u8; 64],
) -> OuterEntryFingerprint {
    let row = EntryRow {
        entry_id: [0x01; 16],
        conversation_id: *convo_id.as_bytes(),
        seq: 1,
        request_digest: [0x02; 32],
        signature,
        received_at: "2026-08-27T22:55:13.000Z".to_owned(),
    };
    control_entry_fingerprint(
        ControlEntryKind::Creation,
        &row,
        &ControlServerFields::empty(ControlEntryKind::Creation).unwrap(),
    )
    .unwrap()
    .fingerprint()
}

fn decode_and_verify_transition_cbor(
    signed_cbor: &[u8],
    expected_kind: SignedMutationKind,
    verifying_key: &[u8; 32],
) -> (VerifiedMutation, serde_json::Value) {
    let root: RawCbor =
        serde_ipld_dagcbor::from_slice(signed_cbor).expect("deserialize DAG-CBOR signed request");
    let RawCbor::Map(map) = root else {
        panic!("signed request must be a CBOR map");
    };
    let body_cbor = map.get("body").expect("missing body field");
    let body_strict = cbor_to_strict_json(body_cbor, None, Some("body"));
    let sig_bytes = match map.get("signature").expect("missing signature field") {
        RawCbor::Bytes(b) => b.clone(),
        other => panic!("expected bytes signature, got {other:?}"),
    };
    let signature: [u8; 64] = sig_bytes.as_slice().try_into().expect("64 byte signature");
    let wrapper = SignedWrapper {
        body: body_strict.clone(),
        signature,
    };
    let projected = match project_signed_body(expected_kind, &wrapper.body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "project_signed_body failed with {e:?} on body: {:#?}",
                wrapper.body
            );
            panic!("project_signed_body: {e:?}");
        }
    };
    let verified = VerifiedMutation::verify(projected, wrapper.signature, verifying_key)
        .expect("VerifiedMutation::verify");
    assert_eq!(verified.kind(), expected_kind);
    (verified, strict_json_to_serde_value(&body_strict))
}

fn coordinate_from_public_group(
    public_group: &PublicGroup,
    convo_id: &ConversationId,
    state_version: i64,
) -> Coordinate {
    let group_id: [u8; 32] = public_group.group_id().as_slice().try_into().unwrap();
    let group_context_tls = public_group
        .group_context()
        .tls_serialize_detached()
        .unwrap();
    let group_context_hash: [u8; 32] = Sha256::digest(&group_context_tls).into();
    let confirmation_tag_tls = public_group
        .confirmation_tag()
        .tls_serialize_detached()
        .unwrap();
    let confirmation_tag_bytes =
        tls_codec::VLBytes::tls_deserialize_exact(&confirmation_tag_tls).unwrap();
    let confirmation_tag: [u8; 32] = confirmation_tag_bytes.as_slice().try_into().unwrap();
    Coordinate {
        conversation_id: convo_id.clone(),
        generation: SafeInteger::ZERO,
        state_version: SafeInteger::new(state_version).unwrap(),
        group_id,
        epoch: SafeInteger::new(public_group.group_context().epoch().as_u64() as i64).unwrap(),
        group_context_hash,
        confirmation_tag,
        lifecycle: Lifecycle::Active,
    }
}

fn v09_fixture_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap();
    let root_path = root.join("docs/generated-artifacts/mls-chat-v1/crypto-wire-v09");
    if root_path.is_dir() {
        return root_path;
    }
    root.join("mls-ds/server/tests/fixtures/crypto-wire-v09")
}

#[test]
fn native_crypto_wire_v09_committed_corpus_replay_and_verification() {
    let fixture_dir = v09_fixture_dir();
    assert!(
        fixture_dir.is_dir(),
        "missing fixture dir: {}",
        fixture_dir.display()
    );
    let manifest_bytes = fs::read(fixture_dir.join("manifest.json")).expect("read manifest");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse manifest");

    // 1. Verify wrapper framing for all wire artifacts
    for (filename, expected_format) in [
        ("key-package.mls", 5u16),
        ("group-info.mls", 4u16),
        ("commit-public.mls", 1u16),
        ("welcome.mls", 3u16),
        ("application-private.mls", 2u16),
        ("commit-generic-public.mls", 1u16),
        ("commit-metadata-appdata-public.mls", 1u16),
        ("own-pending-commit.mls", 1u16),
        ("commit-remove-public.mls", 1u16),
        ("rejoin-key-package.mls", 5u16),
        ("commit-rejoin-public.mls", 1u16),
        ("rejoin-welcome.mls", 3u16),
    ] {
        let payload = fs::read(fixture_dir.join(filename)).expect("read payload");
        assert!(payload.len() >= 4);
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1);
        assert_eq!(
            u16::from_be_bytes([payload[2], payload[3]]),
            expected_format
        );
    }

    let provider = Provider::new().expect("provider");
    let (_alice_signer, alice_pk) = fixed_signer(ALICE_SIGNING_SEED);
    let alice_pub: [u8; 32] = alice_pk.as_slice().try_into().unwrap();

    // 2. Decode and strictly verify all signed requests (creation and state-only transitions)
    let creation_cbor =
        fs::read(fixture_dir.join("creation-signed-request.cbor")).expect("read creation");
    let (verified_creation, creation_body) =
        decode_and_verify_transition_cbor(&creation_cbor, SignedMutationKind::Creation, &alice_pub);
    let creation_coord = coordinate_from_json(&creation_body["next"]);
    assert!(creation_coord.is_creation());
    assert_eq!(creation_coord.state_version.get(), 0);
    assert_eq!(creation_coord.epoch.get(), 0);

    let trans_sv1_cbor =
        fs::read(fixture_dir.join("transition-metadata-sv1.cbor")).expect("read sv1");
    let (_verified_sv1, sv1_body) = decode_and_verify_transition_cbor(
        &trans_sv1_cbor,
        SignedMutationKind::MetadataTransition,
        &alice_pub,
    );
    let sv1_prior = coordinate_from_json(&sv1_body["prior"]);
    let sv1_next = coordinate_from_json(&sv1_body["next"]);
    assert_eq!(sv1_prior, creation_coord);
    creation_coord
        .validate_transition(&sv1_next, TransitionKind::Metadata)
        .expect("valid metadata transition 0 -> 1");
    assert_eq!(sv1_next.state_version.get(), 1);
    assert_eq!(sv1_next.epoch.get(), 0);

    let trans_sv2_cbor =
        fs::read(fixture_dir.join("transition-policy-sv2.cbor")).expect("read sv2");
    let (_verified_sv2, sv2_body) = decode_and_verify_transition_cbor(
        &trans_sv2_cbor,
        SignedMutationKind::PolicyTransition,
        &alice_pub,
    );
    let sv2_prior = coordinate_from_json(&sv2_body["prior"]);
    let sv2_next = coordinate_from_json(&sv2_body["next"]);
    assert_eq!(sv2_prior, sv1_next);
    sv1_next
        .validate_transition(&sv2_next, TransitionKind::Policy)
        .expect("valid policy transition 1 -> 2");
    assert_eq!(sv2_next.state_version.get(), 2);
    assert_eq!(sv2_next.epoch.get(), 0);

    let trans_sv6_cbor =
        fs::read(fixture_dir.join("transition-metadata-sv6.cbor")).expect("read sv6");
    let (_verified_sv6, sv6_body) = decode_and_verify_transition_cbor(
        &trans_sv6_cbor,
        SignedMutationKind::MetadataTransition,
        &alice_pub,
    );
    let sv6_prior = coordinate_from_json(&sv6_body["prior"]);
    let sv6_next = coordinate_from_json(&sv6_body["next"]);
    assert_eq!(sv6_next.state_version.get(), 6);
    assert_eq!(sv6_next.epoch.get(), 3);

    let trans_sv7_cbor =
        fs::read(fixture_dir.join("transition-policy-sv7.cbor")).expect("read sv7");
    let (_verified_sv7, sv7_body) = decode_and_verify_transition_cbor(
        &trans_sv7_cbor,
        SignedMutationKind::PolicyTransition,
        &alice_pub,
    );
    let sv7_prior = coordinate_from_json(&sv7_body["prior"]);
    let sv7_next = coordinate_from_json(&sv7_body["next"]);
    assert_eq!(sv7_prior, sv6_next);
    sv6_next
        .validate_transition(&sv7_next, TransitionKind::Policy)
        .expect("valid policy transition 6 -> 7");
    assert_eq!(sv7_next.state_version.get(), 7);
    assert_eq!(sv7_next.epoch.get(), 3);
    // Initialize Alice's ApplicationReducer and feed initial opening (seq 1)
    let alice_binding = RecipientBinding::new(
        creation_coord.conversation_id,
        BareDid::parse(ALICE_ACTOR_DID).expect("alice did"),
        DeviceId::parse(ALICE_DEVICE_ID).expect("alice device id"),
    );
    let mut alice_reducer = ApplicationReducer::new(alice_binding.clone());
    let creation_transition_id = TransitionId::parse(
        manifest["identifiers"]["creationTransitionId"]
            .as_str()
            .unwrap(),
    )
    .expect("creation transition id");
    let opening_fingerprint = test_creation_fingerprint(
        &creation_coord.conversation_id,
        *verified_creation.signature(),
    );
    let opening = IntervalOpening {
        seq: Seq::new(1).unwrap(),
        kind: OpeningKind::Creation,
        transition_id: creation_transition_id,
        outer_entry_fingerprint: opening_fingerprint,
        context: creation_coord.clone(),
    };
    alice_reducer
        .install_initial_opening(&alice_binding, opening)
        .expect("install initial opening at creation");
    assert_eq!(alice_reducer.expected_context(), Some(&creation_coord));

    // Feed state-only transitions 0 -> 1 and 1 -> 2 through ApplicationReducer
    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(2).unwrap(),
            recipient: alice_binding.clone(),
            previous: creation_coord.clone(),
            next: sv1_next.clone(),
        })
        .expect("apply sv1 control (state_version 0 -> 1)");
    assert_eq!(alice_reducer.expected_context(), Some(&sv1_next));

    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(3).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv1_next.clone(),
            next: sv2_next.clone(),
        })
        .expect("apply sv2 control (state_version 1 -> 2)");
    assert_eq!(alice_reducer.expected_context(), Some(&sv2_next));
    // 3. Load PublicGroup from group-info.mls and verify replay chain
    let group_info_payload = fs::read(fixture_dir.join("group-info.mls")).expect("read group info");
    let group_info_msg =
        MlsMessageIn::tls_deserialize_exact(&group_info_payload).expect("deserialize group info");
    let group_info = match group_info_msg.extract() {
        MlsMessageBodyIn::GroupInfo(gi) => gi,
        other => panic!("expected GroupInfo, got {other:?}"),
    };
    let ratchet_tree = group_info
        .extensions()
        .ratchet_tree()
        .expect("ratchet tree extension")
        .ratchet_tree()
        .clone();
    let (mut public_group, _gi) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        ratchet_tree,
        group_info,
        ProposalStore::new(),
    )
    .expect("public group from group info");
    assert_eq!(public_group.group_context().epoch().as_u64(), 0);
    let commit_payload =
        fs::read(fixture_dir.join("commit-public.mls")).expect("read commit-public");
    let commit_msg =
        MlsMessageIn::tls_deserialize_exact(&commit_payload).expect("deserialize commit-public");
    let commit_proto: ProtocolMessage = commit_msg.try_into().expect("into protocol msg");
    let processed_commit = public_group
        .process_message(provider.crypto(), commit_proto)
        .expect("process commit-public");
    let staged_commit = match processed_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => panic!("expected StagedCommitMessage, got {other:?}"),
    };
    public_group
        .merge_commit(provider.storage(), *staged_commit)
        .expect("merge commit-public");
    assert_eq!(public_group.group_context().epoch().as_u64(), 1);

    // Commit transition: stateVersion 2 -> 3, epoch 0 -> 1
    let sv3_coord = coordinate_from_public_group(&public_group, &creation_coord.conversation_id, 3);
    sv2_next
        .validate_transition(&sv3_coord, TransitionKind::Commit)
        .expect("valid commit transition 2 -> 3");
    assert_eq!(sv3_coord.state_version.get(), 3);
    assert_eq!(sv3_coord.epoch.get(), 1);

    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(4).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv2_next.clone(),
            next: sv3_coord.clone(),
        })
        .expect("apply commit sv3 control");
    assert_eq!(alice_reducer.expected_context(), Some(&sv3_coord));
    // 5. Verify welcome.mls and application-private.mls
    let welcome_payload = fs::read(fixture_dir.join("welcome.mls")).expect("read welcome");
    let welcome_msg =
        MlsMessageIn::tls_deserialize_exact(&welcome_payload).expect("deserialize welcome");
    let welcome = match welcome_msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        other => panic!("expected Welcome, got {other:?}"),
    };
    assert_eq!(welcome.ciphersuite(), CIPHERSUITE);

    let app_payload =
        fs::read(fixture_dir.join("application-private.mls")).expect("read app private");
    let app_msg =
        MlsMessageIn::tls_deserialize_exact(&app_payload).expect("deserialize app private");
    let app_proto: ProtocolMessage = app_msg.try_into().expect("into protocol msg");
    assert_eq!(
        app_proto.group_id().as_slice(),
        public_group.group_id().as_slice()
    );
    assert_eq!(app_proto.epoch().as_u64(), 1);

    let app_frame_bytes =
        fs::read(fixture_dir.join("application-frame.cbor")).expect("read app frame");
    assert!(!app_frame_bytes.is_empty());

    // 6. Process commit-generic-public.mls (epoch 1 -> 2)
    let generic_payload =
        fs::read(fixture_dir.join("commit-generic-public.mls")).expect("read generic commit");
    let generic_msg =
        MlsMessageIn::tls_deserialize_exact(&generic_payload).expect("deserialize generic commit");
    let generic_proto: ProtocolMessage = generic_msg.try_into().expect("into protocol msg");
    let processed_generic = public_group
        .process_message(provider.crypto(), generic_proto)
        .expect("process generic commit");
    let staged_generic = match processed_generic.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => panic!("expected StagedCommitMessage, got {other:?}"),
    };
    public_group
        .merge_commit(provider.storage(), *staged_generic)
        .expect("merge generic commit");
    assert_eq!(public_group.group_context().epoch().as_u64(), 2);

    // Generic commit transition: stateVersion 3 -> 4, epoch 1 -> 2
    let sv4_coord = coordinate_from_public_group(&public_group, &creation_coord.conversation_id, 4);
    sv3_coord
        .validate_transition(&sv4_coord, TransitionKind::Commit)
        .expect("valid generic commit transition 3 -> 4");
    assert_eq!(sv4_coord.state_version.get(), 4);
    assert_eq!(sv4_coord.epoch.get(), 2);

    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(5).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv3_coord.clone(),
            next: sv4_coord.clone(),
        })
        .expect("apply generic commit sv4 control");
    assert_eq!(alice_reducer.expected_context(), Some(&sv4_coord));
    // 7. Verify commit-metadata-appdata-public.mls and own-pending-commit.mls wire payloads
    let appdata_payload = fs::read(fixture_dir.join("commit-metadata-appdata-public.mls"))
        .expect("read appdata commit");
    let appdata_msg =
        MlsMessageIn::tls_deserialize_exact(&appdata_payload).expect("deserialize appdata commit");
    let appdata_proto: ProtocolMessage = appdata_msg.try_into().expect("into protocol msg");
    assert_eq!(
        appdata_proto.group_id().as_slice(),
        b"appdata-wire-metadata-group-v09_"
    );
    assert_eq!(appdata_proto.epoch().as_u64(), 1);

    let own_pending_payload =
        fs::read(fixture_dir.join("own-pending-commit.mls")).expect("read own pending commit");
    let own_pending_msg = MlsMessageIn::tls_deserialize_exact(&own_pending_payload)
        .expect("deserialize own pending commit");
    let own_pending_proto: ProtocolMessage = own_pending_msg.try_into().expect("into protocol msg");
    assert_eq!(
        own_pending_proto.group_id().as_slice(),
        public_group.group_id().as_slice()
    );
    assert_eq!(own_pending_proto.epoch().as_u64(), 2);
    // 8. Process commit-remove-public.mls (epoch 2 -> 3)
    let remove_payload =
        fs::read(fixture_dir.join("commit-remove-public.mls")).expect("read remove commit");
    let remove_msg =
        MlsMessageIn::tls_deserialize_exact(&remove_payload).expect("deserialize remove commit");
    let remove_proto: ProtocolMessage = remove_msg.try_into().expect("into protocol msg");
    let processed_remove = public_group
        .process_message(provider.crypto(), remove_proto)
        .expect("process remove commit");
    let staged_remove = match processed_remove.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => panic!("expected StagedCommitMessage, got {other:?}"),
    };
    public_group
        .merge_commit(provider.storage(), *staged_remove)
        .expect("merge remove commit");
    assert_eq!(public_group.group_context().epoch().as_u64(), 3);

    // Remove commit transition: stateVersion 4 -> 5, epoch 2 -> 3
    let sv5_coord = coordinate_from_public_group(&public_group, &creation_coord.conversation_id, 5);
    sv4_coord
        .validate_transition(&sv5_coord, TransitionKind::Commit)
        .expect("valid remove commit transition 4 -> 5");
    assert_eq!(sv5_coord.state_version.get(), 5);
    assert_eq!(sv5_coord.epoch.get(), 3);

    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(6).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv4_coord.clone(),
            next: sv5_coord.clone(),
        })
        .expect("apply remove commit sv5 control");
    assert_eq!(alice_reducer.expected_context(), Some(&sv5_coord));

    // State-only metadata transition: stateVersion 5 -> 6 (epoch 3)
    assert_eq!(sv6_prior, sv5_coord);
    sv5_coord
        .validate_transition(&sv6_next, TransitionKind::Metadata)
        .expect("valid metadata transition 5 -> 6");
    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(7).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv5_coord.clone(),
            next: sv6_next.clone(),
        })
        .expect("apply metadata sv6 control (state_version 5 -> 6)");
    assert_eq!(alice_reducer.expected_context(), Some(&sv6_next));

    // State-only policy transition: stateVersion 6 -> 7 (epoch 3)
    assert_eq!(sv7_prior, sv6_next);
    sv6_next
        .validate_transition(&sv7_next, TransitionKind::Policy)
        .expect("valid policy transition 6 -> 7");
    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(8).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv6_next.clone(),
            next: sv7_next.clone(),
        })
        .expect("apply policy sv7 control (state_version 6 -> 7)");
    assert_eq!(alice_reducer.expected_context(), Some(&sv7_next));
    let rejoin_payload =
        fs::read(fixture_dir.join("commit-rejoin-public.mls")).expect("read rejoin commit");
    let rejoin_msg =
        MlsMessageIn::tls_deserialize_exact(&rejoin_payload).expect("deserialize rejoin commit");
    let rejoin_proto: ProtocolMessage = rejoin_msg.try_into().expect("into protocol msg");
    let processed_rejoin = public_group
        .process_message(provider.crypto(), rejoin_proto)
        .expect("process rejoin commit");
    let staged_rejoin = match processed_rejoin.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => panic!("expected StagedCommitMessage, got {other:?}"),
    };
    public_group
        .merge_commit(provider.storage(), *staged_rejoin)
        .expect("merge rejoin commit");
    assert_eq!(public_group.group_context().epoch().as_u64(), 4);

    // Rejoin commit transition: stateVersion 7 -> 8, epoch 3 -> 4
    let sv8_coord = coordinate_from_public_group(&public_group, &creation_coord.conversation_id, 8);
    sv7_next
        .validate_transition(&sv8_coord, TransitionKind::Commit)
        .expect("valid rejoin commit transition 7 -> 8");
    assert_eq!(sv8_coord.state_version.get(), 8);
    assert_eq!(sv8_coord.epoch.get(), 4);

    alice_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(9).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv7_next.clone(),
            next: sv8_coord.clone(),
        })
        .expect("apply rejoin commit sv8 control");
    assert_eq!(alice_reducer.expected_context(), Some(&sv8_coord));
    let rejoin_welcome_payload =
        fs::read(fixture_dir.join("rejoin-welcome.mls")).expect("read rejoin welcome");
    let rejoin_welcome_msg = MlsMessageIn::tls_deserialize_exact(&rejoin_welcome_payload)
        .expect("deserialize rejoin welcome");
    let rejoin_welcome = match rejoin_welcome_msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        other => panic!("expected Welcome, got {other:?}"),
    };
    assert_eq!(rejoin_welcome.ciphersuite(), CIPHERSUITE);

    // 10. Verify all 5 public group snapshots are valid schema-2 snapshots
    for snapshot_name in [
        "genesis-public-state.bin",
        "committed-public-state.bin",
        "committed-generic-public-state.bin",
        "committed-remove-public-state.bin",
        "committed-rejoin-public-state.bin",
    ] {
        let snapshot_bytes = fs::read(fixture_dir.join(snapshot_name)).expect("read snapshot");
        assert!(snapshot_bytes.len() >= 16);
        assert_eq!(&snapshot_bytes[..8], b"CBPGSNAP");
        assert_eq!(
            u16::from_be_bytes(snapshot_bytes[8..10].try_into().unwrap()),
            2
        );
    }
}

#[test]
fn native_crypto_wire_v09_live_two_party_flow() {
    let alice_provider = Provider::new().expect("alice provider");
    let bob_provider = Provider::new().expect("bob provider");
    let (alice_signer, alice_pk) = fixed_signer(ALICE_SIGNING_SEED);
    let (bob_signer, bob_pk) = fixed_signer(BOB_SIGNING_SEED);
    alice_signer
        .store(alice_provider.storage())
        .expect("store alice signer");
    bob_signer
        .store(bob_provider.storage())
        .expect("store bob signer");

    let alice_cred_ident = format!("{ALICE_ACTOR_DID}#{ALICE_DEVICE_ID}").into_bytes();
    let bob_cred_ident = format!("{BOB_ACTOR_DID}#{BOB_DEVICE_ID}").into_bytes();

    let test_capabilities = Capabilities::builder()
        .extensions(vec![
            ExtensionType::RatchetTree,
            ExtensionType::AppDataDictionary,
        ])
        .proposals(vec![ProposalType::AppDataUpdate])
        .build();

    let bob_kp_bundle = KeyPackage::builder()
        .leaf_node_capabilities(test_capabilities.clone())
        .build(
            CIPHERSUITE,
            &bob_provider,
            &bob_signer,
            CredentialWithKey {
                credential: BasicCredential::new(bob_cred_ident.clone()).into(),
                signature_key: SignaturePublicKey::from(bob_pk),
            },
        )
        .expect("build bob kp");
    let bob_kp = bob_kp_bundle.key_package().clone();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(test_capabilities)
            .build(),
        GroupId::from_slice(b"native-v09-test-convo-group-32__"),
        CredentialWithKey {
            credential: BasicCredential::new(alice_cred_ident.clone()).into(),
            signature_key: SignaturePublicKey::from(alice_pk),
        },
    )
    .expect("alice group");

    let (_add_commit, welcome_out, _) = alice_group
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .expect("add bob");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("alice merge");

    let welcome_bytes = welcome_out
        .tls_serialize_detached()
        .expect("serialize welcome");
    let welcome_msg =
        MlsMessageIn::tls_deserialize_exact(&welcome_bytes).expect("deserialize welcome");
    let welcome = match welcome_msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        other => panic!("expected welcome, got {other:?}"),
    };

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_group = StagedWelcome::new_from_welcome(&bob_provider, &join_config, welcome, None)
        .expect("staged welcome")
        .into_group(&bob_provider)
        .expect("into group");
    assert_eq!(bob_group.epoch().as_u64(), 1);

    // 2. Application message encrypt and decrypt
    let test_frame = b"canonical test frame content".to_vec();
    let app_out = alice_group
        .create_message(&alice_provider, &alice_signer, &test_frame)
        .expect("create app msg");
    let app_bytes = app_out.tls_serialize_detached().expect("serialize app msg");
    let app_msg = MlsMessageIn::tls_deserialize_exact(&app_bytes).expect("deserialize app msg");
    let app_proto: ProtocolMessage = app_msg.try_into().expect("into protocol msg");

    let processed_app = bob_group
        .process_message(&bob_provider, app_proto)
        .expect("bob process app msg");
    assert_eq!(processed_app.epoch().as_u64(), 1);
    assert_eq!(
        processed_app.credential().serialized_content(),
        alice_cred_ident.as_slice()
    );
    let decrypted = match processed_app.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => msg.into_bytes(),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(decrypted, test_frame);

    // 3. Metadata AppData update commit and resolution
    let update_data = b"{\"v\":1,\"meta\":\"test\"}".to_vec();
    let (_prop_msg, _prop_ref) = alice_group
        .propose_app_data_update(
            &alice_provider,
            &alice_signer,
            catbird_mls::metadata::METADATA_REFERENCE_COMPONENT_ID,
            AppDataUpdateOperation::Update(update_data.into()),
        )
        .expect("propose app data");
    let mut commit_stage = alice_group
        .commit_builder()
        .load_psks(alice_provider.storage())
        .expect("load psks");
    let mut updater = commit_stage.app_data_dictionary_updater();
    for proposal in commit_stage.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            updater.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
    commit_stage.with_app_data_dictionary_updates(updater.changes());
    let commit_bundle = commit_stage
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .expect("build commit")
        .stage_commit(&alice_provider)
        .expect("stage commit");
    let (appdata_commit_out, _, _) = commit_bundle.into_contents();
    let appdata_commit_bytes = appdata_commit_out
        .tls_serialize_detached()
        .expect("serialize appdata commit");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("alice merge appdata commit");

    let appdata_msg = MlsMessageIn::tls_deserialize_exact(&appdata_commit_bytes)
        .expect("deserialize appdata commit");
    let appdata_proto: ProtocolMessage = appdata_msg.try_into().expect("into proto");
    let raw_appdata = bob_group
        .process_message(&bob_provider, appdata_proto)
        .expect("bob process appdata commit");
    let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) = raw_appdata.content() else {
        panic!("expected UnresolvedAppDataCommit");
    };
    let mut bob_updater = bob_group.app_data_dictionary_updater();
    for proposal in unresolved.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            bob_updater.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
    let resolved = bob_group
        .resolve_app_data_commit(&bob_provider, raw_appdata, bob_updater.changes())
        .expect("resolve app data");
    let ProcessedMessageContent::StagedCommitMessage(staged) = resolved.into_content() else {
        panic!("expected StagedCommitMessage");
    };
    assert_eq!(bob_group.epoch().as_u64(), 1);
    bob_group
        .merge_staged_commit(&bob_provider, *staged)
        .expect("bob merge appdata commit");
    assert_eq!(bob_group.epoch().as_u64(), 2);
}

#[test]
fn native_crypto_wire_v09_state_transition_omission_and_mutation_tests() {
    let fixture_dir = v09_fixture_dir();
    let (_alice_signer, alice_pk) = fixed_signer(ALICE_SIGNING_SEED);
    let alice_pub: [u8; 32] = alice_pk.as_slice().try_into().unwrap();
    let (_bob_signer, bob_pk) = fixed_signer(BOB_SIGNING_SEED);
    let bob_pub: [u8; 32] = bob_pk.as_slice().try_into().unwrap();

    let creation_cbor =
        fs::read(fixture_dir.join("creation-signed-request.cbor")).expect("read creation");
    let (_, creation_body) =
        decode_and_verify_transition_cbor(&creation_cbor, SignedMutationKind::Creation, &alice_pub);
    let creation_coord = coordinate_from_json(&creation_body["next"]);

    let trans_sv1_cbor =
        fs::read(fixture_dir.join("transition-metadata-sv1.cbor")).expect("read sv1");
    let (_, sv1_body) = decode_and_verify_transition_cbor(
        &trans_sv1_cbor,
        SignedMutationKind::MetadataTransition,
        &alice_pub,
    );
    let sv1_next = coordinate_from_json(&sv1_body["next"]);

    let trans_sv2_cbor =
        fs::read(fixture_dir.join("transition-policy-sv2.cbor")).expect("read sv2");
    let (_, sv2_body) = decode_and_verify_transition_cbor(
        &trans_sv2_cbor,
        SignedMutationKind::PolicyTransition,
        &alice_pub,
    );
    let sv2_next = coordinate_from_json(&sv2_body["next"]);

    let trans_sv6_cbor =
        fs::read(fixture_dir.join("transition-metadata-sv6.cbor")).expect("read sv6");
    let (_, sv6_body) = decode_and_verify_transition_cbor(
        &trans_sv6_cbor,
        SignedMutationKind::MetadataTransition,
        &alice_pub,
    );
    let sv6_prior = coordinate_from_json(&sv6_body["prior"]);
    let _sv6_next = coordinate_from_json(&sv6_body["next"]);

    let trans_sv7_cbor =
        fs::read(fixture_dir.join("transition-policy-sv7.cbor")).expect("read sv7");
    let (_, sv7_body) = decode_and_verify_transition_cbor(
        &trans_sv7_cbor,
        SignedMutationKind::PolicyTransition,
        &alice_pub,
    );
    let sv7_next = coordinate_from_json(&sv7_body["next"]);

    // 1. Signature mutation on transition-metadata-sv1.cbor must fail verification
    let root: RawCbor = serde_ipld_dagcbor::from_slice(&trans_sv1_cbor).unwrap();
    let RawCbor::Map(map) = root else {
        panic!("map")
    };
    let body_strict = cbor_to_strict_json(map.get("body").unwrap(), None, Some("body"));
    let mut sig_bytes = match map.get("signature").unwrap() {
        RawCbor::Bytes(b) => b.clone(),
        other => panic!("expected bytes signature, got {other:?}"),
    };
    sig_bytes[0] ^= 0xff;
    let signature: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let wrapper = SignedWrapper {
        body: body_strict.clone(),
        signature,
    };
    let projected =
        project_signed_body(SignedMutationKind::MetadataTransition, &wrapper.body).unwrap();
    let verify_err = VerifiedMutation::verify(projected, wrapper.signature, &alice_pub)
        .expect_err("tampered signature on sv1 must fail");
    assert_eq!(verify_err, SignedMutationError::Signature);

    // 2. Wrong public key verification (Bob's key verifying Alice's transition) must fail
    let orig_sig_bytes = match map.get("signature").unwrap() {
        RawCbor::Bytes(b) => b.clone(),
        other => panic!("expected bytes signature, got {other:?}"),
    };
    let orig_signature: [u8; 64] = orig_sig_bytes.as_slice().try_into().unwrap();
    let orig_wrapper = SignedWrapper {
        body: body_strict,
        signature: orig_signature,
    };
    let projected =
        project_signed_body(SignedMutationKind::MetadataTransition, &orig_wrapper.body).unwrap();
    let wrong_key_err = VerifiedMutation::verify(projected, orig_wrapper.signature, &bob_pub)
        .expect_err("Bob public key must not verify Alice's sv1 mutation");
    assert!(matches!(
        wrong_key_err,
        SignedMutationError::KeyIdMismatch | SignedMutationError::Signature
    ));
    // 3. State version omission / gap: skipping sv1 (0 -> 2 directly) must fail coordinate validation
    let gap_err_0_2 = creation_coord
        .validate_transition(&sv2_next, TransitionKind::Policy)
        .expect_err("0 -> 2 state version gap must fail validate_transition");
    assert!(matches!(
        gap_err_0_2,
        CoordinateError::NotIncrementedByOne { .. }
    ));

    // 4. State version omission / gap in ApplicationReducer: skipping sv1 (applying sv2 to creation_coord)
    let alice_binding = RecipientBinding::new(
        creation_coord.conversation_id,
        BareDid::parse(ALICE_ACTOR_DID).unwrap(),
        DeviceId::parse(ALICE_DEVICE_ID).unwrap(),
    );
    let mut test_reducer = ApplicationReducer::new(alice_binding.clone());
    let opening = IntervalOpening {
        seq: Seq::new(1).unwrap(),
        kind: OpeningKind::Creation,
        transition_id: TransitionId::parse("bd135bbe-8b70-4c2b-9823-9662b0fe6d3b").unwrap(),
        outer_entry_fingerprint: test_creation_fingerprint(
            &creation_coord.conversation_id,
            [0x33; 64],
        ),
        context: creation_coord.clone(),
    };
    test_reducer
        .install_initial_opening(&alice_binding, opening)
        .unwrap();

    let reducer_gap_err = test_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(2).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv1_next.clone(),
            next: sv2_next.clone(),
        })
        .expect_err("applying sv2 control without sv1 must fail with ContextMismatch");
    assert!(matches!(
        reducer_gap_err,
        ReducerError::ContextMismatch { .. }
    ));

    // 5. State version omission / gap: skipping sv6 (5 -> 7 directly) must fail coordinate validation
    let gap_err_5_7 = sv6_prior
        .validate_transition(&sv7_next, TransitionKind::Policy)
        .expect_err("5 -> 7 state version gap must fail validate_transition");
    assert!(matches!(
        gap_err_5_7,
        CoordinateError::NotIncrementedByOne { .. }
    ));

    // 6. Transition kind mismatch: validating metadata transition as Commit must fail (epoch did not advance)
    let kind_mismatch_err = creation_coord
        .validate_transition(&sv1_next, TransitionKind::Commit)
        .expect_err("metadata transition evaluated as commit must fail");
    assert!(matches!(
        kind_mismatch_err,
        CoordinateError::FieldMustChange { .. } | CoordinateError::NotIncrementedByOne { .. }
    ));

    // 7. Non-advancing sequence in ApplicationReducer must fail
    test_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(2).unwrap(),
            recipient: alice_binding.clone(),
            previous: creation_coord.clone(),
            next: sv1_next.clone(),
        })
        .unwrap();

    let non_advancing_err = test_reducer
        .apply_sequential_control(&SequentialControl {
            seq: Seq::new(2).unwrap(),
            recipient: alice_binding.clone(),
            previous: sv1_next.clone(),
            next: sv2_next.clone(),
        })
        .expect_err("non-advancing seq must fail");
    assert!(matches!(
        non_advancing_err,
        ReducerError::NotAdvancing { .. }
    ));
}
