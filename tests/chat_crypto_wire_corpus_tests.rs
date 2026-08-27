use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_mls::chat_protocol::{
    encode_application_content, ingest_application_content, verify_application_outer_entry,
    ApplicationBody, ApplicationContentDisposition, ApplicationMlsSender, ConversationContext,
    ExpectedApplicationBinding, Lifecycle, VerifiedApplicationDeviceRegistration,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const FROZEN_MANIFEST_SHA256: &str =
    "40f87efa83bf9d052f725b6d9f7aee4772fe718e2671b3c319f4704aac1dfc84";
const FROZEN_CHAT_PROTOCOL_TREE_SHA256: &str =
    "c2df21a3c4355632223a84e6620a68e94c37692e71098297dc79e6e6d3888284";
const FROZEN_GENERATOR_CARGO_MANIFEST_SHA256: &str =
    "7cbda70b76fc84413263fee75149c2548c5f13638e2755b8ede191cd6d58f3ee";
const FROZEN_GENERATOR_CARGO_LOCK_SHA256: &str =
    "602db6d669d2dbd315e6d439709ee1771702bbde3ea4e6f1896fe8f6292513b1";
const APPLICATION_SEND_BODY_TYPE: &str = "blue.catbird.chat.defs#applicationSendBody";
const APPLICATION_MESSAGE_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-MESSAGE\0";
const ALICE_SIGNING_SEED: [u8; 32] = [
    0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55, 0xa6,
    0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b, 0x12, 0x8d,
];
const TEST_ENTRY_ID: [u8; 16] = [
    0x91, 0x76, 0x1d, 0x4a, 0xc8, 0xc0, 0x45, 0x1b, 0x9c, 0x82, 0x18, 0xd1, 0xce, 0x4c, 0x76, 0x57,
];
const TEST_SIGNED_AT: &str = "2026-07-22T12:34:55.000Z";
const TEST_RECEIVED_AT: &str = "2026-07-22T12:34:56.000Z";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestApplicationAad {
    protocol_version: String,
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    prior: ConversationContext,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestPrivateApplicationMessage {
    framing: String,
    content_type: String,
    #[serde(with = "byte_vec")]
    bytes: Vec<u8>,
    #[serde(with = "bytes32")]
    sha256: [u8; 32],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestApplicationSendBody {
    #[serde(rename = "$type")]
    type_id: String,
    signature_domain: String,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    actor_did: String,
    #[serde(with = "bytes16")]
    actor_device_id: [u8; 16],
    key_id: String,
    auth_generation: u64,
    prior: ConversationContext,
    aad: TestApplicationAad,
    application_message: TestPrivateApplicationMessage,
    blob_bindings: Vec<TestOuterBlobBinding>,
    signed_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestOuterBlobBinding {
    #[serde(with = "bytes16")]
    blob_id: [u8; 16],
    #[serde(with = "bytes32")]
    ciphertext_sha256: [u8; 32],
    ciphertext_size: u64,
    purpose: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestSignedApplicationSend {
    body: TestApplicationSendBody,
    #[serde(with = "bytes64")]
    signature: [u8; 64],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestApplicationEntry {
    #[serde(with = "bytes16")]
    entry_id: [u8; 16],
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    seq: u64,
    signed_request: TestSignedApplicationSend,
    received_at: String,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/generated-artifacts/mls-chat-v1/crypto-wire")
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn hex16(value: &str) -> [u8; 16] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn frozen_crypto_wire_corpus_is_complete_hash_bound_and_consumable() {
    let corpus = corpus_dir();
    let manifest_bytes = fs::read(corpus.join("manifest.json")).unwrap();
    assert_eq!(sha256(&manifest_bytes), FROZEN_MANIFEST_SHA256);
    assert_eq!(manifest_bytes.last(), Some(&b'\n'));
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();

    let files = manifest["files"].as_object().unwrap();
    assert_eq!(files.len(), 10);
    let mut actual_names = fs::read_dir(&corpus)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    actual_names.sort();
    let mut expected_names = files.keys().cloned().collect::<Vec<_>>();
    expected_names.push("manifest.json".to_owned());
    expected_names.sort();
    assert_eq!(
        actual_names, expected_names,
        "corpus must contain exactly 11 files"
    );

    for (name, record) in files {
        let bytes = fs::read(corpus.join(name)).unwrap();
        assert_eq!(
            bytes.len() as u64,
            record["length"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            sha256(&bytes),
            record["sha256Hex"].as_str().unwrap(),
            "{name}"
        );
    }

    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let generator = fs::read(crate_root.join("examples/generate_mls_chat_crypto_wire.rs")).unwrap();
    assert_eq!(sha256(&generator), manifest["generator"]["sourceSha256Hex"]);
    // Cargo inputs are immutable provenance of the frozen generation event,
    // not a requirement that this crate can never add another dependency.
    assert_eq!(
        manifest["generator"]["cargoManifestSha256Hex"],
        FROZEN_GENERATOR_CARGO_MANIFEST_SHA256
    );
    assert_eq!(
        manifest["generator"]["cargoLockSha256Hex"],
        FROZEN_GENERATOR_CARGO_LOCK_SHA256
    );
    assert_eq!(
        manifest["generator"]["chatProtocolSourceTreeSha256Hex"],
        FROZEN_CHAT_PROTOCOL_TREE_SHA256
    );

    assert_eq!(manifest["protocol"], "blue.catbird.chat");
    assert_eq!(manifest["protocolVersion"], "1");
    assert_eq!(manifest["cipherSuite"]["code"], 77);
    assert_eq!(manifest["chain"]["generation"], 0);
    assert_eq!(manifest["chain"]["committedEpoch"], 1);
    assert_eq!(manifest["chain"]["committedStateVersion"], 1);

    verify_wrappers(&corpus, files);
    verify_public_snapshots(&corpus, &manifest);
    verify_application_frame_and_sender(&corpus, &manifest);

    let key_package_ref = fs::read(corpus.join("key-package-ref.bin")).unwrap();
    assert_eq!(key_package_ref.len(), 32);
    assert_eq!(
        hex::encode(key_package_ref),
        manifest["chain"]["innerKeyPackageRefHex"]
    );
}

fn verify_wrappers(corpus: &Path, files: &serde_json::Map<String, Value>) {
    for (name, record) in files {
        let Some(wire_format) = record.get("wireFormat").and_then(Value::as_u64) else {
            continue;
        };
        let bytes = fs::read(corpus.join(name)).unwrap();
        assert!(bytes.len() >= 4, "{name}");
        assert_eq!(
            u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            1,
            "{name}"
        );
        assert_eq!(
            u64::from(u16::from_be_bytes(bytes[2..4].try_into().unwrap())),
            wire_format,
            "{name}"
        );
    }
}

fn verify_application_frame_and_sender(corpus: &Path, manifest: &Value) {
    let message_id = hex16(manifest["identifiers"]["messageIdHex"].as_str().unwrap());
    let context = ConversationContext {
        conversation_id: hex16(
            manifest["identifiers"]["conversationIdHex"]
                .as_str()
                .unwrap(),
        ),
        generation: manifest["chain"]["generation"].as_u64().unwrap(),
        state_version: manifest["chain"]["committedStateVersion"].as_u64().unwrap(),
        group_id: hex32(manifest["chain"]["groupIdHex"].as_str().unwrap()),
        epoch: manifest["chain"]["committedEpoch"].as_u64().unwrap(),
        group_context_hash: hex32(
            manifest["chain"]["committedGroupContextHashHex"]
                .as_str()
                .unwrap(),
        ),
        confirmation_tag: hex32(
            manifest["chain"]["committedConfirmationTagHex"]
                .as_str()
                .unwrap(),
        ),
        lifecycle: Lifecycle::Active,
    };
    // This expectation is built independently from manifest coordinates. It
    // deliberately does not use ExpectedApplicationBinding::from_frame.
    let expected = ExpectedApplicationBinding {
        message_id,
        context: context.clone(),
    };
    let bytes = fs::read(corpus.join("application-frame.cbor")).unwrap();
    let alice = &manifest["identity"]["alice"];
    let signature_public_key = hex32(alice["signaturePublicKeyHex"].as_str().unwrap());
    let signing_key = SigningKey::from_bytes(&ALICE_SIGNING_SEED);
    assert_eq!(signing_key.verifying_key().to_bytes(), signature_public_key);
    let key_id = alice["keyId"].as_str().unwrap();
    assert_eq!(
        key_id,
        URL_SAFE_NO_PAD.encode(Sha256::digest(signature_public_key))
    );
    let actor_device_id = *uuid::Uuid::parse_str(alice["deviceId"].as_str().unwrap())
        .unwrap()
        .as_bytes();
    let application_message = fs::read(corpus.join("application-private.mls")).unwrap();
    let application_message_sha256 = Sha256::digest(&application_message).into();
    let body = TestApplicationSendBody {
        type_id: APPLICATION_SEND_BODY_TYPE.to_owned(),
        signature_domain: String::from_utf8(APPLICATION_MESSAGE_SIGNATURE_DOMAIN.to_vec()).unwrap(),
        message_id,
        actor_did: alice["actorDid"].as_str().unwrap().to_owned(),
        actor_device_id,
        key_id: key_id.to_owned(),
        auth_generation: 1,
        prior: context.clone(),
        aad: TestApplicationAad {
            protocol_version: "1".to_owned(),
            conversation_id: context.conversation_id,
            generation: context.generation,
            message_id,
            prior: context.clone(),
        },
        application_message: TestPrivateApplicationMessage {
            framing: "mlsMessage".to_owned(),
            content_type: "privateMessageApplication".to_owned(),
            bytes: application_message.clone(),
            sha256: application_message_sha256,
        },
        blob_bindings: vec![],
        signed_at: TEST_SIGNED_AT.to_owned(),
    };
    let unsigned_projection = serde_ipld_dagcbor::to_vec(&body).unwrap();
    let mut signing_transcript = APPLICATION_MESSAGE_SIGNATURE_DOMAIN.to_vec();
    signing_transcript.extend_from_slice(&unsigned_projection);
    let signature = signing_key.sign(&signing_transcript).to_bytes();
    let entry = TestApplicationEntry {
        entry_id: TEST_ENTRY_ID,
        conversation_id: context.conversation_id,
        seq: 1,
        signed_request: TestSignedApplicationSend { body, signature },
        received_at: TEST_RECEIVED_AT.to_owned(),
    };
    let entry_cbor = serde_ipld_dagcbor::to_vec(&entry).unwrap();
    let registered_device = VerifiedApplicationDeviceRegistration::test_only(
        alice["actorDid"].as_str().unwrap().to_owned(),
        alice["deviceId"].as_str().unwrap().to_owned(),
        key_id.to_owned(),
        1,
        &signature_public_key,
    )
    .unwrap();
    let verified_outer = verify_application_outer_entry(&entry_cbor, &registered_device).unwrap();
    assert_eq!(verified_outer.raw_entry(), entry_cbor);
    assert_eq!(verified_outer.expected_binding(), &expected);
    assert_eq!(verified_outer.entry_id(), TEST_ENTRY_ID);
    assert_eq!(verified_outer.seq(), 1);
    assert_ne!(verified_outer.fingerprint(), [0; 32]);
    assert_eq!(verified_outer.application_message(), application_message);
    assert_eq!(
        verified_outer.application_message_sha256(),
        application_message_sha256
    );
    let sender = ApplicationMlsSender::test_only(
        true,
        alice["credentialIdentity"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
        signature_public_key.to_vec(),
    );
    let ApplicationContentDisposition::Supported(verified) =
        ingest_application_content(bytes.clone(), &verified_outer, &sender)
    else {
        panic!("frozen application must pass the production authority");
    };
    assert_eq!(verified.frame().message_id, message_id);
    let ApplicationBody::Message(message) = &verified.frame().body else {
        panic!("frozen application is not a message");
    };
    assert_eq!(
        message.text.as_deref(),
        Some("blue.catbird.chat frozen interoperability proof")
    );
    assert!(message.reply_to.is_none() && message.embed.is_none());
    assert_eq!(encode_application_content(verified.frame()).unwrap(), bytes);
    assert_eq!(verified.raw_plaintext(), bytes);
    assert_eq!(verified.sender().actor_did(), alice["actorDid"]);
    assert!(verified.attachment_aad().is_none());
}

fn verify_public_snapshots(corpus: &Path, manifest: &Value) {
    let expected_labels = [
        "ConfirmationTag",
        "GroupContext",
        "InterimTranscriptHash",
        "Tree",
    ];
    let mut prior_keys: Option<Vec<Vec<u8>>> = None;
    for (name, key_field) in [
        ("genesis-public-state.bin", "genesisRecordKeyHex"),
        ("committed-public-state.bin", "committedRecordKeyHex"),
    ] {
        let bytes = fs::read(corpus.join(name)).unwrap();
        let records = decode_snapshot(&bytes);
        assert_eq!(records.len(), 4);
        let keys = records
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let expected_keys = manifest["publicSnapshots"][key_field]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| hex::decode(value.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, expected_keys, "{name}");
        let mut labels = Vec::new();
        for key in &keys {
            let label = expected_labels
                .iter()
                .find(|label| key.starts_with(label.as_bytes()))
                .unwrap();
            labels.push(*label);
            assert!(key.ends_with(&[0, 1]));
        }
        labels.sort();
        assert_eq!(labels, expected_labels);
        if let Some(prior) = &prior_keys {
            assert_eq!(&keys, prior, "snapshots must use the same four public keys");
        }
        prior_keys = Some(keys);
    }
}

fn decode_snapshot(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    assert!(!bytes.is_empty() && bytes.len() <= 8 * 1024 * 1024);
    let mut cursor = Cursor { bytes, offset: 0 };
    assert_eq!(cursor.take(8), b"CBPGSNAP");
    assert_eq!(cursor.u16(), 1);
    let openmls_len = usize::from(cursor.u16());
    assert_eq!(cursor.take(openmls_len), b"0.8.1");
    let storage_len = usize::from(cursor.u16());
    assert_eq!(cursor.take(storage_len), b"0.5.0");
    let count = cursor.u32() as usize;
    assert_eq!(count, 4);
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let key_len = cursor.u32() as usize;
        assert!((1..=65_536).contains(&key_len));
        let key = cursor.take(key_len).to_vec();
        let value_len = cursor.u32() as usize;
        assert!((1..=4 * 1024 * 1024).contains(&value_len));
        let value = cursor.take(value_len).to_vec();
        if let Some((previous, _)) = records.last() {
            assert!(previous < &key);
        }
        records.push((key, value));
    }
    assert_eq!(
        cursor.offset,
        bytes.len(),
        "snapshot must end exactly after record four"
    );
    records
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> &'a [u8] {
        let end = self.offset.checked_add(len).unwrap();
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        value
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
}

mod byte_vec {
    use serde::{ser::Error as _, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.is_empty() {
            return Err(S::Error::custom("byte string must not be empty"));
        }
        serializer.serialize_bytes(value)
    }
}

mod bytes16 {
    use serde::Serializer;

    pub fn serialize<S>(value: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }
}

mod bytes32 {
    use serde::Serializer;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }
}

mod bytes64 {
    use serde::Serializer;

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }
}
