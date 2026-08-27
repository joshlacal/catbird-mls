//! Opt-in generator for the authoritative `blue.catbird.chat` v1 wire corpus.
//!
//! This is intentionally an executable proof, not a collection of hand-written
//! bytes. It creates a live XWing MLS group, tracks its public state in a
//! separate provider, joins Bob through the generated Welcome, and decrypts an
//! application frame produced by the crate's authoritative DAG-CBOR and MLS-AAD
//! codecs. The resulting random HPKE material and group id are frozen in the
//! checked-in corpus.
//!
//! Regeneration is destructive inside the corpus directory and therefore
//! requires the explicit environment opt-in documented in `main`.

// The manifest is assembled with large `serde_json::json!` literals; the added
// `creation` object pushes past the default macro recursion limit.
#![recursion_limit = "256"]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use openmls_traits::OpenMlsProvider;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes};
use uuid::{Uuid, Version};

use catbird_mls::chat_v2::ids::KeyId;

const OPT_IN_ENV: &str = "CATBIRD_REGENERATE_MLS_CHAT_CRYPTO_WIRE";
const OPT_IN_VALUE: &str = "1";
/// Optional scratch-output override for testing emission without writing the
/// freeze-guarded corpus. Unset (default) writes the canonical corpus directory.
const OUTPUT_DIR_ENV: &str = "CATBIRD_MLS_CHAT_CRYPTO_WIRE_OUT_DIR";
const PROTOCOL: &str = "blue.catbird.chat";
const PROTOCOL_VERSION: &str = "1";
const OPENMLS_VERSION: &str = "0.9.0-rc.3";
const STORAGE_VERSION: &str = "0.6.0-rc.3";
const OFFICIAL_CLIENT_REVISION: &str = "e7c2437e845eb767d2cdd22eece2b3c5d484e4e7";
const EXPECTED_FORK_REVISION: &str = "3ea192fc346663fba5db63aa8c90ccc3ae49f12b";

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const CIPHERSUITE_NAME: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const CIPHERSUITE_CODE: u16 = 0x004D;
const LIFETIME_PAST_SKEW_SECONDS: u64 = 60;
const LIFETIME_FUTURE_SECONDS: u64 = 24 * 60 * 60;

const ALICE_ACTOR_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
const BOB_ACTOR_DID: &str = "did:plc:bobterminalccccccccccccc";
const ALICE_DEVICE_ID: [u8; 16] = [
    0x2f, 0x93, 0xa8, 0x2d, 0xb0, 0x61, 0x4c, 0x75, 0x8f, 0x61, 0x57, 0xf2, 0x31, 0x46, 0xb9, 0x10,
];
const BOB_DEVICE_ID: [u8; 16] = [
    0xb4, 0x0c, 0x12, 0xd9, 0xb1, 0xff, 0x4b, 0x24, 0x94, 0xe5, 0x15, 0x74, 0x2d, 0x9e, 0xa6, 0xcf,
];
const CONVERSATION_ID: [u8; 16] = [
    0xf4, 0x3f, 0x8f, 0xb7, 0x3f, 0x8c, 0x49, 0x35, 0xb3, 0x30, 0x99, 0x00, 0xc0, 0x38, 0x00, 0x96,
];
const TRANSITION_ID: [u8; 16] = [
    0x55, 0x2e, 0x98, 0x88, 0xaa, 0xa5, 0x4d, 0xd4, 0xab, 0xcb, 0x83, 0x4d, 0xde, 0x34, 0x9b, 0x36,
];
const GENERIC_TRANSITION_ID: [u8; 16] = [
    0x4f, 0x71, 0x2c, 0xb6, 0x85, 0x7a, 0x4b, 0x47, 0x98, 0xa1, 0xa6, 0xe5, 0x5a, 0xe6, 0x53, 0x8d,
];
const LEAVE_FULFILLMENT_TRANSITION_ID: [u8; 16] = [
    0x0e, 0xa9, 0xb8, 0x3f, 0xc2, 0xa9, 0x41, 0x61, 0x8e, 0xb6, 0x4b, 0x30, 0x45, 0xc0, 0x98, 0x2a,
];
const REJOIN_TRANSITION_ID: [u8; 16] = [
    0xeb, 0xc2, 0x46, 0x85, 0x4c, 0x7e, 0x4e, 0x2a, 0x86, 0x49, 0xfe, 0xe1, 0xdd, 0xb9, 0x62, 0xa5,
];
const MESSAGE_ID: [u8; 16] = [
    0x84, 0xae, 0x72, 0xa8, 0xa7, 0x53, 0x4c, 0xe3, 0xbd, 0xfe, 0x76, 0x2f, 0x42, 0x31, 0xfd, 0x7e,
];
const ALICE_SIGNING_SEED: [u8; 32] = [
    0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55, 0xa6,
    0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b, 0x12, 0x8d,
];
const BOB_SIGNING_SEED: [u8; 32] = [
    0xd4, 0xa1, 0xc4, 0x8e, 0x33, 0x92, 0x40, 0x8e, 0x24, 0x40, 0x90, 0x3f, 0xc5, 0x67, 0x8d, 0xa5,
    0x69, 0x98, 0xeb, 0x66, 0xeb, 0xb8, 0xa9, 0x64, 0xa7, 0xe4, 0xe4, 0xc2, 0xad, 0x82, 0xe9, 0xb5,
];

const CREATION_ENTRY_TYPE: &str = "blue.catbird.chat.defs#creationEntry";
const CREATION_BODY_TYPE: &str = "blue.catbird.chat.defs#creationBody";
const CREATION_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-CREATE\0";

const ALICE_CREATION_TRANSITION_ID: [u8; 16] = [
    0xbd, 0x13, 0x5b, 0xbe, 0x8b, 0x70, 0x4c, 0x2b, 0x98, 0x23, 0x96, 0x62, 0xb0, 0xfe, 0x6d, 0x3b,
];
const CREATION_IDEMPOTENCY_KEY: [u8; 16] = [
    0x2d, 0xe8, 0x96, 0x28, 0x71, 0x36, 0x4e, 0x92, 0x9a, 0xb0, 0xd7, 0x55, 0x74, 0xf7, 0x95, 0x4f,
];
const CREATION_METADATA_NONCE: [u8; 12] = [
    0x86, 0x20, 0xf1, 0x3a, 0x12, 0x21, 0x01, 0xc3, 0x60, 0x8b, 0x42, 0x3e,
];
const CREATION_METADATA_VERSION: u64 = 1;
const METADATA_EXPORTER_LABEL: &str = "blue.catbird.chat.metadata.v1";
const METADATA_EXPORTER_OUTPUT_LENGTH: usize = 32;

const CREATION_SIGNED_REQUEST_FILE: &str = "creation-signed-request.cbor";

macro_rules! creation_fixed_bytes {
    ($module:ident, $length:expr) => {
        mod $module {
            use serde::Serializer;
            pub fn serialize<S>(bytes: &[u8; $length], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(bytes)
            }

            #[allow(dead_code)]
            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; $length], D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct ByteVisitor;
                impl<'de> serde::de::Visitor<'de> for ByteVisitor {
                    type Value = [u8; $length];
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("byte array")
                    }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                        v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
                    }
                    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                        self.visit_bytes(&v)
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                        let mut arr = [0u8; $length];
                        for i in 0..$length {
                            arr[i] = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                        }
                        Ok(arr)
                    }
                }
                deserializer.deserialize_bytes(ByteVisitor)
            }
        }
    };
}
creation_fixed_bytes!(cbytes16, 16);
creation_fixed_bytes!(cbytes32, 32);
creation_fixed_bytes!(cbytes64, 64);

mod cbyte_vec {
    use serde::Serializer;
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }
}

#[derive(Debug)]
struct GeneratorError(String);

impl fmt::Display for GeneratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for GeneratorError {}

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(GeneratorError(message.into()))
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(fail(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationContext {
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    state_version: u64,
    #[serde(with = "cbytes32")]
    group_id: [u8; 32],
    epoch: u64,
    #[serde(with = "cbytes32")]
    group_context_hash: [u8; 32],
    #[serde(with = "cbytes32")]
    confirmation_tag: [u8; 32],
    lifecycle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MetadataCoordinate {
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    #[serde(with = "cbytes32")]
    group_id: [u8; 32],
    epoch: u64,
    #[serde(with = "cbytes32")]
    group_context_hash: [u8; 32],
    #[serde(with = "cbytes32")]
    confirmation_tag: [u8; 32],
}

impl MetadataCoordinate {
    fn from_conversation_context(context: &ConversationContext) -> Self {
        Self {
            conversation_id: context.conversation_id,
            generation: context.generation,
            group_id: context.group_id,
            epoch: context.epoch,
            group_context_hash: context.group_context_hash,
            confirmation_tag: context.confirmation_tag,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitAad<'a> {
    protocol_version: &'static str,
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    #[serde(with = "cbytes16")]
    transition_id: [u8; 16],
    prior: &'a ConversationContext,
}

fn encode_mls_commit_aad(
    conversation_id: [u8; 16],
    generation: u64,
    transition_id: [u8; 16],
    prior: &ConversationContext,
) -> Result<Vec<u8>> {
    let aad_body = CommitAad {
        protocol_version: "1",
        conversation_id,
        generation,
        transition_id,
        prior,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&aad_body)?;
    let mut out = Vec::with_capacity(b"CATBIRD-CHAT-MLS-AAD-COMMIT\0".len() + cbor.len());
    out.extend_from_slice(b"CATBIRD-CHAT-MLS-AAD-COMMIT\0");
    out.extend_from_slice(&cbor);
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationAad<'a> {
    protocol_version: &'static str,
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    #[serde(with = "cbytes16")]
    message_id: [u8; 16],
    prior: &'a ConversationContext,
}

fn encode_mls_application_aad(
    conversation_id: [u8; 16],
    generation: u64,
    message_id: [u8; 16],
    prior: &ConversationContext,
) -> Result<Vec<u8>> {
    let aad_body = ApplicationAad {
        protocol_version: "1",
        conversation_id,
        generation,
        message_id,
        prior,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&aad_body)?;
    let mut out = Vec::with_capacity(b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0".len() + cbor.len());
    out.extend_from_slice(b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0");
    out.extend_from_slice(&cbor);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    embed: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ApplicationBody {
    Message(MessageBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationFrame {
    protocol: String,
    version: u32,
    #[serde(with = "cbytes16")]
    message_id: [u8; 16],
    context: ConversationContext,
    body: ApplicationBody,
}

fn encode_application_content(frame: &ApplicationFrame) -> Result<Vec<u8>> {
    Ok(serde_ipld_dagcbor::to_vec(frame)?)
}

fn decode_application_frame(bytes: &[u8]) -> Result<ApplicationFrame> {
    Ok(serde_ipld_dagcbor::from_slice(bytes)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataExporterContext<'a> {
    protocol: &'static str,
    version: u32,
    coordinate: &'a MetadataCoordinate,
    metadata_version: u64,
    #[serde(with = "cbytes16")]
    origin_transition_id: [u8; 16],
    #[serde(rename = "ciphertextSize")]
    ciphertext_size: u64,
}

fn metadata_exporter_context(
    coordinate: &MetadataCoordinate,
    metadata_version: u64,
    origin_transition_id: [u8; 16],
    ciphertext_size: u64,
) -> Result<Vec<u8>> {
    let ctx = MetadataExporterContext {
        protocol: "blue.catbird.chat.metadata",
        version: 1,
        coordinate,
        metadata_version,
        origin_transition_id,
        ciphertext_size,
    };
    Ok(serde_ipld_dagcbor::to_vec(&ctx)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataContent {
    #[serde(with = "cbytes16")]
    origin_transition_id: [u8; 16],
    metadata_version: u64,
    author_did: String,
    #[serde(with = "cbytes16")]
    author_device_id: [u8; 16],
    author_key_id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<Value>,
}

fn metadata_content_signing_input(content: &MetadataContent) -> Result<Vec<u8>> {
    let cbor = serde_ipld_dagcbor::to_vec(content)?;
    let mut out = Vec::with_capacity(b"CATBIRD-CHAT-METADATA-CONTENT\0".len() + cbor.len());
    out.extend_from_slice(b"CATBIRD-CHAT-METADATA-CONTENT\0");
    out.extend_from_slice(&cbor);
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataPlaintext {
    content: MetadataContent,
    #[serde(with = "cbytes64")]
    content_signature: [u8; 64],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataAad<'a> {
    protocol: &'static str,
    version: u32,
    coordinate: &'a MetadataCoordinate,
    metadata_version: u64,
    #[serde(with = "cbytes16")]
    origin_transition_id: [u8; 16],
    #[serde(rename = "ciphertextSize")]
    ciphertext_size: u64,
}

fn seal_metadata_with_nonce(
    plaintext: &MetadataPlaintext,
    coordinate: &MetadataCoordinate,
    exporter_key: &[u8],
    nonce_bytes: &[u8; 12],
    origin_transition_id: [u8; 16],
    metadata_version: u64,
) -> Result<(Vec<u8>, [u8; 32], u64)> {
    let plaintext_cbor = serde_ipld_dagcbor::to_vec(plaintext)?;
    let cipher = Aes256Gcm::new_from_slice(exporter_key)
        .map_err(|e| fail(format!("AES-256-GCM key init: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext_size = (plaintext_cbor.len() + 16) as u64;
    let aad_struct = MetadataAad {
        protocol: "blue.catbird.chat.metadata",
        version: 1,
        coordinate,
        metadata_version,
        origin_transition_id,
        ciphertext_size,
    };
    let aad_cbor = serde_ipld_dagcbor::to_vec(&aad_struct)?;
    let mut aad = Vec::with_capacity(b"CATBIRD-CHAT-METADATA\0".len() + aad_cbor.len());
    aad.extend_from_slice(b"CATBIRD-CHAT-METADATA\0");
    aad.extend_from_slice(&aad_cbor);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext_cbor,
                aad: &aad,
            },
        )
        .map_err(|e| fail(format!("AES-256-GCM encrypt: {e}")))?;
    ensure(
        ciphertext.len() as u64 == ciphertext_size,
        "ciphertext size mismatch",
    )?;
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
    Ok((ciphertext, ciphertext_sha256, ciphertext_size))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationActorLeaf {
    user_did: String,
    #[serde(with = "cbytes16")]
    device_id: [u8; 16],
    leaf_origin: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationParticipant {
    role: String,
    status: String,
    user_did: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationManifest {
    actor_leaf: CreationActorLeaf,
    participants: Vec<CreationParticipant>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationFramedArtifact {
    #[serde(with = "cbyte_vec")]
    bytes: Vec<u8>,
    #[serde(with = "cbytes32")]
    sha256: [u8; 32],
    framing: String,
    content_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationMetadataAuthorProof {
    author_did: String,
    origin_seq: u64,
    author_key_id: String,
    role_at_origin: String,
    #[serde(with = "cbytes16")]
    author_device_id: [u8; 16],
    #[serde(with = "cbytes16")]
    origin_transition_id: [u8; 16],
    #[serde(with = "cbytes32")]
    signature_public_key: [u8; 32],
    device_status_at_origin: String,
    auth_generation_at_origin: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationMetadataSnapshot {
    #[serde(with = "cbyte_vec")]
    nonce: Vec<u8>,
    #[serde(with = "cbyte_vec")]
    ciphertext: Vec<u8>,
    coordinate: MetadataCoordinate,
    author_proof: CreationMetadataAuthorProof,
    ciphertext_size: u64,
    metadata_version: u64,
    #[serde(with = "cbytes32")]
    ciphertext_sha256: [u8; 32],
    #[serde(with = "cbytes16")]
    origin_transition_id: [u8; 16],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationBody {
    #[serde(rename = "$type")]
    type_id: String,
    signature_domain: String,
    #[serde(with = "cbytes16")]
    transition_id: [u8; 16],
    actor_did: String,
    #[serde(with = "cbytes16")]
    actor_device_id: [u8; 16],
    key_id: String,
    auth_generation: u64,
    next: ConversationContext,
    absence: bool,
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    conversation_kind: String,
    manifest: CreationManifest,
    genesis_group_info: CreationFramedArtifact,
    metadata_snapshot: CreationMetadataSnapshot,
    #[serde(with = "cbytes16")]
    idempotency_key: [u8; 16],
    signed_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedCreation {
    body: CreationBody,
    #[serde(with = "cbytes64")]
    signature: [u8; 64],
}

struct CreationArtifact {
    signed_request_cbor: Vec<u8>,
    unsigned_body_projection_cbor: Vec<u8>,
    signing_transcript: Vec<u8>,
    signature: [u8; 64],
    request_digest: [u8; 32],
    key_id: String,
    metadata_ciphertext_sha256: [u8; 32],
    metadata_ciphertext_size: u64,
    metadata_exporter_context: Vec<u8>,
}

fn build_alice_creation_artifact(
    alice_group: &MlsGroup,
    alice_provider: &Provider,
    alice_public_key: &[u8],
    genesis_context: &ConversationContext,
    group_info_bytes: &[u8],
    signed_at: &str,
    _received_at: &str,
) -> Result<CreationArtifact> {
    ensure(
        alice_group.epoch().as_u64() == 0,
        "creation artifact must be built from the genesis epoch",
    )?;
    let alice_pub: [u8; 32] = alice_public_key
        .try_into()
        .map_err(|_| fail("alice public key is not 32 bytes"))?;
    let key_id = KeyId::from_public_key(&alice_pub).to_string();
    let signing_key = SigningKey::from_bytes(&ALICE_SIGNING_SEED);

    let coordinate = MetadataCoordinate::from_conversation_context(genesis_context);
    let content = MetadataContent {
        origin_transition_id: ALICE_CREATION_TRANSITION_ID,
        metadata_version: CREATION_METADATA_VERSION,
        author_did: ALICE_ACTOR_DID.to_owned(),
        author_device_id: ALICE_DEVICE_ID,
        author_key_id: key_id.clone(),
        title: String::new(),
        description: None,
        avatar: None,
    };
    let content_signing_input = metadata_content_signing_input(&content)?;
    let content_signature = signing_key.sign(&content_signing_input).to_bytes();
    let plaintext = MetadataPlaintext {
        content,
        content_signature,
    };
    let plaintext_cbor = serde_ipld_dagcbor::to_vec(&plaintext)?;
    let expected_ciphertext_size = (plaintext_cbor.len() + 16) as u64;

    let exporter_context = metadata_exporter_context(
        &coordinate,
        CREATION_METADATA_VERSION,
        ALICE_CREATION_TRANSITION_ID,
        expected_ciphertext_size,
    )?;
    let exporter_key = alice_group
        .export_secret(
            alice_provider.crypto(),
            METADATA_EXPORTER_LABEL,
            &exporter_context,
            METADATA_EXPORTER_OUTPUT_LENGTH,
        )
        .map_err(|error| fail(format!("metadata exporter secret: {error}")))?;

    let (ciphertext, ciphertext_sha256, ciphertext_size) = seal_metadata_with_nonce(
        &plaintext,
        &coordinate,
        &exporter_key,
        &CREATION_METADATA_NONCE,
        ALICE_CREATION_TRANSITION_ID,
        CREATION_METADATA_VERSION,
    )?;

    let metadata_snapshot = CreationMetadataSnapshot {
        nonce: CREATION_METADATA_NONCE.to_vec(),
        ciphertext,
        coordinate: MetadataCoordinate::from_conversation_context(genesis_context),
        author_proof: CreationMetadataAuthorProof {
            author_did: ALICE_ACTOR_DID.to_owned(),
            origin_seq: 1,
            author_key_id: key_id.clone(),
            role_at_origin: "admin".to_owned(),
            author_device_id: ALICE_DEVICE_ID,
            origin_transition_id: ALICE_CREATION_TRANSITION_ID,
            signature_public_key: alice_pub,
            device_status_at_origin: "active".to_owned(),
            auth_generation_at_origin: 1,
        },
        ciphertext_size,
        metadata_version: CREATION_METADATA_VERSION,
        ciphertext_sha256,
        origin_transition_id: ALICE_CREATION_TRANSITION_ID,
    };

    let body = CreationBody {
        type_id: CREATION_BODY_TYPE.to_owned(),
        signature_domain: String::from_utf8(CREATION_SIGNATURE_DOMAIN.to_vec())
            .map_err(|_| fail("creation signature domain is not UTF-8"))?,
        transition_id: ALICE_CREATION_TRANSITION_ID,
        actor_did: ALICE_ACTOR_DID.to_owned(),
        actor_device_id: ALICE_DEVICE_ID,
        key_id: key_id.clone(),
        auth_generation: 1,
        next: genesis_context.clone(),
        absence: true,
        conversation_id: CONVERSATION_ID,
        conversation_kind: "direct".to_owned(),
        manifest: CreationManifest {
            actor_leaf: CreationActorLeaf {
                user_did: ALICE_ACTOR_DID.to_owned(),
                device_id: ALICE_DEVICE_ID,
                leaf_origin: "genesis".to_owned(),
            },
            participants: vec![
                CreationParticipant {
                    role: "admin".to_owned(),
                    status: "active".to_owned(),
                    user_did: ALICE_ACTOR_DID.to_owned(),
                },
                CreationParticipant {
                    role: "admin".to_owned(),
                    status: "pending".to_owned(),
                    user_did: BOB_ACTOR_DID.to_owned(),
                },
            ],
        },
        genesis_group_info: CreationFramedArtifact {
            bytes: group_info_bytes.to_vec(),
            sha256: Sha256::digest(group_info_bytes).into(),
            framing: "mlsMessage".to_owned(),
            content_type: "groupInfo".to_owned(),
        },
        metadata_snapshot,
        idempotency_key: CREATION_IDEMPOTENCY_KEY,
        signed_at: signed_at.to_owned(),
    };

    let unsigned_body_projection_cbor = serde_ipld_dagcbor::to_vec(&body)?;
    let mut signing_transcript =
        Vec::with_capacity(CREATION_SIGNATURE_DOMAIN.len() + unsigned_body_projection_cbor.len());
    signing_transcript.extend_from_slice(CREATION_SIGNATURE_DOMAIN);
    signing_transcript.extend_from_slice(&unsigned_body_projection_cbor);
    let signature = signing_key.sign(&signing_transcript).to_bytes();
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript).into();

    let signed_request = SignedCreation { body, signature };
    let signed_request_cbor = serde_ipld_dagcbor::to_vec(&signed_request)?;

    // Strict self-verification
    let key_id_parsed = KeyId::from_public_key(&alice_pub);
    ensure(
        key_id == key_id_parsed.to_string(),
        "creation keyId is not ed25519_key_id(alice_pub)",
    )?;
    catbird_mls::chat_v2::transcript::verify_ed25519_strict(
        &alice_pub,
        &signing_transcript,
        &signature,
    )
    .map_err(|e| fail(format!("verify_ed25519_strict failed: {e}")))?;
    Ok(CreationArtifact {
        signed_request_cbor,
        unsigned_body_projection_cbor,
        signing_transcript,
        signature,
        request_digest,
        key_id,
        metadata_ciphertext_sha256: ciphertext_sha256,
        metadata_ciphertext_size: ciphertext_size,
        metadata_exporter_context: exporter_context,
    })
}

fn main() -> Result<()> {
    if std::env::var(OPT_IN_ENV).as_deref() != Ok(OPT_IN_VALUE) {
        return Err(fail(format!(
            "refusing to regenerate frozen corpus; rerun with {OPT_IN_ENV}={OPT_IN_VALUE}"
        )));
    }

    let fork_rev = std::env::var("CATBIRD_OPENMLS_FORK_REV")
        .map_err(|_| fail("missing required CATBIRD_OPENMLS_FORK_REV env var"))?;
    ensure(
        fork_rev.len() == 40 && fork_rev.chars().all(|c| c.is_ascii_hexdigit()),
        "CATBIRD_OPENMLS_FORK_REV must be a 40-hex string",
    )?;
    ensure(
        fork_rev == EXPECTED_FORK_REVISION,
        format!("CATBIRD_OPENMLS_FORK_REV does not match Task 1 published revision {EXPECTED_FORK_REVISION}: {fork_rev}"),
    )?;

    ensure(
        CIPHERSUITE as u16 == CIPHERSUITE_CODE,
        "XWing codepoint drift",
    )?;
    for identifier in [
        ALICE_DEVICE_ID,
        BOB_DEVICE_ID,
        CONVERSATION_ID,
        TRANSITION_ID,
        MESSAGE_ID,
    ] {
        ensure_uuid_v4(identifier)?;
    }
    assert_fixture_plc_did(ALICE_ACTOR_DID)?;
    assert_fixture_plc_did(BOB_ACTOR_DID)?;
    ensure(
        ALICE_ACTOR_DID != BOB_ACTOR_DID,
        "fixture actors must be distinct",
    )?;

    let evaluation_unix_seconds = unix_time()?;
    let creation_signed_at = DateTime::<Utc>::from_timestamp(
        i64::try_from(evaluation_unix_seconds)
            .map_err(|_| fail("evaluation time does not fit signed timestamp"))?,
        0,
    )
    .ok_or_else(|| fail("evaluation time is outside chrono range"))?
    .format("%Y-%m-%dT%H:%M:%S.000Z")
    .to_string();
    let creation_received_at = DateTime::<Utc>::from_timestamp(
        i64::try_from(
            evaluation_unix_seconds
                .checked_add(1)
                .ok_or_else(|| fail("creation receive time overflow"))?,
        )
        .map_err(|_| fail("creation receive time does not fit timestamp"))?,
        0,
    )
    .ok_or_else(|| fail("creation receive time is outside chrono range"))?
    .format("%Y-%m-%dT%H:%M:%S.000Z")
    .to_string();
    let not_before = evaluation_unix_seconds
        .checked_sub(LIFETIME_PAST_SKEW_SECONDS)
        .ok_or_else(|| fail("evaluation time cannot accommodate lifetime skew"))?;
    let not_after = evaluation_unix_seconds
        .checked_add(LIFETIME_FUTURE_SECONDS)
        .ok_or_else(|| fail("fixture lifetime overflow"))?;
    let lifetime = Lifetime::init(not_before, not_after);
    ensure(
        lifetime.validate().is_ok(),
        "fixture lifetime is not currently valid",
    )?;
    ensure(
        lifetime.has_acceptable_range(),
        "fixture lifetime exceeds OpenMLS policy",
    )?;

    let alice_provider = Provider::new()?;
    let bob_provider = Provider::new()?;
    let public_provider = Provider::new()?;
    let alice_signer = fixed_signer(ALICE_SIGNING_SEED);
    let bob_signer = fixed_signer(BOB_SIGNING_SEED);
    alice_signer.store(alice_provider.storage())?;
    bob_signer.store(bob_provider.storage())?;

    let alice_device_id = uuid_string(ALICE_DEVICE_ID)?;
    let bob_device_id = uuid_string(BOB_DEVICE_ID)?;
    let alice_credential_identity = format!("{ALICE_ACTOR_DID}#{alice_device_id}");
    let bob_credential_identity = format!("{BOB_ACTOR_DID}#{bob_device_id}");
    let alice_public_key = alice_signer.to_public_vec();
    let bob_public_key = bob_signer.to_public_vec();

    let mut group_id = [0u8; 32];
    OsRng.try_fill_bytes(&mut group_id)?;
    ensure(
        group_id.iter().any(|byte| *byte != 0),
        "random group id is zero",
    )?;

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_capabilities())
        .lifetime(lifetime)
        .build();
    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &group_config,
        GroupId::from_slice(&group_id),
        credential_with_key(&alice_credential_identity, &alice_public_key),
    )?;
    ensure(
        alice_group.epoch().as_u64() == 0,
        "genesis epoch is not zero",
    )?;
    ensure(
        alice_group
            .export_group_context()
            .extensions()
            .iter()
            .next()
            .is_none(),
        "genesis GroupContext extensions are not empty",
    )?;
    assert_exact_member_profile(
        alice_group
            .own_leaf_node()
            .ok_or_else(|| fail("Alice genesis leaf is missing"))?,
        &alice_credential_identity,
        &alice_public_key,
    )?;
    assert_key_package_leaf_source(
        alice_group
            .own_leaf_node()
            .ok_or_else(|| fail("Alice genesis leaf is missing"))?,
        &lifetime,
    )?;

    let group_info_out =
        alice_group.export_group_info(alice_provider.crypto(), &alice_signer, true)?;
    let group_info_bytes = group_info_out.tls_serialize_detached()?;
    assert_wrapper(&group_info_bytes, 4)?;
    let parsed_group_info = MlsMessageIn::tls_deserialize_exact(&group_info_bytes)?;
    ensure(
        parsed_group_info.tls_serialize_detached()? == group_info_bytes,
        "GroupInfo parse/reencode mismatch",
    )?;
    let verifiable_group_info = parsed_group_info
        .into_verifiable_group_info()
        .ok_or_else(|| fail("wire-format 4 did not contain GroupInfo"))?;
    let group_info_extension_types: Vec<ExtensionType> = verifiable_group_info
        .extensions()
        .iter()
        .map(Extension::extension_type)
        .collect();
    ensure(
        group_info_extension_types == [ExtensionType::RatchetTree, ExtensionType::ExternalPub],
        format!("GroupInfo extension profile drift: {group_info_extension_types:?}"),
    )?;
    ensure(
        verifiable_group_info.group_id().as_slice() == group_id,
        "GroupInfo group id mismatch",
    )?;
    ensure(
        verifiable_group_info.epoch().as_u64() == 0,
        "GroupInfo epoch mismatch",
    )?;
    let embedded_ratchet_tree = verifiable_group_info
        .extensions()
        .ratchet_tree()
        .ok_or_else(|| fail("GroupInfo has no embedded RatchetTree"))?
        .ratchet_tree()
        .clone();
    ensure(
        embedded_ratchet_tree.tls_serialize_detached()?
            == alice_group.export_ratchet_tree().tls_serialize_detached()?,
        "GroupInfo embedded RatchetTree differs from Alice's exported tree",
    )?;

    let (mut public_group, verified_group_info) = PublicGroup::from_external(
        public_provider.crypto(),
        public_provider.storage(),
        embedded_ratchet_tree,
        verifiable_group_info,
        ProposalStore::new(),
    )?;
    ensure(
        verified_group_info.extensions().iter().count() == 2,
        "verified GroupInfo extension count drift",
    )?;
    assert_public_members(
        &public_group,
        &[(&alice_credential_identity, alice_public_key.as_slice())],
    )?;
    let genesis_context = context_from_public_group(&public_group, 0, 0)?;

    let creation_artifact = build_alice_creation_artifact(
        &alice_group,
        &alice_provider,
        &alice_public_key,
        &genesis_context,
        &group_info_bytes,
        &creation_signed_at,
        &creation_received_at,
    )?;

    let bob_key_package_bundle = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .leaf_node_capabilities(exact_capabilities())
        .build(
            CIPHERSUITE,
            &bob_provider,
            &bob_signer,
            credential_with_key(&bob_credential_identity, &bob_public_key),
        )?;
    let bob_key_package = bob_key_package_bundle.key_package().clone();
    ensure(
        bob_key_package.extensions().iter().next().is_none(),
        "Bob KeyPackage extensions are not empty",
    )?;
    ensure(
        !bob_key_package.last_resort(),
        "Bob KeyPackage is marked last-resort",
    )?;
    assert_exact_member_profile(
        bob_key_package.leaf_node(),
        &bob_credential_identity,
        &bob_public_key,
    )?;
    assert_key_package_leaf_source(bob_key_package.leaf_node(), &lifetime)?;
    ensure(
        bob_key_package.life_time().validate().is_ok(),
        "Bob KeyPackage is not valid at evaluation time",
    )?;
    ensure(
        bob_key_package.life_time().has_acceptable_range(),
        "Bob KeyPackage lifetime range is unacceptable",
    )?;
    let key_package_inner = bob_key_package.tls_serialize_detached()?;
    let key_package_wrapped =
        MlsMessageOut::from(bob_key_package.clone()).tls_serialize_detached()?;
    assert_wrapper(&key_package_wrapped, 5)?;
    ensure(
        key_package_wrapped.get(4..) == Some(key_package_inner.as_slice()),
        "KeyPackage wrapper does not contain the exact inner TLS bytes",
    )?;
    ensure(
        key_package_inner.starts_with(&[0x00, 0x01, 0x00, 0x4D]),
        "KeyPackage inner version/ciphersuite prefix drift",
    )?;
    let reparsed_key_package = MlsMessageIn::tls_deserialize_exact(&key_package_wrapped)?;
    ensure(
        reparsed_key_package.tls_serialize_detached()? == key_package_wrapped,
        "KeyPackage parse/reencode mismatch",
    )?;
    let key_package_ref = bob_key_package.hash_ref(bob_provider.crypto())?;
    let key_package_ref_bytes = key_package_ref.as_slice().to_vec();
    ensure(
        key_package_ref_bytes.len() == 32,
        "XWing KeyPackageRef is not 32 bytes",
    )?;
    let ref_from_exact_inner = openmls::ciphersuite::hash_ref::make_key_package_ref(
        &key_package_inner,
        CIPHERSUITE,
        bob_provider.crypto(),
    )?;
    ensure(
        ref_from_exact_inner.as_slice() == key_package_ref_bytes,
        "KeyPackageRef was not computed over exact inner TLS bytes",
    )?;

    let add_prior_context = context_from_public_group(&public_group, 0, 2)?;
    let commit_aad = encode_mls_commit_aad(
        CONVERSATION_ID,
        0,
        TRANSITION_ID,
        &add_prior_context,
    )?;
    alice_group.set_aad(commit_aad.clone());
    let (commit_out, welcome_out, _post_commit_group_info) = alice_group.add_members(
        &alice_provider,
        &alice_signer,
        std::slice::from_ref(&bob_key_package),
    )?;
    let commit_bytes = commit_out.tls_serialize_detached()?;
    let welcome_bytes = welcome_out.tls_serialize_detached()?;
    assert_wrapper(&commit_bytes, 1)?;
    assert_wrapper(&welcome_bytes, 3)?;

    let parsed_commit = MlsMessageIn::tls_deserialize_exact(&commit_bytes)?;
    ensure(
        parsed_commit.tls_serialize_detached()? == commit_bytes,
        "Commit parse/reencode mismatch",
    )?;
    let commit_protocol = parsed_commit
        .into_protocol_message()
        .ok_or_else(|| fail("wire-format 1 did not contain a protocol message"))?;
    ensure(
        matches!(commit_protocol, ProtocolMessage::PublicMessage(_)),
        "membership Commit is not a PublicMessage",
    )?;
    let processed_commit =
        public_group.process_message(public_provider.crypto(), commit_protocol)?;
    ensure(processed_commit.aad() == commit_aad, "Commit AAD mismatch")?;
    ensure(
        processed_commit.group_id().as_slice() == group_id,
        "Commit group id mismatch",
    )?;
    ensure(
        processed_commit.epoch().as_u64() == 0,
        "Commit prior epoch mismatch",
    )?;
    let staged_commit = match processed_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => return Err(fail(format!("expected staged Commit, got {other:?}"))),
    };
    ensure(
        staged_commit.queued_proposals().count() == 1
            && staged_commit.add_proposals().count() == 1
            && staged_commit
                .queued_proposals()
                .all(|proposal| proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal),
        "Commit must contain exactly one by-value Add proposal",
    )?;
    let committed_add_ref = staged_commit
        .add_proposals()
        .next()
        .ok_or_else(|| fail("Commit Add proposal disappeared"))?
        .add_proposal()
        .key_package()
        .hash_ref(public_provider.crypto())?;
    ensure(
        committed_add_ref.as_slice() == key_package_ref_bytes,
        "Commit Add does not carry the frozen Bob KeyPackage",
    )?;
    let update_path_leaf = staged_commit
        .update_path_leaf_node()
        .ok_or_else(|| fail("ordinary member Commit has no sender update path"))?;
    ensure(
        update_path_leaf.parent_hash().is_some(),
        "ordinary member Commit update path does not use Commit leaf source",
    )?;
    assert_exact_member_profile(
        update_path_leaf,
        &alice_credential_identity,
        &alice_public_key,
    )?;
    public_group.merge_commit(public_provider.storage(), *staged_commit)?;
    assert_public_members(
        &public_group,
        &[
            (&alice_credential_identity, alice_public_key.as_slice()),
            (&bob_credential_identity, bob_public_key.as_slice()),
        ],
    )?;
    ensure(
        public_group.group_context().epoch().as_u64() == 1,
        "public epoch did not advance",
    )?;
    ensure(
        public_group
            .group_context()
            .extensions()
            .iter()
            .next()
            .is_none(),
        "committed GroupContext extensions are not empty",
    )?;
    let committed_context = context_from_public_group(&public_group, 0, 3)?;

    alice_group.merge_pending_commit(&alice_provider)?;
    ensure(
        alice_group.epoch().as_u64() == 1,
        "Alice epoch did not advance",
    )?;
    assert_member_group_matches_public(&alice_group, &public_group, "Alice")?;

    let parsed_welcome = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)?;
    ensure(
        parsed_welcome.tls_serialize_detached()? == welcome_bytes,
        "Welcome parse/reencode mismatch",
    )?;
    let welcome = parsed_welcome
        .into_welcome()
        .ok_or_else(|| fail("wire-format 3 did not contain a Welcome"))?;
    ensure(
        welcome.secrets().len() == 1
            && welcome.secrets()[0].new_member().as_slice() == key_package_ref_bytes,
        "Welcome recipient map does not contain exactly Bob's KeyPackageRef",
    )?;
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob_provider, group_config.join_config(), welcome, None)?
            .into_group(&bob_provider)?;
    ensure(bob_group.epoch().as_u64() == 1, "Bob joined at wrong epoch")?;
    ensure(
        bob_group.group_id().as_slice() == group_id,
        "Bob joined wrong group",
    )?;
    assert_member_group_matches_public(&bob_group, &public_group, "Bob")?;

    let application_frame = ApplicationFrame {
        protocol: "blue.catbird.chat.application".to_owned(),
        version: 1,
        message_id: MESSAGE_ID,
        context: committed_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("blue.catbird.chat frozen interoperability proof".to_owned()),
            reply_to: None,
            embed: None,
        }),
    };
    let application_frame_bytes = encode_application_content(&application_frame)?;
    let decoded_frame = decode_application_frame(&application_frame_bytes)?;
    ensure(
        decoded_frame == application_frame,
        "application frame roundtrip mismatch",
    )?;
    let application_aad = encode_mls_application_aad(
        CONVERSATION_ID,
        0,
        MESSAGE_ID,
        &committed_context,
    )?;
    alice_group.set_aad(application_aad.clone());
    let application_out =
        alice_group.create_message(&alice_provider, &alice_signer, &application_frame_bytes)?;
    let application_private_bytes = application_out.tls_serialize_detached()?;
    assert_wrapper(&application_private_bytes, 2)?;
    let parsed_application = MlsMessageIn::tls_deserialize_exact(&application_private_bytes)?;
    ensure(
        parsed_application.tls_serialize_detached()? == application_private_bytes,
        "PrivateMessage parse/reencode mismatch",
    )?;
    let application_protocol = parsed_application
        .into_protocol_message()
        .ok_or_else(|| fail("wire-format 2 did not contain a protocol message"))?;
    ensure(
        matches!(application_protocol, ProtocolMessage::PrivateMessage(_)),
        "application artifact is not a PrivateMessage",
    )?;
    let processed_application = bob_group.process_message(&bob_provider, application_protocol)?;
    ensure(
        processed_application.group_id().as_slice() == group_id,
        "application group id mismatch",
    )?;
    ensure(
        processed_application.epoch().as_u64() == 1,
        "application epoch mismatch",
    )?;
    ensure(
        processed_application.aad() == application_aad,
        "application AAD mismatch",
    )?;
    ensure(
        matches!(processed_application.sender(), Sender::Member(index) if index.u32() == 0),
        "application sender is not Alice leaf 0",
    )?;
    ensure(
        processed_application.credential().credential_type() == CredentialType::Basic
            && processed_application.credential().serialized_content()
                == alice_credential_identity.as_bytes(),
        "decrypted MLS credential is not Alice's device identity",
    )?;
    let decrypted_frame_bytes = match processed_application.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        other => return Err(fail(format!("expected application content, got {other:?}"))),
    };
    ensure(
        decrypted_frame_bytes == application_frame_bytes,
        "Bob decrypted different application bytes",
    )?;
    let bob_decoded_frame = decode_application_frame(&decrypted_frame_bytes)?;
    ensure(
        bob_decoded_frame == application_frame,
        "Bob decoded different application semantics",
    )?;

    // Generic zero-proposal commit: epoch 1 -> 2
    let generic_prior_context = committed_context.clone();
    let generic_commit_aad = encode_mls_commit_aad(
        CONVERSATION_ID,
        0,
        GENERIC_TRANSITION_ID,
        &generic_prior_context,
    )?;
    alice_group.set_aad(generic_commit_aad.clone());
    let empty_commit_bundle = alice_group
        .commit_builder()
        .load_psks(alice_provider.storage())?
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )?
        .stage_commit(&alice_provider)?;
    let (empty_commit_out, empty_welcome_option, _empty_group_info) =
        empty_commit_bundle.into_contents();
    ensure(
        empty_welcome_option.is_none(),
        "generic commit unexpectedly produced a Welcome",
    )?;
    let empty_commit_bytes = empty_commit_out.tls_serialize_detached()?;
    assert_wrapper(&empty_commit_bytes, 1)?;
    let parsed_empty_commit = MlsMessageIn::tls_deserialize_exact(&empty_commit_bytes)?;
    ensure(
        parsed_empty_commit.tls_serialize_detached()? == empty_commit_bytes,
        "generic commit parse/reencode mismatch",
    )?;
    let empty_commit_protocol = parsed_empty_commit
        .into_protocol_message()
        .ok_or_else(|| fail("wire-format 1 generic commit did not contain a protocol message"))?;
    ensure(
        matches!(empty_commit_protocol, ProtocolMessage::PublicMessage(_)),
        "generic commit is not a PublicMessage",
    )?;
    let processed_empty_commit =
        public_group.process_message(public_provider.crypto(), empty_commit_protocol)?;
    ensure(
        processed_empty_commit.aad() == generic_commit_aad,
        "generic commit Catbird AAD mismatch",
    )?;
    ensure(
        processed_empty_commit.epoch().as_u64() == 1,
        "generic commit prior epoch mismatch",
    )?;
    let staged_empty_commit = match processed_empty_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => {
            return Err(fail(format!(
                "expected staged generic commit, got {other:?}"
            )))
        }
    };
    ensure(
        staged_empty_commit.queued_proposals().count() == 0
            && staged_empty_commit.add_proposals().count() == 0
            && staged_empty_commit.remove_proposals().count() == 0
            && staged_empty_commit.update_proposals().count() == 0,
        "generic commit must contain zero proposals",
    )?;
    ensure(
        staged_empty_commit.update_path_leaf_node().is_some(),
        "generic commit must carry a member update path",
    )?;
    public_group.merge_commit(public_provider.storage(), *staged_empty_commit)?;
    ensure(
        public_group.group_context().epoch().as_u64() == 2,
        "public epoch did not advance to 2 after generic commit",
    )?;
    let generic_committed_context = context_from_public_group(&public_group, 0, 4)?;
    alice_group.merge_pending_commit(&alice_provider)?;
    ensure(
        alice_group.epoch().as_u64() == 2,
        "Alice epoch did not advance to 2",
    )?;
    assert_member_group_matches_public(&alice_group, &public_group, "Alice@epoch2")?;

    let bob_empty_protocol = MlsMessageIn::tls_deserialize_exact(&empty_commit_bytes)?
        .into_protocol_message()
        .ok_or_else(|| fail("generic commit had no protocol message for Bob"))?;
    let bob_processed_empty = bob_group.process_message(&bob_provider, bob_empty_protocol)?;
    let bob_staged_empty = match bob_processed_empty.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => {
            return Err(fail(format!(
                "Bob expected staged generic commit, got {other:?}"
            )))
        }
    };
    bob_group.merge_staged_commit(&bob_provider, *bob_staged_empty)?;
    ensure(
        bob_group.epoch().as_u64() == 2,
        "Bob epoch did not advance to 2",
    )?;
    assert_member_group_matches_public(&bob_group, &public_group, "Bob@epoch2")?;

    // Membership removal commit: epoch 2 -> 3 (Alice removes Bob)
    let bob_leaf_index = public_group
        .members()
        .find(|member| member.credential.serialized_content() == bob_credential_identity.as_bytes())
        .ok_or_else(|| fail("Bob is not a member before removal"))?
        .index;
    let remove_prior_context = generic_committed_context.clone();
    let remove_commit_aad = encode_mls_commit_aad(
        CONVERSATION_ID,
        0,
        LEAVE_FULFILLMENT_TRANSITION_ID,
        &remove_prior_context,
    )?;
    alice_group.set_aad(remove_commit_aad.clone());
    let remove_commit_bundle = alice_group
        .commit_builder()
        .propose_removals(std::iter::once(bob_leaf_index))
        .load_psks(alice_provider.storage())?
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )?
        .stage_commit(&alice_provider)?;
    let (remove_commit_out, remove_welcome_option, _remove_group_info) =
        remove_commit_bundle.into_contents();
    ensure(
        remove_welcome_option.is_none(),
        "removal commit unexpectedly produced a Welcome",
    )?;
    let remove_commit_bytes = remove_commit_out.tls_serialize_detached()?;
    assert_wrapper(&remove_commit_bytes, 1)?;
    let parsed_remove_commit = MlsMessageIn::tls_deserialize_exact(&remove_commit_bytes)?;
    ensure(
        parsed_remove_commit.tls_serialize_detached()? == remove_commit_bytes,
        "removal commit parse/reencode mismatch",
    )?;
    let remove_commit_protocol = parsed_remove_commit
        .into_protocol_message()
        .ok_or_else(|| fail("wire-format 1 removal commit did not contain a protocol message"))?;
    ensure(
        matches!(remove_commit_protocol, ProtocolMessage::PublicMessage(_)),
        "removal commit is not a PublicMessage",
    )?;
    let processed_remove_commit =
        public_group.process_message(public_provider.crypto(), remove_commit_protocol)?;
    ensure(
        processed_remove_commit.epoch().as_u64() == 2
            && processed_remove_commit.aad() == remove_commit_aad,
        "removal commit prior epoch or Catbird AAD mismatch",
    )?;
    let staged_remove_commit = match processed_remove_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => {
            return Err(fail(format!(
                "expected staged removal commit, got {other:?}"
            )))
        }
    };
    ensure(
        staged_remove_commit.remove_proposals().count() == 1
            && staged_remove_commit.add_proposals().count() == 0
            && staged_remove_commit.update_proposals().count() == 0,
        "removal commit must contain exactly one Remove proposal",
    )?;
    ensure(
        staged_remove_commit
            .remove_proposals()
            .next()
            .ok_or_else(|| fail("removal proposal disappeared"))?
            .remove_proposal()
            .removed()
            == bob_leaf_index,
        "removal commit does not target Bob's leaf",
    )?;
    public_group.merge_commit(public_provider.storage(), *staged_remove_commit)?;
    ensure(
        public_group.group_context().epoch().as_u64() == 3,
        "public epoch did not advance to 3 after removal commit",
    )?;
    assert_public_members(
        &public_group,
        &[(&alice_credential_identity, alice_public_key.as_slice())],
    )?;
    let remove_committed_context = context_from_public_group(&public_group, 0, 5)?;
    alice_group.merge_pending_commit(&alice_provider)?;
    ensure(
        alice_group.epoch().as_u64() == 3,
        "Alice epoch did not advance to 3",
    )?;
    assert_member_group_matches_public(&alice_group, &public_group, "Alice@epoch3")?;

    // Post-removal rejoin: epoch 3 -> 4 (Alice adds Bob again)
    let rejoin_bob_provider = Provider::new()?;
    bob_signer.store(rejoin_bob_provider.storage())?;
    let rejoin_key_package_bundle = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .leaf_node_capabilities(exact_capabilities())
        .build(
            CIPHERSUITE,
            &rejoin_bob_provider,
            &bob_signer,
            credential_with_key(&bob_credential_identity, &bob_public_key),
        )?;
    let rejoin_key_package = rejoin_key_package_bundle.key_package().clone();
    ensure(
        rejoin_key_package.extensions().iter().next().is_none(),
        "Bob rejoin KeyPackage extensions are not empty",
    )?;
    ensure(
        !rejoin_key_package.last_resort(),
        "Bob rejoin KeyPackage is marked last-resort",
    )?;
    assert_exact_member_profile(
        rejoin_key_package.leaf_node(),
        &bob_credential_identity,
        &bob_public_key,
    )?;
    assert_key_package_leaf_source(rejoin_key_package.leaf_node(), &lifetime)?;
    ensure(
        rejoin_key_package.life_time().validate().is_ok()
            && rejoin_key_package.life_time().has_acceptable_range(),
        "Bob rejoin KeyPackage lifetime is invalid",
    )?;
    let rejoin_key_package_inner = rejoin_key_package.tls_serialize_detached()?;
    let rejoin_key_package_wrapped =
        MlsMessageOut::from(rejoin_key_package.clone()).tls_serialize_detached()?;
    assert_wrapper(&rejoin_key_package_wrapped, 5)?;
    ensure(
        rejoin_key_package_wrapped.get(4..) == Some(rejoin_key_package_inner.as_slice()),
        "rejoin KeyPackage wrapper does not contain the exact inner TLS bytes",
    )?;
    let reparsed_rejoin_key_package =
        MlsMessageIn::tls_deserialize_exact(&rejoin_key_package_wrapped)?;
    ensure(
        reparsed_rejoin_key_package.tls_serialize_detached()? == rejoin_key_package_wrapped,
        "rejoin KeyPackage parse/reencode mismatch",
    )?;
    let rejoin_key_package_ref = rejoin_key_package.hash_ref(rejoin_bob_provider.crypto())?;
    let rejoin_key_package_ref_bytes = rejoin_key_package_ref.as_slice().to_vec();
    ensure(
        rejoin_key_package_ref_bytes.len() == 32
            && rejoin_key_package_ref_bytes != key_package_ref_bytes,
        "rejoin KeyPackageRef is invalid or aliases the consumed package",
    )?;
    let rejoin_ref_from_exact_inner = openmls::ciphersuite::hash_ref::make_key_package_ref(
        &rejoin_key_package_inner,
        CIPHERSUITE,
        rejoin_bob_provider.crypto(),
    )?;
    ensure(
        rejoin_ref_from_exact_inner.as_slice() == rejoin_key_package_ref_bytes,
        "rejoin KeyPackageRef was not computed over exact inner TLS bytes",
    )?;

    let rejoin_prior_context = context_from_public_group(&public_group, 0, 7)?;
    let rejoin_commit_aad = encode_mls_commit_aad(
        CONVERSATION_ID,
        0,
        REJOIN_TRANSITION_ID,
        &rejoin_prior_context,
    )?;
    alice_group.set_aad(rejoin_commit_aad.clone());
    let (rejoin_commit_out, rejoin_welcome_out, _rejoin_group_info) = alice_group.add_members(
        &alice_provider,
        &alice_signer,
        std::slice::from_ref(&rejoin_key_package),
    )?;
    let rejoin_commit_bytes = rejoin_commit_out.tls_serialize_detached()?;
    let rejoin_welcome_bytes = rejoin_welcome_out.tls_serialize_detached()?;
    assert_wrapper(&rejoin_commit_bytes, 1)?;
    assert_wrapper(&rejoin_welcome_bytes, 3)?;

    let rejoin_commit_protocol = MlsMessageIn::tls_deserialize_exact(&rejoin_commit_bytes)?
        .into_protocol_message()
        .ok_or_else(|| fail("rejoin commit did not contain a protocol message"))?;
    ensure(
        matches!(rejoin_commit_protocol, ProtocolMessage::PublicMessage(_)),
        "rejoin Commit is not a PublicMessage",
    )?;
    let processed_rejoin_commit =
        public_group.process_message(public_provider.crypto(), rejoin_commit_protocol)?;
    ensure(
        processed_rejoin_commit.epoch().as_u64() == 3
            && processed_rejoin_commit.aad() == rejoin_commit_aad,
        "rejoin Commit prior epoch or Catbird AAD mismatch",
    )?;
    let staged_rejoin_commit = match processed_rejoin_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        other => {
            return Err(fail(format!(
                "expected staged rejoin Commit, got {other:?}"
            )))
        }
    };
    ensure(
        staged_rejoin_commit.add_proposals().count() == 1
            && staged_rejoin_commit.remove_proposals().count() == 0
            && staged_rejoin_commit.update_proposals().count() == 0,
        "rejoin Commit must contain exactly one Add proposal",
    )?;
    let committed_rejoin_ref = staged_rejoin_commit
        .add_proposals()
        .next()
        .ok_or_else(|| fail("rejoin Add proposal disappeared"))?
        .add_proposal()
        .key_package()
        .hash_ref(public_provider.crypto())?;
    ensure(
        committed_rejoin_ref.as_slice() == rejoin_key_package_ref_bytes,
        "rejoin Commit Add does not carry the second Bob KeyPackage",
    )?;
    public_group.merge_commit(public_provider.storage(), *staged_rejoin_commit)?;
    ensure(
        public_group.group_context().epoch().as_u64() == 4,
        "public epoch did not advance to 4 after rejoin",
    )?;
    assert_public_members(
        &public_group,
        &[
            (&alice_credential_identity, alice_public_key.as_slice()),
            (&bob_credential_identity, bob_public_key.as_slice()),
        ],
    )?;
    let rejoin_context = context_from_public_group(&public_group, 0, 8)?;

    alice_group.merge_pending_commit(&alice_provider)?;
    ensure(
        alice_group.epoch().as_u64() == 4,
        "Alice epoch did not advance to 4",
    )?;
    assert_member_group_matches_public(&alice_group, &public_group, "Alice@epoch4")?;

    let parsed_rejoin_welcome = MlsMessageIn::tls_deserialize_exact(&rejoin_welcome_bytes)?;
    ensure(
        parsed_rejoin_welcome.tls_serialize_detached()? == rejoin_welcome_bytes,
        "rejoin Welcome parse/reencode mismatch",
    )?;
    let rejoin_welcome = parsed_rejoin_welcome
        .into_welcome()
        .ok_or_else(|| fail("rejoin wire-format 3 did not contain a Welcome"))?;
    ensure(
        rejoin_welcome.secrets().len() == 1
            && rejoin_welcome.secrets()[0].new_member().as_slice() == rejoin_key_package_ref_bytes,
        "rejoin Welcome recipient map does not contain exactly the second Bob KeyPackageRef",
    )?;
    let rejoined_bob_group = StagedWelcome::new_from_welcome(
        &rejoin_bob_provider,
        group_config.join_config(),
        rejoin_welcome,
        None,
    )?
    .into_group(&rejoin_bob_provider)?;
    ensure(
        rejoined_bob_group.epoch().as_u64() == 4
            && rejoined_bob_group.group_id().as_slice() == group_id,
        "Bob rejoined at the wrong epoch or group",
    )?;
    assert_member_group_matches_public(&rejoined_bob_group, &public_group, "Bob@rejoin")?;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let stack_root = manifest_dir
        .parent()
        .ok_or_else(|| fail("catbird-mls has no workspace parent"))?;
    let output_dir = match std::env::var(OUTPUT_DIR_ENV) {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => stack_root.join("docs/generated-artifacts/mls-chat-v1/crypto-wire-v09"),
    };
    fs::create_dir_all(&output_dir)?;

    let mut wire_artifacts: BTreeMap<&str, (Vec<u8>, &'static str, Option<u16>, Option<u64>)> = BTreeMap::new();
    wire_artifacts.insert(
        "key-package.mls",
        (key_package_wrapped, "mlsMessageKeyPackage", Some(5), None),
    );
    wire_artifacts.insert(
        "key-package-inner.tls",
        (key_package_inner, "innerKeyPackageTls", None, None),
    );
    wire_artifacts.insert(
        "key-package-ref.bin",
        (
            key_package_ref_bytes.clone(),
            "rfc9420KeyPackageRef",
            None,
            None,
        ),
    );
    wire_artifacts.insert(
        "group-info.mls",
        (group_info_bytes, "mlsMessageGroupInfo", Some(4), Some(0)),
    );
    wire_artifacts.insert(
        "commit-public.mls",
        (commit_bytes, "mlsMessagePublicCommit", Some(1), Some(0)),
    );
    wire_artifacts.insert(
        "welcome.mls",
        (welcome_bytes, "mlsMessageWelcome", Some(3), Some(1)),
    );
    wire_artifacts.insert(
        "application-frame.cbor",
        (
            application_frame_bytes,
            "canonicalDagCborApplicationFrame",
            None,
            Some(1),
        ),
    );
    wire_artifacts.insert(
        "application-private.mls",
        (
            application_private_bytes,
            "mlsMessagePrivateApplication",
            Some(2),
            Some(1),
        ),
    );
    wire_artifacts.insert(
        "commit-generic-public.mls",
        (
            empty_commit_bytes,
            "mlsMessagePublicCommit",
            Some(1),
            Some(1),
        ),
    );
    wire_artifacts.insert(
        "commit-remove-public.mls",
        (
            remove_commit_bytes,
            "mlsMessagePublicCommit",
            Some(1),
            Some(2),
        ),
    );
    wire_artifacts.insert(
        "rejoin-key-package.mls",
        (
            rejoin_key_package_wrapped,
            "mlsMessageKeyPackage",
            Some(5),
            None,
        ),
    );
    wire_artifacts.insert(
        "rejoin-key-package-inner.tls",
        (rejoin_key_package_inner, "innerKeyPackageTls", None, None),
    );
    wire_artifacts.insert(
        "rejoin-key-package-ref.bin",
        (
            rejoin_key_package_ref_bytes.clone(),
            "rfc9420KeyPackageRef",
            None,
            None,
        ),
    );
    wire_artifacts.insert(
        "commit-rejoin-public.mls",
        (
            rejoin_commit_bytes,
            "mlsMessagePublicCommit",
            Some(1),
            Some(3),
        ),
    );
    wire_artifacts.insert(
        "rejoin-welcome.mls",
        (rejoin_welcome_bytes, "mlsMessageWelcome", Some(3), Some(4)),
    );
    wire_artifacts.insert(
        CREATION_SIGNED_REQUEST_FILE,
        (
            creation_artifact.signed_request_cbor.clone(),
            "canonicalDagCborSignedCreation",
            None,
            Some(0),
        ),
    );

    for (name, (bytes, _, _, _)) in &wire_artifacts {
        write_atomic(&output_dir.join(name), bytes)?;
    }

    let dependencies = dependency_manifest(&manifest_dir.join("Cargo.lock"))?;
    let generator_source = manifest_dir.join(file!());
    let generator_source_sha256 = sha256_hex(&fs::read(&generator_source)?);
    let cargo_manifest_sha256 = sha256_hex(&fs::read(manifest_dir.join("Cargo.toml"))?);
    let cargo_lock_sha256 = sha256_hex(&fs::read(manifest_dir.join("Cargo.lock"))?);
    let chat_protocol_source_sha256 = source_tree_sha256(&manifest_dir.join("src/chat_v2"))?;
    let rustc_version = command_version("rustc")?;
    let cargo_version = command_version("cargo")?;

    let creation_manifest = json!({
        "entryKind": CREATION_ENTRY_TYPE,
        "bodyType": CREATION_BODY_TYPE,
        "signedRequestRef": "blue.catbird.chat.defs#signedCreation",
        "signatureAlgorithm": "Ed25519",
        "signatureDomainHex": hex::encode(CREATION_SIGNATURE_DOMAIN),
        "conversationKind": "direct",
        "absence": true,
        "authGeneration": 1,
        "actorDid": ALICE_ACTOR_DID,
        "actorDeviceId": alice_device_id,
        "keyId": creation_artifact.key_id,
        "transitionId": uuid_string(ALICE_CREATION_TRANSITION_ID)?,
        "transitionIdHex": hex::encode(ALICE_CREATION_TRANSITION_ID),
        "idempotencyKey": uuid_string(CREATION_IDEMPOTENCY_KEY)?,
        "idempotencyKeyHex": hex::encode(CREATION_IDEMPOTENCY_KEY),
        "signedAt": creation_signed_at,
        "receivedAt": creation_received_at,
        "manifestActorLeafOrigin": "genesis",
        "manifestParticipants": [
            {"role": "admin", "status": "active", "userDid": ALICE_ACTOR_DID},
            {"role": "admin", "status": "pending", "userDid": BOB_ACTOR_DID}
        ],
        "signedRequestFile": CREATION_SIGNED_REQUEST_FILE,
        "signedRequestCanonicalDagCborSha256Hex": sha256_hex(&creation_artifact.signed_request_cbor),
        "signedRequestBase64Standard": STANDARD.encode(&creation_artifact.signed_request_cbor),
        "unsignedBodyProjectionCanonicalDagCborHex": hex::encode(&creation_artifact.unsigned_body_projection_cbor),
        "unsignedBodyProjectionSha256Hex": sha256_hex(&creation_artifact.unsigned_body_projection_cbor),
        "signingTranscriptHex": hex::encode(&creation_artifact.signing_transcript),
        "signatureHex": hex::encode(creation_artifact.signature),
        "requestDigestHex": hex::encode(creation_artifact.request_digest),
        "metadata": {
            "exporterLabel": METADATA_EXPORTER_LABEL,
            "exporterOutputLength": METADATA_EXPORTER_OUTPUT_LENGTH,
            "exporterContextCanonicalDagCborHex": hex::encode(&creation_artifact.metadata_exporter_context),
            "metadataVersion": CREATION_METADATA_VERSION,
            "originTransitionIdHex": hex::encode(ALICE_CREATION_TRANSITION_ID),
            "nonceHex": hex::encode(CREATION_METADATA_NONCE),
            "ciphertextSize": creation_artifact.metadata_ciphertext_size,
            "ciphertextSha256Hex": hex::encode(creation_artifact.metadata_ciphertext_sha256),
            "contentTitle": "",
            "contentDescriptionPresent": false,
            "contentAvatarPresent": false,
            "authorRoleAtOrigin": "admin",
            "authorDeviceStatusAtOrigin": "active",
            "authorOriginSeq": 1,
            "reproductionNote": "AES-256-GCM over MetadataPlaintext; key = group.export_secret(blue.catbird.chat.metadata.v1, exporterContext, 32) from the genesis epoch; AAD = metadata_aad(coordinate, version, originTransitionId, ciphertextSize)"
        }
    });

    let stage1_manifest = json!({
        "schemaVersion": 1,
        "protocol": PROTOCOL,
        "protocolVersion": PROTOCOL_VERSION,
        "evaluationUnixSeconds": evaluation_unix_seconds,
        "cipherSuite": {
            "name": CIPHERSUITE_NAME,
            "code": CIPHERSUITE_CODE
        },
        "dependencies": dependencies,
        "generator": {
            "command": format!("{OPT_IN_ENV}={OPT_IN_VALUE} CATBIRD_OPENMLS_FORK_REV={fork_rev} cargo run --locked --features test-utils --example generate_mls_chat_crypto_wire"),
            "source": "catbird-mls/examples/generate_mls_chat_crypto_wire.rs",
            "sourceSha256Hex": generator_source_sha256,
            "cargoManifestSha256Hex": cargo_manifest_sha256,
            "cargoLockSha256Hex": cargo_lock_sha256,
            "chatProtocolSourceTreeSha256Hex": chat_protocol_source_sha256,
            "sourceTreeHashScheme": "sorted relative UTF-8 path, NUL, u64be length, file bytes for every .rs file",
            "rustc": rustc_version,
            "cargo": cargo_version,
            "officialClientRevision": OFFICIAL_CLIENT_REVISION,
            "catbirdOpenMlsForkRev": fork_rev,
            "randomness": "fresh OS randomness for 32-byte group id and libcrux HPKE material; frozen by these artifacts",
            "signingKeys": "fixed test-only Ed25519 seeds; no private key material is emitted"
        },
        "mlsProfile": {
            "version": "MLS 1.0",
            "compatibilityProfile": "OpenMLS-0.9.0-rc.3 XWing draft-ietf-mls-pq-ciphersuites; not an IANA stable assignment",
            "wireFormatPolicy": "PURE_PLAINTEXT_WIRE_FORMAT_POLICY for handshakes; PrivateMessage for application",
            "credentialType": "BasicCredential",
            "capabilities": {
                "versions": [1],
                "cipherSuites": [CIPHERSUITE_CODE],
                "extensions": [],
                "proposals": [],
                "credentials": [1]
            },
            "groupContextExtensions": [],
            "leafNodeExtensions": [],
            "keyPackageExtensions": [],
            "groupInfoExtensions": ["ratchet_tree", "external_pub"],
            "keyPackageLifetime": {
                "notBeforeUnixSeconds": not_before,
                "notAfterUnixSeconds": not_after,
                "validatedAtUnixSeconds": evaluation_unix_seconds
            },
            "frozenLifetimeCaveat": "The opt-in generator validates the live chain at evaluation time. Frozen tests load snapshots and compare bytes/state; they do not claim that GroupInfo or Commit reprocessing remains valid after leaf lifetimes expire."
        },
        "identity": {
            "alice": identity_manifest(ALICE_ACTOR_DID, &alice_device_id, &alice_credential_identity, &alice_public_key),
            "bob": identity_manifest(BOB_ACTOR_DID, &bob_device_id, &bob_credential_identity, &bob_public_key)
        },
        "identifiers": {
            "conversationId": uuid_string(CONVERSATION_ID)?,
            "conversationIdHex": hex::encode(CONVERSATION_ID),
            "transitionId": uuid_string(TRANSITION_ID)?,
            "transitionIdHex": hex::encode(TRANSITION_ID),
            "genericTransitionId": uuid_string(GENERIC_TRANSITION_ID)?,
            "genericTransitionIdHex": hex::encode(GENERIC_TRANSITION_ID),
            "leaveFulfillmentTransitionId": uuid_string(LEAVE_FULFILLMENT_TRANSITION_ID)?,
            "leaveFulfillmentTransitionIdHex": hex::encode(LEAVE_FULFILLMENT_TRANSITION_ID),
            "rejoinTransitionId": uuid_string(REJOIN_TRANSITION_ID)?,
            "rejoinTransitionIdHex": hex::encode(REJOIN_TRANSITION_ID),
            "messageId": uuid_string(MESSAGE_ID)?,
            "messageIdHex": hex::encode(MESSAGE_ID)
        },
        "chain": {
            "groupIdHex": hex::encode(group_id),
            "generation": 0,
            "genesisStateVersion": genesis_context.state_version,
            "genesisEpoch": genesis_context.epoch,
            "genesisGroupContextHashHex": hex::encode(genesis_context.group_context_hash),
            "genesisConfirmationTagHex": hex::encode(genesis_context.confirmation_tag),
            "genesisMemberCredentials": [alice_credential_identity.clone()],
            "addPriorStateVersion": add_prior_context.state_version,
            "committedStateVersion": committed_context.state_version,
            "committedEpoch": committed_context.epoch,
            "committedGroupContextHashHex": hex::encode(committed_context.group_context_hash),
            "committedConfirmationTagHex": hex::encode(committed_context.confirmation_tag),
            "committedMemberCredentials": [
                format!("{ALICE_ACTOR_DID}#{alice_device_id}"),
                format!("{BOB_ACTOR_DID}#{bob_device_id}")
            ],
            "innerKeyPackageRefHex": hex::encode(&key_package_ref_bytes),
            "genericPriorStateVersion": generic_prior_context.state_version,
            "genericCommittedStateVersion": generic_committed_context.state_version,
            "genericCommittedEpoch": generic_committed_context.epoch,
            "genericCommittedGroupContextHashHex": hex::encode(generic_committed_context.group_context_hash),
            "genericCommittedConfirmationTagHex": hex::encode(generic_committed_context.confirmation_tag),
            "removePriorStateVersion": remove_prior_context.state_version,
            "removeCommittedStateVersion": remove_committed_context.state_version,
            "removeCommittedEpoch": remove_committed_context.epoch,
            "removeCommittedGroupContextHashHex": hex::encode(remove_committed_context.group_context_hash),
            "removeCommittedConfirmationTagHex": hex::encode(remove_committed_context.confirmation_tag),
            "rejoinPriorStateVersion": rejoin_prior_context.state_version,
            "rejoinStateVersion": rejoin_context.state_version,
            "rejoinEpoch": rejoin_context.epoch,
            "rejoinGroupContextHashHex": hex::encode(rejoin_context.group_context_hash),
            "rejoinConfirmationTagHex": hex::encode(rejoin_context.confirmation_tag),
            "rejoinMemberCredentials": [
                format!("{ALICE_ACTOR_DID}#{alice_device_id}"),
                format!("{BOB_ACTOR_DID}#{bob_device_id}")
            ],
            "rejoinInnerKeyPackageRefHex": hex::encode(&rejoin_key_package_ref_bytes),
            "commitAadSha256Hex": sha256_hex(&commit_aad),
            "genericCommitAadSha256Hex": sha256_hex(&generic_commit_aad),
            "removeCommitAadSha256Hex": sha256_hex(&remove_commit_aad),
            "rejoinCommitAadSha256Hex": sha256_hex(&rejoin_commit_aad),
            "applicationAadSha256Hex": sha256_hex(&application_aad)
        },
        "liveProof": {
            "actorOnlyGenesisValidated": true,
            "groupInfoSignatureAndLifetimeValidated": true,
            "keyPackageSignatureRefHashAndLifetimeValidated": true,
            "publicCommitProcessedComparedAndMerged": true,
            "welcomeJoinedByBob": true,
            "rejoinKeyPackageIsDistinctAndValid": true,
            "rejoinPublicCommitProcessedComparedAndMerged": true,
            "rejoinWelcomeJoinedByBob": true,
            "privateApplicationDecryptedByBob": true,
            "decryptedSenderLeaf": 0,
            "decryptedSenderCredential": format!("{ALICE_ACTOR_DID}#{alice_device_id}"),
            "authoritativeApplicationCodec": "catbird_mls::chat_v2 DAG-CBOR ApplicationFrame",
            "authoritativeMlsAadCodecs": [
                "catbird_mls::chat_v2 DAG-CBOR CommitAad",
                "catbird_mls::chat_v2 DAG-CBOR ApplicationAad"
            ],
            "snapshotsReloadedInFreshProviders": true,
            "creationEntrySelfVerifiedByCertifiedVerifier": true
        },
        "creation": creation_manifest
    });

    let mut stage1_manifest_bytes = serde_json::to_vec_pretty(&stage1_manifest)?;
    stage1_manifest_bytes.push(b'\n');
    write_atomic(&output_dir.join("candidate-manifest.json"), &stage1_manifest_bytes)?;

    println!(
        "Stage 1: generated {} wire payload artifacts + candidate manifest in {}",
        wire_artifacts.len(),
        output_dir.display()
    );

    // Stage 2: Invoke the mls-ds sealer helper
    let mls_ds_manifest = stack_root.join("mls-ds/server/Cargo.toml");
    println!("Stage 2: invoking mls-ds snapshot sealer...");
    let seal_status = Command::new("cargo")
        .arg("run")
        .arg("--manifest-path")
        .arg(&mls_ds_manifest)
        .arg("--locked")
        .arg("--example")
        .arg("seal_mls_chat_crypto_wire_v09")
        .arg("--")
        .arg(&output_dir)
        .status()?;

    ensure(
        seal_status.success(),
        format!("mls-ds sealer failed with status {seal_status}"),
    )?;

    println!("Stage 2: snapshot sealing and manifest finalization complete!");
    println!("output={}", output_dir.display());
    println!("groupIdHex={}", hex::encode(group_id));
    println!("keyPackageRefHex={}", hex::encode(key_package_ref_bytes));
    println!(
        "rejoinKeyPackageRefHex={}",
        hex::encode(rejoin_key_package_ref_bytes)
    );
    println!("liveProof=group-info+commit+welcome+private-application+schema2-snapshots:ok");
    Ok(())
}

fn exact_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

fn assert_exact_capabilities(capabilities: &Capabilities) -> Result<()> {
    ensure(
        capabilities.versions() == [ProtocolVersion::Mls10],
        "version capability drift",
    )?;
    ensure(
        capabilities.ciphersuites().len() == 1
            && capabilities.ciphersuites()[0].value() == CIPHERSUITE_CODE,
        "ciphersuite capability drift",
    )?;
    ensure(
        capabilities.extensions().is_empty(),
        "extension capability drift",
    )?;
    ensure(
        capabilities.proposals().is_empty(),
        "proposal capability drift",
    )?;
    ensure(
        capabilities.credentials() == [CredentialType::Basic],
        "credential capability drift",
    )?;
    Ok(())
}

fn assert_exact_member_profile(
    leaf: &LeafNode,
    expected_identity: &str,
    expected_signature_key: &[u8],
) -> Result<()> {
    ensure(
        leaf.credential().credential_type() == CredentialType::Basic,
        "leaf is not a BasicCredential",
    )?;
    ensure(
        leaf.credential().serialized_content() == expected_identity.as_bytes(),
        "leaf credential identity mismatch",
    )?;
    ensure(
        leaf.signature_key().as_slice() == expected_signature_key,
        "leaf signature key mismatch",
    )?;
    assert_exact_capabilities(leaf.capabilities())?;
    ensure(
        leaf.extensions().iter().next().is_none(),
        "leaf extensions are not empty",
    )?;
    Ok(())
}

fn assert_key_package_leaf_source(leaf: &LeafNode, expected_lifetime: &Lifetime) -> Result<()> {
    let actual = serde_json::to_value(leaf.leaf_node_source())?;
    let expected = json!({
        "KeyPackage": {
            "not_before": expected_lifetime.not_before(),
            "not_after": expected_lifetime.not_after()
        }
    });
    ensure(
        actual == expected,
        format!("KeyPackage leaf source/lifetime drift: {actual}"),
    )?;
    ensure(
        expected_lifetime.validate().is_ok(),
        "KeyPackage leaf lifetime is not valid at evaluation time",
    )?;
    ensure(
        expected_lifetime.has_acceptable_range(),
        "KeyPackage leaf lifetime range is unacceptable",
    )?;
    Ok(())
}

fn assert_public_members(group: &PublicGroup, expected: &[(&str, &[u8])]) -> Result<()> {
    let members: Vec<Member> = group.members().collect();
    ensure(
        members.len() == expected.len(),
        format!(
            "member count mismatch: {} != {}",
            members.len(),
            expected.len()
        ),
    )?;
    for (member, (identity, public_key)) in members.iter().zip(expected.iter()) {
        ensure(
            member.credential.credential_type() == CredentialType::Basic
                && member.credential.serialized_content() == identity.as_bytes(),
            format!("credential mismatch at leaf {}", member.index.u32()),
        )?;
        ensure(
            member.signature_key.as_slice() == *public_key,
            format!("signature key mismatch at leaf {}", member.index.u32()),
        )?;
    }
    Ok(())
}

fn assert_member_group_matches_public(
    member_group: &MlsGroup,
    public_group: &PublicGroup,
    label: &str,
) -> Result<()> {
    ensure(
        member_group.group_id() == public_group.group_id(),
        format!("{label}/public group id mismatch"),
    )?;
    ensure(
        member_group
            .export_group_context()
            .tls_serialize_detached()?
            == public_group.group_context().tls_serialize_detached()?,
        format!("{label}/public GroupContext mismatch"),
    )?;
    ensure(
        confirmation_tag_bytes(member_group.confirmation_tag())?
            == confirmation_tag_bytes(public_group.confirmation_tag())?,
        format!("{label}/public confirmation tag mismatch"),
    )?;
    ensure(
        member_group
            .export_ratchet_tree()
            .tls_serialize_detached()?
            == public_group
                .export_ratchet_tree()
                .tls_serialize_detached()?,
        format!("{label}/public ratchet tree mismatch"),
    )?;
    let member_group_members: Vec<Member> = member_group.members().collect();
    let public_members: Vec<Member> = public_group.members().collect();
    ensure(
        member_group_members == public_members,
        format!("{label}/public member list mismatch"),
    )?;
    Ok(())
}

fn credential_with_key(identity: &str, public_key: &[u8]) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
        signature_key: public_key.to_vec().into(),
    }
}

fn fixed_signer(seed: [u8; 32]) -> SignatureKeyPair {
    let signing_key = SigningKey::from_bytes(&seed);
    SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        seed.to_vec(),
        signing_key.verifying_key().to_bytes().to_vec(),
    )
}

fn context_from_public_group(
    public_group: &PublicGroup,
    generation: u64,
    state_version: u64,
) -> Result<ConversationContext> {
    let group_id: [u8; 32] = public_group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| fail("public group id is not 32 bytes"))?;
    let group_context_tls = public_group.group_context().tls_serialize_detached()?;
    let group_context_hash = Sha256::digest(group_context_tls).into();
    let confirmation_tag = confirmation_tag_bytes(public_group.confirmation_tag())?;
    Ok(ConversationContext {
        conversation_id: CONVERSATION_ID,
        generation,
        state_version,
        group_id,
        epoch: public_group.group_context().epoch().as_u64(),
        group_context_hash,
        confirmation_tag,
        lifecycle: "active".to_owned(),
    })
}

fn assert_wrapper(bytes: &[u8], expected_wire_format: u16) -> Result<()> {
    ensure(
        bytes.len() >= 4,
        "MLSMessage wrapper is shorter than header",
    )?;
    ensure(
        u16::from_be_bytes(bytes[0..2].try_into()?) == 1,
        "MLSMessage wrapper is not MLS 1.0",
    )?;
    ensure(
        u16::from_be_bytes(bytes[2..4].try_into()?) == expected_wire_format,
        format!("MLSMessage wrapper is not wire format {expected_wire_format}"),
    )?;
    Ok(())
}

fn confirmation_tag_bytes(tag: &ConfirmationTag) -> Result<[u8; 32]> {
    let encoded = tag.tls_serialize_detached()?;
    let bytes = VLBytes::tls_deserialize_exact(&encoded)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| fail("confirmation tag is not 32 bytes"))
}

fn identity_manifest(
    actor_did: &str,
    device_id: &str,
    credential_identity: &str,
    public_key: &[u8],
) -> Value {
    let public_key_sha256 = Sha256::digest(public_key);
    json!({
        "actorDid": actor_did,
        "deviceId": device_id,
        "credentialIdentity": credential_identity,
        "signaturePublicKeyHex": hex::encode(public_key),
        "signaturePublicKeySha256Hex": hex::encode(public_key_sha256),
        "keyId": URL_SAFE_NO_PAD.encode(public_key_sha256)
    })
}

fn dependency_manifest(lock_path: &Path) -> Result<Value> {
    let lock = fs::read_to_string(lock_path)?;
    let wanted = [
        ("openmls", OPENMLS_VERSION, true),
        ("openmls_traits", "0.6.0-rc.3", true),
        ("openmls_basic_credential", "0.6.0-rc.3", true),
        ("openmls_libcrux_crypto", "0.4.0-rc.3", true),
        ("openmls_memory_storage", STORAGE_VERSION, true),
        ("tls_codec", "0.5.0", false),
        ("serde_ipld_dagcbor", "0.6.4", false),
    ];
    let mut output = Map::new();
    for (name, version, is_git) in wanted {
        let package = find_lock_package(&lock, name, version, is_git)?;
        output.insert(name.to_owned(), package);
    }
    Ok(Value::Object(output))
}

fn find_lock_package(
    lock: &str,
    wanted_name: &str,
    wanted_version: &str,
    is_git: bool,
) -> Result<Value> {
    for block in lock.split("[[package]]").skip(1) {
        let name = lock_string_field(block, "name");
        let version = lock_string_field(block, "version");
        if name.as_deref() == Some(wanted_name) && version.as_deref() == Some(wanted_version) {
            let source = lock_string_field(block, "source")
                .ok_or_else(|| fail(format!("{wanted_name} {wanted_version} has no source")))?;
            ensure(!source.is_empty(), "dependency source is empty")?;
            if is_git {
                ensure(
                    source.starts_with("git+"),
                    format!("{wanted_name} source must be git, got {source}"),
                )?;
                ensure(
                    source.contains("https://github.com/openmls/openmls"),
                    format!("{wanted_name} git source must be openmls repository, got {source}"),
                )?;
                ensure(
                    source.contains(OFFICIAL_CLIENT_REVISION),
                    format!("{wanted_name} git source must match revision {OFFICIAL_CLIENT_REVISION}, got {source}"),
                )?;
                return Ok(json!({
                    "version": wanted_version,
                    "source": source
                }));
            } else {
                ensure(
                    source.starts_with("registry+"),
                    format!("{wanted_name} source must be registry, got {source}"),
                )?;
                let checksum = lock_string_field(block, "checksum")
                    .ok_or_else(|| fail(format!("{wanted_name} {wanted_version} has no checksum")))?;
                ensure(!checksum.is_empty(), "dependency checksum is empty")?;
                return Ok(json!({
                    "version": wanted_version,
                    "source": source,
                    "checksum": checksum
                }));
            }
        }
    }
    Err(fail(format!(
        "missing dependency {wanted_name} {wanted_version} in {}",
        lock.lines().next().unwrap_or("Cargo.lock")
    )))
}

fn lock_string_field(block: &str, field: &str) -> Option<String> {
    let prefix = format!("{field} = \"");
    block.lines().find_map(|line| {
        let rest = line.strip_prefix(&prefix)?;
        Some(rest.strip_suffix('"')?.to_owned())
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn source_tree_sha256(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_rust_sources(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    ensure(!files.is_empty(), "chat protocol source tree is empty")?;
    let mut hasher = Sha256::new();
    for (relative, bytes) in files {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(u64::try_from(bytes.len())?.to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_rust_sources(
    root: &Path,
    current: &Path,
    output: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_rust_sources(root, &path, output)?;
        } else if file_type.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("rs")
        {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            output.push((relative, fs::read(path)?));
        }
    }
    Ok(())
}

fn command_version(binary: &str) -> Result<String> {
    let output = Command::new(binary).arg("--version").output()?;
    ensure(
        output.status.success(),
        format!("{binary} --version failed with {}", output.status),
    )?;
    let version = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure(!version.is_empty(), format!("{binary} version is empty"))?;
    Ok(version)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| fail("output path has no UTF-8 filename"))?;
    let temp = path.with_file_name(format!(".{filename}.{}.tmp", std::process::id()));
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn ensure_uuid_v4(bytes: [u8; 16]) -> Result<()> {
    let uuid = Uuid::from_bytes(bytes);
    ensure(
        uuid.get_version() == Some(Version::Random),
        format!("{uuid} is not UUIDv4"),
    )?;
    ensure(
        uuid.get_variant() == uuid::Variant::RFC4122,
        format!("{uuid} is not RFC 4122 variant"),
    )?;
    Ok(())
}

fn assert_fixture_plc_did(did: &str) -> Result<()> {
    let identifier = did
        .strip_prefix("did:plc:")
        .ok_or_else(|| fail(format!("fixture DID is not did:plc: {did}")))?;
    ensure(
        identifier.len() == 24
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)),
        format!("fixture DID is not canonical ATProto did:plc syntax: {did}"),
    )?;
    Ok(())
}

fn uuid_string(bytes: [u8; 16]) -> Result<String> {
    ensure_uuid_v4(bytes)?;
    Ok(Uuid::from_bytes(bytes).hyphenated().to_string())
}
