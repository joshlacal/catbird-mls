use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_protocol::test_utils::decode_application_frame;
use catbird_mls::chat_protocol::{
    encode_application_content, encode_mls_application_aad, ingest_application_content,
    verify_application_outer_entry, ApplicationAccessInterval, ApplicationBody,
    ApplicationContentDisposition, ApplicationEmbed, ApplicationFrame,
    ApplicationIntervalClosingKind, ApplicationIntervalClosingProof,
    ApplicationIntervalOpeningKind, ApplicationMlsSender, ApplicationReducer, AtprotoRecord,
    BlobAlgorithm, BlobDescriptor, BlobPurpose, ConversationContext, EditBody, EncryptedAudio,
    EncryptedImage, ExpectedApplicationBinding, ExternalLink, Lifecycle, MessageBody,
    MessageTarget, MlsApplicationAadBinding, ReactionBody, ReactionOperation, ReadStateBody,
    ReducerError, ReducerOutcome, ReplyPresentation, TombstoneBody,
    VerifiedApplicationControlEntry, VerifiedApplicationDeviceRegistration,
};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

const OPT_IN_ENV: &str = "CATBIRD_REGENERATE_CHAT_APPLICATION_FIXTURES";
const OUTPUT_ENV: &str = "CATBIRD_CHAT_APPLICATION_FIXTURE_OUTPUT";
const DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
const DEVICE_ID: &str = "70707070-7070-4070-b070-707070707070";
const RECEIVER_DID: &str = DID;
const RECEIVER_DEVICE_ID: &str = "72727272-7272-4272-b272-727272727272";
const FOREIGN_DID: &str = "did:plc:malloryfixtureaaaaaaaaaa";
const FOREIGN_DEVICE_ID: &str = "74747474-7474-4474-b474-747474747474";
const SIGNING_SEED: [u8; 32] = [0x91; 32];
const RECEIVER_SIGNING_SEED: [u8; 32] = [0x92; 32];
const FOREIGN_SIGNING_SEED: [u8; 32] = [0x93; 32];
const MESSAGE_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-MESSAGE\0";
const APPLICATION_ENTRY_FINGERPRINT_DOMAIN: &[u8] = b"CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\0";
const CONTROL_ENTRY_FINGERPRINT_DOMAIN: &[u8] = b"CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\0";
const CONVERSATION_CLOSE_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-CLOSE\0";
const AUTHORITY_SOURCE_AGGREGATE_DOMAIN: &[u8] = b"CATBIRD-CHAT-AUTHORITY-SOURCES-V1\0";
const APPLICATION_SEND_BODY_TYPE: &str = "blue.catbird.chat.defs#applicationSendBody";
const CONVERSATION_CLOSE_BODY_TYPE: &str = "blue.catbird.chat.defs#conversationCloseBody";
const CONVERSATION_CLOSE_ENTRY_TYPE: &str = "blue.catbird.chat.defs#conversationCloseEntry";
const CONTROL_ENTRY_KINDS: [&str; 13] = [
    "blue.catbird.chat.defs#commitEntry",
    "blue.catbird.chat.defs#policyEntry",
    "blue.catbird.chat.defs#metadataEntry",
    "blue.catbird.chat.defs#creationEntry",
    "blue.catbird.chat.defs#participantAcceptanceEntry",
    CONVERSATION_CLOSE_ENTRY_TYPE,
    "blue.catbird.chat.defs#resetRequestEntry",
    "blue.catbird.chat.defs#resetActivationEntry",
    "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
    "blue.catbird.chat.defs#leaveRequestEntry",
    "blue.catbird.chat.defs#zeroLeafLeaveEntry",
    "blue.catbird.chat.defs#leaveCancellationEntry",
    "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
];
const SIGNED_AT: &str = "2026-07-22T12:34:55.000Z";
const RECEIVED_AT: &str = "2026-07-22T12:34:56.000Z";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const FIXTURE_GROUP_ID: [u8; 32] = [0x22; 32];
const FIXTURE_FOREIGN_GROUP_ID: [u8; 32] = [0x23; 32];
const FIXTURE_ALICE_RANDOM_SEED: [u8; 32] = [0x42; 32];
const FIXTURE_BOB_RANDOM_SEED: [u8; 32] = [0x43; 32];
const FIXTURE_FOREIGN_ALICE_RANDOM_SEED: [u8; 32] = [0x44; 32];
const FIXTURE_FOREIGN_MEMBER_RANDOM_SEED: [u8; 32] = [0x45; 32];
const COMPILED_GENERATOR_SOURCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/generate_chat_application_fixtures.rs"
));
static FIXTURE_CONTEXT: OnceLock<ConversationContext> = OnceLock::new();

#[derive(Clone)]
struct CapturedProvenanceFile {
    absolute_path: PathBuf,
    relative_path: String,
    bytes: Vec<u8>,
}

impl CapturedProvenanceFile {
    fn capture_source(stack_root: &Path, path: &Path) -> Result<Self> {
        let relative_path = normalized_relative_path(stack_root, path)?;
        let bytes = read_utf8_source(stack_root, path)?;
        Ok(Self {
            absolute_path: path.to_path_buf(),
            relative_path,
            bytes,
        })
    }

    fn capture_artifact(stack_root: &Path, path: &Path) -> Result<Self> {
        let relative_path = normalized_relative_path(stack_root, path)?;
        let bytes = read_regular_file(stack_root, path)?;
        Ok(Self {
            absolute_path: path.to_path_buf(),
            relative_path,
            bytes,
        })
    }

    fn source_record(&self) -> Value {
        json!({
            "path": self.relative_path,
            "sha256Hex": sha256(&self.bytes),
        })
    }

    fn artifact_record(&self) -> Value {
        json!({
            "path": self.relative_path,
            "length": self.bytes.len(),
            "sha256Hex": sha256(&self.bytes),
        })
    }

    fn assert_unchanged(&self, stack_root: &Path) -> Result<()> {
        let current = read_regular_file(stack_root, &self.absolute_path)?;
        if current != self.bytes {
            return Err(format!(
                "provenance source changed during generation: {}",
                self.relative_path
            )
            .into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusOuterBlobBinding {
    #[serde(with = "bytes16")]
    blob_id: [u8; 16],
    #[serde(with = "bytes32")]
    ciphertext_sha256: [u8; 32],
    ciphertext_size: u64,
    purpose: BlobPurpose,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusApplicationAad {
    protocol_version: String,
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    prior: ConversationContext,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusPrivateApplicationMessage {
    framing: String,
    content_type: String,
    #[serde(with = "byte_vec")]
    bytes: Vec<u8>,
    #[serde(with = "bytes32")]
    sha256: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusApplicationSendBody {
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
    aad: CorpusApplicationAad,
    application_message: CorpusPrivateApplicationMessage,
    blob_bindings: Vec<CorpusOuterBlobBinding>,
    signed_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusSignedApplicationSend {
    body: CorpusApplicationSendBody,
    #[serde(with = "bytes64")]
    signature: [u8; 64],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusApplicationEntry {
    #[serde(with = "bytes16")]
    entry_id: [u8; 16],
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    seq: u64,
    signed_request: CorpusSignedApplicationSend,
    received_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusControlCoordinates {
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    state_version: u64,
    #[serde(with = "bytes32")]
    group_id: [u8; 32],
    epoch: u64,
    #[serde(with = "bytes32")]
    group_context_hash: [u8; 32],
    #[serde(with = "bytes32")]
    confirmation_tag: [u8; 32],
    lifecycle: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusConversationCloseBody {
    #[serde(rename = "$type")]
    type_id: String,
    signature_domain: String,
    #[serde(with = "bytes16")]
    transition_id: [u8; 16],
    conversation_kind: String,
    actor_did: String,
    #[serde(with = "bytes16")]
    actor_device_id: [u8; 16],
    key_id: String,
    auth_generation: u64,
    prior: CorpusControlCoordinates,
    retired: CorpusControlCoordinates,
    #[serde(with = "bytes16")]
    idempotency_key: [u8; 16],
    signed_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusSignedConversationClose {
    body: CorpusConversationCloseBody,
    #[serde(with = "bytes64")]
    signature: [u8; 64],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusConversationCloseTombstone {
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    conversation_kind: String,
    retired: CorpusControlCoordinates,
    closed_by_did: String,
    #[serde(with = "bytes16")]
    closed_by_device_id: [u8; 16],
    terminal_seq: u64,
    closed_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusConversationCloseEntry {
    #[serde(with = "bytes16")]
    entry_id: [u8; 16],
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    seq: u64,
    signed_request: CorpusSignedConversationClose,
    tombstone: CorpusConversationCloseTombstone,
    received_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusTerminalServerFields {
    tombstone: CorpusConversationCloseTombstone,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorpusControlEntryFingerprintProjection {
    entry_kind: String,
    #[serde(with = "bytes16")]
    entry_id: [u8; 16],
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    seq: u64,
    #[serde(with = "bytes32")]
    request_digest: [u8; 32],
    #[serde(with = "bytes64")]
    signature: [u8; 64],
    server_fields: CorpusTerminalServerFields,
    received_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSeqHintWire {
    terminal_seq: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorpusApplicationEntryFingerprintProjection {
    #[serde(with = "bytes16")]
    entry_id: [u8; 16],
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    seq: u64,
    #[serde(with = "bytes32")]
    request_digest: [u8; 32],
    #[serde(with = "bytes64")]
    signature: [u8; 64],
    received_at: String,
}

struct SignedApplicationFixture {
    entry: CorpusApplicationEntry,
    fingerprint: [u8; 32],
    json: Value,
}

struct SignedControlEnvelopeFixture {
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    seq: u64,
    fingerprint: [u8; 32],
    previous: ConversationContext,
    json: Value,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct FixtureRandomError;

impl fmt::Display for FixtureRandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deterministic fixture RNG lock is poisoned")
    }
}

impl std::error::Error for FixtureRandomError {}

struct FixtureRandom(Mutex<StdRng>);

impl FixtureRandom {
    fn new(seed: [u8; 32]) -> Self {
        Self(Mutex::new(StdRng::from_seed(seed)))
    }
}

impl OpenMlsRand for FixtureRandom {
    type Error = FixtureRandomError;

    fn random_array<const N: usize>(&self) -> std::result::Result<[u8; N], Self::Error> {
        let mut output = [0_u8; N];
        self.0
            .lock()
            .map_err(|_| FixtureRandomError)?
            .fill_bytes(&mut output);
        Ok(output)
    }

    fn random_vec(&self, len: usize) -> std::result::Result<Vec<u8>, Self::Error> {
        let mut output = vec![0_u8; len];
        self.0
            .lock()
            .map_err(|_| FixtureRandomError)?
            .fill_bytes(&mut output);
        Ok(output)
    }
}

struct FixtureMlsProvider {
    crypto: CryptoProvider,
    random: FixtureRandom,
    storage: MemoryStorage,
}

impl FixtureMlsProvider {
    fn new(seed: [u8; 32]) -> Result<Self> {
        Ok(Self {
            crypto: CryptoProvider::new()?,
            random: FixtureRandom::new(seed),
            storage: MemoryStorage::default(),
        })
    }
}

impl OpenMlsProvider for FixtureMlsProvider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = FixtureRandom;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.random
    }
}

struct ApplicationTransportFixture {
    same_did_lane: TransportLane,
    different_did_lane: TransportLane,
}

struct TransportLane {
    left_did: &'static str,
    left_device_id: &'static str,
    right_did: &'static str,
    right_device_id: &'static str,
    left_provider: FixtureMlsProvider,
    right_provider: FixtureMlsProvider,
    left_signer: SignatureKeyPair,
    right_signer: SignatureKeyPair,
    left_group: MlsGroup,
    right_group: MlsGroup,
    context: ConversationContext,
    processed_application_count: usize,
}

struct TransportedApplication {
    application_message: Vec<u8>,
    sender: ApplicationMlsSender,
    evidence: Value,
}

struct ManifestApplicationCounts {
    top_level: usize,
    scenario_steps: usize,
    scenario_unique_transports: usize,
    scenario_replay_occurrences: usize,
    total_occurrences: usize,
    total: usize,
    same_did_lane: usize,
    different_did_lane: usize,
    same_did_lane_occurrences: usize,
    different_did_lane_occurrences: usize,
}

impl ApplicationTransportFixture {
    fn new() -> Result<Self> {
        let same_did_lane = TransportLane::new(
            FIXTURE_GROUP_ID,
            uuid(0x11),
            DID,
            DEVICE_ID,
            SIGNING_SEED,
            FIXTURE_ALICE_RANDOM_SEED,
            RECEIVER_DID,
            RECEIVER_DEVICE_ID,
            RECEIVER_SIGNING_SEED,
            FIXTURE_BOB_RANDOM_SEED,
        )?;
        FIXTURE_CONTEXT
            .set(same_did_lane.context.clone())
            .map_err(|_| "fixture context initialized twice")?;
        let different_did_lane = TransportLane::new(
            FIXTURE_FOREIGN_GROUP_ID,
            uuid(0x12),
            DID,
            DEVICE_ID,
            SIGNING_SEED,
            FIXTURE_FOREIGN_ALICE_RANDOM_SEED,
            FOREIGN_DID,
            FOREIGN_DEVICE_ID,
            FOREIGN_SIGNING_SEED,
            FIXTURE_FOREIGN_MEMBER_RANDOM_SEED,
        )?;
        Ok(Self {
            same_did_lane,
            different_did_lane,
        })
    }

    fn different_did_context(&self) -> ConversationContext {
        self.different_did_lane.context.clone()
    }

    fn encrypt_and_receive(
        &mut self,
        actor_did: &str,
        sender_device_id: &str,
        message_id: [u8; 16],
        prior: &ConversationContext,
        plaintext: &[u8],
    ) -> Result<TransportedApplication> {
        let same_lane = prior.conversation_id == self.same_did_lane.context.conversation_id
            && prior.group_id == self.same_did_lane.context.group_id
            && prior.epoch == self.same_did_lane.context.epoch;
        let different_lane = prior.conversation_id
            == self.different_did_lane.context.conversation_id
            && prior.group_id == self.different_did_lane.context.group_id
            && prior.epoch == self.different_did_lane.context.epoch;
        let (lane, lane_name) = if same_lane {
            (&mut self.same_did_lane, "sameDidTwoDevice")
        } else if different_lane {
            (&mut self.different_did_lane, "differentDidAuthor")
        } else {
            return Err("application prior is not bound to a fixture MLS lane".into());
        };
        let mut transported =
            lane.encrypt_and_receive(actor_did, sender_device_id, message_id, prior, plaintext)?;
        let evidence = transported
            .evidence
            .as_object_mut()
            .ok_or("transport evidence is not an object")?;
        evidence.insert("laneName".into(), json!(lane_name));
        evidence.insert("senderActorDid".into(), json!(actor_did));
        evidence.insert("senderDeviceId".into(), json!(sender_device_id));
        Ok(transported)
    }
}

impl TransportLane {
    #[allow(clippy::too_many_arguments)]
    fn new(
        group_id: [u8; 32],
        conversation_id: [u8; 16],
        left_did: &'static str,
        left_device_id: &'static str,
        left_signing_seed: [u8; 32],
        left_random_seed: [u8; 32],
        right_did: &'static str,
        right_device_id: &'static str,
        right_signing_seed: [u8; 32],
        right_random_seed: [u8; 32],
    ) -> Result<Self> {
        let left_provider = FixtureMlsProvider::new(left_random_seed)?;
        let right_provider = FixtureMlsProvider::new(right_random_seed)?;
        let left_signer = fixed_mls_signer(left_signing_seed);
        let right_signer = fixed_mls_signer(right_signing_seed);
        left_signer.store(left_provider.storage())?;
        right_signer.store(right_provider.storage())?;
        let left_public_key = left_signer.to_public_vec();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(fixture_capabilities())
            .lifetime(Lifetime::init(0, u64::MAX))
            .build();
        let mut left_group = MlsGroup::new_with_group_id(
            &left_provider,
            &left_signer,
            &config,
            GroupId::from_slice(&group_id),
            CredentialWithKey {
                credential: BasicCredential::new(
                    format!("{left_did}#{left_device_id}").into_bytes(),
                )
                .into(),
                signature_key: left_public_key.into(),
            },
        )?;
        let right_public_key = right_signer.to_public_vec();
        let right_key_package = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(0, u64::MAX))
            .leaf_node_capabilities(fixture_capabilities())
            .build(
                CIPHERSUITE,
                &right_provider,
                &right_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(
                        format!("{right_did}#{right_device_id}").into_bytes(),
                    )
                    .into(),
                    signature_key: right_public_key.into(),
                },
            )?
            .key_package()
            .clone();
        let (_commit, welcome, _group_info) = left_group.add_members(
            &left_provider,
            &left_signer,
            std::slice::from_ref(&right_key_package),
        )?;
        left_group.merge_pending_commit(&left_provider)?;
        let welcome = MlsMessageIn::tls_deserialize_exact(&welcome.tls_serialize_detached()?)?
            .into_welcome()
            .ok_or("fixture add did not produce an MLS Welcome")?;
        let right_group =
            StagedWelcome::new_from_welcome(&right_provider, config.join_config(), welcome, None)?
                .into_group(&right_provider)?;
        if left_group.epoch().as_u64() != 1
            || right_group.epoch().as_u64() != 1
            || left_group.members().count() != 2
            || right_group.members().count() != 2
        {
            return Err("fixture two-member MLS group did not converge at epoch 1".into());
        }
        let group_context = left_group.export_group_context();
        if right_group
            .export_group_context()
            .tls_serialize_detached()?
            != group_context.tls_serialize_detached()?
        {
            return Err("fixture Alice and Bob GroupContexts differ".into());
        }
        let context = ConversationContext {
            conversation_id,
            generation: 1,
            state_version: 2,
            group_id: group_context
                .group_id()
                .as_slice()
                .try_into()
                .map_err(|_| "fixture MLS group id is not 32 bytes")?,
            epoch: group_context.epoch().as_u64(),
            group_context_hash: Sha256::digest(group_context.tls_serialize_detached()?).into(),
            confirmation_tag: confirmation_tag_bytes(left_group.confirmation_tag())?,
            lifecycle: Lifecycle::Active,
        };
        Ok(Self {
            left_did,
            left_device_id,
            right_did,
            right_device_id,
            left_provider,
            right_provider,
            left_signer,
            right_signer,
            left_group,
            right_group,
            context,
            processed_application_count: 0,
        })
    }

    fn encrypt_and_receive(
        &mut self,
        actor_did: &str,
        sender_device_id: &str,
        message_id: [u8; 16],
        prior: &ConversationContext,
        plaintext: &[u8],
    ) -> Result<TransportedApplication> {
        let transported = if actor_did == self.left_did && sender_device_id == self.left_device_id {
            transport_application(
                &mut self.left_group,
                &self.left_provider,
                &self.left_signer,
                &mut self.right_group,
                &self.right_provider,
                self.right_did,
                self.right_device_id,
                message_id,
                prior,
                plaintext,
            )?
        } else if actor_did == self.right_did && sender_device_id == self.right_device_id {
            transport_application(
                &mut self.right_group,
                &self.right_provider,
                &self.right_signer,
                &mut self.left_group,
                &self.left_provider,
                self.left_did,
                self.left_device_id,
                message_id,
                prior,
                plaintext,
            )?
        } else {
            return Err(format!(
                "unknown fixture MLS sender {actor_did}#{sender_device_id} for selected lane"
            )
            .into());
        };
        self.processed_application_count += 1;
        Ok(transported)
    }
}

#[allow(clippy::too_many_arguments)]
fn transport_application(
    sender_group: &mut MlsGroup,
    sender_provider: &FixtureMlsProvider,
    sender_signer: &SignatureKeyPair,
    receiver_group: &mut MlsGroup,
    receiver_provider: &FixtureMlsProvider,
    receiver_did: &str,
    receiver_device_id: &str,
    message_id: [u8; 16],
    prior: &ConversationContext,
    plaintext: &[u8],
) -> Result<TransportedApplication> {
    let aad = encode_mls_application_aad(&MlsApplicationAadBinding {
        conversation_id: prior.conversation_id,
        generation: prior.generation,
        message_id,
        prior: prior.clone(),
    })?;
    sender_group.set_aad(aad.clone());
    let message = sender_group.create_message(sender_provider, sender_signer, plaintext)?;
    let bytes = message.tls_serialize_detached()?;
    let parsed = MlsMessageIn::tls_deserialize_exact(&bytes)?;
    if parsed.tls_serialize_detached()? != bytes {
        return Err("fixture MLSMessage parse/reencode mismatch".into());
    }
    let protocol = parsed
        .into_protocol_message()
        .ok_or("fixture application is not an MLS protocol message")?;
    if protocol.group_id().as_slice() != prior.group_id
        || protocol.epoch().as_u64() != prior.epoch
        || protocol.content_type() != ContentType::Application
    {
        return Err("fixture application PrivateMessage coordinates mismatch".into());
    }
    if !matches!(&protocol, ProtocolMessage::PrivateMessage(message) if message.aad() == aad) {
        return Err("fixture application PrivateMessage AAD mismatch".into());
    }
    let processed = receiver_group.process_message(receiver_provider, protocol)?;
    if processed.group_id().as_slice() != prior.group_id
        || processed.epoch().as_u64() != prior.epoch
        || processed.aad() != aad
    {
        return Err("fixture receiver processed different MLS coordinates".into());
    }
    let sender_leaf_index = match processed.sender() {
        Sender::Member(index) => index.u32(),
        _ => return Err("fixture receiver did not authenticate a member sender".into()),
    };
    if processed.credential().credential_type() != CredentialType::Basic {
        return Err("fixture receiver sender credential is not BasicCredential".into());
    }
    let credential_identity = processed.credential().serialized_content().to_vec();
    let member = receiver_group
        .members()
        .find(|member| member.index.u32() == sender_leaf_index)
        .ok_or("fixture receiver cannot resolve authenticated sender leaf")?;
    let leaf_signature_public_key = member.signature_key.as_slice().to_vec();
    let expected_sender = member.credential.serialized_content();
    if credential_identity != expected_sender {
        return Err("fixture processed sender credential differs from receiver member leaf".into());
    }
    let decrypted = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        _ => return Err("fixture receiver did not process application content".into()),
    };
    if decrypted != plaintext {
        return Err("fixture receiver decrypted different application plaintext".into());
    }
    let sender = ApplicationMlsSender::test_only(
        true,
        credential_identity.clone(),
        leaf_signature_public_key.clone(),
    );
    Ok(TransportedApplication {
        application_message: bytes,
        sender,
        evidence: json!({
            "mode": "twoMemberOpenMlsReceiver",
            "memberCount": 2,
            "senderLeafIndex": sender_leaf_index,
            "senderCredentialType": "BasicCredential",
            "senderCredentialIdentityHex": hex::encode(&credential_identity),
            "senderLeafSignaturePublicKeyHex": hex::encode(&leaf_signature_public_key),
            "receiverActorDid": receiver_did,
            "receiverDeviceId": receiver_device_id,
            "conversationIdHex": hex::encode(prior.conversation_id),
            "groupIdHex": hex::encode(prior.group_id),
            "epoch": prior.epoch,
            "applicationAadLength": aad.len(),
            "applicationAadSha256Hex": sha256(&aad),
            "processedAadExact": true,
            "decryptedPlaintextLength": decrypted.len(),
            "decryptedPlaintextSha256Hex": sha256(&decrypted),
            "decryptedPlaintextExact": true,
        }),
    })
}

fn manifest_application_counts(
    vectors: &[Value],
    scenarios: &[Value],
    transport: &ApplicationTransportFixture,
) -> Result<ManifestApplicationCounts> {
    let mut first_application_by_fingerprint = HashMap::new();
    let mut scenario_steps = 0;
    let mut scenario_unique_transports = 0;
    let mut same_did_lane = 0;
    let mut different_did_lane = 0;
    let mut same_did_lane_occurrences = 0;
    let mut different_did_lane_occurrences = 0;

    let mut visit_occurrence = |fixture: &Value, scope: &str| -> Result<bool> {
        let fingerprint = fixture["outerEntryFingerprintHex"]
            .as_str()
            .ok_or_else(|| format!("{scope} application lacks an outer-entry fingerprint"))?;
        let is_same_lane = manifest_fixture_uses_lane(fixture, transport, scope)?;
        if is_same_lane {
            same_did_lane_occurrences += 1;
        } else {
            different_did_lane_occurrences += 1;
        }
        let is_distinct = match first_application_by_fingerprint.get(fingerprint) {
            Some(first_application) => {
                if first_application != fixture {
                    return Err(format!(
                        "{scope} application reuses transport fingerprint {fingerprint} with different fixture bytes"
                    )
                    .into());
                }
                false
            }
            None => {
                first_application_by_fingerprint.insert(fingerprint.to_owned(), fixture.clone());
                true
            }
        };
        if is_distinct {
            if is_same_lane {
                same_did_lane += 1;
            } else {
                different_did_lane += 1;
            }
        }
        Ok(is_distinct)
    };

    for vector in vectors {
        if !visit_occurrence(vector, "top-level")? {
            return Err("top-level application vectors reuse a transport fingerprint".into());
        }
    }
    for scenario in scenarios {
        for step in scenario["steps"]
            .as_array()
            .ok_or("reducer scenario steps are not an array")?
        {
            if step["op"] != "application" {
                continue;
            }
            scenario_steps += 1;
            let is_distinct = visit_occurrence(&step["application"], "scenario")?;
            let is_exact_replay = step["expect"]["result"]["code"] == "exactReplay";
            if is_distinct == is_exact_replay {
                return Err(format!(
                    "scenario application transport/replay mismatch for {}: distinct={is_distinct}, result={}",
                    step["application"]["name"].as_str().unwrap_or("unnamed"),
                    step["expect"]["result"]["code"]
                )
                .into());
            }
            if is_exact_replay && step["expect"]["stateBefore"] != step["expect"]["stateAfter"] {
                return Err(format!(
                    "scenario exact application replay mutated state for {}",
                    step["application"]["name"].as_str().unwrap_or("unnamed")
                )
                .into());
            }
            if is_distinct {
                scenario_unique_transports += 1;
            }
        }
    }

    let total = vectors.len() + scenario_unique_transports;
    let total_occurrences = vectors.len() + scenario_steps;
    let scenario_replay_occurrences = scenario_steps - scenario_unique_transports;
    let actual_same = transport.same_did_lane.processed_application_count;
    let actual_different = transport.different_did_lane.processed_application_count;
    if same_did_lane != actual_same
        || different_did_lane != actual_different
        || total != actual_same + actual_different
        || total_occurrences != same_did_lane_occurrences + different_did_lane_occurrences
    {
        return Err(format!(
            "manifest transport traversal distinct=({same_did_lane}, {different_did_lane}, {total}) occurrences=({same_did_lane_occurrences}, {different_did_lane_occurrences}, {total_occurrences}) does not match receiver counters ({actual_same}, {actual_different}, {})",
            actual_same + actual_different,
        )
        .into());
    }
    Ok(ManifestApplicationCounts {
        top_level: vectors.len(),
        scenario_steps,
        scenario_unique_transports,
        scenario_replay_occurrences,
        total_occurrences,
        total,
        same_did_lane,
        different_did_lane,
        same_did_lane_occurrences,
        different_did_lane_occurrences,
    })
}

fn manifest_fixture_uses_lane(
    fixture: &Value,
    transport: &ApplicationTransportFixture,
    scope: &str,
) -> Result<bool> {
    let evidence = &fixture["transportEvidence"];
    let entry_cbor = hex::decode(
        fixture["signedOuterEntry"]["applicationEntryCborHex"]
            .as_str()
            .ok_or_else(|| format!("{scope} application lacks signed prior evidence"))?,
    )?;
    let entry: CorpusApplicationEntry = serde_ipld_dagcbor::from_slice(&entry_cbor)?;
    let prior = &entry.signed_request.body.prior;
    if evidence["conversationIdHex"] != hex::encode(prior.conversation_id)
        || evidence["groupIdHex"] != hex::encode(prior.group_id)
        || evidence["epoch"] != prior.epoch
    {
        return Err(
            format!("{scope} application transport coordinates differ from signed prior").into(),
        );
    }
    let sender = (
        evidence["senderActorDid"]
            .as_str()
            .ok_or_else(|| format!("{scope} application lacks sender DID evidence"))?,
        evidence["senderDeviceId"]
            .as_str()
            .ok_or_else(|| format!("{scope} application lacks sender device evidence"))?,
    );
    let signed_sender = (
        entry.signed_request.body.actor_did.as_str(),
        uuid::Uuid::from_bytes(entry.signed_request.body.actor_device_id)
            .hyphenated()
            .to_string(),
    );
    let credential_mismatch = fixture["name"] == "senderCredentialMismatch";
    if credential_mismatch {
        if sender.0 == signed_sender.0 && sender.1 == signed_sender.1 {
            return Err(
                "credential-mismatch vector did not differ from the signed outer actor".into(),
            );
        }
    } else if sender.0 != signed_sender.0 || sender.1 != signed_sender.1 {
        return Err(
            format!("{scope} application sender evidence differs from signed outer actor").into(),
        );
    }
    let receiver = (
        evidence["receiverActorDid"]
            .as_str()
            .ok_or_else(|| format!("{scope} application lacks receiver DID evidence"))?,
        evidence["receiverDeviceId"]
            .as_str()
            .ok_or_else(|| format!("{scope} application lacks receiver device evidence"))?,
    );
    for (is_same, name, lane) in [
        (true, "sameDidTwoDevice", &transport.same_did_lane),
        (false, "differentDidAuthor", &transport.different_did_lane),
    ] {
        let coordinates_match = prior.conversation_id == lane.context.conversation_id
            && prior.group_id == lane.context.group_id
            && prior.epoch == lane.context.epoch;
        let endpoints_match = (sender == (lane.left_did, lane.left_device_id)
            && receiver == (lane.right_did, lane.right_device_id))
            || (sender == (lane.right_did, lane.right_device_id)
                && receiver == (lane.left_did, lane.left_device_id));
        if coordinates_match && endpoints_match {
            if evidence["laneName"] != name {
                return Err(
                    format!("{scope} application lane name does not match coordinates").into(),
                );
            }
            return Ok(is_same);
        }
    }
    Err(format!("{scope} application references an unknown lane identity").into())
}

fn fixture_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

fn fixed_mls_signer(seed: [u8; 32]) -> SignatureKeyPair {
    let signing_key = SigningKey::from_bytes(&seed);
    SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        seed.to_vec(),
        signing_key.verifying_key().to_bytes().to_vec(),
    )
}

fn confirmation_tag_bytes(tag: &ConfirmationTag) -> Result<[u8; 32]> {
    let encoded = tag.tls_serialize_detached()?;
    let bytes = VLBytes::tls_deserialize_exact(&encoded)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "fixture confirmation tag is not 32 bytes".into())
}

fn main() -> Result<()> {
    if std::env::var(OPT_IN_ENV).as_deref() != Ok("1") {
        return Err(format!(
            "refusing to rewrite the shared corpus; set {OPT_IN_ENV}=1 explicitly"
        )
        .into());
    }

    let mut transport = ApplicationTransportFixture::new()?;

    let text = frame(
        0x51,
        ApplicationBody::Message(MessageBody {
            text: Some("blue.catbird.chat application fixture".into()),
            reply_to: None,
            embed: None,
        }),
    );
    let target = MessageTarget {
        target_seq: 1,
        target_message_id: uuid(0x51),
    };
    let gif = frame(
        0x52,
        ApplicationBody::Message(MessageBody {
            text: Some("encrypted GIF".into()),
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedImage(EncryptedImage {
                blob: blob(0x70),
                mime_type: "image/gif".into(),
                width: 320,
                height: 200,
                alt_text: Some("a flying catbird".into()),
                blurhash: Some("LEHV6nWB2yk8pyo0adR*.7kCMdnj".into()),
            })),
        }),
    );
    let mut waveform = [0_u8; 64];
    for (index, sample) in waveform.iter_mut().enumerate() {
        *sample = (index * 4).min(255) as u8;
    }
    let audio = frame(
        0x53,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedAudio(EncryptedAudio {
                blob: blob(0x71),
                mime_type: "audio/opus".into(),
                duration_millis: 1_250,
                waveform,
                transcript: Some("catbird song".into()),
            })),
        }),
    );
    let blurhash_minimum = frame(
        0x4d,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedImage(EncryptedImage {
                blob: blob(0x4d),
                mime_type: "image/png".into(),
                width: 1,
                height: 1,
                alt_text: None,
                blurhash: Some("abcdef".into()),
            })),
        }),
    );
    let blurhash_maximum = frame(
        0x4e,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedImage(EncryptedImage {
                blob: blob(0x4e),
                mime_type: "image/png".into(),
                width: 1,
                height: 1,
                alt_text: None,
                blurhash: Some("a".repeat(256)),
            })),
        }),
    );
    let record = frame(
        0x54,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                uri: "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz".into(),
                cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
            })),
        }),
    );
    let record_mixed_case_terminal = frame(
        0x4f,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                uri: "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.Post/CaseSensitive-RKey"
                    .into(),
                cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
            })),
        }),
    );
    let record_hostname_did = frame(
        0x4c,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                uri: "at://did:web:example.com/com.example.Record/rKeyABC".into(),
                cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
            })),
        }),
    );
    let record_handle = frame(
        0x4b,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                uri: "at://alice.com/com.example.Record/rKeyABC".into(),
                cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
            })),
        }),
    );
    let record_for_uri = |fill, uri: String| {
        frame(
            fill,
            ApplicationBody::Message(MessageBody {
                text: None,
                reply_to: None,
                embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                    uri,
                    cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
                })),
            }),
        )
    };
    let maximum_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let record_did_web_label_63 = record_for_uri(
        0x46,
        format!("at://did:web:{}.com/app.bsky.feed.post/3kz", "a".repeat(63)),
    );
    let record_did_web_host_253 = record_for_uri(
        0x47,
        format!("at://did:web:{maximum_host}/app.bsky.feed.post/3kz"),
    );
    let record_handle_label_63 = record_for_uri(
        0x48,
        format!("at://{}.com/app.bsky.feed.post/3kz", "a".repeat(63)),
    );
    let record_handle_host_253 =
        record_for_uri(0x49, format!("at://{maximum_host}/app.bsky.feed.post/3kz"));
    let link = frame(
        0x55,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::ExternalLink(ExternalLink {
                uri: "https://catbird.blue/chat".into(),
                title: Some("Catbird".into()),
                description: Some("Private group chat".into()),
            })),
        }),
    );
    let reaction = frame(
        0x56,
        ApplicationBody::Reaction(ReactionBody {
            target: target.clone(),
            emoji: "🥳".into(),
            operation: ReactionOperation::Add,
        }),
    );
    let reaction_remove = frame(
        0x5e,
        ApplicationBody::Reaction(ReactionBody {
            target: target.clone(),
            emoji: "🥳".into(),
            operation: ReactionOperation::Remove,
        }),
    );
    let reply = frame(
        0x5f,
        ApplicationBody::Message(MessageBody {
            text: Some("reply".into()),
            reply_to: Some(target.clone()),
            embed: None,
        }),
    );
    let edit = frame(
        0x57,
        ApplicationBody::Edit(EditBody {
            target: target.clone(),
            replacement_text: "corrected".into(),
        }),
    );
    let tombstone = frame(
        0x58,
        ApplicationBody::Tombstone(TombstoneBody {
            target: target.clone(),
        }),
    );
    let read_state = frame(
        0x59,
        ApplicationBody::ReadState(ReadStateBody {
            through_seq: 1,
            through_message_id: target.target_message_id,
        }),
    );

    let gif_outer = outer_for_frame(&gif).unwrap();
    let audio_outer = outer_for_frame(&audio).unwrap();
    let mut vectors = vec![
        supported_vector(&mut transport, "text", &text, vec![], "message")?,
        supported_vector(
            &mut transport,
            "encryptedGif",
            &gif,
            vec![gif_outer.clone()],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "encryptedAudio",
            &audio,
            vec![audio_outer],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "blurhashMinimum",
            &blurhash_minimum,
            vec![outer_for_frame(&blurhash_minimum).unwrap()],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "blurhashMaximum",
            &blurhash_maximum,
            vec![outer_for_frame(&blurhash_maximum).unwrap()],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordDidPlcLowercaseAccepted",
            &record,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordCollectionAndRkeyCasePreserved",
            &record_mixed_case_terminal,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordDidWebLowercaseHostnameAccepted",
            &record_hostname_did,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordHandleLowercaseHostnameAccepted",
            &record_handle,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordDidWebLabel63Accepted",
            &record_did_web_label_63,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordDidWebHost253Accepted",
            &record_did_web_host_253,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordHandleLabel63Accepted",
            &record_handle_label_63,
            vec![],
            "message",
        )?,
        supported_vector(
            &mut transport,
            "atRecordHandleHost253Accepted",
            &record_handle_host_253,
            vec![],
            "message",
        )?,
        supported_vector(&mut transport, "externalLink", &link, vec![], "message")?,
        supported_vector(&mut transport, "reactionAdd", &reaction, vec![], "reaction")?,
        supported_vector(
            &mut transport,
            "reactionRemove",
            &reaction_remove,
            vec![],
            "reaction",
        )?,
        supported_vector(
            &mut transport,
            "messageWithReplyTo",
            &reply,
            vec![],
            "message",
        )?,
        supported_vector(&mut transport, "edit", &edit, vec![], "edit")?,
        supported_vector(&mut transport, "tombstone", &tombstone, vec![], "tombstone")?,
        supported_vector(
            &mut transport,
            "readState",
            &read_state,
            vec![],
            "readState",
        )?,
    ];

    let future = serde_ipld_dagcbor::to_vec(&FutureWire {
        protocol: "blue.catbird.chat.application",
        version: 2,
        message_id: uuid(0x5a),
        context: context(),
        body: FutureBody {
            poll: FuturePoll {
                question: "which migration?",
            },
        },
    })?;
    vectors.push(raw_vector(
        &mut transport,
        "futureVersionOpaque",
        uuid(0x5a),
        future,
        vec![],
        "exact",
        "unsupported",
        None,
    )?);

    vectors.push(raw_vector(
        &mut transport,
        "innerOuterMessageIdMismatch",
        uuid(0xa0),
        encode_application_content(&text)?,
        vec![],
        "exact",
        "rejected",
        Some("bindingMismatch"),
    )?);
    let mut context_mismatches = Vec::new();
    let mut mismatch = text.clone();
    mismatch.context.conversation_id = uuid(0xa2);
    context_mismatches.push(("innerOuterConversationIdMismatch", mismatch));
    let mut mismatch = text.clone();
    mismatch.context.generation += 1;
    context_mismatches.push(("innerOuterGenerationMismatch", mismatch));
    let mut mismatch = text.clone();
    mismatch.context.state_version += 1;
    context_mismatches.push(("innerOuterStateVersionMismatch", mismatch));
    let mut mismatch = text.clone();
    mismatch.context.group_id[0] ^= 1;
    context_mismatches.push(("innerOuterGroupIdMismatch", mismatch));
    let mut mismatch = text.clone();
    mismatch.context.epoch += 1;
    context_mismatches.push(("innerOuterEpochMismatch", mismatch));
    let mut mismatch = text.clone();
    mismatch.context.group_context_hash[0] ^= 1;
    context_mismatches.push(("innerOuterGroupContextHashMismatch", mismatch));
    let mut mismatch = text.clone();
    mismatch.context.confirmation_tag[0] ^= 1;
    context_mismatches.push(("innerOuterConfirmationTagMismatch", mismatch));
    for (name, frame) in context_mismatches {
        vectors.push(raw_vector(
            &mut transport,
            name,
            frame.message_id,
            encode_application_content(&frame)?,
            vec![],
            "exact",
            "rejected",
            Some("bindingMismatch"),
        )?);
    }
    let wrong_lifecycle = encode_application_content_with_lifecycle(&text, "closed")?;
    vectors.push(with_field(
        raw_vector(
            &mut transport,
            "v1LifecycleClosedRejected",
            text.message_id,
            wrong_lifecycle,
            vec![],
            "exact",
            "rejected",
            Some("unknownField"),
        )?,
        "constructionEvidence",
        json!({
            "kind": "explicitRawCborField",
            "field": "context.lifecycle",
            "value": "closed",
            "byteSpliceUsed": false,
        }),
    ));
    let mut unsafe_integer = text.clone();
    unsafe_integer.context.generation = 9_007_199_254_740_992;
    vectors.push(with_field(
        raw_vector(
            &mut transport,
            "v1KnownContextGenerationAboveUint53",
            unsafe_integer.message_id,
            encode_application_content_unchecked(&unsafe_integer)?,
            vec![],
            "exact",
            "rejected",
            Some("integerOverflow"),
        )?,
        "constructionEvidence",
        json!({
            "kind": "knownContextIntegerField",
            "field": "context.generation",
            "valueDecimal": "9007199254740992",
            "unknownExtensionUsed": false,
        }),
    ));

    for (name, raw, reason) in canonical_rejection_vectors() {
        vectors.push(raw_vector(
            &mut transport,
            name,
            uuid(0xa1_u8.wrapping_add(vectors.len() as u8)),
            raw,
            vec![],
            "exact",
            "rejected",
            Some(reason),
        )?);
    }
    for (name, raw) in future_opaque_vectors() {
        vectors.push(raw_vector(
            &mut transport,
            name,
            uuid(0xb1_u8.wrapping_add(vectors.len() as u8)),
            raw,
            vec![],
            "exact",
            "unsupported",
            None,
        )?);
    }
    for (name, raw, reason) in future_rejection_vectors() {
        vectors.push(raw_vector(
            &mut transport,
            name,
            uuid(0xb9_u8.wrapping_add(vectors.len() as u8)),
            raw,
            vec![],
            "exact",
            "rejected",
            Some(reason),
        )?);
    }

    for (name, frame) in invalid_embed_vectors() {
        vectors.push(raw_vector(
            &mut transport,
            name,
            frame.message_id,
            encode_application_content_unchecked(&frame)?,
            vec![],
            "exact",
            "rejected",
            Some("invalidValue"),
        )?);
    }
    for (name, frame, outer, reason) in invalid_semantic_vectors() {
        vectors.push(raw_vector(
            &mut transport,
            name,
            frame.message_id,
            encode_application_content_unchecked(&frame)?,
            outer,
            "exact",
            "rejected",
            Some(reason),
        )?);
    }
    vectors.push(outer_rejection_vector(
        &mut transport,
        "outerMetadataBindingForbidden",
        &text,
        vec![CorpusOuterBlobBinding {
            blob_id: uuid(0xed),
            ciphertext_sha256: [0xed; 32],
            ciphertext_size: 48,
            purpose: BlobPurpose::Metadata,
        }],
        "invalidValue",
    )?);

    let unknown_top = serde_ipld_dagcbor::to_vec(&UnknownTopWire {
        protocol: "blue.catbird.chat.application",
        version: 1,
        message_id: uuid(0x5b),
        context: context(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("closed v1".into()),
            reply_to: None,
            embed: None,
        }),
        extension: "forbidden",
    })?;
    vectors.push(raw_vector(
        &mut transport,
        "unknownV1TopField",
        uuid(0x5b),
        unknown_top,
        vec![],
        "exact",
        "rejected",
        Some("unknownField"),
    )?);

    let unknown_body = serde_ipld_dagcbor::to_vec(&UnknownBodyWire {
        protocol: "blue.catbird.chat.application",
        version: 1,
        message_id: uuid(0x5c),
        context: context(),
        body: TypingBody {
            typing: TypingPayload {
                state: "active".into(),
            },
        },
    })?;
    vectors.push(raw_vector(
        &mut transport,
        "transportTypingBodyForbidden",
        uuid(0x5c),
        unknown_body,
        vec![],
        "exact",
        "rejected",
        Some("unknownField"),
    )?);

    let null_v1 = serde_ipld_dagcbor::to_vec(&NullTextWire {
        protocol: "blue.catbird.chat.application",
        version: 1,
        message_id: uuid(0x5d),
        context: context(),
        body: NullMessageBody {
            message: NullMessage { text: None },
        },
    })?;
    vectors.push(raw_vector(
        &mut transport,
        "nullV1Field",
        uuid(0x5d),
        null_v1,
        vec![],
        "exact",
        "rejected",
        Some("nullNotAllowed"),
    )?);

    vectors.push(raw_vector(
        &mut transport,
        "gifMissingOuterBinding",
        gif.message_id,
        encode_application_content(&gif)?,
        vec![],
        "exact",
        "rejected",
        Some("bindingMismatch"),
    )?);
    vectors.push(raw_vector(
        &mut transport,
        "textDanglingOuterBinding",
        text.message_id,
        encode_application_content(&text)?,
        vec![gif_outer.clone()],
        "exact",
        "rejected",
        Some("bindingMismatch"),
    )?);
    let mut wrong_hash = gif_outer.clone();
    wrong_hash.ciphertext_sha256[0] ^= 1;
    vectors.push(raw_vector(
        &mut transport,
        "gifOuterHashMismatch",
        gif.message_id,
        encode_application_content(&gif)?,
        vec![wrong_hash],
        "exact",
        "rejected",
        Some("bindingMismatch"),
    )?);
    let mut credential_mismatch_frame = text.clone();
    credential_mismatch_frame.message_id = uuid(0xa4);
    credential_mismatch_frame.context = transport.different_did_context();
    vectors.push(receiver_fact_negative_vector(
        &mut transport,
        "senderCredentialMismatch",
        &credential_mismatch_frame,
        FOREIGN_DID,
        FOREIGN_DEVICE_ID,
        &signing_key(),
        "credentialIdentity",
    )?);
    let alternate_outer_signing_key = SigningKey::from_bytes(&[0xa4; 32]);
    vectors.push(receiver_fact_negative_vector(
        &mut transport,
        "senderLeafKeyMismatch",
        &text,
        DID,
        DEVICE_ID,
        &alternate_outer_signing_key,
        "leafSignaturePublicKey",
    )?);
    let authority_boundary_vectors = authority_boundary_vectors(&vectors)?;
    let hint_authority_boundary_vectors = hint_authority_boundary_vectors()?;
    let identity_boundary_vectors = identity_boundary_vectors(&vectors)?;
    let outer_entry_rejection_vectors = outer_entry_rejection_vectors(&vectors)?;

    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let stack_root = crate_root.parent().ok_or("crate has no stack parent")?;
    ensure_cargo_lock_tracked(&crate_root)?;
    let generator_source = CapturedProvenanceFile::capture_source(
        stack_root,
        &crate_root.join("examples/generate_chat_application_fixtures.rs"),
    )?;
    if generator_source.bytes != COMPILED_GENERATOR_SOURCE {
        return Err(
            "live generator source differs from the source embedded in the running binary".into(),
        );
    }
    let authority_source_files = capture_authority_sources(stack_root, &crate_root)?;
    let authority_sources = authority_source_files
        .iter()
        .map(CapturedProvenanceFile::source_record)
        .collect::<Vec<_>>();
    let authority_source_bytes = authority_source_files
        .iter()
        .map(|source| (source.relative_path.clone(), source.bytes.clone()))
        .collect::<Vec<_>>();
    let crypto_manifest = CapturedProvenanceFile::capture_artifact(
        stack_root,
        &stack_root.join("docs/generated-artifacts/mls-chat-v1/crypto-wire/manifest.json"),
    )?;
    let crypto_application_frame = CapturedProvenanceFile::capture_artifact(
        stack_root,
        &stack_root.join("docs/generated-artifacts/mls-chat-v1/crypto-wire/application-frame.cbor"),
    )?;
    let crypto_application_private = CapturedProvenanceFile::capture_artifact(
        stack_root,
        &stack_root
            .join("docs/generated-artifacts/mls-chat-v1/crypto-wire/application-private.mls"),
    )?;
    let crypto_verifier = CapturedProvenanceFile::capture_source(
        stack_root,
        &crate_root.join("tests/chat_crypto_wire_corpus_tests.rs"),
    )?;
    let frozen_crypto_reference = json!({
        "manifest": crypto_manifest.artifact_record(),
        "applicationFrame": crypto_application_frame.artifact_record(),
        "applicationPrivateMessage": crypto_application_private.artifact_record(),
        "verifier": crypto_verifier.source_record(),
        "verifierTestTarget": "chat_crypto_wire_corpus_tests",
        "verifierTestName": "frozen_crypto_wire_corpus_is_complete_hash_bound_and_consumable",
        "verificationCommand": "cargo test --locked --features test-utils --test chat_crypto_wire_corpus_tests frozen_crypto_wire_corpus_is_complete_hash_bound_and_consumable -- --nocapture",
    });
    let contract_source_files = [
        stack_root.join("PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json"),
        stack_root
            .join("PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.sendMessage.json"),
        stack_root.join("mls-ds/lexicon/blue/catbird/chat/blue.catbird.chat.defs.json"),
        stack_root.join("mls-ds/lexicon/blue/catbird/chat/blue.catbird.chat.sendMessage.json"),
        stack_root.join("docs/CHAT_PROTOCOL.md"),
        stack_root.join("docs/CHAT_APPLICATION_PROTOCOL.md"),
        stack_root.join("docs/superpowers/plans/2026-07-22-chat-protocol.md"),
        stack_root.join("docs/program/decisions/ADR-019-chat-protocol-clean-cutover.md"),
        stack_root.join("mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json"),
    ]
    .iter()
    .map(|path| CapturedProvenanceFile::capture_source(stack_root, path))
    .collect::<Result<Vec<_>>>()?;
    let mut contract_mirror_equality = Vec::new();
    for (name, client_index, server_index) in [
        ("defs", 0_usize, 2_usize),
        ("sendMessage", 1_usize, 3_usize),
    ] {
        let client = &contract_source_files[client_index];
        let server = &contract_source_files[server_index];
        if client.bytes != server.bytes {
            return Err(
                format!("{name} client/server lexicon mirrors differ byte-for-byte").into(),
            );
        }
        contract_mirror_equality.push(json!({
            "name": name,
            "clientPath": client.relative_path,
            "serverPath": server.relative_path,
            "byteEqual": true,
            "sha256Hex": sha256(&client.bytes),
        }));
    }
    let contract_sources = contract_source_files
        .iter()
        .map(CapturedProvenanceFile::source_record)
        .collect::<Vec<_>>();
    let cargo_toml =
        CapturedProvenanceFile::capture_source(stack_root, &crate_root.join("Cargo.toml"))?;
    let cargo_lock =
        CapturedProvenanceFile::capture_source(stack_root, &crate_root.join("Cargo.lock"))?;
    let signed_terminal_close = signed_former_device_terminal_fixture(&contract_source_files[8])?;
    let reducer_scenarios = reducer_scenarios(&mut transport, &signed_terminal_close)?;
    let reducer_initialization_vectors = reducer_initialization_vectors()?;
    let reducer_schedule_validation_vectors = reducer_schedule_validation_vectors()?;
    let application_counts = manifest_application_counts(&vectors, &reducer_scenarios, &transport)?;
    let manifest = json!({
        "schemaVersion": 1,
        "protocol": "blue.catbird.chat.application",
        "protocolVersion": 1,
        "encoding": "deterministic RFC8949 length-first DAG-CBOR",
        "generator": {
            "command": format!("{OPT_IN_ENV}=1 cargo run --locked --features test-utils --example generate_chat_application_fixtures"),
            "source": "catbird-mls/examples/generate_chat_application_fixtures.rs",
            "sourceSha256Hex": sha256(&generator_source.bytes),
            "cargoToml": cargo_toml.source_record(),
            "cargoLock": with_field(
                cargo_lock.source_record(),
                "jjTracked",
                json!(true),
            ),
            "authoritySources": authority_sources,
            "authoritySourcesAggregateAlgorithm": "SHA-256(domain || count:u64be || repeated(pathLength:u64be || UTF-8 path || sourceLength:u64be || exact source bytes)), records sorted by path",
            "authoritySourcesAggregateDomainHex": hex::encode(AUTHORITY_SOURCE_AGGREGATE_DOMAIN),
            "authoritySourcesAggregateSha256Hex": hex::encode(authority_source_aggregate(&authority_source_bytes)),
            "contractSources": contract_sources,
            "contractMirrorEquality": contract_mirror_equality,
            "frozenCryptoManifestSha256Hex": sha256(&crypto_manifest.bytes),
            "frozenCryptoReference": frozen_crypto_reference,
        },
        "identity": {
            "actorDid": DID,
            "actorDeviceId": DEVICE_ID,
            "credentialIdentity": format!("{DID}#{DEVICE_ID}"),
            "signaturePublicKeyHex": hex::encode(signature_public_key()),
            "actors": [
                {
                    "actorDid": DID,
                    "devices": [
                        {
                            "actorDeviceId": DEVICE_ID,
                            "credentialIdentity": format!("{DID}#{DEVICE_ID}"),
                            "signaturePublicKeyHex": hex::encode(fixture_signature_public_key(DEVICE_ID)?),
                        },
                        {
                            "actorDeviceId": RECEIVER_DEVICE_ID,
                            "credentialIdentity": format!("{DID}#{RECEIVER_DEVICE_ID}"),
                            "signaturePublicKeyHex": hex::encode(fixture_signature_public_key(RECEIVER_DEVICE_ID)?),
                        },
                    ],
                },
                {
                    "actorDid": FOREIGN_DID,
                    "devices": [{
                        "actorDeviceId": FOREIGN_DEVICE_ID,
                        "credentialIdentity": format!("{FOREIGN_DID}#{FOREIGN_DEVICE_ID}"),
                        "signaturePublicKeyHex": hex::encode(fixture_signature_public_key(FOREIGN_DEVICE_ID)?),
                    }],
                },
            ],
        },
        "context": context_json(),
        "liveProof": {
            "profile": "two independent deterministic two-member OpenMLS 0.8.1 lanes",
            "transportLaneCount": 2,
            "memberCountPerLane": 2,
            "everyEncryptedApplicationProcessedByReceiverBeforeAuthorityIngest": true,
            "senderFactsExtractedFromProcessedMemberLeaf": true,
            "basicCredentialRequired": true,
            "topLevelApplicationVectorCount": application_counts.top_level,
            "scenarioApplicationStepCount": application_counts.scenario_steps,
            "scenarioUniqueTransportCount": application_counts.scenario_unique_transports,
            "scenarioReplayOccurrenceCount": application_counts.scenario_replay_occurrences,
            "totalApplicationOccurrenceCount": application_counts.total_occurrences,
            "totalProcessedApplicationCount": application_counts.total,
            "perLaneProcessedApplicationCounts": {
                "sameDidTwoDevice": application_counts.same_did_lane,
                "differentDidAuthor": application_counts.different_did_lane,
            },
            "perLaneApplicationOccurrenceCounts": {
                "sameDidTwoDevice": application_counts.same_did_lane_occurrences,
                "differentDidAuthor": application_counts.different_did_lane_occurrences,
            },
            "applicationOccurrenceTraversalComplete": true,
            "utf8BoundaryVectorsAreCodecOnly": true,
            "reducerScenarioCount": reducer_scenarios.len(),
            "lanes": [
                {
                    "name": "sameDidTwoDevice",
                    "left": { "actorDid": DID, "actorDeviceId": DEVICE_ID },
                    "right": { "actorDid": RECEIVER_DID, "actorDeviceId": RECEIVER_DEVICE_ID },
                    "context": context_json(),
                },
                {
                    "name": "differentDidAuthor",
                    "left": { "actorDid": DID, "actorDeviceId": DEVICE_ID },
                    "right": { "actorDid": FOREIGN_DID, "actorDeviceId": FOREIGN_DEVICE_ID },
                    "context": context_value(&transport.different_did_context()),
                },
            ],
        },
        "limits": {
            "frameBytes": 65536,
            "imageCiphertextBytes": 10485760,
            "audioCiphertextBytes": 8388608,
            "waveformSamples": 64,
            "waveformSampleMinimum": 0,
            "waveformSampleMaximum": 255,
            "waveformSemantics": "chronological equal-duration amplitude buckets; presentation-only and untrusted",
        },
        "utf8BoundaryVectors": utf8_boundary_vectors()?,
        "vectors": vectors,
        "authorityBoundaryVectors": authority_boundary_vectors,
        "hintAuthorityBoundaryVectors": hint_authority_boundary_vectors,
        "signedControlEnvelopeVectors": [signed_terminal_close.json],
        "identityBoundaryVectors": identity_boundary_vectors,
        "outerEntryRejectionVectors": outer_entry_rejection_vectors,
        "reducerInitializationVectors": reducer_initialization_vectors,
        "reducerScheduleValidationVectors": reducer_schedule_validation_vectors,
        "reducerScenarios": reducer_scenarios,
    });
    let mut encoded = serde_json::to_vec_pretty(&manifest)?;
    encoded.push(b'\n');
    let assert_provenance_stable = || -> Result<()> {
        generator_source.assert_unchanged(stack_root)?;
        cargo_toml.assert_unchanged(stack_root)?;
        cargo_lock.assert_unchanged(stack_root)?;
        crypto_manifest.assert_unchanged(stack_root)?;
        crypto_application_frame.assert_unchanged(stack_root)?;
        crypto_application_private.assert_unchanged(stack_root)?;
        crypto_verifier.assert_unchanged(stack_root)?;
        for source in &authority_source_files {
            source.assert_unchanged(stack_root)?;
        }
        for source in &contract_source_files {
            source.assert_unchanged(stack_root)?;
        }
        Ok(())
    };
    assert_provenance_stable()?;
    let output = std::env::var_os(OUTPUT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            stack_root.join("docs/generated-artifacts/chat-application-v1/manifest.json")
        });
    let output_dir = output.parent().ok_or("fixture output has no parent")?;
    fs::create_dir_all(output_dir)?;
    let temp = output.with_extension("json.tmp");
    fs::write(&temp, &encoded)?;
    assert_provenance_stable()?;
    fs::rename(&temp, &output)?;
    println!("output={}", output.display());
    println!("manifestSha256Hex={}", sha256(&encoded));
    Ok(())
}

fn supported_vector(
    transport: &mut ApplicationTransportFixture,
    name: &str,
    frame: &ApplicationFrame,
    outer: Vec<CorpusOuterBlobBinding>,
    body_tag: &str,
) -> Result<Value> {
    let raw = encode_application_content(frame)?;
    let vector = raw_vector(
        transport,
        name,
        frame.message_id,
        raw,
        outer,
        "exact",
        "supported",
        None,
    )?;
    Ok(with_field(vector, "expectedBodyTag", json!(body_tag)))
}

#[allow(clippy::too_many_arguments)]
fn raw_vector(
    transport: &mut ApplicationTransportFixture,
    name: &str,
    message_id: [u8; 16],
    raw: Vec<u8>,
    outer: Vec<CorpusOuterBlobBinding>,
    sender_mode: &str,
    expected_disposition: &str,
    expected_reason: Option<&str>,
) -> Result<Value> {
    let outer_context = context();
    let transported =
        transport.encrypt_and_receive(DID, DEVICE_ID, message_id, &outer_context, &raw)?;
    let (entry_id, seq) = deterministic_entry_coordinates(name);
    let signed_outer = signed_application_fixture(
        entry_id,
        seq,
        message_id,
        outer_context,
        DID,
        DEVICE_ID,
        &outer,
        transported.application_message,
        &signing_key(),
    )?;
    if sender_mode != "exact" {
        return Err(format!("receiver-backed vector {name} has non-exact sender mode").into());
    }
    let entry_cbor = hex::decode(
        signed_outer.json["applicationEntryCborHex"]
            .as_str()
            .ok_or("fixture entry CBOR")?,
    )?;
    let registration = fixture_registration(DID, DEVICE_ID)?;
    let verified_outer = verify_application_outer_entry(&entry_cbor, &registration)?;
    if verified_outer.raw_entry() != entry_cbor
        || verified_outer.entry_id() != signed_outer.entry.entry_id
        || verified_outer.seq() != signed_outer.entry.seq
        || verified_outer.fingerprint() != signed_outer.fingerprint
        || verified_outer.request_digest()
            != hex::decode(
                signed_outer.json["requestDigestHex"]
                    .as_str()
                    .ok_or("fixture request digest")?,
            )?
            .as_slice()
    {
        return Err(format!("vector {name} outer verifier disagrees with fixture evidence").into());
    }
    let disposition = ingest_application_content(raw.clone(), &verified_outer, &transported.sender);
    let (actual_disposition, actual_reason) = match disposition {
        ApplicationContentDisposition::Supported(_) => ("supported", None),
        ApplicationContentDisposition::Unsupported(_) => ("unsupported", None),
        ApplicationContentDisposition::Rejected(rejected) => {
            ("rejected", Some(rejected.error().reason.code()))
        }
    };
    if actual_disposition != expected_disposition || actual_reason != expected_reason {
        return Err(format!(
            "vector {name} expected {expected_disposition}/{expected_reason:?}, got {actual_disposition}/{actual_reason:?}"
        )
        .into());
    }
    Ok(json!({
        "name": name,
        "messageIdHex": hex::encode(message_id),
        "cborHex": hex::encode(&raw),
        "length": raw.len(),
        "sha256Hex": sha256(&raw),
        "outerBlobBindings": outer.iter().map(outer_json).collect::<Vec<_>>(),
        "signedOuterEntry": signed_outer.json,
        "outerEntryFingerprintHex": hex::encode(signed_outer.fingerprint),
        "transportEvidence": transported.evidence,
        "senderMode": sender_mode,
        "expectedDisposition": expected_disposition,
        "expectedReason": expected_reason,
    }))
}

#[allow(clippy::too_many_arguments)]
fn receiver_fact_negative_vector(
    transport: &mut ApplicationTransportFixture,
    name: &str,
    frame: &ApplicationFrame,
    transport_actor_did: &str,
    transport_actor_device_id: &str,
    outer_signing_key: &SigningKey,
    mismatch_dimension: &str,
) -> Result<Value> {
    let raw = encode_application_content(frame)?;
    let transported = transport.encrypt_and_receive(
        transport_actor_did,
        transport_actor_device_id,
        frame.message_id,
        &frame.context,
        &raw,
    )?;
    let (entry_id, seq) = deterministic_entry_coordinates(name);
    let signed_outer = signed_application_fixture(
        entry_id,
        seq,
        frame.message_id,
        frame.context.clone(),
        DID,
        DEVICE_ID,
        &[],
        transported.application_message,
        outer_signing_key,
    )?;
    let outer_public_key = outer_signing_key.verifying_key().to_bytes();
    let registration = VerifiedApplicationDeviceRegistration::test_only(
        DID.into(),
        DEVICE_ID.into(),
        fixture_key_id(&outer_public_key),
        1,
        &outer_public_key,
    )?;
    let entry_cbor = hex::decode(
        signed_outer.json["applicationEntryCborHex"]
            .as_str()
            .ok_or("receiver-fact negative entry CBOR")?,
    )?;
    let verified_outer = verify_application_outer_entry(&entry_cbor, &registration)?;
    let expected_credential = format!("{DID}#{DEVICE_ID}").into_bytes();
    match mismatch_dimension {
        "credentialIdentity" => {
            if transported.sender.credential_identity() == expected_credential {
                return Err(
                    "credential-mismatch fixture did not use a distinct member identity".into(),
                );
            }
        }
        "leafSignaturePublicKey" => {
            if transported.sender.credential_identity() != expected_credential
                || transported.sender.leaf_signature_public_key() == outer_public_key
            {
                return Err(
                    "leaf-key-mismatch fixture changed more than the registered leaf key binding"
                        .into(),
                );
            }
        }
        _ => {
            return Err(
                format!("unknown receiver-fact mismatch dimension {mismatch_dimension}").into(),
            )
        }
    }
    let disposition = ingest_application_content(raw.clone(), &verified_outer, &transported.sender);
    let ApplicationContentDisposition::Rejected(rejected) = disposition else {
        return Err(format!("receiver-fact negative {name} was not rejected").into());
    };
    if rejected.error().reason.code() != "bindingMismatch" {
        return Err(format!(
            "receiver-fact negative {name} expected bindingMismatch, got {}",
            rejected.error().reason.code()
        )
        .into());
    }
    Ok(json!({
        "name": name,
        "messageIdHex": hex::encode(frame.message_id),
        "cborHex": hex::encode(&raw),
        "length": raw.len(),
        "sha256Hex": sha256(&raw),
        "outerBlobBindings": [],
        "signedOuterEntry": signed_outer.json,
        "outerEntryFingerprintHex": hex::encode(signed_outer.fingerprint),
        "transportEvidence": transported.evidence,
        "senderMode": "receiverFactsExact",
        "senderFactsSource": "processedMemberLeaf",
        "receiverFactsUsedWithoutMutation": true,
        "senderBindingEvidence": {
            "mismatchDimension": mismatch_dimension,
            "transportSenderActorDid": transport_actor_did,
            "transportSenderDeviceId": transport_actor_device_id,
            "signedOuterActorDid": DID,
            "signedOuterDeviceId": DEVICE_ID,
            "registeredSignaturePublicKeyHex": hex::encode(outer_public_key),
        },
        "expectedDisposition": "rejected",
        "expectedReason": "bindingMismatch",
    }))
}

fn authority_boundary_vectors(vectors: &[Value]) -> Result<Vec<Value>> {
    let base = vectors
        .iter()
        .find(|vector| vector["name"] == "text")
        .ok_or("missing text authority-boundary base vector")?;
    let raw = hex::decode(base["cborHex"].as_str().ok_or("base plaintext CBOR")?)?;
    let entry_cbor = hex::decode(
        base["signedOuterEntry"]["applicationEntryCborHex"]
            .as_str()
            .ok_or("base outer-entry CBOR")?,
    )?;
    let verified_outer =
        verify_application_outer_entry(&entry_cbor, &fixture_registration(DID, DEVICE_ID)?)?;
    let credential_identity = hex::decode(
        base["transportEvidence"]["senderCredentialIdentityHex"]
            .as_str()
            .ok_or("base sender credential evidence")?,
    )?;
    let leaf_signature_public_key = hex::decode(
        base["transportEvidence"]["senderLeafSignaturePublicKeyHex"]
            .as_str()
            .ok_or("base sender leaf-key evidence")?,
    )?;
    let synthetic_boundary_sender = ApplicationMlsSender::test_only(
        false,
        credential_identity.clone(),
        leaf_signature_public_key.clone(),
    );
    let disposition = ingest_application_content(raw, &verified_outer, &synthetic_boundary_sender);
    let ApplicationContentDisposition::Rejected(rejected) = disposition else {
        return Err("non-member authority-boundary vector was not rejected".into());
    };
    if rejected.error().reason.code() != "bindingMismatch" {
        return Err(format!(
            "non-member authority-boundary vector expected bindingMismatch, got {}",
            rejected.error().reason.code()
        )
        .into());
    }
    Ok(vec![json!({
        "name": "senderNotMember",
        "validationScope": "authorityBoundary",
        "receiverProcessed": false,
        "baseReceiverProcessedVector": "text",
        "senderFactsConstruction": {
            "isMember": false,
            "credentialIdentityHex": hex::encode(credential_identity),
            "leafSignaturePublicKeyHex": hex::encode(leaf_signature_public_key),
            "mutation": "membershipFlagOnly",
        },
        "expectedDisposition": "rejected",
        "expectedReason": "bindingMismatch",
    })])
}

fn hint_authority_boundary_vectors() -> Result<Vec<Value>> {
    let initial_context = context();
    let opening = scenario_opening(
        "initialization.exact",
        uuid(0x10),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let interval = scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context,
        None,
    )?;
    let reducer = ApplicationReducer::new(&opening.entry, vec![interval])?;
    let state_before = reducer_state(&reducer, &[], &[DID]);
    if !state_before["terminalProof"].is_null()
        || !state_before["accessIntervals"][0]["closing"].is_null()
    {
        return Err("hint authority-boundary baseline is not open and nonterminal".into());
    }
    [
        (
            "tombstoneTerminalSeqOnlyCannotAuthorizeClose",
            "tombstone",
        ),
        ("eventTerminalSeqOnlyCannotAuthorizeClose", "event"),
        (
            "inventoryTerminalSeqOnlyCannotAuthorizeClose",
            "inventory",
        ),
        (
            "intervalSummaryTerminalSeqOnlyCannotAuthorizeClose",
            "intervalSummary",
        ),
    ]
    .into_iter()
    .map(|(name, hint_kind)| {
        let hint = json!({ "terminalSeq": 3 });
        let encoded_hint = serde_json::to_vec(&hint)?;
        let decoded_hint: TerminalSeqHintWire = serde_json::from_slice(&encoded_hint)?;
        if serde_json::to_value(&decoded_hint)? != hint {
            return Err(format!("hint authority-boundary vector {name} is not exact-key").into());
        }
        let state_after = reducer_state(&reducer, &[], &[DID]);
        if state_after != state_before
            || !state_after["terminalProof"].is_null()
            || !state_after["accessIntervals"][0]["closing"].is_null()
        {
            return Err(format!("hint authority-boundary vector {name} mutated authority state").into());
        }
        Ok(json!({
            "name": name,
            "validationScope": "authorityTypeBoundary",
            "evidenceMode": "hintOnlyExactDto",
            "hintKind": hint_kind,
            "hint": hint,
            "hintJsonSha256Hex": sha256(&encoded_hint),
            "receiverProcessed": false,
            "signedControlRowPresent": false,
            "outerEntryFingerprintPresent": false,
            "forbiddenAuthorityFieldsAbsent": true,
            "productionAuthorityApi": "ApplicationReducer::advance_non_application(&VerifiedApplicationControlEntry)",
            "reducerCall": "noneByType",
            "controlConstructorCalled": false,
            "expectedDisposition": "rejectedBeforeControlAuthority",
            "expectedReason": "unverifiedHintCannotConstructControl",
            "stateBefore": state_before,
            "stateAfter": state_after,
            "openIntervalUnchanged": true,
            "terminalStateUnchanged": true,
        }))
    })
    .collect()
}

fn identity_boundary_vectors(vectors: &[Value]) -> Result<Vec<Value>> {
    let base = vectors
        .iter()
        .find(|vector| vector["name"] == "text")
        .ok_or("missing identity-boundary transport artifact")?;
    let base_entry_cbor = hex::decode(
        base["signedOuterEntry"]["applicationEntryCborHex"]
            .as_str()
            .ok_or("identity-boundary base outer entry")?,
    )?;
    let base_entry: CorpusApplicationEntry = serde_ipld_dagcbor::from_slice(&base_entry_cbor)?;
    let receiver_processed_application_message =
        base_entry.signed_request.body.application_message.bytes;
    let maximum_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let oversized_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    let cases = [
        (
            "bareDidMin12BasicCredentialMin49Accepted",
            "did:web:a.co".to_owned(),
            12,
            49,
            true,
        ),
        (
            "bareDidMax261BasicCredentialMax298Accepted",
            format!("did:web:{maximum_host}"),
            261,
            298,
            true,
        ),
        (
            "bareDidBelowMin11BasicCredentialBelowMin48Rejected",
            "did:web:a.c".to_owned(),
            11,
            48,
            false,
        ),
        (
            "bareDidAboveMax262BasicCredentialAboveMax299Rejected",
            format!("did:web:{oversized_host}"),
            262,
            299,
            false,
        ),
    ];
    cases
        .into_iter()
        .map(
            |(name, actor_did, expected_did_length, expected_credential_length, accepted)| {
                identity_boundary_case(
                    name,
                    actor_did,
                    expected_did_length,
                    expected_credential_length,
                    accepted,
                    &receiver_processed_application_message,
                )
            },
        )
        .collect()
}

fn identity_boundary_case(
    name: &str,
    actor_did: String,
    expected_did_length: usize,
    expected_credential_length: usize,
    accepted: bool,
    receiver_processed_application_message: &[u8],
) -> Result<Value> {
    let credential_identity = format!("{actor_did}#{DEVICE_ID}").into_bytes();
    if !actor_did.is_ascii()
        || actor_did.len() != expected_did_length
        || credential_identity.len() != expected_credential_length
    {
        return Err(format!("identity boundary recipe {name} has incorrect byte lengths").into());
    }
    let public_key = signature_public_key();
    let registration = VerifiedApplicationDeviceRegistration::test_only(
        actor_did.clone(),
        DEVICE_ID.into(),
        fixture_key_id(&public_key),
        1,
        &public_key,
    );
    if !accepted {
        let error = registration.expect_err("invalid identity boundary unexpectedly registered");
        if error.reason.code() != "invalidValue" {
            return Err(format!(
                "identity boundary {name} expected invalidValue, got {}",
                error.reason.code()
            )
            .into());
        }
        return Ok(json!({
            "name": name,
            "validationScope": "identityBoundary",
            "receiverProcessed": false,
            "actorDid": actor_did,
            "actorDidUtf8Length": expected_did_length,
            "actorDeviceId": DEVICE_ID,
            "basicCredentialIdentityHex": hex::encode(&credential_identity),
            "basicCredentialUtf8Length": expected_credential_length,
            "credentialDerivation": "UTF8(actorDid + \"#\" + actorDeviceId)",
            "expectedRegistration": "rejected",
            "expectedDisposition": "rejectedBeforeOuter",
            "expectedReason": "invalidValue",
            "outerSenderBindingChecked": false,
            "signedOuterEntry": null,
        }));
    }

    let registration = registration?;
    let frame = frame(
        0x3f,
        ApplicationBody::Message(MessageBody {
            text: Some("identity boundary".into()),
            reply_to: None,
            embed: None,
        }),
    );
    let raw = encode_application_content(&frame)?;
    let (entry_id, seq) = deterministic_entry_coordinates(name);
    let signed_outer = signed_application_fixture(
        entry_id,
        seq,
        frame.message_id,
        frame.context.clone(),
        &actor_did,
        DEVICE_ID,
        &[],
        receiver_processed_application_message.to_vec(),
        &signing_key(),
    )?;
    let entry_cbor = hex::decode(
        signed_outer.json["applicationEntryCborHex"]
            .as_str()
            .ok_or("identity boundary entry CBOR")?,
    )?;
    let verified_outer = verify_application_outer_entry(&entry_cbor, &registration)?;
    let sender =
        ApplicationMlsSender::test_only(true, credential_identity.clone(), public_key.to_vec());
    if !matches!(
        ingest_application_content(raw, &verified_outer, &sender),
        ApplicationContentDisposition::Supported(_)
    ) {
        return Err(format!("identity boundary {name} did not pass outer/sender binding").into());
    }
    Ok(json!({
        "name": name,
        "validationScope": "identityBoundary",
        "receiverProcessed": false,
        "actorDid": actor_did,
        "actorDidUtf8Length": expected_did_length,
        "actorDeviceId": DEVICE_ID,
        "basicCredentialIdentityHex": hex::encode(&credential_identity),
        "basicCredentialUtf8Length": expected_credential_length,
        "credentialDerivation": "UTF8(actorDid + \"#\" + actorDeviceId)",
        "expectedRegistration": "accepted",
        "expectedDisposition": "supported",
        "expectedReason": null,
        "outerSenderBindingChecked": true,
        "applicationArtifactSource": "text.receiverProcessed",
        "signedOuterEntry": signed_outer.json,
    }))
}

fn with_field(mut value: Value, name: &str, field: Value) -> Value {
    value
        .as_object_mut()
        .unwrap()
        .insert(name.to_owned(), field);
    value
}

fn outer_for_frame(frame: &ApplicationFrame) -> Option<CorpusOuterBlobBinding> {
    let descriptor = match &frame.body {
        ApplicationBody::Message(message) => match &message.embed {
            Some(ApplicationEmbed::EncryptedImage(image)) => &image.blob,
            Some(ApplicationEmbed::EncryptedAudio(audio)) => &audio.blob,
            _ => return None,
        },
        _ => return None,
    };
    Some(CorpusOuterBlobBinding {
        blob_id: descriptor.blob_id,
        ciphertext_sha256: descriptor.ciphertext_sha256,
        ciphertext_size: descriptor.ciphertext_size,
        purpose: descriptor.purpose,
    })
}

fn outer_json(binding: &CorpusOuterBlobBinding) -> Value {
    json!({
        "blobIdHex": hex::encode(binding.blob_id),
        "ciphertextSha256Hex": hex::encode(binding.ciphertext_sha256),
        "ciphertextSize": binding.ciphertext_size,
        "purpose": match binding.purpose { BlobPurpose::Attachment => "attachment", BlobPurpose::Metadata => "metadata" },
    })
}

fn utf8_boundary_vectors() -> Result<Vec<Value>> {
    let mut recipes = [
        ("body.message.text", 16_384, "", 4_096, "", "a"),
        ("body.edit.replacementText", 16_384, "", 4_096, "", "a"),
        ("encryptedAudio.transcript", 16_384, "", 4_096, "", "a"),
        ("encryptedImage.altText", 4_096, "", 1_024, "", "a"),
        ("externalLink.title", 512, "", 128, "", "a"),
        ("externalLink.description", 2_048, "", 512, "", "a"),
        ("externalLink.uri", 2_048, "https://x.test/", 508, "a", "aa"),
    ];
    let mut output = Vec::new();
    for (index, (field, limit, prefix, repeats, at_suffix, over_suffix)) in
        recipes.iter_mut().enumerate()
    {
        output.push(boundary_vector(
            index,
            field,
            *limit,
            prefix,
            "🐦",
            *repeats,
            at_suffix,
            over_suffix,
        )?);
    }

    // One NFC extended grapheme at the exact 64-byte reaction ceiling.
    output.push(boundary_vector(
        output.len(),
        "body.reaction.emoji",
        64,
        "á",
        "\u{0300}",
        31,
        "",
        "\u{0300}",
    )?);

    // The exact maximum accepted restricted AT URI: hostname-level did:web
    // (261 bytes), NSID (317), and record key (512), plus separators.
    let maximum_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let maximum_collection = format!(
        "{}.{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63),
        "E".repeat(61)
    );
    let at_prefix = format!("at://did:web:{maximum_host}/{maximum_collection}/");
    let at_uri_boundary = boundary_vector(
        output.len(),
        "atprotoRecord.uri",
        1_097,
        &at_prefix,
        "r",
        512,
        "",
        "r",
    )?;
    output.push(with_field(
        with_field(
            at_uri_boundary,
            "acceptedCaseName",
            json!("atRecordUriMax1097Accepted"),
        ),
        "rejectedCaseName",
        json!("atRecordUriTooLong1098Rejected"),
    ));
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn boundary_vector(
    index: usize,
    field: &str,
    limit: usize,
    prefix: &str,
    unit: &str,
    repeats: usize,
    at_suffix: &str,
    over_suffix: &str,
) -> Result<Value> {
    let at_limit = format!("{prefix}{}{at_suffix}", unit.repeat(repeats));
    let over_limit = format!("{prefix}{}{over_suffix}", unit.repeat(repeats));
    if at_limit.len() != limit || over_limit.len() <= limit {
        return Err(format!("invalid byte-boundary recipe for {field}").into());
    }
    let at_limit_frame = boundary_frame(index as u8, field, at_limit.clone());
    let at_limit_cbor = encode_application_content(&at_limit_frame)?;
    let decoded = decode_application_frame(
        &at_limit_cbor,
        &ExpectedApplicationBinding::from_frame(&at_limit_frame),
    )?;
    if decoded != at_limit_frame || encode_application_content(&decoded)? != at_limit_cbor {
        return Err(format!("codec round trip disagrees for {field}").into());
    }
    let over_error =
        encode_application_content(&boundary_frame(index as u8, field, over_limit.clone()))
            .expect_err("over-limit recipe must be rejected by the authority");
    Ok(json!({
        "field": field,
        "limitBytes": limit,
        "prefix": prefix,
        "unit": unit,
        "unitUtf8Hex": hex::encode(unit.as_bytes()),
        "unitRepeats": repeats,
        "atLimitSuffix": at_suffix,
        "overLimitSuffix": over_suffix,
        "atLimitBytes": at_limit.len(),
        "overLimitBytes": over_limit.len(),
        "atLimitUtf8Sha256Hex": sha256(at_limit.as_bytes()),
        "overLimitUtf8Sha256Hex": sha256(over_limit.as_bytes()),
        "expectedAtLimit": "supported",
        "expectedOverLimit": "rejected",
        "expectedOverReason": over_error.reason.code(),
        "authorityChecked": true,
        "validationScope": "codecOnly",
        "evidenceMode": "authorityCodecRoundTrip",
        "receiverProcessed": false,
        "atLimitCborHex": hex::encode(&at_limit_cbor),
        "atLimitCborLength": at_limit_cbor.len(),
        "atLimitCborSha256Hex": sha256(&at_limit_cbor),
        "decodedFrameMatched": true,
        "canonicalRoundTripMatched": true,
    }))
}

fn boundary_frame(index: u8, field: &str, value: String) -> ApplicationFrame {
    let target = MessageTarget {
        target_seq: 1,
        target_message_id: uuid(0x51),
    };
    let body = match field {
        "body.message.text" => ApplicationBody::Message(MessageBody {
            text: Some(value),
            reply_to: None,
            embed: None,
        }),
        "body.edit.replacementText" => ApplicationBody::Edit(EditBody {
            target,
            replacement_text: value,
        }),
        "body.reaction.emoji" => ApplicationBody::Reaction(ReactionBody {
            target,
            emoji: value,
            operation: ReactionOperation::Add,
        }),
        "encryptedAudio.transcript" => ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedAudio(EncryptedAudio {
                blob: blob(0x72),
                mime_type: "audio/opus".into(),
                duration_millis: 1,
                waveform: [0; 64],
                transcript: Some(value),
            })),
        }),
        "encryptedImage.altText" => ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedImage(EncryptedImage {
                blob: blob(0x73),
                mime_type: "image/png".into(),
                width: 1,
                height: 1,
                alt_text: Some(value),
                blurhash: None,
            })),
        }),
        "externalLink.uri" => link_boundary_body(value, "ok".into(), "ok".into()),
        "externalLink.title" => link_boundary_body("https://x.test".into(), value, "ok".into()),
        "externalLink.description" => {
            link_boundary_body("https://x.test".into(), "ok".into(), value)
        }
        "atprotoRecord.uri" => ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                uri: value,
                cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
            })),
        }),
        _ => panic!("unknown boundary field {field}"),
    };
    frame(0x60_u8.wrapping_add(index), body)
}

fn link_boundary_body(uri: String, title: String, description: String) -> ApplicationBody {
    ApplicationBody::Message(MessageBody {
        text: None,
        reply_to: None,
        embed: Some(ApplicationEmbed::ExternalLink(ExternalLink {
            uri,
            title: Some(title),
            description: Some(description),
        })),
    })
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_SEED)
}

fn signature_public_key() -> [u8; 32] {
    signing_key().verifying_key().to_bytes()
}

fn fixture_signing_key(actor_device_id: &str) -> Result<SigningKey> {
    match actor_device_id {
        DEVICE_ID => Ok(signing_key()),
        RECEIVER_DEVICE_ID => Ok(SigningKey::from_bytes(&RECEIVER_SIGNING_SEED)),
        FOREIGN_DEVICE_ID => Ok(SigningKey::from_bytes(&FOREIGN_SIGNING_SEED)),
        _ => Err(format!("unknown fixture signing device {actor_device_id}").into()),
    }
}

fn fixture_signature_public_key(actor_device_id: &str) -> Result<[u8; 32]> {
    Ok(fixture_signing_key(actor_device_id)?
        .verifying_key()
        .to_bytes())
}

fn fixture_registration(
    actor_did: &str,
    actor_device_id: &str,
) -> Result<VerifiedApplicationDeviceRegistration> {
    let public_key = fixture_signature_public_key(actor_device_id)?;
    Ok(VerifiedApplicationDeviceRegistration::test_only(
        actor_did.into(),
        actor_device_id.into(),
        fixture_key_id(&public_key),
        1,
        &public_key,
    )?)
}

fn context() -> ConversationContext {
    FIXTURE_CONTEXT
        .get()
        .expect("fixture transport initializes context before frames")
        .clone()
}

fn context_json() -> Value {
    let context = context();
    json!({
        "conversationIdHex": hex::encode(context.conversation_id),
        "generation": context.generation,
        "stateVersion": context.state_version,
        "groupIdHex": hex::encode(context.group_id),
        "epoch": context.epoch,
        "groupContextHashHex": hex::encode(context.group_context_hash),
        "confirmationTagHex": hex::encode(context.confirmation_tag),
        "lifecycle": "active",
    })
}

fn frame(fill: u8, body: ApplicationBody) -> ApplicationFrame {
    ApplicationFrame {
        message_id: uuid(fill),
        context: context(),
        body,
    }
}

fn blob(fill: u8) -> BlobDescriptor {
    BlobDescriptor {
        blob_id: uuid(fill),
        algorithm: BlobAlgorithm::A256Gcm,
        purpose: BlobPurpose::Attachment,
        key: [fill.wrapping_add(1); 32],
        nonce: [fill.wrapping_add(2); 12],
        ciphertext_sha256: [fill.wrapping_add(3); 32],
        ciphertext_size: 48,
        plaintext_size: 32,
        metadata_origin: None,
    }
}

const fn uuid(fill: u8) -> [u8; 16] {
    let mut bytes = [fill; 16];
    bytes[6] = (fill & 0x0f) | 0x40;
    bytes[8] = (fill & 0x3f) | 0x80;
    bytes
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn normalized_relative_path(stack_root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(stack_root)?;
    if relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "provenance path is not strictly relative: {}",
            path.display()
        )
        .into());
    }
    let mut checked = stack_root.to_path_buf();
    let root_metadata = fs::symlink_metadata(stack_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(format!(
            "provenance root is not a real directory: {}",
            stack_root.display()
        )
        .into());
    }
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            unreachable!("components were validated above")
        };
        component
            .to_str()
            .ok_or("provenance source path component is not UTF-8")?;
        checked.push(component);
        if fs::symlink_metadata(&checked)?.file_type().is_symlink() {
            return Err(format!(
                "provenance path component must not be a symlink: {}",
                checked.display()
            )
            .into());
        }
    }
    let relative = relative
        .to_str()
        .ok_or("provenance source path is not UTF-8")?;
    if relative.contains('\\') {
        return Err("provenance source path is not slash-normalized".into());
    }
    Ok(relative.to_owned())
}

fn read_regular_file(stack_root: &Path, path: &Path) -> Result<Vec<u8>> {
    normalized_relative_path(stack_root, path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(format!("provenance path is not a regular file: {}", path.display()).into());
    }
    Ok(fs::read(path)?)
}

fn read_utf8_source(stack_root: &Path, path: &Path) -> Result<Vec<u8>> {
    let bytes = read_regular_file(stack_root, path)?;
    std::str::from_utf8(&bytes)
        .map_err(|_| format!("provenance source is not UTF-8: {}", path.display()))?;
    Ok(bytes)
}

fn ensure_cargo_lock_tracked(crate_root: &Path) -> Result<()> {
    let lock = crate_root.join("Cargo.lock");
    if !lock.is_file() {
        return Err("catbird-mls/Cargo.lock is missing".into());
    }
    let output = Command::new("jj")
        .args(["file", "list", "Cargo.lock"])
        .current_dir(crate_root)
        .output()?;
    if !output.status.success()
        || std::str::from_utf8(&output.stdout)?
            .lines()
            .all(|line| line.trim() != "Cargo.lock")
    {
        return Err("catbird-mls/Cargo.lock is not jj-tracked".into());
    }
    Ok(())
}

fn capture_authority_sources(
    stack_root: &Path,
    crate_root: &Path,
) -> Result<Vec<CapturedProvenanceFile>> {
    let mut paths = vec![
        crate_root.join("build.rs"),
        crate_root.join("src/application_content.rs"),
        crate_root.join("src/lib.rs"),
        stack_root.join("catbird-atproto/Cargo.toml"),
    ];
    paths.extend(rust_sources_below(
        stack_root,
        &crate_root.join("src/chat_protocol"),
    )?);
    paths.extend(rust_sources_below(
        stack_root,
        &stack_root.join("catbird-atproto/src"),
    )?);
    let mut ordered = paths
        .into_iter()
        .map(|path| Ok((normalized_relative_path(stack_root, &path)?, path)))
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    if ordered.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err("authority source paths are not strictly ordered and unique".into());
    }
    ordered
        .iter()
        .map(|(_, path)| CapturedProvenanceFile::capture_source(stack_root, path))
        .collect()
}

fn rust_sources_below(stack_root: &Path, directory: &Path) -> Result<Vec<PathBuf>> {
    normalized_relative_path(stack_root, directory)?;
    if !fs::symlink_metadata(directory)?.file_type().is_dir() {
        return Err(format!(
            "authority source root is not a directory: {}",
            directory.display()
        )
        .into());
    }
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(format!(
                    "authority source traversal encountered a symlink: {}",
                    path.display()
                )
                .into());
            }
            if file_type.is_dir() {
                normalized_relative_path(stack_root, &path)?;
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| extension == "rs")
            {
                read_utf8_source(stack_root, &path)?;
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn authority_source_aggregate(sources: &[(String, Vec<u8>)]) -> [u8; 32] {
    let mut ordered = sources.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_SOURCE_AGGREGATE_DOMAIN);
    hasher.update((ordered.len() as u64).to_be_bytes());
    for (path, bytes) in ordered {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UncheckedApplicationFrameWire<'a> {
    protocol: &'a str,
    version: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    context: ConversationContext,
    body: ApplicationBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UncheckedLifecycleFrameWire<'a> {
    protocol: &'a str,
    version: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    context: UncheckedLifecycleContextWire<'a>,
    body: ApplicationBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UncheckedLifecycleContextWire<'a> {
    #[serde(with = "bytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    state_version: u64,
    #[serde(with = "bytes32")]
    group_id: [u8; 32],
    epoch: u64,
    #[serde(with = "bytes32")]
    group_context_hash: [u8; 32],
    #[serde(with = "bytes32")]
    confirmation_tag: [u8; 32],
    lifecycle: &'a str,
}

fn encode_application_content_unchecked(frame: &ApplicationFrame) -> Result<Vec<u8>> {
    Ok(serde_ipld_dagcbor::to_vec(
        &UncheckedApplicationFrameWire {
            protocol: "blue.catbird.chat.application",
            version: 1,
            message_id: frame.message_id,
            context: frame.context.clone(),
            body: frame.body.clone(),
        },
    )?)
}

fn encode_application_content_with_lifecycle(
    frame: &ApplicationFrame,
    lifecycle: &str,
) -> Result<Vec<u8>> {
    let context = &frame.context;
    Ok(serde_ipld_dagcbor::to_vec(&UncheckedLifecycleFrameWire {
        protocol: "blue.catbird.chat.application",
        version: 1,
        message_id: frame.message_id,
        context: UncheckedLifecycleContextWire {
            conversation_id: context.conversation_id,
            generation: context.generation,
            state_version: context.state_version,
            group_id: context.group_id,
            epoch: context.epoch,
            group_context_hash: context.group_context_hash,
            confirmation_tag: context.confirmation_tag,
            lifecycle,
        },
        body: frame.body.clone(),
    })?)
}

fn canonical_wrapper(version: u8, value: Option<&[u8]>) -> Vec<u8> {
    let mut raw = Vec::new();
    if let Some(value) = value {
        raw.extend_from_slice(&[0xa3, 0x61, b'x']);
        raw.extend_from_slice(value);
    } else {
        raw.push(0xa2);
    }
    raw.extend_from_slice(&[0x67]);
    raw.extend_from_slice(b"version");
    raw.push(version);
    raw.extend_from_slice(&[0x68]);
    raw.extend_from_slice(b"protocol");
    raw.extend_from_slice(&[0x78, 0x1d]);
    raw.extend_from_slice(b"blue.catbird.chat.application");
    raw
}

fn canonical_rejection_vectors() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let mut duplicate = vec![0xa3, 0x67];
    duplicate.extend_from_slice(b"version");
    duplicate.push(0x01);
    duplicate.push(0x67);
    duplicate.extend_from_slice(b"version");
    duplicate.push(0x01);
    duplicate.push(0x68);
    duplicate.extend_from_slice(b"protocol");
    duplicate.extend_from_slice(&[0x78, 0x1d]);
    duplicate.extend_from_slice(b"blue.catbird.chat.application");

    let mut nonminimal_integer = canonical_wrapper(1, None);
    let version_value = nonminimal_integer
        .iter()
        .position(|byte| *byte == 0x01)
        .expect("version value");
    nonminimal_integer.splice(version_value..=version_value, [0x18, 0x01]);

    let mut nonminimal_length = vec![0xa2, 0x67];
    nonminimal_length.extend_from_slice(b"version");
    nonminimal_length.push(0x01);
    nonminimal_length.push(0x68);
    nonminimal_length.extend_from_slice(b"protocol");
    nonminimal_length.extend_from_slice(&[0x79, 0x00, 0x1d]);
    nonminimal_length.extend_from_slice(b"blue.catbird.chat.application");

    let mut wrong_order = vec![0xa2, 0x68];
    wrong_order.extend_from_slice(b"protocol");
    wrong_order.extend_from_slice(&[0x78, 0x1d]);
    wrong_order.extend_from_slice(b"blue.catbird.chat.application");
    wrong_order.push(0x67);
    wrong_order.extend_from_slice(b"version");
    wrong_order.push(0x01);

    let mut trailing = canonical_wrapper(1, None);
    trailing.push(0x00);
    vec![
        ("cborDuplicateKey", duplicate, "duplicateKey"),
        ("cborNonminimalInteger", nonminimal_integer, "nonCanonical"),
        ("cborNonminimalLength", nonminimal_length, "nonCanonical"),
        ("cborWrongKeyOrder", wrong_order, "nonCanonical"),
        (
            "cborIndefiniteLength",
            canonical_wrapper(1, Some(&[0x9f, 0xff])),
            "indefiniteLength",
        ),
        (
            "cborInvalidUtf8",
            canonical_wrapper(1, Some(&[0x61, 0xff])),
            "invalidUtf8",
        ),
        (
            "cborTagV1",
            canonical_wrapper(1, Some(&[0xc0, 0x00])),
            "tagNotAllowed",
        ),
        (
            "cborFloatV1",
            canonical_wrapper(1, Some(&[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0])),
            "floatNotAllowed",
        ),
        (
            "cborNullV1",
            canonical_wrapper(1, Some(&[0xf6])),
            "nullNotAllowed",
        ),
        ("cborTrailingData", trailing, "trailingData"),
    ]
}

fn future_opaque_vectors() -> Vec<(&'static str, Vec<u8>)> {
    let mut cid = vec![0xd8, 0x2a, 0x58, 0x25, 0x00, 0x01, 0x55, 0x12, 0x20];
    cid.extend_from_slice(&[0x11; 32]);
    vec![
        (
            "futureV2FiniteF64",
            canonical_wrapper(2, Some(&[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0])),
        ),
        ("futureV2CidLink", canonical_wrapper(2, Some(&cid))),
        ("futureV2Null", canonical_wrapper(2, Some(&[0xf6]))),
        ("futureV2Bool", canonical_wrapper(2, Some(&[0xf5]))),
        (
            "futureV2DefiniteArray",
            canonical_wrapper(2, Some(&[0x83, 0x01, 0xf4, 0xf6])),
        ),
        (
            "futureV2CanonicalMap",
            canonical_wrapper(2, Some(&[0xa2, 0x61, b'a', 0xf6, 0x61, b'b', 0xf5])),
        ),
        (
            "futureV2IntegerAboveUint53",
            canonical_wrapper(2, Some(&[0x1b, 0x00, 0x20, 0, 0, 0, 0, 0, 0])),
        ),
    ]
}

fn future_rejection_vectors() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let mut valid_cid_without_zero = vec![0xd8, 0x2a, 0x58, 0x24, 0x01, 0x55, 0x12, 0x20];
    valid_cid_without_zero.extend_from_slice(&[0x11; 32]);
    let malformed_cid = [0xd8, 0x2a, 0x43, 0x00, 0x01, 0x02];
    let mut noncanonical_cid = vec![0xd8, 0x2a, 0x58, 0x26, 0x00, 0x81, 0x00, 0x55, 0x12, 0x20];
    noncanonical_cid.extend_from_slice(&[0x11; 32]);
    vec![
        (
            "futureV2PositiveInfinity",
            canonical_wrapper(2, Some(&[0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0])),
            "floatNotAllowed",
        ),
        (
            "futureV2NaN",
            canonical_wrapper(2, Some(&[0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0])),
            "floatNotAllowed",
        ),
        (
            "futureV2Non42Tag",
            canonical_wrapper(2, Some(&[0xc0, 0x00])),
            "tagNotAllowed",
        ),
        (
            "futureV2CidMissingMultibaseZero",
            canonical_wrapper(2, Some(&valid_cid_without_zero)),
            "invalidValue",
        ),
        (
            "futureV2MalformedCid",
            canonical_wrapper(2, Some(&malformed_cid)),
            "invalidValue",
        ),
        (
            "futureV2NoncanonicalCid",
            canonical_wrapper(2, Some(&noncanonical_cid)),
            "invalidValue",
        ),
        (
            "futureV2HalfFloat",
            canonical_wrapper(2, Some(&[0xf9, 0x3c, 0x00])),
            "floatNotAllowed",
        ),
        (
            "futureV2SingleFloat",
            canonical_wrapper(2, Some(&[0xfa, 0x3f, 0x80, 0x00, 0x00])),
            "floatNotAllowed",
        ),
    ]
}

fn invalid_embed_vectors() -> Vec<(&'static str, ApplicationFrame)> {
    let record = |fill, uri: &str| {
        frame(
            fill,
            ApplicationBody::Message(MessageBody {
                text: None,
                reply_to: None,
                embed: Some(ApplicationEmbed::AtprotoRecord(AtprotoRecord {
                    uri: uri.into(),
                    cid: "bafyreibwzif5knqq7jkflasfxpcd5yzt7f6q3f4v2x2m3zq4k5w6y7zaaa".into(),
                })),
            }),
        )
    };
    let link = |fill, uri: &str| {
        frame(
            fill,
            ApplicationBody::Message(MessageBody {
                text: None,
                reply_to: None,
                embed: Some(ApplicationEmbed::ExternalLink(ExternalLink {
                    uri: uri.into(),
                    title: None,
                    description: None,
                })),
            }),
        )
    };
    vec![
        (
            "atRecordMissingCollectionRejected",
            record(0xc0, "at://did:plc:abcdefghijklmnopqrstuvwx"),
        ),
        (
            "atRecordMissingRkeyRejected",
            record(
                0xc1,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post",
            ),
        ),
        (
            "atRecordFragmentRejected",
            record(
                0xc2,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz#fragment",
            ),
        ),
        (
            "atRecordUppercaseSchemeRejected",
            record(0x80, "AT://alice.com/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidPlcUppercaseMethodRejected",
            record(
                0x81,
                "at://did:PLC:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidPlcUppercaseMethodSpecificRejected",
            record(
                0x82,
                "at://did:plc:Abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidPlcMalformedRejected",
            record(
                0x83,
                "at://did:plc:abcdefghijklmnopqrstuvw/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidPlcInvalidAlphabetRejected",
            record(
                0x84,
                &format!("at://did:plc:{}1/app.bsky.feed.post/3kz", "a".repeat(23)),
            ),
        ),
        (
            "atRecordUnsupportedDidMethodRejected",
            record(0x85, "at://did:key:z6Mkh/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebIpv6Rejected",
            record(0x86, "at://did:web:[::1]/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebLabelOver63Rejected",
            record(
                0x87,
                &format!("at://did:web:{}.com/app.bsky.feed.post/3kz", "a".repeat(64)),
            ),
        ),
        (
            "atRecordDidWebHostOver253Rejected",
            record(
                0x88,
                &format!(
                    "at://did:web:{}.{}.{}.{}/app.bsky.feed.post/3kz",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62)
                ),
            ),
        ),
        (
            "atRecordHandleLabelOver63Rejected",
            record(
                0x89,
                &format!("at://{}.com/app.bsky.feed.post/3kz", "a".repeat(64)),
            ),
        ),
        (
            "atRecordHandleHostOver253Rejected",
            record(
                0x8a,
                &format!(
                    "at://{}.{}.{}.{}/app.bsky.feed.post/3kz",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62)
                ),
            ),
        ),
        (
            "atRecordRkeyDotRejected",
            record(0x8b, "at://alice.com/app.bsky.feed.post/."),
        ),
        (
            "atRecordRkeyDotDotRejected",
            record(0x8c, "at://alice.com/app.bsky.feed.post/.."),
        ),
        (
            "atRecordUppercaseHandleRejected",
            record(0xcb, "at://EXAMPLE.COM/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordNonAsciiAuthorityRejected",
            record(0x9b, "at://álîce.com/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordLeadingHyphenAuthorityRejected",
            record(0x9c, "at://-alice.com/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordTrailingHyphenAuthorityRejected",
            record(0x9d, "at://alice-.com/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordEmptyAuthorityLabelRejected",
            record(0x9e, "at://alice..com/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordUppercaseCollectionDomainRejected",
            record(0x9f, "at://alice.com/app.Bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebUppercaseHostRejected",
            record(0xd2, "at://did:web:Example.com/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebPathRejected",
            record(
                0xd3,
                "at://did:web:example.com:users:alice/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidWebUppercasePathRejected",
            record(
                0xa1,
                "at://did:web:example.com:Users:alice/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidWebPortRejected",
            record(0xd4, "at://did:web:example.com:443/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebSingleLabelRejected",
            record(0xd5, "at://did:web:singlelabel/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebLocalhostRejected",
            record(0xd6, "at://did:web:localhost/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordBareLocalhostHandleRejected",
            record(0xa2, "at://localhost/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebIpRejected",
            record(0xd7, "at://did:web:127.0.0.1/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebNumericTldRejected",
            record(0xd8, "at://did:web:example.123/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleNumericTldRejected",
            record(0xa0, "at://example.123/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedAltTldRejected",
            record(0x8d, "at://did:web:example.alt/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedArpaTldRejected",
            record(0x8e, "at://did:web:example.arpa/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedExampleTldRejected",
            record(0x8f, "at://did:web:example.example/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedInternalTldRejected",
            record(0x90, "at://did:web:example.internal/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordReservedTldRejected",
            record(0xd9, "at://did:web:example.invalid/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedLocalTldRejected",
            record(0x91, "at://did:web:example.local/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedLocalhostTldRejected",
            record(
                0x92,
                "at://did:web:example.localhost/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidWebReservedOnionTldRejected",
            record(0x93, "at://did:web:example.onion/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebReservedTestTldRejected",
            record(0xda, "at://did:web:example.test/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedAltTldRejected",
            record(0x94, "at://handle.alt/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedArpaTldRejected",
            record(0x95, "at://handle.arpa/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedExampleTldRejected",
            record(0x96, "at://handle.example/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedInternalTldRejected",
            record(0x97, "at://handle.internal/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleInvalidRejected",
            record(0xdb, "at://handle.invalid/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedLocalTldRejected",
            record(0x98, "at://handle.local/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedLocalhostTldRejected",
            record(0x99, "at://handle.localhost/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedOnionTldRejected",
            record(0x9a, "at://handle.onion/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordHandleReservedTestTldRejected",
            record(0xdc, "at://handle.test/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordDidWebPercentRejected",
            record(
                0xdd,
                "at://did:web:example.com%2Fpath/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidWebLowercasePercentEscapeRejected",
            record(
                0xa3,
                "at://did:web:example.com%2fpath/app.bsky.feed.post/3kz",
            ),
        ),
        (
            "atRecordDidWebAsciiPercentEscapeRejected",
            record(0xa4, "at://did:web:example.com%41/app.bsky.feed.post/3kz"),
        ),
        (
            "atRecordRkeyPercentRejected",
            record(
                0xcc,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3%6bz",
            ),
        ),
        (
            "atRecordQueryRejected",
            record(
                0xcd,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz?view=1",
            ),
        ),
        (
            "atRecordTrailingPathRejected",
            record(
                0xce,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz/",
            ),
        ),
        (
            "atRecordDuplicateSlashRejected",
            record(
                0xcf,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post//3kz",
            ),
        ),
        (
            "atRecordDotPathSegmentRejected",
            record(
                0xd0,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/./3kz",
            ),
        ),
        (
            "atRecordEmptyCollectionRejected",
            record(0xa5, "at://alice.com//rKeyABC"),
        ),
        (
            "atRecordCollectionDotRejected",
            record(0xa6, "at://alice.com/./rKeyABC"),
        ),
        (
            "atRecordParentPathSegmentRejected",
            record(0xa7, "at://alice.com/com.example.Record/../rKeyABC"),
        ),
        (
            "atRecordExtraSegmentRejected",
            record(
                0xd1,
                "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/3kz/extra",
            ),
        ),
        (
            "externalLinkNonHttps",
            link(0xc3, "http://catbird.blue/chat"),
        ),
        ("externalLinkRelative", link(0xc4, "/chat")),
        ("externalLinkEmptyHost", link(0xc5, "https:///")),
        (
            "externalLinkUserinfo",
            link(0xc6, "https://user@catbird.blue/chat"),
        ),
        (
            "externalLinkBackslash",
            link(0xc7, "https://catbird.blue\\chat"),
        ),
        (
            "externalLinkWhitespace",
            link(0xc8, "https://catbird.blue/a b"),
        ),
        (
            "externalLinkControl",
            link(0xc9, "https://catbird.blue/a\n"),
        ),
        (
            "externalLinkInvalidPercent",
            link(0xca, "https://catbird.blue/%zz"),
        ),
    ]
}

fn invalid_semantic_vectors() -> Vec<(
    &'static str,
    ApplicationFrame,
    Vec<CorpusOuterBlobBinding>,
    &'static str,
)> {
    let reaction = |fill, emoji: &str| {
        frame(
            fill,
            ApplicationBody::Reaction(ReactionBody {
                target: MessageTarget {
                    target_seq: 1,
                    target_message_id: uuid(0x51),
                },
                emoji: emoji.into(),
                operation: ReactionOperation::Add,
            }),
        )
    };
    let image = |fill, blurhash: Option<String>, ciphertext_size, purpose| {
        frame(
            fill,
            ApplicationBody::Message(MessageBody {
                text: None,
                reply_to: None,
                embed: Some(ApplicationEmbed::EncryptedImage(EncryptedImage {
                    blob: BlobDescriptor {
                        ciphertext_size,
                        purpose,
                        ..blob(fill)
                    },
                    mime_type: "image/png".into(),
                    width: 1,
                    height: 1,
                    alt_text: None,
                    blurhash,
                })),
            }),
        )
    };
    let blurhash_below = image(0xdb, Some("abcde".into()), 48, BlobPurpose::Attachment);
    let blurhash_above = image(0xdc, Some("a".repeat(257)), 48, BlobPurpose::Attachment);
    let image_size = image(0xdd, None, 49, BlobPurpose::Attachment);
    let metadata_purpose = image(0xde, None, 48, BlobPurpose::Metadata);
    let audio_size = frame(
        0xdf,
        ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedAudio(EncryptedAudio {
                blob: BlobDescriptor {
                    ciphertext_size: 47,
                    ..blob(0xdf)
                },
                mime_type: "audio/opus".into(),
                duration_millis: 1,
                waveform: [0; 64],
                transcript: None,
            })),
        }),
    );
    vec![
        (
            "reactionNonNfc",
            reaction(0xd8, "a\u{301}"),
            vec![],
            "invalidReaction",
        ),
        (
            "reactionTwoGraphemes",
            reaction(0xd9, "👍👍"),
            vec![],
            "invalidReaction",
        ),
        (
            "reactionSingleGraphemeOver64Bytes",
            reaction(0xda, &format!("á{}", "\u{300}".repeat(32))),
            vec![],
            "invalidReaction",
        ),
        (
            "blurhashBelowMinimum",
            blurhash_below.clone(),
            vec![outer_for_frame(&blurhash_below).unwrap()],
            "invalidValue",
        ),
        (
            "blurhashAboveMaximum",
            blurhash_above.clone(),
            vec![outer_for_frame(&blurhash_above).unwrap()],
            "sizeLimitExceeded",
        ),
        (
            "imageCiphertextTagSizeMismatch",
            image_size.clone(),
            vec![outer_for_frame(&image_size).unwrap()],
            "sizeLimitExceeded",
        ),
        (
            "audioCiphertextTagSizeMismatch",
            audio_size.clone(),
            vec![outer_for_frame(&audio_size).unwrap()],
            "sizeLimitExceeded",
        ),
        (
            "applicationMetadataPurposeForbidden",
            metadata_purpose,
            vec![],
            "bindingMismatch",
        ),
    ]
}

fn outer_rejection_vector(
    transport: &mut ApplicationTransportFixture,
    name: &str,
    frame: &ApplicationFrame,
    outer: Vec<CorpusOuterBlobBinding>,
    expected_reason: &str,
) -> Result<Value> {
    let raw = encode_application_content(frame)?;
    let prior = context();
    let transported =
        transport.encrypt_and_receive(DID, DEVICE_ID, frame.message_id, &prior, &raw)?;
    let (entry_id, seq) = deterministic_entry_coordinates(name);
    let signed_outer = signed_application_fixture(
        entry_id,
        seq,
        frame.message_id,
        prior,
        DID,
        DEVICE_ID,
        &outer,
        transported.application_message,
        &signing_key(),
    )?;
    let entry_cbor = hex::decode(
        signed_outer.json["applicationEntryCborHex"]
            .as_str()
            .ok_or("outer rejection entry CBOR")?,
    )?;
    let error = verify_application_outer_entry(&entry_cbor, &fixture_registration(DID, DEVICE_ID)?)
        .expect_err("outer rejection vector must fail production verification");
    if error.reason.code() != expected_reason {
        return Err(format!(
            "outer vector {name} expected {expected_reason}, got {}",
            error.reason.code()
        )
        .into());
    }
    Ok(json!({
        "name": name,
        "messageIdHex": hex::encode(frame.message_id),
        "cborHex": hex::encode(&raw),
        "length": raw.len(),
        "sha256Hex": sha256(&raw),
        "outerBlobBindings": outer.iter().map(outer_json).collect::<Vec<_>>(),
        "signedOuterEntry": signed_outer.json,
        "outerEntryFingerprintHex": hex::encode(signed_outer.fingerprint),
        "transportEvidence": transported.evidence,
        "senderMode": "exact",
        "expectedDisposition": "outerRejected",
        "expectedReason": expected_reason,
    }))
}

fn outer_entry_rejection_vectors(vectors: &[Value]) -> Result<Vec<Value>> {
    let base = vectors
        .iter()
        .find(|vector| vector["name"] == "text")
        .ok_or("missing text base vector")?;
    let entry_bytes = hex::decode(
        base["signedOuterEntry"]["applicationEntryCborHex"]
            .as_str()
            .ok_or("text entry bytes")?,
    )?;
    let entry: CorpusApplicationEntry = serde_ipld_dagcbor::from_slice(&entry_bytes)?;
    let default_registration = matrix_registration(DID, DEVICE_ID, 1, signature_public_key());
    let mut cases = Vec::new();

    let pairs = split_definite_cbor_map_pairs(&entry_bytes, 5)?;
    let mut duplicate_key = vec![0xa6];
    for pair in &pairs {
        duplicate_key.extend_from_slice(pair);
    }
    duplicate_key.extend_from_slice(&pairs[0]);
    cases.push(outer_raw_matrix_case(
        "applicationEntryDuplicateTopLevelKey",
        duplicate_key,
        default_registration.clone(),
        "duplicateKey",
    )?);

    let mut unknown_field = vec![0xa6, 0x61, b'x', 0x00];
    for pair in &pairs {
        unknown_field.extend_from_slice(pair);
    }
    cases.push(outer_raw_matrix_case(
        "applicationEntryUnknownTopLevelField",
        unknown_field,
        default_registration.clone(),
        "unknownField",
    )?);

    let mut wrong_key_order = vec![0xa5];
    wrong_key_order.extend_from_slice(&pairs[1]);
    wrong_key_order.extend_from_slice(&pairs[0]);
    for pair in &pairs[2..] {
        wrong_key_order.extend_from_slice(pair);
    }
    cases.push(outer_raw_matrix_case(
        "applicationEntryNoncanonicalKeyOrder",
        wrong_key_order,
        default_registration.clone(),
        "nonCanonical",
    )?);

    let mut nonminimal_header = vec![0xb8, 0x05];
    nonminimal_header.extend_from_slice(&entry_bytes[1..]);
    cases.push(outer_raw_matrix_case(
        "applicationEntryNonminimalMapHeader",
        nonminimal_header,
        default_registration.clone(),
        "nonCanonical",
    )?);

    let mut bad_signature = entry.clone();
    bad_signature.signed_request.signature[0] ^= 1;
    cases.push(outer_matrix_case(
        "badSignature",
        bad_signature,
        default_registration.clone(),
        "invalidSignature",
    )?);

    let mut conversation_mismatch = entry.clone();
    conversation_mismatch.conversation_id = uuid(0xec);
    cases.push(outer_matrix_case(
        "entryBodyConversationMismatch",
        conversation_mismatch,
        default_registration.clone(),
        "bindingMismatch",
    )?);

    let mut aad_mismatch = entry.clone();
    aad_mismatch.signed_request.body.aad.generation += 1;
    resign_entry(&mut aad_mismatch, &signing_key())?;
    cases.push(outer_matrix_case(
        "bodyAadMismatch",
        aad_mismatch,
        default_registration.clone(),
        "bindingMismatch",
    )?);

    cases.push(outer_matrix_case(
        "registryDidMismatch",
        entry.clone(),
        matrix_registration(
            "did:plc:bobfixturebbbbbbbbbbbbbb",
            DEVICE_ID,
            1,
            signature_public_key(),
        ),
        "bindingMismatch",
    )?);
    cases.push(outer_matrix_case(
        "registryDeviceMismatch",
        entry.clone(),
        matrix_registration(
            DID,
            "74747474-7474-4474-b474-747474747474",
            1,
            signature_public_key(),
        ),
        "bindingMismatch",
    )?);
    let alternate_key = SigningKey::from_bytes(&[0x92; 32]);
    cases.push(outer_matrix_case(
        "registryKeyIdMismatch",
        entry.clone(),
        matrix_registration(DID, DEVICE_ID, 1, alternate_key.verifying_key().to_bytes()),
        "bindingMismatch",
    )?);
    cases.push(outer_matrix_case(
        "registryAuthGenerationMismatch",
        entry.clone(),
        matrix_registration(DID, DEVICE_ID, 2, signature_public_key()),
        "bindingMismatch",
    )?);

    let mut artifact_sha = entry;
    artifact_sha.signed_request.body.application_message.sha256[0] ^= 1;
    resign_entry(&mut artifact_sha, &signing_key())?;
    cases.push(outer_matrix_case(
        "applicationArtifactShaMismatch",
        artifact_sha,
        default_registration,
        "integrityMismatch",
    )?);
    Ok(cases)
}

fn split_definite_cbor_map_pairs(input: &[u8], expected_pairs: usize) -> Result<Vec<Vec<u8>>> {
    if input.first().copied() != Some(0xa0 | u8::try_from(expected_pairs)?) {
        return Err("outer-entry fixture is not the expected definite CBOR map".into());
    }
    let mut cursor = 1;
    let mut pairs = Vec::with_capacity(expected_pairs);
    for _ in 0..expected_pairs {
        let start = cursor;
        cursor = cbor_item_end(input, cursor, 0)?;
        cursor = cbor_item_end(input, cursor, 0)?;
        pairs.push(input[start..cursor].to_vec());
    }
    if cursor != input.len() {
        return Err("outer-entry CBOR pair splitter left trailing bytes".into());
    }
    Ok(pairs)
}

fn cbor_item_end(input: &[u8], start: usize, depth: usize) -> Result<usize> {
    if depth > 32 {
        return Err("fixture CBOR nesting exceeds parser bound".into());
    }
    let initial = *input.get(start).ok_or("truncated fixture CBOR item")?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let (argument, mut cursor) = cbor_argument(input, start + 1, additional)?;
    match major {
        0 | 1 | 7 => {}
        2 | 3 => {
            cursor = cursor
                .checked_add(usize::try_from(argument)?)
                .ok_or("fixture CBOR length overflow")?;
            if cursor > input.len() {
                return Err("truncated fixture CBOR string".into());
            }
        }
        4 => {
            for _ in 0..argument {
                cursor = cbor_item_end(input, cursor, depth + 1)?;
            }
        }
        5 => {
            for _ in 0..argument {
                cursor = cbor_item_end(input, cursor, depth + 1)?;
                cursor = cbor_item_end(input, cursor, depth + 1)?;
            }
        }
        6 => cursor = cbor_item_end(input, cursor, depth + 1)?,
        _ => return Err("unsupported fixture CBOR major type".into()),
    }
    Ok(cursor)
}

fn cbor_argument(input: &[u8], cursor: usize, additional: u8) -> Result<(u64, usize)> {
    let read = |width: usize| -> Result<&[u8]> {
        input
            .get(cursor..cursor + width)
            .ok_or_else(|| "truncated fixture CBOR argument".into())
    };
    match additional {
        value @ 0..=23 => Ok((u64::from(value), cursor)),
        24 => Ok((u64::from(read(1)?[0]), cursor + 1)),
        25 => Ok((
            u64::from(u16::from_be_bytes(read(2)?.try_into()?)),
            cursor + 2,
        )),
        26 => Ok((
            u64::from(u32::from_be_bytes(read(4)?.try_into()?)),
            cursor + 4,
        )),
        27 => Ok((u64::from_be_bytes(read(8)?.try_into()?), cursor + 8)),
        _ => Err("indefinite or reserved fixture CBOR argument".into()),
    }
}

fn matrix_registration(
    actor_did: &str,
    actor_device_id: &str,
    auth_generation: u64,
    public_key: [u8; 32],
) -> Value {
    json!({
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
        "keyId": fixture_key_id(&public_key),
        "authGeneration": auth_generation,
        "signaturePublicKeyHex": hex::encode(public_key),
    })
}

fn outer_matrix_case(
    name: &str,
    entry: CorpusApplicationEntry,
    registration: Value,
    expected_reason: &str,
) -> Result<Value> {
    let entry_cbor = serde_ipld_dagcbor::to_vec(&entry)?;
    let public_key = hex::decode(
        registration["signaturePublicKeyHex"]
            .as_str()
            .ok_or("matrix public key")?,
    )?;
    let verified_registration = VerifiedApplicationDeviceRegistration::test_only(
        registration["actorDid"]
            .as_str()
            .ok_or("matrix actor DID")?
            .into(),
        registration["actorDeviceId"]
            .as_str()
            .ok_or("matrix actor device")?
            .into(),
        registration["keyId"]
            .as_str()
            .ok_or("matrix key ID")?
            .into(),
        registration["authGeneration"]
            .as_u64()
            .ok_or("matrix auth generation")?,
        &public_key,
    )?;
    let error = verify_application_outer_entry(&entry_cbor, &verified_registration)
        .expect_err("outer-entry rejection matrix case must be terminal");
    if error.reason.code() != expected_reason {
        return Err(format!(
            "outer-entry case {name} expected {expected_reason}, got {}",
            error.reason.code()
        )
        .into());
    }
    Ok(json!({
        "name": name,
        "applicationEntryCborHex": hex::encode(&entry_cbor),
        "applicationEntryCborSha256Hex": sha256(&entry_cbor),
        "registeredDevice": registration,
        "expectedDisposition": "outerRejected",
        "expectedReason": expected_reason,
        "validationStage": "outerPreDecrypt",
        "terminalPreDecrypt": true,
        "canonicalTypedEntry": true,
    }))
}

fn outer_raw_matrix_case(
    name: &str,
    entry_cbor: Vec<u8>,
    registration: Value,
    expected_reason: &str,
) -> Result<Value> {
    let public_key = hex::decode(
        registration["signaturePublicKeyHex"]
            .as_str()
            .ok_or("matrix public key")?,
    )?;
    let verified_registration = VerifiedApplicationDeviceRegistration::test_only(
        registration["actorDid"]
            .as_str()
            .ok_or("matrix actor DID")?
            .into(),
        registration["actorDeviceId"]
            .as_str()
            .ok_or("matrix actor device")?
            .into(),
        registration["keyId"]
            .as_str()
            .ok_or("matrix key ID")?
            .into(),
        registration["authGeneration"]
            .as_u64()
            .ok_or("matrix auth generation")?,
        &public_key,
    )?;
    let error = verify_application_outer_entry(&entry_cbor, &verified_registration)
        .expect_err("raw outer-entry rejection matrix case must be terminal");
    if error.reason.code() != expected_reason {
        return Err(format!(
            "raw outer-entry case {name} expected {expected_reason}, got {}",
            error.reason.code()
        )
        .into());
    }
    Ok(json!({
        "name": name,
        "applicationEntryCborHex": hex::encode(&entry_cbor),
        "applicationEntryCborSha256Hex": sha256(&entry_cbor),
        "registeredDevice": registration,
        "expectedDisposition": "outerRejected",
        "expectedReason": expected_reason,
        "validationStage": "outerPreDecrypt",
        "terminalPreDecrypt": true,
        "canonicalTypedEntry": false,
    }))
}

fn resign_entry(entry: &mut CorpusApplicationEntry, signing_key: &SigningKey) -> Result<()> {
    let projection = serde_ipld_dagcbor::to_vec(&entry.signed_request.body)?;
    let mut transcript = MESSAGE_SIGNATURE_DOMAIN.to_vec();
    transcript.extend_from_slice(&projection);
    entry.signed_request.signature = signing_key.sign(&transcript).to_bytes();
    Ok(())
}

#[derive(Clone)]
struct ScenarioApplication {
    fixture: Value,
    disposition: ApplicationContentDisposition,
}

#[derive(Clone)]
struct ScenarioControl {
    fixture: Value,
    entry: VerifiedApplicationControlEntry,
}

fn reducer_initialization_vectors() -> Result<Vec<Value>> {
    let initial_context = context();
    let exact = scenario_opening(
        "initialization.exact",
        uuid(0x10),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let interval = scenario_interval(
        1,
        exact.entry.transition_id(),
        exact.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?;
    let exact_transition = exact.entry.transition_id();
    let exact_fingerprint = exact.entry.outer_entry_fingerprint();
    let mut vectors = vec![initialization_case(
        "exactInitialOpeningAccepted",
        exact.clone(),
        vec![interval.clone()],
        expected_ok_empty("initialized"),
    )?];
    let alternate_entry = scenario_opening_for_recipient(
        "initialization.alternateEntryId",
        uuid(0x11),
        exact_transition,
        exact_fingerprint,
        1,
        DID,
        DEVICE_ID,
        ApplicationIntervalOpeningKind::Creation,
        None,
        None,
        initial_context.clone(),
    )?;
    vectors.push(initialization_case(
        "appendEntryIdIsIndependentPositive",
        alternate_entry,
        vec![interval.clone()],
        expected_ok_empty("initialized"),
    )?);
    let cases = vec![
        (
            "initialOpeningSeqMismatch",
            scenario_opening_for_recipient(
                "initialization.wrongSeq",
                uuid(0x12),
                exact_transition,
                exact_fingerprint,
                2,
                DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                initial_context.clone(),
            )?,
            2,
        ),
        (
            "initialOpeningKindMismatch",
            scenario_opening_for_recipient(
                "initialization.wrongKind",
                uuid(0x13),
                exact_transition,
                exact_fingerprint,
                1,
                DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Add,
                None,
                None,
                initial_context.clone(),
            )?,
            1,
        ),
        (
            "initialOpeningTransitionIdMismatch",
            scenario_opening_for_recipient(
                "initialization.wrongTransition",
                uuid(0x14),
                scenario_transition_id("initialization.wrongTransition"),
                exact_fingerprint,
                1,
                DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                initial_context.clone(),
            )?,
            1,
        ),
        (
            "initialOpeningFingerprintMismatch",
            scenario_opening_for_recipient(
                "initialization.wrongFingerprint",
                uuid(0x15),
                exact_transition,
                scenario_fingerprint("initialization.wrongFingerprint"),
                1,
                DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                initial_context.clone(),
            )?,
            1,
        ),
        (
            "initialOpeningContextMismatch",
            scenario_opening_for_recipient(
                "initialization.wrongContext",
                uuid(0x16),
                exact_transition,
                exact_fingerprint,
                1,
                DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                advanced_context(&initial_context, 1),
            )?,
            1,
        ),
        (
            "initialOpeningRecipientDidMismatch",
            scenario_opening_for_recipient(
                "initialization.wrongDid",
                uuid(0x17),
                exact_transition,
                exact_fingerprint,
                1,
                FOREIGN_DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                initial_context.clone(),
            )?,
            1,
        ),
        (
            "initialOpeningSiblingDeviceMismatch",
            scenario_opening_for_recipient(
                "initialization.siblingDevice",
                uuid(0x18),
                exact_transition,
                exact_fingerprint,
                1,
                DID,
                RECEIVER_DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                initial_context.clone(),
            )?,
            1,
        ),
        (
            "appendEntryIdCannotSubstituteForOpeningTransitionId",
            scenario_opening_for_recipient(
                "initialization.entryIdSubstitution",
                exact_transition,
                uuid(0x10),
                exact_fingerprint,
                1,
                DID,
                DEVICE_ID,
                ApplicationIntervalOpeningKind::Creation,
                None,
                None,
                initial_context.clone(),
            )?,
            1,
        ),
    ];
    for (name, opening, seq) in cases {
        vectors.push(initialization_case(
            name,
            opening,
            vec![interval.clone()],
            expected_error("invalid_interval_opening", Some(seq), None, None, None),
        )?);
    }

    let reset_previous = initial_context;
    let reset_context = advanced_context(&reset_previous, 10);
    let reset_transition = scenario_transition_id("initialization.resetFirstExact");
    let reset_fingerprint = scenario_fingerprint("initialization.resetFirstExact");
    let reset_exact = scenario_opening_for_recipient(
        "initialization.resetFirstExact",
        uuid(0x20),
        reset_transition,
        reset_fingerprint,
        10,
        DID,
        DEVICE_ID,
        ApplicationIntervalOpeningKind::Reset,
        None,
        Some(reset_previous.clone()),
        reset_context.clone(),
    )?;
    let reset_interval = scenario_interval(
        10,
        reset_transition,
        reset_fingerprint,
        ApplicationIntervalOpeningKind::Reset,
        reset_context.clone(),
        None,
    )?;
    vectors.push(initialization_case(
        "exactResetFirstOpeningAccepted",
        reset_exact,
        vec![reset_interval.clone()],
        expected_ok_empty("initialized"),
    )?);
    vectors.push(initialization_case(
        "resetFirstOpeningSeqMismatch",
        scenario_opening_for_recipient(
            "initialization.resetFirstWrongSeq",
            uuid(0x21),
            reset_transition,
            reset_fingerprint,
            11,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Reset,
            None,
            Some(reset_previous.clone()),
            reset_context.clone(),
        )?,
        vec![reset_interval.clone()],
        expected_error("invalid_interval_opening", Some(11), None, None, None),
    )?);
    vectors.push(invalid_initialization_opening_construction_case(
        "resetFirstOpeningKindMismatch",
        uuid(0x22),
        reset_transition,
        reset_fingerprint,
        10,
        ApplicationIntervalOpeningKind::Add,
        Some(reset_previous.clone()),
        reset_context.clone(),
        &reset_interval,
    )?);
    vectors.push(initialization_case(
        "resetFirstOpeningTransitionIdMismatch",
        scenario_opening_for_recipient(
            "initialization.resetFirstWrongTransition",
            uuid(0x23),
            scenario_transition_id("initialization.resetFirstWrongTransition"),
            reset_fingerprint,
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Reset,
            None,
            Some(reset_previous.clone()),
            reset_context.clone(),
        )?,
        vec![reset_interval.clone()],
        expected_error("invalid_interval_opening", Some(10), None, None, None),
    )?);
    vectors.push(initialization_case(
        "resetFirstOpeningFingerprintMismatch",
        scenario_opening_for_recipient(
            "initialization.resetFirstWrongFingerprint",
            uuid(0x24),
            reset_transition,
            scenario_fingerprint("initialization.resetFirstWrongFingerprint"),
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Reset,
            None,
            Some(reset_previous.clone()),
            reset_context.clone(),
        )?,
        vec![reset_interval.clone()],
        expected_error("invalid_interval_opening", Some(10), None, None, None),
    )?);
    vectors.push(initialization_case(
        "resetFirstOpeningContextMismatch",
        scenario_opening_for_recipient(
            "initialization.resetFirstWrongContext",
            uuid(0x25),
            reset_transition,
            reset_fingerprint,
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Reset,
            None,
            Some(reset_previous.clone()),
            advanced_context(&reset_previous, 11),
        )?,
        vec![reset_interval],
        expected_error("invalid_interval_opening", Some(10), None, None, None),
    )?);
    Ok(vectors)
}

#[allow(clippy::too_many_arguments)]
fn invalid_initialization_opening_construction_case(
    name: &str,
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    fingerprint: [u8; 32],
    seq: u64,
    opening_kind: ApplicationIntervalOpeningKind,
    previous: Option<ConversationContext>,
    next: ConversationContext,
    interval: &ApplicationAccessInterval,
) -> Result<Value> {
    let error = VerifiedApplicationControlEntry::test_only_interval_opening(
        entry_id,
        transition_id,
        seq,
        fingerprint,
        DID.into(),
        DEVICE_ID.into(),
        opening_kind,
        None,
        previous.clone(),
        next.clone(),
    )
    .expect_err("invalid reset-first kind candidate unexpectedly constructed");
    let actual = reducer_result(
        std::result::Result::<ReducerOutcome, ReducerError>::Err(error),
        None,
    );
    let expected = expected_error("invalid_interval_opening", Some(seq), None, None, None);
    if actual != expected {
        return Err(format!("initialization construction vector {name} returned {actual}").into());
    }
    Ok(json!({
        "name": name,
        "validationLayer": "verifiedControlConstruction",
        "opening": {
            "kind": "intervalOpening",
            "entryIdHex": hex::encode(entry_id),
            "transitionIdHex": hex::encode(transition_id),
            "seq": seq,
            "outerEntryFingerprintHex": hex::encode(fingerprint),
            "recipientDid": DID,
            "recipientDeviceId": DEVICE_ID,
            "openingKind": interval_kind_name(opening_kind),
            "closingKind": null,
            "previous": previous.as_ref().map(context_value),
            "next": context_value(&next),
        },
        "accessIntervals": [interval_value(interval)],
        "expectedResult": expected,
        "expectedState": null,
        "reducerConstructed": false,
    }))
}

fn initialization_case(
    name: &str,
    opening: ScenarioControl,
    intervals: Vec<ApplicationAccessInterval>,
    expected_result: Value,
) -> Result<Value> {
    let initialized = ApplicationReducer::new(&opening.entry, intervals.clone());
    let (actual_result, state) = match initialized {
        Ok(reducer) => (
            expected_ok_empty("initialized"),
            Some(reducer_state(&reducer, &[], &[])),
        ),
        Err(error) => (
            reducer_result(
                std::result::Result::<ReducerOutcome, ReducerError>::Err(error),
                None,
            ),
            None,
        ),
    };
    if actual_result != expected_result {
        return Err(format!(
            "initialization vector {name} expected {expected_result}, got {actual_result}"
        )
        .into());
    }
    if let Some(snapshot) = state.as_ref() {
        let first_interval = intervals
            .first()
            .ok_or_else(|| format!("successful initialization vector {name} has no interval"))?;
        let processed = snapshot["processed"].as_array().ok_or_else(|| {
            format!("successful initialization vector {name} has no processed rows")
        })?;
        let seen_entry_ids = snapshot["seenEntryIds"]
            .as_array()
            .ok_or_else(|| format!("successful initialization vector {name} has no entry index"))?;
        let expected_access_intervals = Value::Array(
            intervals
                .iter()
                .map(|interval| {
                    let mut value = interval_value(interval);
                    value
                        .as_object_mut()
                        .expect("interval fixtures are objects")
                        .remove("endSeq");
                    value
                })
                .collect(),
        );
        let exact_input_checks = [
            (
                "recipientDid",
                snapshot["recipientDid"] == first_interval.recipient_did(),
            ),
            (
                "recipientDeviceId",
                snapshot["recipientDeviceId"] == first_interval.recipient_device_id(),
            ),
            (
                "conversationIdHex",
                snapshot["conversationIdHex"]
                    == hex::encode(first_interval.opening_context().conversation_id),
            ),
            ("afterSeq", snapshot["afterSeq"] == opening.entry.seq()),
            (
                "expectedContext",
                snapshot["expectedContext"] == context_value(first_interval.opening_context()),
            ),
            ("terminalProof", snapshot["terminalProof"].is_null()),
            (
                "accessIntervals",
                snapshot["accessIntervals"] == expected_access_intervals,
            ),
            ("processedCount", processed.len() == 1),
            ("processedSeq", processed[0]["seq"] == opening.entry.seq()),
            (
                "processedEntryId",
                processed[0]["entryIdHex"] == hex::encode(opening.entry.entry_id()),
            ),
            (
                "processedFingerprint",
                processed[0]["outerEntryFingerprintHex"]
                    == hex::encode(opening.entry.outer_entry_fingerprint()),
            ),
            ("seenEntryCount", seen_entry_ids.len() == 1),
            (
                "seenEntrySeq",
                seen_entry_ids[0]["seq"] == opening.entry.seq(),
            ),
            (
                "seenEntryId",
                seen_entry_ids[0]["identifierHex"] == hex::encode(opening.entry.entry_id()),
            ),
            ("seenMessageIds", snapshot["seenMessageIds"] == json!([])),
            ("originalsBySeq", snapshot["originalsBySeq"] == json!([])),
            ("messages", snapshot["messages"] == json!([])),
            ("readFrontiers", snapshot["readFrontiers"] == json!([])),
        ];
        if let Some((field, _)) = exact_input_checks.iter().find(|(_, matches)| !matches) {
            return Err(format!(
                "successful initialization vector {name} state field {field} is not derived exactly from its input"
            )
            .into());
        }
    }
    Ok(json!({
        "name": name,
        "opening": opening.fixture,
        "accessIntervals": intervals.iter().map(interval_value).collect::<Vec<_>>(),
        "expectedResult": expected_result,
        "expectedState": state,
    }))
}

fn reducer_schedule_validation_vectors() -> Result<Vec<Value>> {
    let context0 = context();
    let context3 = advanced_context(&context0, 3);
    let context4 = advanced_context(&context0, 4);
    let opening = scenario_opening(
        "schedule.opening",
        uuid(0x01),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let open_interval = scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        None,
    )?;
    let mut vectors = Vec::new();

    let mut finite_missing_proof = interval_value(&open_interval);
    finite_missing_proof["endSeq"] = json!(3);
    vectors.push(malformed_schedule_case(
        "finiteIntervalMissingClosingProof",
        &opening,
        vec![finite_missing_proof],
    ));

    let mut finite_partial_proof = interval_value(&open_interval);
    finite_partial_proof["endSeq"] = json!(3);
    finite_partial_proof["closing"] = json!({
        "seq": 3,
        "transitionIdHex": hex::encode(scenario_transition_id("schedule.partialClose")),
        "kind": "remove",
    });
    vectors.push(malformed_schedule_case(
        "finiteIntervalPartialClosingProof",
        &opening,
        vec![finite_partial_proof],
    ));

    let remove = scenario_interval_closing(
        "schedule.remove",
        uuid(0x02),
        3,
        ApplicationIntervalClosingKind::Remove,
        context0.clone(),
        context3.clone(),
    )?;
    let finite_remove = scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        Some((&remove, ApplicationIntervalClosingKind::Remove)),
    )?;
    let mut open_with_close = interval_value(&finite_remove);
    open_with_close["endSeq"] = Value::Null;
    vectors.push(malformed_schedule_case(
        "openIntervalCarriesClosingProof",
        &opening,
        vec![open_with_close],
    ));
    let mut mismatched_close_seq = interval_value(&finite_remove);
    mismatched_close_seq["endSeq"] = json!(4);
    vectors.push(malformed_schedule_case(
        "finiteIntervalEndSeqClosingSeqMismatch",
        &opening,
        vec![mismatched_close_seq],
    ));

    let mut same_seq_terminal = interval_value(&open_interval);
    same_seq_terminal["endSeq"] = json!(1);
    same_seq_terminal["closing"] = json!({
        "seq": 1,
        "transitionIdHex": hex::encode(scenario_transition_id("schedule.sameSeqTerminal")),
        "outerEntryFingerprintHex": hex::encode(scenario_fingerprint("schedule.sameSeqTerminal")),
        "kind": "terminal",
    });
    vectors.push(malformed_schedule_case(
        "creationOpenTerminalCloseSameSeq",
        &opening,
        vec![same_seq_terminal],
    ));

    let mut close_before_opening = interval_value(&open_interval);
    close_before_opening["startSeq"] = json!(10);
    close_before_opening["endSeq"] = json!(9);
    close_before_opening["closing"] = json!({
        "seq": 9,
        "transitionIdHex": hex::encode(scenario_transition_id("schedule.closeBeforeOpening")),
        "outerEntryFingerprintHex": hex::encode(scenario_fingerprint("schedule.closeBeforeOpening")),
        "kind": "remove",
    });
    vectors.push(malformed_schedule_case(
        "finiteIntervalCloseBeforeOpeningRejected",
        &opening,
        vec![close_before_opening],
    ));

    let touching_add = scenario_interval(
        3,
        scenario_transition_id("schedule.touchingAdd"),
        scenario_fingerprint("schedule.touchingAdd"),
        ApplicationIntervalOpeningKind::Add,
        context3.clone(),
        None,
    )?;
    vectors.push(schedule_reducer_case(
        "removeTouchingAddRejected",
        &opening,
        vec![finite_remove.clone(), touching_add],
    )?);

    let overlapping_add = scenario_interval(
        2,
        scenario_transition_id("schedule.overlappingAdd"),
        scenario_fingerprint("schedule.overlappingAdd"),
        ApplicationIntervalOpeningKind::Add,
        context3.clone(),
        None,
    )?;
    vectors.push(schedule_reducer_case(
        "removeWithoutStrictGapRejected",
        &opening,
        vec![finite_remove.clone(), overlapping_add],
    )?);

    let terminal = scenario_terminal("schedule.terminal", uuid(0x03), 3, context0.clone())?;
    let finite_terminal = scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        Some((&terminal, ApplicationIntervalClosingKind::Terminal)),
    )?;
    let post_terminal_add = scenario_interval(
        4,
        scenario_transition_id("schedule.postTerminalAdd"),
        scenario_fingerprint("schedule.postTerminalAdd"),
        ApplicationIntervalOpeningKind::Add,
        context4.clone(),
        None,
    )?;
    vectors.push(schedule_reducer_case(
        "terminalIntervalHasNoSuccessor",
        &opening,
        vec![finite_terminal, post_terminal_add],
    )?);

    let replace = scenario_interval_closing(
        "schedule.replace",
        uuid(0x04),
        3,
        ApplicationIntervalClosingKind::Replace,
        context0.clone(),
        context3.clone(),
    );
    assert!(
        replace.is_err(),
        "close-only Replace controls are type-forbidden"
    );
    let replace_transition = scenario_transition_id("schedule.replaceShared");
    let replace_fingerprint = scenario_fingerprint("schedule.replaceShared");
    let first_replace = ApplicationAccessInterval::test_only(
        DID.into(),
        DEVICE_ID.into(),
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        Some(ApplicationIntervalClosingProof::test_only(
            3,
            replace_transition,
            replace_fingerprint,
            ApplicationIntervalClosingKind::Replace,
        )?),
    )?;
    let nonshared_add = scenario_interval(
        3,
        scenario_transition_id("schedule.nonsharedAdd"),
        scenario_fingerprint("schedule.nonsharedAdd"),
        ApplicationIntervalOpeningKind::Add,
        context3.clone(),
        None,
    )?;
    vectors.push(schedule_reducer_case(
        "replaceAddNonsharedProofRejected",
        &opening,
        vec![first_replace, nonshared_add],
    )?);

    let reset_transition = scenario_transition_id("schedule.resetShared");
    let reset_fingerprint = scenario_fingerprint("schedule.resetShared");
    let first_reset = ApplicationAccessInterval::test_only(
        DID.into(),
        DEVICE_ID.into(),
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0,
        Some(ApplicationIntervalClosingProof::test_only(
            3,
            reset_transition,
            reset_fingerprint,
            ApplicationIntervalClosingKind::Reset,
        )?),
    )?;
    let wrong_reset_successor = scenario_interval(
        3,
        reset_transition,
        reset_fingerprint,
        ApplicationIntervalOpeningKind::Add,
        context3,
        None,
    )?;
    vectors.push(schedule_reducer_case(
        "resetTouchingAddRejected",
        &opening,
        vec![first_reset, wrong_reset_successor],
    )?);
    Ok(vectors)
}

fn malformed_schedule_case(name: &str, opening: &ScenarioControl, intervals: Vec<Value>) -> Value {
    json!({
        "name": name,
        "validationLayer": "strictFixtureRestore",
        "opening": opening.fixture,
        "accessIntervals": intervals,
        "expectedResult": expected_error("invalid_access_intervals", None, None, None, None),
        "expectedState": null,
    })
}

fn schedule_reducer_case(
    name: &str,
    opening: &ScenarioControl,
    intervals: Vec<ApplicationAccessInterval>,
) -> Result<Value> {
    let error = ApplicationReducer::new(&opening.entry, intervals.clone())
        .expect_err("invalid schedule vector unexpectedly initialized");
    let actual = reducer_result(
        std::result::Result::<ReducerOutcome, ReducerError>::Err(error),
        None,
    );
    let expected = expected_error("invalid_access_intervals", None, None, None, None);
    if actual != expected {
        return Err(format!("schedule vector {name} returned {actual}").into());
    }
    Ok(json!({
        "name": name,
        "validationLayer": "reducerSchedule",
        "opening": opening.fixture,
        "accessIntervals": intervals.iter().map(interval_value).collect::<Vec<_>>(),
        "expectedResult": expected,
        "expectedState": null,
    }))
}

fn reducer_scenarios(
    transport: &mut ApplicationTransportFixture,
    signed_terminal_close: &SignedControlEnvelopeFixture,
) -> Result<Vec<Value>> {
    Ok(vec![
        named_scenario("editReply", reducer_edit_reply_replay_conflicts(transport))?,
        named_scenario("reaction", reducer_reaction_tombstone(transport))?,
        named_scenario("replies", reducer_reply_presentations(transport))?,
        named_scenario("read", reducer_read_frontiers(transport))?,
        named_scenario(
            "sameDidAuthority",
            reducer_same_did_cross_device_authority(transport),
        )?,
        named_scenario(
            "differentDidAuthority",
            reducer_different_did_authority(transport),
        )?,
        named_scenario(
            "missingTarget",
            reducer_missing_accessible_target_corruption(transport),
        )?,
        named_scenario(
            "dynamicReplace",
            reducer_dynamic_replace_add_boundary(transport),
        )?,
        named_scenario(
            "touchingReplace",
            reducer_touching_opening_provenance(
                transport,
                "touchingReplaceAddOpeningProvenance",
                "touchingReplace",
                ApplicationIntervalOpeningKind::Add,
                ApplicationIntervalClosingKind::Replace,
                0x20,
            ),
        )?,
        named_scenario(
            "touchingReset",
            reducer_touching_opening_provenance(
                transport,
                "touchingResetResetOpeningProvenance",
                "touchingReset",
                ApplicationIntervalOpeningKind::Reset,
                ApplicationIntervalClosingKind::Reset,
                0x30,
            ),
        )?,
        named_scenario("finiteClose", reducer_finite_close_provenance(transport))?,
        named_scenario("nonleafReset", reducer_nonleaf_reset_activator(transport))?,
        named_scenario(
            "terminalAfterRemove",
            reducer_terminal_after_closed_gap(
                transport,
                "terminalAfterRemoveClosedGap",
                "terminalAfterRemove",
                ApplicationIntervalClosingKind::Remove,
                0x60,
                Some(signed_terminal_close),
            ),
        )?,
        named_scenario(
            "terminalAfterReset",
            reducer_terminal_after_closed_gap(
                transport,
                "terminalAfterResetClosedGap",
                "terminalAfterReset",
                ApplicationIntervalClosingKind::Reset,
                0x70,
                None,
            ),
        )?,
        named_scenario("context", reducer_context_reset_terminal(transport))?,
        named_scenario("reanchor", reducer_non_touching_reanchor(transport))?,
        named_scenario("storage", reducer_opaque_rejected_retired(transport))?,
    ])
}

fn named_scenario(name: &str, result: Result<Value>) -> Result<Value> {
    result.map_err(|error| format!("reducer scenario {name}: {error}").into())
}

fn reducer_missing_accessible_target_corruption(
    transport: &mut ApplicationTransportFixture,
) -> Result<Value> {
    let initial_context = context();
    let opening = scenario_opening(
        "missingTarget.opening",
        uuid(0x21),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let target = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0x22),
    };
    let tracked = vec![("corruptedOriginal", target.clone())];
    let actors = vec![DID];
    let original = scenario_application_frame(
        transport,
        "missingTarget.original",
        uuid(0x23),
        2,
        &ApplicationFrame {
            message_id: target.target_message_id,
            context: initial_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("must remain indexed after storage corruption".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    let mut steps = vec![scenario_application_step(
        &mut reducer,
        &original,
        &tracked,
        &actors,
    )];
    steps.push(scenario_corrupt_remove_original_step(
        &mut reducer,
        &target,
        &tracked,
        &actors,
    ));
    let edit = scenario_application_frame(
        transport,
        "missingTarget.edit",
        uuid(0x24),
        3,
        &ApplicationFrame {
            message_id: uuid(0x25),
            context: initial_context,
            body: ApplicationBody::Edit(EditBody {
                target: target.clone(),
                replacement_text: "must fail closed".into(),
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &edit,
        &tracked,
        &actors,
    ));
    let expected_missing_error = json!({
        "status": "error",
        "code": "missing_accessible_target",
        "seq": target.target_seq,
        "expectedSeq": null,
        "identifierHex": null,
        "target": target_value(&target),
    });
    assert_eq!(steps[2]["expect"]["result"], expected_missing_error);
    assert_eq!(
        steps[2]["expect"]["stateBefore"],
        steps[2]["expect"]["stateAfter"]
    );
    assert_eq!(steps[2]["expect"]["stateAfter"]["afterSeq"], 2);
    assert_step_results(
        "missingAccessibleTargetCorruption",
        &steps,
        &[
            expected_ok_target("messageStored", &target),
            json!({
                "status": "ok",
                "code": "storedOriginalRemoved",
                "detail": { "target": target_value(&target) },
            }),
            expected_error(
                "missing_accessible_target",
                Some(target.target_seq),
                None,
                None,
                Some(&target),
            ),
        ],
    );
    Ok(scenario_json(
        "missingAccessibleTargetCorruption",
        "an accessible indexed original missing from durable message storage fails closed with a stable target-bearing error and no reducer mutation",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_dynamic_replace_add_boundary(
    transport: &mut ApplicationTransportFixture,
) -> Result<Value> {
    let context0 = context();
    let context3 = advanced_context(&context0, 3);
    let opening = scenario_opening(
        "dynamicReplace.opening",
        uuid(0x81),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let before = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0x82),
    };
    let after = MessageTarget {
        target_seq: 4,
        target_message_id: uuid(0x83),
    };
    let tracked = vec![
        ("beforeReplace", before.clone()),
        ("afterAdd", after.clone()),
    ];
    let actors = vec![DID];
    let first = scenario_application_frame(
        transport,
        "dynamicReplace.before",
        uuid(0x84),
        2,
        &ApplicationFrame {
            message_id: before.target_message_id,
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("before dynamic replace".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    let mut steps = vec![scenario_application_step(
        &mut reducer,
        &first,
        &tracked,
        &actors,
    )];
    let transition_id = scenario_transition_id("dynamicReplace.exact");
    let fingerprint = scenario_fingerprint("dynamicReplace.exact");
    for (label, entry_id, recipient_did, recipient_device_id) in [
        (
            "dynamicReplace.siblingDevice",
            uuid(0x85),
            DID,
            RECEIVER_DEVICE_ID,
        ),
        (
            "dynamicReplace.differentDid",
            uuid(0x86),
            FOREIGN_DID,
            DEVICE_ID,
        ),
    ] {
        let wrong = scenario_opening_for_recipient(
            label,
            entry_id,
            transition_id,
            fingerprint,
            3,
            recipient_did,
            recipient_device_id,
            ApplicationIntervalOpeningKind::Add,
            Some(ApplicationIntervalClosingKind::Replace),
            Some(context0.clone()),
            context3.clone(),
        )?;
        steps.push(scenario_control_step(
            &mut reducer,
            &wrong,
            &tracked,
            &actors,
        ));
    }
    let exact = scenario_opening_for_recipient(
        "dynamicReplace.exact",
        uuid(0x87),
        transition_id,
        fingerprint,
        3,
        DID,
        DEVICE_ID,
        ApplicationIntervalOpeningKind::Add,
        Some(ApplicationIntervalClosingKind::Replace),
        Some(context0.clone()),
        context3.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &exact,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &exact,
        &tracked,
        &actors,
    ));
    let second = scenario_application_frame(
        transport,
        "dynamicReplace.after",
        uuid(0x88),
        4,
        &ApplicationFrame {
            message_id: after.target_message_id,
            context: context3,
            body: ApplicationBody::Message(MessageBody {
                text: Some("after exact dynamic add".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &second,
        &tracked,
        &actors,
    ));
    assert_step_results(
        "dynamicReplaceAddExactRecipient",
        &steps,
        &[
            expected_ok_target("messageStored", &before),
            expected_error("invalid_interval_opening", Some(3), None, None, None),
            expected_error("invalid_interval_opening", Some(3), None, None, None),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_ok_empty("exactReplay"),
            expected_ok_target("messageStored", &after),
        ],
    );
    Ok(scenario_json(
        "dynamicReplaceAddExactRecipient",
        "a dynamic touching Replace to Add boundary is exact-device bound, atomically extends the schedule, and its shared row is processed once",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_touching_opening_provenance(
    transport: &mut ApplicationTransportFixture,
    scenario_name: &str,
    label: &str,
    opening_kind: ApplicationIntervalOpeningKind,
    closing_kind: ApplicationIntervalClosingKind,
    fill: u8,
) -> Result<Value> {
    let context0 = context();
    let context3 = advanced_context(&context0, 3);
    let opening = scenario_opening(
        &format!("{label}.opening"),
        uuid(fill),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let exact_transition = scenario_transition_id(&format!("{label}.exact"));
    let exact_fingerprint = scenario_fingerprint(&format!("{label}.exact"));
    let exact = scenario_opening_for_recipient(
        &format!("{label}.exact"),
        uuid(fill.wrapping_add(1)),
        exact_transition,
        exact_fingerprint,
        3,
        DID,
        DEVICE_ID,
        opening_kind,
        Some(closing_kind),
        Some(context0.clone()),
        context3.clone(),
    )?;
    let intervals = vec![
        scenario_interval(
            1,
            opening.entry.transition_id(),
            opening.entry.outer_entry_fingerprint(),
            ApplicationIntervalOpeningKind::Creation,
            context0.clone(),
            Some((&exact, closing_kind)),
        )?,
        scenario_interval(
            3,
            exact_transition,
            exact_fingerprint,
            opening_kind,
            context3.clone(),
            None,
        )?,
    ];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let before = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(fill.wrapping_add(2)),
    };
    let after = MessageTarget {
        target_seq: 4,
        target_message_id: uuid(fill.wrapping_add(3)),
    };
    let tracked = vec![
        ("beforeTouching", before.clone()),
        ("afterTouching", after.clone()),
    ];
    let actors = vec![DID];
    let before_app = scenario_application_frame(
        transport,
        &format!("{label}.before"),
        uuid(fill.wrapping_add(4)),
        2,
        &ApplicationFrame {
            message_id: before.target_message_id,
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("before exact touching boundary".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    let mut steps = vec![scenario_application_step(
        &mut reducer,
        &before_app,
        &tracked,
        &actors,
    )];
    let wrong_seq = scenario_opening_for_recipient(
        &format!("{label}.wrongSeq"),
        uuid(fill.wrapping_add(5)),
        exact_transition,
        exact_fingerprint,
        4,
        DID,
        DEVICE_ID,
        opening_kind,
        Some(closing_kind),
        Some(context0.clone()),
        context3.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &wrong_seq,
        &tracked,
        &actors,
    ));
    let invalid_kind = match opening_kind {
        ApplicationIntervalOpeningKind::Add => ApplicationIntervalOpeningKind::Reset,
        ApplicationIntervalOpeningKind::Reset => ApplicationIntervalOpeningKind::Add,
        ApplicationIntervalOpeningKind::Creation => {
            return Err("touching provenance requires Add or Reset".into())
        }
    };
    steps.push(scenario_invalid_opening_construction_step(
        &reducer,
        &format!("{label}.wrongKind"),
        uuid(fill.wrapping_add(6)),
        exact_transition,
        exact_fingerprint,
        3,
        DID,
        DEVICE_ID,
        invalid_kind,
        Some(closing_kind),
        Some(context0.clone()),
        context3.clone(),
        &tracked,
        &actors,
    )?);
    let wrong_transition = scenario_opening_for_recipient(
        &format!("{label}.wrongTransition"),
        uuid(fill.wrapping_add(7)),
        scenario_transition_id(&format!("{label}.wrongTransition")),
        exact_fingerprint,
        3,
        DID,
        DEVICE_ID,
        opening_kind,
        Some(closing_kind),
        Some(context0.clone()),
        context3.clone(),
    )?;
    let wrong_fingerprint = scenario_opening_for_recipient(
        &format!("{label}.wrongFingerprint"),
        uuid(fill.wrapping_add(8)),
        exact_transition,
        scenario_fingerprint(&format!("{label}.wrongFingerprint")),
        3,
        DID,
        DEVICE_ID,
        opening_kind,
        Some(closing_kind),
        Some(context0.clone()),
        context3.clone(),
    )?;
    let wrong_context = scenario_opening_for_recipient(
        &format!("{label}.wrongContext"),
        uuid(fill.wrapping_add(9)),
        exact_transition,
        exact_fingerprint,
        3,
        DID,
        DEVICE_ID,
        opening_kind,
        Some(closing_kind),
        Some(context0.clone()),
        advanced_context(&context0, 4),
    )?;
    for wrong in [&wrong_transition, &wrong_fingerprint, &wrong_context] {
        steps.push(scenario_control_step(
            &mut reducer,
            wrong,
            &tracked,
            &actors,
        ));
    }
    steps.push(scenario_control_step(
        &mut reducer,
        &exact,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &exact,
        &tracked,
        &actors,
    ));
    let after_app = scenario_application_frame(
        transport,
        &format!("{label}.after"),
        uuid(fill.wrapping_add(10)),
        4,
        &ApplicationFrame {
            message_id: after.target_message_id,
            context: context3,
            body: ApplicationBody::Message(MessageBody {
                text: Some("after exact touching boundary".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &after_app,
        &tracked,
        &actors,
    ));
    assert_step_results(
        scenario_name,
        &steps,
        &[
            expected_ok_target("messageStored", &before),
            expected_error("sequence_gap", Some(4), Some(3), None, None),
            expected_error("invalid_interval_opening", Some(3), None, None, None),
            expected_error("invalid_interval_opening", Some(3), None, None, None),
            expected_error("invalid_interval_opening", Some(3), None, None, None),
            expected_error("invalid_interval_opening", Some(3), None, None, None),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_ok_empty("exactReplay"),
            expected_ok_target("messageStored", &after),
        ],
    );
    Ok(scenario_json(
        scenario_name,
        "a predeclared touching row is consumed exactly once and rejects isolated opening provenance mutations without changing reducer state",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_finite_close_provenance(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let context0 = context();
    let context3 = advanced_context(&context0, 3);
    let opening = scenario_opening(
        "finiteClose.opening",
        uuid(0x89),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let close = scenario_interval_closing(
        "finiteClose.exact",
        uuid(0x8a),
        3,
        ApplicationIntervalClosingKind::Remove,
        context0.clone(),
        context3.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        Some((&close, ApplicationIntervalClosingKind::Remove)),
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let target = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0x8b),
    };
    let tracked = vec![("finiteCloseAnchor", target.clone())];
    let actors = vec![DID];
    let original = scenario_application_frame(
        transport,
        "finiteClose.original",
        uuid(0x8c),
        2,
        &ApplicationFrame {
            message_id: target.target_message_id,
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("finite close anchor".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    let mut steps = vec![scenario_application_step(
        &mut reducer,
        &original,
        &tracked,
        &actors,
    )];
    let application_at_close = scenario_application_frame(
        transport,
        "finiteClose.applicationAtClose",
        uuid(0x8d),
        3,
        &ApplicationFrame {
            message_id: uuid(0x8e),
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("cannot replace the close row".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &application_at_close,
        &tracked,
        &actors,
    ));
    let context_at_close = scenario_context_transition(
        "finiteClose.contextAtClose",
        uuid(0x8f),
        3,
        context0.clone(),
        context3.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &context_at_close,
        &tracked,
        &actors,
    ));
    let exact_transition = close.entry.transition_id();
    let exact_fingerprint = close.entry.outer_entry_fingerprint();
    let wrong_closes = vec![
        scenario_interval_closing_with_provenance(
            "finiteClose.wrongTransition",
            uuid(0x91),
            scenario_transition_id("finiteClose.wrongTransition"),
            exact_fingerprint,
            3,
            DID,
            DEVICE_ID,
            ApplicationIntervalClosingKind::Remove,
            context0.clone(),
            context3.clone(),
        )?,
        scenario_interval_closing_with_provenance(
            "finiteClose.wrongFingerprint",
            uuid(0x92),
            exact_transition,
            scenario_fingerprint("finiteClose.wrongFingerprint"),
            3,
            DID,
            DEVICE_ID,
            ApplicationIntervalClosingKind::Remove,
            context0.clone(),
            context3.clone(),
        )?,
        scenario_interval_closing_with_provenance(
            "finiteClose.wrongKind",
            uuid(0x93),
            exact_transition,
            exact_fingerprint,
            3,
            DID,
            DEVICE_ID,
            ApplicationIntervalClosingKind::Reset,
            context0.clone(),
            context3.clone(),
        )?,
        scenario_interval_closing_with_provenance(
            "finiteClose.siblingDevice",
            uuid(0x94),
            exact_transition,
            exact_fingerprint,
            3,
            DID,
            RECEIVER_DEVICE_ID,
            ApplicationIntervalClosingKind::Remove,
            context0.clone(),
            context3.clone(),
        )?,
        scenario_interval_closing_with_provenance(
            "finiteClose.differentDid",
            uuid(0x95),
            exact_transition,
            exact_fingerprint,
            3,
            FOREIGN_DID,
            DEVICE_ID,
            ApplicationIntervalClosingKind::Remove,
            context0.clone(),
            context3.clone(),
        )?,
        scenario_interval_closing_with_provenance(
            "finiteClose.wrongPrevious",
            uuid(0x96),
            exact_transition,
            exact_fingerprint,
            3,
            DID,
            DEVICE_ID,
            ApplicationIntervalClosingKind::Remove,
            advanced_context(&context0, 99),
            context3.clone(),
        )?,
    ];
    for wrong in &wrong_closes {
        steps.push(scenario_control_step(
            &mut reducer,
            wrong,
            &tracked,
            &actors,
        ));
    }
    steps.push(scenario_control_step(
        &mut reducer,
        &close,
        &tracked,
        &actors,
    ));
    let after_close = scenario_application_frame(
        transport,
        "finiteClose.after",
        uuid(0x98),
        4,
        &ApplicationFrame {
            message_id: uuid(0x99),
            context: context3,
            body: ApplicationBody::Message(MessageBody {
                text: Some("outside closed interval".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &after_close,
        &tracked,
        &actors,
    ));
    let mut expected = vec![
        expected_ok_target("messageStored", &target),
        expected_error("expected_control_boundary", Some(3), None, None, None),
        expected_error("expected_control_boundary", Some(3), None, None, None),
    ];
    expected.extend(std::iter::repeat_n(
        expected_error("invalid_interval_closing", Some(3), None, None, None),
        wrong_closes.len(),
    ));
    expected.extend([
        expected_ok_empty("nonApplicationAdvanced"),
        expected_error(
            "sequence_outside_access_interval",
            Some(4),
            None,
            None,
            None,
        ),
    ]);
    assert_step_results("finiteCloseExactProvenance", &steps, &expected);
    Ok(scenario_json(
        "finiteCloseExactProvenance",
        "a finite close row cannot be replaced by application or context data and must match recipient, kind, transition, fingerprint, and contexts exactly",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_nonleaf_reset_activator(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let predecessor = context();
    let reset_context = advanced_context(&predecessor, 10);
    let opening = scenario_opening(
        "nonleafReset.opening",
        uuid(0x9a),
        10,
        ApplicationIntervalOpeningKind::Reset,
        Some(predecessor),
        reset_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        10,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Reset,
        reset_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let target = MessageTarget {
        target_seq: 11,
        target_message_id: uuid(0x9b),
    };
    let tracked = vec![("firstPostResetMessage", target.clone())];
    let actors = vec![DID];
    let app = scenario_application_frame(
        transport,
        "nonleafReset.firstApplication",
        uuid(0x9c),
        11,
        &ApplicationFrame {
            message_id: target.target_message_id,
            context: reset_context,
            body: ApplicationBody::Message(MessageBody {
                text: Some("no pre-reset interval was granted".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    let steps = vec![scenario_application_step(
        &mut reducer,
        &app,
        &tracked,
        &actors,
    )];
    assert_step_results(
        "nonLeafResetActivatorFirstInterval",
        &steps,
        &[expected_ok_target("messageStored", &target)],
    );
    Ok(scenario_json(
        "nonLeafResetActivatorFirstInterval",
        "a verified reset activator that was not an old leaf begins at its first Reset opening and receives no pre-reset interval",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_terminal_after_closed_gap(
    transport: &mut ApplicationTransportFixture,
    scenario_name: &str,
    label: &str,
    closing_kind: ApplicationIntervalClosingKind,
    fill: u8,
    signed_terminal_close: Option<&SignedControlEnvelopeFixture>,
) -> Result<Value> {
    let context0 = context();
    let closed_context = advanced_context(&context0, 3);
    let stale_untrusted_previous = signed_terminal_close
        .map(|fixture| fixture.previous.clone())
        .unwrap_or_else(|| advanced_context(&context0, 77));
    if stale_untrusted_previous.conversation_id != context0.conversation_id {
        return Err(
            format!("{scenario_name} Terminal signed prior changed conversation identity").into(),
        );
    }
    let opening = scenario_opening(
        &format!("{label}.opening"),
        uuid(fill),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let close = scenario_interval_closing(
        &format!("{label}.close"),
        uuid(fill.wrapping_add(1)),
        3,
        closing_kind,
        context0.clone(),
        closed_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        context0.clone(),
        Some((&close, closing_kind)),
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let target = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(fill.wrapping_add(2)),
    };
    let tracked = vec![("beforeClosedGap", target.clone())];
    let actors = vec![DID];
    let original = scenario_application_frame(
        transport,
        &format!("{label}.original"),
        uuid(fill.wrapping_add(3)),
        2,
        &ApplicationFrame {
            message_id: target.target_message_id,
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("before closed membership gap".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    let mut steps = vec![scenario_application_step(
        &mut reducer,
        &original,
        &tracked,
        &actors,
    )];
    steps.push(scenario_control_step(
        &mut reducer,
        &close,
        &tracked,
        &actors,
    ));
    let gap_application = scenario_application_frame(
        transport,
        &format!("{label}.gapApplication"),
        uuid(fill.wrapping_add(4)),
        4,
        &ApplicationFrame {
            message_id: uuid(fill.wrapping_add(5)),
            context: closed_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("gap access must remain denied".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &gap_application,
        &tracked,
        &actors,
    ));
    let terminal_entry_id = signed_terminal_close
        .map(|fixture| fixture.entry_id)
        .unwrap_or_else(|| uuid(fill.wrapping_add(6)));
    let terminal_transition_id = signed_terminal_close
        .map(|fixture| fixture.transition_id)
        .unwrap_or_else(|| scenario_transition_id(&format!("{label}.terminal")));
    let terminal_fingerprint = signed_terminal_close
        .map(|fixture| fixture.fingerprint)
        .unwrap_or_else(|| scenario_fingerprint(&format!("{label}.terminal")));
    let terminal_seq = signed_terminal_close.map_or(10, |fixture| fixture.seq);
    if terminal_seq != 10 {
        return Err(format!("{scenario_name} signed Terminal fixture has unexpected seq").into());
    }
    let mut terminal = scenario_terminal_with_provenance(
        &format!("{label}.terminal"),
        terminal_entry_id,
        terminal_transition_id,
        terminal_fingerprint,
        terminal_seq,
        DID,
        DEVICE_ID,
        stale_untrusted_previous.clone(),
    )?;
    if signed_terminal_close.is_some() {
        terminal
            .fixture
            .as_object_mut()
            .ok_or("Terminal control fixture is not an object")?
            .extend([
                ("evidenceMode".into(), json!("signedControlEnvelopeBound")),
                (
                    "signedControlEnvelopeRef".into(),
                    json!("formerDeviceRemoveGapTerminalSignedEnvelope"),
                ),
            ]);
    }
    let mut cross_conversation_previous = stale_untrusted_previous.clone();
    cross_conversation_previous.conversation_id = uuid(fill.wrapping_add(9));
    for wrong in [
        scenario_terminal_with_provenance(
            &format!("{label}.terminalWrongDid"),
            uuid(fill.wrapping_add(10)),
            terminal_transition_id,
            terminal_fingerprint,
            10,
            FOREIGN_DID,
            DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalSiblingDevice"),
            uuid(fill.wrapping_add(11)),
            terminal_transition_id,
            terminal_fingerprint,
            10,
            DID,
            RECEIVER_DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalCrossConversation"),
            uuid(fill.wrapping_add(12)),
            terminal_transition_id,
            terminal_fingerprint,
            10,
            DID,
            DEVICE_ID,
            cross_conversation_previous.clone(),
        )?,
    ] {
        steps.push(scenario_control_step(
            &mut reducer,
            &wrong,
            &tracked,
            &actors,
        ));
    }
    let terminal_kind_substitution = scenario_interval_closing_with_provenance(
        &format!("{label}.terminalKindSubstitution"),
        uuid(fill.wrapping_add(13)),
        terminal_transition_id,
        terminal_fingerprint,
        10,
        DID,
        DEVICE_ID,
        ApplicationIntervalClosingKind::Reset,
        stale_untrusted_previous.clone(),
        advanced_context(&context0, 78),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &terminal_kind_substitution,
        &tracked,
        &actors,
    ));
    let exact_terminal_step_index = steps.len();
    if signed_terminal_close.is_some() && exact_terminal_step_index != 7 {
        return Err(format!(
            "signed former-device Terminal binding moved from step 7 to {exact_terminal_step_index}"
        )
        .into());
    }
    steps.push(scenario_control_step(
        &mut reducer,
        &terminal,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &terminal,
        &tracked,
        &actors,
    ));
    let mut conflict_previous = stale_untrusted_previous.clone();
    conflict_previous.state_version += 1;
    let conflicts = vec![
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictEntryId"),
            uuid(fill.wrapping_add(14)),
            terminal_transition_id,
            terminal_fingerprint,
            10,
            DID,
            DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictTransition"),
            terminal_entry_id,
            scenario_transition_id(&format!("{label}.terminalConflictTransition")),
            terminal_fingerprint,
            10,
            DID,
            DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictFingerprint"),
            terminal_entry_id,
            terminal_transition_id,
            scenario_fingerprint(&format!("{label}.terminalConflictFingerprint")),
            10,
            DID,
            DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictDid"),
            terminal_entry_id,
            terminal_transition_id,
            terminal_fingerprint,
            10,
            FOREIGN_DID,
            DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictDevice"),
            terminal_entry_id,
            terminal_transition_id,
            terminal_fingerprint,
            10,
            DID,
            RECEIVER_DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictPrevious"),
            terminal_entry_id,
            terminal_transition_id,
            terminal_fingerprint,
            10,
            DID,
            DEVICE_ID,
            conflict_previous,
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictConversation"),
            terminal_entry_id,
            terminal_transition_id,
            terminal_fingerprint,
            10,
            DID,
            DEVICE_ID,
            cross_conversation_previous,
        )?,
        scenario_terminal_with_provenance(
            &format!("{label}.terminalConflictSeq"),
            terminal_entry_id,
            terminal_transition_id,
            terminal_fingerprint,
            9,
            DID,
            DEVICE_ID,
            stale_untrusted_previous.clone(),
        )?,
    ];
    for conflict in &conflicts {
        steps.push(scenario_control_step(
            &mut reducer,
            conflict,
            &tracked,
            &actors,
        ));
    }
    let later_terminal = scenario_terminal_with_provenance(
        &format!("{label}.terminalLaterRow"),
        uuid(fill.wrapping_add(15)),
        terminal_transition_id,
        terminal_fingerprint,
        11,
        DID,
        DEVICE_ID,
        stale_untrusted_previous.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &later_terminal,
        &tracked,
        &actors,
    ));
    let post_terminal = scenario_application_frame(
        transport,
        &format!("{label}.postTerminal"),
        uuid(fill.wrapping_add(7)),
        11,
        &ApplicationFrame {
            message_id: uuid(fill.wrapping_add(8)),
            context: closed_context,
            body: ApplicationBody::Message(MessageBody {
                text: Some("terminal schedule is irreversible".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &post_terminal,
        &tracked,
        &actors,
    ));
    assert_step_results(
        scenario_name,
        &steps,
        &[
            expected_ok_target("messageStored", &target),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_error(
                "sequence_outside_access_interval",
                Some(4),
                None,
                None,
                None,
            ),
            expected_error("invalid_interval_closing", Some(10), None, None, None),
            expected_error("invalid_interval_closing", Some(10), None, None, None),
            expected_error("invalid_interval_closing", Some(10), None, None, None),
            expected_error("invalid_interval_closing", Some(10), None, None, None),
            expected_ok_empty("conversationTerminated"),
            expected_ok_empty("exactReplay"),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(10), None, None, None),
            expected_error("sequence_conflict", Some(9), None, None, None),
            expected_error("reducer_terminal", Some(11), None, None, None),
            expected_error("reducer_terminal", Some(11), None, None, None),
        ],
    );
    let terminal_state = &steps[exact_terminal_step_index]["expect"]["stateAfter"]["terminalProof"];
    assert_eq!(terminal_state["recipientDid"], DID);
    assert_eq!(terminal_state["recipientDeviceId"], DEVICE_ID);
    assert_eq!(
        terminal_state["conversationIdHex"],
        hex::encode(context0.conversation_id)
    );
    assert_eq!(terminal_state["entryIdHex"], hex::encode(terminal_entry_id));
    assert_eq!(terminal_state["seq"], 10);
    assert_eq!(
        terminal_state["transitionIdHex"],
        hex::encode(terminal_transition_id)
    );
    assert_eq!(
        terminal_state["outerEntryFingerprintHex"],
        hex::encode(terminal_fingerprint)
    );
    let final_snapshot = &steps.last().unwrap()["expect"]["stateAfter"];
    assert_eq!(final_snapshot["terminalProof"]["seq"], 10);
    assert_eq!(
        final_snapshot["accessIntervals"][0]["closing"]["kind"],
        interval_closing_kind_name(closing_kind)
    );
    assert_eq!(final_snapshot["accessIntervals"][0]["closing"]["seq"], 3);
    Ok(scenario_json(
        scenario_name,
        "a later exact-device Terminal proof crosses an inaccessible closed gap without granting history or rewriting the earlier close, then terminalizes irreversibly",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_same_did_cross_device_authority(
    transport: &mut ApplicationTransportFixture,
) -> Result<Value> {
    let initial_context = context();
    let opening = scenario_opening(
        "sameDidAuthority.opening",
        uuid(0x31),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let editable = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0x32),
    };
    let tombstoned = MessageTarget {
        target_seq: 4,
        target_message_id: uuid(0x34),
    };
    let tracked = vec![
        ("crossDeviceEdit", editable.clone()),
        ("crossDeviceTombstone", tombstoned.clone()),
    ];
    let actors = vec![DID];
    let specs = vec![
        (
            2,
            uuid(0x42),
            DEVICE_ID,
            ApplicationFrame {
                message_id: editable.target_message_id,
                context: initial_context.clone(),
                body: ApplicationBody::Message(MessageBody {
                    text: Some("device A original".into()),
                    reply_to: None,
                    embed: None,
                }),
            },
        ),
        (
            3,
            uuid(0x43),
            RECEIVER_DEVICE_ID,
            ApplicationFrame {
                message_id: uuid(0x33),
                context: initial_context.clone(),
                body: ApplicationBody::Edit(EditBody {
                    target: editable.clone(),
                    replacement_text: "edited by device B of the same DID".into(),
                }),
            },
        ),
        (
            4,
            uuid(0x44),
            DEVICE_ID,
            ApplicationFrame {
                message_id: tombstoned.target_message_id,
                context: initial_context.clone(),
                body: ApplicationBody::Message(MessageBody {
                    text: Some("second device may tombstone me".into()),
                    reply_to: None,
                    embed: None,
                }),
            },
        ),
        (
            5,
            uuid(0x45),
            RECEIVER_DEVICE_ID,
            ApplicationFrame {
                message_id: uuid(0x35),
                context: initial_context.clone(),
                body: ApplicationBody::Tombstone(TombstoneBody {
                    target: tombstoned.clone(),
                }),
            },
        ),
    ];
    let mut steps = Vec::new();
    for (seq, entry_id, device_id, frame) in specs {
        let application = scenario_application_frame(
            transport,
            &format!("sameDidAuthority.step{seq}"),
            entry_id,
            seq,
            &frame,
            vec![],
            DID,
            device_id,
            "exact",
        )?;
        steps.push(scenario_application_step(
            &mut reducer,
            &application,
            &tracked,
            &actors,
        ));
    }
    assert_step_results(
        "sameDidCrossDeviceAuthorAuthority",
        &steps,
        &[
            expected_ok_target("messageStored", &editable),
            expected_ok_target("editApplied", &editable),
            expected_ok_target("messageStored", &tombstoned),
            expected_ok_target("tombstoneApplied", &tombstoned),
        ],
    );
    Ok(scenario_json(
        "sameDidCrossDeviceAuthorAuthority",
        "edit and tombstone authority is the verified root DID, so another real MLS device of that DID is authorized",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_different_did_authority(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let initial_context = transport.different_did_context();
    let opening = scenario_opening(
        "differentDidAuthority.opening",
        uuid(0x46),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let editable = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0x47),
    };
    let tombstoned = MessageTarget {
        target_seq: 3,
        target_message_id: uuid(0x48),
    };
    let tracked = vec![
        ("foreignEditDenied", editable.clone()),
        ("foreignTombstoneDenied", tombstoned.clone()),
    ];
    let actors = vec![DID, FOREIGN_DID];
    let specs = vec![
        (
            2,
            uuid(0x49),
            DID,
            DEVICE_ID,
            ApplicationFrame {
                message_id: editable.target_message_id,
                context: initial_context.clone(),
                body: ApplicationBody::Message(MessageBody {
                    text: Some("Alice edit anchor".into()),
                    reply_to: None,
                    embed: None,
                }),
            },
        ),
        (
            3,
            uuid(0x4a),
            DID,
            DEVICE_ID,
            ApplicationFrame {
                message_id: tombstoned.target_message_id,
                context: initial_context.clone(),
                body: ApplicationBody::Message(MessageBody {
                    text: Some("Alice tombstone anchor".into()),
                    reply_to: None,
                    embed: None,
                }),
            },
        ),
        (
            4,
            uuid(0x4b),
            FOREIGN_DID,
            FOREIGN_DEVICE_ID,
            ApplicationFrame {
                message_id: uuid(0x4c),
                context: initial_context.clone(),
                body: ApplicationBody::Edit(EditBody {
                    target: editable.clone(),
                    replacement_text: "foreign edit must not apply".into(),
                }),
            },
        ),
        (
            5,
            uuid(0x4d),
            FOREIGN_DID,
            FOREIGN_DEVICE_ID,
            ApplicationFrame {
                message_id: uuid(0x4e),
                context: initial_context.clone(),
                body: ApplicationBody::Tombstone(TombstoneBody {
                    target: tombstoned.clone(),
                }),
            },
        ),
    ];
    let mut steps = Vec::new();
    for (seq, entry_id, actor_did, device_id, frame) in specs {
        let application = scenario_application_frame(
            transport,
            &format!("differentDidAuthority.step{seq}"),
            entry_id,
            seq,
            &frame,
            vec![],
            actor_did,
            device_id,
            "exact",
        )?;
        steps.push(scenario_application_step(
            &mut reducer,
            &application,
            &tracked,
            &actors,
        ));
    }
    assert_step_results(
        "differentDidAuthorAuthority",
        &steps,
        &[
            expected_ok_target("messageStored", &editable),
            expected_ok_target("messageStored", &tombstoned),
            expected_noop("unauthorized_actor", &editable),
            expected_noop("unauthorized_actor", &tombstoned),
        ],
    );
    Ok(scenario_json(
        "differentDidAuthorAuthority",
        "a real MLS member under a different verified root DID receives stable unauthorized-actor no-ops for edit and tombstone",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_edit_reply_replay_conflicts(
    transport: &mut ApplicationTransportFixture,
) -> Result<Value> {
    let initial_context = context();
    let opening = scenario_opening(
        "editReply.opening",
        uuid(0xd0),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let original_target = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0xd1),
    };
    let reply_target = MessageTarget {
        target_seq: 3,
        target_message_id: uuid(0xd2),
    };
    let tracked = vec![
        ("original", original_target.clone()),
        ("reply", reply_target.clone()),
    ];
    let actors = vec![DID];
    let mut steps = Vec::new();
    let original_frame = ApplicationFrame {
        message_id: original_target.target_message_id,
        context: initial_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: None,
            reply_to: None,
            embed: Some(ApplicationEmbed::EncryptedImage(EncryptedImage {
                blob: blob(0xd1),
                mime_type: "image/gif".into(),
                width: 2,
                height: 2,
                alt_text: Some("original embed".into()),
                blurhash: Some("abcdef".into()),
            })),
        }),
    };
    let original = scenario_application_frame(
        transport,
        "editReply.original",
        uuid(0xe2),
        2,
        &original_frame,
        vec![outer_for_frame(&original_frame).unwrap()],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &original,
        &tracked,
        &actors,
    ));
    let reply_frame = ApplicationFrame {
        message_id: reply_target.target_message_id,
        context: initial_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("reply text".into()),
            reply_to: Some(original_target.clone()),
            embed: None,
        }),
    };
    let reply = scenario_application_frame(
        transport,
        "editReply.reply",
        uuid(0xe3),
        3,
        &reply_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &reply,
        &tracked,
        &actors,
    ));
    let edit_frame = ApplicationFrame {
        message_id: uuid(0xd3),
        context: initial_context.clone(),
        body: ApplicationBody::Edit(EditBody {
            target: original_target.clone(),
            replacement_text: "caption after edit".into(),
        }),
    };
    let edit = scenario_application_frame(
        transport,
        "editReply.edit",
        uuid(0xe4),
        4,
        &edit_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &edit,
        &tracked,
        &actors,
    ));
    steps.push(scenario_application_step(
        &mut reducer,
        &edit,
        &tracked,
        &actors,
    ));

    let changed_signature = scenario_application_frame(
        transport,
        "editReply.changedSignature",
        uuid(0xe4),
        4,
        &edit_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &changed_signature,
        &tracked,
        &actors,
    ));
    let changed_entry = scenario_application_frame(
        transport,
        "editReply.changedEntryId",
        uuid(0xe5),
        4,
        &edit_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &changed_entry,
        &tracked,
        &actors,
    ));
    let changed_seq = scenario_application_frame(
        transport,
        "editReply.changedSeq",
        uuid(0xe4),
        5,
        &edit_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &changed_seq,
        &tracked,
        &actors,
    ));
    let changed_context_value = advanced_context(&initial_context, 9);
    let mut changed_context_frame = edit_frame.clone();
    changed_context_frame.context = changed_context_value;
    let changed_context = scenario_application_frame(
        transport,
        "editReply.changedContext",
        uuid(0xe6),
        4,
        &changed_context_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &changed_context,
        &tracked,
        &actors,
    ));
    let changed_sender = scenario_application_frame(
        transport,
        "editReply.changedSender",
        uuid(0xe7),
        4,
        &edit_frame,
        vec![],
        DID,
        RECEIVER_DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &changed_sender,
        &tracked,
        &actors,
    ));
    let changed_blob_binding = CorpusOuterBlobBinding {
        blob_id: uuid(0xee),
        ciphertext_sha256: [0xee; 32],
        ciphertext_size: 48,
        purpose: BlobPurpose::Attachment,
    };
    let changed_blob = scenario_application_raw(
        transport,
        "editReply.changedBlob",
        uuid(0xe8),
        4,
        edit_frame.message_id,
        edit_frame.context.clone(),
        encode_application_content(&edit_frame)?,
        vec![changed_blob_binding],
        DID,
        DEVICE_ID,
        "exact",
        "rejected",
        Some("bindingMismatch"),
        Some("edit"),
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &changed_blob,
        &tracked,
        &actors,
    ));
    assert_step_results(
        "editReplyEmbedReplayAndConflicts",
        &steps,
        &[
            expected_ok_target("messageStored", &original_target),
            expected_ok_target("messageStored", &reply_target),
            expected_ok_target("editApplied", &original_target),
            expected_ok_empty("exactReplay"),
            expected_error("sequence_conflict", Some(4), None, None, None),
            expected_error("sequence_conflict", Some(4), None, None, None),
            expected_error("retired_entry_id", None, None, Some(uuid(0xe4)), None),
            expected_error("sequence_conflict", Some(4), None, None, None),
            expected_error("sequence_conflict", Some(4), None, None, None),
            expected_error("sequence_conflict", Some(4), None, None, None),
        ],
    );
    Ok(scenario_json(
        "editReplyEmbedReplayAndConflicts",
        "edit is caption-only; reply/embed survive; exact replay is idempotent and every changed immutable coordinate conflicts",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_reaction_tombstone(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let initial_context = context();
    let opening = scenario_opening(
        "reaction.opening",
        uuid(0xd4),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let target = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0xd5),
    };
    let tracked = vec![("original", target.clone())];
    let actors = vec![DID];
    let mut steps = Vec::new();
    let bodies = vec![
        ApplicationBody::Message(MessageBody {
            text: Some("react to me".into()),
            reply_to: None,
            embed: None,
        }),
        ApplicationBody::Reaction(ReactionBody {
            target: target.clone(),
            emoji: "👍".into(),
            operation: ReactionOperation::Add,
        }),
        ApplicationBody::Reaction(ReactionBody {
            target: target.clone(),
            emoji: "👍".into(),
            operation: ReactionOperation::Remove,
        }),
        ApplicationBody::Reaction(ReactionBody {
            target: target.clone(),
            emoji: "👍".into(),
            operation: ReactionOperation::Add,
        }),
        ApplicationBody::Tombstone(TombstoneBody {
            target: target.clone(),
        }),
        ApplicationBody::Reaction(ReactionBody {
            target: target.clone(),
            emoji: "👍".into(),
            operation: ReactionOperation::Add,
        }),
        ApplicationBody::Edit(EditBody {
            target: target.clone(),
            replacement_text: "too late".into(),
        }),
    ];
    for (offset, body) in bodies.into_iter().enumerate() {
        let seq = 2 + offset as u64;
        let message_id = if seq == 2 {
            target.target_message_id
        } else {
            uuid(0xd5 + offset as u8)
        };
        let frame = ApplicationFrame {
            message_id,
            context: initial_context.clone(),
            body,
        };
        let app = scenario_application_frame(
            transport,
            &format!("reaction.step{seq}"),
            uuid(0xf0 + offset as u8),
            seq,
            &frame,
            vec![],
            DID,
            DEVICE_ID,
            "exact",
        )?;
        steps.push(scenario_application_step(
            &mut reducer,
            &app,
            &tracked,
            &actors,
        ));
    }
    assert_step_results(
        "reactionLifecycleAndTombstone",
        &steps,
        &[
            expected_ok_target("messageStored", &target),
            expected_ok_target("reactionApplied", &target),
            expected_ok_target("reactionApplied", &target),
            expected_ok_target("reactionApplied", &target),
            expected_ok_target("tombstoneApplied", &target),
            expected_noop("tombstone_dominates", &target),
            expected_noop("tombstone_dominates", &target),
        ],
    );
    Ok(scenario_json(
        "reactionLifecycleAndTombstone",
        "reaction add/remove is keyed by DID and emoji; tombstone clears reactions and permanently dominates later mutations",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_reply_presentations(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let initial_context = context();
    let closed_context = advanced_context(&initial_context, 5);
    let reanchor_context = advanced_context(&initial_context, 10);
    let opening = scenario_opening(
        "replies.opening",
        uuid(0x91),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let reanchor = scenario_opening(
        "replies.reanchor",
        uuid(0x92),
        10,
        ApplicationIntervalOpeningKind::Add,
        None,
        reanchor_context.clone(),
    )?;
    let close = scenario_interval_closing(
        "replies.close",
        uuid(0x90),
        5,
        ApplicationIntervalClosingKind::Remove,
        initial_context.clone(),
        closed_context,
    )?;
    let intervals = vec![
        scenario_interval(
            1,
            opening.entry.transition_id(),
            opening.entry.outer_entry_fingerprint(),
            ApplicationIntervalOpeningKind::Creation,
            initial_context.clone(),
            Some((&close, ApplicationIntervalClosingKind::Remove)),
        )?,
        scenario_interval(
            10,
            reanchor.entry.transition_id(),
            reanchor.entry.outer_entry_fingerprint(),
            ApplicationIntervalOpeningKind::Add,
            reanchor_context.clone(),
            None,
        )?,
    ];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let original = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0x93),
    };
    let deleted_reply = MessageTarget {
        target_seq: 4,
        target_message_id: uuid(0x94),
    };
    let unavailable_reply = MessageTarget {
        target_seq: 11,
        target_message_id: uuid(0x95),
    };
    let tracked = vec![
        ("original", original.clone()),
        ("deletedReply", deleted_reply.clone()),
        ("unavailableReply", unavailable_reply.clone()),
    ];
    let actors = vec![DID];
    let mut steps = Vec::new();
    let initial_apps = [
        ApplicationFrame {
            message_id: original.target_message_id,
            context: initial_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("original".into()),
                reply_to: None,
                embed: None,
            }),
        },
        ApplicationFrame {
            message_id: uuid(0x96),
            context: initial_context.clone(),
            body: ApplicationBody::Tombstone(TombstoneBody {
                target: original.clone(),
            }),
        },
        ApplicationFrame {
            message_id: deleted_reply.target_message_id,
            context: initial_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("reply to deleted".into()),
                reply_to: Some(original.clone()),
                embed: None,
            }),
        },
    ];
    for (offset, frame) in initial_apps.iter().enumerate() {
        let seq = 2 + offset as u64;
        let app = scenario_application_frame(
            transport,
            &format!("replies.step{seq}"),
            uuid(0x97 + offset as u8),
            seq,
            frame,
            vec![],
            DID,
            DEVICE_ID,
            "exact",
        )?;
        steps.push(scenario_application_step(
            &mut reducer,
            &app,
            &tracked,
            &actors,
        ));
    }
    steps.push(scenario_control_step(
        &mut reducer,
        &close,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &reanchor,
        &tracked,
        &actors,
    ));
    let post_gap_context = reanchor_context;
    let post_gap_frames = [
        ApplicationFrame {
            message_id: unavailable_reply.target_message_id,
            context: post_gap_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("reply to inaccessible row".into()),
                reply_to: Some(MessageTarget {
                    target_seq: 6,
                    target_message_id: uuid(0x98),
                }),
                embed: None,
            }),
        },
        ApplicationFrame {
            message_id: uuid(0x99),
            context: post_gap_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("pair mismatch".into()),
                reply_to: Some(MessageTarget {
                    target_seq: 4,
                    target_message_id: uuid(0xfe),
                }),
                embed: None,
            }),
        },
        ApplicationFrame {
            message_id: uuid(0x9a),
            context: post_gap_context.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("not original".into()),
                reply_to: Some(MessageTarget {
                    target_seq: 3,
                    target_message_id: uuid(0x96),
                }),
                embed: None,
            }),
        },
    ];
    for (offset, frame) in post_gap_frames.iter().enumerate() {
        let seq = 11 + offset as u64;
        let app = scenario_application_frame(
            transport,
            &format!("replies.postGap{seq}"),
            uuid(0xa1 + offset as u8),
            seq,
            frame,
            vec![],
            DID,
            DEVICE_ID,
            "exact",
        )?;
        steps.push(scenario_application_step(
            &mut reducer,
            &app,
            &tracked,
            &actors,
        ));
    }
    assert_step_results(
        "replyPresentationDistinctions",
        &steps,
        &[
            expected_ok_target("messageStored", &original),
            expected_ok_target("tombstoneApplied", &original),
            expected_ok_target("messageStored", &deleted_reply),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_ok_target("messageStored", &unavailable_reply),
            expected_noop(
                "target_pair_mismatch",
                &MessageTarget {
                    target_seq: 4,
                    target_message_id: uuid(0xfe),
                },
            ),
            expected_noop(
                "target_not_original",
                &MessageTarget {
                    target_seq: 3,
                    target_message_id: uuid(0x96),
                },
            ),
        ],
    );
    Ok(scenario_json(
        "replyPresentationDistinctions",
        "accessible tombstones render deleted stubs, inaccessible intervals render unavailable stubs, and pair/not-original targets are terminal no-ops",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_read_frontiers(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let initial_context = context();
    let opening = scenario_opening(
        "read.opening",
        uuid(0xa4),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let first = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0xa5),
    };
    let second = MessageTarget {
        target_seq: 5,
        target_message_id: uuid(0xa6),
    };
    let tracked = vec![("first", first.clone()), ("second", second.clone())];
    let actors = vec![DID];
    let second_device = RECEIVER_DEVICE_ID;
    let specs = vec![
        (
            2,
            first.target_message_id,
            ApplicationBody::Message(MessageBody {
                text: Some("one".into()),
                reply_to: None,
                embed: None,
            }),
            DEVICE_ID,
        ),
        (
            3,
            uuid(0xa7),
            ApplicationBody::ReadState(ReadStateBody {
                through_seq: 2,
                through_message_id: first.target_message_id,
            }),
            DEVICE_ID,
        ),
        (
            4,
            uuid(0xa8),
            ApplicationBody::ReadState(ReadStateBody {
                through_seq: 2,
                through_message_id: first.target_message_id,
            }),
            second_device,
        ),
        (
            5,
            second.target_message_id,
            ApplicationBody::Message(MessageBody {
                text: Some("two".into()),
                reply_to: None,
                embed: None,
            }),
            DEVICE_ID,
        ),
        (
            6,
            uuid(0xa9),
            ApplicationBody::ReadState(ReadStateBody {
                through_seq: 5,
                through_message_id: second.target_message_id,
            }),
            second_device,
        ),
        (
            7,
            uuid(0xaa),
            ApplicationBody::ReadState(ReadStateBody {
                through_seq: 2,
                through_message_id: first.target_message_id,
            }),
            DEVICE_ID,
        ),
        (
            8,
            uuid(0xab),
            ApplicationBody::ReadState(ReadStateBody {
                through_seq: 5,
                through_message_id: uuid(0xff),
            }),
            DEVICE_ID,
        ),
    ];
    let mut steps = Vec::new();
    for (index, (seq, message_id, body, device_id)) in specs.into_iter().enumerate() {
        let frame = ApplicationFrame {
            message_id,
            context: initial_context.clone(),
            body,
        };
        let app = scenario_application_frame(
            transport,
            &format!("read.step{seq}"),
            uuid(0xac + index as u8),
            seq,
            &frame,
            vec![],
            DID,
            device_id,
            "exact",
        )?;
        steps.push(scenario_application_step(
            &mut reducer,
            &app,
            &tracked,
            &actors,
        ));
    }
    assert_step_results(
        "readFrontierSemantics",
        &steps,
        &[
            expected_ok_target("messageStored", &first),
            expected_ok_frontier("readStateAdvanced", &first),
            expected_ok_frontier("readStateUnchanged", &first),
            expected_ok_target("messageStored", &second),
            expected_ok_frontier("readStateAdvanced", &second),
            expected_noop("read_frontier_regression", &first),
            expected_noop(
                "read_frontier_pair_mismatch",
                &MessageTarget {
                    target_seq: 5,
                    target_message_id: uuid(0xff),
                },
            ),
        ],
    );
    Ok(scenario_json(
        "readFrontierSemantics",
        "read frontiers are DID-wide across devices, monotonic, pair-bound, and distinguish unchanged from regression",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_context_reset_terminal(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let context0 = context();
    let context1 = advanced_context(&context0, 1);
    let context2 = advanced_context(&context0, 2);
    let context3 = advanced_context(&context0, 3);
    let context4 = advanced_context(&context0, 4);
    let opening = scenario_opening(
        "context.opening",
        uuid(0xb4),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let reset_entry_id = uuid(0xb5);
    let reset_transition_id = scenario_transition_id("context.reset");
    let future_opening_entry_id = uuid(0xb6);
    let reset = scenario_opening_with_transition(
        "context.reset",
        reset_entry_id,
        reset_transition_id,
        4,
        ApplicationIntervalOpeningKind::Reset,
        Some(ApplicationIntervalClosingKind::Reset),
        Some(context1.clone()),
        context2.clone(),
    )?;
    let terminal_entry_id = uuid(0xc1);
    let terminal_transition_id = scenario_transition_id("context.terminal");
    let terminal_fingerprint = scenario_fingerprint("context.terminal");
    let terminal = scenario_terminal_with_provenance(
        "context.terminal",
        terminal_entry_id,
        terminal_transition_id,
        terminal_fingerprint,
        7,
        DID,
        DEVICE_ID,
        context3.clone(),
    )?;
    let intervals = vec![
        scenario_interval(
            1,
            opening.entry.transition_id(),
            opening.entry.outer_entry_fingerprint(),
            ApplicationIntervalOpeningKind::Creation,
            context0.clone(),
            Some((&reset, ApplicationIntervalClosingKind::Reset)),
        )?,
        scenario_interval(
            4,
            reset.entry.transition_id(),
            reset.entry.outer_entry_fingerprint(),
            ApplicationIntervalOpeningKind::Reset,
            context2.clone(),
            Some((&terminal, ApplicationIntervalClosingKind::Terminal)),
        )?,
    ];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let target = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0xb7),
    };
    let tracked = vec![("beforeTransition", target.clone())];
    let actors = vec![DID];
    let mut steps = Vec::new();
    let first = scenario_application_frame(
        transport,
        "context.first",
        uuid(0xb8),
        2,
        &ApplicationFrame {
            message_id: target.target_message_id,
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("before context transition".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &first,
        &tracked,
        &actors,
    ));
    let transition = scenario_context_transition(
        "context.transition",
        uuid(0xb9),
        3,
        context0.clone(),
        context1.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &transition,
        &tracked,
        &actors,
    ));
    let wrong_opening = scenario_opening_with_transition(
        "context.wrongOpeningId",
        uuid(0xba),
        scenario_transition_id("context.wrongOpeningId"),
        4,
        ApplicationIntervalOpeningKind::Reset,
        Some(ApplicationIntervalClosingKind::Reset),
        Some(context1.clone()),
        context2.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &wrong_opening,
        &tracked,
        &actors,
    ));
    let wrong_previous = scenario_opening_with_transition(
        "context.wrongPrevious",
        reset_entry_id,
        reset_transition_id,
        4,
        ApplicationIntervalOpeningKind::Reset,
        Some(ApplicationIntervalClosingKind::Reset),
        Some(context0.clone()),
        context2.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &wrong_previous,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &reset,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &reset,
        &tracked,
        &actors,
    ));
    let after_reset = scenario_application_frame(
        transport,
        "context.afterReset",
        uuid(0xbb),
        5,
        &ApplicationFrame {
            message_id: uuid(0xbc),
            context: context2.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("after reset".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &after_reset,
        &tracked,
        &actors,
    ));
    let mid_interval_opening = scenario_opening(
        "context.midIntervalOpening",
        uuid(0xbd),
        6,
        ApplicationIntervalOpeningKind::Add,
        None,
        context3.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &mid_interval_opening,
        &tracked,
        &actors,
    ));
    let mut foreign_previous = context2.clone();
    foreign_previous.conversation_id = uuid(0xbe);
    let mut foreign_next = context3.clone();
    foreign_next.conversation_id = foreign_previous.conversation_id;
    let cross_conversation = scenario_context_transition(
        "context.crossConversation",
        uuid(0xbf),
        6,
        foreign_previous,
        foreign_next,
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &cross_conversation,
        &tracked,
        &actors,
    ));
    let valid_second_transition = scenario_context_transition(
        "context.secondTransition",
        uuid(0xc0),
        6,
        context2.clone(),
        context3.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &valid_second_transition,
        &tracked,
        &actors,
    ));
    let mut terminal_cross_conversation = context3.clone();
    terminal_cross_conversation.conversation_id = uuid(0x41);
    let terminal_negatives = vec![
        scenario_terminal_with_provenance(
            "context.terminalWrongSeq",
            uuid(0x42),
            terminal_transition_id,
            terminal_fingerprint,
            8,
            DID,
            DEVICE_ID,
            context3.clone(),
        )?,
        scenario_terminal_with_provenance(
            "context.terminalWrongTransition",
            uuid(0x43),
            scenario_transition_id("context.terminalWrongTransition"),
            terminal_fingerprint,
            7,
            DID,
            DEVICE_ID,
            context3.clone(),
        )?,
        scenario_terminal_with_provenance(
            "context.terminalWrongFingerprint",
            uuid(0x44),
            terminal_transition_id,
            scenario_fingerprint("context.terminalWrongFingerprint"),
            7,
            DID,
            DEVICE_ID,
            context3.clone(),
        )?,
        scenario_terminal_with_provenance(
            "context.terminalWrongPrevious",
            uuid(0x45),
            terminal_transition_id,
            terminal_fingerprint,
            7,
            DID,
            DEVICE_ID,
            context2.clone(),
        )?,
        scenario_terminal_with_provenance(
            "context.terminalCrossConversation",
            uuid(0x46),
            terminal_transition_id,
            terminal_fingerprint,
            7,
            DID,
            DEVICE_ID,
            terminal_cross_conversation,
        )?,
        scenario_terminal_with_provenance(
            "context.terminalSiblingDevice",
            uuid(0x47),
            terminal_transition_id,
            terminal_fingerprint,
            7,
            DID,
            RECEIVER_DEVICE_ID,
            context3.clone(),
        )?,
        scenario_terminal_with_provenance(
            "context.terminalWrongDid",
            uuid(0x48),
            terminal_transition_id,
            terminal_fingerprint,
            7,
            FOREIGN_DID,
            DEVICE_ID,
            context3.clone(),
        )?,
    ];
    for wrong in &terminal_negatives {
        steps.push(scenario_control_step(
            &mut reducer,
            wrong,
            &tracked,
            &actors,
        ));
    }
    let terminal_kind_substitution = scenario_interval_closing_with_provenance(
        "context.terminalKindSubstitution",
        uuid(0x49),
        terminal_transition_id,
        terminal_fingerprint,
        7,
        DID,
        DEVICE_ID,
        ApplicationIntervalClosingKind::Reset,
        context3.clone(),
        context4,
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &terminal_kind_substitution,
        &tracked,
        &actors,
    ));
    let exact_terminal_step_index = steps.len();
    steps.push(scenario_control_step(
        &mut reducer,
        &terminal,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &terminal,
        &tracked,
        &actors,
    ));
    let conflicting_terminal_replay = scenario_terminal_with_provenance(
        "context.terminalConflictingReplay",
        terminal_entry_id,
        scenario_transition_id("context.terminalConflictingReplay"),
        terminal_fingerprint,
        7,
        DID,
        DEVICE_ID,
        context3.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &conflicting_terminal_replay,
        &tracked,
        &actors,
    ));
    let post_terminal = scenario_opening(
        "context.postTerminal",
        future_opening_entry_id,
        10,
        ApplicationIntervalOpeningKind::Add,
        None,
        advanced_context(&context0, 10),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &post_terminal,
        &tracked,
        &actors,
    ));
    assert_step_results(
        "contextTransitionResetAndTerminal",
        &steps,
        &[
            expected_ok_target("messageStored", &target),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_error("invalid_interval_opening", Some(4), None, None, None),
            expected_error("invalid_interval_opening", Some(4), None, None, None),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_ok_empty("exactReplay"),
            expected_ok_target(
                "messageStored",
                &MessageTarget {
                    target_seq: 5,
                    target_message_id: uuid(0xbc),
                },
            ),
            expected_error("invalid_interval_opening", Some(6), None, None, None),
            expected_error("context_mismatch", Some(6), None, None, None),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_error("invalid_interval_closing", Some(8), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_error("invalid_interval_closing", Some(7), None, None, None),
            expected_ok_empty("conversationTerminated"),
            expected_ok_empty("exactReplay"),
            expected_error("sequence_conflict", Some(7), None, None, None),
            expected_error("reducer_terminal", Some(10), None, None, None),
        ],
    );
    let terminal_state = &steps[exact_terminal_step_index]["expect"]["stateAfter"]["terminalProof"];
    assert_eq!(terminal_state["recipientDid"], DID);
    assert_eq!(terminal_state["recipientDeviceId"], DEVICE_ID);
    assert_eq!(
        terminal_state["conversationIdHex"],
        hex::encode(context0.conversation_id)
    );
    assert_eq!(terminal_state["entryIdHex"], hex::encode(terminal_entry_id));
    assert_eq!(terminal_state["seq"], 7);
    assert_eq!(
        terminal_state["transitionIdHex"],
        hex::encode(terminal_transition_id)
    );
    assert_eq!(
        terminal_state["outerEntryFingerprintHex"],
        hex::encode(terminal_fingerprint)
    );
    Ok(scenario_json(
        "contextTransitionResetAndTerminal",
        "conversation identity is immutable; every previous context equals expected before next; touching reset is consumed once; terminal close is permanent",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_non_touching_reanchor(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let context0 = context();
    let context3 = advanced_context(&context0, 3);
    let context10 = advanced_context(&context0, 10);
    let opening = scenario_opening(
        "reanchor.opening",
        uuid(0xc2),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        context0.clone(),
    )?;
    let reanchor_entry_id = uuid(0xc3);
    let reanchor_transition_id = scenario_transition_id("reanchor.valid");
    let reanchor_fingerprint = scenario_fingerprint("reanchor.valid");
    let close = scenario_interval_closing(
        "reanchor.close",
        uuid(0xc1),
        3,
        ApplicationIntervalClosingKind::Remove,
        context0.clone(),
        context3,
    )?;
    let intervals = vec![
        scenario_interval(
            1,
            opening.entry.transition_id(),
            opening.entry.outer_entry_fingerprint(),
            ApplicationIntervalOpeningKind::Creation,
            context0.clone(),
            Some((&close, ApplicationIntervalClosingKind::Remove)),
        )?,
        scenario_interval(
            10,
            reanchor_transition_id,
            reanchor_fingerprint,
            ApplicationIntervalOpeningKind::Add,
            context10.clone(),
            None,
        )?,
    ];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let before = MessageTarget {
        target_seq: 2,
        target_message_id: uuid(0xc4),
    };
    let after = MessageTarget {
        target_seq: 11,
        target_message_id: uuid(0xc5),
    };
    let tracked = vec![("beforeGap", before.clone()), ("afterGap", after.clone())];
    let actors = vec![DID];
    let mut steps = Vec::new();
    let before_app = scenario_application_frame(
        transport,
        "reanchor.before",
        uuid(0xc6),
        2,
        &ApplicationFrame {
            message_id: before.target_message_id,
            context: context0.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("before membership gap".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &before_app,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &close,
        &tracked,
        &actors,
    ));
    let wrong_openings = vec![
        scenario_opening_for_recipient(
            "reanchor.wrongSeq",
            uuid(0xc8),
            reanchor_transition_id,
            reanchor_fingerprint,
            11,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Add,
            None,
            None,
            context10.clone(),
        )?,
        scenario_opening_for_recipient(
            "reanchor.wrongKind",
            uuid(0xc9),
            reanchor_transition_id,
            reanchor_fingerprint,
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Creation,
            None,
            None,
            context10.clone(),
        )?,
        scenario_opening_for_recipient(
            "reanchor.wrongTransition",
            uuid(0xca),
            scenario_transition_id("reanchor.wrongTransition"),
            reanchor_fingerprint,
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Add,
            None,
            None,
            context10.clone(),
        )?,
        scenario_opening_for_recipient(
            "reanchor.wrongFingerprint",
            uuid(0xcb),
            reanchor_transition_id,
            scenario_fingerprint("reanchor.wrongFingerprint"),
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Add,
            None,
            None,
            context10.clone(),
        )?,
        scenario_opening_for_recipient(
            "reanchor.wrongContext",
            uuid(0xcc),
            reanchor_transition_id,
            reanchor_fingerprint,
            10,
            DID,
            DEVICE_ID,
            ApplicationIntervalOpeningKind::Add,
            None,
            None,
            advanced_context(&context0, 11),
        )?,
    ];
    for wrong in &wrong_openings {
        steps.push(scenario_control_step(
            &mut reducer,
            wrong,
            &tracked,
            &actors,
        ));
    }
    let reanchor = scenario_opening_for_recipient(
        "reanchor.valid",
        reanchor_entry_id,
        reanchor_transition_id,
        reanchor_fingerprint,
        10,
        DID,
        DEVICE_ID,
        ApplicationIntervalOpeningKind::Add,
        None,
        None,
        context10.clone(),
    )?;
    steps.push(scenario_control_step(
        &mut reducer,
        &reanchor,
        &tracked,
        &actors,
    ));
    steps.push(scenario_control_step(
        &mut reducer,
        &reanchor,
        &tracked,
        &actors,
    ));
    let after_app = scenario_application_frame(
        transport,
        "reanchor.after",
        uuid(0xc7),
        11,
        &ApplicationFrame {
            message_id: after.target_message_id,
            context: context10.clone(),
            body: ApplicationBody::Message(MessageBody {
                text: Some("after authenticated post-join opening".into()),
                reply_to: None,
                embed: None,
            }),
        },
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &after_app,
        &tracked,
        &actors,
    ));
    assert_step_results(
        "nonTouchingWelcomeReanchor",
        &steps,
        &[
            expected_ok_target("messageStored", &before),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_error("invalid_interval_opening", Some(11), None, None, None),
            expected_error("invalid_interval_opening", Some(10), None, None, None),
            expected_error("invalid_interval_opening", Some(10), None, None, None),
            expected_error("invalid_interval_opening", Some(10), None, None, None),
            expected_error("invalid_interval_opening", Some(10), None, None, None),
            expected_ok_empty("nonApplicationAdvanced"),
            expected_ok_empty("exactReplay"),
            expected_ok_target("messageStored", &after),
        ],
    );
    Ok(scenario_json(
        "nonTouchingWelcomeReanchor",
        "a non-touching post-membership gap opens only with the exact authenticated Add row and no invented previous context",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn reducer_opaque_rejected_retired(transport: &mut ApplicationTransportFixture) -> Result<Value> {
    let initial_context = context();
    let opening = scenario_opening(
        "storage.opening",
        uuid(0xc8),
        1,
        ApplicationIntervalOpeningKind::Creation,
        None,
        initial_context.clone(),
    )?;
    let intervals = vec![scenario_interval(
        1,
        opening.entry.transition_id(),
        opening.entry.outer_entry_fingerprint(),
        ApplicationIntervalOpeningKind::Creation,
        initial_context.clone(),
        None,
    )?];
    let mut reducer = ApplicationReducer::new(&opening.entry, intervals.clone())?;
    let original_target = MessageTarget {
        target_seq: 4,
        target_message_id: uuid(0xc9),
    };
    let tracked = vec![("original", original_target.clone())];
    let actors = vec![DID];
    let mut steps = Vec::new();
    let future = scenario_application_raw(
        transport,
        "storage.future",
        uuid(0xca),
        2,
        uuid(0xcb),
        initial_context.clone(),
        canonical_wrapper(2, Some(&[0xf5])),
        vec![],
        DID,
        DEVICE_ID,
        "exact",
        "unsupported",
        None,
        None,
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &future,
        &tracked,
        &actors,
    ));
    let malformed = scenario_application_raw(
        transport,
        "storage.rejected",
        uuid(0xcc),
        3,
        uuid(0xcd),
        initial_context.clone(),
        canonical_wrapper(1, Some(&[0xf6])),
        vec![],
        DID,
        DEVICE_ID,
        "exact",
        "rejected",
        Some("nullNotAllowed"),
        None,
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &malformed,
        &tracked,
        &actors,
    ));
    let original_frame = ApplicationFrame {
        message_id: original_target.target_message_id,
        context: initial_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("retirement anchor".into()),
            reply_to: None,
            embed: None,
        }),
    };
    let original_entry_id = uuid(0xce);
    let original = scenario_application_frame(
        transport,
        "storage.original",
        original_entry_id,
        4,
        &original_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &original,
        &tracked,
        &actors,
    ));
    let reused_entry_frame = ApplicationFrame {
        message_id: uuid(0xcf),
        context: initial_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("reused entry id".into()),
            reply_to: None,
            embed: None,
        }),
    };
    let reused_entry = scenario_application_frame(
        transport,
        "storage.reusedEntry",
        original_entry_id,
        5,
        &reused_entry_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &reused_entry,
        &tracked,
        &actors,
    ));
    let reused_message_frame = ApplicationFrame {
        message_id: original_target.target_message_id,
        context: initial_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("reused message id".into()),
            reply_to: None,
            embed: None,
        }),
    };
    let reused_message = scenario_application_frame(
        transport,
        "storage.reusedMessage",
        uuid(0xd8),
        5,
        &reused_message_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &reused_message,
        &tracked,
        &actors,
    ));
    let final_frame = ApplicationFrame {
        message_id: uuid(0xd9),
        context: initial_context.clone(),
        body: ApplicationBody::Message(MessageBody {
            text: Some("valid after retired-id probes".into()),
            reply_to: None,
            embed: None,
        }),
    };
    let final_app = scenario_application_frame(
        transport,
        "storage.final",
        uuid(0xda),
        5,
        &final_frame,
        vec![],
        DID,
        DEVICE_ID,
        "exact",
    )?;
    steps.push(scenario_application_step(
        &mut reducer,
        &final_app,
        &tracked,
        &actors,
    ));
    assert_step_results(
        "opaqueRejectedAndRetiredIdentifiers",
        &steps,
        &[
            expected_unsupported("blue.catbird.chat.application", 2),
            expected_rejection("nullNotAllowed"),
            expected_ok_target("messageStored", &original_target),
            expected_error(
                "retired_entry_id",
                None,
                None,
                Some(original_entry_id),
                None,
            ),
            expected_error(
                "retired_message_id",
                None,
                None,
                Some(original_target.target_message_id),
                None,
            ),
            expected_ok_target(
                "messageStored",
                &MessageTarget {
                    target_seq: 5,
                    target_message_id: uuid(0xd9),
                },
            ),
        ],
    );
    Ok(scenario_json(
        "opaqueRejectedAndRetiredIdentifiers",
        "unsupported and rejected rows advance durably while entry IDs and message IDs remain permanently retired",
        opening,
        &intervals,
        &tracked,
        &actors,
        steps,
    ))
}

fn advanced_context(base: &ConversationContext, marker: u64) -> ConversationContext {
    let mut context = base.clone();
    context.generation = base.generation + marker;
    context.state_version = base.state_version + marker;
    context.group_context_hash[0] ^= marker as u8;
    context.confirmation_tag[0] ^= marker as u8;
    context
}

fn scenario_fingerprint(label: &str) -> [u8; 32] {
    Sha256::digest(
        [
            b"CATBIRD-CHAT-SCENARIO-CONTROL\0".as_slice(),
            label.as_bytes(),
        ]
        .concat(),
    )
    .into()
}

fn scenario_transition_id(label: &str) -> [u8; 16] {
    let digest = Sha256::digest(
        [
            b"CATBIRD-CHAT-SCENARIO-TRANSITION\0".as_slice(),
            label.as_bytes(),
        ]
        .concat(),
    );
    let mut transition_id: [u8; 16] = digest[..16].try_into().unwrap();
    transition_id[6] = (transition_id[6] & 0x0f) | 0x40;
    transition_id[8] = (transition_id[8] & 0x3f) | 0x80;
    transition_id
}

fn scenario_opening(
    label: &str,
    entry_id: [u8; 16],
    seq: u64,
    kind: ApplicationIntervalOpeningKind,
    previous: Option<ConversationContext>,
    next: ConversationContext,
) -> Result<ScenarioControl> {
    scenario_opening_with_transition(
        label,
        entry_id,
        scenario_transition_id(label),
        seq,
        kind,
        None,
        previous,
        next,
    )
}

#[allow(clippy::too_many_arguments)]
fn scenario_opening_with_transition(
    label: &str,
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    seq: u64,
    kind: ApplicationIntervalOpeningKind,
    closing_kind: Option<ApplicationIntervalClosingKind>,
    previous: Option<ConversationContext>,
    next: ConversationContext,
) -> Result<ScenarioControl> {
    scenario_opening_for_recipient(
        label,
        entry_id,
        transition_id,
        scenario_fingerprint(label),
        seq,
        DID,
        DEVICE_ID,
        kind,
        closing_kind,
        previous,
        next,
    )
}

#[allow(clippy::too_many_arguments)]
fn scenario_opening_for_recipient(
    _label: &str,
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    fingerprint: [u8; 32],
    seq: u64,
    recipient_did: &str,
    recipient_device_id: &str,
    kind: ApplicationIntervalOpeningKind,
    closing_kind: Option<ApplicationIntervalClosingKind>,
    previous: Option<ConversationContext>,
    next: ConversationContext,
) -> Result<ScenarioControl> {
    let entry = VerifiedApplicationControlEntry::test_only_interval_opening(
        entry_id,
        transition_id,
        seq,
        fingerprint,
        recipient_did.into(),
        recipient_device_id.into(),
        kind,
        closing_kind,
        previous.clone(),
        next.clone(),
    )?;
    Ok(ScenarioControl {
        fixture: json!({
            "kind": "intervalOpening",
            "entryIdHex": hex::encode(entry_id),
            "transitionIdHex": hex::encode(transition_id),
            "seq": seq,
            "outerEntryFingerprintHex": hex::encode(fingerprint),
            "recipientDid": recipient_did,
            "recipientDeviceId": recipient_device_id,
            "openingKind": interval_kind_name(kind),
            "closingKind": closing_kind.map(interval_closing_kind_name),
            "previous": previous.as_ref().map(context_value),
            "next": context_value(&next),
        }),
        entry,
    })
}

fn scenario_context_transition(
    label: &str,
    entry_id: [u8; 16],
    seq: u64,
    previous: ConversationContext,
    next: ConversationContext,
) -> Result<ScenarioControl> {
    let fingerprint = scenario_fingerprint(label);
    let transition_id = scenario_transition_id(label);
    let entry = VerifiedApplicationControlEntry::test_only_context_transition(
        entry_id,
        transition_id,
        seq,
        fingerprint,
        previous.clone(),
        next.clone(),
    )?;
    Ok(ScenarioControl {
        fixture: json!({
            "kind": "contextTransition",
            "entryIdHex": hex::encode(entry_id),
            "transitionIdHex": hex::encode(transition_id),
            "seq": seq,
            "outerEntryFingerprintHex": hex::encode(fingerprint),
            "previous": context_value(&previous),
            "next": context_value(&next),
        }),
        entry,
    })
}

fn scenario_interval_closing(
    label: &str,
    entry_id: [u8; 16],
    seq: u64,
    kind: ApplicationIntervalClosingKind,
    previous: ConversationContext,
    next: ConversationContext,
) -> Result<ScenarioControl> {
    let fingerprint = scenario_fingerprint(label);
    let transition_id = scenario_transition_id(label);
    scenario_interval_closing_with_provenance(
        label,
        entry_id,
        transition_id,
        fingerprint,
        seq,
        DID,
        DEVICE_ID,
        kind,
        previous,
        next,
    )
}

#[allow(clippy::too_many_arguments)]
fn scenario_interval_closing_with_provenance(
    _label: &str,
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    fingerprint: [u8; 32],
    seq: u64,
    recipient_did: &str,
    recipient_device_id: &str,
    kind: ApplicationIntervalClosingKind,
    previous: ConversationContext,
    next: ConversationContext,
) -> Result<ScenarioControl> {
    let entry = VerifiedApplicationControlEntry::test_only_interval_closing(
        entry_id,
        transition_id,
        seq,
        fingerprint,
        recipient_did.into(),
        recipient_device_id.into(),
        kind,
        previous.clone(),
        next.clone(),
    )?;
    Ok(ScenarioControl {
        fixture: json!({
            "kind": "intervalClosing",
            "entryIdHex": hex::encode(entry_id),
            "transitionIdHex": hex::encode(transition_id),
            "seq": seq,
            "outerEntryFingerprintHex": hex::encode(fingerprint),
            "recipientDid": recipient_did,
            "recipientDeviceId": recipient_device_id,
            "closingKind": interval_closing_kind_name(kind),
            "previous": context_value(&previous),
            "next": context_value(&next),
        }),
        entry,
    })
}

fn scenario_terminal(
    label: &str,
    entry_id: [u8; 16],
    seq: u64,
    previous: ConversationContext,
) -> Result<ScenarioControl> {
    scenario_terminal_with_provenance(
        label,
        entry_id,
        scenario_transition_id(label),
        scenario_fingerprint(label),
        seq,
        DID,
        DEVICE_ID,
        previous,
    )
}

#[allow(clippy::too_many_arguments)]
fn scenario_terminal_with_provenance(
    _label: &str,
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    fingerprint: [u8; 32],
    seq: u64,
    recipient_did: &str,
    recipient_device_id: &str,
    previous: ConversationContext,
) -> Result<ScenarioControl> {
    let entry = VerifiedApplicationControlEntry::test_only_terminal(
        entry_id,
        transition_id,
        seq,
        fingerprint,
        recipient_did.into(),
        recipient_device_id.into(),
        previous.clone(),
    )?;
    Ok(ScenarioControl {
        fixture: json!({
            "kind": "terminal",
            "entryIdHex": hex::encode(entry_id),
            "transitionIdHex": hex::encode(transition_id),
            "seq": seq,
            "outerEntryFingerprintHex": hex::encode(fingerprint),
            "recipientDid": recipient_did,
            "recipientDeviceId": recipient_device_id,
            "previous": context_value(&previous),
        }),
        entry,
    })
}

fn scenario_interval(
    start_seq: u64,
    opening_transition_id: [u8; 16],
    opening_outer_entry_fingerprint: [u8; 32],
    opening_kind: ApplicationIntervalOpeningKind,
    opening_context: ConversationContext,
    closing: Option<(&ScenarioControl, ApplicationIntervalClosingKind)>,
) -> Result<ApplicationAccessInterval> {
    let closing = closing
        .map(|(control, kind)| {
            ApplicationIntervalClosingProof::test_only(
                control.entry.seq(),
                control.entry.transition_id(),
                control.entry.outer_entry_fingerprint(),
                kind,
            )
        })
        .transpose()?;
    Ok(ApplicationAccessInterval::test_only(
        DID.into(),
        DEVICE_ID.into(),
        start_seq,
        opening_transition_id,
        opening_outer_entry_fingerprint,
        opening_kind,
        opening_context,
        closing,
    )?)
}

fn interval_kind_name(kind: ApplicationIntervalOpeningKind) -> &'static str {
    match kind {
        ApplicationIntervalOpeningKind::Creation => "creation",
        ApplicationIntervalOpeningKind::Add => "add",
        ApplicationIntervalOpeningKind::Reset => "reset",
    }
}

fn interval_closing_kind_name(kind: ApplicationIntervalClosingKind) -> &'static str {
    match kind {
        ApplicationIntervalClosingKind::Remove => "remove",
        ApplicationIntervalClosingKind::Replace => "replace",
        ApplicationIntervalClosingKind::Reset => "reset",
        ApplicationIntervalClosingKind::Terminal => "terminal",
    }
}

#[allow(clippy::too_many_arguments)]
fn scenario_application_frame(
    transport: &mut ApplicationTransportFixture,
    label: &str,
    entry_id: [u8; 16],
    seq: u64,
    frame: &ApplicationFrame,
    outer: Vec<CorpusOuterBlobBinding>,
    actor_did: &str,
    actor_device_id: &str,
    sender_mode: &str,
) -> Result<ScenarioApplication> {
    let body_tag = match &frame.body {
        ApplicationBody::Message(_) => "message",
        ApplicationBody::Reaction(_) => "reaction",
        ApplicationBody::Edit(_) => "edit",
        ApplicationBody::Tombstone(_) => "tombstone",
        ApplicationBody::ReadState(_) => "readState",
    };
    scenario_application_raw(
        transport,
        label,
        entry_id,
        seq,
        frame.message_id,
        frame.context.clone(),
        encode_application_content(frame)?,
        outer,
        actor_did,
        actor_device_id,
        sender_mode,
        "supported",
        None,
        Some(body_tag),
    )
}

#[allow(clippy::too_many_arguments)]
fn scenario_application_raw(
    transport: &mut ApplicationTransportFixture,
    label: &str,
    entry_id: [u8; 16],
    seq: u64,
    message_id: [u8; 16],
    prior: ConversationContext,
    raw: Vec<u8>,
    outer: Vec<CorpusOuterBlobBinding>,
    actor_did: &str,
    actor_device_id: &str,
    sender_mode: &str,
    expected_disposition: &str,
    expected_reason: Option<&str>,
    body_tag: Option<&str>,
) -> Result<ScenarioApplication> {
    let transported =
        transport.encrypt_and_receive(actor_did, actor_device_id, message_id, &prior, &raw)?;
    let signed_outer = signed_application_fixture(
        entry_id,
        seq,
        message_id,
        prior,
        actor_did,
        actor_device_id,
        &outer,
        transported.application_message,
        &fixture_signing_key(actor_device_id)?,
    )?;
    let entry_cbor = hex::decode(
        signed_outer.json["applicationEntryCborHex"]
            .as_str()
            .ok_or("scenario application entry CBOR")?,
    )?;
    let registration = fixture_registration(actor_did, actor_device_id)?;
    let verified_outer = verify_application_outer_entry(&entry_cbor, &registration)?;
    if verified_outer.entry_id() != entry_id
        || verified_outer.seq() != seq
        || verified_outer.fingerprint() != signed_outer.fingerprint
    {
        return Err(format!("scenario {label} outer evidence mismatch").into());
    }
    if actor_did != DID && actor_did != FOREIGN_DID {
        return Err(format!("unknown fixture actor DID {actor_did}").into());
    }
    if sender_mode != "exact" {
        return Err(format!("receiver-backed scenario {label} has non-exact sender mode").into());
    }
    let disposition = ingest_application_content(raw.clone(), &verified_outer, &transported.sender);
    let (actual_disposition, actual_reason) = match &disposition {
        ApplicationContentDisposition::Supported(_) => ("supported", None),
        ApplicationContentDisposition::Unsupported(_) => ("unsupported", None),
        ApplicationContentDisposition::Rejected(rejected) => {
            ("rejected", Some(rejected.error().reason.code()))
        }
    };
    if actual_disposition != expected_disposition || actual_reason != expected_reason {
        return Err(format!(
            "scenario application {label} expected {expected_disposition}/{expected_reason:?}, got {actual_disposition}/{actual_reason:?}"
        )
        .into());
    }
    let mut fixture = json!({
        "name": label,
        "messageIdHex": hex::encode(message_id),
        "cborHex": hex::encode(&raw),
        "length": raw.len(),
        "sha256Hex": sha256(&raw),
        "outerBlobBindings": outer.iter().map(outer_json).collect::<Vec<_>>(),
        "signedOuterEntry": signed_outer.json,
        "outerEntryFingerprintHex": hex::encode(signed_outer.fingerprint),
        "transportEvidence": transported.evidence,
        "senderMode": sender_mode,
        "expectedDisposition": expected_disposition,
        "expectedReason": expected_reason,
    });
    if let Some(body_tag) = body_tag {
        fixture
            .as_object_mut()
            .unwrap()
            .insert("expectedBodyTag".into(), json!(body_tag));
    }
    Ok(ScenarioApplication {
        fixture,
        disposition,
    })
}

fn scenario_application_step(
    reducer: &mut ApplicationReducer,
    application: &ScenarioApplication,
    tracked: &[(&str, MessageTarget)],
    actors: &[&str],
) -> Value {
    let state_before = reducer_state(reducer, tracked, actors);
    let result = reducer_result(
        reducer.apply(&application.disposition),
        disposition_operation_target(&application.disposition),
    );
    let state_after = reducer_state(reducer, tracked, actors);
    assert_unchanged_on_error_or_replay(&result, &state_before, &state_after);
    json!({
        "op": "application",
        "application": application.fixture,
        "expect": {
            "result": result,
            "stateBefore": state_before,
            "stateAfter": state_after,
        },
    })
}

fn scenario_control_step(
    reducer: &mut ApplicationReducer,
    control: &ScenarioControl,
    tracked: &[(&str, MessageTarget)],
    actors: &[&str],
) -> Value {
    let state_before = reducer_state(reducer, tracked, actors);
    let result = reducer_result(reducer.advance_non_application(&control.entry), None);
    let state_after = reducer_state(reducer, tracked, actors);
    assert_unchanged_on_error_or_replay(&result, &state_before, &state_after);
    json!({
        "op": "control",
        "control": control.fixture,
        "expect": {
            "result": result,
            "stateBefore": state_before,
            "stateAfter": state_after,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn scenario_invalid_opening_construction_step(
    reducer: &ApplicationReducer,
    label: &str,
    entry_id: [u8; 16],
    transition_id: [u8; 16],
    fingerprint: [u8; 32],
    seq: u64,
    recipient_did: &str,
    recipient_device_id: &str,
    opening_kind: ApplicationIntervalOpeningKind,
    closing_kind: Option<ApplicationIntervalClosingKind>,
    previous: Option<ConversationContext>,
    next: ConversationContext,
    tracked: &[(&str, MessageTarget)],
    actors: &[&str],
) -> Result<Value> {
    let state_before = reducer_state(reducer, tracked, actors);
    let error = VerifiedApplicationControlEntry::test_only_interval_opening(
        entry_id,
        transition_id,
        seq,
        fingerprint,
        recipient_did.into(),
        recipient_device_id.into(),
        opening_kind,
        closing_kind,
        previous.clone(),
        next.clone(),
    )
    .expect_err("invalid opening-kind candidate unexpectedly constructed");
    let result = reducer_result(
        std::result::Result::<ReducerOutcome, ReducerError>::Err(error),
        None,
    );
    let expected = expected_error("invalid_interval_opening", Some(seq), None, None, None);
    if result != expected {
        return Err(format!("construction candidate {label} returned {result}").into());
    }
    let state_after = reducer_state(reducer, tracked, actors);
    assert_eq!(
        state_before, state_after,
        "rejected control construction must not mutate reducer state"
    );
    Ok(json!({
        "op": "controlConstructionRejected",
        "controlCandidate": {
            "kind": "intervalOpening",
            "entryIdHex": hex::encode(entry_id),
            "transitionIdHex": hex::encode(transition_id),
            "seq": seq,
            "outerEntryFingerprintHex": hex::encode(fingerprint),
            "recipientDid": recipient_did,
            "recipientDeviceId": recipient_device_id,
            "openingKind": interval_kind_name(opening_kind),
            "closingKind": closing_kind.map(interval_closing_kind_name),
            "previous": previous.as_ref().map(context_value),
            "next": context_value(&next),
        },
        "validationLayer": "verifiedControlConstruction",
        "expect": {
            "result": expected,
            "stateBefore": state_before,
            "stateAfter": state_after,
        },
    }))
}

fn scenario_corrupt_remove_original_step(
    reducer: &mut ApplicationReducer,
    target: &MessageTarget,
    tracked: &[(&str, MessageTarget)],
    actors: &[&str],
) -> Value {
    let state_before = reducer_state(reducer, tracked, actors);
    assert!(reducer.test_only_remove_stored_original(target));
    let state_after = reducer_state(reducer, tracked, actors);
    assert_ne!(state_before, state_after);
    json!({
        "op": "testCorruptionRemoveStoredOriginal",
        "target": target_value(target),
        "expect": {
            "result": {
                "status": "ok",
                "code": "storedOriginalRemoved",
                "detail": { "target": target_value(target) },
            },
            "stateBefore": state_before,
            "stateAfter": state_after,
        },
    })
}

fn assert_unchanged_on_error_or_replay(result: &Value, before: &Value, after: &Value) {
    if result["status"] == "error" || result["code"] == "exactReplay" {
        assert_eq!(
            before, after,
            "reducer errors and exact replays must preserve the complete structural snapshot"
        );
    }
}

fn assert_step_results(scenario: &str, steps: &[Value], expected: &[Value]) {
    assert_eq!(
        steps.len(),
        expected.len(),
        "hand-authored result count changed for {scenario}"
    );
    for (index, (step, expected_result)) in steps.iter().zip(expected).enumerate() {
        assert_eq!(
            step["expect"]["result"], *expected_result,
            "unexpected complete result for {scenario} step {index}"
        );
    }
}

fn expected_ok_empty(code: &str) -> Value {
    json!({ "status": "ok", "code": code, "detail": {} })
}

fn expected_ok_target(code: &str, target: &MessageTarget) -> Value {
    json!({
        "status": "ok",
        "code": code,
        "detail": { "target": target_value(target) },
    })
}

fn expected_ok_frontier(code: &str, target: &MessageTarget) -> Value {
    json!({
        "status": "ok",
        "code": code,
        "detail": { "frontier": target_value(target) },
    })
}

fn expected_noop(reason: &str, target: &MessageTarget) -> Value {
    json!({
        "status": "ok",
        "code": "terminalNoOp",
        "detail": { "reason": reason, "target": target_value(target) },
    })
}

fn expected_error(
    code: &str,
    seq: Option<u64>,
    expected_seq: Option<u64>,
    identifier: Option<[u8; 16]>,
    target: Option<&MessageTarget>,
) -> Value {
    json!({
        "status": "error",
        "code": code,
        "seq": seq,
        "expectedSeq": expected_seq,
        "identifierHex": identifier.map(hex::encode),
        "target": target.map(target_value),
    })
}

fn expected_unsupported(protocol: &str, version: u64) -> Value {
    json!({
        "status": "ok",
        "code": "unsupportedStored",
        "detail": { "protocol": protocol, "version": version },
    })
}

fn expected_rejection(reason: &str) -> Value {
    json!({
        "status": "ok",
        "code": "rejectionStored",
        "detail": { "reason": reason },
    })
}

fn reducer_result(
    result: std::result::Result<ReducerOutcome, ReducerError>,
    operation_target: Option<MessageTarget>,
) -> Value {
    match result {
        Ok(outcome) => json!({
            "status": "ok",
            "code": reducer_outcome_name(&outcome),
            "detail": reducer_outcome_detail(&outcome, operation_target.as_ref()),
        }),
        Err(error) => json!({
            "status": "error",
            "code": error.code(),
            "seq": error.seq(),
            "expectedSeq": error.expected_seq(),
            "identifierHex": error.identifier().map(hex::encode),
            "target": error.target().map(target_value),
        }),
    }
}

fn reducer_outcome_detail(
    outcome: &ReducerOutcome,
    operation_target: Option<&MessageTarget>,
) -> Value {
    match outcome {
        ReducerOutcome::MessageStored { target }
        | ReducerOutcome::EditApplied { target }
        | ReducerOutcome::ReactionApplied { target }
        | ReducerOutcome::TombstoneApplied { target } => json!({
            "target": target_value(target),
        }),
        ReducerOutcome::ReadStateAdvanced { frontier }
        | ReducerOutcome::ReadStateUnchanged { frontier } => json!({
            "frontier": target_value(frontier),
        }),
        ReducerOutcome::TerminalNoOp { reason } => json!({
            "reason": reason.code(),
            "target": operation_target.map(target_value),
        }),
        ReducerOutcome::UnsupportedStored { protocol, version } => json!({
            "protocol": protocol,
            "version": version,
        }),
        ReducerOutcome::RejectionStored { reason } => json!({
            "reason": reason.code(),
        }),
        ReducerOutcome::NonApplicationAdvanced
        | ReducerOutcome::ConversationTerminated
        | ReducerOutcome::ExactReplay => json!({}),
    }
}

fn disposition_operation_target(
    disposition: &ApplicationContentDisposition,
) -> Option<MessageTarget> {
    let ApplicationContentDisposition::Supported(content) = disposition else {
        return None;
    };
    match &content.frame().body {
        ApplicationBody::Message(message) => message.reply_to.clone(),
        ApplicationBody::Reaction(reaction) => Some(reaction.target.clone()),
        ApplicationBody::Edit(edit) => Some(edit.target.clone()),
        ApplicationBody::Tombstone(tombstone) => Some(tombstone.target.clone()),
        ApplicationBody::ReadState(read) => Some(MessageTarget {
            target_seq: read.through_seq,
            target_message_id: read.through_message_id,
        }),
    }
}

fn reducer_outcome_name(outcome: &ReducerOutcome) -> &'static str {
    match outcome {
        ReducerOutcome::MessageStored { .. } => "messageStored",
        ReducerOutcome::EditApplied { .. } => "editApplied",
        ReducerOutcome::ReactionApplied { .. } => "reactionApplied",
        ReducerOutcome::TombstoneApplied { .. } => "tombstoneApplied",
        ReducerOutcome::ReadStateAdvanced { .. } => "readStateAdvanced",
        ReducerOutcome::ReadStateUnchanged { .. } => "readStateUnchanged",
        ReducerOutcome::TerminalNoOp { .. } => "terminalNoOp",
        ReducerOutcome::UnsupportedStored { .. } => "unsupportedStored",
        ReducerOutcome::RejectionStored { .. } => "rejectionStored",
        ReducerOutcome::NonApplicationAdvanced => "nonApplicationAdvanced",
        ReducerOutcome::ConversationTerminated => "conversationTerminated",
        ReducerOutcome::ExactReplay => "exactReplay",
    }
}

fn scenario_json(
    name: &str,
    invariant: &str,
    opening: ScenarioControl,
    intervals: &[ApplicationAccessInterval],
    tracked: &[(&str, MessageTarget)],
    actors: &[&str],
    steps: Vec<Value>,
) -> Value {
    let initial_reducer = ApplicationReducer::new(&opening.entry, intervals.to_vec())
        .expect("already-validated scenario reducer initialization");
    json!({
        "name": name,
        "invariant": invariant,
        "trackedMessages": tracked.iter().map(|(label, target)| json!({
            "name": label,
            "target": target_value(target),
        })).collect::<Vec<_>>(),
        "readActors": actors,
        "initial": {
            "opening": opening.fixture,
            "accessIntervals": intervals.iter().map(interval_value).collect::<Vec<_>>(),
            "state": reducer_state(&initial_reducer, tracked, actors),
        },
        "steps": steps,
        "finalState": steps.last().map(|step| step["expect"]["stateAfter"].clone())
            .unwrap_or_else(|| reducer_state(&initial_reducer, tracked, actors)),
    })
}

fn interval_value(interval: &ApplicationAccessInterval) -> Value {
    json!({
        "recipientDid": interval.recipient_did(),
        "recipientDeviceId": interval.recipient_device_id(),
        "startSeq": interval.start_seq(),
        "endSeq": interval.end_seq(),
        "openingTransitionIdHex": hex::encode(interval.opening_transition_id()),
        "openingOuterEntryFingerprintHex": hex::encode(interval.opening_outer_entry_fingerprint()),
        "openingKind": interval_kind_name(interval.opening_kind()),
        "openingContext": context_value(interval.opening_context()),
        "closing": interval.closing().map(|closing| json!({
            "seq": closing.seq(),
            "transitionIdHex": hex::encode(closing.transition_id()),
            "outerEntryFingerprintHex": hex::encode(closing.outer_entry_fingerprint()),
            "kind": interval_closing_kind_name(closing.kind()),
        })),
    })
}

fn target_value(target: &MessageTarget) -> Value {
    json!({
        "targetSeq": target.target_seq,
        "targetMessageIdHex": hex::encode(target.target_message_id),
    })
}

fn context_value(context: &ConversationContext) -> Value {
    json!({
        "conversationIdHex": hex::encode(context.conversation_id),
        "generation": context.generation,
        "stateVersion": context.state_version,
        "groupIdHex": hex::encode(context.group_id),
        "epoch": context.epoch,
        "groupContextHashHex": hex::encode(context.group_context_hash),
        "confirmationTagHex": hex::encode(context.confirmation_tag),
        "lifecycle": "active",
    })
}

fn reducer_state(
    reducer: &ApplicationReducer,
    _tracked: &[(&str, MessageTarget)],
    _actors: &[&str],
) -> Value {
    let snapshot = reducer.test_only_snapshot();
    json!({
        "conversationIdHex": hex::encode(snapshot.conversation_id),
        "recipientDid": snapshot.recipient_did,
        "recipientDeviceId": snapshot.recipient_device_id,
        "expectedContext": snapshot.expected_context.as_ref().map(context_value),
        "terminalProof": snapshot.terminal_proof.map(|proof| json!({
            "recipientDid": proof.recipient_did,
            "recipientDeviceId": proof.recipient_device_id,
            "conversationIdHex": hex::encode(proof.conversation_id),
            "entryIdHex": hex::encode(proof.entry_id),
            "seq": proof.seq,
            "transitionIdHex": hex::encode(proof.transition_id),
            "outerEntryFingerprintHex": hex::encode(proof.outer_entry_fingerprint),
            "dispositionIntegrityHex": hex::encode(proof.disposition_integrity),
        })),
        "accessIntervals": snapshot.access_intervals.into_iter().map(|interval| json!({
            "recipientDid": interval.recipient_did,
            "recipientDeviceId": interval.recipient_device_id,
            "startSeq": interval.start_seq,
            "openingTransitionIdHex": hex::encode(interval.opening_transition_id),
            "openingOuterEntryFingerprintHex": hex::encode(interval.opening_outer_entry_fingerprint),
            "openingKind": interval_kind_name(interval.opening_kind),
            "openingContext": context_value(&interval.opening_context),
            "closing": interval.closing.map(|closing| json!({
                "seq": closing.seq,
                "transitionIdHex": hex::encode(closing.transition_id),
                "outerEntryFingerprintHex": hex::encode(closing.outer_entry_fingerprint),
                "kind": interval_closing_kind_name(closing.kind),
            })),
        })).collect::<Vec<_>>(),
        "afterSeq": snapshot.after_seq,
        "processed": snapshot.processed.into_iter().map(|entry| json!({
            "seq": entry.seq,
            "entryIdHex": hex::encode(entry.entry_id),
            "outerEntryFingerprintHex": hex::encode(entry.outer_entry_fingerprint),
            "dispositionIntegrityHex": hex::encode(entry.disposition_integrity),
        })).collect::<Vec<_>>(),
        "seenEntryIds": snapshot.seen_entry_ids.into_iter().map(|entry| json!({
            "identifierHex": hex::encode(entry.identifier),
            "seq": entry.seq,
        })).collect::<Vec<_>>(),
        "seenMessageIds": snapshot.seen_message_ids.into_iter().map(|entry| json!({
            "identifierHex": hex::encode(entry.identifier),
            "seq": entry.seq,
        })).collect::<Vec<_>>(),
        "originalsBySeq": snapshot.originals_by_seq.into_iter().map(|entry| json!({
            "seq": entry.seq,
            "messageIdHex": hex::encode(entry.message_id),
        })).collect::<Vec<_>>(),
        "messages": snapshot.messages.into_iter().map(|message| {
            let reply_presentation = match &message.reply_presentation {
                ReplyPresentation::None => json!({"kind": "none"}),
                ReplyPresentation::Available(target) => json!({
                    "kind": "available", "target": target_value(target),
                }),
                ReplyPresentation::DeletedMessageStub(target) => json!({
                    "kind": "deletedMessageStub", "target": target_value(target),
                }),
                ReplyPresentation::UnavailableMessageStub(target) => json!({
                    "kind": "unavailableMessageStub", "target": target_value(target),
                }),
            };
            json!({
                "storageSeq": message.storage_seq,
                "storageMessageIdHex": hex::encode(message.storage_message_id),
                "target": target_value(&message.target),
                "authorDid": message.author_did,
                "authorDeviceId": message.author_device_id,
                "text": message.text,
                "replyTo": message.reply_to.as_ref().map(target_value),
                "embed": message.embed.as_ref().map(|embed| serde_json::to_value(embed).expect("embed JSON")),
                "replyPresentation": reply_presentation,
                "tombstoned": message.tombstoned,
                "lastEditSeq": message.last_edit_seq,
                "reactions": message.reactions.into_iter().map(|reaction| json!({
                    "actorDid": reaction.actor_did,
                    "emoji": reaction.emoji,
                    "operation": match reaction.operation {
                        ReactionOperation::Add => "add",
                        ReactionOperation::Remove => "remove",
                    },
                    "seq": reaction.seq,
                })).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "readFrontiers": snapshot.read_frontiers.into_iter().map(|frontier| json!({
            "actorDid": frontier.actor_did,
            "target": target_value(&frontier.target),
        })).collect::<Vec<_>>(),
    })
}

#[allow(clippy::too_many_arguments)]
fn signed_application_fixture(
    entry_id: [u8; 16],
    seq: u64,
    message_id: [u8; 16],
    prior: ConversationContext,
    actor_did: &str,
    actor_device_id: &str,
    blob_bindings: &[CorpusOuterBlobBinding],
    application_message_bytes: Vec<u8>,
    signing_key: &SigningKey,
) -> Result<SignedApplicationFixture> {
    let actor_device_id = *uuid::Uuid::parse_str(actor_device_id)?.as_bytes();
    let application_message_sha256: [u8; 32] = Sha256::digest(&application_message_bytes).into();
    let body = CorpusApplicationSendBody {
        type_id: APPLICATION_SEND_BODY_TYPE.into(),
        signature_domain: String::from_utf8(MESSAGE_SIGNATURE_DOMAIN.to_vec())?,
        message_id,
        actor_did: actor_did.into(),
        actor_device_id,
        key_id: fixture_key_id(&signing_key.verifying_key().to_bytes()),
        auth_generation: 1,
        prior: prior.clone(),
        aad: CorpusApplicationAad {
            protocol_version: "1".into(),
            conversation_id: prior.conversation_id,
            generation: prior.generation,
            message_id,
            prior: prior.clone(),
        },
        application_message: CorpusPrivateApplicationMessage {
            framing: "mlsMessage".into(),
            content_type: "privateMessageApplication".into(),
            bytes: application_message_bytes,
            sha256: application_message_sha256,
        },
        blob_bindings: blob_bindings.to_vec(),
        signed_at: SIGNED_AT.into(),
    };
    let unsigned_projection_cbor = serde_ipld_dagcbor::to_vec(&body)?;
    let mut signing_transcript = MESSAGE_SIGNATURE_DOMAIN.to_vec();
    signing_transcript.extend_from_slice(&unsigned_projection_cbor);
    let signature = signing_key.sign(&signing_transcript).to_bytes();
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript).into();
    let entry = CorpusApplicationEntry {
        entry_id,
        conversation_id: prior.conversation_id,
        seq,
        signed_request: CorpusSignedApplicationSend { body, signature },
        received_at: RECEIVED_AT.into(),
    };
    if entry.conversation_id != entry.signed_request.body.prior.conversation_id {
        return Err("entry conversationId does not match signed prior".into());
    }
    let entry_cbor = serde_ipld_dagcbor::to_vec(&entry)?;
    let fingerprint_projection = CorpusApplicationEntryFingerprintProjection {
        entry_id,
        conversation_id: entry.conversation_id,
        seq,
        request_digest,
        signature,
        received_at: entry.received_at.clone(),
    };
    let fingerprint_projection_cbor = serde_ipld_dagcbor::to_vec(&fingerprint_projection)?;
    let mut hasher = Sha256::new();
    hasher.update(APPLICATION_ENTRY_FINGERPRINT_DOMAIN);
    hasher.update(&fingerprint_projection_cbor);
    let fingerprint = hasher.finalize().into();
    let json = json!({
        "signatureAlgorithm": "Ed25519",
        "messageSignatureDomainHex": hex::encode(MESSAGE_SIGNATURE_DOMAIN),
        "applicationEntryFingerprintDomainHex": hex::encode(APPLICATION_ENTRY_FINGERPRINT_DOMAIN),
        "applicationEntryCborHex": hex::encode(&entry_cbor),
        "applicationEntryCborSha256Hex": sha256(&entry_cbor),
        "unsignedSendProjectionCborHex": hex::encode(&unsigned_projection_cbor),
        "signingTranscriptHex": hex::encode(&signing_transcript),
        "requestDigestHex": hex::encode(request_digest),
        "fingerprintProjectionCborHex": hex::encode(&fingerprint_projection_cbor),
        "fingerprintHex": hex::encode(fingerprint),
    });
    Ok(SignedApplicationFixture {
        entry,
        fingerprint,
        json,
    })
}

fn signed_former_device_terminal_fixture(
    contract_source: &CapturedProvenanceFile,
) -> Result<SignedControlEnvelopeFixture> {
    let contract: Value = serde_json::from_slice(&contract_source.bytes)?;
    let case = contract["controlEntryFingerprints"]["cases"]
        .as_array()
        .ok_or("contract fixture lacks control-entry cases")?
        .iter()
        .find(|case| case["entryKind"] == CONVERSATION_CLOSE_ENTRY_TYPE)
        .ok_or("contract fixture lacks conversationCloseEntry case")?;
    let contract_unsigned_projection_cbor = hex::decode(
        case["unsignedSigningProjectionCanonicalDagCborHex"]
            .as_str()
            .ok_or("conversationCloseEntry case lacks unsigned projection")?,
    )?;
    let body: CorpusConversationCloseBody =
        serde_ipld_dagcbor::from_slice(&contract_unsigned_projection_cbor)?;
    if serde_ipld_dagcbor::to_vec(&body)? != contract_unsigned_projection_cbor {
        return Err("server Terminal body golden is not canonical round-trip stable".into());
    }
    let contract_projection_cbor = hex::decode(
        case["canonicalDagCborHex"]
            .as_str()
            .ok_or("conversationCloseEntry case lacks fingerprint projection")?,
    )?;
    let contract_projection: CorpusControlEntryFingerprintProjection =
        serde_ipld_dagcbor::from_slice(&contract_projection_cbor)?;
    if serde_ipld_dagcbor::to_vec(&contract_projection)? != contract_projection_cbor {
        return Err("server Terminal fingerprint golden is not canonical round-trip stable".into());
    }
    let prior_context = conversation_context_from_control_coordinates(&body.prior)?;
    let entry_id = contract_projection.entry_id;
    let transition_id = body.transition_id;
    let seq = contract_projection.seq;
    let actor_device_id = body.actor_device_id;
    let terminal_recipient_device_id = *uuid::Uuid::parse_str(DEVICE_ID)?.as_bytes();
    let signing_key = fixture_signing_key(RECEIVER_DEVICE_ID)?;
    if actor_device_id == terminal_recipient_device_id
        || signing_key.verifying_key().to_bytes() == signature_public_key()
        || transition_id != scenario_transition_id("terminalAfterRemove.terminal")
        || entry_id != uuid(0x66)
        || seq != 10
        || body.actor_did != RECEIVER_DID
        || body.actor_device_id != *uuid::Uuid::parse_str(RECEIVER_DEVICE_ID)?.as_bytes()
        || body.type_id != CONVERSATION_CLOSE_BODY_TYPE
        || body.signature_domain != String::from_utf8(CONVERSATION_CLOSE_SIGNATURE_DOMAIN.to_vec())?
    {
        return Err(
            "server Terminal golden does not match former-device scenario coordinates".into(),
        );
    }
    let unsigned_projection_cbor = serde_ipld_dagcbor::to_vec(&body)?;
    let decoded_body: CorpusConversationCloseBody =
        serde_ipld_dagcbor::from_slice(&unsigned_projection_cbor)?;
    if unsigned_projection_cbor != contract_unsigned_projection_cbor
        || serde_ipld_dagcbor::to_vec(&decoded_body)? != unsigned_projection_cbor
    {
        return Err("signed Terminal body is not canonical round-trip stable".into());
    }
    let mut signing_transcript = CONVERSATION_CLOSE_SIGNATURE_DOMAIN.to_vec();
    signing_transcript.extend_from_slice(&unsigned_projection_cbor);
    let signed = signing_key.sign(&signing_transcript);
    signing_key
        .verifying_key()
        .verify(&signing_transcript, &signed)?;
    let signature = signed.to_bytes();
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript).into();
    let tombstone = contract_projection.server_fields.tombstone.clone();
    if tombstone.conversation_id != prior_context.conversation_id
        || tombstone.retired != body.retired
        || tombstone.closed_by_did != RECEIVER_DID
        || tombstone.closed_by_device_id != actor_device_id
        || tombstone.terminal_seq != seq
    {
        return Err("server Terminal tombstone does not match signed close/scenario".into());
    }
    let entry = CorpusConversationCloseEntry {
        entry_id,
        conversation_id: prior_context.conversation_id,
        seq,
        signed_request: CorpusSignedConversationClose { body, signature },
        tombstone: tombstone.clone(),
        received_at: contract_projection.received_at.clone(),
    };
    let entry_cbor = serde_ipld_dagcbor::to_vec(&entry)?;
    let decoded_entry: CorpusConversationCloseEntry = serde_ipld_dagcbor::from_slice(&entry_cbor)?;
    if serde_ipld_dagcbor::to_vec(&decoded_entry)? != entry_cbor {
        return Err("signed Terminal entry is not canonical round-trip stable".into());
    }
    let projection = CorpusControlEntryFingerprintProjection {
        entry_kind: CONVERSATION_CLOSE_ENTRY_TYPE.into(),
        entry_id,
        conversation_id: prior_context.conversation_id,
        seq,
        request_digest,
        signature,
        server_fields: CorpusTerminalServerFields { tombstone },
        received_at: contract_projection.received_at.clone(),
    };
    let fingerprint_projection_cbor = serde_ipld_dagcbor::to_vec(&projection)?;
    let decoded_projection: CorpusControlEntryFingerprintProjection =
        serde_ipld_dagcbor::from_slice(&fingerprint_projection_cbor)?;
    if fingerprint_projection_cbor != contract_projection_cbor
        || serde_ipld_dagcbor::to_vec(&decoded_projection)? != fingerprint_projection_cbor
    {
        return Err("Terminal fingerprint projection is not canonical round-trip stable".into());
    }
    let mut fingerprint_hasher = Sha256::new();
    fingerprint_hasher.update(CONTROL_ENTRY_FINGERPRINT_DOMAIN);
    fingerprint_hasher.update(&fingerprint_projection_cbor);
    let fingerprint = fingerprint_hasher.finalize().into();
    let mut fixture = SignedControlEnvelopeFixture {
        entry_id,
        transition_id,
        seq,
        fingerprint,
        previous: prior_context.clone(),
        json: json!({
            "name": "formerDeviceRemoveGapTerminalSignedEnvelope",
            "entryKind": CONVERSATION_CLOSE_ENTRY_TYPE,
            "signedRequestRef": "blue.catbird.chat.defs#signedConversationClose",
            "signingDomainHex": hex::encode(CONVERSATION_CLOSE_SIGNATURE_DOMAIN),
            "controlEntryFingerprintDomainHex": hex::encode(CONTROL_ENTRY_FINGERPRINT_DOMAIN),
            "signatureAlgorithm": "Ed25519",
            "historicalSignaturePublicKeyHex": hex::encode(signing_key.verifying_key().to_bytes()),
            "unsignedSigningProjectionCanonicalDagCborHex": hex::encode(&unsigned_projection_cbor),
            "signingTranscriptHex": hex::encode(&signing_transcript),
            "requestDigestHex": hex::encode(request_digest),
            "signatureHex": hex::encode(signature),
            "conversationCloseEntryCanonicalDagCborHex": hex::encode(&entry_cbor),
            "fingerprintProjectionCanonicalDagCborHex": hex::encode(&fingerprint_projection_cbor),
            "fingerprintSha256Hex": hex::encode(fingerprint),
            "canonicalBodyRoundTripMatched": true,
            "canonicalEntryRoundTripMatched": true,
            "canonicalFingerprintProjectionRoundTripMatched": true,
            "historicalSignatureVerified": true,
            "terminalRecipient": {
                "actorDid": DID,
                "actorDeviceId": DEVICE_ID,
            },
            "authorizedCloseSigner": {
                "actorDid": RECEIVER_DID,
                "actorDeviceId": RECEIVER_DEVICE_ID,
            },
            "signerScenarioRosterBinding": {
                "conversationKind": "group",
                "participantStatus": "active",
                "participantRole": "admin",
                "mlsLeafState": "current",
                "liveMemberEvidenceRef": "liveProof.lanes[name=sameDidTwoDevice].right",
                "evidenceScope": "authoredScenarioInputNotServerAuthorizationProof",
            },
            "signerIsTerminalRecipientDevice": false,
            "deliveryOrAudienceRoutingClaimed": false,
            "scenarioBinding": {
                "scenarioName": "terminalAfterRemoveClosedGap",
                "stepIndex": 7,
                "controlName": "terminalAfterRemove.terminal",
                "entryIdHex": hex::encode(entry_id),
                "conversationIdHex": hex::encode(prior_context.conversation_id),
                "seq": seq,
                "transitionIdHex": hex::encode(transition_id),
                "terminalOuterEntryFingerprintHex": hex::encode(fingerprint),
            },
        }),
    };
    bind_signed_terminal_to_contract_fixture(&mut fixture, contract_source)?;
    Ok(fixture)
}

fn bind_signed_terminal_to_contract_fixture(
    fixture: &mut SignedControlEnvelopeFixture,
    contract_source: &CapturedProvenanceFile,
) -> Result<()> {
    let contract: Value = serde_json::from_slice(&contract_source.bytes)?;
    let root = contract
        .get("controlEntryFingerprints")
        .ok_or("contract fixture lacks controlEntryFingerprints")?;
    if root["domain"] != String::from_utf8(CONTROL_ENTRY_FINGERPRINT_DOMAIN.to_vec())?
        || root["projectionFields"]
            != json!([
                "entryKind",
                "entryId",
                "conversationId",
                "seq",
                "requestDigest",
                "signature",
                "serverFields",
                "receivedAt"
            ])
        || root["ordinaryServerFields"] != json!({})
        || root["nonemptyServerFields"][CONVERSATION_CLOSE_ENTRY_TYPE] != json!(["tombstone"])
    {
        return Err("control-entry fingerprint contract metadata drifted".into());
    }
    let cases = root["cases"]
        .as_array()
        .ok_or("control-entry fingerprint cases are not an array")?;
    if cases.len() != 13 {
        return Err(format!(
            "control-entry fingerprint contract has {} cases instead of 13",
            cases.len()
        )
        .into());
    }
    let mut actual_kinds = cases
        .iter()
        .map(|case| {
            case["entryKind"]
                .as_str()
                .ok_or("control-entry fingerprint case lacks entryKind")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut expected_kinds = CONTROL_ENTRY_KINDS.to_vec();
    actual_kinds.sort_unstable();
    expected_kinds.sort_unstable();
    if actual_kinds != expected_kinds {
        return Err("control-entry fingerprint cases are not the exact closed 13-kind set".into());
    }
    let matching_cases = cases
        .iter()
        .filter(|case| case["entryKind"] == CONVERSATION_CLOSE_ENTRY_TYPE)
        .collect::<Vec<_>>();
    let [case] = matching_cases.as_slice() else {
        return Err("contract fixture must contain exactly one conversationCloseEntry case".into());
    };
    let expected_case_fields = [
        "entryKind",
        "signedRequestRef",
        "signingDomain",
        "unsignedSigningProjectionCanonicalDagCborHex",
        "signingTranscriptHex",
        "historicalPublicKeyRef",
        "entryId",
        "conversationId",
        "seq",
        "requestDigest",
        "signature",
        "serverFields",
        "receivedAt",
        "uuidBytePaths",
        "base64BytePaths",
        "canonicalDagCborHex",
        "fingerprintSha256Hex",
    ];
    let case_object = case
        .as_object()
        .ok_or("conversationCloseEntry contract case is not an object")?;
    if case_object.len() != expected_case_fields.len()
        || expected_case_fields
            .iter()
            .any(|field| !case_object.contains_key(*field))
    {
        return Err("conversationCloseEntry contract case fields drifted".into());
    }
    let evidence = &fixture.json;
    let evidence_hex = |field: &str| -> Result<Vec<u8>> {
        Ok(hex::decode(evidence[field].as_str().ok_or_else(|| {
            format!("signed Terminal evidence lacks {field}")
        })?)?)
    };
    let case_text = |field: &str| -> Result<&str> {
        case[field]
            .as_str()
            .ok_or_else(|| format!("conversationCloseEntry contract case lacks {field}").into())
    };
    let contract_entry_id = *uuid::Uuid::parse_str(case_text("entryId")?)?.as_bytes();
    let contract_conversation_id = *uuid::Uuid::parse_str(case_text("conversationId")?)?.as_bytes();
    let contract_request_digest = STANDARD.decode(case_text("requestDigest")?)?;
    let contract_signature = STANDARD.decode(case_text("signature")?)?;
    let contract_projection_cbor = hex::decode(case_text("canonicalDagCborHex")?)?;
    let local_projection_cbor = evidence_hex("fingerprintProjectionCanonicalDagCborHex")?;
    let contract_projection: CorpusControlEntryFingerprintProjection =
        serde_ipld_dagcbor::from_slice(&contract_projection_cbor)?;
    let local_projection: CorpusControlEntryFingerprintProjection =
        serde_ipld_dagcbor::from_slice(&local_projection_cbor)?;
    if contract_projection != local_projection
        || serde_ipld_dagcbor::to_vec(&contract_projection)? != contract_projection_cbor
    {
        return Err(
            "conversationCloseEntry contract serverFields/projection differ from local typed projection"
                .into(),
        );
    }
    let historical_key_ref = case_text("historicalPublicKeyRef")?;
    let historical_key_hex = root["historicalPublicKeys"][historical_key_ref]
        .as_str()
        .ok_or("conversationCloseEntry historical public key reference is unresolved")?;
    let expected_uuid_paths = json!([
        "entryId",
        "conversationId",
        "serverFields.tombstone.conversationId",
        "serverFields.tombstone.retired.conversationId",
        "serverFields.tombstone.closedByDeviceId"
    ]);
    let expected_base64_paths = json!([
        "requestDigest",
        "signature",
        "serverFields.tombstone.retired.groupId",
        "serverFields.tombstone.retired.groupContextHash",
        "serverFields.tombstone.retired.confirmationTag"
    ]);
    let exact_values_match = case["entryKind"] == CONVERSATION_CLOSE_ENTRY_TYPE
        && case["signedRequestRef"] == "blue.catbird.chat.defs#signedConversationClose"
        && case["signingDomain"]
            == String::from_utf8(CONVERSATION_CLOSE_SIGNATURE_DOMAIN.to_vec())?
        && case_text("unsignedSigningProjectionCanonicalDagCborHex")?
            == evidence["unsignedSigningProjectionCanonicalDagCborHex"]
        && case_text("signingTranscriptHex")? == evidence["signingTranscriptHex"]
        && contract_entry_id == fixture.entry_id
        && contract_conversation_id == context().conversation_id
        && case["seq"] == fixture.seq
        && contract_request_digest == evidence_hex("requestDigestHex")?
        && contract_signature == evidence_hex("signatureHex")?
        && case_text("receivedAt")? == RECEIVED_AT
        && case["uuidBytePaths"] == expected_uuid_paths
        && case["base64BytePaths"] == expected_base64_paths
        && contract_projection_cbor == local_projection_cbor
        && case_text("fingerprintSha256Hex")? == hex::encode(fixture.fingerprint)
        && historical_key_hex == evidence["historicalSignaturePublicKeyHex"];
    if !exact_values_match {
        return Err(
            "locally generated signed Terminal does not exactly match the server contract golden"
                .into(),
        );
    }
    fixture
        .json
        .as_object_mut()
        .ok_or("signed Terminal evidence is not an object")?
        .insert(
            "contractFixtureReference".into(),
            json!({
                "path": contract_source.relative_path,
                "sourceSha256Hex": sha256(&contract_source.bytes),
                "root": "controlEntryFingerprints",
                "entryKind": CONVERSATION_CLOSE_ENTRY_TYPE,
                "historicalPublicKeyRef": historical_key_ref,
                "comparedFields": expected_case_fields,
                "exactCrossLanguageEquality": true,
            }),
        );
    Ok(())
}

fn conversation_context_from_control_coordinates(
    coordinates: &CorpusControlCoordinates,
) -> Result<ConversationContext> {
    if coordinates.lifecycle != "active" {
        return Err("Terminal signed prior must have active lifecycle".into());
    }
    Ok(ConversationContext {
        conversation_id: coordinates.conversation_id,
        generation: coordinates.generation,
        state_version: coordinates.state_version,
        group_id: coordinates.group_id,
        epoch: coordinates.epoch,
        group_context_hash: coordinates.group_context_hash,
        confirmation_tag: coordinates.confirmation_tag,
        lifecycle: Lifecycle::Active,
    })
}

fn fixture_key_id(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

fn deterministic_entry_coordinates(name: &str) -> ([u8; 16], u64) {
    let digest = Sha256::digest(
        [
            b"CATBIRD-CHAT-APPLICATION-FIXTURE-ENTRY\0".as_slice(),
            name.as_bytes(),
        ]
        .concat(),
    );
    let mut entry_id: [u8; 16] = digest[..16].try_into().unwrap();
    entry_id[6] = (entry_id[6] & 0x0f) | 0x40;
    entry_id[8] = (entry_id[8] & 0x3f) | 0x80;
    let mut seq_bytes = [0_u8; 8];
    seq_bytes.copy_from_slice(&digest[16..24]);
    let seq = (u64::from_be_bytes(seq_bytes) & ((1_u64 << 53) - 1)).max(1);
    (entry_id, seq)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FutureWire<'a> {
    protocol: &'a str,
    version: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    context: ConversationContext,
    body: FutureBody<'a>,
}

#[derive(Serialize)]
struct FutureBody<'a> {
    poll: FuturePoll<'a>,
}

#[derive(Serialize)]
struct FuturePoll<'a> {
    question: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownTopWire<'a> {
    protocol: &'a str,
    version: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    context: ConversationContext,
    body: ApplicationBody,
    extension: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownBodyWire<'a> {
    protocol: &'a str,
    version: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    context: ConversationContext,
    body: TypingBody,
}

#[derive(Serialize)]
struct TypingBody {
    typing: TypingPayload,
}

#[derive(Serialize)]
struct TypingPayload {
    state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NullTextWire<'a> {
    protocol: &'a str,
    version: u64,
    #[serde(with = "bytes16")]
    message_id: [u8; 16],
    context: ConversationContext,
    body: NullMessageBody,
}

#[derive(Serialize)]
struct NullMessageBody {
    message: NullMessage,
}

#[derive(Serialize)]
struct NullMessage {
    text: Option<String>,
}

macro_rules! fixed_bytes_module {
    ($module:ident, $length:expr) => {
        mod $module {
            use serde::de::{self, Visitor};
            use serde::{Deserializer, Serializer};
            use std::fmt;

            pub fn serialize<S>(bytes: &[u8; $length], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(bytes)
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; $length], D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FixedBytesVisitor;

                impl<'de> Visitor<'de> for FixedBytesVisitor {
                    type Value = [u8; $length];

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(formatter, "exactly {} raw bytes", $length)
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        value
                            .try_into()
                            .map_err(|_| E::invalid_length(value.len(), &self))
                    }

                    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        self.visit_bytes(&value)
                    }
                }

                deserializer.deserialize_bytes(FixedBytesVisitor)
            }
        }
    };
}

fixed_bytes_module!(bytes16, 16);
fixed_bytes_module!(bytes32, 32);
fixed_bytes_module!(bytes64, 64);

mod byte_vec {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteVecVisitor;

        impl<'de> Visitor<'de> for ByteVecVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a raw byte string")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(value)
            }
        }

        deserializer.deserialize_bytes(ByteVecVisitor)
    }
}
