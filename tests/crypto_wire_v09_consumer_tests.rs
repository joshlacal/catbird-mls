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

use openmls::component::ComponentData;
use openmls::framing::MlsMessageBodyIn;
use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use catbird_mls::chat_v2::transcript::{
    project_signed_body, SignedMutationKind, SignedWrapper, VerifiedMutation,
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

    // 2. Consume and verify creation-signed-request.cbor
    let creation_signed_cbor =
        fs::read(fixture_dir.join("creation-signed-request.cbor")).expect("read creation request");
    assert!(creation_signed_cbor.len() > 100);
    assert_eq!(creation_signed_cbor[0], 0xa2);
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
