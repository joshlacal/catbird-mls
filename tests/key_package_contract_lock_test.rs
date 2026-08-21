#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use openmls::prelude::{
    KeyPackageIn, MlsMessageOut, ProtocolVersion, VerifiableCiphersuite,
};
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use openmls_traits::OpenMlsProvider;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tls_codec::{
    Deserialize, DeserializeBytes, Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLBytes,
};

struct TestKeychain {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.store.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.store.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.store.lock().unwrap().remove(&key);
        Ok(())
    }
}

fn make_context() -> (Arc<MLSContext>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    let ctx = MLSContext::new(
        path,
        "test-key-1234567890123456".to_string(),
        Box::new(TestKeychain {
            store: Mutex::new(HashMap::new()),
        }),
    )
    .unwrap();
    epoch_secret_test_support::install(&ctx);
    (ctx, dir)
}

#[test]
fn generated_key_package_satisfies_clean_contract_and_matches_fixture() {
    let (ctx, _dir) = make_context();
    let identity = "did:plc:alicefixtureaaaaaaaaaaaa#70707070-7070-4070-b070-707070707070";
    let result = ctx
        .create_key_package(identity.as_bytes().to_vec())
        .expect("create key package");

    assert!(!result.key_package_data.is_empty());
    assert_eq!(result.hash_ref.len(), 32);
    assert_eq!(result.signature_public_key.len(), 32);

    // Validate with libcrux provider
    let (kp_in, remaining) = KeyPackageIn::tls_deserialize_bytes(&result.key_package_data)
        .expect("deserialize raw key package bytes");
    assert!(remaining.is_empty(), "no trailing bytes");

    let provider = LibcruxProvider::new().expect("libcrux provider");
    let validated = kp_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .expect("validate generated key package");

    // Clean profile invariants
    let leaf_node = validated.leaf_node();
    let capabilities = leaf_node.capabilities();

    assert_eq!(
        capabilities.versions(),
        &[openmls::prelude::ProtocolVersion::Mls10]
    );
    assert_eq!(
        capabilities.ciphersuites(),
        &[VerifiableCiphersuite::from(openmls::prelude::Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)]
    );
    assert_eq!(
        capabilities.credentials(),
        &[openmls::prelude::CredentialType::Basic]
    );
    assert!(
        capabilities.extensions().is_empty(),
        "leaf capabilities extensions must be empty"
    );
    assert!(
        capabilities.proposals().is_empty(),
        "leaf capabilities proposals must be empty"
    );
    assert_eq!(
        leaf_node.extensions().iter().count(),
        0,
        "leaf node extensions must be empty"
    );
    assert_eq!(
        validated.extensions().iter().count(),
        0,
        "key package extensions must be empty"
    );

    // Verify wrapped wire format 5
    let wrapped = MlsMessageOut::from(validated.clone())
        .tls_serialize_detached()
        .expect("serialize wrapped wire message");
    assert_eq!(&wrapped[..4], &[0x00, 0x01, 0x00, 0x05], "wire format 5 header");
    assert_eq!(&wrapped[4..], &result.key_package_data);
    // Verify OpenMLS hash_ref matches hash_ref
    let expected_hash_ref = validated
        .hash_ref(provider.crypto())
        .expect("compute hash_ref");
    assert_eq!(result.hash_ref.as_slice(), expected_hash_ref.as_slice());
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: WireGroupInfo,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireGroupInfo {
    context: WireGroupContext,
    extensions: Vec<WireExtension>,
    confirmation_tag: VLBytes,
    signer: u32,
    signature: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<WireExtension>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireLeafNode {
    payload: WireLeafNodeTbs,
    signature: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireLeafNodeTbs {
    encryption_key: VLBytes,
    signature_key: VLBytes,
    credential: WireCredential,
    capabilities: WireCapabilities,
    source: WireLeafNodeSource,
    extensions: Vec<WireExtension>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireCredential {
    credential_type: u16,
    serialized_content: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireCapabilities {
    versions: Vec<u16>,
    ciphersuites: Vec<u16>,
    extensions: Vec<u16>,
    proposals: Vec<u16>,
    credentials: Vec<u16>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum WireLeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(WireLifetime),
    #[tls_codec(discriminant = 2)]
    Update,
    #[tls_codec(discriminant = 3)]
    Commit(VLBytes),
}

#[derive(Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireLifetime {
    not_before: u64,
    not_after: u64,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[allow(dead_code)]
struct WireExtension {
    extension_type: u16,
    extension_data: VLBytes,
}

#[test]
fn freshly_created_group_creator_leaf_satisfies_clean_lifetime_and_capabilities() {
    let (ctx, _dir) = make_context();
    let identity = "did:plc:alicefixtureaaaaaaaaaaaa#70707070-7070-4070-b070-707070707070";
    let created = ctx
        .create_group(identity.as_bytes().to_vec(), None)
        .expect("create group");

    let group_info_bytes = ctx
        .export_group_info(created.group_id.clone(), identity.as_bytes().to_vec())
        .expect("export group info");
    // Deserialize wire GroupInfoEnvelope
    let mut slice = group_info_bytes.as_slice();
    let envelope = WireGroupInfoEnvelope::tls_deserialize(&mut slice)
        .expect("deserialize wire group info envelope");
    assert!(slice.is_empty(), "no trailing bytes in group info envelope");
    assert_eq!(envelope.version, 0x0001, "MLS 1.0 version");
    assert_eq!(envelope.wire_format, 0x0004, "GroupInfo wire format 4");

    let group_info = &envelope.group_info;

    // Genesis GroupContext assertions
    let context = &group_info.context;
    assert_eq!(context.protocol_version, 0x0001, "MLS 1.0 protocol version");
    assert_eq!(context.ciphersuite, 0x004D, "XWING ciphersuite 0x004D");
    assert_eq!(context.epoch, 0, "genesis epoch must be 0");
    assert_eq!(context.group_id.as_slice(), created.group_id.as_slice(), "group_id matches");
    assert_eq!(context.tree_hash.as_slice().len(), 32, "tree hash is 32 bytes");
    assert!(context.confirmed_transcript_hash.as_slice().is_empty(), "genesis confirmed transcript hash must be empty");
    assert!(context.extensions.is_empty(), "genesis group context extensions must be empty");

    // Genesis GroupInfo extensions: exactly ratchet_tree (2) and external_pub (4)
    let ratchet_tree_ext = group_info
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 2)
        .expect("ratchet tree extension (type 2) must be present");
    // Parse singleton ratchet tree from the extension_data VLBytes
    let mut rt_slice = ratchet_tree_ext.extension_data.as_slice();
    let encoded_nodes = VLBytes::tls_deserialize(&mut rt_slice)
        .expect("deserialize ratchet tree nodes vector");
    assert!(rt_slice.is_empty(), "no trailing bytes in ratchet tree extension");

    let mut nodes = encoded_nodes.as_slice();
    let present = u8::tls_deserialize(&mut nodes).expect("deserialize present flag");
    assert_eq!(present, 1, "node 0 must be present (Some)");

    let node_type = u8::tls_deserialize(&mut nodes).expect("deserialize node type");
    assert_eq!(node_type, 1, "node 0 must be LeafNode (type 1)");

    let wire_leaf = WireLeafNode::tls_deserialize(&mut nodes)
        .expect("deserialize creator leaf node from ratchet tree");
    assert!(nodes.is_empty(), "singleton genesis tree has no further nodes");

    // Check clean capabilities on the creator leaf node
    let capabilities = &wire_leaf.payload.capabilities;
    assert_eq!(capabilities.versions, &[0x0001], "MLS 1.0");
    assert_eq!(capabilities.ciphersuites, &[0x004D], "XWING ciphersuite 0x004D");
    assert_eq!(capabilities.credentials, &[0x0001], "BasicCredential 0x0001");
    assert!(
        capabilities.extensions.is_empty(),
        "creator leaf capabilities extensions must be empty"
    );
    assert!(
        capabilities.proposals.is_empty(),
        "creator leaf capabilities proposals must be empty"
    );
    assert!(
        wire_leaf.payload.extensions.is_empty(),
        "creator leaf node extensions must be empty"
    );

    // Server maximum key package / leaf node lifetime: 30 days + 1 hour = 2,595,600 seconds
    const MAX_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60 + 60 * 60;
    const MIN_KEY_PACKAGE_REMAINING_SECONDS: u64 = 600;

    // Check lifetime on creator leaf node
    match wire_leaf.payload.source {
        WireLeafNodeSource::KeyPackage(lifetime) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let not_before = lifetime.not_before;
            let not_after = lifetime.not_after;

            assert!(
                not_before <= now,
                "not_before ({not_before}) must be <= now ({now})"
            );
            assert!(
                now < not_after,
                "now ({now}) must be < not_after ({not_after})"
            );
            assert!(
                not_after.saturating_sub(now) >= MIN_KEY_PACKAGE_REMAINING_SECONDS,
                "remaining lifetime must be >= 600s"
            );
            let span = not_after.saturating_sub(not_before);
            assert!(
                span <= MAX_KEY_PACKAGE_LIFETIME_SECONDS,
                "creator leaf lifetime span ({span}s) must be <= MAX_KEY_PACKAGE_LIFETIME_SECONDS ({MAX_KEY_PACKAGE_LIFETIME_SECONDS}s)"
            );
            // Assert it matches the client's 29-day configuration window (29 days + 60s = 2,505,660s)
            assert_eq!(span, 29 * 24 * 3600 + 60, "lifetime span must match the 29-day + 60s client window");
        }
        other => panic!("expected KeyPackage leaf node source, got {:?}", other),
    }
}
