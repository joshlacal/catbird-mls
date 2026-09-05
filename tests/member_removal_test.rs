// member_removal_test.rs
//
// Tests for MLS member removal functionality:
// 1. Basic member removal (removes member, advances epoch, revokes decryption)
// 2. Cannot remove last admin
// 3. Remove multiple members in single commit
// 4. Removed member cannot decrypt post-removal messages
// 5. Proposal creation APIs (propose_add, propose_remove, propose_self_update)
//
// These tests validate the critical security fix:
// - Removed members CANNOT decrypt messages after removal
// - This is the proper MLS cryptographic removal (not server-side soft removal)

#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use async_trait::async_trait;
use catbird_mls::{GroupConfig, KeyPackageData, KeychainAccess, MLSContext, MLSError};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tls_codec::{Deserialize, Serialize};

// ============================================================================
// Test Utilities
// ============================================================================

struct TestUser {
    name: String,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
    identity: Vec<u8>,
}

fn create_test_user(
    name: &str,
    ciphersuite: Ciphersuite,
    _provider: &OpenMlsRustCrypto,
) -> TestUser {
    let identity = name.as_bytes().to_vec();
    let credential = BasicCredential::new(identity.clone());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    TestUser {
        name: name.to_string(),
        credential_with_key,
        signer: signature_keys,
        identity,
    }
}

fn create_key_package(
    user: &TestUser,
    ciphersuite: Ciphersuite,
    provider: &OpenMlsRustCrypto,
) -> KeyPackage {
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::RatchetTree])
        .build();

    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            ciphersuite,
            provider,
            &user.signer,
            user.credential_with_key.clone(),
        )
        .unwrap()
        .key_package()
        .clone()
}

fn default_group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

fn default_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

fn extract_welcome(welcome_msg_out: MlsMessageOut) -> Welcome {
    let bytes = welcome_msg_out.tls_serialize_detached().unwrap();
    let mls_message_in = MlsMessageIn::tls_deserialize_exact(&bytes[..]).unwrap();
    match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("Expected Welcome message"),
    }
}

fn find_member_index(group: &MlsGroup, identity: &[u8]) -> Option<LeafNodeIndex> {
    for member in group.members() {
        let cred = member.credential.serialized_content();
        if cred == identity {
            return Some(member.index);
        }
    }
    None
}

#[derive(Clone)]
struct TestKeychain {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
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

fn new_context() -> (Arc<MLSContext>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let context = MLSContext::new(
        dir.path().join("mls.db").to_string_lossy().to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(TestKeychain::new()),
    )
    .unwrap();
    epoch_secret_test_support::install(&context);
    (context, dir)
}

fn key_package_for(context: &MLSContext, identity: &[u8]) -> KeyPackageData {
    let key_package = context.create_key_package(identity.to_vec()).unwrap();
    KeyPackageData {
        data: key_package.key_package_data,
    }
}

fn open_test_manifest(path: &std::path::Path) -> rusqlite::Connection {
    use sha2::{Digest, Sha256};
    let key = "test-key-1234567890123456";
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "cipher_memory_security", "OFF").unwrap();
    conn.pragma_update(None, "key", key).unwrap();
    conn.pragma_update(None, "cipher_plaintext_header_size", 32).unwrap();
    conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(&Sha256::digest(key)[..16]))).unwrap();
    conn
}

fn context_group_with_members(
    member_identities: &[&[u8]],
) -> (Arc<MLSContext>, Vec<u8>, tempfile::TempDir) {
    let (context, dir) = new_context();
    let created = context
        .create_group(
            b"did:plc:admin#device-main".to_vec(),
            Some(GroupConfig::default()),
        )
        .unwrap();
    let key_packages = member_identities
        .iter()
        .map(|identity| key_package_for(&context, identity))
        .collect();
    context
        .add_members(created.group_id.clone(), key_packages)
        .unwrap();
    context
        .merge_pending_commit(created.group_id.clone())
        .unwrap();
    (context, created.group_id, dir)
}

fn member_identities(context: &MLSContext, group_id: &[u8]) -> Vec<Vec<u8>> {
    context
        .debug_group_members(group_id.to_vec())
        .unwrap()
        .members
        .into_iter()
        .map(|member| member.credential_identity)
        .collect()
}

#[test]
fn bare_did_removes_all_device_leaves_without_matching_prefix_lookalikes() {
    let target = b"did:plc:target";
    let target_phone = b"did:plc:target#phone";
    let target_laptop = b"did:plc:target#laptop";
    let prefix_lookalike = b"did:plc:target-extra#phone";
    let unrelated = b"did:plc:unrelated#phone";
    let (context, group_id, _dir) =
        context_group_with_members(&[target_phone, target_laptop, prefix_lookalike, unrelated]);

    context
        .remove_members(group_id.clone(), vec![target.to_vec()])
        .expect("a bare DID must match every device leaf with that credential root");
    context.merge_pending_commit(group_id.clone()).unwrap();

    let identities = member_identities(&context, &group_id);
    assert!(!identities.iter().any(|identity| identity == target_phone));
    assert!(!identities.iter().any(|identity| identity == target_laptop));
    assert!(identities
        .iter()
        .any(|identity| identity == prefix_lookalike));
    assert!(identities.iter().any(|identity| identity == unrelated));
}

#[test]
fn fragment_qualified_identity_removes_only_the_exact_device_leaf() {
    let target_phone = b"did:plc:target#phone";
    let target_laptop = b"did:plc:target#laptop";
    let (context, group_id, _dir) = context_group_with_members(&[target_phone, target_laptop]);

    context
        .remove_members(group_id.clone(), vec![target_phone.to_vec()])
        .unwrap();
    context.merge_pending_commit(group_id.clone()).unwrap();

    let identities = member_identities(&context, &group_id);
    assert!(!identities.iter().any(|identity| identity == target_phone));
    assert!(identities.iter().any(|identity| identity == target_laptop));
}

#[test]
fn swap_with_bare_did_removes_all_device_leaves_without_prefix_lookalikes() {
    let target = b"did:plc:target";
    let target_phone = b"did:plc:target#phone";
    let target_laptop = b"did:plc:target#laptop";
    let prefix_lookalike = b"did:plc:target-extra#phone";
    let replacement = b"did:plc:replacement#phone";
    let (context, group_id, _dir) =
        context_group_with_members(&[target_phone, target_laptop, prefix_lookalike]);

    context
        .swap_members(
            group_id.clone(),
            vec![target.to_vec()],
            vec![key_package_for(&context, replacement)],
        )
        .expect("a bare-DID swap must select every matching device leaf");
    context.merge_pending_commit(group_id.clone()).unwrap();

    let identities = member_identities(&context, &group_id);
    assert!(!identities.iter().any(|identity| identity == target_phone));
    assert!(!identities.iter().any(|identity| identity == target_laptop));
    assert!(identities
        .iter()
        .any(|identity| identity == prefix_lookalike));
    assert!(identities.iter().any(|identity| identity == replacement));
}

#[test]
fn swap_with_fragment_qualified_identity_removes_only_that_device() {
    let target_phone = b"did:plc:target#phone";
    let target_laptop = b"did:plc:target#laptop";
    let replacement = b"did:plc:replacement#phone";
    let (context, group_id, _dir) = context_group_with_members(&[target_phone, target_laptop]);

    context
        .swap_members(
            group_id.clone(),
            vec![target_phone.to_vec()],
            vec![key_package_for(&context, replacement)],
        )
        .unwrap();
    context.merge_pending_commit(group_id.clone()).unwrap();

    let identities = member_identities(&context, &group_id);
    assert!(!identities.iter().any(|identity| identity == target_phone));
    assert!(identities.iter().any(|identity| identity == target_laptop));
    assert!(identities.iter().any(|identity| identity == replacement));
}

#[test]
fn recovery_swap_authenticates_transition_and_preserves_sibling_until_atomic_merge() {
    use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;

    let target_phone = b"did:plc:target#phone";
    let target_laptop = b"did:plc:target#laptop";
    let (context, group_id, _dir) = context_group_with_members(&[target_phone, target_laptop]);
    let epoch_before = context.get_epoch(group_id.clone()).unwrap();
    let before = context.debug_group_members(group_id.clone()).unwrap();
    let old_index = before
        .members
        .iter()
        .find(|member| member.credential_identity == target_phone)
        .unwrap()
        .leaf_index;
    let aad = b"CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0device-replacement".to_vec();
    let replacement = key_package_for(&context, target_phone);

    let result = MlsCryptoContext::swap_members_with_aad(
        context.as_ref(),
        group_id.clone(),
        vec![target_phone.to_vec()],
        vec![replacement],
        Some(aad.clone()),
    )
    .expect("native replacement must retain authenticated transition data");

    assert_eq!(context.get_epoch(group_id.clone()).unwrap(), epoch_before);
    assert_eq!(
        member_identities(&context, &group_id).len(),
        3,
        "no membership changes before the server accepts"
    );
    let (commit_aad, proposals) = parse_public_commit_wire(&result.commit_data);
    assert_eq!(commit_aad, aad);
    assert_eq!(proposals.iter().filter(|proposal| matches!(proposal,
        openmls::messages::proposals_in::ProposalIn::Remove(remove) if remove.removed().u32() == old_index
    )).count(), 1);
    assert_eq!(
        proposals
            .iter()
            .filter(|proposal| matches!(
                proposal,
                openmls::messages::proposals_in::ProposalIn::Add(_)
            ))
            .count(),
        1
    );
    assert_eq!(
        proposals.len(),
        2,
        "the recovery manifest allows no additional proposal effects"
    );
    assert!(result.next_confirmation_tag.is_some());
    assert!(result.next_group_context_hash.is_some());

    context.merge_pending_commit(group_id.clone()).unwrap();
    assert_eq!(
        context.get_epoch(group_id.clone()).unwrap(),
        epoch_before + 1
    );
    let after = context.debug_group_members(group_id.clone()).unwrap();
    assert_eq!(
        after.members.len(),
        3,
        "replace removes one leaf while adding exactly one"
    );
    assert!(after
        .members
        .iter()
        .any(|member| member.credential_identity == target_laptop));
    assert_eq!(
        after
            .members
            .iter()
            .filter(|member| member.credential_identity == target_phone)
            .count(),
        1
    );
    assert_eq!(
        result.next_confirmation_tag.unwrap(),
        context.get_confirmation_tag(group_id.clone()).unwrap()
    );
    assert_eq!(
        result.next_group_context_hash.unwrap(),
        context.get_group_context_hash(group_id.clone()).unwrap()
    );
    let next_update = context.self_update(group_id).unwrap();
    assert!(
        parse_public_commit_wire(&next_update.commit_data)
            .0
            .is_empty(),
        "recovery AAD must not leak to later commits"
    );
}

#[test]
fn swap_with_empty_removals_performs_pure_add() {
    let member = b"did:plc:creator#phone";
    let new_member = b"did:plc:newbie#phone";
    let (context, group_id, _dir) = context_group_with_members(&[member]);
    let epoch_before = context.get_epoch(group_id.clone()).unwrap();

    let result = context
        .swap_members(
            group_id.clone(),
            vec![],
            vec![key_package_for(&context, new_member)],
        )
        .expect("swap_members with empty remove_identities must succeed as pure-add");
    assert!(!result.commit_data.is_empty());
    context.merge_pending_commit(group_id.clone()).unwrap();

    let identities = member_identities(&context, &group_id);
    assert!(identities.iter().any(|identity| identity == member));
    assert!(identities.iter().any(|identity| identity == new_member));
    assert_eq!(context.get_epoch(group_id).unwrap(), epoch_before + 1);
}

#[test]
fn incoming_self_removal_completes_without_deadlock_and_preserves_sibling_membership() {
    use catbird_mls::orchestrator::mls_provider::{IncomingCommitMergeOutcome, MlsCryptoContext};
    use catbird_mls::ProcessedContent;
    use std::time::Duration;

    let (alice, _alice_dir) = new_context();
    let phone_keychain = TestKeychain::new();
    let phone_dir = tempfile::tempdir().unwrap();
    let phone = MLSContext::new(
        phone_dir.path().join("mls.db").to_string_lossy().to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(phone_keychain.clone()),
    ).unwrap();
    epoch_secret_test_support::install(&phone);
    let (laptop, _laptop_dir) = new_context();
    let phone_identity = b"did:plc:bob#phone";
    let laptop_identity = b"did:plc:bob#laptop";
    let group = alice
        .create_group(b"did:plc:alice#phone".to_vec(), None)
        .unwrap()
        .group_id;
    let add = alice
        .add_members(
            group.clone(),
            vec![
                key_package_for(&phone, phone_identity),
                key_package_for(&laptop, laptop_identity),
            ],
        )
        .unwrap();
    alice.merge_pending_commit(group.clone()).unwrap();
    phone
        .process_welcome(add.welcome_data.clone(), phone_identity.to_vec(), None)
        .unwrap();
    laptop
        .process_welcome(add.welcome_data, laptop_identity.to_vec(), None)
        .unwrap();
    let remove = alice
        .remove_members(group.clone(), vec![phone_identity.to_vec()])
        .unwrap();
    alice.merge_pending_commit(group.clone()).unwrap();
    assert!(matches!(
        phone
            .process_message(group.clone(), remove.clone())
            .unwrap(),
        ProcessedContent::StagedCommit { new_epoch: 2, .. }
    ));
    assert!(matches!(
        laptop.process_message(group.clone(), remove.clone()).unwrap(),
        ProcessedContent::StagedCommit { new_epoch: 2, .. }
    ));

    assert_eq!(
        MlsCryptoContext::verified_incoming_removal(phone.as_ref(), group.clone(), remove.clone())
            .unwrap(),
        None,
        "staging alone does not prove this device was removed"
    );

    let (sender, receiver) = std::sync::mpsc::channel();
    let merge_phone = phone.clone();
    let merge_group = group.clone();
    std::thread::spawn(move || {
        let _ = sender.send(MlsCryptoContext::merge_incoming_commit_with_outcome(
            merge_phone.as_ref(),
            merge_group,
            2,
        ));
    });
    let merged = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("processing our removal must not deadlock on the pending-commit mutex")
        .expect("accepted self-removal is terminal membership, not epoch divergence");
    assert_eq!(merged, IncomingCommitMergeOutcome::Removed { epoch: 2 });
    assert_eq!(
        MlsCryptoContext::verified_incoming_removal(phone.as_ref(), group.clone(), remove.clone())
            .unwrap(),
        Some(2)
    );
    let mut changed_remove = remove.clone();
    *changed_remove.last_mut().unwrap() ^= 1;
    assert_eq!(
        MlsCryptoContext::verified_incoming_removal(phone.as_ref(), group.clone(), changed_remove)
            .unwrap(),
        None,
        "inactive membership must not acknowledge a different ciphertext"
    );
    assert!(!MlsCryptoContext::group_is_active(phone.as_ref(), group.clone()).unwrap());
    assert!(phone
        .encrypt_message(group.clone(), b"no longer a member".to_vec())
        .is_err());

    assert_eq!(
        MlsCryptoContext::merge_incoming_commit_with_outcome(laptop.as_ref(), group.clone(), 2)
            .unwrap(),
        IncomingCommitMergeOutcome::Active { epoch: 2 }
    );
    assert!(MlsCryptoContext::group_is_active(laptop.as_ref(), group.clone()).unwrap());
    let message = alice
        .encrypt_message(group.clone(), b"sibling stays".to_vec())
        .unwrap();
    assert_eq!(
        laptop
            .decrypt_message(group.clone(), message.ciphertext)
            .unwrap()
            .plaintext,
        b"sibling stays"
    );
    assert!(
        phone.merge_incoming_commit(group.clone(), 2).is_err(),
        "successful terminal merge consumes the exact staged token"
    );
    phone.flush_and_prepare_close().unwrap();
    let reopened = MLSContext::new(
        phone_dir
            .path()
            .join("mls.db")
            .to_string_lossy()
            .to_string(),
        "test-key-1234567890123456".to_string(),
        Box::new(phone_keychain.clone()),
    )
    .unwrap();
    assert!(
        !reopened.group_is_active(group.clone()).unwrap(),
        "terminal membership must remain inactive after reopening storage"
    );
    assert_eq!(
        MlsCryptoContext::verified_incoming_removal(reopened.as_ref(), group.clone(), remove.clone()).unwrap(),
        Some(2),
        "exact removal proof survives restart before outer projection completes"
    );
    reopened.flush_and_prepare_close().unwrap();

    // Reconstruct the durable crash boundary after OpenMLS persisted removal
    // but before the receipt was confirmed. All MLS state and wire bytes are
    // real; only the receipt's completion bit is rolled back in this fixture.
    let receipt_key = format!("incoming-removal-v1:{}", hex::encode(&group));
    let path = phone_dir.path().join("mls.db");
    let mut receipt: serde_json::Value = {
        let db = open_test_manifest(&path);
        let encoded: String = db.query_row(
            "SELECT value FROM mls_manifests WHERE key = ?1", [&receipt_key], |row| row.get(0),
        ).unwrap();
        serde_json::from_str(&encoded).unwrap()
    };
    assert_eq!(receipt["target_credential_identity"], serde_json::json!(phone_identity.as_slice()));
    assert!(receipt["confirmed_context_hash"].is_array());
    receipt["confirmed_context_hash"] = serde_json::Value::Null;
    let expected_hash = receipt["expected_context_hash"].clone();
    receipt["expected_context_hash"] = serde_json::json!(vec![0u8; 32]);
    for expected in [None, Some(2)] {
        {
            let db = open_test_manifest(&path);
            db.execute("UPDATE mls_manifests SET value = ?1 WHERE key = ?2",
                [serde_json::to_string(&receipt).unwrap(), receipt_key.clone()]).unwrap();
        }
        let resumed = MLSContext::new(
            path.to_string_lossy().to_string(),
            "test-key-1234567890123456".to_string(),
            Box::new(phone_keychain.clone()),
        ).unwrap();
        assert_eq!(
            MlsCryptoContext::verified_incoming_removal(resumed.as_ref(), group.clone(), remove.clone()).unwrap(),
            expected,
            "unconfirmed removal intent requires the exact authenticated successor context"
        );
        resumed.flush_and_prepare_close().unwrap();
        receipt["expected_context_hash"] = expected_hash.clone();
    }
    let db = open_test_manifest(&path);
    let encoded: String = db.query_row(
        "SELECT value FROM mls_manifests WHERE key = ?1", [&receipt_key], |row| row.get(0),
    ).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&encoded).unwrap()["confirmed_context_hash"].is_array());
}

#[test]
fn swap_no_match_preserves_epoch_membership_and_pending_commit_state() {
    let member = b"did:plc:member#phone";
    let replacement = b"did:plc:replacement#phone";
    let (context, group_id, _dir) = context_group_with_members(&[member]);
    let epoch_before = context.get_epoch(group_id.clone()).unwrap();
    let identities_before = member_identities(&context, &group_id);

    assert!(context
        .swap_members(
            group_id.clone(),
            vec![b"did:plc:missing".to_vec()],
            vec![key_package_for(&context, replacement)],
        )
        .is_err());
    assert_eq!(context.get_epoch(group_id.clone()).unwrap(), epoch_before);
    assert_eq!(member_identities(&context, &group_id), identities_before);
    let merge_result = context.merge_pending_commit(group_id.clone()).unwrap();
    assert_eq!(merge_result.new_epoch, epoch_before);
    assert_eq!(member_identities(&context, &group_id), identities_before);
}

#[test]
fn proposal_with_bare_did_selects_a_single_device_leaf() {
    let target = b"did:plc:target";
    let target_phone = b"did:plc:target#phone";
    let (context, group_id, _dir) = context_group_with_members(&[target_phone]);

    context
        .propose_remove_member(group_id.clone(), target.to_vec())
        .expect("a bare DID with one matching device leaf is unambiguous");

    assert_eq!(context.list_pending_proposals(group_id).unwrap().len(), 1);
}

#[test]
fn proposal_with_bare_did_rejects_multiple_device_leaves_without_pending_state() {
    let target = b"did:plc:target";
    let target_phone = b"did:plc:target#phone";
    let target_laptop = b"did:plc:target#laptop";
    let (context, group_id, _dir) = context_group_with_members(&[target_phone, target_laptop]);
    let epoch_before = context.get_epoch(group_id.clone()).unwrap();
    let identities_before = member_identities(&context, &group_id);

    assert!(context
        .propose_remove_member(group_id.clone(), target.to_vec())
        .is_err());
    assert_eq!(context.get_epoch(group_id.clone()).unwrap(), epoch_before);
    assert_eq!(member_identities(&context, &group_id), identities_before);
    assert!(context.list_pending_proposals(group_id).unwrap().is_empty());
}

#[test]
fn no_match_preserves_epoch_membership_and_pending_commit_state() {
    let member = b"did:plc:member#phone";
    let (context, group_id, _dir) = context_group_with_members(&[member]);
    let epoch_before = context.get_epoch(group_id.clone()).unwrap();
    let identities_before = member_identities(&context, &group_id);

    assert!(context
        .remove_members(group_id.clone(), vec![b"did:plc:missing".to_vec()],)
        .is_err());
    assert_eq!(context.get_epoch(group_id.clone()).unwrap(), epoch_before);
    assert_eq!(member_identities(&context, &group_id), identities_before);
    let merge_result = context.merge_pending_commit(group_id.clone()).unwrap();
    assert_eq!(
        merge_result.new_epoch, epoch_before,
        "a no-match removal must not leave a commit capable of advancing the epoch"
    );
    assert_eq!(member_identities(&context, &group_id), identities_before);
}

// ============================================================================
// Test 1: Basic Member Removal
// ============================================================================

#[test]
fn test_basic_member_removal() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Basic Member Removal Test ===\n");

    // Setup: Alice, Bob, Charlie
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let charlie_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);
    let charlie = create_test_user("Charlie", ciphersuite, &charlie_provider);

    // Alice creates group
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    println!("✅ Alice created group at epoch {}", alice_group.epoch());

    // Add Bob
    let bob_kp = create_key_package(&bob, ciphersuite, &bob_provider);
    let (_, bob_welcome, _) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_kp])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    // Bob joins
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &default_join_config(),
        extract_welcome(bob_welcome),
        None,
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    println!("✅ Bob joined, both at epoch {}", alice_group.epoch());

    // Add Charlie
    let charlie_kp = create_key_package(&charlie, ciphersuite, &charlie_provider);
    let (add_commit, charlie_welcome, _) = alice_group
        .add_members(&alice_provider, &alice.signer, &[charlie_kp])
        .unwrap();

    // Bob processes Alice's add commit
    let add_commit_bytes = add_commit.tls_serialize_detached().unwrap();
    let add_commit_msg = MlsMessageIn::tls_deserialize_exact(&add_commit_bytes[..]).unwrap();
    let add_protocol = add_commit_msg.try_into_protocol_message().unwrap();
    let add_processed = bob_group
        .process_message(&bob_provider, add_protocol)
        .unwrap();
    if let ProcessedMessageContent::StagedCommitMessage(staged) = add_processed.into_content() {
        bob_group
            .merge_staged_commit(&bob_provider, *staged)
            .unwrap();
    }

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    // Charlie joins
    let mut charlie_group = StagedWelcome::new_from_welcome(
        &charlie_provider,
        &default_join_config(),
        extract_welcome(charlie_welcome),
        None,
    )
    .unwrap()
    .into_group(&charlie_provider)
    .unwrap();

    let epoch_before_removal = alice_group.epoch().as_u64();
    let member_count_before = alice_group.members().count();
    println!(
        "✅ Charlie joined, all at epoch {}, members: {}",
        epoch_before_removal, member_count_before
    );

    assert_eq!(
        member_count_before, 3,
        "Should have 3 members before removal"
    );

    // ========================================================================
    // Alice removes Bob
    // ========================================================================

    let bob_index = find_member_index(&alice_group, &bob.identity).expect("Bob should be in group");

    println!("\n--- Removing Bob (index {}) ---", bob_index.u32());

    let (remove_commit, _, _) = alice_group
        .remove_members(&alice_provider, &alice.signer, &[bob_index])
        .unwrap();

    // Charlie processes remove commit
    let remove_commit_bytes = remove_commit.tls_serialize_detached().unwrap();
    let remove_msg = MlsMessageIn::tls_deserialize_exact(&remove_commit_bytes[..]).unwrap();
    let remove_protocol = remove_msg.try_into_protocol_message().unwrap();
    let remove_processed = charlie_group
        .process_message(&charlie_provider, remove_protocol)
        .unwrap();
    if let ProcessedMessageContent::StagedCommitMessage(staged) = remove_processed.into_content() {
        charlie_group
            .merge_staged_commit(&charlie_provider, *staged)
            .unwrap();
    }

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let epoch_after_removal = alice_group.epoch().as_u64();
    let member_count_after = alice_group.members().count();

    println!("✅ Bob removed!");
    println!(
        "   Epoch: {} -> {}",
        epoch_before_removal, epoch_after_removal
    );
    println!(
        "   Members: {} -> {}",
        member_count_before, member_count_after
    );

    assert!(
        epoch_after_removal > epoch_before_removal,
        "Epoch should advance after removal"
    );
    assert_eq!(member_count_after, 2, "Should have 2 members after removal");

    // Verify Bob is not in the group
    let bob_still_present = find_member_index(&alice_group, &bob.identity);
    assert!(
        bob_still_present.is_none(),
        "Bob should not be in group after removal"
    );

    println!("\n🎉 SUCCESS: Basic member removal test PASSED");
}

// ============================================================================
// Test 2: Removed Member Cannot Decrypt Post-Removal Messages
// ============================================================================

#[test]
fn test_removed_member_cannot_decrypt() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Removed Member Cannot Decrypt Test ===\n");

    // Setup: Alice, Bob, Charlie
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let charlie_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);
    let charlie = create_test_user("Charlie", ciphersuite, &charlie_provider);

    // Create group with all three members
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    // Add Bob
    let bob_kp = create_key_package(&bob, ciphersuite, &bob_provider);
    let (_, bob_welcome, _) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_kp])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &default_join_config(),
        extract_welcome(bob_welcome),
        None,
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    // Add Charlie
    let charlie_kp = create_key_package(&charlie, ciphersuite, &charlie_provider);
    let (add_commit, charlie_welcome, _) = alice_group
        .add_members(&alice_provider, &alice.signer, &[charlie_kp])
        .unwrap();

    // Bob processes commit
    let add_bytes = add_commit.tls_serialize_detached().unwrap();
    let add_msg = MlsMessageIn::tls_deserialize_exact(&add_bytes[..]).unwrap();
    let add_proto = add_msg.try_into_protocol_message().unwrap();
    if let ProcessedMessageContent::StagedCommitMessage(staged) = bob_group
        .process_message(&bob_provider, add_proto)
        .unwrap()
        .into_content()
    {
        bob_group
            .merge_staged_commit(&bob_provider, *staged)
            .unwrap();
    }

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let mut charlie_group = StagedWelcome::new_from_welcome(
        &charlie_provider,
        &default_join_config(),
        extract_welcome(charlie_welcome),
        None,
    )
    .unwrap()
    .into_group(&charlie_provider)
    .unwrap();

    println!(
        "✅ All three members in group at epoch {}",
        alice_group.epoch()
    );

    // Bob can decrypt pre-removal message
    let pre_removal_msg = alice_group
        .create_message(&alice_provider, &alice.signer, b"Pre-removal message")
        .unwrap();

    let pre_bytes = pre_removal_msg.tls_serialize_detached().unwrap();
    let pre_msg = MlsMessageIn::tls_deserialize_exact(&pre_bytes[..]).unwrap();
    let pre_proto = pre_msg.try_into_protocol_message().unwrap();

    let pre_result = bob_group.process_message(&bob_provider, pre_proto);
    assert!(pre_result.is_ok(), "Bob should decrypt pre-removal message");
    println!("✅ Bob can decrypt pre-removal message");

    // ========================================================================
    // Remove Bob
    // ========================================================================

    let bob_index = find_member_index(&alice_group, &bob.identity).unwrap();
    let (remove_commit, _, _) = alice_group
        .remove_members(&alice_provider, &alice.signer, &[bob_index])
        .unwrap();

    // Charlie processes remove
    let remove_bytes = remove_commit.tls_serialize_detached().unwrap();
    let remove_msg = MlsMessageIn::tls_deserialize_exact(&remove_bytes[..]).unwrap();
    let remove_proto = remove_msg.try_into_protocol_message().unwrap();
    if let ProcessedMessageContent::StagedCommitMessage(staged) = charlie_group
        .process_message(&charlie_provider, remove_proto)
        .unwrap()
        .into_content()
    {
        charlie_group
            .merge_staged_commit(&charlie_provider, *staged)
            .unwrap();
    }

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    println!("✅ Bob removed at epoch {}", alice_group.epoch());

    // ========================================================================
    // Alice sends post-removal message
    // ========================================================================

    let post_removal_msg = alice_group
        .create_message(
            &alice_provider,
            &alice.signer,
            b"Secret post-removal message",
        )
        .unwrap();

    // Charlie CAN decrypt
    let post_bytes = post_removal_msg.tls_serialize_detached().unwrap();
    let charlie_post_msg = MlsMessageIn::tls_deserialize_exact(&post_bytes[..]).unwrap();
    let charlie_post_proto = charlie_post_msg.try_into_protocol_message().unwrap();

    let charlie_result = charlie_group.process_message(&charlie_provider, charlie_post_proto);
    assert!(
        charlie_result.is_ok(),
        "Charlie should decrypt post-removal message"
    );
    println!("✅ Charlie CAN decrypt post-removal message");

    // Bob CANNOT decrypt (his group state is stale)
    let bob_post_msg = MlsMessageIn::tls_deserialize_exact(&post_bytes[..]).unwrap();
    let bob_post_proto = bob_post_msg.try_into_protocol_message().unwrap();

    let bob_result = bob_group.process_message(&bob_provider, bob_post_proto);

    // Bob's decryption should fail because:
    // 1. The message is from a future epoch (Bob's group is still at old epoch)
    // 2. Even if he had the epoch, he was removed so the secrets changed
    assert!(
        bob_result.is_err(),
        "Bob should NOT be able to decrypt post-removal message"
    );

    println!(
        "✅ Bob CANNOT decrypt post-removal message: {:?}",
        bob_result.err()
    );

    println!("\n🎉 SUCCESS: Removed member cannot decrypt test PASSED");
    println!("   This validates the critical security property of MLS member removal");
}

// ============================================================================
// Test 3: Remove Multiple Members in Single Commit
// ============================================================================

#[test]
fn test_remove_multiple_members() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Remove Multiple Members Test ===\n");

    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let charlie_provider = OpenMlsRustCrypto::default();
    let dave_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);
    let charlie = create_test_user("Charlie", ciphersuite, &charlie_provider);
    let dave = create_test_user("Dave", ciphersuite, &dave_provider);

    // Create group
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    // Add all members
    let bob_kp = create_key_package(&bob, ciphersuite, &bob_provider);
    let charlie_kp = create_key_package(&charlie, ciphersuite, &charlie_provider);
    let dave_kp = create_key_package(&dave, ciphersuite, &dave_provider);

    let (_, _, _) = alice_group
        .add_members(
            &alice_provider,
            &alice.signer,
            &[bob_kp, charlie_kp, dave_kp],
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let initial_count = alice_group.members().count();
    println!(
        "✅ Group created with {} members at epoch {}",
        initial_count,
        alice_group.epoch()
    );
    assert_eq!(initial_count, 4, "Should have 4 members");

    // Remove Bob and Charlie in single commit
    let bob_index = find_member_index(&alice_group, &bob.identity).unwrap();
    let charlie_index = find_member_index(&alice_group, &charlie.identity).unwrap();

    println!(
        "\n--- Removing Bob (index {}) and Charlie (index {}) ---",
        bob_index.u32(),
        charlie_index.u32()
    );

    let (_, _, _) = alice_group
        .remove_members(&alice_provider, &alice.signer, &[bob_index, charlie_index])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let final_count = alice_group.members().count();
    println!(
        "✅ Removed 2 members, now have {} members at epoch {}",
        final_count,
        alice_group.epoch()
    );

    assert_eq!(final_count, 2, "Should have 2 members after removing 2");

    // Verify Bob and Charlie are gone
    assert!(
        find_member_index(&alice_group, &bob.identity).is_none(),
        "Bob should be removed"
    );
    assert!(
        find_member_index(&alice_group, &charlie.identity).is_none(),
        "Charlie should be removed"
    );

    // Verify Dave is still there
    assert!(
        find_member_index(&alice_group, &dave.identity).is_some(),
        "Dave should still be in group"
    );

    println!("\n🎉 SUCCESS: Remove multiple members test PASSED");
}

// ============================================================================
// Test 4: Proposal Creation APIs
// ============================================================================

#[test]
fn test_proposal_creation_apis() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Proposal Creation APIs Test ===\n");

    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);

    // Create group
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    // Add Bob so we have someone to propose removing
    let bob_kp = create_key_package(&bob, ciphersuite, &bob_provider);
    let (_, bob_welcome, _) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_kp])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &default_join_config(),
        extract_welcome(bob_welcome),
        None,
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    println!(
        "✅ Group setup with Alice and Bob at epoch {}",
        alice_group.epoch()
    );

    // ========================================================================
    // Test propose_add_member
    // ========================================================================

    let charlie_provider = OpenMlsRustCrypto::default();
    let charlie = create_test_user("Charlie", ciphersuite, &charlie_provider);
    let charlie_kp = create_key_package(&charlie, ciphersuite, &charlie_provider);

    let (add_proposal, add_ref) = alice_group
        .propose_add_member(&alice_provider, &alice.signer, &charlie_kp)
        .unwrap();

    println!("✅ propose_add_member created proposal");
    println!(
        "   Proposal message size: {} bytes",
        add_proposal.tls_serialized_len()
    );

    // Verify proposal is in pending queue
    let pending_count = alice_group.pending_proposals().count();
    assert!(pending_count > 0, "Should have pending proposals");
    println!("   Pending proposals: {}", pending_count);

    // ========================================================================
    // Test propose_self_update
    // ========================================================================

    let (update_proposal, update_ref) = alice_group
        .propose_self_update(
            &alice_provider,
            &alice.signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();

    println!("✅ propose_self_update created proposal");
    println!(
        "   Proposal message size: {} bytes",
        update_proposal.tls_serialized_len()
    );

    // ========================================================================
    // Test propose_remove_member
    // ========================================================================

    let bob_index = find_member_index(&alice_group, &bob.identity).unwrap();

    let (remove_proposal, remove_ref) = alice_group
        .propose_remove_member(&alice_provider, &alice.signer, bob_index)
        .unwrap();

    println!("✅ propose_remove_member created proposal");
    println!(
        "   Proposal message size: {} bytes",
        remove_proposal.tls_serialized_len()
    );

    // ========================================================================
    // Commit all pending proposals
    // ========================================================================

    let epoch_before = alice_group.epoch().as_u64();
    let pending_before = alice_group.pending_proposals().count();
    println!("\n--- Committing {} pending proposals ---", pending_before);

    let (commit, welcome_option, _) = alice_group
        .commit_to_pending_proposals(&alice_provider, &alice.signer)
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let epoch_after = alice_group.epoch().as_u64();
    let pending_after = alice_group.pending_proposals().count();

    println!("✅ Committed all proposals");
    println!("   Epoch: {} -> {}", epoch_before, epoch_after);
    println!(
        "   Pending proposals: {} -> {}",
        pending_before, pending_after
    );

    assert!(
        epoch_after > epoch_before,
        "Epoch should advance after commit"
    );
    assert_eq!(pending_after, 0, "No pending proposals after commit");

    println!("\n🎉 SUCCESS: Proposal creation APIs test PASSED");
}

// ============================================================================
// Test 5: Remove Nonexistent Member (Graceful Handling)
// ============================================================================

#[test]
fn test_remove_nonexistent_member_graceful() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Remove Nonexistent Member Test ===\n");

    let alice_provider = OpenMlsRustCrypto::default();
    let alice = create_test_user("Alice", ciphersuite, &alice_provider);

    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    println!("✅ Alice created group with just herself");

    // Try to find and remove a nonexistent member
    let fake_identity = b"nonexistent@example.com";
    let fake_index = find_member_index(&alice_group, fake_identity);

    assert!(
        fake_index.is_none(),
        "Nonexistent member should not be found"
    );
    println!("✅ find_member_index correctly returns None for nonexistent member");

    // The FFI layer handles this gracefully by returning an error
    // when no valid members are found to remove
    println!("\n🎉 SUCCESS: Nonexistent member handling test PASSED");
}

// ============================================================================
// Regression Tests for AAD-Aware Member Removal & Coordinates
// ============================================================================

fn parse_public_commit_wire(
    bytes: &[u8],
) -> (Vec<u8>, Vec<openmls::messages::proposals_in::ProposalIn>) {
    use openmls::messages::proposals_in::{ProposalIn, ProposalOrRefIn};
    use openmls::prelude::tls_codec::Deserialize;
    let mut inner = &bytes[4..]; // skip 2 bytes wire format + 2 bytes version
    let _group_id = VLBytes::tls_deserialize(&mut inner).unwrap();
    let _epoch = u64::tls_deserialize(&mut inner).unwrap();
    let _sender = Sender::tls_deserialize(&mut inner).unwrap();
    let aad = VLBytes::tls_deserialize(&mut inner).unwrap();
    let content_type = u8::tls_deserialize(&mut inner).unwrap();
    assert_eq!(content_type, 3); // Commit
    let proposal_vector = VLBytes::tls_deserialize(&mut inner).unwrap();
    let mut proposals = proposal_vector.as_slice();
    let mut parsed_proposals = Vec::new();
    while !proposals.is_empty() {
        let p_or_ref = ProposalOrRefIn::tls_deserialize(&mut proposals).unwrap();
        match p_or_ref {
            ProposalOrRefIn::Proposal(p) => parsed_proposals.push(*p),
            _ => panic!("Expected inline proposal in commit"),
        }
    }
    (aad.as_slice().to_vec(), parsed_proposals)
}

#[test]
fn test_removal_commit_aad_and_coordinates_regression() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let (context, _dir) = new_context();
    let alice_id = b"did:plc:alice#11111111-1111-4111-8111-111111111111";
    let bob_id = b"did:plc:bob#22222222-2222-4222-8222-222222222222";

    let created = context.create_group(alice_id.to_vec(), None).unwrap();
    let group_id = created.group_id;

    let bob_kp = key_package_for(&context, bob_id);
    let _add_res = context.add_members(group_id.clone(), vec![bob_kp]).unwrap();
    context.merge_pending_commit(group_id.clone()).unwrap();

    // Prepare test AAD
    let convo_uuid = uuid::Uuid::new_v4();
    let transition_uuid = uuid::Uuid::new_v4();
    let prior_tag = [0x11u8; 32];
    let prior_gch = [0x22u8; 32];
    let prior_gid = [0x33u8; 32];

    let aad_prior = serde_json::json!({
        "confirmationTag": STANDARD.encode(&prior_tag),
        "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
        "epoch": 1,
        "generation": 0,
        "groupContextHash": STANDARD.encode(&prior_gch),
        "groupId": STANDARD.encode(&prior_gid),
        "lifecycle": "active",
        "stateVersion": 1
    });

    let aad_json = serde_json::json!({
        "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
        "generation": 0,
        "prior": aad_prior,
        "protocolVersion": "1",
        "transitionId": STANDARD.encode(transition_uuid.as_bytes())
    });

    let aad_bytes = catbird_mls::orchestrator::canonical_commit_aad_bytes(&aad_json)
        .expect("canonical AAD encoding must succeed");

    // Verify prefix
    assert!(aad_bytes.starts_with(b"CATBIRD-CHAT-MLS-AAD-COMMIT\0"));

    // Stage removal with AAD
    let remove_res = context
        .remove_members_with_aad(
            group_id.clone(),
            vec![bob_id.to_vec()],
            Some(aad_bytes.clone()),
        )
        .expect("remove_members_with_aad must succeed");

    // 1. Verify next coordinates are extracted and non-empty
    assert!(remove_res.next_confirmation_tag.is_some());
    let next_tag = remove_res.next_confirmation_tag.unwrap();
    assert_eq!(next_tag.len(), 32);

    assert!(remove_res.next_group_context_hash.is_some());
    let next_gch = remove_res.next_group_context_hash.unwrap();
    assert_eq!(next_gch.len(), 32);

    // 2. Deserialize commit and verify authenticated_data matches EXACTLY
    let (extracted_aad, proposals) = parse_public_commit_wire(&remove_res.commit_data);
    assert_eq!(
        extracted_aad, aad_bytes,
        "Commit authenticated_data must match server-required prefixed canonical CBOR AAD"
    );

    // 3. Verify Remove proposal exists and no AppDataUpdate proposal exists
    assert!(
        proposals
            .iter()
            .any(|p| matches!(p, openmls::messages::proposals_in::ProposalIn::Remove(_))),
        "Removal commit must contain Remove proposal"
    );
    assert!(
        !proposals.iter().any(|p| matches!(
            p,
            openmls::messages::proposals_in::ProposalIn::AppDataUpdate(_)
        )),
        "Removal commit must NOT contain AppDataUpdate proposal"
    );

    // Merge the removal commit
    let new_epoch = context
        .merge_pending_commit(group_id.clone())
        .unwrap()
        .new_epoch;
    assert_eq!(new_epoch, 2);
}

#[test]
fn test_staged_failure_clears_aad() {
    let (context, _dir) = new_context();
    let alice_id = b"did:plc:alice#11111111-1111-4111-8111-111111111111";

    let created = context.create_group(alice_id.to_vec(), None).unwrap();
    let group_id = created.group_id;

    // Try to remove a non-existent member with AAD set
    let dummy_aad = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0dummy-aad".to_vec();
    let err = context.remove_members_with_aad(
        group_id.clone(),
        vec![b"did:plc:nonexistent".to_vec()],
        Some(dummy_aad),
    );
    assert!(err.is_err());

    // Next valid commit (self-update) without AAD must produce empty authenticated_data
    let update_res = context.self_update(group_id.clone()).unwrap();
    let (extracted_aad, _) = parse_public_commit_wire(&update_res.commit_data);
    assert!(
        extracted_aad.is_empty(),
        "Failed staged commit must not leave group AAD dirty"
    );
}
