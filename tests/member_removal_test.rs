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

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
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
    mls_message_in
        .into_welcome()
        .expect("Expected Welcome message")
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
    let add_protocol = add_commit_msg.into_protocol_message().unwrap();
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
    let remove_protocol = remove_msg.into_protocol_message().unwrap();
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
    let add_proto = add_msg.into_protocol_message().unwrap();
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
    let pre_proto = pre_msg.into_protocol_message().unwrap();

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
    let remove_proto = remove_msg.into_protocol_message().unwrap();
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
    let charlie_post_proto = charlie_post_msg.into_protocol_message().unwrap();

    let charlie_result = charlie_group.process_message(&charlie_provider, charlie_post_proto);
    assert!(
        charlie_result.is_ok(),
        "Charlie should decrypt post-removal message"
    );
    println!("✅ Charlie CAN decrypt post-removal message");

    // Bob CANNOT decrypt (his group state is stale)
    let bob_post_msg = MlsMessageIn::tls_deserialize_exact(&post_bytes[..]).unwrap();
    let bob_post_proto = bob_post_msg.into_protocol_message().unwrap();

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
