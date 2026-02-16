// persistence_repro.rs
//
// Minimal Rust-only test to isolate whether there's a bug in OpenMLS
// persistence for group creators after add_members + merge_pending_commit
//
// This test uses ONLY:
// - openmls 0.7.1
// - openmls_rust_crypto
// - openmls_basic_credential
// - openmls_memory_storage (via provider)
//
// NO custom serialization, NO FFI, NO JSON - just the documented OpenMLS flow.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

// ============================================================================
// Test Utilities
// ============================================================================

struct TestUser {
    identity: Vec<u8>,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
}

fn create_test_user(
    name: &str,
    ciphersuite: Ciphersuite,
    provider: &OpenMlsRustCrypto,
) -> TestUser {
    let identity = name.as_bytes().to_vec();
    let credential = BasicCredential::new(identity.clone());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    TestUser {
        identity,
        credential_with_key,
        signer: signature_keys,
    }
}

fn create_key_package(
    user: &TestUser,
    ciphersuite: Ciphersuite,
    provider: &OpenMlsRustCrypto,
) -> KeyPackage {
    // CRITICAL: Key packages must advertise support for RatchetTree extension
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

// Helper to extract Welcome from MlsMessageOut
fn extract_welcome(welcome_msg_out: MlsMessageOut) -> Welcome {
    let bytes = welcome_msg_out.tls_serialize_detached().unwrap();
    let mls_message_in = MlsMessageIn::tls_deserialize_exact(&bytes[..]).unwrap();
    mls_message_in
        .into_welcome()
        .expect("Expected Welcome message")
}

// Helper to create a provider with deserialized storage
fn provider_with_storage(storage_bytes: &[u8]) -> OpenMlsRustCrypto {
    let mut cursor = std::io::Cursor::new(storage_bytes);
    let storage = openmls_memory_storage::MemoryStorage::deserialize(&mut cursor).unwrap();

    // OpenMlsRustCrypto doesn't expose a constructor that takes storage,
    // so we need to create a new provider and replace its storage
    let provider = OpenMlsRustCrypto::default();

    // Replace the storage contents
    let mut provider_values = provider.storage().values.write().unwrap();
    let storage_values = storage.values.read().unwrap();
    provider_values.clear();
    provider_values.extend(storage_values.clone());
    drop(provider_values);

    provider
}

// ============================================================================
// Core Test: Creator can decrypt after restart
// ============================================================================

#[test]
fn test_creator_can_decrypt_after_restart() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Setup Alice and Bob
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);

    println!("✅ Created Alice and Bob");

    // Alice creates a group
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    println!(
        "✅ Alice created group: {:?}",
        hex::encode(alice_group.group_id().as_slice())
    );

    // Alice adds Bob
    let bob_key_package = create_key_package(&bob, ciphersuite, &bob_provider);

    let (_commit, welcome_msg_out, _group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_key_package])
        .unwrap();

    println!("✅ Alice added Bob to group");

    alice_group.merge_pending_commit(&alice_provider).unwrap();
    println!("✅ Alice merged pending commit");

    // Bob joins from Welcome
    let welcome = extract_welcome(welcome_msg_out);
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob_provider, &default_join_config(), welcome, None)
            .unwrap()
            .into_group(&bob_provider)
            .unwrap();

    println!("✅ Bob joined group from Welcome");

    // Sanity check: Alice can decrypt Bob's message BEFORE restart
    let bob_msg1 = bob_group
        .create_message(&bob_provider, &bob.signer, b"Hello Alice before restart")
        .unwrap();

    let processed1 =
        alice_group.process_message(&alice_provider, bob_msg1.into_protocol_message().unwrap());
    assert!(
        processed1.is_ok(),
        "❌ Alice should decrypt Bob's message BEFORE restart, got: {:?}",
        processed1.err()
    );
    println!("✅ Alice successfully decrypted Bob's message BEFORE restart");

    // ========================================================================
    // CRITICAL: Serialize Alice's storage RIGHT HERE
    // ========================================================================

    let mut alice_storage_bytes = Vec::new();
    alice_provider
        .storage()
        .serialize(&mut alice_storage_bytes)
        .unwrap();

    let alice_entry_count = alice_provider.storage().values.read().unwrap().len();
    println!(
        "📊 Alice storage entries before restart: {}",
        alice_entry_count
    );

    let bob_entry_count = bob_provider.storage().values.read().unwrap().len();
    println!("📊 Bob storage entries: {}", bob_entry_count);

    // ========================================================================
    // SIMULATE RESTART: New provider with deserialized storage
    // ========================================================================

    let alice_provider2 = provider_with_storage(&alice_storage_bytes);
    println!("✅ Created new provider with deserialized storage");

    let alice_entry_count2 = alice_provider2.storage().values.read().unwrap().len();
    println!(
        "📊 Alice storage entries after restart: {}",
        alice_entry_count2
    );

    // Reload Alice's group from storage
    let mut alice_group2 = MlsGroup::load(alice_provider2.storage(), alice_group.group_id())
        .unwrap()
        .expect("Group should exist in storage");

    println!("✅ Reloaded Alice's group from storage");

    // ========================================================================
    // THE CRITICAL TEST: Can Alice decrypt Bob's message AFTER restart?
    // ========================================================================

    let bob_msg2 = bob_group
        .create_message(&bob_provider, &bob.signer, b"Hello Alice after restart")
        .unwrap();

    println!("📨 Bob created message after Alice's restart");

    let processed2 =
        alice_group2.process_message(&alice_provider2, bob_msg2.into_protocol_message().unwrap());

    assert!(
        processed2.is_ok(),
        "❌ CRITICAL: Alice should decrypt Bob's message AFTER restart, got: {:?}",
        processed2.err()
    );

    println!("✅ SUCCESS: Alice decrypted Bob's message AFTER restart");
}

// ============================================================================
// Variant A: Round-trip both sides
// ============================================================================

#[test]
fn test_both_sides_can_decrypt_after_restart() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Setup
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

    // Add Bob
    let bob_key_package = create_key_package(&bob, ciphersuite, &bob_provider);
    let (_commit, welcome_msg_out, _group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome = extract_welcome(welcome_msg_out);
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob_provider, &default_join_config(), welcome, None)
            .unwrap()
            .into_group(&bob_provider)
            .unwrap();

    // Exchange messages before restart
    let bob_msg1 = bob_group
        .create_message(&bob_provider, &bob.signer, b"msg1")
        .unwrap();
    alice_group
        .process_message(&alice_provider, bob_msg1.into_protocol_message().unwrap())
        .unwrap();

    let alice_msg1 = alice_group
        .create_message(&alice_provider, &alice.signer, b"msg2")
        .unwrap();
    bob_group
        .process_message(&bob_provider, alice_msg1.into_protocol_message().unwrap())
        .unwrap();

    println!("✅ Both sides exchanged messages before restart");

    // Serialize BOTH sides
    let mut alice_storage_bytes = Vec::new();
    alice_provider
        .storage()
        .serialize(&mut alice_storage_bytes)
        .unwrap();

    let mut bob_storage_bytes = Vec::new();
    bob_provider
        .storage()
        .serialize(&mut bob_storage_bytes)
        .unwrap();

    println!(
        "📊 Alice entries: {}",
        alice_provider.storage().values.read().unwrap().len()
    );
    println!(
        "📊 Bob entries: {}",
        bob_provider.storage().values.read().unwrap().len()
    );

    // Restart both
    let alice_provider2 = provider_with_storage(&alice_storage_bytes);
    let bob_provider2 = provider_with_storage(&bob_storage_bytes);

    let mut alice_group2 = MlsGroup::load(alice_provider2.storage(), alice_group.group_id())
        .unwrap()
        .expect("Alice group should exist");
    let mut bob_group2 = MlsGroup::load(bob_provider2.storage(), bob_group.group_id())
        .unwrap()
        .expect("Bob group should exist");

    println!("✅ Both sides reloaded from storage");

    // Exchange messages after restart
    let bob_msg2 = bob_group2
        .create_message(&bob_provider2, &bob.signer, b"msg3")
        .unwrap();
    let result =
        alice_group2.process_message(&alice_provider2, bob_msg2.into_protocol_message().unwrap());

    assert!(
        result.is_ok(),
        "❌ Alice should decrypt Bob's message after both restarted, got: {:?}",
        result.err()
    );

    println!("✅ SUCCESS: Both sides can decrypt after restart");
}

// ============================================================================
// Variant B: Serialize at different times
// ============================================================================

#[test]
fn test_serialize_at_different_stages() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);

    // Stage 1: After group creation, before adding members
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    let mut snapshot1 = Vec::new();
    alice_provider.storage().serialize(&mut snapshot1).unwrap();
    let count1 = alice_provider.storage().values.read().unwrap().len();
    println!("📊 Stage 1 (after group creation): {} entries", count1);

    // Stage 2: After add_members, before merge
    let bob_key_package = create_key_package(&bob, ciphersuite, &bob_provider);
    let (_commit, welcome_msg_out, _group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_key_package])
        .unwrap();

    let mut snapshot2 = Vec::new();
    alice_provider.storage().serialize(&mut snapshot2).unwrap();
    let count2 = alice_provider.storage().values.read().unwrap().len();
    println!(
        "📊 Stage 2 (after add_members, before merge): {} entries",
        count2
    );

    // Stage 3: After merge
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let mut snapshot3 = Vec::new();
    alice_provider.storage().serialize(&mut snapshot3).unwrap();
    let count3 = alice_provider.storage().values.read().unwrap().len();
    println!("📊 Stage 3 (after merge): {} entries", count3);

    // Bob joins
    let welcome = extract_welcome(welcome_msg_out);
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob_provider, &default_join_config(), welcome, None)
            .unwrap()
            .into_group(&bob_provider)
            .unwrap();

    // Stage 4: After first message
    let bob_msg = bob_group
        .create_message(&bob_provider, &bob.signer, b"msg")
        .unwrap();
    alice_group
        .process_message(&alice_provider, bob_msg.into_protocol_message().unwrap())
        .unwrap();

    let mut snapshot4 = Vec::new();
    alice_provider.storage().serialize(&mut snapshot4).unwrap();
    let count4 = alice_provider.storage().values.read().unwrap().len();
    println!("📊 Stage 4 (after first message): {} entries", count4);

    // Test each snapshot
    for (stage_name, snapshot) in [
        ("Stage 3 (after merge)", &snapshot3),
        ("Stage 4 (after message)", &snapshot4),
    ] {
        let provider = provider_with_storage(snapshot);
        let mut group = MlsGroup::load(provider.storage(), alice_group.group_id())
            .unwrap()
            .expect("Group should exist");

        let bob_msg2 = bob_group
            .create_message(&bob_provider, &bob.signer, b"test")
            .unwrap();
        let result = group.process_message(&provider, bob_msg2.into_protocol_message().unwrap());

        assert!(
            result.is_ok(),
            "❌ {} snapshot should allow decryption, got: {:?}",
            stage_name,
            result.err()
        );

        println!("✅ {} snapshot works", stage_name);
    }
}
