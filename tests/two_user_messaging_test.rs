// two_user_messaging_test.rs
//
// Reproduces the two-user rapid messaging scenario to isolate whether
// SecretReuseError is an OpenMLS bug or an FFI bug.
//
// Scenario:
// 1. Alice creates group (epoch 0)
// 2. Alice adds Bob via add_members → commit + welcome
// 3. Alice merges pending commit (advances to epoch 1)
// 4. Alice sends application message (uses sender key A0)
// 5. Bob processes Welcome and joins (epoch 1)
// 6. Bob processes Alice's message (verifies Alice's sender chain)
// 7. Bob sends application message (uses sender key B0)
// 8. Alice receives and processes Bob's message
//
// Expected: This should PASS if OpenMLS correctly handles this flow.
// If it FAILS with SecretReuseError, there's an OpenMLS bug to report.
//
// Configuration matches Catbird:
// - Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
// - OpenMlsRustCrypto provider (in-memory storage)
// - Basic credentials

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

// ============================================================================
// Test Utilities
// ============================================================================

struct TestUser {
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
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

// Helper to extract ProcessedMessage from ProtocolMessage
fn process_and_extract_message(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    msg: ProtocolMessage,
) -> Result<Vec<u8>, String> {
    let processed = group
        .process_message(provider, msg)
        .map_err(|e| format!("ProcessMessageError: {:?}", e))?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(app_msg.into_bytes()),
        _ => Err("Expected ApplicationMessage".to_string()),
    }
}

// ============================================================================
// Core Test: Two-User Rapid Messaging Scenario
// ============================================================================

#[test]
fn test_two_user_rapid_messaging() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Two-User Rapid Messaging Test ===\n");

    // Setup Alice and Bob with separate providers
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);

    println!("✅ Step 0: Created Alice and Bob");

    // ========================================================================
    // STEP 1: Alice creates a group (epoch 0)
    // ========================================================================

    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    println!(
        "✅ Step 1: Alice created group at epoch {}",
        alice_group.epoch()
    );
    println!(
        "   Group ID: {}",
        hex::encode(alice_group.group_id().as_slice())
    );
    assert_eq!(
        alice_group.epoch().as_u64(),
        0,
        "Alice should be at epoch 0"
    );

    // ========================================================================
    // STEP 2: Alice adds Bob via add_members → commit + welcome
    // ========================================================================

    let bob_key_package = create_key_package(&bob, ciphersuite, &bob_provider);

    let (_commit_msg_out, welcome_msg_out, _group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_key_package])
        .unwrap();

    println!("✅ Step 2: Alice added Bob to group (commit created)");
    println!(
        "   Alice still at epoch {} (pending commit)",
        alice_group.epoch()
    );

    // ========================================================================
    // STEP 3: Alice merges pending commit (advances to epoch 1)
    // ========================================================================

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    println!("✅ Step 3: Alice merged pending commit");
    println!("   Alice now at epoch {}", alice_group.epoch());
    assert_eq!(
        alice_group.epoch().as_u64(),
        1,
        "Alice should be at epoch 1 after merge"
    );

    // ========================================================================
    // STEP 4: Alice sends application message (uses sender key A0)
    // ========================================================================

    let alice_msg_1 = alice_group
        .create_message(&alice_provider, &alice.signer, b"Hello Bob from Alice!")
        .unwrap();

    println!("✅ Step 4: Alice created application message");
    println!("   Alice sender chain generation: (should be 0 for first message)");
    println!("   Message created at epoch {}", alice_group.epoch());

    // ========================================================================
    // STEP 5: Bob processes Welcome and joins (epoch 1)
    // ========================================================================

    let welcome = extract_welcome(welcome_msg_out);
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob_provider, &default_join_config(), welcome, None)
            .unwrap()
            .into_group(&bob_provider)
            .unwrap();

    println!("✅ Step 5: Bob joined group from Welcome");
    println!("   Bob at epoch {}", bob_group.epoch());
    assert_eq!(bob_group.epoch().as_u64(), 1, "Bob should be at epoch 1");
    assert_eq!(
        bob_group.epoch(),
        alice_group.epoch(),
        "Bob and Alice should be at same epoch"
    );

    // ========================================================================
    // STEP 6: Bob processes Alice's message (verifies Alice's sender chain)
    // ========================================================================

    let alice_msg_1_protocol = alice_msg_1.into_protocol_message().unwrap();

    let received_msg_1 =
        process_and_extract_message(&mut bob_group, &bob_provider, alice_msg_1_protocol);

    assert!(
        received_msg_1.is_ok(),
        "❌ CRITICAL: Bob should decrypt Alice's message, got: {:?}",
        received_msg_1.err()
    );

    println!("✅ Step 6: Bob successfully decrypted Alice's message");
    println!(
        "   Message content: {:?}",
        String::from_utf8_lossy(&received_msg_1.unwrap())
    );
    println!("   Bob still at epoch {}", bob_group.epoch());

    // ========================================================================
    // STEP 7: Bob sends application message (uses sender key B0)
    // ========================================================================

    let bob_msg_1 = bob_group
        .create_message(&bob_provider, &bob.signer, b"Hello Alice from Bob!")
        .unwrap();

    println!("✅ Step 7: Bob created application message");
    println!("   Bob sender chain generation: (should be 0 for first message)");
    println!("   Message created at epoch {}", bob_group.epoch());

    // ========================================================================
    // STEP 8: Alice receives and processes Bob's message
    // ========================================================================

    let bob_msg_1_protocol = bob_msg_1.into_protocol_message().unwrap();

    let received_msg_2 =
        process_and_extract_message(&mut alice_group, &alice_provider, bob_msg_1_protocol);

    assert!(
        received_msg_2.is_ok(),
        "❌ CRITICAL: Alice should decrypt Bob's message, got: {:?}",
        received_msg_2.err()
    );

    println!("✅ Step 8: Alice successfully decrypted Bob's message");
    println!(
        "   Message content: {:?}",
        String::from_utf8_lossy(&received_msg_2.unwrap())
    );
    println!("   Alice still at epoch {}", alice_group.epoch());

    // ========================================================================
    // SUCCESS: All steps completed without SecretReuseError
    // ========================================================================

    println!("\n🎉 SUCCESS: Two-user rapid messaging test PASSED");
    println!("   - Both users successfully exchanged messages");
    println!("   - No SecretReuseError occurred");
    println!("   - OpenMLS correctly handled sender chain initialization");
}

// ============================================================================
// Extended Test: Multiple Message Exchange
// ============================================================================

#[test]
fn test_two_user_multiple_messages() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Two-User Multiple Messages Test ===\n");

    // Setup
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);

    // Alice creates group
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    // Alice adds Bob
    let bob_key_package = create_key_package(&bob, ciphersuite, &bob_provider);
    let (_commit, welcome_msg_out, _group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    // Bob joins
    let welcome = extract_welcome(welcome_msg_out);
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob_provider, &default_join_config(), welcome, None)
            .unwrap()
            .into_group(&bob_provider)
            .unwrap();

    println!(
        "✅ Setup complete - both users at epoch {}",
        alice_group.epoch()
    );

    // ========================================================================
    // Exchange multiple messages rapidly
    // ========================================================================

    for i in 0..5 {
        println!("\n--- Message Exchange Round {} ---", i + 1);

        // Alice sends to Bob
        let alice_msg = alice_group
            .create_message(
                &alice_provider,
                &alice.signer,
                format!("Alice message {}", i + 1).as_bytes(),
            )
            .unwrap();

        let alice_received = process_and_extract_message(
            &mut bob_group,
            &bob_provider,
            alice_msg.into_protocol_message().unwrap(),
        );

        assert!(
            alice_received.is_ok(),
            "❌ Bob failed to decrypt Alice's message {}: {:?}",
            i + 1,
            alice_received.err()
        );

        println!(
            "✅ Bob received: {:?}",
            String::from_utf8_lossy(&alice_received.unwrap())
        );

        // Bob sends to Alice
        let bob_msg = bob_group
            .create_message(
                &bob_provider,
                &bob.signer,
                format!("Bob message {}", i + 1).as_bytes(),
            )
            .unwrap();

        let bob_received = process_and_extract_message(
            &mut alice_group,
            &alice_provider,
            bob_msg.into_protocol_message().unwrap(),
        );

        assert!(
            bob_received.is_ok(),
            "❌ Alice failed to decrypt Bob's message {}: {:?}",
            i + 1,
            bob_received.err()
        );

        println!(
            "✅ Alice received: {:?}",
            String::from_utf8_lossy(&bob_received.unwrap())
        );
    }

    println!("\n🎉 SUCCESS: Multiple message exchange test PASSED");
    println!("   - Exchanged {} message pairs successfully", 5);
    println!("   - Both users remain at epoch {}", alice_group.epoch());
}

// ============================================================================
// Edge Case: Out-of-order Message Delivery
// ============================================================================

#[test]
fn test_two_user_out_of_order_messages() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    println!("\n=== Two-User Out-of-Order Messages Test ===\n");

    // Setup
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let alice = create_test_user("Alice", ciphersuite, &alice_provider);
    let bob = create_test_user("Bob", ciphersuite, &bob_provider);

    // Alice creates group and adds Bob
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice.signer,
        &default_group_config(),
        alice.credential_with_key.clone(),
    )
    .unwrap();

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

    println!("✅ Setup complete");

    // ========================================================================
    // Alice creates multiple messages in sequence
    // ========================================================================

    let alice_msg_1 = alice_group
        .create_message(&alice_provider, &alice.signer, b"Message 1")
        .unwrap();

    let alice_msg_2 = alice_group
        .create_message(&alice_provider, &alice.signer, b"Message 2")
        .unwrap();

    let alice_msg_3 = alice_group
        .create_message(&alice_provider, &alice.signer, b"Message 3")
        .unwrap();

    println!("✅ Alice created 3 messages in sequence");

    // ========================================================================
    // Bob receives messages out of order: 2, 1, 3
    // ========================================================================

    println!("\n--- Delivering messages out of order ---");

    // Message 2 first
    let result_2 = process_and_extract_message(
        &mut bob_group,
        &bob_provider,
        alice_msg_2.into_protocol_message().unwrap(),
    );
    println!("📨 Delivered message 2: {:?}", result_2.is_ok());

    // Message 1 second
    let result_1 = process_and_extract_message(
        &mut bob_group,
        &bob_provider,
        alice_msg_1.into_protocol_message().unwrap(),
    );
    println!("📨 Delivered message 1: {:?}", result_1.is_ok());

    // Message 3 third
    let result_3 = process_and_extract_message(
        &mut bob_group,
        &bob_provider,
        alice_msg_3.into_protocol_message().unwrap(),
    );
    println!("📨 Delivered message 3: {:?}", result_3.is_ok());

    // At least some messages should be successfully processed
    let successful_messages = [result_1.is_ok(), result_2.is_ok(), result_3.is_ok()]
        .iter()
        .filter(|&&x| x)
        .count();

    println!("\n📊 Out of order delivery results:");
    println!(
        "   - Message 1: {}",
        if result_1.is_ok() {
            "✅ OK"
        } else {
            "❌ Failed"
        }
    );
    println!(
        "   - Message 2: {}",
        if result_2.is_ok() {
            "✅ OK"
        } else {
            "❌ Failed"
        }
    );
    println!(
        "   - Message 3: {}",
        if result_3.is_ok() {
            "✅ OK"
        } else {
            "❌ Failed"
        }
    );
    println!("   - Total successful: {}/3", successful_messages);

    // Note: OpenMLS may reject out-of-order messages depending on implementation.
    // This test is primarily to observe behavior rather than enforce strict pass/fail.
    println!("\n✅ Out-of-order test complete (observed behavior documented)");
}
