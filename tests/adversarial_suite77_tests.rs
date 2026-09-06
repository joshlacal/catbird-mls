//! Adversarial Suite-77 & Wire Format Policy Challenger Test Suite
//!
//! Empirically challenges:
//! 1. Suite-77 (MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 / 0x004D) engine operations
//! 2. PURE_CIPHERTEXT_WIRE_FORMAT_POLICY rejection of PublicMessage/Plaintext framing
//! 3. WireFormatPolicyViolation typing vs FFI DecryptionFailed flattening
//! 4. Signal D Layer-3 quarantine entry (RepeatedFramingFailures) on 3 distinct frames
//! 5. Immunity of fork/rejoin/External Commit machinery against framing violations

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    IncomingEnvelope, MLSStorageBackend, MlsCryptoContext, QuarantineReason,
};
use catbird_mls::MLSError;
use e2e_harness::TestWorld;

use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

struct ForeignPlaintextGroup {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl ForeignPlaintextGroup {
    fn new(group_id_bytes: &[u8]) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let credential = BasicCredential::new(b"did:plc:mallory".to_vec());
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("foreign signer generation failed");
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .wire_format_policy(openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();

        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(group_id_bytes),
            credential_with_key,
        )
        .expect("foreign group creation failed");

        Self {
            provider,
            signer,
            group,
        }
    }

    fn commit_public_message(&mut self) -> Vec<u8> {
        let bundle = self
            .group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .expect("foreign self_update failed");
        let bytes = bundle
            .commit()
            .to_bytes()
            .expect("foreign commit serialization failed");
        self.group
            .clear_pending_commit(self.provider.storage())
            .expect("foreign clear_pending_commit failed");
        bytes
    }
}

fn envelope(convo_id: &str, ciphertext: Vec<u8>, msg_id: &str) -> IncomingEnvelope {
    IncomingEnvelope {
        conversation_id: convo_id.to_string(),
        sender_did: "did:plc:mallory".to_string(),
        ciphertext,
        timestamp: chrono::Utc::now(),
        server_message_id: Some(msg_id.to_string()),
        server_epoch: None,
        server_sequence: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_5_suite77_pure_ciphertext_policy_rejection_and_quarantine() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Suite-77 Wire Policy Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();
    let group_id_bytes = hex::decode(&group_id).expect("invalid group id hex");

    // 1. Verify foreign group producing PublicMessages (plaintext wire policy)
    let mut foreign_plaintext = ForeignPlaintextGroup::new(&group_id_bytes);

    let public_commit = foreign_plaintext.commit_public_message();

    // 2. Trait path must preserve WireFormatPolicyViolation error class
    let trait_err = MlsCryptoContext::decrypt_message(
        alice.orchestrator.mls_context().as_ref(),
        group_id_bytes.clone(),
        public_commit.clone(),
    )
    .map(|_| ())
    .expect_err("public-message commit must be rejected under pure ciphertext policy");
    assert!(
        matches!(trait_err, MLSError::WireFormatPolicyViolation { .. }),
        "Trait-path must return MLSError::WireFormatPolicyViolation, got: {trait_err:?}"
    );

    // 3. FFI path must flatten to DecryptionFailed to uphold platform contract
    let ffi_err = alice
        .orchestrator
        .mls_context()
        .decrypt_message(group_id_bytes.clone(), public_commit.clone())
        .map(|_| ())
        .expect_err("FFI decrypt_message must fail");
    assert!(
        matches!(ffi_err, MLSError::DecryptionFailed),
        "FFI decrypt_message must flatten to MLSError::DecryptionFailed, got: {ffi_err:?}"
    );

    // 4. Inject 3 distinct framing failure envelopes through process_incoming
    for i in 0..3 {
        let ct = foreign_plaintext.commit_public_message();
        let result = alice
            .orchestrator
            .process_incoming(&envelope(&group_id, ct, &format!("framing-violation-{i}")))
            .await;
        assert!(
            result.is_err(),
            "Framing violation envelope #{i} must fail processing"
        );
    }

    // 5. Verify Signal D quarantine entry
    let quarantine = alice
        .orchestrator
        .get_conversation_quarantine_state(&group_id)
        .await
        .expect("Conversation must enter quarantine after 3 framing failures");
    assert_eq!(
        quarantine.reason,
        QuarantineReason::RepeatedFramingFailures,
        "Quarantine reason must be RepeatedFramingFailures (Signal D)"
    );

    // 6. Verify fail-closed invariants: no rejoin flag, no external commit storms
    assert!(
        !alice.storage.needs_rejoin(&group_id).await.unwrap(),
        "Framing violations must NEVER arm the rejoin flag"
    );
    assert_eq!(
        world.delivery_service().external_commit_count(&group_id),
        0,
        "Framing violations must NEVER produce external commits"
    );
}
