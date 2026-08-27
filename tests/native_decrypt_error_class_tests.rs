//! N38 integration tests: typed OpenMLS error classes through NATIVE decrypt.
//!
//! Before N38, `MLSContext::decrypt_message` flattened every OpenMLS
//! `process_message` failure to `MLSError::DecryptionFailed`, so the
//! orchestrator's WrongEpoch silent-skip arm (`messaging.rs`) and the
//! Layer-3 peer-bad quarantine classifier could only be tripped with mock
//! crypto (see `PeerBadCrypto` in `ws5_recovery_persistence_tests.rs`).
//!
//! These tests drive REAL OpenMLS errors through `process_incoming` against
//! the production `MLSContext` (via the class-preserving
//! `decrypt_message_classified` path used by the `MlsCryptoContext` trait
//! impl):
//!
//! - `ValidationError::WrongEpoch` — an application message from a foreign
//!   group state at a FUTURE epoch (same group id). Must be silently
//!   skipped: `Ok(None)`, no failure counters, no rejoin flag, no
//!   quarantine, and the local group still works.
//! - `ProcessMessageError::IncompatibleWireFormat` — a member COMMIT framed
//!   as a PublicMessage from a foreign (forked) group state. Catbird groups
//!   use `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`, so this is a wire-format
//!   policy breach → typed `MLSError::WireFormatPolicyViolation` →
//!   peer-bad → three distinct frames must enter Layer-3 quarantine
//!   (Signal D, `RepeatedFramingFailures`) WITHOUT arming the
//!   fork/rejoin/External-Commit machinery.
//!
//! NOTE (MLS Encryption Changes rule): the FFI surface is intentionally
//! unchanged (`decrypt_message` still flattens to `DecryptionFailed` —
//! asserted below), but end-to-end message-display verification on the
//! platforms (iOS, catmos, catmos-cli, Android) is still required before
//! release.

#![allow(dead_code)]

mod e2e_harness;

use catbird_mls::orchestrator::{
    IncomingEnvelope, MLSStorageBackend, MlsCryptoContext, QuarantineReason,
};
use catbird_mls::{KeyPackageData, MLSError};
use e2e_harness::TestWorld;

use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

// ---------------------------------------------------------------------------
// Foreign-group fixture: a real OpenMLS group that shares Alice's group id
// but none of her state (forked/foreign group state).
// ---------------------------------------------------------------------------

struct ForeignGroup {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl ForeignGroup {
    /// Build a foreign MLS group with the SAME group id as `group_id_bytes`
    /// but completely independent key material.
    ///
    /// `plaintext_policy` controls the foreign group's wire format policy:
    /// `PURE_PLAINTEXT` makes its handshake messages PublicMessages, which
    /// Alice's `PURE_CIPHERTEXT` group must reject with
    /// `IncompatibleWireFormat` (a REAL OpenMLS peer-bad class).
    fn new(group_id_bytes: &[u8], plaintext_policy: bool) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let credential = BasicCredential::new(b"did:plc:mallory".to_vec());
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("foreign signer generation failed");
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let mut config = MlsGroupCreateConfig::builder().ciphersuite(ciphersuite);
        if plaintext_policy {
            config = config.wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY);
        } else {
            config = config.wire_format_policy(openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY);
        }
        let config = config.build();

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

    /// Advance the foreign group's epoch by one (self-update commit, merged
    /// locally).
    fn advance_epoch(&mut self) {
        self.group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .expect("foreign self_update failed");
        self.group
            .merge_pending_commit(&self.provider)
            .expect("foreign merge_pending_commit failed");
    }

    /// Serialized application message from the foreign group's CURRENT epoch.
    fn application_message(&mut self, text: &[u8]) -> Vec<u8> {
        let msg = self
            .group
            .create_message(&self.provider, &self.signer, text)
            .expect("foreign create_message failed");
        msg.to_bytes()
            .expect("foreign message serialization failed")
    }

    /// Serialized (unmerged) member COMMIT from the foreign group. With
    /// `plaintext_policy` this is a PublicMessage — exactly the framing
    /// Alice's pure-ciphertext group must refuse.
    fn commit_message(&mut self) -> Vec<u8> {
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
    }
}

// ---------------------------------------------------------------------------
// 1. WrongEpoch silent-skip arm fires on a REAL OpenMLS WrongEpoch
// ---------------------------------------------------------------------------

/// A future-epoch application message (real `ValidationError::WrongEpoch`,
/// fired by OpenMLS `validate_framing` before any AEAD work) must be
/// silently skipped — repeatedly — without tripping decrypt-failure
/// counters, the rejoin flag, fork-readd External Commits, or quarantine.
#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_epoch_messages_silently_skipped_native() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("WrongEpoch Native Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();
    let group_id_bytes = hex::decode(&group_id).expect("invalid group id hex");

    let local_epoch = alice
        .orchestrator
        .mls_context()
        .get_epoch(group_id_bytes.clone())
        .expect("get_epoch failed");

    // Foreign group with the same id, pure-ciphertext policy, advanced past
    // Alice's epoch — its application messages carry a FUTURE epoch.
    let mut foreign = ForeignGroup::new(&group_id_bytes, false);
    for _ in 0..=(local_epoch + 1) {
        foreign.advance_epoch();
    }

    // Sanity: the class-preserving native decrypt yields a WrongEpoch-class
    // error (this is what the orchestrator's silent-skip arm matches on).
    let probe = foreign.application_message(b"future-epoch probe");
    let probe_err = MlsCryptoContext::decrypt_message(
        alice.orchestrator.mls_context().as_ref(),
        group_id_bytes.clone(),
        probe,
    )
    .map(|_| ())
    .expect_err("future-epoch message must not decrypt");
    assert!(
        probe_err.is_wrong_epoch(),
        "native decrypt must preserve the WrongEpoch class, got: {probe_err:?}"
    );

    // Drive MORE wrong-epoch frames than DECRYPTION_FAILURE_THRESHOLD (3)
    // through the full inbound pipeline: every one must be silently skipped.
    for i in 0..4 {
        let ct = foreign.application_message(format!("future-epoch {i}").as_bytes());
        let result = alice
            .orchestrator
            .process_incoming(&envelope(&group_id, ct, &format!("wrong-epoch-{i}")))
            .await;
        assert!(
            matches!(result, Ok(None)),
            "WrongEpoch frame #{i} must be silently skipped (Ok(None)), got: {result:?}"
        );
    }

    // No recovery machinery may have been armed.
    assert!(
        alice
            .orchestrator
            .get_conversation_quarantine_state(&group_id)
            .await
            .is_none(),
        "WrongEpoch frames must never quarantine"
    );
    assert!(
        !alice.storage.needs_rejoin(&group_id).await.unwrap(),
        "WrongEpoch frames must not set the rejoin flag"
    );
    assert_eq!(
        world.delivery_service().external_commit_count(&group_id),
        0,
        "WrongEpoch frames must not trigger External Commits"
    );

    // Normal traffic unaffected: the local group still encrypts and sends.
    world
        .client("Alice")
        .orchestrator
        .send_message(&group_id, "still alive after wrong-epoch storm")
        .await
        .expect("send_message must still work after WrongEpoch skips");
}

// ---------------------------------------------------------------------------
// 2. Peer-bad classifier + quarantine entry fire on REAL OpenMLS errors
// ---------------------------------------------------------------------------

/// A member commit framed as a PublicMessage from a foreign/forked group
/// state is a REAL `ProcessMessageError::IncompatibleWireFormat`. The N38
/// typed mapping turns it into `MLSError::WireFormatPolicyViolation`, the
/// peer-bad classifier picks it up, and three distinct frames must enter
/// Layer-3 quarantine (Signal D) — without arming fork/rejoin machinery.
#[tokio::test(flavor = "multi_thread")]
async fn test_peer_bad_wire_format_commits_enter_quarantine_native() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Peer-Bad Native Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();
    let group_id_bytes = hex::decode(&group_id).expect("invalid group id hex");

    // Foreign group with ciphertext wire-format policy: its member commits
    // are PrivateMessages, which Alice's pure-plaintext handshake group must reject.
    let mut foreign = ForeignGroup::new(&group_id_bytes, false);

    // Sanity check the typed class boundary first:
    //   - trait path (orchestrator) sees WireFormatPolicyViolation;
    //   - FFI path keeps flattening to DecryptionFailed (iOS/catmos-cli
    //     contract, MLS Encryption Changes rule).
    let probe = foreign.commit_message();
    let trait_err = MlsCryptoContext::decrypt_message(
        alice.orchestrator.mls_context().as_ref(),
        group_id_bytes.clone(),
        probe.clone(),
    )
    .map(|_| ())
    .expect_err("foreign public-message commit must not process");
    assert!(
        matches!(trait_err, MLSError::WireFormatPolicyViolation { .. }),
        "trait-path decrypt must surface the typed wire-format class, got: {trait_err:?}"
    );
    let ffi_err = alice
        .orchestrator
        .mls_context()
        .decrypt_message(group_id_bytes.clone(), probe)
        .map(|_| ())
        .expect_err("foreign public-message commit must not process (FFI)");
    assert!(
        matches!(ffi_err, MLSError::DecryptionFailed),
        "FFI decrypt_message must keep flattening to DecryptionFailed, got: {ffi_err:?}"
    );

    // Three distinct peer-bad frames within the framing window trip
    // Signal D (RepeatedFramingFailures).
    for i in 0..3 {
        let ct = foreign.commit_message();
        let result = alice
            .orchestrator
            .process_incoming(&envelope(&group_id, ct, &format!("peer-bad-{i}")))
            .await;
        assert!(
            result.is_err(),
            "peer-bad frame #{i} must surface an error, got: {result:?}"
        );
    }

    let q = alice
        .orchestrator
        .get_conversation_quarantine_state(&group_id)
        .await
        .expect("three real peer-bad frames must enter Layer-3 quarantine");
    assert_eq!(
        q.reason,
        QuarantineReason::RepeatedFramingFailures,
        "quarantine must be entered via Signal D (distinct framing failures)"
    );

    // Peer-bad classification must NOT have armed the self-recovery cascade.
    assert!(
        !alice.storage.needs_rejoin(&group_id).await.unwrap(),
        "peer-bad frames must not set the rejoin flag"
    );
    assert_eq!(
        world.delivery_service().external_commit_count(&group_id),
        0,
        "peer-bad frames must not trigger External Commits"
    );
}

// ---------------------------------------------------------------------------
// 3. Normal traffic is unaffected by the typed classification
// ---------------------------------------------------------------------------

/// Garbage that fails before OpenMLS processing (TLS deserialization) keeps
/// its legacy non-peer-bad classification: it counts toward ordinary decrypt
/// failures (fork/rejoin path), NOT quarantine.
#[tokio::test(flavor = "multi_thread")]
async fn test_pre_process_garbage_still_not_peer_bad() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Garbage Classification Test", None, None)
        .await
        .expect("create_group failed");
    let group_id = convo.group_id.clone();

    for i in 0..3 {
        let result = alice
            .orchestrator
            .process_incoming(&envelope(
                &group_id,
                format!("not-an-mls-message-{i}").into_bytes(),
                &format!("garbage-{i}"),
            ))
            .await;
        assert!(result.is_err(), "garbage frame #{i} must error");
    }

    assert!(
        alice
            .orchestrator
            .get_conversation_quarantine_state(&group_id)
            .await
            .is_none(),
        "pre-process garbage (SerializationError) must not enter quarantine — \
         it is ambiguous, not peer-bad"
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn test_own_message_becomes_rust_only_outcome_before_credential_extraction() {
    use catbird_mls::orchestrator::MlsDecryptOutcome;

    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Own Echo Test", None, None)
        .await
        .expect("create_group failed");
    let group_id_bytes = hex::decode(&convo.group_id).expect("valid hex group_id");

    // Alice encrypts an application message
    let encrypted = alice
        .orchestrator
        .mls_context()
        .encrypt_message(group_id_bytes.clone(), b"hello from self".to_vec())
        .expect("encrypt_message failed");

    // 1. Rust-internal outcome seam: decrypt_message_outcome returns OwnPrivateMessage
    let outcome = alice
        .orchestrator
        .mls_context()
        .decrypt_message_outcome(group_id_bytes.clone(), encrypted.ciphertext.clone())
        .expect("decrypt_message_outcome must succeed for own private message");

    match outcome {
        MlsDecryptOutcome::OwnPrivateMessage {
            epoch,
            aad_sha256: _,
            ciphertext_sha256,
        } => {
            assert_eq!(epoch, 0, "own message is at epoch 0");
            assert_ne!(ciphertext_sha256, [0u8; 32]);
        }
        other => panic!("expected OwnPrivateMessage, got {other:?}"),
    }

    // 2. Exported FFI decrypt_message maps OwnPrivateMessage to DecryptionFailed
    let ffi_err = alice
        .orchestrator
        .mls_context()
        .decrypt_message(group_id_bytes.clone(), encrypted.ciphertext)
        .expect_err("FFI decrypt_message must fail for own private message");
    assert!(
        matches!(ffi_err, MLSError::DecryptionFailed),
        "FFI decrypt_message must map own message to MLSError::DecryptionFailed, got: {ffi_err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_own_pending_commit_becomes_rust_only_outcome_before_credential_extraction() {
    use catbird_mls::orchestrator::MlsDecryptOutcome;

    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    let _did = world.register_device("Alice").await.unwrap();

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Own Pending Commit Test", None, None)
        .await
        .expect("create_group failed");
    let group_id_bytes = hex::decode(&convo.group_id).expect("valid hex group_id");

    // Alice creates and stages a self-update commit locally (staged as pending_commit).
    let add_res = alice
        .orchestrator
        .mls_context()
        .self_update(group_id_bytes.clone())
        .expect("self_update failed");
    let commit_bytes = add_res.commit_data;

    // 1. Rust-internal outcome seam: decrypt_message_outcome returns OwnPendingCommit before credential extraction
    let outcome = alice
        .orchestrator
        .mls_context()
        .decrypt_message_outcome(group_id_bytes.clone(), commit_bytes.clone())
        .expect("decrypt_message_outcome must succeed for own pending commit");

    match outcome {
        MlsDecryptOutcome::OwnPendingCommit => {}
        other => panic!("expected OwnPendingCommit, got {other:?}"),
    }

    // 2. Exported FFI decrypt_message maps OwnPendingCommit to DecryptionFailed
    let ffi_err = alice
        .orchestrator
        .mls_context()
        .decrypt_message(group_id_bytes.clone(), commit_bytes.clone())
        .expect_err("FFI decrypt_message must fail for own pending commit");
    assert!(
        matches!(ffi_err, MLSError::DecryptionFailed),
        "FFI decrypt_message must map own pending commit to MLSError::DecryptionFailed, got: {ffi_err:?}"
    );
}

/// Regression for the explicit `process_commit` receive arms. The wildcard this
/// replaced mapped every non-`StagedCommitMessage` variant to `InvalidCommit`,
/// hiding the own outcomes. Both halves assert exactly one error class, so
/// collapsing the arms again fails this test.
#[tokio::test(flavor = "multi_thread")]
async fn test_process_commit_explicit_error_mapping_on_own_and_non_commit_variants() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    world.add_client("Bob").await;
    world.register_device("Bob").await.unwrap();

    let alice = world.client("Alice");
    let bob = world.client("Bob");
    let convo = alice
        .orchestrator
        .create_group("Process Commit Error Mapping Test", None, None)
        .await
        .expect("create_group failed");
    let group_id_bytes = hex::decode(&convo.group_id).expect("valid hex group_id");

    // 1. Own pending commit: the own arm must map to DecryptionFailed, never InvalidCommit.
    let staged = alice
        .orchestrator
        .mls_context()
        .self_update(group_id_bytes.clone())
        .expect("self_update failed");
    // `ProcessCommitResult` has no `Debug`, so unwrap the error by match.
    let own_err = match alice
        .orchestrator
        .mls_context()
        .process_commit(group_id_bytes.clone(), staged.commit_data)
    {
        Ok(_) => panic!("process_commit on own pending commit must fail"),
        Err(e) => e,
    };
    assert!(
        matches!(own_err, MLSError::DecryptionFailed),
        "process_commit on own pending commit must return exactly DecryptionFailed, got: {own_err:?}"
    );
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group_id_bytes.clone())
        .expect("merge_pending_commit failed");

    // 2. Ordinary non-commit content: Bob joins Alice's MLS group, so his
    //    application message really decrypts to `ApplicationMessage` on Alice's
    //    side instead of failing earlier as a foreign frame.
    let bob_key_package = bob
        .orchestrator
        .mls_context()
        .create_key_package(b"did:plc:bob#phone".to_vec())
        .expect("Bob create_key_package failed");
    let add = alice
        .orchestrator
        .mls_context()
        .add_members(
            group_id_bytes.clone(),
            vec![KeyPackageData {
                data: bob_key_package.key_package_data,
            }],
        )
        .expect("Alice add_members failed");
    alice
        .orchestrator
        .mls_context()
        .merge_pending_commit(group_id_bytes.clone())
        .expect("merge add_members commit failed");
    bob.orchestrator
        .mls_context()
        .process_welcome(add.welcome_data, b"did:plc:bob#phone".to_vec(), None)
        .expect("Bob process_welcome failed");

    let encrypted_by_bob = bob
        .orchestrator
        .mls_context()
        .encrypt_message(group_id_bytes.clone(), b"peer application message".to_vec())
        .expect("Bob encrypt_message failed");
    // Strip the 4-byte big-endian length prefix added by `pad_ciphertext`.
    let len = u32::from_be_bytes(encrypted_by_bob.ciphertext[0..4].try_into().unwrap()) as usize;
    let peer_application_message = encrypted_by_bob.ciphertext[4..4 + len].to_vec();

    let app_err = match alice
        .orchestrator
        .mls_context()
        .process_commit(group_id_bytes.clone(), peer_application_message)
    {
        Ok(_) => panic!("process_commit on a peer application message must fail"),
        Err(e) => e,
    };
    assert!(
        matches!(app_err, MLSError::InvalidCommit),
        "process_commit on peer application content must return exactly InvalidCommit, got: {app_err:?}"
    );
}
