//! Regression coverage for the two-phase inbound proposal authorization path.
//!
//! A standalone proposal is authenticated by MLS during decrypt, but its outer
//! sender DID is bound by the orchestrator afterwards. The proposal must not be
//! visible to OpenMLS's commit queue in that interval.

#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use async_trait::async_trait;
use catbird_mls::orchestrator::MlsCryptoContext;
use catbird_mls::{
    DecryptContentType, KeyPackageData, KeychainAccess, MLSContext, MLSError, ProcessedContent,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct TestKeychain {
    values: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.values.lock().unwrap().get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.values.lock().unwrap().insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.values.lock().unwrap().remove(&key);
        Ok(())
    }
}

fn context() -> (Arc<MLSContext>, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let context = MLSContext::new(
        directory
            .path()
            .join("mls.db")
            .to_string_lossy()
            .to_string(),
        "proposal-authorization-test-key".to_string(),
        Box::new(TestKeychain::default()),
    )
    .unwrap();
    epoch_secret_test_support::install(&context);
    (context, directory)
}

fn two_member_group() -> (
    Arc<MLSContext>,
    Arc<MLSContext>,
    Vec<u8>,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let (alice, alice_directory) = context();
    let (bob, bob_directory) = context();
    let created = alice
        .create_group(b"did:plc:alice#phone".to_vec(), None)
        .unwrap();
    let group_id = created.group_id;
    let bob_key_package = bob
        .create_key_package(b"did:plc:bob#phone".to_vec())
        .unwrap();
    let add = alice
        .add_members(
            group_id.clone(),
            vec![KeyPackageData {
                data: bob_key_package.key_package_data,
            }],
        )
        .unwrap();
    alice.merge_pending_commit(group_id.clone()).unwrap();
    bob.process_welcome(add.welcome_data, b"did:plc:bob#phone".to_vec(), None)
        .unwrap();
    (alice, bob, group_id, alice_directory, bob_directory)
}

fn three_member_group() -> (
    Arc<MLSContext>,
    Arc<MLSContext>,
    Arc<MLSContext>,
    Vec<u8>,
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let (alice, alice_directory) = context();
    let (bob, bob_directory) = context();
    let (carol, carol_directory) = context();
    let created = alice
        .create_group(b"did:plc:alice#phone".to_vec(), None)
        .unwrap();
    let group_id = created.group_id;
    let bob_key_package = bob
        .create_key_package(b"did:plc:bob#phone".to_vec())
        .unwrap();
    let carol_key_package = carol
        .create_key_package(b"did:plc:carol#phone".to_vec())
        .unwrap();
    let add = alice
        .add_members(
            group_id.clone(),
            vec![
                KeyPackageData {
                    data: bob_key_package.key_package_data,
                },
                KeyPackageData {
                    data: carol_key_package.key_package_data,
                },
            ],
        )
        .unwrap();
    alice.merge_pending_commit(group_id.clone()).unwrap();
    bob.process_welcome(
        add.welcome_data.clone(),
        b"did:plc:bob#phone".to_vec(),
        None,
    )
    .unwrap();
    carol
        .process_welcome(add.welcome_data, b"did:plc:carol#phone".to_vec(), None)
        .unwrap();
    (
        alice,
        bob,
        carol,
        group_id,
        alice_directory,
        bob_directory,
        carol_directory,
    )
}

#[test]
fn decrypted_proposal_is_not_committable_until_explicit_acceptance() {
    let (alice, bob, group_id, _alice_directory, _bob_directory) = two_member_group();
    let proposal_message = bob.propose_self_remove(group_id.clone()).unwrap();

    let decrypted =
        MlsCryptoContext::decrypt_message(alice.as_ref(), group_id.clone(), proposal_message)
            .unwrap();
    assert_eq!(decrypted.content_type, DecryptContentType::Proposal);
    let proposal_ref = decrypted
        .proposal_ref
        .expect("member proposal must return its exact authorization handle");
    assert!(
        alice
            .list_pending_proposals(group_id.clone())
            .unwrap()
            .is_empty(),
        "decrypt alone must not publish a proposal into OpenMLS"
    );
    assert!(matches!(
        alice.commit_pending_proposals(group_id.clone()),
        Err(MLSError::InvalidInput { .. })
    ));

    let mut wrong_ref = proposal_ref.clone();
    *wrong_ref.last_mut().unwrap() ^= 1;
    assert!(matches!(
        MlsCryptoContext::accept_incoming_proposal(alice.as_ref(), group_id.clone(), wrong_ref,),
        Err(MLSError::InvalidProposalRef)
    ));

    MlsCryptoContext::accept_incoming_proposal(
        alice.as_ref(),
        group_id.clone(),
        proposal_ref.clone(),
    )
    .unwrap();
    let queued = alice.list_pending_proposals(group_id.clone()).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].data, proposal_ref);
    assert!(
        !alice.commit_pending_proposals(group_id).unwrap().is_empty(),
        "an explicitly accepted proposal must become committable"
    );
}

#[test]
fn rejected_proposal_is_discarded_without_touching_openmls_store() {
    let (alice, bob, group_id, _alice_directory, _bob_directory) = two_member_group();
    let proposal_message = bob.propose_self_remove(group_id.clone()).unwrap();
    let decrypted =
        MlsCryptoContext::decrypt_message(alice.as_ref(), group_id.clone(), proposal_message)
            .unwrap();
    let proposal_ref = decrypted.proposal_ref.unwrap();

    MlsCryptoContext::discard_incoming_proposal(
        alice.as_ref(),
        group_id.clone(),
        proposal_ref.clone(),
    )
    .unwrap();
    // Discard is intentionally idempotent for error-cleanup paths.
    MlsCryptoContext::discard_incoming_proposal(alice.as_ref(), group_id.clone(), proposal_ref)
        .unwrap();

    assert!(alice
        .list_pending_proposals(group_id.clone())
        .unwrap()
        .is_empty());
    assert!(matches!(
        alice.commit_pending_proposals(group_id),
        Err(MLSError::InvalidInput { .. })
    ));
}

#[test]
fn distinct_same_epoch_commit_cannot_replace_first_authorized_stage() {
    let (alice, bob, carol, group_id, _alice_directory, _bob_directory, _carol_directory) =
        three_member_group();
    let source_epoch = alice.get_epoch(group_id.clone()).unwrap();

    // Bob and Carol independently create valid commits from the same source
    // epoch. Both therefore target the same next epoch but represent different
    // authenticated state transitions.
    let bob_commit = bob.self_update(group_id.clone()).unwrap().commit_data;
    let carol_commit = carol.self_update(group_id.clone()).unwrap().commit_data;
    assert_ne!(bob_commit, carol_commit);

    let first = alice.process_message(group_id.clone(), bob_commit).unwrap();
    let target_epoch = match first {
        ProcessedContent::StagedCommit { new_epoch, .. } => new_epoch,
        _ => panic!("Bob's self-update must produce a staged commit"),
    };
    assert_eq!(target_epoch, source_epoch + 1);

    assert!(matches!(
        alice.process_message(group_id.clone(), carol_commit),
        Err(MLSError::InvalidCommit)
    ));
    assert_eq!(
        alice.get_epoch(group_id.clone()).unwrap(),
        source_epoch,
        "rejecting the colliding commit must not advance local crypto state"
    );

    // The collision must preserve Bob's original staged object. Merge it and
    // prove Alice interoperates with Bob's corresponding post-commit state.
    assert_eq!(
        alice
            .merge_incoming_commit(group_id.clone(), target_epoch)
            .unwrap(),
        target_epoch
    );
    bob.merge_pending_commit(group_id.clone()).unwrap();
    let probe = bob
        .encrypt_message(group_id.clone(), b"first commit preserved".to_vec())
        .unwrap();
    match alice.process_message(group_id, probe.ciphertext).unwrap() {
        ProcessedContent::ApplicationMessage { plaintext, .. } => {
            assert_eq!(plaintext, b"first commit preserved")
        }
        _ => panic!("post-commit probe must decrypt as an application message"),
    }
}
