//! Integration test for `MLSContext::create_group_with_id` (spec §8.5
//! first-responder bootstrap).
//!
//! Asserts that creating a group at a predetermined `group_id` produces an
//! `MlsGroup` whose `group_id()` matches the bytes the caller supplied bit-
//! for-bit. This is the load-bearing invariant for first-responder bootstrap:
//! every candidate creates an MLS group at the SAME id so the race winner's
//! Welcome message can be deserialized by every recipient — if `group_id`
//! drifted, race losers would be holding orphan local groups against the
//! winner's published Welcome.

#![allow(dead_code)]

#[path = "epoch_secret_test_support.rs"]
mod epoch_secret_test_support;
#[path = "mock_api_client.rs"]
mod mock_api_client;
#[path = "mock_credentials.rs"]
mod mock_credentials;
#[path = "mock_storage.rs"]
mod mock_storage;

use async_trait::async_trait;
use catbird_mls::orchestrator::{
    CommitKind, MLSOrchestrator, MLSStorageBackend, OrchestratorConfig,
};
use catbird_mls::{GroupConfig, KeychainAccess, MLSContext, MLSError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct TestKeychain {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
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

fn make_unconfigured_context() -> (Arc<MLSContext>, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "catbird_mls_create_group_with_id_test_{}_{}_{}",
        std::process::id(),
        id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.db").to_str().unwrap().to_string();
    let ctx = MLSContext::new(
        path,
        "test-key-1234567890123456".to_string(),
        Box::new(TestKeychain::new()),
    )
    .unwrap();
    (ctx, dir)
}

fn make_context() -> (Arc<MLSContext>, std::path::PathBuf) {
    let (ctx, dir) = make_unconfigured_context();
    epoch_secret_test_support::install(&ctx);
    (ctx, dir)
}

#[test]
fn create_group_with_id_uses_predetermined_bytes() {
    let (ctx, _dir) = make_context();

    // 32 bytes — the size of a hex-decoded `groupResetEvent.newGroupId`
    // (server emits a SHA-256-style identifier for the post-reset group).
    let predetermined = vec![
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18,
    ];

    let result = ctx
        .create_group_with_id(
            b"alice@example.com".to_vec(),
            predetermined.clone(),
            Some(GroupConfig::default()),
        )
        .expect("create_group_with_id should succeed");

    assert_eq!(
        result.group_id, predetermined,
        "MLSContext::create_group_with_id MUST return a group whose id matches the caller's bytes verbatim — race-loss recipients would otherwise reject the winner's Welcome"
    );

    // Sanity: the FFI epoch lookup is keyed on the same group_id we supplied.
    let epoch = ctx
        .get_epoch(predetermined)
        .expect("get_epoch should succeed for newly-created group");
    assert_eq!(epoch, 0, "newly-created group should be at epoch 0");
}

#[test]
fn create_group_without_id_still_uses_random_openmls_default() {
    // Backward-compat: existing `create_group(identity, config)` callers must
    // keep getting OpenMLS-generated random group_ids. Regression guard for
    // the create_group_internal refactor that routes both paths through one
    // implementation.
    let (ctx, _dir) = make_context();

    let result_a = ctx
        .create_group(b"alice@example.com".to_vec(), Some(GroupConfig::default()))
        .expect("create_group should succeed");
    let result_b = ctx
        .create_group(b"bob@example.com".to_vec(), Some(GroupConfig::default()))
        .expect("create_group should succeed");

    assert_ne!(
        result_a.group_id, result_b.group_id,
        "two separate create_group calls must produce different random ids"
    );
    assert!(
        !result_a.group_id.is_empty(),
        "OpenMLS should always pick a non-empty random id"
    );
}

#[test]
fn create_group_with_id_two_calls_at_same_id_are_rejected_by_storage() {
    // Sanity check: OpenMLS storage can't hold two groups at the same id in
    // the same MLSContext. This isn't the production race-loss path (the
    // server's bootstrapResetGroup returns 409 AlreadyBootstrapped BEFORE
    // we'd hit local storage on subsequent attempts — see mls-ds task #17 /
    // catbird-mls task #18), but it documents that local storage is also
    // collision-safe — race losers should always `delete_group(predetermined)`
    // after seeing the 409, never assume the local entry was magically
    // cleaned up.
    let (ctx, _dir) = make_context();

    let predetermined = vec![0xff; 32];

    let first = ctx.create_group_with_id(
        b"alice@example.com".to_vec(),
        predetermined.clone(),
        Some(GroupConfig::default()),
    );
    assert!(first.is_ok(), "first create_group_with_id should succeed");

    let second = ctx.create_group_with_id(
        b"alice@example.com".to_vec(),
        predetermined.clone(),
        Some(GroupConfig::default()),
    );
    assert!(
        second.is_err(),
        "second create_group_with_id at the same id MUST fail (local storage collision); race losers must delete_group before retrying"
    );
}

#[test]
fn failed_deterministic_create_rolls_back_and_retry_succeeds_after_storage_install() {
    let (ctx, _dir) = make_unconfigured_context();
    let predetermined = vec![0xa5; 32];

    let error = match ctx.create_group_with_id(
        b"alice@example.com".to_vec(),
        predetermined.clone(),
        Some(GroupConfig::default()),
    ) {
        Ok(_) => panic!("group creation without epoch-secret storage must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, MLSError::StorageFailed));
    assert!(
        !ctx.group_exists(predetermined.clone()),
        "failed creation must not publish the group in memory"
    );

    epoch_secret_test_support::install(&ctx);
    let retried = ctx
        .create_group_with_id(
            b"alice@example.com".to_vec(),
            predetermined.clone(),
            Some(GroupConfig::default()),
        )
        .expect("rollback must remove persisted state so the same deterministic id can be retried");

    assert_eq!(retried.group_id, predetermined);
}

#[test]
fn direct_discard_preserves_handle_when_crypto_cleanup_fails() {
    let (alice, _alice_dir) = make_context();
    let (bob, _bob_dir) = make_context();
    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(GroupConfig::default()))
        .unwrap();
    let bob_key_package = bob.create_key_package(b"did:plc:bob".to_vec()).unwrap();

    let plan = alice
        .stage_commit(
            hex::encode(&created.group_id),
            catbird_mls::orchestrator_bridge::FFICommitKind::AddMembers {
                member_dids: vec!["did:plc:bob".to_string()],
                key_packages: vec![bob_key_package.key_package_data],
            },
            b"did:plc:alice".to_vec(),
        )
        .expect("stage direct add-members commit");

    // Force `clear_pending_commit` to fail at the crypto layer. The first
    // discard must surface that error without consuming the exact handle.
    alice.set_suspended(true);
    assert!(
        alice.discard_pending(plan.handle.clone()).is_err(),
        "crypto cleanup failure must be returned to the direct caller"
    );

    alice.set_suspended(false);
    alice
        .discard_pending(plan.handle.clone())
        .expect("the preserved handle must remain retryable after crypto recovers");
    assert!(
        alice.discard_pending(plan.handle).is_err(),
        "a handle is consumed only after successful crypto cleanup"
    );
}

#[test]
fn direct_stage_rejects_substituted_add_did_before_openmls_and_allows_retry() {
    let (alice, _alice_dir) = make_context();
    let (mallory, _mallory_dir) = make_context();
    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(GroupConfig::default()))
        .unwrap();
    let mallory_key_package = mallory
        .create_key_package(b"did:plc:mallory#device-1".to_vec())
        .unwrap();
    let key_package_bytes = mallory_key_package.key_package_data;
    let group_id = hex::encode(&created.group_id);

    let error = match alice.stage_commit(
        group_id.clone(),
        catbird_mls::orchestrator_bridge::FFICommitKind::AddMembers {
            member_dids: vec!["did:plc:bob".to_string()],
            key_packages: vec![key_package_bytes.clone()],
        },
        b"did:plc:alice".to_vec(),
    ) {
        Ok(_) => panic!("Mallory's embedded DID root must not satisfy Bob's authority"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("do not exactly match"),
        "the direct API must report exact credential-root binding failure: {error}"
    );
    assert_eq!(alice.get_epoch(created.group_id.clone()).unwrap(), 0);

    let valid = alice
        .stage_commit(
            group_id,
            catbird_mls::orchestrator_bridge::FFICommitKind::AddMembers {
                member_dids: vec!["did:plc:mallory".to_string()],
                key_packages: vec![key_package_bytes],
            },
            b"did:plc:alice".to_vec(),
        )
        .expect("a matching bare DID root must remain a valid direct add");
    alice
        .discard_pending(valid.handle)
        .expect("binding rejection must leave no pending OpenMLS commit");
}

#[test]
fn direct_stage_rejects_substituted_swap_did_before_openmls_and_allows_retry() {
    let (alice, _alice_dir) = make_context();
    let (bob, _bob_dir) = make_context();
    let (mallory, _mallory_dir) = make_context();
    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(GroupConfig::default()))
        .unwrap();
    let group_id = hex::encode(&created.group_id);

    let bob_key_package = bob
        .create_key_package(b"did:plc:bob#device-1".to_vec())
        .unwrap();
    let add_bob = alice
        .stage_commit(
            group_id.clone(),
            catbird_mls::orchestrator_bridge::FFICommitKind::AddMembers {
                member_dids: vec!["did:plc:bob".to_string()],
                key_packages: vec![bob_key_package.key_package_data],
            },
            b"did:plc:alice".to_vec(),
        )
        .expect("stage Bob add");
    alice
        .confirm_commit(add_bob.handle, add_bob.target_epoch)
        .expect("confirm Bob add");

    let mallory_key_package = mallory
        .create_key_package(b"did:plc:mallory#device-1".to_vec())
        .unwrap();
    let key_package_bytes = mallory_key_package.key_package_data;
    let source_epoch = alice.get_epoch(created.group_id.clone()).unwrap();

    let error = match alice.stage_commit(
        group_id.clone(),
        catbird_mls::orchestrator_bridge::FFICommitKind::SwapMembers {
            remove_dids: vec!["did:plc:bob".to_string()],
            add_dids: vec!["did:plc:eve".to_string()],
            add_key_packages: vec![key_package_bytes.clone()],
        },
        b"did:plc:alice".to_vec(),
    ) {
        Ok(_) => panic!("Mallory's embedded DID root must not satisfy Eve's authority"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("do not exactly match"));
    assert_eq!(
        alice.get_epoch(created.group_id).unwrap(),
        source_epoch,
        "a rejected swap must not advance or partially mutate the group"
    );

    let valid = alice
        .stage_commit(
            group_id,
            catbird_mls::orchestrator_bridge::FFICommitKind::SwapMembers {
                remove_dids: vec!["did:plc:bob".to_string()],
                add_dids: vec!["did:plc:mallory".to_string()],
                add_key_packages: vec![key_package_bytes],
            },
            b"did:plc:alice".to_vec(),
        )
        .expect("a matching bare DID root must remain a valid direct swap");
    alice
        .discard_pending(valid.handle)
        .expect("binding rejection must leave no pending OpenMLS commit");
}

#[test]
fn direct_group_info_export_failure_clears_untracked_commit_and_allows_retry() {
    let (alice, _alice_dir) = make_context();
    let (bob, _bob_dir) = make_context();
    let created = alice
        .create_group(b"did:plc:alice".to_vec(), Some(GroupConfig::default()))
        .unwrap();
    let group_id = hex::encode(&created.group_id);
    let bob_key_package = bob
        .create_key_package(b"did:plc:bob#device-1".to_vec())
        .unwrap();
    let key_package_bytes = bob_key_package.key_package_data;

    let error = match alice.stage_commit(
        group_id.clone(),
        catbird_mls::orchestrator_bridge::FFICommitKind::AddMembers {
            member_dids: vec!["did:plc:bob".to_string()],
            key_packages: vec![key_package_bytes.clone()],
        },
        b"did:plc:unknown-signer".to_vec(),
    ) {
        Ok(_) => panic!("GroupInfo export with an unknown signer must fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("Signer not found"),
        "the primary GroupInfo failure must be preserved when cleanup succeeds: {error}"
    );
    assert_eq!(alice.get_epoch(created.group_id).unwrap(), 0);

    let retried = alice
        .stage_commit(
            group_id,
            catbird_mls::orchestrator_bridge::FFICommitKind::AddMembers {
                member_dids: vec!["did:plc:bob".to_string()],
                key_packages: vec![key_package_bytes],
            },
            b"did:plc:alice".to_vec(),
        )
        .expect("failed GroupInfo export must clear the untracked pending commit");
    alice
        .discard_pending(retried.handle)
        .expect("successful retry remains explicitly discardable");
}

#[tokio::test(flavor = "multi_thread")]
async fn orchestrator_group_info_export_failure_clears_untracked_commit_and_allows_retry() {
    const AUTHENTICATED_DID: &str = "did:plc:authenticated-non-signer";
    const GROUP_SIGNER_DID: &[u8] = b"did:plc:group-signer";
    const CONVERSATION_ID: &str = "group-info-export-cleanup";

    let (context, _dir) = make_context();
    let created = context
        .create_group(GROUP_SIGNER_DID.to_vec(), Some(GroupConfig::default()))
        .expect("create group under a different signer identity");
    let group_id = hex::encode(&created.group_id);

    let storage = mock_storage::MockStorage::new();
    storage
        .ensure_conversation_exists(AUTHENTICATED_DID, CONVERSATION_ID, &group_id)
        .await
        .expect("persist stable conversation/group binding");
    let api = mock_api_client::MockDeliveryService::new(AUTHENTICATED_DID);
    let credentials = mock_credentials::MockCredentials::new();
    let orchestrator = MLSOrchestrator::new(
        context.clone(),
        Arc::new(storage),
        Arc::new(api),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator
        .initialize(AUTHENTICATED_DID)
        .await
        .expect("initialize orchestrator under the non-signer DID");
    let own_commits_before = orchestrator.own_commits().lock().await.len();

    let error = match orchestrator
        .stage_commit(
            CONVERSATION_ID,
            CommitKind::UpdateMetadata {
                group_info_extension: Vec::new(),
            },
        )
        .await
    {
        Ok(_) => panic!("GroupInfo export with the lifecycle DID missing a signer must fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("Signer not found"),
        "cleanup success must preserve the primary export error: {error}"
    );
    assert_eq!(
        orchestrator.own_commits().lock().await.len(),
        own_commits_before,
        "failed export must not publish own-commit tracking"
    );
    assert_eq!(context.get_epoch(created.group_id).unwrap(), 0);

    let retry = context
        .stage_commit(
            group_id,
            catbird_mls::orchestrator_bridge::FFICommitKind::UpdateMetadata {
                group_info_extension: Vec::new(),
            },
            GROUP_SIGNER_DID.to_vec(),
        )
        .expect("orchestrator export failure must clear the OpenMLS pending commit");
    context
        .discard_pending(retry.handle)
        .expect("the valid retry must remain explicitly discardable");
}
