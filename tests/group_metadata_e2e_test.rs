//! E2E test: Two-user metadata visibility via Welcome
//!
//! Alice creates a group with metadata, adds Bob via Welcome, and verifies
//! Bob can read the same metadata after processing the Welcome message.

use async_trait::async_trait;
use catbird_mls::group_metadata::GroupMetadata;
use catbird_mls::metadata::MetadataReference;
use catbird_mls::{GroupConfig, KeyPackageData, KeychainAccess, MLSContext, MLSError};
use std::collections::HashMap;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// In-memory keychain for tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn test_metadata_visible_to_joiner_via_welcome() {
    // -- Setup: two separate MLS contexts with isolated storage --
    let alice_dir = tempfile::tempdir().expect("failed to create alice temp dir");
    let bob_dir = tempfile::tempdir().expect("failed to create bob temp dir");

    let enc_key = "test-encryption-key!"; // >= 16 bytes

    let alice_db = alice_dir.path().join("mls.db");
    let bob_db = bob_dir.path().join("mls.db");

    let alice_ctx = MLSContext::new(
        alice_db.to_str().unwrap().to_string(),
        enc_key.to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("alice context creation failed");

    let bob_ctx = MLSContext::new(
        bob_db.to_str().unwrap().to_string(),
        enc_key.to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("bob context creation failed");

    let alice_identity = b"did:plc:alice".to_vec();
    let bob_identity = b"did:plc:bob".to_vec();

    // 1. Alice creates a group with metadata
    let config = GroupConfig {
        group_name: Some("Secret Club".to_string()),
        group_description: Some("Members only".to_string()),
        ..Default::default()
    };

    let group_result = alice_ctx
        .create_group(alice_identity.clone(), Some(config.clone()))
        .expect("alice create_group failed");
    let group_id = group_result.group_id;

    // 2. Verify Alice can read her own metadata
    let alice_meta_bytes = alice_ctx
        .get_group_metadata(group_id.clone())
        .expect("alice get_group_metadata failed");
    assert!(
        !alice_meta_bytes.is_empty(),
        "Alice metadata should not be empty"
    );

    let alice_meta = GroupMetadata::from_extension_bytes(&alice_meta_bytes)
        .expect("failed to parse alice metadata");
    assert_eq!(alice_meta.name.as_deref(), Some("Secret Club"));
    assert_eq!(alice_meta.description.as_deref(), Some("Members only"));

    // 3. Bob creates a key package
    let bob_kp = bob_ctx
        .create_key_package(bob_identity.clone())
        .expect("bob create_key_package failed");

    // 4. Alice adds Bob
    let add_result = alice_ctx
        .add_members(
            group_id.clone(),
            vec![KeyPackageData {
                data: bob_kp.key_package_data,
            }],
        )
        .expect("alice add_members failed");

    // 5. Alice merges her pending commit
    let _epoch = alice_ctx
        .merge_pending_commit(group_id.clone())
        .expect("alice merge_pending_commit failed");

    // 6. Bob processes the Welcome message
    let welcome_result = bob_ctx
        .process_welcome(add_result.welcome_data, bob_identity.clone(), Some(config))
        .expect("bob process_welcome failed");

    assert_eq!(
        welcome_result.group_id, group_id,
        "Bob's group_id should match Alice's"
    );

    // 7. Bob reads metadata — should see "Secret Club" and "Members only"
    let joined_group_id = welcome_result.group_id.clone();

    let bob_meta_bytes = bob_ctx
        .get_group_metadata(joined_group_id.clone())
        .expect("bob get_group_metadata failed");
    assert!(
        !bob_meta_bytes.is_empty(),
        "Bob metadata should not be empty"
    );

    let bob_meta =
        GroupMetadata::from_extension_bytes(&bob_meta_bytes).expect("failed to parse bob metadata");
    assert_eq!(
        bob_meta.name.as_deref(),
        Some("Secret Club"),
        "Bob should see group name 'Secret Club'"
    );
    assert_eq!(
        bob_meta.description.as_deref(),
        Some("Members only"),
        "Bob should see group description 'Members only'"
    );

    // 8. Bob can derive the current metadata key and should now receive the
    // MetadataReference from the group's AppDataDictionary.
    let bob_current_metadata = bob_ctx
        .get_current_metadata(joined_group_id)
        .expect("bob get_current_metadata failed")
        .expect("bob current metadata should be derivable after Welcome");

    assert_eq!(
        bob_current_metadata.epoch, 1,
        "Bob should be at epoch 1 after Welcome"
    );
    assert_eq!(
        bob_current_metadata.metadata_key.len(),
        32,
        "Metadata key should be a 32-byte exporter-derived key"
    );
    let reference_json = bob_current_metadata
        .metadata_reference_json
        .expect("Welcome joiner should receive MetadataReference from AppDataDictionary");
    let reference: MetadataReference =
        serde_json::from_slice(&reference_json).expect("failed to decode MetadataReference");
    assert_eq!(reference.metadata_version, 1);
    assert!(
        !reference.blob_locator.is_empty(),
        "MetadataReference should carry a blob locator"
    );
}

#[test]
fn test_metadata_reference_present_on_incoming_metadata_update_commit() {
    let alice_dir = tempfile::tempdir().expect("failed to create alice temp dir");
    let bob_dir = tempfile::tempdir().expect("failed to create bob temp dir");

    let enc_key = "test-encryption-key!";
    let alice_db = alice_dir.path().join("mls.db");
    let bob_db = bob_dir.path().join("mls.db");

    let alice_ctx = MLSContext::new(
        alice_db.to_str().unwrap().to_string(),
        enc_key.to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("alice context creation failed");
    let bob_ctx = MLSContext::new(
        bob_db.to_str().unwrap().to_string(),
        enc_key.to_string(),
        Box::new(TestKeychain::new()),
    )
    .expect("bob context creation failed");

    let alice_identity = b"did:plc:alice".to_vec();
    let bob_identity = b"did:plc:bob".to_vec();

    let config = GroupConfig {
        group_name: Some("Secret Club".to_string()),
        group_description: Some("Members only".to_string()),
        ..Default::default()
    };

    let group_result = alice_ctx
        .create_group(alice_identity.clone(), Some(config.clone()))
        .expect("alice create_group failed");
    let group_id = group_result.group_id;

    let bob_kp = bob_ctx
        .create_key_package(bob_identity.clone())
        .expect("bob create_key_package failed");

    let add_result = alice_ctx
        .add_members(
            group_id.clone(),
            vec![KeyPackageData {
                data: bob_kp.key_package_data,
            }],
        )
        .expect("alice add_members failed");

    alice_ctx
        .merge_pending_commit(group_id.clone())
        .expect("alice merge_pending_commit failed");

    bob_ctx
        .process_welcome(add_result.welcome_data, bob_identity, Some(config))
        .expect("bob process_welcome failed");

    let updated_metadata = GroupMetadata::new(
        Some("Renamed Club".to_string()),
        Some("Still members only".to_string()),
    );
    let commit_bytes = alice_ctx
        .update_group_metadata(
            group_id.clone(),
            updated_metadata.to_extension_bytes().unwrap(),
        )
        .expect("alice update_group_metadata failed");

    let processed_commit = bob_ctx
        .process_commit(group_id.clone(), commit_bytes)
        .expect("bob process_commit failed");

    let commit_metadata = processed_commit
        .commit_metadata
        .expect("incoming commit should derive metadata key");
    let reference_json = commit_metadata
        .metadata_reference_json
        .expect("incoming commit should carry MetadataReference");
    let reference: MetadataReference =
        serde_json::from_slice(&reference_json).expect("failed to decode MetadataReference");
    assert_eq!(reference.metadata_version, 2);
    assert!(
        !reference.blob_locator.is_empty(),
        "updated commit should carry a blob locator"
    );

    let bob_meta_bytes = bob_ctx
        .get_group_metadata(group_id.clone())
        .expect("bob get_group_metadata failed");
    let bob_meta =
        GroupMetadata::from_extension_bytes(&bob_meta_bytes).expect("failed to parse bob metadata");
    assert_eq!(bob_meta.name.as_deref(), Some("Renamed Club"));
    assert_eq!(bob_meta.description.as_deref(), Some("Still members only"));

    let bob_current_metadata = bob_ctx
        .get_current_metadata(group_id)
        .expect("bob get_current_metadata failed")
        .expect("bob current metadata should still be derivable");
    assert!(
        bob_current_metadata.metadata_reference_json.is_some(),
        "current metadata should retain the committed MetadataReference"
    );
}
