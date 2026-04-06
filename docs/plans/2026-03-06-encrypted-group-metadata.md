# Encrypted Group Metadata via MLS Group Context Extensions

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Store encrypted group title, description, and avatar hash in MLS group context extensions so the server never sees plaintext metadata and late joiners get it automatically.

**Architecture:** Use OpenMLS 0.8's `Extension::Unknown(0xff00, UnknownExtension(bytes))` to embed a JSON-serialized metadata blob in the MLS group context. Metadata is set at group creation via `MlsGroupCreateConfig::builder().with_group_context_extensions()` and updated via `MlsGroup::update_group_context_extensions()`. The server processes commits as opaque blobs — zero server changes needed. Every member (including late joiners via Welcome or External Commit) reads metadata from `group.context().extensions()`.

**Tech Stack:** Rust (OpenMLS 0.8, serde_json), Swift (UniFFI), SvelteKit/WASM (catmos-web)

---

## Extension Type Convention

We use a single custom extension type ID for all group metadata:

```
const CATBIRD_METADATA_EXTENSION_TYPE: u16 = 0xff00;
```

The extension payload is JSON-encoded bytes:

```json
{
  "v": 1,
  "name": "Team Chat",
  "description": "Our secure group",
  "avatar_hash": "sha256:abc123..."
}
```

The `v` field allows future schema evolution without changing the extension type ID.

---

### Task 1: Add metadata serialization types to catbird-mls

**Files:**
- Create: `catbird-mls/src/group_metadata.rs`
- Modify: `catbird-mls/src/lib.rs` (add `pub mod group_metadata;`)

**Step 1: Create the metadata module**

```rust
// catbird-mls/src/group_metadata.rs

use openmls::prelude::*;
use serde::{Deserialize, Serialize};

/// Extension type ID for Catbird group metadata.
/// 0xff00 is in the private-use range per RFC 9420.
pub const CATBIRD_METADATA_EXTENSION_TYPE: u16 = 0xff00;

/// Encrypted group metadata stored in MLS group context extensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMetadata {
    /// Schema version (currently 1)
    pub v: u32,
    /// Group display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Group description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SHA-256 hash of the avatar image (hex-encoded), if set.
    /// Actual image bytes are stored/fetched separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_hash: Option<String>,
}

impl GroupMetadata {
    pub fn new(name: Option<String>, description: Option<String>) -> Self {
        Self {
            v: 1,
            name,
            description,
            avatar_hash: None,
        }
    }

    /// Serialize to JSON bytes for embedding in an MLS extension.
    pub fn to_extension_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from MLS extension bytes.
    pub fn from_extension_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Build an OpenMLS Extensions containing this metadata.
    pub fn to_extensions(&self) -> Result<Extensions<GroupContext>, String> {
        let bytes = self.to_extension_bytes().map_err(|e| e.to_string())?;
        Extensions::single(Extension::Unknown(
            CATBIRD_METADATA_EXTENSION_TYPE,
            UnknownExtension(bytes),
        ))
        .map_err(|e| format!("{:?}", e))
    }

    /// Extract metadata from an MLS group's context extensions.
    /// Returns None if the extension is not present.
    pub fn from_group(group: &MlsGroup) -> Option<Self> {
        for ext in group.context().extensions().iter() {
            if let Extension::Unknown(CATBIRD_METADATA_EXTENSION_TYPE, UnknownExtension(data)) = ext
            {
                return Self::from_extension_bytes(data).ok();
            }
        }
        None
    }
}
```

**Step 2: Register the module**

Modify `catbird-mls/src/lib.rs` — add alongside existing module declarations:

```rust
pub mod group_metadata;
```

**Step 3: Run tests to verify compilation**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo build`
Expected: Compiles with no errors

**Step 4: Write unit tests**

Append to `catbird-mls/src/group_metadata.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_serialize() {
        let meta = GroupMetadata {
            v: 1,
            name: Some("Team Chat".to_string()),
            description: Some("Our group".to_string()),
            avatar_hash: None,
        };
        let bytes = meta.to_extension_bytes().unwrap();
        let decoded = GroupMetadata::from_extension_bytes(&bytes).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn test_empty_metadata() {
        let meta = GroupMetadata::new(None, None);
        let bytes = meta.to_extension_bytes().unwrap();
        let decoded = GroupMetadata::from_extension_bytes(&bytes).unwrap();
        assert_eq!(decoded.v, 1);
        assert!(decoded.name.is_none());
    }

    #[test]
    fn test_to_extensions() {
        let meta = GroupMetadata::new(Some("Test".to_string()), None);
        let exts = meta.to_extensions().unwrap();
        // Should have exactly one extension
        assert_eq!(exts.iter().count(), 1);
    }

    #[test]
    fn test_skip_serializing_none() {
        let meta = GroupMetadata::new(Some("Test".to_string()), None);
        let json = String::from_utf8(meta.to_extension_bytes().unwrap()).unwrap();
        assert!(!json.contains("description"));
        assert!(!json.contains("avatar_hash"));
    }
}
```

**Step 5: Run tests**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo test group_metadata`
Expected: 4 tests pass

**Step 6: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add src/group_metadata.rs src/lib.rs
git commit -m "feat: add GroupMetadata type for MLS group context extensions"
```

---

### Task 2: Wire metadata into group creation (mls_context.rs)

**Files:**
- Modify: `catbird-mls/src/mls_context.rs:1726-1900` (create_group method)
- Modify: `catbird-mls/src/types.rs:162-181` (GroupConfig struct)

**Step 1: Add metadata fields to GroupConfig**

In `catbird-mls/src/types.rs`, add optional metadata fields to `GroupConfig`:

```rust
#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct GroupConfig {
    pub max_past_epochs: u32,
    pub out_of_order_tolerance: u32,
    pub maximum_forward_distance: u32,
    pub max_leaf_lifetime_seconds: u64,
    /// Optional group name (encrypted in MLS group context extension)
    pub group_name: Option<String>,
    /// Optional group description (encrypted in MLS group context extension)
    pub group_description: Option<String>,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            max_past_epochs: 5,
            out_of_order_tolerance: 10,
            maximum_forward_distance: 2000,
            max_leaf_lifetime_seconds: 86400 * 90,
            group_name: None,
            group_description: None,
        }
    }
}
```

**Step 2: Update create_group in mls_context.rs to set extensions**

In `catbird-mls/src/mls_context.rs`, modify the `create_group` method (around line 1779-1799). Replace the capabilities and config builder:

```rust
        use crate::group_metadata::{GroupMetadata, CATBIRD_METADATA_EXTENSION_TYPE};

        // Configure required capabilities — include ratchet tree AND our custom metadata extension
        let capabilities = Capabilities::new(
            None,
            None,
            Some(&[
                ExtensionType::RatchetTree,
                ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE),
            ]),
            None,
            None,
        );

        // Build group context extensions with metadata if name or description provided
        let mut group_config_builder = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .capabilities(capabilities)
            .use_ratchet_tree_extension(true);

        // Embed metadata in group context extensions
        if config.group_name.is_some() || config.group_description.is_some() {
            let metadata = GroupMetadata::new(
                config.group_name.clone(),
                config.group_description.clone(),
            );
            if let Ok(extensions) = metadata.to_extensions() {
                group_config_builder = group_config_builder
                    .with_group_context_extensions(extensions);
                crate::info_log!(
                    "[MLS-CONTEXT] Group metadata set: name={:?}",
                    config.group_name
                );
            }
        }

        let group_config = group_config_builder.build();
```

**Step 3: Build and run existing tests**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo test`
Expected: All existing tests still pass. GroupConfig default now has 2 extra None fields.

**Step 4: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add src/mls_context.rs src/types.rs
git commit -m "feat: embed GroupMetadata in MLS group context on creation"
```

---

### Task 3: Add get_group_metadata and update_group_metadata to MLSContext

**Files:**
- Modify: `catbird-mls/src/mls_context.rs` (add 2 new methods to `MLSContextInner`)
- Modify: `catbird-mls/src/api.rs` (expose via FFI wrapper `MLSContext`)

**Step 1: Add methods to MLSContextInner (mls_context.rs)**

Add after the existing `get_epoch` method (or any convenient location in `MLSContextInner impl`):

```rust
    /// Read group metadata from the MLS group context extensions.
    /// Returns None if no metadata extension is present.
    pub fn get_group_metadata(&self, group_id: &[u8]) -> Result<Option<crate::group_metadata::GroupMetadata>, MLSError> {
        let gid = GroupId::from_slice(group_id);
        self.with_group_ref(&gid, |group, _provider| {
            Ok(crate::group_metadata::GroupMetadata::from_group(group))
        })
    }

    /// Update group metadata by proposing + committing a GroupContextExtensions change.
    /// Returns the commit message bytes that must be sent to the server.
    /// Caller must call merge_pending_commit() after the server acknowledges.
    pub fn update_group_metadata(
        &mut self,
        group_id: &[u8],
        metadata: crate::group_metadata::GroupMetadata,
    ) -> Result<Vec<u8>, MLSError> {
        let gid = GroupId::from_slice(group_id);

        self.with_group(&gid, |group, provider, signer| {
            let extensions = metadata.to_extensions().map_err(|e| {
                MLSError::Internal(format!("Failed to build metadata extensions: {}", e))
            })?;

            let (commit_msg, _welcome, _group_info) = group
                .update_group_context_extensions(provider, extensions, signer)
                .map_err(|e| {
                    crate::error_log!("[MLS-CONTEXT] Failed to update group context extensions: {:?}", e);
                    MLSError::OpenMLSError
                })?;

            let commit_bytes = commit_msg
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("Failed to serialize commit: {:?}", e)))?;

            crate::info_log!(
                "[MLS-CONTEXT] Group metadata update committed, {} bytes",
                commit_bytes.len()
            );

            Ok(commit_bytes)
        })
    }
```

**Step 2: Expose via FFI in api.rs**

Add to the `impl MLSContext` block in `catbird-mls/src/api.rs`:

```rust
    /// Read encrypted group metadata from MLS group context.
    /// Returns JSON bytes of the metadata, or empty vec if none set.
    pub fn get_group_metadata(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        crate::info_log!("[MLS-FFI] get_group_metadata: {}", hex::encode(&group_id));

        let guard = self.inner.lock().map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        match inner.get_group_metadata(&group_id)? {
            Some(meta) => meta
                .to_extension_bytes()
                .map_err(|e| MLSError::Internal(format!("JSON serialize: {}", e))),
            None => Ok(Vec::new()),
        }
    }

    /// Update group metadata. Returns commit bytes to send to server.
    /// After server ACK, call merge_pending_commit().
    pub fn update_group_metadata(
        &self,
        group_id: Vec<u8>,
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        crate::info_log!("[MLS-FFI] update_group_metadata: {}", hex::encode(&group_id));

        let metadata = crate::group_metadata::GroupMetadata::from_extension_bytes(&metadata_json)
            .map_err(|e| MLSError::invalid_input(format!("Invalid metadata JSON: {}", e)))?;

        let mut guard = self.inner.lock().map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let commit_bytes = inner.update_group_metadata(&group_id, metadata)?;

        inner.flush_database().map_err(|e| {
            crate::error_log!("[MLS-FFI] Failed to flush after metadata update: {:?}", e);
            e
        })?;
        inner.maybe_truncate_checkpoint();

        Ok(commit_bytes)
    }
```

**Step 3: Build**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo build`
Expected: Compiles. Note: `tls_serialize_detached` requires `use tls_codec::Serialize as TlsSerializeTrait;` — add the import if needed.

**Step 4: Write integration test**

Create `catbird-mls/tests/group_metadata_test.rs`:

```rust
//! Integration test for group context extension metadata

use catbird_mls::api::MLSContext;
use catbird_mls::group_metadata::GroupMetadata;
use catbird_mls::types::GroupConfig;
use tempfile::TempDir;

fn make_context() -> (MLSContext, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    let ctx = MLSContext::new(path, "test-key-1234567890123456".to_string(), None).unwrap();
    (ctx, dir)
}

#[test]
fn test_create_group_with_metadata() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("My Group".to_string()),
        group_description: Some("A test group".to_string()),
        ..Default::default()
    };

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    // Read metadata back
    let meta_bytes = ctx.get_group_metadata(result.group_id.clone()).unwrap();
    assert!(!meta_bytes.is_empty(), "Metadata should be present");

    let meta = GroupMetadata::from_extension_bytes(&meta_bytes).unwrap();
    assert_eq!(meta.name.as_deref(), Some("My Group"));
    assert_eq!(meta.description.as_deref(), Some("A test group"));
    assert!(meta.avatar_hash.is_none());
}

#[test]
fn test_create_group_without_metadata() {
    let (ctx, _dir) = make_context();

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), None)
        .unwrap();

    let meta_bytes = ctx.get_group_metadata(result.group_id).unwrap();
    assert!(meta_bytes.is_empty(), "No metadata should be present");
}

#[test]
fn test_update_group_metadata() {
    let (ctx, _dir) = make_context();

    let config = GroupConfig {
        group_name: Some("Original".to_string()),
        ..Default::default()
    };

    let result = ctx
        .create_group(b"alice@example.com".to_vec(), Some(config))
        .unwrap();

    // Update metadata
    let new_meta = GroupMetadata::new(
        Some("Renamed Group".to_string()),
        Some("New description".to_string()),
    );
    let commit_bytes = ctx
        .update_group_metadata(
            result.group_id.clone(),
            new_meta.to_extension_bytes().unwrap(),
        )
        .unwrap();
    assert!(!commit_bytes.is_empty());

    // Merge the pending commit (simulating server ACK)
    ctx.merge_pending_commit(result.group_id.clone()).unwrap();

    // Read updated metadata
    let meta_bytes = ctx.get_group_metadata(result.group_id).unwrap();
    let meta = GroupMetadata::from_extension_bytes(&meta_bytes).unwrap();
    assert_eq!(meta.name.as_deref(), Some("Renamed Group"));
    assert_eq!(meta.description.as_deref(), Some("New description"));
}
```

**Step 5: Run integration test**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo test --test group_metadata_test`
Expected: 3 tests pass

**Step 6: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add src/mls_context.rs src/api.rs tests/group_metadata_test.rs
git commit -m "feat: add get/update_group_metadata FFI methods using group context extensions"
```

---

### Task 4: Wire metadata through the orchestrator layer

**Files:**
- Modify: `catbird-mls/src/orchestrator/groups.rs:24-92` (create_group)
- Modify: `catbird-mls/src/orchestrator/types.rs:14-44` (ConversationView, ConversationMetadata)

**Step 1: Update orchestrator create_group to pass metadata to MLS context**

In `catbird-mls/src/orchestrator/groups.rs`, modify `create_group` (lines ~46-51) to pass name/description into the MLS group config:

```rust
        // Create MLS group locally — with encrypted metadata in group context
        let identity_bytes = user_did.as_bytes().to_vec();
        let mut group_config = self.config().group_config.clone();
        if !name.is_empty() {
            group_config.group_name = Some(name.to_string());
        }
        if let Some(desc) = description {
            group_config.group_description = Some(desc.to_string());
        }
        let creation_result = self
            .mls_context()
            .create_group(identity_bytes, Some(group_config))?;
```

**Step 2: Add update_metadata method to orchestrator**

Add a new public method to the orchestrator `impl` block in `groups.rs`:

```rust
    /// Update encrypted group metadata (name, description, avatar_hash).
    /// Produces a commit that advances the epoch. Send commit to server
    /// via commitGroupChange, then merge locally.
    pub async fn update_group_metadata(
        &self,
        conversation_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        avatar_hash: Option<&str>,
    ) -> Result<()> {
        self.check_shutdown().await?;
        let _user_did = self.require_user_did().await?;

        let group_id = hex::decode(conversation_id)
            .map_err(|e| OrchestratorError::Internal(format!("Invalid group ID hex: {}", e)))?;

        let metadata = crate::group_metadata::GroupMetadata {
            v: 1,
            name: name.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            avatar_hash: avatar_hash.map(|s| s.to_string()),
        };

        let metadata_json = metadata
            .to_extension_bytes()
            .map_err(|e| OrchestratorError::Internal(format!("Metadata serialize: {}", e)))?;

        let commit_bytes = self
            .mls_context()
            .update_group_metadata(group_id.clone(), metadata_json)?;

        // Send commit to server (reuse existing commitGroupChange flow)
        self.api_client()
            .commit_group_change(conversation_id, &commit_bytes, "updateMetadata")
            .await?;

        // Merge pending commit locally
        self.mls_context().merge_pending_commit(group_id)?;

        // Update in-memory cache
        if let Some(convo) = self.conversations().lock().await.get_mut(conversation_id) {
            convo.metadata = Some(super::types::ConversationMetadata {
                name: name.map(|s| s.to_string()),
                description: description.map(|s| s.to_string()),
                avatar_url: None,
            });
        }

        // Persist group state
        let epoch = self.mls_context().get_epoch(hex::decode(conversation_id)
            .unwrap_or_default())?;
        if let Ok(Some(mut gs)) = self.storage().get_group_state(conversation_id).await {
            gs.epoch = epoch;
            let _ = self.storage().set_group_state(&gs).await;
        }

        tracing::info!(conversation_id, "Group metadata updated");
        Ok(())
    }

    /// Read decrypted group metadata from MLS group context.
    pub fn get_group_metadata(
        &self,
        conversation_id: &str,
    ) -> Result<Option<crate::group_metadata::GroupMetadata>> {
        let group_id = hex::decode(conversation_id)
            .map_err(|e| OrchestratorError::Internal(format!("Invalid group ID hex: {}", e)))?;

        let meta_bytes = self.mls_context().get_group_metadata(group_id)?;
        if meta_bytes.is_empty() {
            return Ok(None);
        }
        crate::group_metadata::GroupMetadata::from_extension_bytes(&meta_bytes)
            .map(Some)
            .map_err(|e| OrchestratorError::Internal(format!("Metadata deserialize: {}", e)))
    }
```

**Step 3: Check if commit_group_change exists on the API client trait**

The orchestrator needs to send the commit to the server. Check if `commit_group_change` (or equivalent) exists on `MLSAPIClient`. If not, you may need to reuse the existing `process_external_commit` or add a new trait method. The server's `commitGroupChange` handler already accepts arbitrary commit blobs with an `action` field.

If the trait method doesn't exist, add to `catbird-mls/src/orchestrator/api_client.rs`:

```rust
    /// Send a commit (e.g. metadata update) to the server.
    async fn commit_group_change(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        action: &str,
    ) -> Result<()> {
        // Default: no-op for backends that don't support it
        let _ = (convo_id, commit_data, action);
        Ok(())
    }
```

**Step 4: Build**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo build`
Expected: Compiles

**Step 5: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add src/orchestrator/groups.rs src/orchestrator/api_client.rs
git commit -m "feat: orchestrator update_group_metadata with commit_group_change flow"
```

---

### Task 5: Read metadata on incoming commits (process_message)

**Files:**
- Modify: `catbird-mls/src/mls_context.rs` (process_message path where GroupContextExtensions proposals are handled, ~line 2591)

**Context:** When another member updates metadata, the commit arrives via `process_message`. OpenMLS automatically applies the extension update when the commit is processed. We just need to ensure we read the updated metadata after processing.

**Step 1: Verify existing behavior**

The code at `mls_context.rs:2591` already recognizes `Proposal::GroupContextExtensions(_)` in pending proposals. When the commit containing this proposal is processed via `group.process_message()` + `group.merge_staged_commit()`, OpenMLS updates the group context extensions automatically.

No changes needed to the MLS processing path itself. The extensions are part of the group state and persist via OpenMLS's SQLite storage.

**Step 2: Add a helper to read metadata after processing incoming commits**

In the orchestrator's `process_incoming` method (`catbird-mls/src/orchestrator/messaging.rs`), after a commit is processed and merged, read and cache the updated metadata. Find the section where commit messages are handled (look for "commit" processing) and add after the merge:

```rust
// After processing a commit, check if metadata was updated
if let Ok(Some(meta)) = self.get_group_metadata(conversation_id) {
    if let Some(convo) = self.conversations().lock().await.get_mut(conversation_id) {
        convo.metadata = Some(ConversationMetadata {
            name: meta.name,
            description: meta.description,
            avatar_url: None,
        });
    }
}
```

**Step 3: Build and test**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo build`
Expected: Compiles

**Step 4: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add src/orchestrator/messaging.rs
git commit -m "feat: refresh cached metadata after processing incoming commits"
```

---

### Task 6: Expose metadata through UniFFI to Swift

**Files:**
- Modify: `catbird-mls/src/api.rs` (ensure `get_group_metadata` and `update_group_metadata` are `#[uniffi::export]` or equivalent)
- Modify: `catbird-mls/src/types.rs` (add UniFFI-compatible metadata struct if needed)

**Step 1: Check UniFFI export pattern**

Look at how existing methods like `create_group`, `get_epoch` are exported. The `MLSContext` struct is likely `#[derive(uniffi::Object)]`. Methods on it are automatically exported.

Verify the two new methods on `MLSContext` (`get_group_metadata`, `update_group_metadata`) follow the same pattern as other public methods — accepting and returning primitive types (`Vec<u8>`, `String`) that UniFFI can handle.

The current API uses `Vec<u8>` for metadata JSON bytes, which is UniFFI-compatible. No additional structs needed — Swift can deserialize the JSON bytes.

**Step 2: Rebuild FFI bindings**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/CatbirdMLSCore && ./Scripts/rebuild-ffi.sh`
Expected: Generates updated Swift bindings with `getGroupMetadata()` and `updateGroupMetadata()` methods

**Step 3: Verify the generated Swift methods exist**

Run: `grep -n "getGroupMetadata\|updateGroupMetadata" /Users/joshlacalamito/Developer/Catbird+Petrel/CatbirdMLSCore/Sources/CatbirdMLS/CatbirdMLS.swift`
Expected: Both methods present in generated bindings

**Step 4: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel
git add CatbirdMLSCore/Sources/CatbirdMLS/
git commit -m "feat: regenerate UniFFI bindings with group metadata methods"
```

---

### Task 7: Implement commit_group_change in catmos-web WasmApiClient

**Files:**
- Modify: `catmos/catmos-web/src/api_client.rs` (add `commit_group_change` method)

**Step 1: Implement the trait method**

Add to the `impl MLSAPIClient for WasmApiClient` block:

```rust
    async fn commit_group_change(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        action: &str,
    ) -> Result<()> {
        let token = self.auth_header()?;
        let input: lexicon::commit_group_change::Input =
            lexicon::commit_group_change::InputData {
                convo_id: convo_id.to_string(),
                commit: base64::engine::general_purpose::STANDARD.encode(commit_data),
                action: action.to_string(),
                welcome_message: None,
                idempotency_key: Some(uuid::Uuid::new_v4().to_string()),
            }
            .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }
```

**Step 2: Build WASM**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catmos/catmos-web && ./build-dev.sh`
Expected: Compiles

**Step 3: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catmos
git add catmos-web/src/api_client.rs
git commit -m "feat: implement commit_group_change for WasmApiClient"
```

---

### Task 8: Remove plaintext metadata from server flow

**Files:**
- Modify: `catbird-mls/src/orchestrator/groups.rs` (stop sending plaintext metadata to create_conversation)

**Step 1: Remove metadata from create_conversation API call**

In `groups.rs`, the `create_conversation` call currently sends `metadata.as_ref()`. Since metadata is now encrypted in the MLS group context, we should stop sending it plaintext to the server. Change:

```rust
        // Create conversation on server — metadata is now encrypted in MLS group context,
        // no need to send plaintext to server
        let result = self
            .api_client()
            .create_conversation(
                &group_id_hex,
                filtered_members_ref,
                None,  // metadata is in MLS extensions, not plaintext
                None,
                None,
            )
            .await
```

Remove the `metadata` variable construction block entirely (lines 80-92).

**Step 2: Build**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo build`
Expected: Compiles

**Step 3: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add src/orchestrator/groups.rs
git commit -m "feat: stop sending plaintext metadata to server (now encrypted in MLS extensions)"
```

---

### Task 9: Update catmos-web WASM exports for metadata

**Files:**
- Modify: `catmos/catmos-web/src/lib.rs` (add wasm_bindgen exports for metadata operations)

**Step 1: Add metadata WASM exports**

Add to `catmos/catmos-web/src/lib.rs`:

```rust
/// Get encrypted group metadata (decrypted locally from MLS group context).
/// Returns JSON string with { name, description, avatar_hash } or empty string if none.
#[wasm_bindgen]
pub async fn wasm_get_group_metadata(convo_id: String) -> Result<JsValue, JsValue> {
    let orchestrator = get_orchestrator()
        .await
        .map_err(|e| js_err!("No orchestrator: {:?}", e))?;

    match orchestrator.get_group_metadata(&convo_id) {
        Ok(Some(meta)) => {
            let json = serde_json::to_string(&meta)
                .map_err(|e| js_err!("JSON serialize: {:?}", e))?;
            Ok(JsValue::from_str(&json))
        }
        Ok(None) => Ok(JsValue::from_str("")),
        Err(e) => Err(js_err!("get_group_metadata failed: {:?}", e)),
    }
}

/// Update group metadata (encrypted in MLS group context).
#[wasm_bindgen]
pub async fn wasm_update_group_metadata(
    convo_id: String,
    name: Option<String>,
    description: Option<String>,
    avatar_hash: Option<String>,
) -> Result<JsValue, JsValue> {
    let orchestrator = get_orchestrator()
        .await
        .map_err(|e| js_err!("No orchestrator: {:?}", e))?;

    orchestrator
        .update_group_metadata(
            &convo_id,
            name.as_deref(),
            description.as_deref(),
            avatar_hash.as_deref(),
        )
        .await
        .map_err(|e| js_err!("update_group_metadata failed: {:?}", e))?;

    Ok(JsValue::from_str("ok"))
}
```

**Step 2: Build WASM**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catmos/catmos-web && ./build-dev.sh`
Expected: Compiles

**Step 3: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catmos
git add catmos-web/src/lib.rs
git commit -m "feat: expose group metadata get/update via WASM"
```

---

### Task 10: End-to-end test — two-user metadata visibility

**Files:**
- Create: `catbird-mls/tests/group_metadata_e2e_test.rs`

**Step 1: Write two-user E2E test**

This test creates two MLSContext instances (Alice and Bob), creates a group with metadata, adds Bob, and verifies Bob can read the metadata after joining via Welcome.

```rust
//! E2E test: metadata visible to second user after joining

use catbird_mls::api::MLSContext;
use catbird_mls::group_metadata::GroupMetadata;
use catbird_mls::types::GroupConfig;
use tempfile::TempDir;

fn make_context(name: &str) -> (MLSContext, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir
        .path()
        .join(format!("{}.db", name))
        .to_str()
        .unwrap()
        .to_string();
    let ctx = MLSContext::new(path, format!("{}-key-1234567890123456", name), None).unwrap();
    (ctx, dir)
}

#[test]
fn test_metadata_visible_after_welcome_join() {
    let (alice_ctx, _alice_dir) = make_context("alice");
    let (bob_ctx, _bob_dir) = make_context("bob");

    // Alice creates group with metadata
    let config = GroupConfig {
        group_name: Some("Secret Club".to_string()),
        group_description: Some("Members only".to_string()),
        ..Default::default()
    };

    let group = alice_ctx
        .create_group(b"did:plc:alice".to_vec(), Some(config))
        .unwrap();

    // Bob creates a key package
    let bob_kp = bob_ctx
        .create_key_package(b"did:plc:bob".to_vec())
        .unwrap();

    // Alice adds Bob
    let add_result = alice_ctx
        .add_members(
            group.group_id.clone(),
            vec![catbird_mls::types::KeyPackageData {
                data: bob_kp.key_package_data,
            }],
        )
        .unwrap();

    // Alice merges her pending commit
    alice_ctx
        .merge_pending_commit(group.group_id.clone())
        .unwrap();

    // Bob processes the Welcome message
    let bob_welcome = bob_ctx
        .process_welcome(add_result.welcome_data)
        .unwrap();

    // Bob reads metadata from his group context
    let meta_bytes = bob_ctx
        .get_group_metadata(bob_welcome.group_id)
        .unwrap();
    assert!(!meta_bytes.is_empty(), "Bob should see metadata after Welcome join");

    let meta = GroupMetadata::from_extension_bytes(&meta_bytes).unwrap();
    assert_eq!(meta.name.as_deref(), Some("Secret Club"));
    assert_eq!(meta.description.as_deref(), Some("Members only"));
}
```

**Step 2: Run the E2E test**

Run: `cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls && cargo test --test group_metadata_e2e_test`
Expected: Test passes — Bob sees Alice's metadata after joining via Welcome

**Step 3: Commit**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
git add tests/group_metadata_e2e_test.rs
git commit -m "test: E2E verify metadata visible to joiner via Welcome"
```

---

## Summary

| Task | What | Where | Epoch Impact |
|------|------|-------|-------------|
| 1 | GroupMetadata serde type | `group_metadata.rs` | None |
| 2 | Set metadata at group creation | `mls_context.rs` | None (creation is epoch 0) |
| 3 | get/update FFI methods | `api.rs`, `mls_context.rs` | Update = 1 epoch advance |
| 4 | Orchestrator wiring | `groups.rs` | None |
| 5 | Read metadata on incoming commits | `messaging.rs` | None |
| 6 | UniFFI Swift bindings | `rebuild-ffi.sh` | None |
| 7 | catmos-web commit_group_change | `api_client.rs` | None |
| 8 | Remove plaintext metadata from server | `groups.rs` | None |
| 9 | WASM exports | `lib.rs` | None |
| 10 | E2E two-user test | `tests/` | None |

**Server changes: ZERO.** The server processes commits as opaque blobs. Metadata is invisible to the server.

**Epoch impact:** Only explicit metadata updates (Task 3) advance the epoch. Group creation embeds metadata at epoch 0 for free.
