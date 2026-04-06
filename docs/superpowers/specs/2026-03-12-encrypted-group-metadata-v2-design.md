# Encrypted Group Metadata v2

## Problem

Group metadata (title, description, avatar) is broken for non-creators. The current design derives a random key known only to the group creator — no other member can decrypt it. The server sees no plaintext. The result: every non-creator sees "Secure Group" as the conversation title.

The current approach also conflates message encryption keys (sender ratchets) with metadata keys. These are fundamentally different: metadata is long-lived shared state, not per-message ephemeral data.

## Design Goals

1. **Encrypted at rest** — metadata is opaque ciphertext on the server; never plaintext
2. **All members can decrypt** — any current group member reads metadata at the current epoch
3. **Epoch-bound keys** — metadata key derived from MLS exporter (RFC 9420 §8), tied to a specific epoch
4. **Eager re-wrap** — every epoch-advancing commit re-encrypts metadata for the new epoch
5. **No migration** — server will be wiped; old groups lose metadata; no legacy code paths
6. **Lexicon-defined API** — blob storage endpoints defined as AT Protocol lexicons, generated into Rust (Jacquard) and Swift (Petrel)

## Architecture

Two layers (with optional third later):

```
┌─────────────────────────────────────────────┐
│  Persistent reference (in committed state)  │
│  Lightweight MetadataReference              │
│  - schema, metadata_version, blob_locator,  │
│    ciphertext_hash                          │
├─────────────────────────────────────────────┤
│  Server-side encrypted blob                 │
│  Opaque ciphertext stored via lexicon API   │
│  Keyed by blob_locator (UUIDv4)            │
├─────────────────────────────────────────────┤
│  (Future) AppEphemeral inline delivery      │
│  Optional: attach blob to commit for        │
│  immediate availability without extra fetch │
└─────────────────────────────────────────────┘
```

The persistent reference lives in `app_data_dictionary` (MLS extensions draft, draft-ietf-mls-extensions-08). This is an **intentional draft dependency** — not part of RFC 9420 core. Acceptable because Catbird controls both ends (DS, Rust SDK, Swift client), but worth noting that this surface is still moving in OpenMLS.

### Why not inline in GroupContext?

GroupContext is replicated to every member on every commit. Encrypted blobs bloat the commit and are limited by MLS extension size constraints. Storing a lightweight reference (~100 bytes) in `app_data_dictionary` and the actual ciphertext out-of-band keeps commits small and allows metadata to grow (avatar images) without protocol pressure.

## Section 1: Key Derivation

### Exporter-derived metadata key

Derive the metadata encryption key from the MLS exporter (RFC 9420 §8), NOT from sender ratchets or random keys:

```
metadata_key = export_secret(
  label:   "blue.catbird/group-metadata/v1",
  context: group_id || to_be_bytes(epoch),
  length:  32
)
```

- The key is a 32-byte ChaCha20-Poly1305 symmetric key
- Every member in the epoch's group state can independently derive the same key
- The epoch is bound in both the exporter context AND the AEAD additional data

### Staged-commit next-epoch export

In OpenMLS 0.8.1, `StagedCommit` exposes `export_secret()`. This gives access to the **next epoch's** exporter before merge. This eliminates any chicken-and-egg problem: the sender can derive the key, encrypt the metadata, upload the blob, and include the complete MetadataReference in the commit — all before merge and send.

### Sender flow

```
1. Read current plaintext metadata from local cache
2. Generate blob_locator (UUIDv4)
3. Build and stage the commit → StagedCommit
4. staged_commit.export_secret() → metadata_key for the new epoch
5. Encrypt metadata with key
6. Upload encrypted blob to server at blob_locator
7. Compute ciphertext_hash (SHA-256 of encrypted blob)
8. Build MetadataReference with blob_locator, ciphertext_hash, metadata_version
9. Include MetadataReference in app_data_dictionary as part of the commit
10. Send commit to server
11. Merge staged commit locally
```

**Invariant: do not publish a commit whose MetadataReference points to a blob that hasn't been uploaded yet.** Steps 6 and 10 enforce this — upload before send.

### Receiver flow

```
1. Receive commit → stage it (StagedCommit)
2. staged_commit.export_secret() → metadata_key for new epoch
3. Read MetadataReference from staged commit's app_data_dictionary
4. Fetch encrypted blob from server using blob_locator
5. Verify ciphertext_hash (SHA-256)
6. Decrypt with derived key
7. Cache plaintext metadata locally
8. Merge staged commit
```

### Why post-commit epoch, not pre-commit?

Pre-commit derivation uses the OLD epoch's key material. If the commit adds a new member, the new member doesn't have the old epoch's state and cannot derive the key. Post-commit (next-epoch) derivation uses the NEW epoch, which all members (including newly added ones) share. RFC 9420 defines groups as a sequence of epochs and provides the exporter specifically for deriving application secrets from epoch state.

## Section 2: Data Model

### MetadataReference (stored in app_data_dictionary)

```rust
struct MetadataReference {
    schema: String,           // "blue.catbird/group-metadata/v1"
    metadata_version: u64,    // monotonic counter, incremented on each metadata update
    blob_locator: String,     // UUIDv4 opaque locator (not content-addressed, not epoch-shaped)
    ciphertext_hash: Vec<u8>, // SHA-256 of the encrypted blob (integrity check)
}
```

Key decisions:
- `blob_locator` is a random UUIDv4, NOT derived from epoch or group ID. This prevents the server from correlating metadata updates with epoch transitions.
- `ciphertext_hash` lets receivers verify blob integrity without trusting the server.
- `metadata_version` is a simple monotonic counter for conflict detection. No `updated_by` or `updated_at` — unnecessary for v1.

### GroupMetadataV1 (plaintext payload, encrypted before storage)

```rust
struct GroupMetadataV1 {
    version: u32,               // 1
    title: String,              // max 128 chars
    description: String,        // max 512 chars
    avatar_blob_locator: Option<String>,  // UUIDv4 locator for encrypted avatar blob
    avatar_content_type: Option<String>,  // e.g. "image/jpeg"
}
```

The avatar is stored as a separate encrypted blob on the same mls-ds blob store, using the same epoch-derived metadata key for encryption. `avatar_blob_locator` points to it. When metadata is re-wrapped for a new epoch, the avatar blob is also re-encrypted and re-uploaded (new locator, new key). The avatar is encrypted with the same AEAD parameters as the metadata blob, but with `"avatar"` appended to the AAD to domain-separate.

No timestamps. No author tracking. These can be added in a future `GroupMetadataV2` schema indicated by the `schema` field in `MetadataReference`.

### AEAD Encryption

Algorithm: ChaCha20-Poly1305

For the metadata blob:
```
nonce:  random 12 bytes (prepended to ciphertext)
key:    metadata_key (from exporter)
aad:    group_id || to_be_bytes(epoch) || to_be_bytes(metadata_version)
input:  serde_json::to_vec(&metadata) (deterministic for a given serde_json version)
output: nonce || ciphertext || tag
```

For the avatar blob:
```
nonce:  random 12 bytes (prepended to ciphertext)
key:    metadata_key (same key from exporter)
aad:    group_id || to_be_bytes(epoch) || to_be_bytes(metadata_version) || b"avatar"
input:  raw avatar image bytes
output: nonce || ciphertext || tag
```

The AAD binds each ciphertext to its group, epoch, version, and domain — preventing cross-group, replay, and metadata/avatar confusion attacks.

## Section 3: Eager Re-wrap

Every epoch-advancing commit MUST re-encrypt metadata (and avatar if present) for the new epoch. This is non-negotiable: OpenMLS keeps `max_past_epochs` at 0 by default, meaning old epoch key material is not generally available. Metadata encrypted for an old epoch becomes undecryptable by late joiners.

### Which commits advance the epoch?

All of them that go through the commit path:
- Add member
- Remove member
- Update (key rotation)
- GroupContextExtensions (including metadata updates)
- AppDataUpdate proposals
- External commits (rejoin)

### Re-wrap flow

```
1. Read current plaintext metadata from local cache
2. Generate new blob_locator(s) (UUIDv4)
3. Build and stage the commit → StagedCommit
4. staged_commit.export_secret() → new metadata_key
5. Encrypt metadata with new key → upload new metadata blob
6. If avatar exists: encrypt avatar with new key → upload new avatar blob
7. Build MetadataReference with new locator(s), ciphertext_hash, same metadata_version
8. Include updated MetadataReference in app_data_dictionary
9. Send commit to server
10. Merge staged commit locally
```

If the commit IS a metadata update (title/description/avatar change), increment `metadata_version` in step 7.

### What if re-wrap fails?

If the blob upload fails (step 5/6), the commit still proceeds but **metadata is temporarily unavailable** to receivers at the new epoch. Old epoch key material is gone after merge, so the previous blob is undecryptable. Metadata recovers on the next successful re-wrap. Group operation is never blocked by metadata — the group just shows a placeholder title until the next epoch.

### Conflict resolution

If two members concurrently commit metadata updates with the same `metadata_version`, the server-sequenced commit order determines the winner. The losing commit is rejected as an epoch conflict (409), and the losing client must retry against the new epoch. This is standard MLS conflict resolution — no special handling needed for metadata.

### Cleanup

After a successful re-wrap, old blobs can be garbage collected. The server implements TTL-based cleanup (e.g., 30 days after creation) since metadata blobs are small and infrequent. Clients do not need to explicitly delete old blobs.

## Section 4: Server-Side Blob Storage API

Metadata blobs use the existing `blue.catbird.mlsChat` namespace with two new dedicated lexicon endpoints. This separates metadata blobs from media blobs (images/attachments) for independent quota management and lifecycle policies.

### Lexicon: `blue.catbird.mlsChat.putGroupMetadataBlob`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mlsChat.putGroupMetadataBlob",
  "description": "Store an encrypted group metadata blob",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Upload an encrypted metadata blob. The blobLocator is client-generated (UUIDv4) and serves as the idempotency key. The server stores opaque bytes — it never sees plaintext metadata. Used for both metadata JSON blobs and encrypted avatar images.",
      "input": {
        "encoding": "*/*",
        "schema": {
          "type": "bytes",
          "description": "Encrypted blob bytes (nonce || ciphertext || tag)",
          "maxLength": 1048576
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["blobLocator", "size"],
          "properties": {
            "blobLocator": {
              "type": "string",
              "description": "The blob locator (echoed from input parameter)"
            },
            "size": {
              "type": "integer",
              "description": "Stored blob size in bytes"
            }
          }
        }
      },
      "parameters": {
        "type": "params",
        "required": ["blobLocator", "groupId"],
        "properties": {
          "blobLocator": {
            "type": "string",
            "description": "Client-generated UUIDv4 blob locator. Also the idempotency key."
          },
          "groupId": {
            "type": "string",
            "description": "Hex-encoded MLS group ID this metadata belongs to"
          }
        }
      },
      "errors": [
        {
          "name": "BlobTooLarge",
          "description": "Metadata blob exceeds maximum size (1MB)"
        },
        {
          "name": "InvalidBlobLocator",
          "description": "blobLocator is not a valid UUIDv4"
        },
        {
          "name": "GroupNotFound",
          "description": "The specified group does not exist or caller is not a member"
        }
      ]
    }
  }
}
```

### Lexicon: `blue.catbird.mlsChat.getGroupMetadataBlob`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mlsChat.getGroupMetadataBlob",
  "description": "Fetch an encrypted group metadata blob by locator",
  "defs": {
    "main": {
      "type": "query",
      "description": "Download an encrypted metadata blob. Returns raw encrypted bytes. The blob is opaque — decryption requires the MLS epoch key derived by group members.",
      "parameters": {
        "type": "params",
        "required": ["blobLocator", "groupId"],
        "properties": {
          "blobLocator": {
            "type": "string",
            "description": "The blob locator to fetch"
          },
          "groupId": {
            "type": "string",
            "description": "Hex-encoded MLS group ID (for server-side membership check)"
          }
        }
      },
      "output": {
        "encoding": "*/*",
        "schema": {
          "type": "bytes",
          "description": "Raw encrypted blob bytes"
        }
      },
      "errors": [
        {
          "name": "BlobNotFound",
          "description": "Metadata blob does not exist or has been garbage collected"
        }
      ]
    }
  }
}
```

### Code Generation

These lexicon files live in `mls-ds/lexicon/blue/catbird/mlsChat/` (source of truth) and are mirrored to `Petrel/Generator/lexicons/blue/catbird/mlsChat/`.

- **Rust (server)**: Generated via Jacquard into `mls-ds/server/src/generated_types.rs` — request/response types, error enums, and Axum handler signatures
- **Swift (client)**: Generated via `Petrel/Generator/main.py` into Petrel's generated AT Protocol models — used by CatbirdMLSCore for API calls

### Server Implementation

The server stores metadata blobs in a `group_metadata_blobs` table:

```sql
CREATE TABLE group_metadata_blobs (
    blob_locator TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    data BYTEA NOT NULL,
    size INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gmb_group ON group_metadata_blobs (group_id);
```

Lifecycle: blobs are immutable once written. Old blobs are garbage collected via TTL sweep (30 days after creation).

## Section 5: OpenMLS Feature Flag

Enable `extensions-draft-08` in catbird-mls. This is an **intentional draft dependency** — these extension types are defined in draft-ietf-mls-extensions-08, not RFC 9420 core. The OpenMLS changelog shows ongoing alignment work with these proposal types, meaning the API surface may shift between OpenMLS releases. Acceptable for Catbird because we control both endpoints.

```toml
# catbird-mls/Cargo.toml
openmls = { version = "0.8", features = ["test-utils", "js", "extensions-draft-08"] }
```

This feature flag enables:
- `AppDataDictionary` extension type — persistent key-value store in GroupContext
- `AppDataUpdate` proposal — incremental updates to app_data_dictionary without full GCE replacement
- `AppEphemeral` proposal — ephemeral data attached to a commit (discarded after epoch transition)

v1 uses only `AppDataDictionary` and `AppDataUpdate`. `AppEphemeral` is deferred.

## Section 6: Phased Implementation

### Phase 1: Core encryption + blob storage + avatar
- Add `extensions-draft-08` feature flag to `catbird-mls/Cargo.toml`
- Implement `metadata_v2` module in catbird-mls:
  - `derive_metadata_key(staged_commit, group_id, epoch) -> [u8; 32]`
  - `encrypt_metadata_blob(key, group_id, epoch, metadata_version, payload) -> Vec<u8>`
  - `decrypt_metadata_blob(key, group_id, epoch, metadata_version, ciphertext) -> GroupMetadataV1`
  - `build_metadata_reference(schema, version, locator, hash) -> MetadataReference`
  - Same encrypt/decrypt for avatar blobs (domain-separated AAD)
- Create lexicon files for `putGroupMetadataBlob` and `getGroupMetadataBlob`
- Generate Rust types (Jacquard) and Swift types (Petrel) from lexicons
- Server endpoints for blob put/get with `group_metadata_blobs` table
- Wire into `create_group`: stage commit, derive key, encrypt metadata + optional avatar, upload blobs, include reference, send, merge

### Phase 2: Eager re-wrap on all commit paths
- Wire re-wrap into every commit path in api.rs: `process_message`, `process_message_async`, `process_commit`, `merge_pending_commit`
- On StagedCommit: derive new metadata_key, re-encrypt metadata + avatar, upload new blobs, update reference
- Handle re-wrap failure gracefully (commit proceeds, metadata temporarily unavailable)

### Phase 3: Swift integration (CatbirdMLSCore)
- Update UniFFI bindings to expose metadata_v2 functions
- Update `MLSConversationManager+Groups.swift` to use new metadata flow
- Update `MLSConversationManager+Sync.swift` to decrypt metadata on incoming commits
- Avatar display in conversation UI
- Remove all old MEK/metadata code paths

### Not in v1
- AppEphemeral inline delivery (optimization — saves one server fetch per commit)
- Migration from old metadata format (server wipe eliminates this)

## Rust API Surface

The core helper functions exposed by the `metadata_v2` module:

```rust
/// Derive the metadata encryption key from a staged commit's next-epoch exporter.
pub fn derive_metadata_key(
    staged_commit: &StagedCommit,
    group_id: &[u8],
    epoch: u64,
) -> Result<[u8; 32], MetadataError>;

/// Encrypt a GroupMetadataV1 payload into an opaque blob.
pub fn encrypt_metadata_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    metadata: &GroupMetadataV1,
) -> Result<Vec<u8>, MetadataError>;

/// Decrypt an opaque blob back into GroupMetadataV1.
pub fn decrypt_metadata_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    ciphertext: &[u8],
) -> Result<GroupMetadataV1, MetadataError>;

/// Encrypt raw avatar bytes into an opaque blob (domain-separated AAD).
pub fn encrypt_avatar_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    avatar_bytes: &[u8],
) -> Result<Vec<u8>, MetadataError>;

/// Decrypt an opaque avatar blob back into raw image bytes.
pub fn decrypt_avatar_blob(
    key: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    metadata_version: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, MetadataError>;

/// Build a MetadataReference from components.
pub fn build_metadata_reference(
    metadata_version: u64,
    blob_locator: &str,
    ciphertext_hash: &[u8],
) -> MetadataReference;
```

## Files to Create/Modify

### New files
- `catbird-mls/src/metadata_v2.rs` — key derivation, encrypt/decrypt, types, Rust API surface above
- `mls-ds/lexicon/blue/catbird/mlsChat/blue.catbird.mlsChat.putGroupMetadataBlob.json`
- `mls-ds/lexicon/blue/catbird/mlsChat/blue.catbird.mlsChat.getGroupMetadataBlob.json`
- Mirror lexicons to `Petrel/Generator/lexicons/blue/catbird/mlsChat/`

### Modified files
- `catbird-mls/Cargo.toml` — add `extensions-draft-08` feature
- `catbird-mls/src/api.rs` — wire metadata_v2 into all commit paths
- `catbird-mls/src/mls_context.rs` — replace old metadata key code with metadata_v2 calls
- `catbird-mls/src/lib.rs` — add `mod metadata_v2`
- `catbird-mls/src/group_metadata.rs` — gut and replace (or delete, redirect to metadata_v2)
- `catbird-mls/src/orchestrator/mls_provider.rs` — add blob storage trait methods
- `mls-ds/server/src/generated_types.rs` — regenerate with new endpoint types
- `CatbirdMLSCore/Sources/CatbirdMLS/CatbirdMLS.swift` — regenerate UniFFI bindings
- `CatbirdMLSCore/Sources/CatbirdMLSCore/Service/Extensions/MLSConversationManager+Groups.swift`
- `CatbirdMLSCore/Sources/CatbirdMLSCore/Service/Extensions/MLSConversationManager+Sync.swift`

### Deleted code
- All `derive_and_cache_mek` / `store_metadata_key` / `metadata_keys` HashMap in mls_context.rs
- `EncryptedMetadataEnvelope` and related types in group_metadata.rs
- Any old metadata key references throughout the codebase
