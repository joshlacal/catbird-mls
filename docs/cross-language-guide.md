# catbird-mls Cross-Language Usage Guide

## 1. Overview

catbird-mls is a Rust MLS (Messaging Layer Security) SDK that provides end-to-end encrypted group chat. It exposes a unified `CatbirdMls` API across four platforms:

| Platform | Binding | Transport |
|----------|---------|-----------|
| Swift (iOS/macOS) | UniFFI XCFramework | Synchronous FFI calls (Rust blocks internally on async) |
| Kotlin (Android) | UniFFI JNI | Synchronous FFI calls (Rust blocks internally on async) |
| Python | UniFFI Python | Synchronous FFI calls (Rust blocks internally on async) |
| TypeScript/WASM | wasm-bindgen | Native async/await via `WasmCatbirdClient` |

The `CatbirdMls` object (UniFFI) and `WasmCatbirdClient` (WASM) share the same underlying orchestrator and MLS engine. The high-level API hides all MLS protocol details -- no epochs, key packages, or commits are exposed for standard chat operations.

### Architecture

```
CatbirdMls (UniFFI)  /  WasmCatbirdClient (WASM)
        |                        |
    CatbirdClient (high-level, MLS-free)
        |
    MLSOrchestrator<S, A, C, P>
        |
    MLSContext (OpenMLS + SQLCipher)
```

Three platform callback traits must be implemented by each host:

- **OrchestratorStorageCallback** -- persist conversations, messages, sync cursors, group state
- **OrchestratorAPICallback** -- communicate with the MLS delivery service
- **OrchestratorCredentialCallback** -- manage signing keys, device UUIDs, MLS DIDs

---

## 2. Concepts

### MLS Groups

Every conversation is backed by an MLS group. Groups provide forward secrecy and post-compromise security. When a participant joins or leaves, the group's cryptographic state advances to a new **epoch**.

### Epochs

An epoch is a version of the group's key material. Each membership change (add, remove, self-update) creates a new epoch. Messages are encrypted under the current epoch. Epoch mismatches indicate desync.

### Key Packages

A key package is a pre-published bundle that allows other users to add you to a group without you being online. The orchestrator automatically creates and replenishes key packages on the MLS delivery service.

### The Orchestrator Model

`MLSOrchestrator` coordinates all MLS operations:

1. **Device registration** -- registers this device with the MLS service on init
2. **Key package management** -- auto-replenishes when below threshold
3. **Group lifecycle** -- create, join, leave, add/remove members
4. **Message encryption/decryption** -- transparent to the caller
5. **Sync** -- fetches server state, processes commits, handles epoch recovery
6. **Circuit breaker** -- backs off on repeated sync failures

### Callback Pattern

The three platform traits (`StorageCallback`, `APICallback`, `CredentialCallback`) are implemented in the host language (Swift, Kotlin, Python) and passed to the Rust constructor. Rust calls back into your platform code for persistence, networking, and keychain access.

On UniFFI platforms (Swift/Kotlin/Python), callbacks are synchronous from the FFI boundary. On WASM, the traits are `async` and `?Send`.

---

## 3. Swift (iOS/macOS)

### Setup

The catbird-mls XCFramework is distributed as a local Swift package dependency via `CatbirdMLSCore`.

**Package.swift:**

```swift
dependencies: [
    .package(path: "../catbird-mls")  // Or use a binary XCFramework target
]
```

Build the XCFramework from the catbird-mls repo:

```bash
cd catbird-mls
./create-xcframework.sh    # Builds for iOS device + simulator
```

Or build from source using the rebuild script in CatbirdMLSCore:

```bash
cd CatbirdMLSCore
./Scripts/rebuild-ffi.sh   # Compiles Rust, generates Swift bindings, builds XCFramework
```

### Initialization

```swift
import CatbirdMLS

// 1. Implement the three callback protocols
class MyStorage: OrchestratorStorageCallback { /* ... */ }
class MyAPIClient: OrchestratorAPICallback { /* ... */ }
class MyCredentials: OrchestratorCredentialCallback { /* ... */ }
class MyKeychain: KeychainAccess {
    func read(key: String) async throws -> Data? { /* iOS Keychain read */ }
    func write(key: String, value: Data) async throws { /* iOS Keychain write */ }
    func delete(key: String) async throws { /* iOS Keychain delete */ }
}

// 2. Configure
let config = FfiOrchestratorConfig(
    maxDevices: 5,
    targetKeyPackageCount: 10,
    keyPackageReplenishThreshold: 3,
    syncCooldownSeconds: 5,
    maxConsecutiveSyncFailures: 5,
    syncPauseDurationSeconds: 30,
    rejoinCooldownSeconds: 60,
    maxRejoinAttempts: 3
)

// 3. Create the unified API
let mls = try CatbirdMls(
    userDid: "did:plc:abc123",
    storagePath: dbPath,           // Per-user SQLite path
    encryptionKey: sqlcipherKey,   // SQLCipher key from Keychain
    keychain: MyKeychain(),
    storage: MyStorage(),
    apiClient: MyAPIClient(),
    credentials: MyCredentials(),
    config: config
)

// 4. Run launch checkpoint (clears leftover WAL from previous session)
try mls.launchCheckpoint()

// 5. Optionally set epoch secret storage and logger
mls.setLogger(logger: MyOSLogBridge())
try mls.setEpochSecretStorage(storage: MyEpochStorage())
```

### Basic Workflow

```swift
// List conversations
let conversations = try mls.listConversations()

// Create a 1:1 conversation
let convo = try mls.createConversation(
    name: nil,
    participantDids: ["did:plc:other_user"]
)

// Send a message
let msg = try mls.sendMessage(
    conversationId: convo.id,
    text: "Hello from Catbird!"
)

// Fetch new messages from server
let newMessages = try mls.fetchNewMessages(
    conversationId: convo.id,
    cursor: nil,
    limit: 50
)

// Sync all conversations with server
try mls.sync(fullSync: false)

// Get message history (local storage)
let history = try mls.messages(
    conversationId: convo.id,
    limit: 20,
    beforeSequence: nil
)
```

### Lifecycle Management (0xdead10cc Prevention)

On iOS, holding SQLite file locks during app suspension causes `0xdead10cc` termination. catbird-mls uses budget-based WAL checkpoints and provides explicit lifecycle methods.

```swift
// App entering background
func sceneDidEnterBackground() {
    // Flush and close all database connections
    try? mls.flushAndPrepareClose()
    // After this call, mls.isClosed() returns true
    // Create a new CatbirdMls instance on next foreground
}

// App returning to foreground
func sceneWillEnterForeground() {
    if mls.isClosed() {
        // Re-create the CatbirdMls instance
        mls = try CatbirdMls(...)
        try mls.launchCheckpoint()
    }
}

// Clean shutdown
func applicationWillTerminate() {
    mls.shutdown()
    try? mls.flushAndPrepareClose()
}
```

### Error Handling

All methods throw `OrchestratorBridgeError`:

```swift
do {
    try mls.sendMessage(conversationId: id, text: "Hi")
} catch let error as OrchestratorBridgeError {
    switch error {
    case .notAuthenticated:
        // Re-authenticate
    case .conversationNotFound(let id):
        // Conversation deleted or never synced
    case .epochMismatch(let local, let remote):
        // Trigger rejoin
        try mls.rejoinConversation(conversationId: id)
    case .mls(let message):
        // Low-level MLS error
        print("MLS error: \(message)")
    case .api(let message):
        // Server communication error
    case .storage(let message):
        // Persistence error
    case .deviceLimitReached:
        // Too many registered devices
    case .recoveryFailed(let message):
        // Rejoin attempt failed
    case .shuttingDown:
        // Operation rejected during shutdown
    case .invalidInput(let message):
        // Bad parameters
    case .credential(let message):
        // Keychain/credential error
    }
}
```

---

## 4. Kotlin (Android)

### Setup

**build.gradle.kts:**

```kotlin
dependencies {
    implementation(files("libs/catbird-mls.aar"))
    // Or use the generated Kotlin bindings directly:
    implementation(project(":catbird-mls-bindings"))
}
```

Generate Kotlin bindings:

```bash
cd catbird-mls
./build-android.sh          # Cross-compiles for Android targets
# Bindings are generated at: src/generated/kotlin/
```

Load the native library in your Application class:

```kotlin
class MyApplication : Application() {
    init {
        System.loadLibrary("catbird_mls")
    }
}
```

### Initialization

```kotlin
import blue.catbird.mls.*

// Implement callbacks
class AndroidStorage : OrchestratorStorageCallback {
    override fun ensureConversationExists(userDid: String, conversationId: String, groupId: String) { /* Room DB */ }
    override fun listConversations(userDid: String): List<FfiConversationView> { /* ... */ }
    // ... all other methods
}

class AndroidApiClient : OrchestratorAPICallback {
    override fun isAuthenticatedAs(did: String): Boolean { /* ... */ }
    override fun sendMessage(convoId: String, ciphertext: ByteArray, epoch: ULong) { /* ... */ }
    // ... all other methods
}

class AndroidCredentials : OrchestratorCredentialCallback {
    override fun storeSigningKey(userDid: String, keyData: ByteArray) { /* EncryptedSharedPreferences */ }
    override fun getSigningKey(userDid: String): ByteArray? { /* ... */ }
    // ... all other methods
}

class AndroidKeychain : KeychainAccess {
    override suspend fun read(key: String): ByteArray? { /* Android Keystore */ }
    override suspend fun write(key: String, value: ByteArray) { /* ... */ }
    override suspend fun delete(key: String) { /* ... */ }
}

val config = FfiOrchestratorConfig(
    maxDevices = 5u,
    targetKeyPackageCount = 10u,
    keyPackageReplenishThreshold = 3u,
    syncCooldownSeconds = 5uL,
    maxConsecutiveSyncFailures = 5u,
    syncPauseDurationSeconds = 30uL,
    rejoinCooldownSeconds = 60uL,
    maxRejoinAttempts = 3u
)

val mls = CatbirdMls(
    userDid = "did:plc:abc123",
    storagePath = context.getDatabasePath("mls-state.db").absolutePath,
    encryptionKey = sqlcipherKey,
    keychain = AndroidKeychain(),
    storage = AndroidStorage(),
    apiClient = AndroidApiClient(),
    credentials = AndroidCredentials(),
    config = config
)

mls.launchCheckpoint()
```

### Basic Workflow

```kotlin
// List conversations
val conversations = mls.listConversations()

// Create conversation
val convo = mls.createConversation(
    name = null,
    participantDids = listOf("did:plc:other_user")
)

// Send message
val msg = mls.sendMessage(
    conversationId = convo.id,
    text = "Hello from Android!"
)

// Fetch new messages
val newMessages = mls.fetchNewMessages(
    conversationId = convo.id,
    cursor = null,
    limit = 50u
)

// Sync
mls.sync(fullSync = false)
```

### Lifecycle Management

```kotlin
// In ViewModel or lifecycle-aware component
override fun onCleared() {
    mls.shutdown()
    mls.flushAndPrepareClose()
}

// Process lifecycle
lifecycle.addObserver(object : DefaultLifecycleObserver {
    override fun onStop(owner: LifecycleOwner) {
        mls.syncDatabase()  // Flush + checkpoint
    }
})
```

### Error Handling

```kotlin
try {
    mls.sendMessage(conversationId = id, text = "Hi")
} catch (e: OrchestratorBridgeError.NotAuthenticated) {
    // Re-authenticate
} catch (e: OrchestratorBridgeError.EpochMismatch) {
    mls.rejoinConversation(conversationId = id)
} catch (e: OrchestratorBridgeError) {
    Log.e("MLS", "Error: ${e.message}")
}
```

---

## 5. Python

### Setup

```bash
pip install catbird-mls
# Or build from source:
cd catbird-mls
pip install -e .
```

The UniFFI Python bindings are generated alongside Swift/Kotlin. Ensure `libcatbird_mls.dylib` (macOS) or `libcatbird_mls.so` (Linux) is on the library path.

### Initialization

```python
from catbird_mls import CatbirdMls, FfiOrchestratorConfig

class PythonStorage:
    """Implements OrchestratorStorageCallback using SQLite."""
    def ensure_conversation_exists(self, user_did: str, conversation_id: str, group_id: str):
        # SQLite insert
        pass

    def list_conversations(self, user_did: str):
        # Return list of FfiConversationView
        return []

    def store_message(self, message):
        # Persist message
        pass

    # ... all other methods

class PythonApiClient:
    """Implements OrchestratorAPICallback using requests/httpx."""
    def is_authenticated_as(self, did: str) -> bool:
        return self._current_did == did

    def send_message(self, convo_id: str, ciphertext: bytes, epoch: int):
        self._http.post(f"/xrpc/blue.catbird.mls.sendMessage", ...)

    # ... all other methods

class PythonCredentials:
    """Implements OrchestratorCredentialCallback using encrypted file."""
    def store_signing_key(self, user_did: str, key_data: bytes):
        # Encrypt and store
        pass

    def get_signing_key(self, user_did: str) -> bytes | None:
        # Decrypt and return
        pass

    # ... all other methods

class PythonKeychain:
    """Implements KeychainAccess."""
    def read(self, key: str) -> bytes | None:
        pass
    def write(self, key: str, value: bytes):
        pass
    def delete(self, key: str):
        pass

config = FfiOrchestratorConfig(
    max_devices=5,
    target_key_package_count=10,
    key_package_replenish_threshold=3,
    sync_cooldown_seconds=5,
    max_consecutive_sync_failures=5,
    sync_pause_duration_seconds=30,
    rejoin_cooldown_seconds=60,
    max_rejoin_attempts=3,
)

mls = CatbirdMls(
    user_did="did:plc:abc123",
    storage_path="/tmp/mls-state/abc123.db",
    encryption_key="your-sqlcipher-key",
    keychain=PythonKeychain(),
    storage=PythonStorage(),
    api_client=PythonApiClient(),
    credentials=PythonCredentials(),
    config=config,
)

mls.launch_checkpoint()
```

### Basic Workflow

```python
# List conversations
conversations = mls.list_conversations()

# Create conversation
convo = mls.create_conversation(
    name=None,
    participant_dids=["did:plc:other_user"]
)

# Send message
msg = mls.send_message(
    conversation_id=convo.id,
    text="Hello from Python!"
)

# Fetch new messages
new_messages = mls.fetch_new_messages(
    conversation_id=convo.id,
    cursor=None,
    limit=50
)

# Sync
mls.sync(full_sync=False)

# Shutdown
mls.shutdown()
mls.flush_and_prepare_close()
```

### Error Handling

```python
from catbird_mls import OrchestratorBridgeError

try:
    mls.send_message(conversation_id=id, text="Hi")
except OrchestratorBridgeError.NotAuthenticated:
    # Re-authenticate
    pass
except OrchestratorBridgeError.EpochMismatch as e:
    mls.rejoin_conversation(conversation_id=id)
except OrchestratorBridgeError as e:
    print(f"MLS error: {e}")
```

---

## 6. TypeScript/WASM

### Setup

The WASM target uses `WasmCatbirdClient` which implements the same high-level contracts as the native `CatbirdClient` but with native `async/await` and `?Send` trait bounds suitable for single-threaded browser runtimes.

```bash
npm install catbird-mls-web
```

Or build from source:

```bash
cd catbird-mls
wasm-pack build --target web --features browser
```

### Initialization

```typescript
import { WasmCatbirdClient, OrchestratorConfig } from 'catbird-mls-web';

// Implement the three backend traits as JS objects
const storage: StorageBackend = {
  ensureConversationExists(userDid: string, conversationId: string, groupId: string) { /* IndexedDB */ },
  listConversations(userDid: string) { /* ... */ },
  storeMessage(message: Message) { /* ... */ },
  // ... all methods from MLSStorageBackend
};

const apiClient: ApiClient = {
  async isAuthenticatedAs(did: string): Promise<boolean> { /* ... */ },
  async sendMessage(convoId: string, ciphertext: Uint8Array, epoch: bigint) {
    await fetch('/xrpc/blue.catbird.mls.sendMessage', { /* ... */ });
  },
  // ... all methods from MLSAPIClient
};

const credentials: CredentialStore = {
  async storeSigningKey(userDid: string, keyData: Uint8Array) { /* IndexedDB encrypted */ },
  async getSigningKey(userDid: string): Promise<Uint8Array | null> { /* ... */ },
  // ... all methods from CredentialStore
};

const config: OrchestratorConfig = {
  maxDevices: 5,
  targetKeyPackageCount: 10,
  keyPackageReplenishThreshold: 3,
  syncCooldownSeconds: 5n,
  maxConsecutiveSyncFailures: 5,
  syncPauseDurationSeconds: 30n,
  rejoinCooldownSeconds: 60n,
  maxRejoinAttempts: 3,
};
```

### Async Patterns

All WASM operations are natively async -- no blocking:

```typescript
// Bootstrap (creates orchestrator, registers device, replenishes key packages)
const client = await WasmCatbirdClient.bootstrapInit(
  { userDid: 'did:plc:abc123' },
  mlsContext,
  storage,
  apiClient,
  credentials,
  config
);

// All operations are async
const conversations = await client.conversations();

const convo = await client.createConversation(
  'Team Chat',
  ['did:plc:alice', 'did:plc:bob']
);

const msg = await client.sendMessage(convo.id, 'Hello from the browser!');

const newMessages = await client.fetchNewMessages(convo.id, null, 50);

await client.sync(false);

// Cleanup
await client.shutdown();
```

### Lifecycle Management

In the browser, there are no file lock concerns. Handle page visibility changes for sync:

```typescript
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState === 'visible') {
    await client.sync(false);
  }
});

// Before tab close
window.addEventListener('beforeunload', () => {
  client.shutdown();
});
```

### Error Handling

```typescript
try {
  await client.sendMessage(convoId, 'Hello');
} catch (e) {
  if (e.message.includes('Not authenticated')) {
    // Re-authenticate
  } else if (e.message.includes('Epoch mismatch')) {
    await client.rejoinConversation(convoId);
  } else {
    console.error('MLS error:', e);
  }
}
```

---

## 7. Implementing Platform Callbacks

### OrchestratorStorageCallback

Persists conversations, messages, sync cursors, and group state. Use a durable store (SQLite, GRDB, Room, IndexedDB).

| Method | Purpose |
|--------|---------|
| `ensure_conversation_exists(user_did, conversation_id, group_id)` | Create conversation record if absent |
| `update_join_info(conversation_id, user_did, join_method, join_epoch)` | Record how/when user joined (join_method: "welcome", "external_commit", "creator") |
| `get_conversation(user_did, conversation_id)` | Return single conversation or nil |
| `list_conversations(user_did)` | Return all conversations for user |
| `delete_conversations(user_did, ids)` | Delete conversations by ID |
| `set_conversation_state(conversation_id, state)` | Update state string ("active", "inactive", "error") |
| `mark_needs_rejoin(conversation_id)` | Flag conversation for rejoin |
| `needs_rejoin(conversation_id)` | Check rejoin flag |
| `clear_rejoin_flag(conversation_id)` | Clear rejoin flag after successful rejoin |
| `store_message(message)` | Persist a decrypted message (FFIMessage with id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own) |
| `get_messages(conversation_id, limit, before_sequence)` | Paginated message history ordered by sequence_number descending |
| `message_exists(message_id)` | Deduplication check before storing |
| `get_sync_cursor(user_did)` | Return sync cursor (conversations_cursor, messages_cursor) |
| `set_sync_cursor(user_did, cursor)` | Persist sync cursor |
| `set_group_state(state)` | Store group state (group_id, conversation_id, epoch, members list) |
| `get_group_state(group_id)` | Retrieve group state |
| `delete_group_state(group_id)` | Delete group state |

### OrchestratorAPICallback

Communicates with the MLS delivery service. All networking -- authentication headers, serialization, retries -- is the host's responsibility.

| Method | Purpose |
|--------|---------|
| `is_authenticated_as(did)` | Check if client is authenticated as this DID |
| `current_did()` | Return currently authenticated DID or nil |
| `get_conversations(limit, cursor)` | Fetch paginated conversation list from server |
| `create_conversation(group_id, initial_members, metadata_name, metadata_description, commit_data, welcome_data)` | Create conversation on server with MLS commit/welcome data |
| `leave_conversation(convo_id)` | Notify server of departure |
| `add_members(convo_id, member_dids, commit_data, welcome_data)` | Send add-members commit to server |
| `remove_members(convo_id, member_dids, commit_data)` | Send remove-members commit to server |
| `send_message(convo_id, ciphertext, epoch)` | Send encrypted ciphertext to delivery service |
| `get_messages(convo_id, cursor, limit)` | Fetch encrypted envelopes from server |
| `publish_key_package(key_package, cipher_suite, expires_at)` | Upload a key package |
| `get_key_packages(dids)` | Fetch key packages for DIDs |
| `get_key_package_stats()` | Get available/total key package counts |
| `sync_key_packages(local_hashes, device_id)` | Detect orphaned key packages |
| `register_device(device_uuid, device_name, mls_did, signature_key, key_packages)` | Register device with MLS service |
| `list_devices()` | List registered devices |
| `remove_device(device_id)` | Unregister a device |
| `publish_group_info(convo_id, group_info)` | Upload GroupInfo for external joins |
| `get_group_info(convo_id)` | Fetch GroupInfo for external join |

### OrchestratorCredentialCallback

Manages cryptographic identity material. Use the platform's secure storage (iOS Keychain, Android Keystore, encrypted file).

| Method | Purpose |
|--------|---------|
| `store_signing_key(user_did, key_data)` | Persist Ed25519 signing key |
| `get_signing_key(user_did)` | Retrieve signing key or nil |
| `delete_signing_key(user_did)` | Delete signing key |
| `store_mls_did(user_did, mls_did)` | Persist MLS device DID |
| `get_mls_did(user_did)` | Retrieve MLS DID or nil |
| `store_device_uuid(user_did, uuid)` | Persist device UUID |
| `get_device_uuid(user_did)` | Retrieve device UUID or nil |
| `has_credentials(user_did)` | Check if device is registered (has signing key + MLS DID + device UUID) |
| `clear_all(user_did)` | Wipe all credentials for recovery |

### KeychainAccess

Low-level key-value storage for the MLS context's internal secrets (separate from CredentialCallback).

| Method | Purpose |
|--------|---------|
| `read(key)` | Read bytes by key, return nil if absent |
| `write(key, value)` | Store bytes by key |
| `delete(key)` | Delete entry by key |

---

## 8. API Reference

### Lifecycle

| Method | Description |
|--------|-------------|
| `CatbirdMls(user_did, storage_path, encryption_key, keychain, storage, api_client, credentials, config)` | Constructor. Creates MLS context, orchestrator, registers device, replenishes key packages. |
| `CatbirdMls.with_context(user_did, mls_context, storage, api_client, credentials, config)` | Constructor from existing MLSContext. Use when sharing context across components. |
| `shutdown()` | Release orchestrator resources. Does not close the database. |
| `flush_and_prepare_close()` | Flush writes and close database connections. Required for iOS 0xdead10cc prevention. Instance is unusable after this. |
| `launch_checkpoint()` | TRUNCATE WAL checkpoint. Call once at app startup. |
| `is_closed()` | Check if the MLS context has been closed. |
| `sync_database()` | Flush + checkpoint without closing. |
| `user_did()` | Get the authenticated user's DID. |

### Configuration

| Method | Description |
|--------|-------------|
| `set_epoch_secret_storage(storage)` | Set epoch secret persistence backend. Call during init before MLS operations. |
| `set_credential_validator(validator)` | Set callback for client-side credential validation policy. |
| `set_external_join_authorizer(authorizer)` | Set callback for authorizing external join requests. |
| `set_logger(logger)` | Set logging backend (routes Rust logs to platform logger). |

### Conversations

| Method | Description |
|--------|-------------|
| `list_conversations()` | List all conversations for the current user. Returns `Vec<Conversation>`. |
| `create_conversation(name, participant_dids)` | Create a new conversation. Handles MLS group creation, commit, welcome internally. |
| `leave_conversation(conversation_id)` | Leave a conversation. Sends leave commit to server. |

### Messaging

| Method | Description |
|--------|-------------|
| `send_message(conversation_id, text)` | Send a text message. Encrypts, sends to server, returns `ChatMessage`. |
| `messages(conversation_id, limit, before_sequence)` | Get message history from local storage. Paginated by sequence number. |
| `fetch_new_messages(conversation_id, cursor, limit)` | Fetch and decrypt new messages from the server. |
| `mark_read(conversation_id, message_id)` | Mark a conversation as read up to a message. |

### Members

| Method | Description |
|--------|-------------|
| `add_participants(conversation_id, participant_dids)` | Add members to conversation. Fetches their key packages, sends add commit. |
| `remove_participants(conversation_id, participant_dids)` | Remove members. Sends remove commit. |

### Key Packages

| Method | Description |
|--------|-------------|
| `create_key_package(identity_bytes)` | Create a single key package (low-level). Returns `KeyPackageResult`. |
| `create_key_packages_batch(identity_bytes, count)` | Create multiple key packages at once. |
| `replenish_key_packages_if_needed()` | Auto-check and replenish if below threshold. |
| `get_key_package_stats()` | Get available/total counts from server. |
| `get_key_package_bundle_count()` | Count locally stored key package bundles. |

### Devices

| Method | Description |
|--------|-------------|
| `ensure_device_registered()` | Register device if not already registered. Returns MLS DID. |
| `list_devices()` | List all registered devices. Returns `Vec<FFIDeviceInfo>`. |
| `remove_device(device_id)` | Unregister a device by ID. |

### Sync / Recovery

| Method | Description |
|--------|-------------|
| `sync(full_sync)` | Sync conversations and messages with server. `full_sync=true` re-fetches everything. |
| `rejoin_conversation(conversation_id)` | Force rejoin via External Commit (epoch desync recovery). |
| `join_group(welcome_data)` | Join a group via Welcome message bytes. |
| `force_rejoin(convo_id)` | Low-level rejoin via orchestrator. |
| `perform_silent_recovery(conversation_ids)` | Batch recovery across multiple conversations. |

### MLS Escape Hatch

Direct access to low-level MLS operations. Use only when the high-level API is insufficient.

| Method | Description |
|--------|-------------|
| `get_epoch(group_id)` | Get current epoch for a group. |
| `group_exists(group_id)` | Check if group exists in local storage. |
| `export_group_info(group_id, signer_identity_bytes)` | Export GroupInfo for external commit. |
| `encrypt_message_raw(group_id, plaintext)` | Raw MLS encryption. Returns `EncryptResult` with ciphertext and padded_size. |
| `decrypt_message_raw(group_id, ciphertext)` | Raw MLS decryption. Returns `DecryptResult` with plaintext, epoch, sequence_number, sender_credential. |
| `process_message_raw(group_id, message_data)` | Process any MLS message (commit, proposal, or application). |
| `create_external_commit(group_info_bytes, identity_bytes)` | Create External Commit to join a group. |
| `merge_pending_commit(group_id)` | Merge pending commit after server acknowledgment. Returns new epoch. |
| `clear_pending_commit(group_id)` | Clear pending commit after server rejection. |
| `discard_pending_external_join(group_id)` | Discard pending external join after rejection. |
| `self_update(group_id)` | Create self-update commit to refresh leaf node. |
| `export_identity_key(identity)` | Export identity key pair for backup. |
| `import_identity_key(identity, key_data)` | Import identity key pair from backup. |
| `sign_with_identity_key(identity, data)` | Sign arbitrary data with identity key. |
| `validate_group_info_format(group_info_bytes)` | Validate GroupInfo without joining. |
| `process_welcome(welcome_data, identity_bytes, config)` | Process Welcome message (low-level join). |
| `create_group_raw(identity_bytes, config)` | Create MLS group directly. |
| `add_members_raw(group_id, key_packages)` | Add members with raw key packages. Returns commit + welcome data. |
| `remove_members_raw(group_id, member_identities)` | Remove members by identity bytes. |
| `delete_group(group_id)` | Delete group from local storage. |
| `flush_storage()` | Flush pending writes to disk. |
| `export_epoch_secret(group_id)` | Export current epoch secret to storage backend. |
| `process_commit(group_id, commit_data)` | Process a commit message. Returns new epoch and proposal details. |

### Debug

| Method | Description |
|--------|-------------|
| `debug_group_members(group_id)` | Get member list with leaf indices and credential types. |
| `debug_list_key_package_hashes()` | List hashes of locally stored key packages. |
| `get_group_debug_state(group_id)` | Get full group state as JSON string. |
| `mls_context()` | Get the underlying `MLSContext` for advanced usage. |
