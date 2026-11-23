# Integrating the client

This walks through what an app does with `CatbirdMlsClient`, in the order Catbird's apps do it. Names are the Rust/UniFFI names; Swift renders them in camelCase (`enroll_device` is `enrollDevice`). Catbird's Swift wrapper, `MLSClientCoordinator` in [CatbirdMLSCore](swift-package.md), is the reference integration.

## 1. Implement the platform traits

The client reaches the platform only through these traits (see [Platform traits](platform-traits.md)):

- `PlatformKeyStore`: the database key and the device signing key, in the Keychain or Keystore.
- `PlatformTransport`: HTTP requests (authenticated with the account's AT Protocol OAuth session) and the realtime stream.
- `PlatformChangeObserver` (optional): change notifications for the UI.

The client calls them synchronously from its own threads. Keep them fast and never call back into the client from inside them.

## 2. Open the client

```swift
let config = CatbirdMlsClientConfig(
    storageRoot: appGroupContainerPath,
    accountDid: did,
    deviceId: deviceUUID,          // UUIDv4, stable for this install
    homeDsDid: homeDsDid,
    homeDsEndpoint: homeDsURL,
    pdsEndpoint: pdsURL
)
let client = try CatbirdMlsClient.open(config: config, keystore: keyStore,
                                       transport: transport, observer: observer)
```

On iOS, `storageRoot` must be the App Group container the Notification Service Extension shares. Open the client off the main thread, since it opens the database and touches the keychain.

## 3. Enroll the device

```swift
let status = client.checkSpacesEligibility(grantedOauthScopes: scopes)
let receipt = try client.enrollDevice(grantedOauthScopes: scopes)
```

`enroll_device` is idempotent. It needs the OAuth scopes for Spaces, `blue.catbird.chat.device`, `blue.catbird.chat.deviceRevocation` and `blue.catbird.labyrinth.mailboxKeys`; `MLSAppGroupStorage.requiredSpacesScopes` in CatbirdMLSCore lists them. On a second device, `is_device_pending_approval()` is true until another device calls `approve_device`.

Then:

- top up KeyPackages with `replenish_key_packages(count)` (Catbird uses 10);
- register for push: build the registration with `build_signed_push_gateway_registration` and send it.

## 4. Conversations and messages

```swift
let convo = try client.createGroup(conversationId: UUID().uuidString.lowercased(),
                                   sequencerDid: homeDsDid,
                                   memberDids: members, title: "Trip", description: nil)
let row = try client.sendMessage(conversationId: convo.conversationId,
                                 messageId: UUID().uuidString.lowercased(), text: "hi")
```

Conversation and message IDs must be UUIDv4. If `create_group` throws `GroupCreationPending` or `GroupCreationNeedsUserAction`, the creation is journaled: use `pending_group_creation_status`, `retry_pending_group_creation` or `cancel_pending_group_creation`.

## 5. Receive

Call `sync()` whenever there may be new entries: when the realtime stream delivers, on a push wake, on `resume_from_background`, and on `handle_darwin_push_wakeup` (after the extension committed). Then read with `list_conversations`, `list_messages` and `list_requests`, or react to `PlatformChangeEvent`s. `sync()` can throw `SyncIncomplete`, which reports how many entries were applied and which failed; call it again later.

## 6. Flush the history archive

```swift
_ = try client.flushLabyrinthQueue()
```

Nothing is written to the archive on the send path itself. Call this after sending and syncing, and before the app is suspended.

## 7. Push extension

In the Notification Service Extension, do not open a client. Call the free function:

```swift
let preview = try processPushNotification(storageRoot: root, accountDidHash: hash,
                                          keystore: pushKeyStore, transport: fetchTransport,
                                          wake: wake)
```

Show `preview`. If `preview.receiptVerified` is false, label it as unconfirmed (see [Local storage and push](../overview/storage-and-push.md)). The extension posts `blue.catbird.mls.nseDidCommit`; when the app receives it, call `handle_darwin_push_wakeup()`.

## 8. Background, sign-out, deletion

- `prepare_for_background()` before suspension; `resume_from_background()` on return.
- `sign_out_and_wipe()` on sign-out deletes local state and keys.
- `delete_account_data()` deletes the account: it publishes this device's revocation on the PDS, purges the account's history mailbox and its delivery-service state, then wipes local state. It keeps retry state, so an interrupted deletion can be resumed by calling it again.
