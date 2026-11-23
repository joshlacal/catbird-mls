# Local storage and push

## The local database

Each account has one database per device at `<storage_root>/catbird-mls/<sha256(did)>.db`, opened through SQLCipher.

- **Key.** The platform supplies a 32-byte key (`PlatformKeyStore::load_or_create_db_key`), kept in the iOS Keychain or Android Keystore. Its storage and accessibility class are the app's responsibility.
- **Cipher settings.** The key is used as a raw SQLCipher key, so there is no password-based key derivation. The salt is derived from the key with HKDF-SHA256 (`catbird-mls-sqlcipher-salt-v1`). The first 32 bytes of the file are left unencrypted (`cipher_plaintext_header_size = 32`) so iOS can recognise it as a SQLite database while the app is suspended; the WAL journal is used with `synchronous = FULL`.
- **Web.** The browser build uses SQLite3 Multiple Ciphers with ChaCha20 over the Origin Private File System.
- **Format versions.** There are no migrations between local format versions: a client that finds an older format reports `LocalStateFormatUnsupported`, and the app must wipe and re-enrol. Opening the client also removes files left by the pre-release client.

The database holds the device's MLS group state, its signing key (also in the keychain), decrypted messages, read state and the Labyrinth client state. `sign_out_and_wipe` deletes the database files and the device's keychain entries.

### Background and shared access

On iOS the database lives in an App Group container shared with the Notification Service Extension.

- Before the app is suspended it calls `prepare_for_background`, which disconnects the realtime stream, checkpoints the WAL and closes the database (an open SQLite lock in a suspended app gets it killed with `0xdead10cc`).
- Write transactions never make network calls (`I6`).
- After the extension writes, the app picks up the change through SQLite's `data_version` and a Darwin notification (`I7`, `I11`).

## Push

The delivery service holds no APNs or FCM tokens. Each device registers its native push token with Catbird's push gateway and gets back an opaque push key; it then registers the gateway URL, app ID and push key with its home delivery service in a request signed by the device key. Wakes are sent to the gateway with a short-lived service token.

A wake carries the conversation ID, generation, sequence number and epoch, an optional sender DID, whether a fetch is required, and the MLS ciphertext itself when it is at most 2,200 bytes (`I12`).

### In the extension

The Notification Service Extension (or Android's push handler) never opens a full client. It calls `process_push_notification` with the storage root, a read-only key store, an optional fetch transport and the wake. That function:

- opens the shared database in a low-memory mode with a short lock timeout;
- fetches missing entries if it can (the extension never refreshes OAuth tokens, `I10`; without a cached token it can't fetch);
- verifies and decrypts the message, and returns a `NotificationPreview`;
- posts the Darwin notification `blue.catbird.mls.nseDidCommit` after it commits, so the app can reload.

If it can't decrypt, the preview says "New encrypted message".

**Unsequenced previews.** With no network, the extension can still decrypt an inline message that is next in order, check the sender and the attestation, and show a preview, but it cannot verify the sequencer's receipt. That preview has `receipt_verified = false`. It does not prove the server accepted or ordered the message, and until the app syncs, such a wake could be replayed or reordered within the ratchet window. The extension rolls back its transaction in that case, so nothing is stored. **Apps should label these previews as unconfirmed.**
