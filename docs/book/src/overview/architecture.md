# Architecture

```text
   Device A (Catbird app)                         Device B
 ┌──────────────────────────┐                 ┌──────────────────┐
 │ Swift / Kotlin / web UI  │                 │       ...        │
 │   └─ CatbirdMlsClient    │                 └────────┬─────────┘
 │       • MLS groups       │                          │
 │       • SQLCipher DB     │   signed requests,       │
 │       • Labyrinth client │   MLS ciphertext         │
 └───────┬───────────┬──────┘                          │
         │           │                                 │
         │           ▼                                 ▼
         │   ┌─────────────────────────────────────────────────┐
         │   │ mls-ds (each account's home delivery service)   │
         │   │  devices, KeyPackages, Welcomes, ordering,      │
         │   │  I13 receipts, push wakes, federation           │
         │   └─────────────────────────────────────────────────┘
         │ Spaces (encrypted history), device records
         ▼
   ┌─────────────────────────────┐
   │ The account's PDS           │
   │  public: chat devices,      │
   │  declaration, mailboxKeys   │
   │  Spaces: Labyrinth archive  │
   └─────────────────────────────┘
```

## Who does what

**The client** holds every secret. It runs the MLS state machine, encrypts and decrypts messages, verifies everything the servers return, keeps its state in an encrypted local database, and archives history with Labyrinth. All platforms drive the same Rust object, `CatbirdMlsClient`.

**The home delivery service.** Each account names one delivery service in a public record on its PDS (`blue.catbird.chat.declaration/self`). The client talks only to that service. It:

- enrolls the account's devices and stores their KeyPackages;
- accepts each conversation's entries (MLS Commits, application messages, membership and policy changes), orders them, and signs a **sequencer receipt** for each;
- holds Welcomes until the joining device fetches them;
- sends push wakes through the app's push gateway;
- relays to and from other delivery services, when the members' accounts use different ones.

The service that created a conversation is its **sequencer**: it assigns every entry's sequence number and signs its receipt. Other members' home services keep mirrors that only the sequencer can extend. mls-ds never holds MLS secrets; it checks the public parts of MLS messages and the signatures on each request.

**The PDS** publishes the account's chat devices (`blue.catbird.chat.device`) and their revocations, so other clients can check that a device key really belongs to an account. It also hosts the account's Labyrinth mailbox and its writes to each conversation's archive, in AT Protocol Spaces.

## Inside the crate

| Area | Source | What it does |
|---|---|---|
| Client | `src/client/` | `CatbirdMlsClient`: enrollment, the live data plane (`live_plane.rs`), sync (`live_sync.rs`), the chat wire format (`chat_wire.rs`, `canonical_transport.rs`), the Labyrinth archive (`native_archive.rs`) |
| Platform traits | `src/client/traits.rs` | `PlatformKeyStore`, `PlatformTransport`, `PlatformChangeObserver` |
| Storage | `src/storage/` | The per-account SQLCipher database, and the WASM storage driver |
| Push | `src/push/` | `process_push_notification` for the iOS Notification Service Extension and Android's push handler |
| Metadata | `src/metadata.rs` | Encrypted group titles, descriptions and avatar pointers |
| Labyrinth wiring | `src/labyrinth/` | The mls-ds directory transport, Space transport and session setup for the Labyrinth client |
| Circles | `src/circles/` | Encrypted owner state for Catbird circles, stored in Spaces |
| FFI | `src/ffi/` | The UniFFI exports |
| Legacy engine | `src/orchestrator/`, `src/mls_engine_context.rs`, `src/engine.rs` | The previous generation of the client. Compiled only with the `legacy-orchestrator` feature and not used by the apps. |

The ciphersuite is `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (`0x004D`), using a fork of [OpenMLS](https://github.com/openmls/openmls) (`0.9.0-rc.3`) with libcrux providing the cryptography.

## What lives where

| Data | Where |
|---|---|
| MLS group state, device signing key, local message history | The device's encrypted database (and the platform keychain for the database key and signing key) |
| MLS ciphertext of each message | mls-ds, until every recipient has acknowledged it (and at least 72 hours), and never more than 30 days |
| Encrypted long-term history, recovery bundles | The account's PDS, in Spaces, through Labyrinth |
| Encrypted group title, description and avatar pointer | mls-ds, as the latest metadata snapshot |
| Encrypted avatar images and attachments | Blobs in the uploader's Space on its PDS |
| Device public keys | The PDS (public records) and mls-ds |
