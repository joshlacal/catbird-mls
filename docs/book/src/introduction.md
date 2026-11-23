# Catbird MLS

`catbird-mls` is the client library behind Catbird's end-to-end encrypted chat. It implements the client side of Catbird's chat protocol on AT Protocol: [Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420) (MLS) groups with a post-quantum ciphersuite, a delivery service that orders messages and signs receipts for them, and encrypted, recoverable history through [Labyrinth](https://joshlacal.github.io/labyrinth/). One Rust crate serves iOS, macOS, Android and the web.

> **Status: pre-release.** The protocol and this library have not been independently audited. The wire formats, lexicons and storage formats may still change, and the local database has no migrations between format versions. The archive contract with Labyrinth is not sealed; the repository's own notes (dated 2026-11-07) record a failed review round and a fix round in progress. Treat every security property on these pages as a design goal that the code implements and tests, not as an audited guarantee.

## Who this is for

- **Outside readers and security reviewers.** The *Overview* explains what is encrypted, what each server sees, how devices and groups are managed, and where the known gaps are.
- **Developers.** The *Developer guide* covers building the library for each platform, integrating the client and its platform traits, and the Swift package. The *API reference* is generated from the source.

## The pieces

| Component | Role |
|---|---|
| [`catbird-mls`](https://github.com/joshlacal/catbird-mls) | This library. MLS groups, the chat wire protocol, the local encrypted database, push handling, and the Labyrinth archive integration. Exposed to Swift and Kotlin through UniFFI. |
| [`mls-ds`](https://github.com/joshlacal/mls-ds) | Catbird's delivery service. It enrolls devices, stores KeyPackages, orders each conversation's entries, signs a receipt for each one, holds Welcomes, sends push wakes and federates with other delivery services. It holds no MLS secrets. |
| The user's PDS | Publishes the account's chat devices and its choice of delivery service, and hosts the account's encrypted history in AT Protocol Spaces. |
| [Labyrinth](https://joshlacal.github.io/labyrinth/) | Encrypted, recoverable message history, stored in Spaces. |
| [`CatbirdMLSCore`](https://github.com/joshlacal/CatbirdMLSCore) | The Swift package that ships the compiled library and Swift wrappers for Catbird's Apple apps. |
| `catbird-mls-web` | The web facade, `WasmMlsClient`, in a separate repository. |

## Sources

These pages summarize the code at the time of writing. Where they and the code disagree, the code wins. The governing protocol document the source cites (`MLS_CLIENT_PROTOCOL.md`, "Spec §n", invariants `I1`–`I16`) is not published yet; [Invariants](reference/invariants.md) summarizes how the code uses each one.

## Reporting a vulnerability

Report privately through [GitHub's private vulnerability reporting](https://github.com/joshlacal/catbird-mls/security/advisories/new) or by email to `security@catbird.blue`. Do not open a public issue. See [`SECURITY.md`](https://github.com/joshlacal/catbird-mls/blob/main/SECURITY.md).

## License

Dual-licensed under MIT or Apache-2.0, at your option.
