# Labyrinth history backup in catbird-mls (feature `labyrinth`)

**What this is.** Labyrinth 1.1 is Meta's protocol for encrypted chat *history*. Catbird's implementation is the private `labyrinth` crate (`~/Developer/labyrinth`, bookmark `labyrinth-1.1`), and mls-ds serves it under `blue.catbird.labyrinth.*` (local bookmark `local/labyrinth-backend-20261004` in mls-ds). This change wires the crate into the shared Rust orchestrator behind a new cargo feature, `labyrinth`, which is off by default. A device can now back up the messages it sends, restore onto a new device with a recovery code, read or import a conversation's history, revoke another device, and re-archive before leaving. Nothing here is pushed, and platform bindings are not regenerated.

Code: `src/labyrinth/` (module docs list each file). Crate design: `docs/MLSDS_BACKEND.md` and `docs/DECISIONS.md` in the labyrinth repo. Server admission (headers, signature domain): mls-ds `server/src/labyrinth/auth.rs`.

## What is wired

| Hook | Where | Behaviour |
|---|---|---|
| Enable / reopen | `MLSOrchestrator::labyrinth_enable` | Opens the saved state, or creates the mailbox (`Labyrinth::initialize`). |
| Recovery code | `labyrinth_create_recovery_code` | Creates a bundle and returns the code. |
| Restore | `labyrinth_restore_with_recovery_code` | Enrolls this device from a code. |
| Archive on send | `send_payload_message` → `labyrinth_archive_sent` | Best effort, after the message is stored. |
| History | `labyrinth_load_history`, `labyrinth_import_history` | Decrypts history; import stores missing messages through `MLSStorageBackend`. |
| Revoke | `labyrinth_revoke_device(device_key_hex)` | Revokes a device and opens a new epoch ([CB-11]). |
| Leave | `leave_conversation` → `labyrinth_rearchive_before_leave` | Best effort ([CB-22]). |
| Shutdown / account switch | `clear_runtime_state` | Drops the in-memory session. The saved state is kept. |
| UniFFI | `src/labyrinth/ffi.rs` (child of `orchestrator_bridge`) | `labyrinth_enable_backup`, `labyrinth_create_recovery_code`, `labyrinth_restore_with_recovery_code`, `labyrinth_load_history_page`, `labyrinth_import_history`, `labyrinth_revoke_device` |

## Decisions (provisional, overridable before merge)

## 2026-10-05 · catbird-mls · D1 Labyrinth is a local-only path dependency
Chose: `labyrinth = { path = "../../../labyrinth", features = ["xrpc"], optional = true }`, which resolves only from a lane workspace two directories below `~/Developer`. Because: the crate is in a private repo and Josh has not decided how to publish it. Cargo loads every path dependency's manifest even when the feature is off. **This Cargo.toml line therefore breaks every build outside such a lane, including CI and the canonical checkout.** It must not reach a public branch. Rejected: a git dependency on the private repo, which fails the same way for anyone without access and also exposes the repo URL.
Reversible until: any push of catbird-mls. Override by: (a) making labyrinth public and pinning a git rev, (b) vendoring it, or (c) keeping this feature on an unpushed branch until Spaces reach GA. **Josh decides (Red tier: publication).**

## 2026-10-05 · catbird-mls · D2 Base revision is the consolidation line, so no merge was needed
Chose: base `94a55cab` (`codex/main-consolidation-native-20261002`, 2026-10-02). It contains `direct_request_bootstrap` and `EpochSecretStorage`, which is what the merged mls-ds `e2e-tests` import. It also contains every file that `main`'s last content commit `64cd27d5` added; those commits were re-landed under new hashes by the history repair. `main` (`1495be65`) is not an ancestor, but no content is missing. Rejected: merging `main` again, which would only duplicate the re-landed work.
Reversible until: merge. Override by: rebasing onto a different base.

## 2026-10-05 · catbird-mls · D3 A separate gateway seam for Labyrinth requests
Chose: a feature-gated `MLSAPIClient::submit_labyrinth_request(LabyrinthRequest)` whose default refuses. `LabyrinthRequest` carries the NSID (the service-auth `lxm`), the path, the body and the two signed-write headers. The one non-Labyrinth query, `getConversationState`, uses the existing `submit_prepared_request`. Because: `PreparedRequest` has no header field and `CanonicalOperation` is a closed enum that is mirrored across UniFFI. Widening either would change the FFI for every caller. Rejected: adding Labyrinth variants to `CanonicalOperation`.
Consequence: the UniFFI `OrchestratorAPICallback` does not forward the new method yet, so on iOS and Android every Labyrinth call fails with `Api("this gateway does not implement Labyrinth requests")`. Next step: add the callback method, then run `ffi-propagate`.

## 2026-10-05 · catbird-mls · D4 Signing uses the chat device key through platform custody
Chose: sign through `CredentialStore::sign_clean_chat_transcript`, falling back to the MLS identity signer. This is the same path as signed clean-chat and direct-request bodies. The signature is verified locally before use. Labyrinth's `TransportSigner` cannot fail, so a failure produces a zero signature and is recorded in a latch, and the session then returns `Credential(..)`. Because: the private key must never cross the FFI. Every Labyrinth signing input carries its own `catbird.labyrinth.*` or `CATBIRD-LABYRINTH-WRITE\0` prefix, so these signatures cannot be confused with clean-chat signatures.
Override by: a fallible signer trait in the crate.

## 2026-10-05 · catbird-mls · D5 Client state lives in the encrypted MLS database
Chose: store `Labyrinth::export_state` in `MlsCryptoContext::compare_exchange_request_value`, namespace `labyrinthClientState`, keyed by account DID. This is the SQLCipher store that already holds direct-request keys. The write is a compare-and-swap, so a concurrent writer (for example the notification extension) is reported instead of being overwritten silently. Rejected: the `KeychainAccess` callback, which the orchestrator cannot reach (it is owned by `MLSContext`). Gap: there is no delete API for request values, so disabling Labyrinth cannot erase the state yet.

## 2026-10-05 · catbird-mls · D6 mls-ds is the only directory
Chose: `XrpcDirectory` (mls-ds) is the client's directory, with no PDS `mailboxKeys` publisher. Because: the crate has no atproto PDS store yet, so `CompositeDirectory` has nothing to cross-check against. Cost: with the mailbox in mls-ds, the [CB-28] truncation check and first contact under [CB-29] both rest on mls-ds alone (labyrinth design §1c). Override by: adding a PDS directory and publisher, then wrapping both in `CompositeDirectory` in `SessionDeps::backends`.

## 2026-10-05 · catbird-mls · D7 Flush each sent message, archiving inline and best effort
Chose: archive and flush each sent message, awaited inside `send_message` after local storage. A failure is logged and never fails the send. Because: the state blob does not include unflushed batches, so a killed app would silently lose buffered history. Cost: one `appendBatch` per message, plus a `getConversationState` and roster lookups, all added to send latency. Rejected: buffering up to 256 messages per batch ([CB-20]), and detached background archiving, which suspension makes unreliable. Override by: flushing on a timer or at lifecycle suspend, or spawning the archive task.

## 2026-10-05 · catbird-mls · D8 Roster and import rules
Chose:
- The roster is every participant in `getConversationState` that is `active` and has `leafCount > 0`. `labyrinthHead` is not required, because `resolve_roster` skips DIDs that are not enrolled.
- Import stores sender-mode messages only: owner copies carry no sender DID. It skips [CB-31] conflict copies and frames that are not an `MLSMessagePayload`.
- Imported messages get `epoch = 0` and `sequence_number = 0`, because they have no MLS coordinates.

Override by: editing `hooks::roster_members` or `labyrinth_import_history`.

## 2026-10-05 · catbird-mls · D9 Revoking a chat device does not revoke its Labyrinth device
Chose: revocation is explicit, through `labyrinth_revoke_device(device_key_hex)`. Because: at `labyrinth-1.1` a Labyrinth device record has no link to a chat device id. The `gaps` lane in the labyrinth repo (`8b634487`, unmerged) adds a `chatBinding` ([CB-36]). Once that lands, `remove_device` can map a chat device to its Labyrinth device and revoke both.

## Tests

`src/labyrinth/tests.rs` covers the following:
- A mock gateway checks every request the way mls-ds admission does, then serves it from the crate's memory-backed reference server. It checks `actorDeviceId`, the base64url write body under `deny_unknown_fields`, the lowercase-hex digest and operation id, the NSID, the 300-second clock window, and the Ed25519 signature over the domain and body.
- The full lifecycle: archive, a recovery-code restore on a second device, history, revocation, reopening from the vault, and sending after rotation.
- Re-archive, a forged-key write, a signer failure, a concurrent state writer and the roster filter.
- One orchestrator test on the e2e harness (`TestWorld`). A send is archived, a second device of the account restores and imports the message into its own storage, leaving re-archives, and the second device revokes the first.

No harness runs catbird-mls against a live mls-ds. The mls-ds lane's `e2e-tests` crate depends on `../../catbird-mls` and could host such a test once the gateway seam is implemented for its HTTP client.
