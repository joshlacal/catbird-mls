# Direct conversation recovery implementation plan

**Goal:** Recover an authorized existing direct conversation after the delivery service rejects duplicate creation, or present the precise pending/cooldown state without losing saved history.

**Architecture:** Rust remains the authority for inventory discovery and existing-conversation adoption. Swift preserves transport error responses and presents actionable lifecycle outcomes. No membership bypass, forced rejoin, or conversation deletion is part of this change.

**Tech stack:** Rust orchestrator, UniFFI, Swift/GRDB, Xcode device build.

**Contract:** `../PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.createConversation.json`; a direct conversation is unique per nonterminal DID pair. A duplicate may return `ConversationAlreadyExists`; discovery must use the acting device's authorized inventory.

## Evidence and constraints

Phone process 3291 received HTTP 400 `ConversationAlreadyExists` at 11:32:01 and 11:32:04. Swift hid the subsequent underlying error behind its generic open-conversation alert. The linked native artifact is v1.5.18 and contains duplicate discovery/adoption code. Existing HTTP 400 coverage uses no peer, while adoption tests start with HTTP 200; the full one-peer path lacks coverage. Other actors have extensive uncommitted changes in all involved repositories; preserve them and make path-scoped changes only. Production releases, server writes, and data deletion are outside this implementation.

## Tasks

- [x] Verify lexicon, Swift response preservation, Rust duplicate classification, and linked artifact provenance.
- [x] Capture the actual failure before `MLSConversationLifecycleError.presenting` wraps it. Add a diagnostic at `../CatbirdMLSCore/Sources/CatbirdMLSCore/Service/MLSOrchestratorRuntime.swift:createConversation`, rebuild on the same phone, and repeat the user's attempt. Distinguish an inventory cooldown, unavailable authorized conversation, and failed adoption; do not infer from the original create response alone.
- [x] Add a Rust integration regression in `tests/clean_chat_direct_adoption_tests.rs`: first create receives HTTP 400 `ConversationAlreadyExists`; one exact peer is provided; inventory returns the authorized active direct pair; adoption returns the same stable conversation ID and discards the speculative new MLS group. Also verify no unauthorized or closed inventory entry is adopted. Run `cargo test --test clean_chat_direct_adoption_tests` with the repository's required features.
- [x] Apply the smallest correction at the demonstrated failure boundary. For discovery/adoption failure, change `src/orchestrator/direct_adoption.rs` or the corresponding create branch in `src/orchestrator/groups.rs` and reproduce before/after with the integration regression. For a valid cooldown or device-access-pending result, retain the protocol outcome and correct `MLSConversationLifecycleError.swift` presentation with a Swift regression; do not bypass server authority or cooldown to make the UI appear successful.
- [x] Run focused Rust and Swift tests and review exact diffs. If native code changes, build a local matching native artifact without publishing or changing unrelated generated bindings, and verify the phone links it. Preserve the published dependency configuration outside the local verification build.
- [ ] Build and launch on Josh's iPhone using Xcode MCP. Capture create/recovery logs and the user's send attempt. Report separately whether existing-chat opening, server acceptance of a message, and recipient delivery were observed.

## Acceptance

An authorized existing direct chat opens using its existing stable identity after duplicate creation. Closed transcripts remain history. A pending device or server cooldown produces an accurate user-visible state. A successful build or local send alone is not proof of recipient delivery.

## Confirmed diagnosis and implementation decision

The diagnostic phone build captured `ServerError(status: 429, body: "Rate limited. Retry after 240 seconds.")` immediately after duplicate creation. Rust integration tests cover both an HTTP 429 inventory response and a callback-thrown 429; all 29 passed and the speculative group was cleaned up while existing history/keys remained. Duplicate recovery itself is correct; subsequent startup evidence below identifies the native request multiplier requiring correction.

Implement a typed Swift lifecycle cooldown in `MLSConversationLifecycleError.swift`, accepting only a validated server delay. Add an app-level asynchronous retry coordinator outside native locks: at most three direct-conversation creation attempts (one peer only), delay bounded by the inventory contract's 901-second maximum, cancellable countdown, and active-account/screen checks. Both new-chat views display progress and cancel their owned creation task on dismissal. Unknown-delay rate limits and other errors return without automatic retry. Preserve selected members and metadata across retries. Tests exercise successful retry, cancellation, changed context, invalid/no hint, other errors, and bounded repeated throttling. Verify Swift package tests, a full phone build, and fresh runtime reproduction before claiming user-path recovery.

## Implementation verification

- Rust direct adoption suite: 29 passed (`/tmp/mls-direct-adoption-regression.log`).
- Lifecycle cooldown mapping: 5 new plus 6 existing presentation tests passed (`/tmp/mls-lifecycle-rate-green.log`).
- App retry coordinator: 8 deterministic tests passed (`/tmp/mls-create-retry-green.log`); source tests are checked into the app test directory, executed through a standalone package.
- Xcode full physical-device build succeeded and launched PID 3808, session `7721d53300`, with the local Swift package overrides. No native production changes or artifact release required.
- Fresh user reproduction and recipient delivery remain pending.

## Startup inventory batch correction — September 7

Phone PID 3808 issued 20 fresh `getConversations` requests between September 6 12:59:04 and 12:59:11, then received HTTP 429. Duplicate creation recovery at 12:59:33 inherited that cooldown. Each `ConversationChanged` hint independently reconciles terminal inventory and discovers missing-leaf Welcomes; `fetch_welcome_delivery` allocates another inventory with `limit=1`. Recovery and typed conversation lookup add further allocations.

Decision: use the existing `processServerEvent(String)` ABI with `{"$type":"blue.catbird.internal#inventoryHintBatch","events":[...]}`. Validate the complete envelope before effects (at most 10,000 hints and 16 MiB UTF-8). Native code fetches one authorized inventory snapshot scoped only to that batch. Terminal reconciliation, Welcome discovery, recovery/reset and relevant conversation lookup share it; mutation-authorizing point reads, terminal verification, pagination/fence checks and account/device isolation remain mandatory. No host-provided inventory is authoritative. Discard batch state after success or failure.

The Swift adapter is already edited but must not run against published native v1.5.18. Public inventory callback overrides disable batching. Ordered reconciliation must succeed before cursor persistence or completion. Build a matching native artifact and generated bindings only in a temporary verification package; leave published dependency configuration unchanged.

- [x] Finish native envelope validation and batch-scoped authorized inventory.
- [x] Cover allocation counts, subsequent fresh batches/live events, malformed input, pagination/fence failures and error propagation.
- [x] Complete Swift ordering, selector and reconciliation barrier tests.
- [x] Rebuild matching native libraries/bindings and run native/Swift regression gates.
- [x] Build and launch the matching phone app and measure fresh startup inventory requests.
- [x] Observe the user's conversation-opening and send attempt; report opening, server acceptance and recipient delivery separately.
- [ ] Recipient explicitly accepts the invitation; verify subsequent server acceptance and recipient delivery. Blocked on recipient consent, not authorized for autonomous acceptance or sending.

The disk blocker is resolved: 833 GiB available at session start. `catbird-mls/target` was absent; both device and macOS libraries were rebuilt from source. The obsolete `/tmp/CatbirdPhoneVerification.ogMFLX/dd-control` still exists and was left untouched.

Verification package: `/var/folders/f6/7_1t6xsd07j6601z9xpxxbdw0000gn/T/CatbirdBatchVerification.4fu_r9cz`. Its `CatbirdMLSCore` manifest and generated bindings are temporary; canonical published dependency configuration remains unchanged. The regenerated C header is byte-identical to published v1.5.18. Device library SHA-256: `8e6765aa70b51a244f751e00363292695486eef64be38c7be9463aeb91afa223`; macOS library: `d510bd40673e0429d60d3fdba099022a0f971cdccb1fce3d3230693310bbf196`.

Native batch context is execution-local, not an orchestrator-wide cache: Tokio scopes the snapshot to the executing future, with orchestrator identity and DID/device checks. Concurrent batches cannot lend or clear one another's inventory. Native-only scope code is excluded from WASM, preserving its existing non-batch behavior.

Verified gates:
- `cargo test --features test-utils --lib engine::server_events::tests`: 20 passed.
- `cargo test --features test-utils --test clean_chat_direct_adoption_tests --test clean_chat_engine_invitation_tests --test full_rust_engine_lifecycle_tests`: 79 passed. Removed an obsolete `leafIndex` fixture override; the resume fixture now retains its credential store across engine recreation.
- `cargo check --lib --target wasm32-unknown-unknown --features browser`: passed with warnings.
- `cargo clippy --lib --features test-utils`: passed with warnings. Whole-repository `cargo fmt --check` reports existing unrelated formatting differences; changed native files were formatted and checked separately.
- Temporary-package Swift test filter `MLSCanonicalRustEventHandlerTests|MLSConversationRateLimitTests|MLSStreamReconnectPolicyTests|MLSDirectConversationLookupTests`: 37 passed (23 batch/adapter, 5 cooldown, 5 lookup, 4 reconnect).
- `cargo build --lib --release --target aarch64-apple-ios --target aarch64-apple-darwin`: passed; UniFFI bindings regenerated from the matching host library.
- Full signed phone build succeeded with `xcodebuild -workspace <verification>/CatbirdBatch.xcworkspace -scheme Catbird -destination id=00008130-0016681004E1401C -derivedDataPath <verification>/dd build`.

Xcode MCP initially listed Josh's iPhone as active/eligible but rejected it in `DeviceInteractionStartWorkspaceSession`. Workspace open and subsequent list calls then timed out repeatedly; desktop inspection reported no active displays. The successful phone build, installation and launch used Xcode CLI/devicectl fallback. No production deployment, publication, data deletion or autonomous test-message sending was performed.

### Physical runtime result — not delivery completion

Installed the matching signed app and launched phone PID 6441 with stdout/OSLog capture. The linked `Debug-iphoneos/libCatbirdMLSFFI.a` checksum matches the rebuilt device library above. Initial startup made six fresh inventory requests between 03:57:07.821 and 03:57:08.996 local time (UTC−04:00), all HTTP 200; the global WebSocket connected at 03:57:09.411. Subsequent interactive activity brought the complete capture to 22 inventory requests, with no observed HTTP 429. The six-request count describes initial startup only, not the whole session.

The conversation opened far enough for two actual `sendMessage` requests at 03:57:44.451 and 03:57:46.038. Both reached the server and returned HTTP 400 `RecipientNotReady`. Server acceptance therefore failed, and recipient delivery was not observed. The app entered the background at 03:57:54 and later terminated with signal 9, ending capture; the termination cause is not established.

Read-only production query for conversation `5ad64d82-4b69-42e1-99c6-7e5a59b25a38` confirms an active direct conversation at generation/stateVersion 0. Sender `did:plc:7nmnou7umkr46rp7u2hbd3nb` is active. Recipient `did:plc:34x52srgxttjewbke5hguloh` (`j0sh.bsky.social`) is still pending, invited at `2026-09-06T15:30:49.795Z`, with `accepted_at = NULL`; eight active registered devices exist for that account. Registration is not the missing prerequisite: recipient consent is.

`mls-ds/server/src/chat_protocol/repository/message_delivery.rs:require_recipient_ready` requires an active, consented recipient with a valid application interval. The sender cannot authorize recipient acceptance. Next action: in recipient account `j0sh.bsky.social`, open the encrypted chat request and explicitly tap Accept. Keep a sender device online for leaf/Welcome fulfillment, then have the user send again and check the recipient device. This flow remains unverified after acceptance.

Evidence: `/tmp/mls-batch-startup-2026-09-07.log` and `/tmp/mls-batch-delivery-2026-09-07.log`. Final native rerun: 20 batch tests plus 79 recovery/invitation/lifecycle tests passed. Swift: 37 selected tests passed with the matching native library. Changed-file Rust/Swift formatting checks passed. Native editor diagnostics returned OK; SourceKit-LSP was unavailable, so Swift compilation and tests are the diagnostic proof.

## Pending direct invitations were invisible to the recipient — September 7

The recipient reported no encrypted requests and no active conversations. Two independent causes were found.

**Server (deployed).** `read_authority.rs` classified a direct-chat pending invitee as entitled to current state but excluded it from enumerable inventory, and `chat.validate_inventory_conversation_item_source()` restricted the pending-participant branch to `conversation_row.kind = 'group'`. A recipient therefore could not discover the invitation it alone may accept. Live snapshots for `did:plc:34x52srgxttjewbke5hguloh` confirmed the omission: five active conversations materialized, and conversation `5ad64d82-4b69-42e1-99c6-7e5a59b25a38` was absent.

With explicit user approval for state-only access plus deployment, the production source now returns the state arm for any pending participant, and forward migration `20260907000001_chat_direct_pending_inventory.sql` removes only the group-kind condition, guarded on the exact old and new `pg_get_functiondef` text. Message, entry, and blob authority still require an open leaf, and acceptance remains recipient-only.

Gate receipts (`authorization-gate-result.json`, source manifest `8551dd30df623a6b96e21ab1c67be23640f63537d77bad00501f36b0a163792c`): `pending_participants_get_state_only`, `inventory_precedence_is_close_open_finite_participant_none`, and `post_reset_old_exact_device_cannot_inherit_current_did_state` each passed against real PostgreSQL, asserting materialized inventory, denied entries, zero leaves/intervals, unrelated-DID denial, and exact-device finite-interval precedence. A disposable database replayed the full 85-migration baseline to 86 rows, reaching function SHA-256 `07507559efe9dd2a4c266d7205336a844c197438209164538661b9a3156f6d87`, and the migration re-ran idempotently.

Deployment used the pinned OpenMLS 0.9 builder, never the older `0.8.1` checkout. Candidate image `sha256:5f012d70f1fe664337b1a6b057b68d7319d6a02a990eb3d26229cf5e70f2a9d5` (binary `6dd9f1d7505d1bff1991b3e5cde6184e8f847f21a6022da39476ced48ad4df92`) is live and ready with the 86-row ledger, corrected function, and unchanged environment. The first attempt rolled back correctly: its readiness probe treated the public endpoint's documented `403` baseline as unreachable, so it stopped the healthy candidate and restored the forward-migration-compatible fallback `sha256:5d08e05953be7ba12cf95127f396b295d05a4b99494240eb51c993b7e2a45d03`. `switch_to_candidate.py` accepts any answered public status, still requiring local `200`, the exact image, release label, and running binary hash. Backups: `/home/josh/backups/mlsv2-recipient-state-access-activation-20260907T150302Z` (37,617,450-byte database dump, SHA-256 `9a421ece0408445cf727b89917e54d0f0b4226f4bf7365f4b35d7e879a60ca68`) and `…-candidate-switch-20260907T151026Z`.

**Client (built, not runtime-verified).** `AppState.loadMLSConversations()` never notified `stateInvalidationBus`, and `ChatTabView.refreshable` only re-read local SQLite, so a completed server sync could leave the list stale; `syncWithServer` in `.rustFull` mode also skipped `notifyObservers(.syncCompleted)`. Native projection was already correct: pending invitations persist canonical policy and survive restart without a local leaf, proven by `fresh_recipient_native_sync_yields_durable_pending_invitation_without_crypto_mutation` and its live-batch/restart sibling (26 invitation tests pass). Swift adds `testRecipientPendingRequestVisibilityAndAccountScoping` (42 selected tests pass).

Remaining: the recipient must open Catbird on `j0sh.bsky.social` so its device fetches a fresh authorized inventory; existing snapshots for that account have since expired, so no post-deployment recipient snapshot exists yet. Only then can request visibility, acceptance, leaf/Welcome fulfillment, and delivery be verified. Nothing was accepted or sent on the user's behalf.

Physical-device tooling: Xcode 27's `DeviceInteractionStartWorkspaceSession` rejects this connected iPhone (`exact_DeviceInteractionStartWorkspaceSession.json`; supported list is simulator-only), while `XcodeListRunDestinations` reports it eligible and non-simulator. A signed `agent-device` XCTest runner supplied UI hierarchy, hitPoint taps, screenshots, logs, termination, and relaunch (`/tmp/phone_evidence_20260907_094854`). Same-process post-relaunch log proof is unfinished: the saved log belongs to a later PID, and the tool refuses physical-runner startup now that `DevToolsSecurity` is restored to disabled at the user's request.
