# Catbird MLS Code-Smell Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an exact-snapshot, cross-client inventory of confirmed hardcoded values, silent no-ops/stubs, swallowed failures, dead compatibility paths, and protocol drift in the Catbird MLS chat system, without changing product code.

**Architecture:** Treat Catbird MLS as a repository-of-repositories joined by protocol, generated-code, FFI, identity, and persistence contracts. Freeze the current `jj` commit and dirty state of every lane, run parallel read-only audits with separate evidence files, validate candidates by tracing live callers and running focused tests, then reconcile everything into one ranked report and a separately gated remediation queue. Generated and vendored code is provenance evidence, not part of raw smell counts.

**Tech Stack:** Rust/OpenMLS/Axum/UniFFI/wasm-bindgen, Swift/SwiftUI/GRDB, Kotlin/Compose/Room/Gradle, TypeScript/SvelteKit/Tauri, PostgreSQL, SQLite/SQLCipher, jj.

**Spec:** `/Users/joshlacalamito/Developer/Catbird+Petrel/docs/MLS_CLIENT_PROTOCOL.md`, `/Users/joshlacalamito/Developer/Catbird+Petrel/docs/mls-v2/CHAT_PROTOCOL.md`, `/Users/joshlacalamito/Developer/Catbird+Petrel/docs/SECURITY_MODEL.md`, and the canonical Petrel/PetrelCatbird lexicons.

## Global Constraints

- This plan is the approval gate. Do not begin the full audit or any remediation until the user approves it.
- Product source, tests, migrations, generated bindings, lockfiles, and configuration remain read-only during the audit. The only intended writes are audit evidence and reports under this repository's `artifacts/code-smell-audit/2026-09-04/` and `docs/reviews/` directories.
- `jj` is the only history-writing tool. Do not checkpoint, clean, restore, or otherwise absorb user-owned changes in sibling repositories.
- Record the exact `jj` working-copy commit, parent, status, and diff summary before each lane. Re-record them at lane completion. If the commit changes, mark prior evidence stale and rerun only the affected checks.
- Several sibling repositories are already dirty, especially Android. Audit their recorded working-copy commits as they exist; do not call them clean baselines and do not regenerate in their canonical checkouts.
- Any byte-for-byte regeneration check runs only in an isolated `jj` workspace rooted at the recorded commit. A generator must never run over the user's current working copy.
- No production deploy, restart, migration, database write, cutover flag change, package release, push, external CI trigger, live-account enrollment, or credentialed E2E run is in scope.
- Do not load secrets or test-account credentials. Local fixtures, disposable databases, simulators, and credential-free browser tests are allowed.
- Preserve the core identity invariant: stable `conversationId` is used for API/storage/UI identity; mutable `groupId` is used for MLS crypto. A substitution is a finding only after its caller and reset behavior are traced.
- Keep legacy `blue.catbird.mlsChat.*` and clean-chat `blue.catbird.chat.*` surfaces distinct. Compatibility code is classified by reachable caller; namespace text alone is not a defect.
- A grep match is a candidate, not a finding. A confirmed finding needs exact snapshot and file/line evidence, a reachable caller or shipped configuration, behavioral consequence, source-of-truth comparison, confidence, and a regression-test recommendation.
- An empty return, `Ok(())`, `false`, `None`, or `OperationNotSupported` is not automatically wrong. Classify whether it is test-only, an explicit unsupported capability, a warned compatibility default, a safe fail-closed behavior, or a reachable silent success/failure.
- A hardcoded value is acceptable only when it is a wire/cryptographic invariant with a canonical assertion, a test fixture, or a documented safe default with an explicit override. Duplicated protocol policy, production origins/identities, magic sentinel values, and drift-prone timers/limits remain candidates.
- Generated, vendored, fixture, `_trash`, build, package-cache, and artifact paths are excluded from smell counts. They are inspected only for provenance, stale output, or accidental production inclusion.
- Skipped/ignored tests are not passes. Report pass, fail, skip, environmental block, and not-run as separate states.
- No remediation is bundled into this audit. The final report proposes fix waves; implementation begins only under a new approval.

## Scope and Ownership

| Lane | Repositories / paths | Primary concerns |
|---|---|---|
| Contract and provenance | workspace `docs/`, `Petrel`, `PetrelCatbird`, `catbird-atproto` | normative constants, lexicons, generated hashes, endpoint schemas, stale pins |
| Shared Rust core | `catbird-mls` | trait defaults, no-op/unsupported methods, panic reachability, feature flags, duplicated policy |
| Server and gateway | `mls-ds/server`, `nest/catbird` | route-to-handler parity, cutover/config defaults, swallowed proxy failures, schema drift |
| Apple | `CatbirdMLSCore`, MLS-related `Catbird` code | UniFFI callbacks, Swift fallbacks, duplicated timers/limits, lifecycle/concurrency, identity routing |
| Android | `android/Catbird` | stale JNI/UniFFI artifacts, callback defaults, coroutine lifetime, Room scoping, release/debug leakage |
| Web and desktop | `catbird-mls-web`, `catmos` | WASM/Tauri parity, silent subscriptions, parser defaults, WebSocket ownership, browser key/config fallbacks |
| CLI and bot | `catmos-cli`, `BIRDaemon` | silent CLI success, pagination/cursors, restart/idempotence, credential fallbacks, direct identity mapping |

The coordinator alone owns shared matrices, the candidate register, and the final report. Each lane worker is read-only and returns evidence to the coordinator; lane workers do not edit product code or shared report files.

Explicitly out of scope: upstream `atproto/` and `social-app/`, non-chat Catbird features, `nest/circle-appview`, historical backup/workspace copies, production infrastructure, and speculative architectural rewrites.

## Finding Taxonomy

| Code | Class | Confirmation question |
|---|---|---|
| `HC` | Hardcoded policy/configuration | Is a drift-prone origin, DID, route, timer, limit, cipher, or sentinel duplicated outside its source of truth or used as an unsafe fallback? |
| `NOOP` | No-op/stub/fake success | Can a live caller observe success, empty data, or unchanged state when required work did not occur? |
| `ERR` | Swallowed/lossy error | Is a distinct operational or integrity failure collapsed into empty/zero/false/current-time/generic status without safe caller handling? |
| `DRIFT` | Contract/generated/pin drift | Do lexicon, route, generated binding, dependency, or client/server revisions disagree? |
| `DEAD` | Dead/obsolete path | Is compatibility, feature-flag, debug, or alternate implementation unreachable or misleading yet still shipped? |
| `ID` | Identity/tenant drift | Are `conversationId`, `groupId`, DID, device, generation, cursor, or account ownership conflated? |
| `LIFE` | Lifecycle/concurrency smell | Can detached work, stale handles, blocking bridges, missing cancellation, or singleton attribution outlive its owner? |
| `TEST` | Coverage/evidence smell | Can a lane pass through skips, ignored tests, no-op mocks, stale fixtures, or assertion-free probes? |

Severity is based on reachability and consequence, not style:

- `P0`: reachable credential/key compromise, cross-account corruption, durable data loss, or catastrophic cryptographic invariant break.
- `P1`: reachable silent success/data drop, unusable registered route, stale production FFI, reset/identity corruption, or broadly reachable crash.
- `P2`: drift-prone policy duplication, swallowed operational failure, lifecycle leak/race, missing pagination/cursor handling, or misleading compatibility behavior.
- `P3`: dead code, stale comments/docs, unused flags, redundant wrappers, or localized maintainability debt with no proven runtime consequence.

## Reconnaissance Seeds, Not Final Findings

The audit starts with these concrete seeds, but must revalidate all of them against the frozen snapshots:

- Rust trait defaults in `src/orchestrator/storage.rs`, `mls_provider.rs`, `api_client.rs`, and `credentials.rs`, plus declared `android`/`browser` features that are documented as reserved.
- `CatbirdMLSCore`'s `MLSOrchestratorAPIAdapter.getDeliveryStatus` empty result and duplicated config/recovery constants across Swift managers.
- Android generated contract metadata that names a different Rust source revision than the current Rust checkout.
- Nest's clean-chat endpoint inventory currently containing one procedure not present in the mls-ds endpoint inventory; previous historical handler counts are not assumed current.
- Browser/Tauri subscription functions that appear to no-op or report success before spawned work fails, plus lossy WebSocket field defaults.
- CLI/database paths that return success for empty identifiers or collapse epoch/fetch failures to zero/empty, and BIR credential/config fallbacks that require live-path classification.

---

### Task 0: Freeze Scope, Snapshots, and Evidence Schema

**Files:**
- Create: `artifacts/code-smell-audit/2026-09-04/snapshot-manifest.md`
- Create: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`
- Create: `artifacts/code-smell-audit/2026-09-04/validation-matrix.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/contract-provenance.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/rust-core.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/server-gateway.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/apple.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/android.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/web-desktop.md`
- Create: `artifacts/code-smell-audit/2026-09-04/lanes/cli-bir.md`

**Interfaces:**
- Consumes: the current `jj` working-copy commit in each repository and the global constraints above.
- Produces: an immutable audit manifest and one normalized evidence schema used by Tasks 1–10.

- [ ] **Step 1: Record each repository snapshot without changing it**

  Run `jj log -r @`, `jj log -r @-`, `jj status`, and `jj diff --summary` in the workspace root, `catbird-mls`, `CatbirdMLSCore`, `Catbird`, `Petrel`, `PetrelCatbird`, `android`, `catmos`, `catbird-mls-web`, `catmos-cli`, `BIRDaemon`, `mls-ds`, `nest`, and `catbird-atproto`. Record the full working-copy commit ID, parent ID, dirty paths, conflicts, and active bookmarks in `snapshot-manifest.md`.

- [ ] **Step 2: Hash ignored/generated runtime artifacts**

  Record presence and SHA-256 for the CatbirdMLSCore XCFramework/generated Swift binding, Android Kotlin/JNI outputs for all four ABIs, `catbird-mls-web/pkg` JS/TypeScript/WASM outputs, relevant lockfiles, and provenance metadata. Missing ignored artifacts are recorded as `ABSENT`, never silently regenerated.

- [ ] **Step 3: Record toolchain identity**

  Capture `jj version`, `rustc --version --verbose`, `cargo --version`, `swift --version`, `xcodebuild -version`, `java -version`, Android `./gradlew --version`, `node --version`, `npm --version`, and `wasm-pack --version` where installed. Missing tools are evidence states, not reasons to omit a lane.

- [ ] **Step 4: Initialize the candidate schema**

  Use columns `id,category,severity,confidence,status,repo,snapshot,file,line,symbol,live_entrypoint,behavior,source_of_truth,evidence,test_result,existing_tracker,fix_wave`. Allowed `status` values are `candidate`, `confirmed`, `accepted`, `duplicate`, `false_positive`, and `blocked`.

- [ ] **Step 5: Verify the manifest is internally complete**

  Every in-scope repository must have one snapshot row, every generated boundary must have a hash or `ABSENT`, and every lane must name its exact snapshot before static searching begins.

### Task 1: Build the Canonical Contract, Constant, Route, and Provenance Matrices

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/contract-provenance.md`
- Create: `artifacts/code-smell-audit/2026-09-04/constants-matrix.csv`
- Create: `artifacts/code-smell-audit/2026-09-04/route-contract-matrix.csv`
- Create: `artifacts/code-smell-audit/2026-09-04/generated-provenance-matrix.csv`

**Interfaces:**
- Consumes: Task 0 manifest; `MLS_CLIENT_PROTOCOL.md`; clean-chat protocol docs; Petrel/PetrelCatbird lexicons; generated Rust/Swift/Kotlin types.
- Produces: the sources of truth against which every hardcoded/default/route candidate is judged.

- [ ] **Step 1: Extract normative identities and policy values**

  Enumerate required-now recovery, sync, key-package, retry, cursor, message-size, media, cryptographic-length, and server policy values. Record each spec value and its owning source symbol; keep roadmap-only values in a separate state so unimplemented roadmap work is not mislabeled as a smell.

- [ ] **Step 2: Extract all clean-chat endpoint declarations**

  Compare lexicon NSID and HTTP method, mls-ds `ChatEndpoint::ALL`, mls-ds router/handler, Nest `CHAT_ENDPOINTS`, Rust canonical routes, generated clients, and handwritten client adapters. One row per endpoint must state `declared`, `routed`, `implemented`, `proxied`, and `consumed` for every platform.

- [ ] **Step 3: Build the identity and state vocabulary matrix**

  Record exact field names and semantics for `conversationId`, `groupId`, `seq`, `epoch`, `resetGeneration`, actor DID, device UUID/server device ID, JKT, auth generation, and subscription cursor. Include the Rust orchestrator state machine and each platform's user-facing recovery state mapping without treating their intentionally different roles as drift.

- [ ] **Step 4: Build the generated-artifact chain**

  Trace lexicon input revisions to generated Rust/Swift/Kotlin hashes, Rust source revision to iOS XCFramework/Swift binding, Rust source revision to Android Kotlin/four `.so` files, and Rust source revision to WASM package/types. Record declared revision, resolved revision, artifact hash, and consumer pin.

- [ ] **Step 5: Compare resolved dependency graphs**

  Use `cargo metadata --locked`, `cargo tree -e features`, Swift `Package.resolved`, and Gradle dependency reports to compare OpenMLS, TLS codec, CatbirdMLSCore, Petrel, PetrelCatbird, and local sibling dependencies. Manifest comments never override resolved lock data.

- [ ] **Step 6: Promote only proven mismatches**

  A matrix mismatch enters `candidate-register.csv` only with both compared values, exact source locations, and the affected generated/runtime consumer.

### Task 2: Audit the Shared Rust Core

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/rust-core.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: Tasks 0–1; `catbird-mls/src/**`; existing tests.
- Produces: classified Rust-core findings and validation evidence for downstream clients.

- [ ] **Step 1: Inventory defaults and apparent no-ops**

  Search production Rust for `Ok(())`, empty collections, `None`, constant booleans/zeros, `OperationNotSupported`, ignored `Result`, `.ok()`, `unwrap_or*`, `todo!`, `unimplemented!`, panic/expect/unwrap, and empty trait bodies. For every trait default, enumerate every production implementer and every live caller before classification.

- [ ] **Step 2: Audit hardcoded protocol and deployment values**

  Compare durations, retry counts, thresholds, page sizes, byte limits, extension/component IDs, endpoint paths, NSIDs, signing domains, JSON field names, DIDs, and URLs against Task 1. Test fixtures and asserted wire constants remain excluded.

- [ ] **Step 3: Audit feature and target gates**

  Map declared Cargo features and `cfg` branches to actual symbols and build targets. Classify reserved flags, prototype-only storage, native/WASM differences, and compatibility exports as used, deliberately unsupported, or dead/misleading.

- [ ] **Step 4: Trace panic and fallback reachability**

  For each production `panic!`, `expect`, or `unwrap`, trace whether attacker/server/platform input can reach it and whether `catch_unwind` protects the FFI boundary. Deliberate invariant assertions need their validating guard and test cited.

- [ ] **Step 5: Run focused behavior checks**

  Run the storage compatibility/fail-closed tests, credential binding tests, recovery scheduler/state/reset tests, persistence/epoch tests, resolved conversation identity tests, group lifecycle/messaging/staged-commit tests, clean-chat transcript/reducer/storage tests, and FFI classifier tests. Capture exact test names and outcomes.

- [ ] **Step 6: Run the Rust build matrix**

  With `CMAKE_POLICY_VERSION_MINIMUM=3.5`, run `cargo test --locked --no-fail-fast`, `cargo test --locked --no-default-features --no-fail-fast`, `cargo test --locked --all-features --no-fail-fast`, `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and the supported WASM build. Record pre-existing warnings separately from findings proved by source/runtime behavior.

### Task 3: Audit mls-ds and the Nest Gateway

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/server-gateway.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`
- Modify: `artifacts/code-smell-audit/2026-09-04/route-contract-matrix.csv`

**Interfaces:**
- Consumes: Tasks 0–1; mls-ds/Nest route, handler, runtime, auth, config, migration, and test code.
- Produces: route reachability, config/default, proxy-error, and server/gateway drift findings.

- [ ] **Step 1: Prove route-to-handler completeness**

  Reconcile all clean-chat lexicons, `ChatEndpoint::ALL`, `chat_router`, `implemented_routes`, `ChatEndpoint::is_implemented`, Nest `CHAT_ENDPOINTS`, and client call sites. Stale comments are documentation findings only; actual route behavior decides implementation status.

- [ ] **Step 2: Classify server/gateway no-ops and fallbacks**

  Inspect placeholder handlers, empty success responses, invariant-error fallbacks, `.ok().flatten()`, UUID generation, unsupported-method-to-GET conversion, generic status conversion, and temporary diagnostic probes. Trace whether each path is reachable before or after cutover admission.

- [ ] **Step 3: Audit hardcoded operational values and flags**

  Compare direct/gateway origins, service DIDs, issuer/audience/key IDs, instance IDs, timeouts, quotas, page sizes, and retry hints with config and Task 1. Verify precedence for `CHAT_CUTOVER_ENABLED`, `CHAT_ENABLED`, and direct-proxy gates in test, development, and production configurations.

- [ ] **Step 4: Run endpoint inventory and contract tests**

  Run mls-ds `chat_protocol_route_inventory`, `chat_protocol_error`, `chat_protocol_production_cfg`, `chat_protocol_device_handlers`, `chat_protocol_task6_handlers`, `chat_protocol_get_entries_handler`, and `mls_chat_lexicon_contract` tests. Run Nest clean-chat token/DPoP integration coverage plus `oauth_upgrade` and `push_security` tests.

- [ ] **Step 5: Exercise negative route behavior locally**

  On disposable local state, verify all mls-ds endpoints when cutover is off, authenticated admission when on, opposite-method `405`, malformed bodies, and Nest forwarding. No external service or production database is contacted.

- [ ] **Step 6: Run server checks**

  Run `cargo fmt --check`, normal Clippy, and full tests where local PostgreSQL/fixture requirements are available. Record ignored DB suites and environmental blocks explicitly.

### Task 4: Audit CatbirdMLSCore and Catbird

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/apple.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: Tasks 0–2; generated UniFFI surface; Swift runtime adapters, storage, recovery, lifecycle, routing, and UI callers.
- Produces: Apple callback/default, identity, lifecycle, pin/provenance, and production-target findings.

- [ ] **Step 1: Audit every UniFFI callback implementation**

  Compare generated callback requirements with `MLSOrchestratorAPIAdapter`, `MLSOrchestratorStorageAdapter`, `MLSOrchestratorCredentialAdapter`, and runtime configuration. Trace empty/false/nil/default values, semaphore bridges, `Task.detached`, `try?`, broad catches, and stringly state mappings into live Rust-authoritative call paths.

- [ ] **Step 2: Reconcile Swift constants and configuration**

  Compare `MLSOrchestratorConfig+Defaults`, `MLSConversationManager`, database gates, decryption ledger, recovery manager, keychain identifiers, cipher suites, and refresh/sync timers against Task 1. Platform-specific UI timeouts remain separate only when named and justified.

- [ ] **Step 3: Trace identity and account ownership end-to-end**

  Follow `conversationId` and `groupId` through storage, sync, recovery/reset, unified chat projection, detail navigation, notifications, App Intents, share-to-chat, macOS routing, and background refresh. Inspect tenant scoping, account switch, stale manager reuse, shutdown, and observer cleanup.

- [ ] **Step 4: Audit legacy/debug/preview reachability**

  Inventory generated legacy exports, deprecated reset/message methods, debug diagnostics, previews, mocks, and conditional compilation. Confirm Xcode target membership and live call sites before classifying them.

- [ ] **Step 5: Validate existing focused suites**

  Run `swift build`, `swift test`, and focused adapter, identity/alias, database gate, recovery, full-Rust, and canonical transport tests in CatbirdMLSCore. Run SwiftLint plus Catbird MLS identity, initialization, manager, list/detail view model, recovery, ordering, notification routing, and unified-render tests.

- [ ] **Step 6: Build Apple consumers without regenerating FFI**

  Build and test the Catbird scheme on the configured iOS simulator and build the macOS target where supported. If Task 1 establishes an FFI revision mismatch, record it; do not run `rebuild-ffi.sh` in the canonical checkout during this audit.

### Task 5: Audit Android

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/android.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: Tasks 0–2; Android generated contract metadata; Kotlin MLS runtime/storage/UI code.
- Produces: Android callback/default, lifecycle, identity, tenant-scoping, and artifact-coherence findings.

- [ ] **Step 1: Prove JNI/UniFFI artifact coherence**

  Compare recorded Rust revision, generated contract revision, Kotlin binding checksum, and all four native-library hashes. Run `MlsffiArtifactCoherenceTest` and `MLSClientCapabilitiesTest`; missing or mismatched artifacts are reported without regenerating the dirty checkout.

- [ ] **Step 2: Audit callback fallbacks and error collapse**

  Inspect `MLSPlatformLayer`, Hilt modules, device/profile/block providers, and FFI guards for `runBlocking`, broad catches, `runCatching`, `getOrNull`, empty/zero/false responses, and thread-guard behavior. Trace each candidate to the orchestrator caller and Kotlin caller semantics.

- [ ] **Step 3: Audit coroutine and account lifecycle**

  Map private/application/internal scopes, cold-start reconciliation, recovery retries, quarantine observers, workers, shutdown, logout, and account switch. Verify cancellation, DID attribution, singleton cleanup, and error visibility.

- [ ] **Step 4: Audit identity and Room scoping**

  Trace `conversationId`, `groupId`, device identifiers, reset generation, event request IDs, and cursors through DAOs, projection stores, transport, recovery, event stream, and ViewModels. For every unscoped DAO method, enumerate callers and prove tenant isolation or record a finding.

- [ ] **Step 5: Audit debug/release and hardcoded policy**

  Compare endpoints, timeouts, page sizes, retry delays, and limits with Task 1/config. Inspect debug source sets, `BuildConfig.DEBUG`, mocks, manifests, and diagnostics for release reachability.

- [ ] **Step 6: Run Android validation**

  Run focused lifecycle, recovery, identity, binding/signing, event/subscription, migration/scoping, cursor-transaction, and worker tests; then `:app:testDebugUnitTest`, `:app:lint`, `:app:assembleDebug`, `:app:assembleRelease`, `:mlsffi:assembleRelease`, and Petrel Kotlin compilation. Instrumentation remains local and is reported separately if no emulator/device is available.

### Task 6: Audit catbird-mls-web and Catmos

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/web-desktop.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: Tasks 0–2; WASM/browser/Tauri runtime, transport, persistence, and frontend code.
- Produces: browser/Tauri no-op, parser, WebSocket, key/config, identity, and dependency findings.

- [ ] **Step 1: Audit browser and Tauri command truthfulness**

  Trace subscription/unsubscription, metadata bootstrap, cursor updates, typing/member operations, and unsupported legacy mutations. Confirm whether success is returned before required background work begins or fails, and whether unsupported capabilities fail explicitly.

- [ ] **Step 2: Audit WebSocket parsing and ownership**

  Inspect ticket URL construction/encoding, endpoint-origin validation, request timeouts, callback errors, malformed/unknown frame handling, missing-field defaults, cursor persistence, replacement/close races, logout cleanup, and global `*` subscription mapping.

- [ ] **Step 3: Audit identity mapping and persistence**

  Follow canonical conversation IDs, legacy aliases, current group IDs, reset events, message merge, memberships, system messages, and cursors through Worker, WASM, and Tauri paths. Use reset/global-subscription cases to expose group-shaped IDs or wildcard leakage.

- [ ] **Step 4: Audit browser/Tauri configuration and key custody defaults**

  Classify hardcoded Nest/DS origins, local preview behavior, session/local storage keys, plaintext fallback, timer values, and verbose release logging. Compare documented storage behavior with actual runtime code.

- [ ] **Step 5: Reconcile browser protocol duplication**

  Compare handwritten `browser_transport.rs`, browser/Tauri `websocket.rs`, and Tauri `api_client.rs` with generated lexicons and shared Rust canonical projection/routes. Separately resolve the web manifest's OpenMLS/TLS versions through `cargo metadata`.

- [ ] **Step 6: Run web/desktop validation**

  Run web native/WASM/tooling tests and build, browser transport/provenance tests, Catmos `npm run check`, `npm run build`, `npm run check:rust`, `npm run build:wasm`, and focused Tauri API/storage/WebSocket tests. Record browser features that are untestable without credentials as not-run.

### Task 7: Audit catmos-cli and BIRDaemon

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/lanes/cli-bir.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: Tasks 0–2; CLI/TUI and bot transport/storage/auth/lifecycle code.
- Produces: CLI/bot no-op, pagination, identity, persistence, credential, and operational-default findings.

- [ ] **Step 1: Audit CLI command truthfulness**

  Trace every command branch from argument parsing through service/storage calls to exit status and output. Verify empty IDs, fetch failures, unsupported operations, and missing data cannot become successful empty output or exit zero.

- [ ] **Step 2: Audit CLI storage and migration behavior**

  Inspect ignored row errors, HMAC lookup collapse, message deletion migrations, `/tmp` fallbacks, encryption initialization, and alias/cursor/reset/quarantine persistence. Require explicit failure or documented recovery for partial/corrupt rows.

- [ ] **Step 3: Audit bot authority, credential, and configuration paths**

  Trace app-password, bearer/DPoP/delegation compatibility, clean-chat JKT keys, Nest authority, SQLCipher key derivation, bridge client fallback, loopback defaults, refresh/relogin, and platform keychain/stub behavior from startup to message send.

- [ ] **Step 4: Audit WebSocket, pagination, restart, and idempotence**

  Verify URL encoding, cursor monotonicity, duplicate-cursor detection, all `hasMore` loops, stale handle cleanup, pending Welcome/reset state, bridge polling identity, and restart behavior.

- [ ] **Step 5: Separate active and dormant implementations**

  Prove whether BIR `BridgeClient` or the older LLM client is instantiated, and whether test/fake/non-macOS implementations can enter shipped runtime. Dead code is not reported as a live security flaw.

- [ ] **Step 6: Run CLI/BIR validation**

  With `CMAKE_POLICY_VERSION_MINIMUM=3.5`, run focused catmos-core canonical/auth/WebSocket/recovery/storage tests, then workspace check/tests/fmt/clippy. Run BIR canonical runtime, XRPC, chat-authority, storage, credentials, and keychain tests, then full check/tests/fmt/clippy. No daemon login or external message send occurs.

### Task 8: Reconcile Cross-Client Contract and Generated-Artifact Drift

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/constants-matrix.csv`
- Modify: `artifacts/code-smell-audit/2026-09-04/route-contract-matrix.csv`
- Modify: `artifacts/code-smell-audit/2026-09-04/generated-provenance-matrix.csv`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: Tasks 1–7 lane evidence.
- Produces: deduplicated root causes instead of per-client copies of the same drift.

- [ ] **Step 1: Compare every duplicated constant by semantic owner**

  Group values by policy name rather than number. Distinguish required-now protocol policy, server-only policy, platform UI behavior, and roadmap constants. Promote one root finding when multiple clients copy the same policy source.

- [ ] **Step 2: Compare every endpoint and error mapping**

  Require NSID, HTTP method, input/output fields, optionality, typed error/status, pagination, and auth/signing classification to agree from lexicon through server, gateway, generated clients, and handwritten adapters.

- [ ] **Step 3: Verify cross-target serialization vectors**

  Run existing golden-vector tests for signed transcripts, canonical body projection, fingerprints, AAD, recovery provenance, and wire payloads in Rust, Swift, Kotlin, and WASM. Record missing consumers as coverage findings.

- [ ] **Step 4: Verify FFI/API revision propagation**

  Resolve one Rust source revision for iOS, Android, and WASM. A mismatch is one provenance root cause with affected-consumer children, not separate unrelated tickets.

- [ ] **Step 5: Verify identity/recovery semantics across every adapter**

  Compare create/adopt, send, receive, reset, rejoin, subscription, notification, and navigation flows for stable conversation identity, mutable group identity, monotonic sequence, reset generation, and account/device binding.

- [ ] **Step 6: Audit compatibility shims as a graph**

  Inventory old namespace routes, legacy FFI exports, aliases, fallback authentication, and deprecated storage fields. Classify each edge as required compatibility with a live owner, explicit unsupported failure, or removable dead path.

### Task 9: Validate Candidates and Audit the Test Harness

**Files:**
- Modify: `artifacts/code-smell-audit/2026-09-04/validation-matrix.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`

**Interfaces:**
- Consumes: all candidates from Tasks 2–8.
- Produces: confirmed/accepted/false-positive/blocked dispositions with reproducible evidence.

- [ ] **Step 1: Audit tests for false green states**

  Inventory Rust `#[ignore]`, Swift/Kotlin disabled tests, shell `SKIP`, `|| true`, caught assertions, empty mocks, always-success adapters, fixture-only request construction, and E2E aggregation that passes despite skips.

- [ ] **Step 2: Trace candidate reachability**

  For each candidate, record the runtime entrypoint, implementation selection, feature/build target, caller handling, and state mutation. Unreachable code moves to `DEAD`; test-only code moves to `accepted` unless it masks production parity.

- [ ] **Step 3: Prove behavioral consequence with existing tests or read-only probes**

  Prefer an existing focused test. If none exists, use a disposable external harness or static counterexample without editing product tests. Record the exact regression test that remediation must add.

- [ ] **Step 4: Recheck known backlog and prior reports**

  Mark already-tracked issues as `duplicate` with the exact current tracker and verify whether their stated status still matches the frozen source. Historical “fixed” and “stub” claims are never accepted without current code evidence.

- [ ] **Step 5: Apply severity and confidence consistently**

  Require two independent pieces of evidence for `P0/P1` where practical: source/reachability plus a focused test, contract mismatch, or deterministic runtime proof. Separate security impact from correctness, operability, and maintainability impact.

- [ ] **Step 6: Re-freeze snapshots and identify drift**

  Repeat Task 0's repository checks. Rerun evidence for lanes whose commit changed; otherwise record the same commit ID as the audit end state.

### Task 10: Produce the Final Report and Remediation Waves

**Files:**
- Create: `docs/reviews/2026-09-04-catbird-mls-code-smell-audit.md`
- Modify: `artifacts/code-smell-audit/2026-09-04/candidate-register.csv`
- Modify: `artifacts/code-smell-audit/2026-09-04/validation-matrix.md`

**Interfaces:**
- Consumes: frozen manifest, lane reports, matrices, candidate dispositions, and test results.
- Produces: one reviewable audit verdict and a separately approved remediation sequence.

- [ ] **Step 1: Write a cold-reader executive summary**

  State exact scope/snapshots, dirty-state caveats, total confirmed findings by severity/category/repository, the highest-risk root causes, and what was not tested. Do not describe “zero findings” as exhaustive proof.

- [ ] **Step 2: Write each confirmed finding in a fixed format**

  Include title, severity, category, affected snapshots, exact file/line/symbol, live call chain, observed/expected behavior, consequence, proof, current tests, proposed regression test, affected clients, and suggested owner.

- [ ] **Step 3: Publish non-findings and accepted exceptions**

  List high-signal false positives, intentional compatibility defaults, wire constants, test fixtures, and unreachable stubs so later audits do not rediscover them without context.

- [ ] **Step 4: Publish coverage and provenance gaps**

  List skipped/ignored/blocked tests, absent artifacts, dirty-snapshot limitations, unverified credentialed flows, and any generator comparison that could not safely run.

- [ ] **Step 5: Propose dependency-ordered remediation waves**

  Wave 0: sources of truth, endpoint/route truthfulness, stale generated artifacts, identity/account binding, and reachable silent success/data loss. Wave 1: error propagation, lifecycle ownership, pagination/cursors, and centralized configuration. Wave 2: dead compatibility paths, reserved flags, stale docs/comments, and maintainability cleanup. Each wave names owning repositories, required regression tests, cross-client propagation, and verification gates.

- [ ] **Step 6: Run two independent read-only reviews of the report**

  One reviewer checks evidence/reachability and false positives; the other checks cross-client contract/provenance completeness. Resolve disagreements in the report without changing product code.

- [ ] **Step 7: Self-review the report and stop**

  Verify every in-scope lane has a disposition, every `P0/P1` has reproducible support, every recommendation maps to a confirmed finding or coverage gap, and no remediation was performed. Hand the report and proposed waves to the user for a separate implementation decision.

## Execution Command Matrix

Run these commands against the Task 0 snapshots. Capture exit code and full output; do not shorten a failure to “red.” Commands that require unavailable local services remain `blocked`, not `passed`.

### Contract and provenance

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Petrel
swift build
swift test

cd /Users/joshlacalamito/Developer/Catbird+Petrel/PetrelCatbird
swift build
swift test

cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-atproto
cargo metadata --locked --format-version 1 --no-deps
cargo test --locked --no-fail-fast
```

If byte-for-byte generation is needed, create isolated `jj` workspaces at the manifest commits and run only there:

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel
./scripts/regenerate-atproto-types.sh

cd /Users/joshlacalamito/Developer/Catbird+Petrel/Petrel
./Scripts/regenerate-generated.sh
```

Expected: the isolated regeneration either produces no semantic/hash drift or records an exact diff tied to both input revisions. Do not copy output back during the audit.

### Shared Rust core

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --locked --no-fail-fast
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --locked --no-default-features --no-fail-fast
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --locked --all-features --no-fail-fast
cargo fmt --check
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo clippy --all-targets --all-features
cargo metadata --locked --format-version 1 --no-deps
cargo tree -e features
cargo build --target wasm32-unknown-unknown
```

Expected: every suite reports a discrete pass/fail/ignore count; feature and WASM failures are classified by root cause instead of being hidden behind the default build.

### mls-ds server

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls-ds/server
cargo test --locked --test chat_protocol_route_inventory
cargo test --locked --test chat_protocol_error
cargo test --locked --test chat_protocol_production_cfg
cargo test --locked --test chat_protocol_device_handlers
cargo test --locked --test chat_protocol_task6_handlers
cargo test --locked --test chat_protocol_get_entries_handler
cargo test --locked --test mls_chat_lexicon_contract
cargo test --locked --no-fail-fast
cargo fmt --check
cargo clippy --all-targets --all-features
```

Expected: route and lexicon inventories agree or yield exact missing/extra NSIDs; database-dependent failures name the missing service/fixture rather than being counted as product regressions.

### Nest gateway

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/nest/catbird
cargo test --locked --test integration_tests test_clean_chat_token_and_dpop_proof_flow
cargo test --locked --test integration_tests
cargo test --locked --test oauth_upgrade
cargo test --locked --test push_security
cargo test --locked --no-fail-fast
cargo fmt --check
cargo clippy --all-targets --all-features
```

Expected: gateway forwarding, device binding, and method/status behavior fail explicitly where prerequisites are absent; no fallback is credited without caller-level proof.

### CatbirdMLSCore

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/CatbirdMLSCore
swift build
swift test --filter MLSOrchestratorStorageAdapterTests
swift test --filter MLSOrchestratorCredentialAdapterTests
swift test --filter MLSConversationIdentityTests
swift test --filter MLSConversationAliasSafetyTests
swift test --filter MLSDatabaseGateTests
swift test --filter MLSRecovery
swift test --filter MLSFullRust
swift test --filter MLSCanonicalTransportAdapterTests
swift test
```

Expected: focused adapter/default/identity/recovery behavior is visible before the aggregate suite; generated FFI is not rebuilt in this checkout.

### Catbird app

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Catbird
swiftlint
xcodebuild -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/MLSConversationIdentityBoundaryTests
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/MLSConversationInitializationTests
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/MLSConversationManagerTests
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/MLSRecoveryTests
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/MLSMessageOrderingTests
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/ChatNotificationRoutingTests
xcodebuild test -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -only-testing:CatbirdTests/UnifiedChatRenderSignatureTests
```

Expected: the app compiles against the recorded Core/FFI pin and focused identity/lifecycle/rendering suites produce explicit results. No live account is used.

### Android

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/android/Catbird
./gradlew :app:testDebugUnitTest --tests 'blue.catbird.mls.*' --tests 'blue.catbird.data.local.db.*' --tests 'blue.catbird.workers.MLS*'
./gradlew :app:testDebugUnitTest
./gradlew :app:lint
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease
./gradlew :mlsffi:assembleRelease
./gradlew :petrel-catbird-kotlin:compileKotlin
```

Expected: `MlsffiArtifactCoherenceTest` and `MLSClientCapabilitiesTest` identify stale/missing artifacts before aggregate tests; ignored JNI output is not regenerated in the dirty checkout.

### catbird-mls-web

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls-web
./test-native.sh
./test-wasm.sh
./test-tooling-config.sh
AR_wasm32_unknown_unknown="$PWD/build-tools/wasm-ar" cargo check --target wasm32-unknown-unknown
./build.sh
cargo metadata --locked --format-version 1 --no-deps
cargo tree -e features
```

Expected: native and WASM results remain distinct; dependency/version drift is judged from resolved metadata, not comments.

### Catmos

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catmos
npm run check
npm run build
npm run check:rust
npm run build:wasm
```

Expected: Svelte/TypeScript, Tauri Rust, and WASM packaging each report separately; a disabled subscription or unsupported command is not treated as passing because the UI builds.

### catmos-cli

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/catmos-cli
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo check --locked -p catmos-core
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --locked -p catmos-core --no-fail-fast
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --locked --workspace --no-fail-fast
cargo fmt --check
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo clippy --all-targets --all-features
./scripts/check-canonical-sibling-provenance.sh
```

Expected: command/storage/auth failures remain visible and sibling provenance either matches the manifest or produces an exact mismatch.

### BIRDaemon

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/BIRDaemon
cargo check --locked
cargo test --locked canonical_runtime_tests --no-fail-fast
cargo test --locked xrpc_client --no-fail-fast
cargo test --locked chat_authority --no-fail-fast
cargo test --locked storage --no-fail-fast
cargo test --locked credentials --no-fail-fast
cargo test --locked keychain --no-fail-fast
cargo test --locked --no-fail-fast
cargo fmt --check
cargo clippy --all-targets --all-features
./scripts/check-canonical-sibling-provenance.sh
```

Expected: local tests exercise authority/storage/lifecycle without starting the daemon, logging in, or sending a message.

### Credentialed and external validation boundary

The workspace scripts below are inventoried for skip/failure semantics during Task 9, but are not executed under this plan without separate authorization and an exact test-account scope:

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel
./scripts/e2e_mls_chat.sh
./scripts/e2e_mls_group.sh
./scripts/e2e_parallel.sh
```

## Completion Rule

The audit is complete only when every scoped repository is tied to an exact start/end snapshot, every candidate has a disposition, route/constants/generated matrices are reconciled, focused validation is reported without converting skips into passes, and the final report separates confirmed findings, accepted exceptions, known duplicates, false positives, and blocked coverage. Product code remains unchanged.
