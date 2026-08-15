# chat_v2 — Task 3 handoff

State of the clean chat protocol (`blue.catbird.chat.*`) client implementation
as of the eighteenth sealed slice. Written for the session that continues it.

Workspace: `catbird-mls-task3-ws` (isolated jj workspace; Josh's default
workspace is untouched and must stay that way).

Verification at handoff: **479 lib tests pass, 0 failures.** `cargo fmt
--check` clean, `cargo clippy --lib --all-targets` reports zero warnings under
`chat_v2`, `wasm32-unknown-unknown` builds.

---

## 1. Sealed commits

Eighteen, oldest first. All additive; the only pre-existing file touched is
`src/lib.rs` (three lines declaring the module).

| Change | Commit | What |
|---|---|---|
| `zwxousst` | `b2f5f844` | Identity primitives: canonical UUIDv4, bare DID, keyId, timestamp, Seq/SafeInteger, BasicCredential |
| `xmsovtqr` | `2ca73d78` | Typed endpoint-error mapping over all 91 codes, plus policy classification |
| `kzkorxkz` | `16c5997a` | Cursors (AfterSeq / SnapshotSeq / EventCursor) and the ordered append-log pull |
| `owzulrlq` | `02d722b0` | Pinned the getEntries advance rule; recorded two ratified decisions |
| `okvuostu` | `5ddb0871` | Skeletal UniFFI surface to unblock the iOS/Android lanes |
| `txxrsslv` | `726b1651` | Pending-transition journal; terminal close and proof primitives |
| `mxquskum` | `756538cf` | Coordinate transition relations; interval provenance types |
| `ssqpvqst` | `8e088173` | Reducer sequencing core (6a) |
| `zxryzskq` | `7c8f7a20` | Interval closure, verified reanchor, touching boundaries (6b) |
| `oukpxxkq` | `3d54a64c` | Reset-activator classification (6c) |
| `nzvoxxxn` | `0b02a553` | The two Terminal modes (6d) |
| `twsmwtww` | `a16e4fe5` | Handoff refresh for the built reducer |
| `kszmquql` | `6309353f` | Canonical signing transcript, byte-identical to mls-ds (S7a) |
| `xyxvwryy` | `6d88c594` | Strict signed-wrapper decode and Ed25519 verification (S7b) |
| `ykrlymzw` | `0b6da15f` | Vector provenance, ratified I-1 correction, two doc anchors |
| `rlqxsxqt` | `beb865c5` | The two outer entry fingerprint domains (S7c) |
| `wvyrrrox` | `8b71a345` | Wire JSON projection through the lexicon contract (S7d-pre) |
| `ysqxmrrk` | `a57914c4` | Application entry verification and sender binding (S7d) |

### The detached-HEAD trap — read before concluding a server file is missing

`mls-ds`'s working tree is checked out at a **detached revision that predates
the clean-chat work**. `server/src/chat_protocol/transcript.rs` and
`server/tests/fixtures/*.json` are **not on disk there**, and a filesystem
search finds only stale copies under `.codex-workspaces/` lanes. They are
tracked on `main` and must be read through git:

```sh
cd Catbird+Petrel/mls-ds
/usr/bin/git ls-tree -r --name-only main -- server/src/chat_protocol/
/usr/bin/git show main:server/src/chat_protocol/transcript.rs
```

This session nearly concluded the transcript implementation did not exist.
Absence proofs need positive controls: before reporting a server file missing,
check `git ls-tree` on `main`, not just the working tree. Git stays read-only
here — `show`/`ls-tree`/`rev-parse` only, never a checkout.

### Known pre-existing breakage, not ours

`tests/sequencer_did_sync_tests.rs` does not compile. It writes
`TypedConvoView<'_>` but the current generated `ConvoView<S: BosStr>` takes a
type parameter, not a lifetime — jacquard generator drift in v1 `mlsChat`
territory. Proven pre-existing by building it in a throwaway workspace at the
parent revision `f76b01d7`, where `src/chat_v2` does not exist, and getting the
identical two `E0107` errors. Filed with the lead as a separate v1 item.

Also worth knowing: `cargo test --no-run --no-fail-fast` reports *extra*
broken targets that are actually fine — cargo lists cascading and aborted
targets. Build each target individually before believing a regression.

---

## 2. Ratified decisions — do not silently revisit

Each was decided with evidence and is pinned by a test. Changing one is a
deliberate policy change, not a refactor.

**Auto-retry set is exactly two codes**: `RateLimited` and
`RelationshipPolicyUnavailable`. The latter signals unavailable, incomplete, or
stale *evidence* rather than a denial. Its denial counterparts
(`BlockedRelationship`, `MessagesDisabled`, `GroupInvitesDisabled`,
`NotFollowedByRecipient`) are never retried — waiting cannot clear a block, and
scheduled re-attempts keep leaking activity and presence to exactly the party
who asked not to receive it. That second reason is the safety one and is
recorded in `endpoint_error/class.rs`.

**Unknown error codes fail closed** — not retryable, not resync, terminal. The
classification match is exhaustive with no wildcard, so a lexicon change adding
a code breaks the build until someone triages it. That is intentional:
defaulting new codes to "retry" is how a client hammers an endpoint that will
never succeed.

**`nextAfterSeq` is strict equality with the greatest returned seq.** The lead
initially asked for `>=` to accommodate per-device visibility gaps; that was
withdrawn after review. Gaps are skipped by the *entries*, not the cursor — a
page may return seq 5 then seq 900 and land the cursor on 900 — so an invisible
row is never something the cursor must step over. Relaxing to `>=` would make a
server returning seq 1 while claiming `nextAfterSeq` 900 indistinguishable from
a legitimate gapped page, silently losing 899 entitled entries. Both cases are
pinned as distinguishable in `append_log.rs`.

**Bare-DID constraints are cumulative** (Josh, verbatim): "A DID MUST satisfy
the global 12–261 ASCII-byte length bound in addition to its method-specific
grammar; consequently, `did:web:a.b` is invalid despite satisfying the
`did:web` hostname-production rules." The 11-byte rejection vector cites this
ruling in `ids/did.rs`, because a reader seeing only the grammar would conclude
it is valid.

**Chartered open question — scan budget.** The frozen contract gives a server
no way to say "I scanned a large inaccessible region, found nothing visible, and
have not reached the end". Empty forces `nextAfterSeq == afterSeq`, and
`hasMore` is defined by whether a visible entry exists above rather than by how
far the server looked — so a device resuming beneath a very large gap implies an
unbounded server scan. This needs a *contract* answer before `getEntries` is
built. It is on the Task 1 / stub-program charter list; the write-up in
`append_log.rs`'s module docs is its input. Do not paper over it with a
client-side `>=`.

---

## 3. Module map

```
chat_v2/
  ids/          identity grammars, all reject-never-normalize
  endpoint_error/  91 codes, policy classification, serde extraction
  cursor.rs     AfterSeq / SnapshotSeq / EventCursor
  append_log.rs ordered pull, page validation, sink contract
  wire.rs       the ONLY place that pattern-matches the generated union
  journal.rs    pending-transition journal
  provenance.rs fingerprints, close kinds, hint-vs-authority split
  coordinate.rs full coordinate + transition relations
  interval.rs   interval provenance, adjacency, schedule terminal proof
  transcript/   envelope verification, complete (S7a-S7d)
    value.rs    the canonical value model; UUID-as-bytes lives here
    strict_json.rs  the strict JSON profile and STANDARD base64
    signed.rs   two-field wrapper, verify_strict, key-ID binding
    fingerprint.rs  both fingerprint domains, 13 control kinds, serverFields
    contract.rs the embedded lexicon projection; the four ref-name special cases
    entry.rs    application entry shape, conversation binding, sender identity
    vectors/    vendored server golden vectors + lexicon + PROVENANCE.md
  reducer/
    mod.rs      sequencing core (6a)
    reanchor.rs closure, reanchor, touching boundaries (6b)
    reset.rs    the three reset-activator roles (6c)
    terminal.rs the two Terminal modes (6d)
  ffi.rs        skeletal UniFFI surface (cfg'd out on wasm32)
```

### Isolation from v1

`chat_v2::isolation` is a test that walks the tree and fails on any v1
orchestrator import, with a positive control proving the matcher can fail. The
needles are assembled at runtime so the gate's own source is not a violation of
itself. **Keep it passing.** v1 and v2 never interoperate.

Storage isolation is still to be built and must be *physical*: v2 gets its own
storage trait with every method required (v1's 20-of-34 default-no-op methods
are a silent data-loss footgun), and platforms open a separate store. v1's
storage is flat with no namespace concept to parallel, and the OpenMLS store has
no prefix mechanism, so a shared context would put v1 and v2 groups in the same
table keyed only by group id.

---

## 4. Reducer: complete (6a–6d)

Every path §6 describes is now built. No unbuilt path remains in the reducer,
so a refusal you meet here is a real rule rather than a placeholder — check the
status table at the end of this section before relaxing one.

### Built (6a, `reducer/mod.rs`)

`ApplicationReducer` bound to one `RecipientBinding` = `(conversation, DID,
device)`. Initial opening install comparing all five fields;
`apply_sequential_control` requiring `previous == expected` and installing
`next`; inclusive-range application visibility; post-terminal guard.

### Built (6b, `reducer/reanchor.rs`)

`close_interval` (clears expected — nothing sequences through a gap),
`reanchor` gated on `ReanchorAuthority`, `apply_touching_boundary` processing
one shared row once.

Two design points that must survive refactoring:

- **`ReanchorAuthority` has no constructor from a hint.** It is a closed
  two-variant enum (`VerifiedWelcome`, `VerifiedPostJoinOpening`). The spec says
  "an arbitrary current head and a mid-interval row are never reanchor proof";
  the absence of a constructor is what enforces that. Do not add a
  `From<CloseHint>` or an "unchecked" variant.
- **`TouchingBoundary` is one object because it is one row.** The spec requires
  the boundary be processed once and advance once. Splitting it back into a
  close call plus an open call would let one authenticated event advance the
  context twice.

### Built (6c, `reducer/reset.rs`)

`apply_reset_activation` covers all three §6 roles and **derives** which one
applies. `ResetActivation` carries only what the verified row states, including
a two-variant `ResetParticipation` (`Activator { opening_context }` /
`Retired`); the reducer decides old-leaf vs non-leaf from `has_open_interval()`
and returns a `ResetRole`.

| Participation | Held access | Role | Mechanism |
|---|---|---|---|
| `Activator` | yes | `OldLeafActivator` | touching `Reset -> Reset` |
| `Activator` | no | `NonLeafActivator` | first `Reset` interval at the reset row |
| `Retired` | yes | `RetiredOldLeaf` | close only |
| `Retired` | no | — | `ResetAffectsNoInterval` |

Design points that must survive refactoring:

- **The role is derived, never accepted.** The hazard is an old leaf taking the
  non-leaf path, which deliberately does not compare `previous` against an
  expected context. Deriving the role means no argument exists that could
  request that, so it is unrepresentable rather than refused.
- **Case 2 does not go through `reanchor`.** An earlier draft of this document
  said it did. It cannot: `ReanchorAuthority` is a closed two-variant enum and
  reset activation is neither variant. Case 2 has its own private path
  (`open_activator_genesis`), and `ReanchorAuthority` was left alone. No new
  authority marker type was added either — the row's `OuterEntryFingerprint` is
  already constructible only by the envelope-verification layer, so it is the
  same structural gate.
- **"Not an old leaf" means not a leaf *at the reset*, not never a leaf.** A
  device removed at seq 3 can activate a reset at seq 20, so the new opening
  must clear any earlier close strictly.

### Built (6d, `reducer/terminal.rs`)

`apply_terminal` covers both §6 modes and derives which applies, returning a
`TerminalMode`.

1. **Open interval** → `ClosedOpenInterval`. Requires `previous == expected`,
   closes inclusively, and installs `ApplicationScheduleTerminalProof`.
   **Atomicity is the requirement**: every fallible check runs before any state
   is touched, so the close and the proof land together or not at all. A test
   pins that a refusal deposits neither half.
2. **Last interval already closed by Remove or Reset** → `ScheduleProofOnly`.
   Installs only the schedule proof. Does not consult `previous`, does not
   rewrite or double-close the old interval, grants no gap history — three
   separate tests.

Both modes are irreversible, and that is checked against **all seven** entry
points rather than a sample, with a positive control proving the sweep rejects a
reducer that was never terminalized.

### Named refusals: current status

The standing rule is that unbuilt paths refuse by name rather than permit.

| Refusal | Where | Status |
|---|---|---|
| `TerminalRequiresScheduleProof` | `close_interval`, `apply_touching_boundary` | **permanent, not a placeholder** |
| `NoOpenInterval` on a post-gap control | `apply_sequential_control` | converted by 6b (reanchor) |
| `install_initial_opening` over a closed interval | `reducer/mod.rs` | stays refused; reanchor is the path |
| `ResetAffectsNoInterval` | `apply_reset_activation` | permanent; §6 has no fourth reset role |
| `TerminalAfterUnsupportedClose`, `TerminalWithoutSchedule` | `apply_terminal` | permanent |

`TerminalRequiresScheduleProof` deserves the emphasis. 6d did **not** widen the
ordinary close paths to accept `CloseKind::Terminal`. Those paths have no proof
to install, so accepting a Terminal there is exactly the failure the refusal
exists to prevent. What 6d converted is that the refusal now has a destination:
one test pins the wrong entry point refusing *and* the identical row succeeding
through `apply_terminal`. Do not "finish the conversion" by relaxing it.

---

## 5. Envelope verification — complete (S7a–S7d)

Built in `transcript/`. Every claim below is pinned by golden vectors lifted
from the server, not by an expectation written here.

**The transcript reproduces the server byte for byte**, and the server's own
signature over its own key verifies against a transcript this crate rebuilds
from wire JSON. Format agreement would not pass those tests; only byte
agreement does.

### What each slice built

| Slice | Commit | What |
|---|---|---|
| S7a | `6309353f` | Canonical value model, DAG-CBOR transcript, 25 signing domains, request digest |
| S7b | `6d88c594` | Strict JSON profile, STANDARD base64, two-field wrapper, `verify_strict`, key-ID binding |
| S7c | `beb865c5` | Both fingerprint domains, 13 control kinds, `serverFields` rules |
| S7d-pre | `8b71a345` | Wire JSON → `CanonicalBody` through the embedded lexicon contract |
| S7d | `a57914c4` | Application entry shape, conversation binding, sender identity |

### Things that will be got wrong if not read

Beyond the four byte-identity traps in section 1:

- **The lexicon does not encode the UUID-bytes rule.** `operationId` and
  `deviceId` are format-less plain strings in the contract. A field is sixteen
  raw bytes exactly when its schema is a `ref` to `#operationId` or
  `#deviceId` — a hardcoded set of four ref names in `contract.rs`, mirrored
  from the server, short-circuited before the schema is read. Deriving the rule
  from the schema yields text UUIDs and signatures that verify nowhere.
- **The conversation binding does not always read `prior`.** `creationBody` and
  `leaveCancellationBody` carry `conversationId` directly; every other
  conversation-scoped kind carries it under `prior.conversationId`. A test
  derives that pair from the contract rather than trusting the constant.
- **`ControlServerFields` refuses in both directions.** Eleven control kinds
  must carry an empty `serverFields` map; exactly two carry one field each
  (`recovery` for acceptance, `tombstone` for close). Handing content to an
  ordinary kind, or emptiness to a special one, is refused by name — a silent
  well-formed fingerprint over the wrong bytes is the worst failure available
  in this family.
- **The two fingerprint projections are different shapes on purpose.**
  Application binds six fields, control binds eight (the same six plus
  `entryKind` and `serverFields`). `entryKind` is what stops one kind's
  fingerprint being presented as another's. Unifying the shapes changes every
  fingerprint on one side; the CBOR map headers are asserted directly.

### Two refusals are security events, not format errors

`EntryError::ConversationBindingViolated` and
`EntryError::SenderIdentityMismatch` both render with a `SECURITY:` prefix, and
a test asserts that prefix so it cannot be softened as a wording nit. The first
is the replay case — a row legitimately signed for a different conversation —
and is checked **before** the signature, because reporting "bad signature" for a
replay attempt hides what happened. The second refuses a same-DID sibling device
as firmly as a stranger, since visibility is per exact `(DID, deviceId)`.

### Where the reducer and the envelope meet

`OuterEntryFingerprint` is produced only by verified-entry paths, and the
reducer accepts provenance only in that form. A row cannot reach interval
provenance without having had its shape, binding, and signature checked first.
That was the design intent recorded back in `provenance.rs`; it is now
structural rather than promised.

### Conventions worth keeping

- **Never serialize a generated DTO** for a transcript or fingerprint. DTOs emit
  fields alphabetically and carry a flattened `extra_data` catch-all.
- **Vendored vectors carry provenance.** Source repo, path, commit hash, and
  SHA-256 per source file, in `vectors/PROVENANCE.md`. A vendored vector failing
  against the encoder is **a finding to report, never a vector to adjust**.
- **`VerifiedApplicationEntry` is deliberately not `PartialEq`.** Comparing two
  verified authorities by value is not a meaningful operation.

## 6. Slices 8 and 9 — outline

**S8, application content predicates.** The five-value encrypted-image MIME enum
(`image/heic|jpeg|png|webp|gif`, with GIF on the ordinary encrypted-image path
and no remote dialect); blurhash 6–256 **UTF-8 bytes** with multibyte boundary
cases; checked `ciphertextSize == plaintextSize + 16` for image and audio;
reaction text NFC, control-free, exactly one UAX #29 extended grapheme cluster
under Unicode 17.0.0, ≤64 UTF-8 bytes; the restricted AT-URI (≤1,097 bytes,
derived `5 + 261 + 1 + 317 + 1 + 512`, no percent sign anywhere, lowercase
scheme and collection domain labels, case-sensitive terminal name and rkey);
external links ≤2,048 bytes, absolute HTTPS, nonempty host, no userinfo,
backslash, whitespace, control chars, or malformed percent encoding.

`ids/did.rs::validate_handle_hostname` is public precisely so the AT-URI
authority reuses the same grammar — do not write a second one.

**S9, recovery ladder and projection.** The bounded ladder is catch-up, pending
Welcome, target-device recovery request, reset request — in that order, and
nothing else. Deliberate absences that must stay absent:

- **No external commits.** The protocol forbids them outright. v1's
  `force_rejoin_unlocked` (`orchestrator/recovery.rs:1851`) does `delete_group`
  then `create_external_commit`; v2 must never grow an equivalent.
- **No autonomous destructive reset.** Reset activation is an explicit
  authorized act, never a fallback.
- A pending invite must accept before Add; direct traffic stays disabled until
  both participants are active and leafed.

Poison handling: detect deterministic Commit/Welcome processing failure, freeze
unsafe send and ratchet advancement, sign `recoveryKind=replace` outside MLS,
select a healthy different-DID fulfiller when available, escalate
all-peers-poisoned to active-admin reset or direct close. Server authorization
remains the general different-current-leaf rule, because poison is not
server-visible.

S9 also owns the single recovery projection platforms consume, and extending
`ffi.rs` beyond its current skeleton.

---

## 7. FFI notes for whoever extends `ffi.rs`

- The surface is deliberately small: only shapes settled by sealed slices.
  Reducer state and interval provenance are **absent on purpose** until their
  shapes stop moving.
- `chat_v2_status()` reports `is_operational = false`. A test pins
  `is_operational == outstanding.is_empty()` and that no capability appears in
  both lists. Flip it only when the outstanding list is genuinely empty.
- Policy booleans are **precomputed fields**, not derived platform-side. A sweep
  asserts they agree with the Rust classification for all 91 codes. Keep that
  sweep.
- **Confirmed negative**: the `build-android.sh` Kotlin patch list does *not*
  need an entry for `ChatV2ValidationError`. UniFFI emits `override val message
  get() = ...` as a getter rather than a constructor property, so there is no
  `Throwable.message` collision. Verified by generating Kotlin, not assumed.
  This holds only while v2 error types avoid a field literally named `message`.
- Bindings are committed artifacts. A rebuilt library without regenerated
  Swift/Kotlin gives a runtime checksum-mismatch panic, not a compile error. See
  the `ffi-propagate` skill.
- WASM shares nothing with UniFFI: `catbird-mls-web` is a separate hand-written
  `#[wasm_bindgen]` facade that consumes the orchestrator *through the traits*.
  So trait-based v2 design reaches WASM for free, but the exported JS surface is
  still hand-written per function.

---

## 8. Working conventions that earned their keep

- **Unbuilt paths refuse by name.** Every not-yet-implemented path gets an error
  variant and a test before it exists, so the next slice converts an explicit
  refusal into an implementation rather than filling silent permissiveness.
- **Assert state is unchanged after a refusal.** A rejected row that still moved
  state is worse than one that was accepted.
- **Prefer unrepresentable over checked.** Constructor absence
  (`ReanchorAuthority`), single-object modelling (`TouchingBoundary`), and
  all-or-none structs (`CloseProof`) beat runtime validation someone can route
  around.
- **Absence proofs need positive controls.** The isolation gate has a test
  proving its matcher can fail; the `chat_v2_status` probe has one proving it
  cannot lie. A control that cannot fail is not a control.
- **Verify, don't assume.** Two things this session would have got wrong
  otherwise: the pre-existing dead test target (proved by building at the parent
  revision) and the Android patch-list risk (disproved by actually generating
  Kotlin).
