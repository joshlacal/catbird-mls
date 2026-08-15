# chat_v2 — Task 3 handoff

State of the clean chat protocol (`blue.catbird.chat.*`) client implementation
as of the ninth sealed slice. Written for the session that continues it.

Workspace: `catbird-mls-task3-ws` (isolated jj workspace; Josh's default
workspace is untouched and must stay that way).

Verification at handoff: **364 lib tests pass, 0 failures.** `cargo fmt
--check` clean, `cargo clippy --lib --all-targets` reports zero warnings under
`chat_v2`, `wasm32-unknown-unknown` builds.

---

## 1. Sealed commits

Nine, oldest first. All additive; the only pre-existing file touched is
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
  reducer/
    mod.rs      sequencing core (6a)
    reanchor.rs closure, reanchor, touching boundaries (6b)
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

## 4. Reducer: what exists, what 6c/6d must do

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

### Named refusals 6c/6d must convert

The standing rule is that unbuilt paths refuse by name rather than permit. Each
of these is an error variant plus a test; converting them is the work, and the
tests should become positives rather than being deleted.

| Refusal | Where | Converted by |
|---|---|---|
| `TerminalRequiresScheduleProof` | `close_interval`, `apply_touching_boundary` | 6d |
| `NoOpenInterval` on a post-gap control | `apply_sequential_control` | already 6b (reanchor) |
| `install_initial_opening` over a closed interval | `reducer/mod.rs` | stays refused; reanchor is the path |

### 6c — the three reset-activator cases

All three *mechanisms* exist; 6c is classification plus one new prohibition.

1. **Old-leaf activator** → `apply_touching_boundary` with
   `Reset -> Reset`. Already works; 6c decides when this role applies.
2. **Registered active-admin activator that was NOT an old leaf** → opens its
   first `Reset` interval at the reset row via `reanchor`. The new work is
   **no pre-reset access**: this device must not become able to see entries
   below its opening. The existing "entries before the opening are never
   visible" behaviour already covers the mechanics — 6c needs the explicit
   named test, and must verify the signed outer reset predecessor without that
   verification granting history.
3. **Every other old leaf** → close only, via `close_interval` with
   `CloseKind::Reset`, and no successor unless separately re-added.

### 6d — the two Terminal paths

1. **Open interval**: the Terminal row is sequential, requires
   `previous == expected`, and *atomically* closes the interval **and** installs
   `ApplicationScheduleTerminalProof`. Atomicity matters — a close without the
   proof is the exact failure the current named refusal exists to prevent.
2. **Last interval already closed by Remove or Reset**: an entitled signed
   Terminal arriving across the inaccessible gap installs **only** the schedule
   proof. It must NOT compare its `previous` against the reducer's stale
   expected context, must NOT rewrite or double-close the old interval, and must
   NOT grant gap history. Upstream outer Terminal authority already verified the
   real predecessor. `interval.rs` has a test sketching this shape
   (`a_schedule_proof_is_independent_of_interval_closure`).

Both paths are irreversible. Neither a hint nor a current head may substitute
for the signed row and proof.

---

## 5. Slice 7 — envelope verification

**Dependencies are ratified by Josh**: promote `ed25519-dalek` v2 and
`serde_ipld_dagcbor` 0.6 to *direct* dependencies of `catbird-mls`. These are
the exact crates and versions `mls-ds` declares directly
(`server/Cargo.toml:43,109`), both already resolve to identical versions
(2.2.0 and 0.6.4), and both are already linked transitively — `ed25519-dalek`
via `openmls_basic_credential`, `serde_ipld_dagcbor` via `jacquard-common` ←
`catbird-atproto`. So this is promotion only: no new resolution, no new
supply-chain surface. Surface the `Cargo.toml` diff before sealing, as agreed.

**Byte-identity with the server is the requirement**, so anchor on the server's
implementation rather than inventing one. `mls-ds` main,
`server/src/chat_protocol/transcript.rs`:

- `decode_canonical_signed_mutation` at `:1267`, with `verify_ed25519_strict`,
  `verify_signed_mutation`, `decode_and_verify_signed_mutation` immediately
  after.
- The two fingerprint domains are frozen there as byte constants.
- Signing transcripts are built through a hand-rolled closed `RawJson` type
  that rejects floats and negative integers outright and decodes with
  duplicate/null rejection, projecting only through an **embedded copy of the
  lexicon contract** (`include_str!` of `blue.catbird.chat.defs.json`) before
  any generated DTO exists.
- `serde_ipld_dagcbor` is used in `transcript.rs` (18 sites) and heavily in
  `state_machine.rs` (47). So the DAG-CBOR half is a real crate; only the
  JSON-decode/projection half is hand-rolled. Mirror the hand-roll with shared
  vectors rather than substituting a differently-opinionated crate.

**PROGRAM INVARIANT I-1 (dual bytes encoding)** — binding on all clients, and
verified against current code at handoff. Signed request bodies use the
certified transcript canonical form with **bare STANDARD base64** for bytes, and
the signature binds to *that* form. Jacquard's `{"$bytes": ...}` DAG-JSON
encoding is authoritative **only** for responses and unsigned params. The two
forms are mutually exclusive. The server extracts signed-body bytes via
mutation projection, never a generated-DTO parse; S7 must do the client half, so
every signer and verifier round-trips against
`decode_canonical_signed_mutation`'s semantics.

**Never serialize generated DTOs** for transcripts or fingerprints. They emit
fields alphabetically and carry a flattened `extra_data` catch-all, and the spec
forbids DTO bytes as transcript or fingerprint input. `chat_v2` owns its
encoder.

Lift golden vectors from the server suites so the two implementations cannot
drift silently. If the investigation turns up any reason these crates *cannot*
achieve byte-identity with the server encoder, surface it before sealing rather
than working around it.

S7 also owns: the exact five-field application-entry shape check, conversation
binding (`entry.conversationId == signedRequest.body.prior.conversationId`),
canonical send transcript reconstruction and strict Ed25519 verification
**before** decryption or attribution, the immutable outer fingerprint, and the
same for all 13 control kinds including their `serverFields` projection
(`{}` for ordinary, `{recovery}` for acceptance, `{tombstone}` for close — see
`wire.rs::ENTRY_KINDS_WITH_SERVER_FIELDS`).

After decryption, the authenticated MLS sender leaf and BasicCredential must
equal the verified signed outer actor DID and device. The outer identity is
never display authority by itself. `ids/credential.rs` has the comparison type.

---

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
