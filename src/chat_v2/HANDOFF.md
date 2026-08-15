# chat_v2 — Task 3 handoff

State of the clean chat protocol (`blue.catbird.chat.*`) client implementation
as of the sealed commits listed below. Written for the session that continues it.

Workspace: `catbird-mls-task3-ws` (isolated jj workspace; Josh's default
workspace is untouched and must stay that way).

> ## ⚠ CONSUMING THIS REVISION REQUIRES REGENERATING BINDINGS
>
> The UniFFI surface **changed** in `967deea2` (S9b), `eaf655ff` (S9d), and
> again in `b947ec01` (S10f): the recovery projection and its rung enum were
> added, the status probe's capability lists moved twice, and those lists then
> became `Vec<ChatV2Capability>` (name plus description) rather than
> `Vec<String>`.
>
> A client built against a rebuilt library **without regenerated Swift/Kotlin
> panics at runtime with a checksum mismatch.** It is not a compile error, so
> nothing catches it before the app is running.
>
> - iOS: `CatbirdMLSCore/Scripts/rebuild-ffi.sh`
> - Android: `./build-android.sh`
> - See the `ffi-propagate` skill.
>
> Bindings are committed artifacts. Regeneration belongs to the coordinated
> landing pass, not to this workspace — nothing ships from here — but the
> obligation travels with the revision.

Verification at handoff: **690 lib tests pass, 0 failures.** `cargo fmt
--check` clean, `cargo clippy --lib` reports zero warnings under `chat_v2`,
`wasm32-unknown-unknown` builds.

> The count in this line has been stale twice. It is the output of
> `cargo test --lib` at the tip listed in section 1, and nothing else.

### The fix round is complete

Every finding from the adversarial review of `83ff47d8` is closed. The two items
the storage lane handed forward — the missing seq high-water mark and
`apply_close` overwriting an existing close — are both fixed here, so this
section no longer carries open work.

| Finding | Commit | What closed it |
|---|---|---|
| F1 direct-traffic cardinality | `cc3bec3e` | a direct's roster is exactly the sender and one distinct other |
| F2 no seq high-water mark | `90a76b40` | one mark per schedule, checked and recorded by every accepting path |
| F3 `ReanchorAuthority` unread | `ab0b71ff` | variants carry the verified row; `reanchor` checks it matches the opening |
| F4 fingerprint mint ungated | `4fd32260` | a sealed `EnvelopeVerification` token only `transcript` can produce |
| F5 sender binding skippable | `4fd32260` | `fingerprint()` moved to `SenderBoundApplicationEntry` |
| F6 three gate evasions | `7b0eae69` | one hardened scanner; brace form, `include!`, and string literals all closed |
| F7 NSID authority direction | `f63585e5` | the TLD rules moved to the first segment, where a reversed domain keeps its TLD |
| F8 gate scope | `7b0eae69` | the `src/chat_v2`-only limitation stated in `gate_support.rs` and below |
| minors | `99de99f3`, `142050a2` | reaction cap, avatar MIME, double close, FFI doc, signing-domain vectors |
| restore-bypass sweep | `2a9200e4` | swept the whole tree; one finding in `journal.rs`, fixed |
| F9 crate-root re-exports | `6674e049` | the forbidden `crate::<Name>` set is derived from `lib.rs`'s globs |
| F1 addendum | `bd6be439` | `SenderNotAParticipant` carries the server's `NotParticipant` |
| expects and their predicates | `b8196784` | the duplicated close predicate collapsed; `is_open()` pinned |
| high-water durability | `adcabf3e` | the mark's store round-trip proved on the case that cannot be derived |
| review micro-round | `4e2fa917` | depth-two guard made enforced, nested-tail re-exports derived, vector verdict below |
| ratifications | `32166d6d` | §5 active-admin interpretation + unicode-normalization dep, both ratified by Josh |
| spot-check closures | (this seal) | the four `use`-shape escapes the micro-round spot-check found, all closed |

**Micro-round (post-re-verification), three closures.** (1) The derivation's
depth-one limit was *documented* as guarded by a count assertion that did not
exist — the docs-overstate-the-code shape recurring inside the F9 fix itself.
It is now genuinely guarded twice: `the_re_export_surface_is_the_reviewed_one`
pins the glob-module set (a new `lib.rs` glob is a deliberate re-pin), and
`no_glob_source_module_globs_a_third` refuses the depth-two shape inside the
globbed modules, with a positive control on the matcher. (2) The nested-tail
evasion (`pub use orchestrator::types::ConversationState;` hoists
`ConversationState`, which the old whole-tail plain-ident check skipped) is
closed: `parse_pub_use` hoists the final segment of nested named re-exports
and handles nested globs; the rename skip stays, by its recorded rationale.
(3) **The 11 unpinned signing domains cannot be lifted from the existing
fixture**: `mls_chat_contract_vectors.json` @ `425e149f` carries exactly ONE
`signedMutator` case (blobDelete) — verified by opening it, not assumed. The
13 control domains are pinned via `controlEntryFingerprints`; the mutation
domains (`CATBIRD-CHAT-MESSAGE` above all — the application-send domain)
require **server-side vector generation in mls-ds**. That is a chartered
cross-repo item for the landing pass, not a defect this lane can close.

**Spot-check round (post-micro-round), four escapes closed.** An independent
spot-check of `4e2fa917` confirmed both depth-two tests bite on injection, then
proved by compilation that four `use` shapes still escaped the derivation —
one LIVE in the tree: `engine.rs:14`'s named re-export of a v1 orchestrator
result type, hoisted to the crate root by the `engine` glob and caught by no
gate (the NAMED form of depth two). The other three were parser skips: the
single-level brace list (`pub use m::{A, B};`), restricted visibility
(`pub(crate) use`), and a PRIVATE `use` at the crate root (still visible to
descendant modules — chat_v2 is one). All four are closed by one change of
shape: `parse_use_decl` reads every visibility and every single-line form,
distinguishes "not a use" from "a use it cannot read", and **both derivation
entry points panic on the unreadable** — the old parser's silent `None` on the
unknown was the common root of all four. The glob sources' own top-level
`pub use` lines are now derived (so `crate::MessageProcessingResult` is
forbidden, pinned by `the_named_depth_two_re_export_is_derived`), the four
shapes are permanent controls in `the_shapes_the_spot_check_found_are_now_read`,
and the depth-two GLOB form stays refused rather than recursed into. Renames
stay skipped, by their recorded rationale.

**F9 is the one worth reading before touching a gate.** `use crate::MLSContext;`
inside `chat_v2` compiled, reached v1's SQLCipher group and crypto surface, and
passed all five gates — because `src/lib.rs` globs six modules to the crate root
and every needle was keyed to a *module path* the short spelling never names.
Listing the two spellings would have left the hole. The forbidden set is now
**derived** from the re-export surface, so a new glob in `lib.rs`, or a new `pub`
item in a module already globbed, is covered without anyone extending a list.
Do not replace that derivation with a list.

A note on the lint command: `cargo clippy --all-targets` exits **101**, and that
is the pre-existing `tests/sequencer_did_sync_tests.rs` breakage documented in
section 1 — not a regression. `cargo clippy --lib` is the signal that means
anything here.

---

## 1. Sealed commits

Oldest first, and the table is the count — a number written beside it is a
second source of truth that drifts, which it did. All additive; the only
pre-existing files touched are
`src/lib.rs` (three lines declaring the module) and `Cargo.toml` (two
promotions and one new dependency).

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
| `ptlzkqyx` | `4e9651a7` | The first Task 3 handoff document |
| `oukpxxkq` | `3d54a64c` | Reset-activator classification (6c) |
| `nzvoxxxn` | `0b02a553` | The two Terminal modes (6d) |
| `twsmwtww` | `a16e4fe5` | Handoff refresh for the built reducer |
| `kszmquql` | `6309353f` | Canonical signing transcript, byte-identical to mls-ds (S7a) |
| `xyxvwryy` | `6d88c594` | Strict signed-wrapper decode and Ed25519 verification (S7b) |
| `ykrlymzw` | `0b6da15f` | Vector provenance, ratified I-1 correction, two doc anchors |
| `rlqxsxqt` | `beb865c5` | The two outer entry fingerprint domains (S7c) |
| `wvyrrrox` | `8b71a345` | Wire JSON projection through the lexicon contract (S7d-pre) |
| `ysqxmrrk` | `a57914c4` | Application entry verification and sender binding (S7d) |
| `xrzuzrrs` | `97725bae` | Handoff refresh for S7; fixed a NUL byte in this file |
| `puwwnvty` | `acd8d075` | Encrypted media and reaction predicates (S8a) |
| `rlxukvvz` | `43693690` | Restricted AT URI and external link predicates (S8b) |
| `vrzwlopk` | `7cb107dc` | The bounded recovery ladder and its absence gate (S9a) |
| `unrqvtzr` | `0cfdfc40` | Handoff refresh for content predicates and the ladder |
| `uqkyovyq` | `b8fdd164` | The NFC check completing the reaction predicate (S8b-pre) |
| `szlxmzrz` | `967deea2` | The single recovery projection on the FFI surface (S9b) |
| `zlmxmxww` | `b0a8c2f5` | Poisoned-state containment (S9c) |
| `xwnzpuqk` | `eaf655ff` | Participation status and the direct-traffic gate (S9d) |
| `pxukowsz` | `f3f227a9` | Handoff refresh for completed content, recovery, participation |
| `oyuopxzp` | `83ff47d8` | The open §5 veto recorded (stand-down doc seal) |
| `lwnmxyqk` | `b43f460d` | Per-DID store scope and the storage error taxonomy (S10a) |
| `vyrukxnt` | `6c0f8973` | The store trait, the atomic page commit, the no-default gate (S10b) |
| `pllzwzuo` | `b55034d3` | Journal persistence with byte-identical rehydration (S10c) |
| `oxowttxz` | `cc11d4ec` | Exact-device schedule persistence and coherent restore (S10d) |
| `qkskwkzl` | `a5ed57f1` | The physical-separation gate and a pinned scope sweep (S10e) |
| `yuwqpuuz` | `5124fa48` | Handoff refresh for the storage subsystem |
| `qylztuwk` | `9943c4af` | Split the reference store's tests into a sibling file |
| `ovkuwqzx` | `4a313a50` | Gate the reference store out of production builds (S10e addendum) |
| `olrmypzv` | `b947ec01` | Correct the readiness probe to protocol completeness (S10f) |
| `lwouupwq` | `8fa1427d` | Handoff refresh for S10f and the reference-store gating |
| `ptkyzxrn` | `0075e5c5` | Refuse structurally corrupt restored schedules (review follow-up) |
| `vtzppxwx` | `c47683e7` | Handoff refresh for the restore hardening |
| `yynwtlqo` | `cc3bec3e` | A direct's roster is exactly the sender and one other (F1) |
| `rqspwsrz` | `90a76b40` | The schedule's seq high-water mark (F2) |
| `xwtumvzq` | `4fd32260` | Close the fingerprint mint and bind the sender to it (F4, F5) |
| `lonyvztp` | `ab0b71ff` | A reanchor authority carries the row it stands on (F3) |
| `rumknqur` | `7b0eae69` | One hardened scanner behind every gate (F6, F8) |
| `zpunqyms` | `f63585e5` | An NSID authority is a reversed domain, so its TLD is first (F7) |
| `muwnpzxr` | `99de99f3` | Four minors: reaction cap, avatar MIME, double close, FFI doc |
| `urvnorpl` | `142050a2` | Re-lift the dropped signing-domain vectors |
| `kquvuzsm` | `2a9200e4` | Sweep the restore-bypass pattern across the whole tree |

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

**RATIFIED (Josh, 2026-08-15): a previously removed device MAY activate a
reset.** The reading built into `reducer/reset.rs` is **yes**. §5
says `activateReset` is "uniformly active-admin-only: an active registered
device of an active admin DID may activate **without being an old-generation
leaf**", so interval history is not an admission criterion — "not an old leaf"
means not a leaf *at the reset*, not *never* a leaf. A device removed at seq 3
may therefore activate at seq 20, constrained only by the schedule rule that its
new opening clear the old close strictly.

The layering behind that reading, confirmed with the lead: **admission** (is this
device currently active, registered, admin?) is the authority layer's question
and is answered server-side; the reducer owns only the **schedule** constraint.
That is why the refusals there are the neutral interval errors rather than a
reset-specific one — a bespoke error would encode admission policy into the
schedule layer, where it does not belong.

Josh held a veto window on this and declined to exercise it on 2026-08-15,
ratifying the staged active-admin interpretation. The window is CLOSED; no code
change follows. The anchors remain exact for future readers: the §5 sentence is
quoted verbatim in `reducer/reset.rs`'s module docs and again in the comment on
`a_previously_removed_activator_opens_after_a_strict_gap`. Do not re-derive the
reasoning — read those two places.

**The NSID collection authority is a REVERSED domain** (ruled by the lead in the
fix round). `app.bsky.feed.post` belongs to `bsky.app`, so its TLD is `app` —
the *first* segment — and the TLD rules (lowercase-letter start, reserved-TLD
list) apply there. The four cases that pin it are in `content/uri_tests.rs`:
`org.4chan.post` and `app.bsky.test.record` are valid, `test.foo.record` and
`3ao.thing.foo` are not. A handle authority still reads forwards, and a test
pins that too, so the two directions cannot be swapped wholesale. One grammar
serves both: `validate_domain_labels` plus `validate_tld_label`, with each
caller naming where its TLD is.

**The restricted AT URI does not adopt the upstream rkey charset**, and does
adopt the NSID 63-byte per-segment bound. §8 enumerates its rkey restrictions
and a character set is not among them; a client refusing a key the server
accepts would silently drop legitimate embeds. The segment bound comes from the
same grammar the 317-byte NSID total already comes from. Both recorded in
`at_uri.rs` and pinned by tests, so neither reads as an omission.

**A direct's traffic gate takes the sender's DID.** §9's "both exact
participants" cannot be checked without knowing who one of the two is meant to
be, so `require_traffic_allowed` refuses a roster that is not exactly the sender
and one distinct other. Three local refusals, none of which carries an endpoint
code — a server never sees the roster.

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
  gate_support.rs  the shared source scanner behind all five gates (cfg(test))
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
    witness.rs  the sealed token that closes the fingerprint mint
    vectors/    vendored server golden vectors + lexicon + PROVENANCE.md
  content/      application content predicates (S8); no server to mirror
    media.rs    MIME sets, checked ciphertext arithmetic, byte bounds
    reaction.rs grapheme cluster + control-free; NFC refuses by name
    at_uri.rs   the restricted canonical AT URI
    link.rs     external links
  participation.rs  pending vs active-zero-leaf; direct/group gate asymmetry
  recovery/     bounded ladder (S9a) + the forbidden-mechanism absence gate
    ladder.rs   four rungs, skip/descent/exhaustion refused by name
    poison.rs   deterministic-only poison, containment, different-DID fulfiller
  reducer/
    mod.rs      sequencing core (6a) + the schedule seq high-water mark + rehydrate, the restore feed
    restore_tests.rs  what rehydrate accepts back; why restore checks shape
    reanchor.rs closure, reanchor, touching boundaries (6b)
    reset.rs    the three reset-activator roles (6c)
    terminal.rs the two Terminal modes (6d)
  storage/      physically separate durable storage (S10); NOT gated off wasm
    mod.rs      StoreScope (one store per DID) + the physical-separation gate
    error.rs    the named taxonomy; every failure says which record and why
    page.rs     PageCommit — the atomic unit; entries + ratchet + cursor as one
    store.rs    the ChatV2Store trait, every method required + the no-default gate
    memory.rs   a NON-DURABLE reference impl, cfg(test) ONLY — absent from release
    memory_tests.rs  its behaviour tests; what any platform store must also meet
  ffi.rs        skeletal UniFFI surface (cfg'd out on wasm32)
```

### Isolation from v1

`chat_v2::isolation` is a test that walks the tree and fails on any v1
orchestrator import, with a positive control proving the matcher can fail. The
needles are assembled at runtime so the gate's own source is not a violation of
itself. **Keep it passing.** v1 and v2 never interoperate.

Storage isolation is **built** (S10a-S10e) and is physical. See section 6.5.

There are now **five** gates, not two, and they catch different things. That is
not redundancy — it was verified. Injecting a real
`use crate::hybrid_storage::HybridStorageProvider;` into a `chat_v2` file leaves
*both* original gates passing, because the isolation gate forbids
`crate::orchestrator` and that store does not live there. Keep all five green:

| Gate | Where | Catches |
|---|---|---|
| v1 import isolation | `chat_v2/mod.rs` | `crate::orchestrator` imports |
| forbidden recovery mechanism | `recovery/mod.rs` | external commits, `force_rejoin` |
| no default trait method | `storage/store.rs` | a store method that could silently discard state |
| physical separation | `storage/mod.rs` | reaching a v1 or OpenMLS store by any path |
| reference store absent from release | `storage/mod.rs` | `mod memory;` losing its `#[cfg(test)]` |

The isolation gate carries a second needle set, **derived rather than written**:
every `crate::<Name>` that `lib.rs`'s `pub use <mod>::*;` globs hoist to the
crate root — 72 names today, across `api`, `engine`, `error`, `keychain`,
`platform_lifecycle`, and `types`. Module-path needles cannot cover those, and
that is structural rather than an oversight, which is why the coverage is
derived. A compile-fail test was evaluated and rejected: the offending import
*compiles*, so there is nothing for `trybuild` to assert, and making it a compile
error would mean narrowing the `lib.rs` globs — the crate's public API, consumed
by the UniFFI scaffolding, and not this lane's to narrow.

They share one scanner, `chat_v2/gate_support.rs`, and the sharing is the point:
each had its own copy of "walk, strip comments, match a substring", and the
copies shared three evasions that a review reproduced by mutation — a brace-form
`use` tree, code reached through `include!` of a non-`.rs` file, and a string
literal containing `//` that truncated the line. All three are closed and each
is a permanent positive control there. **Do not reintroduce a local matcher**;
extend the shared one, so the next evasion is fixed once rather than five times.

**What these gates prove, exactly.** That a token is absent *from
`src/chat_v2`*. A thin wrapper in the v1 tree — a function in
`src/orchestrator` that calls the forbidden thing, re-exported under an innocent
name — is invisible here, and importing that name would satisfy every gate.
Widening the walk is not the fix: scanning v1 would flag v1's legitimate use of
its own mechanisms on every run. The real guard is that adding such a wrapper
means editing the v1 tree deliberately, which is a review event rather than the
editor accident these gates exist to catch. Stated so the gates are not read as
proving more than they do.

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

### The schedule high-water mark (fix round, F2)

`ApplicationReducer` carries one `high_water: Option<Seq>` — the greatest
sequence it has applied — and **every** accepting path requires a row strictly
above it before touching state, then records the row once. Before this, each
path compared against the interval it landed in, and an interval records only
where it opened and where it closed: a control row consumed at seq 100 left no
mark, so a terminal at seq 2 was accepted and deposited irreversible proof
beneath consumed history.

Three things about it that a refactor could quietly undo:

- **A touching boundary is one row, checked once and recorded once.** The shared
  seq between its close and its opening is a single consumption. A rule written
  as "strictly greater than everything including my own opening" would break a
  ratified schedule.
- **`rehydrate` takes the mark as a parameter and cannot derive it.** Rows
  consumed inside an open interval leave no trace in the interval list, so a
  derived mark restores below the truth and reopens the replay window. Restore
  checks a floor only: the greatest sequence the restored schedule itself
  records — a mark *lower* than the truth is indistinguishable from a schedule
  that legitimately consumed less, so nothing finer is catchable. A platform
  store that decomposes a schedule **must persist this mark**; `put_schedule`
  says so, a store test proves the round-trip on a schedule whose mark the
  interval list cannot express, and the no-default gate cannot help here because
  nothing can force a field to be serialized.
- **The refusal is the existing `NotAdvancing`**, whose `expected_after` now
  carries the mark. The old comparison was a weaker form of the same rule, not a
  different rule, so no previously pinned refusal changed value.

Two design points that must survive refactoring:

- **`ReanchorAuthority` carries the row it stands on.** It is still a closed
  two-variant enum with no constructor from a hint — and each variant now holds
  a private-field `VerifiedOpeningRow` carrying the verified row's
  `OuterEntryFingerprint`, which only the envelope layer can mint. `reanchor`
  requires that fingerprint to equal the opening's, refusing
  `ReanchorAuthorityMismatch` otherwise. The nullary variants were a claim
  anyone could write, and the argument was bound to `_authority` and never read.
  Do not add a `From<CloseHint>`, an "unchecked" variant, or a public payload
  constructor.
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

`OuterEntryFingerprint` is produced only by the envelope-verification layer, and
that is now **enforced** rather than documented: its constructor takes an
`EnvelopeVerification` token whose own constructor is `pub(super)` inside
`transcript`, so no other module can mint one. Tests use `#[cfg(test)]
for_tests`, which does not exist in a release build.

On the application path the ordering is enforced by type too. `verify()` yields
a `VerifiedApplicationEntry` that cannot produce a fingerprint at all;
`bind_sender()` — the sender-identity comparison — is the only route to a
`SenderBoundApplicationEntry`, which alone exposes `fingerprint()`. Recording
provenance for a row whose sender was never checked is unrepresentable rather
than merely discouraged. It was previously possible, and the check was called by
nothing outside its own tests.

**What that does not cover, stated so nobody reads it as more:**

- `EntryRow` is public with public fields, deliberately — it is the input to a
  pure function and the golden vectors are assembled that way. A fingerprint
  over an invented row is computable and meaningless.
- The **control** path has no verified-entry type, because control verification
  is not built in this tree. There the token is the only structural guarantee
  and "verify before fingerprint" remains a convention.
- `SequentialControl` is the one reducer row struct carrying no fingerprint, so
  its "construction implies verification" claim is a convention its doc now
  admits to. Its four siblings carry fingerprints and so cannot be assembled
  from nothing — though construction still does not check that their other
  fields describe the same row as the fingerprint.

### Conventions worth keeping

- **Never serialize a generated DTO** for a transcript or fingerprint. DTOs emit
  fields alphabetically and carry a flattened `extra_data` catch-all.
- **Vendored vectors carry provenance.** Source repo, path, commit hash, and
  SHA-256 per source file, in `vectors/PROVENANCE.md`. A vendored vector failing
  against the encoder is **a finding to report, never a vector to adjust**.
- **`VerifiedApplicationEntry` is deliberately not `PartialEq`.** Comparing two
  verified authorities by value is not a meaningful operation.

## 6. Content predicates, recovery, and participation — complete

Everything §8 and §9 describe is built. Storage followed in S10a-S10e (section
6.5), so every **domain** layer this tree owns is now complete.

`chat_v2_status()` still reports `is_operational = false`, and correctly: what
remains is not a domain layer but two seams that do not exist here at all — no
transport and no MLS crypto. An earlier revision of this document said storage
was "the only thing left before this protocol is usable end to end". That was
wrong, and believing it would have flipped the readiness probe on a build with
no way to reach a server.

### Built (S8a/S8b/S8b-pre, `content/`)

The character of this code differs from `transcript/`, and the difference
matters: **application content is encrypted, so the server never sees it.**
Confirmed by inspection, with a positive control run on the search first. Two
consequences:

- **There are no golden vectors to lift.** The "a failing vector is a finding"
  rule has no analogue. Vectors are constructed from spec text, and the tests
  read the **embedded contract's own** `minimum`/`maximum`/`enum` values and
  assert agreement rather than restating them.
- **Every client is the whole enforcement, independently.** Nothing upstream
  catches a disagreement, which is why both Unicode versions are asserted.

Traps recorded because each cost time or would have:

- **Extended vs legacy grapheme clusters differ on SpacingMark and Prepend, NOT
  on ZWJ.** A ZWJ sequence is one cluster under both, so a test using one proves
  nothing. An earlier version did exactly that and failed.
- **Segmentation and normalization are different crates.** Both report Unicode
  17.0.0 and a test asserts they agree with each other and with the pin; a
  mismatch would be a cross-version seam. The `unicode-normalization` 0.1.25
  addition sat under a new-dependency veto window; Josh declined the veto on
  2026-08-15 — strict Unicode 17 NFC **validation** stays, and normalization is
  never applied (the "checked, never applied" rule below is ratified behavior,
  not a provisional choice).
- **Byte bounds are UTF-8 bytes, not characters** — character-counting accepts
  roughly twice the permitted data.
- **The AT URI and external-link grammars disagree about percent signs on
  purpose**, and a test pins the disagreement so nobody harmonizes it.
- **NFC is checked, never applied.** Reactions reduce by `(verified DID, NFC
  grapheme)`, so a decomposed value and its composed twin land in different
  buckets — one person's reaction rendering as two.

### Built (S9a/S9c/S9d, `recovery/` and `participation.rs`)

The bounded four-rung ladder, refusing skip, descent, and past-top by name;
**the absence gate**; poisoned-state containment; and the participation gate.

- **The absence gate is the enforcement shape for every "we will never" in this
  tree.** v1 documents the prohibition *and* ships `force_rejoin_unlocked`, with
  700-800 production epochs as the result. The gate walks the tree, has a
  positive control, assembles needles at runtime, and requires every entry to
  carry a reason so a deleter must read why first.
- **A poisoned device requests, never activates.** Its next rung is the
  target-device recovery request. Fulfiller selection is by **different DID**,
  and a test pins that a *healthy sibling of the victim's own DID is refused* —
  poison plausibly affects every device of one principal.
- **Containment freezes sending and ratchet advancement together**, as one value
  so a caller cannot apply half. Half is worse than none.
- **Direct and group are gated differently on purpose**, with an identical
  roster refused as a direct and permitted as a group. Pending →
  `ConversationNotAccepted`; active-zero-leaf → `RecipientNotReady`. Reporting
  the first for a recovery gap tells a user their peer ignored them.
- **Acceptance changes only status.** A freshly accepted participant is
  *addable but not yet sendable*, and the refusal is the leaf one.

## 6.5 Storage — complete (S10a–S10e)

Physically separate, per DID, with every method required.

### The three shapes that carry the invariants

- **`StoreScope` is opened *for* a DID**, not a shared store filtered by a DID
  column. It offers no way to widen itself — no two-DID constructor, no setter,
  no "any principal" variant — so a second principal requires a second store.
  A foreign access is `CrossDidAccess`, deliberately **not** `NotFound`: a miss
  is something callers retry, repair, or create through, and a containment
  breach must not read as one.
- **`PageCommit` carries entries, ratchet checkpoint, and the new cursor as one
  value, and the trait has no cursor setter.** §9 states the atomicity rule
  twice. A seam with separate `store_entry` / `store_ratchet` / `set_cursor`
  satisfies it only if every caller wraps them and every platform's wrapping is
  genuinely transactional, neither of which is checkable — and the failure is
  silent *and permanent*, because a cursor past unwritten entries skips them
  forever (`afterSeq` is exclusive; the server never returns them again). Same
  shape as `CloseProof`, `TouchingBoundary`, and `Containment`.
- **Every trait method is required**, enforced mechanically. v1's backend
  defaults 20 of 34 methods to no-ops and mitigates it with a self-reported
  capabilities *warning*; a platform that skips one there loses the state and is
  told nothing.

### Things that will be got wrong if not read

- **Commits are compare-and-set, with two distinct refusals.**
  `CursorMismatch` means another commit advanced this cursor; a `NotFound`
  cursor means the page continued from a position this store never held. The
  first is a lost race, the second is a misrouted store. Different mistakes,
  different fixes, so different errors.
- **`ApplicationReducer::rehydrate` prevents a panic, not a wrong answer.** The
  reducer maintains "an interval is open exactly when an expected context is
  installed", and `apply_sequential_control` reaches for that context with
  `.expect()`, treating absence as unreachable. Restore is the only way into the
  type that bypasses the paths maintaining it, so it refuses an incoherent pair
  by name. Do not relax that check to accept a row that "looks fine".
- **Restore is a second feed, and that is the whole reason it checks shape.**
  `rehydrate` also refuses an unordered, overlapping, or non-finally-open
  interval list, because three paths read `intervals.last()` as "the current
  interval": `has_open_interval`, `reanchor`'s strict gap, and the `last_mut()`
  that `close_interval` writes into. The specified append-log feed cannot
  produce such a list, so those paths were written to trust the shape; durable
  storage hands back whatever was written. Demonstrated rather than argued: with
  the checks removed, an unordered restore let `reanchor` accept an opening at
  seq 15 *inside* the real latest interval `10..=20` and return `Ok`. Equality at
  a touching boundary is permitted and pinned — tightening it to a strict
  comparison would reject legal schedules.
- **Restore reinstates; it does not re-adjudicate.** Replaying admission
  decisions against rows the client no longer holds would refuse a schedule that
  was legitimately built. What restore *does* enforce is exact-recipient
  ownership and the coherence pair above.
- **Reads return absence, never a substituted default.** `cursor` yields
  `Option`, not `AfterSeq::START`. "Never scanned" and "scanned to the
  beginning" want different handling.
- **The schedule key includes the device.** Visibility is per exact
  `(DID, deviceId)`; a conversation-only key hands a sibling device history it
  never had.
- **`MemoryStore` is `cfg(test)` only, and that is structural, not a label.** A
  store that forgets everything on process exit is the failure this layer exists
  to prevent, and a type merely *documented* as unsuitable is one import away
  from being used. In a release build the symbol does not exist — verified by
  importing it from `ffi.rs` and getting `error[E0432]`. A gate keeps the
  attribute in place. A platform wanting one for its own tests writes it against
  `ChatV2Store`, where every method is required.
- **The store method list is pinned by a test.** Foreign-principal refusal is
  checked by *calling* each method, and a call-based sweep cannot notice a
  method nobody added to it. Adding a method fails that test with an instruction
  to extend the sweep — extend it, do not bump the list.

Conventions kept from the rest of the tree: page well-formedness stays with
`append_log` (nothing here re-derives `nextAfterSeq` or the entry bound), and
where a predicate already exists it is reused rather than restated —
`AfterSeq::admits` for the exclusive bound, `JournalEntry::should_submit` for
which states are terminal.

### Still outstanding

**Storage was the last domain layer, but it is not the last thing.** Two seams
do not exist in this tree at all, and both are required before the protocol is
usable end to end:

- **No transport.** A grep for `reqwest`, `xrpc`, or `HttpClient` over
  `src/chat_v2` returns nothing, while the identical needles fire on v1
  (`src/orchestrator/api_client.rs`). Nothing here can talk to a server.
- **No MLS crypto seam.** Same result for `openmls` and `MlsGroup`, with the
  positive control firing on `src/mls_context.rs`. The ratchet checkpoint that
  travels in a `PageCommit` is opaque bytes precisely because the layer that
  produces them does not exist yet.

Both absences were checked with a firing positive control rather than asserted.

**The probe now names them, and this was ruled on rather than assumed.**
`outstanding_capabilities` lists `transport-binding` and `mls-crypto-seam`, each
with a sentence; `storage` moved to implemented; `is_operational` stays `false`.

The correction worth understanding is *why* the old list was wrong. It read
`["storage"]`, which was one lane's remaining work rather than the protocol's —
and since the probe pins `is_operational == outstanding.is_empty()`, finishing
that lane appeared to empty the list and would have flipped the build to
advertising a usable protocol. The list tracks **protocol completeness**, which
is what `is_operational` claims. Entries beyond the current lane's scope belong
in it for exactly that reason.


## 7. FFI notes for whoever extends `ffi.rs`

- The surface is deliberately small: only shapes settled by sealed slices.
  Reducer state and interval provenance are **absent on purpose** until their
  shapes stop moving.
- `chat_v2_status()` reports `is_operational = false`. A test pins
  `is_operational == outstanding.is_empty()` and that no capability appears in
  both lists. Flip it only when the outstanding list is genuinely empty.

  **Resolved in S10f.** The list previously tracked one lane's scope, which is
  not what `is_operational` claims; it now tracks protocol completeness and names
  `transport-binding` and `mls-crypto-seam`. Capabilities carry a description
  because an unexplained outstanding entry is what gets deleted by someone who
  cannot tell why it is there. Do not treat a stale-looking entry as a tidy-up:
  this is the one field telling other lanes whether the protocol can be used.
- **The storage layer is deliberately absent from the FFI surface.** Its shape is
  settled now, so exporting it is defensible — but it has never been bound, and
  adding it changes the UniFFI checksum. That is the coordinated landing pass's
  call, not a drive-by.
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
