# Vendored golden vector provenance

`mls_ds_transcript_vectors.json` is **not authored here**. It is a verbatim
subset of a fixture owned by the `mls-ds` server, vendored so that this crate's
tests cannot depend on a path that escapes the repository.

**mls-ds remains the authority for these bytes.** The hashes below are what let
a future session *detect* server-side drift rather than argue about whether it
happened.

## Source

| | |
|---|---|
| Source repo | `mls-ds` (workspace sibling `Catbird+Petrel/mls-ds`) |
| Source path | `server/tests/fixtures/mls_chat_contract_vectors.json` |
| Source revision | `425e149fc8682623c0a94e58ce51793c73df7ecc` |
| Vendored on | 2026-08-15 |

The revision is recorded as a **commit hash, not a ref name**. `main` moves; the
hash is what a drift check can actually compare against.

## Source file hashes at vendoring time

SHA-256 of each source file, read from the tracked object at that revision
(`/usr/bin/git show <rev>:<path> | shasum -a 256`):

| File | SHA-256 |
|---|---|
| `server/tests/fixtures/mls_chat_contract_vectors.json` | `96044be0c06e3dd43cbe77b7ac29c1ecfcee1922782b1c5e74258768b1aa3c6d` |
| `server/src/chat_protocol/transcript.rs` | `ddda5d11005143f74b61286f36a826f178a71b3c51b69f5c7d8f4519262849ad` |

`transcript.rs` is hashed too even though nothing is vendored from it, because
it is the implementation these vectors describe. If the encoder changes, the
vectors may still hash-match while no longer meaning what they did.

Not yet vendored, recorded for the slice that needs it (S7c, control
fingerprints):

| File | SHA-256 |
|---|---|
| `server/tests/fixtures/mls_chat_control_fingerprint_source.json` | `f33406a5d99dba3b604da108c4df2e53d70531b9fa0be14b21e2db94ba07b311` |

## The embedded lexicon contract

`blue.catbird.chat.defs.json` is the contract the projection walks, and it must
be **the same bytes the server embeds** — the server reaches it through
`include_str!("../../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json")`.

| | |
|---|---|
| Source path | `lexicon/blue/catbird/chat/blue.catbird.chat.defs.json` |
| Source revision | `425e149fc8682623c0a94e58ce51793c73df7ecc` |
| SHA-256 | `9791a2828a7d4d286b6f2f5362ac2f31691598cd7f3761e8ceef3abb09d3fcfc` |
| Size / defs | 131,642 bytes / 200 definitions |

**Verified identical across every live copy in the workspace** at vendoring
time — the server's embedded copy, `PetrelCatbird/lexicons/` (the canonical
codegen source), `mls-ds-lane-e-ws/`, `nest-chat-auth-ws/`, and
`nest-merge-ws/` all hash to the same value. There is no divergence between the
codegen source of truth and what the server actually embeds, so projecting
through this copy is projecting through the server's contract.

To re-check:

```sh
cd Catbird+Petrel/mls-ds
/usr/bin/git show <rev>:lexicon/blue/catbird/chat/blue.catbird.chat.defs.json | shasum -a 256
shasum -a 256 ../PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json
```

**The contract does not encode the UUID-bytes rule.** `operationId` and
`deviceId` are declared as plain strings with no `format`. What makes them
sixteen raw bytes is a hardcoded set of four reference names in the projection
code, mirrored from the server. See `contract.rs`'s module documentation; a test
pins that these definitions really are plain strings, so nobody tries to derive
the rule from the schema.

## What was lifted

Both vendored files come from the **same source file at the same revision**, so
the hash above covers both.

### `mls_ds_fingerprint_vectors.json` (S7c)

- `applicationEntryFingerprint` — the six-field projection, its canonical
  DAG-CBOR hex, and the resulting fingerprint
- `controlEntryFingerprints` — the domain, the eight `projectionFields`, the
  `ordinaryServerFields` / `nonemptyServerFields` rules, and **all thirteen
  cases**, each with its `serverFields`, `uuidBytePaths`, `base64BytePaths`,
  canonical DAG-CBOR hex, and fingerprint

Per case, twelve keys were kept and the rest dropped as belonging to later
slices: `unsignedSigningProjectionCanonicalDagCborHex`, `signingTranscriptHex`,
`signedRequestRef`, `signingDomain`, and `historicalPublicKeyRef` are the
signing-side vectors, and `historicalPublicKeys` /
`authoritativeReferenceBindings` go with them. **Dropping is not editing** — no
kept value is altered, and the omitted keys are still in the source file at the
recorded revision for whichever slice needs them.

The `uuidBytePaths` / `base64BytePaths` lists are what make these usable without
reimplementing the lexicon contract: they declare, by dotted path and at every
depth, which fields are raw 16-byte UUIDs and which are base64 byte strings.

### `mls_ds_transcript_vectors.json` (S7a/S7b)

Four sections, copied without modification:

- `canonicalOrdering` — string and byte array ordering
- `dagCbor` — a two-key map with its canonical hex and SHA-256
- `ed25519` — public key, message, signature, and a one-byte mutated signature
- `signedMutator` — a full `blobDeletionBody`, its `uuidByteFields` list, the
  canonical DAG-CBOR hex, the domain-prefixed transcript hex, request digest,
  public key, signature, and a declared field mutation with its expected bytes

Keys are sorted and the JSON is re-indented; **no value is altered**. That makes
the vendored file diffable against a freshly extracted subset.

## Re-lifting

```sh
cd Catbird+Petrel/mls-ds
/usr/bin/git show <rev>:server/tests/fixtures/mls_chat_contract_vectors.json > /tmp/src.json
/usr/bin/git show <rev>:server/tests/fixtures/mls_chat_contract_vectors.json | shasum -a 256
```

Note that these fixtures are **tracked in git but absent from the mls-ds working
tree** at its current detached revision — see the detached-HEAD trap in
`HANDOFF.md`. Read them through `git show`, not the filesystem.

## The standing rule

If a vendored vector ever fails against this crate's encoder, **that is a
finding to report, not a vector to adjust.** The server is the authority. A
vector edited to make a test pass destroys the only thing these files are for.
