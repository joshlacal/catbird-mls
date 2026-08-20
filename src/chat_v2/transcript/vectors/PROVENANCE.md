# Vendored golden vector provenance

`mls_ds_transcript_vectors.json` is **not authored here**. It is a verbatim
subset of a fixture owned by the `mls-ds` server, vendored so that this crate's
tests cannot depend on a path that escapes the repository. The same is true of
`mls_ds_fingerprint_vectors.json` and `mls_ds_signing_domain_vectors.json`.

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

`mls_ds_signing_domain_vectors.json` came later, from a different source file at
a different revision:

| | |
|---|---|
| Source repo | `mls-ds` |
| Source path | `server/tests/fixtures/mls_chat_signing_domain_vectors.json` |
| Source revision | `ec5028ce4f424af3819aa3e993c86fca1a85bbde` |
| Vendored on | 2026-08-20 |

That revision is **local to this machine and unpushed** at vendoring time. A
drift check that cannot resolve it is looking at a checkout the seal has not
reached yet — resolve the hash below against the file's bytes instead.

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

For the 10-case clean-cutover signing-domain vectors, hashed at `ec5028ce`:

| File | SHA-256 |
|---|---|
| `server/tests/fixtures/mls_chat_signing_domain_vectors.json` | `5533e6457fe4dc1b45fe7ff014940a6aea91657d23bf3d5b1493ac65aeefe984` |
| `server/tests/chat_protocol_signing_domain_vectors.rs` | `cf32d5107632597d59d7443dd170f5bcc85e6cb8b000bc11e1d3a9cdd91ccac7` |
| `server/tests/common/signing_domain_bodies.rs` | `2b30ca38f38d068e900cc484dec60517ec442f373fffb0c9158f187436fa9259` |
| `server/src/chat_protocol/transcript.rs` | `1ede8ace0d97fb6c55519bd73aa72f37ad63a99a51b1fd72988886752b1ee5de` |

The `transcript.rs` hash reflects the clean-cutover transcript implementation
at `ec5028ce` after removing `deviceAuthenticationRebind` and legacy clean-chat
DPoP fields.

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
| Source revision | `aa0d0d489443d8a5622a86732e771d3116748b0e` (PetrelCatbird) / `ec5028ce4f424af3819aa3e993c86fca1a85bbde` (mls-ds) |
| SHA-256 | `dea9b6e72128d71d70f8c05036bf90889c2f91987c7a11fb82904a3e63df6caf` |
| Size / defs | 123,233 bytes / 198 definitions |
| Prior SHA-256 | `7a0411afdfde050c255c9b415f700c7e0d93041679d2cde23497797428bdab03` @ `b1814a6c`, 131,653 bytes / 200 definitions |

**The changes between those two digests** reflect the standard service-auth
clean cutover: removal of `deviceAuthenticationRebind` / `deviceAuthenticationRebindBody`
and associated public clean-chat DPoP fields, which reduced the definition count
from 200 to 198.

**Verified identical across every live copy at sync time** — this vendored copy,
`PetrelCatbird/lexicons/` (the canonical codegen source), and the mls-ds mirror
the server embeds all hash to `dea9b6e7…`.

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

Per case, fourteen keys are now kept. Twelve came with the original S7c
vendoring; `signingDomain` and `signingTranscriptHex` were **re-lifted from the
same source file at the same recorded revision** once it became clear what their
absence cost — see below. Still dropped as belonging to later slices:
`unsignedSigningProjectionCanonicalDagCborHex`, `signedRequestRef`, and
`historicalPublicKeyRef`, together with the top-level `historicalPublicKeys` /
`authoritativeReferenceBindings`. **Dropping is not editing** — no kept value is
altered, and the omitted keys are still in the source file at the recorded
revision for whichever slice needs them.

#### Why the two signing keys came back

The domain table in `transcript/mod.rs` is transcribed by hand from the server's
`signed_mutation_kinds!` macro, and a single wrong byte produces signatures that
verify locally and nowhere else. With `signingDomain` dropped, exactly **one** of
the twenty-four domains — `CATBIRD-CHAT-BLOB-DELETE`, from the transcript
vectors' `signedMutator` — was pinned against server bytes. The other
twenty-three rested on the transcription being right.

Re-lifting these two keys pins **fourteen of the twenty-four**: the thirteen
control entries plus blob-delete. `fingerprint_tests.rs` asserts, per case, that
this crate holds exactly one domain spelled identically to the server's
(terminal NUL included) and that the case's transcript begins with those bytes.

The remaining **ten had no server vector in this fixture at all** and rested
on the transcribed table alone: `deviceEnrollmentBody`,
`keyPackageReplenishmentBody`, `deviceRevocationBody`,
`blobUploadPreparationBody`, `applicationSendBody`, `typingBody`,
`leafRecoveryRequestBody`, `leafRecoveryCancellationBody`,
`welcomeAcknowledgementBody`, and `welcomeRejectionBody`. **They are now pinned**
by `mls_ds_signing_domain_vectors.json`, described below. `fingerprint_tests.rs`
still names the ten, but as "pinned by the other fixture, not this one" —
scope, not a gap.

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

### `mls_ds_signing_domain_vectors.json` (the ten remaining domains)

Vendored **verbatim** — the whole source file, byte for byte, not a subset. Its
SHA-256 above is therefore also the vendored file's.

Ten cases, one per signing domain with no control entry, each carrying the
same key names the `signedMutator` vector uses: the wire `body`, its
`uuidByteFields`, `canonicalUnsignedDagCborHex`, `transcriptHex`,
`canonicalRequestDigestHex`, `publicKeyHex`, `signatureHex`, and a declared
one-field `mutation` with `mutatedTranscriptHex` / `mutatedRequestDigestHex`. No
new field kind was invented; `bodyName` and `signingDomain` are the only
additions, and both already exist on the control cases.

**How the server produced them.** Not by re-implementing the construction — that
would prove nothing. Each body is handed to the server's own
`decode_canonical_signed_mutation`, the entry point its live handlers call,
which selects the domain from `SignedMutationKind`, projects the body through
the closed lexicon contract, and builds the transcript. The harness signs *those*
bytes with a fixed test-only Ed25519 seed and re-enters through
`decode_and_verify_signed_mutation`, so every case is one the server has
actually accepted, key-id binding included. A body the live contract rejects
fails the run rather than being quietly encoded. See
`mls-ds/server/tests/chat_protocol_signing_domain_vectors.rs`; regenerate with
`CATBIRD_REGENERATE_SIGNING_DOMAIN_VECTORS=1`.

**Why it is a separate file on the server side.** The ten cases deliberately
do not extend `mls_chat_contract_vectors.json`. That file's bytes are hashed
into frozen generated-artifact provenance
(`docs/generated-artifacts/chat-application-v1/manifest.json`, via its
`contractSources` list). Editing it desyncs that record silently, and the guard
that would catch the desync cannot even run from a checkout where the
generated-artifact tree is absent — which is the state of this workspace.

**The signing key is deliberately not the RFC 8032 one.** The `signedMutator`
vector signs under the RFC 8032 test key; these ten use a different fixed
seed, so a case cross-wired between the two fixtures fails its key-id binding
instead of silently verifying.

`domain_vector_tests.rs` consumes them: it rebuilds each transcript from the
wire body through this crate's own projection, checks all three hex products,
verifies the server's signature over the locally rebuilt bytes, replays the
declared mutation to prove the signature covers that field, and cross-checks
each case's `uuidByteFields` against the contract-derived UUID set — the same
independent-sources check `contract_tests.rs` runs for blob-delete.

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
