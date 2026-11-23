# Invariants

The source code cites numbered invariants, `I1` to `I16`, from Catbird's chat protocol specification. That specification is not published yet. This table summarizes how the code uses each one, so readers can follow the citations; it is not the specification itself.

| Invariant | As used in the code |
|---|---|
| `I2` | Entries are applied in sequence order through a single cursor per conversation |
| `I3` | The delivery service accepts a change before any client merges it locally |
| `I4` | Every MLS leaf's signature key must match a device the account published on its PDS |
| `I5` | The members an archived message is addressed to are the authenticated roster |
| `I6` | No network call inside a database write transaction |
| `I7` | After another process (the push extension) writes, the app reconciles through SQLite's `data_version` |
| `I8` | The database is SQLCipher with a 32-byte raw key and an HKDF-derived salt |
| `I9` | `prepare_for_background` checkpoints and releases the database before suspension |
| `I10` | The push extension never refreshes OAuth tokens |
| `I11` | The push extension closes the database and posts a Darwin notification after it commits |
| `I12` | A push wake inlines ciphertext of at most 2,200 bytes |
| `I13` | Each entry carries a sequencer receipt that binds a blinded archive commitment |
| `I14` | The delivery service is a directory and sequencer, not a content store |
| `I15` | Spaces access is gated on the granted OAuth scopes |
| `I16` | The post-quantum profile (X-Wing for MLS; hybrid KEMs in Labyrinth) |

`I1` is not cited in the live client.
