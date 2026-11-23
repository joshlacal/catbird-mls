# catbird-mls integration tests

Integration targets for `catbird-mls`. Run them from the repository root.

The crate pins OpenMLS `=0.9.0-rc.3` (rev `679bdc31ef44dc919f28aee9ce442ec8eb0682c0`). It also depends on the sibling `labyrinth` crate through the default `labyrinth` feature, so the toolchain must build edition-2024 crates (Rust 1.85 or later).

## Client and archive contract targets

The archive contract these targets pin is described in `CLAUDE.md`, under "Native archive contract". The commands below match the ones the Task 4 report used. Nothing was run for this README update.

| Target | Covers | Command |
|---|---|---|
| `client_live_chat_data_plane` | Live sends, ordered sync, `I4`/`I13` verification, C33, and the C33 creation and acceptance retry journals (`Retry-After`, exact replay) | `cargo test --features sim --test client_live_chat_data_plane` |
| `two_process_data_version_and_background` | App and NSE on one database: `PRAGMA data_version` reconciliation (`I7`) and backgrounding (`I9`) | `cargo test --features sim --test two_process_data_version_and_background` |
| `determinism_seams_test` | Deterministic clock and entropy seams | `cargo test --features sim --test determinism_seams_test` |
| `client_labyrinth_fault_lines` | The **test-only** offline Space archive harness (`open_offline_archive_for_test`), not the production archive | `cargo test --features sim --test client_labyrinth_fault_lines` |
| `push_processor_memory_and_gap` | The NSE/FCM push processor | `cargo test --features sim --test push_processor_memory_and_gap` |

`client_labyrinth_fault_lines` and `push_processor_memory_and_gap` declare `required-features = ["sim"]` in `Cargo.toml`.

The production archive's verified restore, witness copies, account-deletion hiding and Space read checks are covered by in-crate unit tests:

```bash
cargo test --lib native_restore_tests
cargo test --lib native_archive_space_auth
```

## Historical OpenMLS diagnostics

`two_user_messaging_test.rs`, `persistence_repro.rs` and `member_removal_test.rs` date from the OpenMLS 0.7.1 era, when they isolated a `SecretReuseError`. They use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` with `OpenMlsRustCrypto` in-memory storage, not the production X-Wing suite. Their earlier "all tests pass on OpenMLS 0.7.1" results were not re-run against the current pin.

```bash
cargo test --test two_user_messaging_test -- --nocapture
cargo test --test persistence_repro -- --nocapture
cargo test --test member_removal_test -- --nocapture
```

## Debugging

- Tests use `env_logger`, so `RUST_LOG=debug cargo test --test <target> -- --nocapture` prints detailed logs.
- Add `-- --test-threads=1` for deterministic output ordering.
- `cargo test --release` keeps the post-quantum key-package and SQLCipher-heavy targets fast.
