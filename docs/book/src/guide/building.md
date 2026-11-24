# Building

## Prerequisites

- **Rust 1.85 or newer**, stable. (The release builds use 1.97.1.)
- **Sibling checkouts.** `Cargo.toml` takes three repositories by path, so clone them next to this one:

  ```text
  workspace/
  ├── catbird-atproto/   # also provides atproto-spaces
  ├── labyrinth/         # also provides labyrinth-protocol
  └── catbird-mls/
  ```

  The commits a release was built from are recorded in `CatbirdMLSCore`'s `Scripts/ffi-release-inputs.json`. Labyrinth is an optional dependency, but Cargo resolves its path even when the feature is off, so it must be present.
- **Git dependencies.** OpenMLS comes from a fork (`github.com/joshlacal/openmls`, pinned by revision in `Cargo.toml`), and a transitive dependency is fetched from `tangled.org`. If Cargo's built-in git client stalls, set `CARGO_NET_GIT_FETCH_WITH_CLI=true`.
- **C toolchain and CMake.** SQLCipher is compiled from source (`rusqlite` with `bundled-sqlcipher`; Android uses its vendored OpenSSL), and libopus is built statically through CMake for voice messages. `.cargo/config.toml` sets `CMAKE_POLICY_VERSION_MINIMUM=3.5` for it. On Linux you also need OpenSSL headers and `pkg-config`.

## Host build and tests

```bash
cargo build
cargo test --release            # release keeps the post-quantum and SQLCipher tests fast
cargo fmt --check
cargo clippy --all-targets
```

Some integration tests need the deterministic-simulation feature, for example:

```bash
cargo test --release --features sim --test client_live_chat_data_plane
```

`tests/README.md` lists them. About 70 older test targets need `--features legacy-orchestrator` and exercise the previous client.

## Feature flags

| Feature | Effect |
|---|---|
| `labyrinth` (default) | History backup, circles and their FFI methods. The apps always build with it. |
| `browser` | Same as `labyrinth`; for the web build. |
| `legacy-orchestrator` | Compiles the previous client (`orchestrator`, `engine`). Not used by the apps. |
| `fork-resolution` | Legacy fork recovery by re-adding. |
| `echo-bot` | The `echo-bot` test binary (implies `legacy-orchestrator`). |
| `test-utils`, `e2e-aad` | Test harnesses. Never shipped. |
| `sim`, `plant_*` | Deterministic simulation and planted-bug tests. Never shipped. |

Avoid `--all-features` outside CI lint jobs: it turns on the simulation and planted-bug features.

## Apple: XCFramework

`create-xcframework.sh` is the build the releases use. It requires macOS with Xcode.

```bash
CMAKE_POLICY_VERSION_MINIMUM=3.5 ./create-xcframework.sh
```

It builds seven targets (iOS device, iOS simulator on Apple silicon and Intel, Mac Catalyst on both, macOS on both) with `--locked --release`, generates the Swift bindings with UniFFI, and packages four slices into `CatbirdMLSFFI.xcframework`: iOS, iOS simulator, Mac Catalyst and macOS. Deployment targets are iOS 18 and macOS 15. Features come from `CATBIRD_MLS_FEATURES` (default `labyrinth`). The Swift bindings are `CatbirdMLS.swift`, `CatbirdMLSFFI.h` and its module map.

To ship it, see [The Swift package](swift-package.md).

## Android

```bash
export ANDROID_NDK_HOME=/path/to/ndk
./build-android.sh
```

It builds `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64` (API 21 linkers, 16 KiB page alignment), generates Kotlin bindings (package `blue.catbird.mls`), and writes an `mlsffi` Android module to `build/android/`, synced by default into `../android/Catbird/mlsffi`. Without `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` it looks under the macOS default SDK path. `ANDROID_BUILD_GUIDE.md` has details.

## Web

```bash
cargo build --target wasm32-unknown-unknown --features browser
```

The FFI layer, the voice codec and the legacy engine are left out on `wasm32`. The JavaScript-facing wrapper, `WasmMlsClient`, lives in the separate `catbird-mls-web` repository, which also supplies the SQLite driver.

## API documentation

```bash
cargo doc --no-deps --open
```

The published copy is under [API reference](../reference/api.md).

## This book

```bash
cargo install mdbook --version 0.4.52 --locked
mdbook serve docs/book
```
