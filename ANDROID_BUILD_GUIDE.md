# Android MLS Build Guide

`catbird-mls` is the canonical Android MLS source. The Rust crate owns the UniFFI surface, and the generated Kotlin/JNI artifacts are staged under `catbird-mls/build/android/mlsffi/` and synced into `android/Catbird/mlsffi/` for local Android builds.

## Canonical regeneration paths

### From the Rust crate

```bash
cd catbird-mls
./build-android.sh
```

This is the primary workflow inside the monorepo. The script now:

1. Auto-detects the latest installed Android NDK (or uses `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` if set)
2. Cross-compiles `libcatbird_mls.so` for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`
3. Runs UniFFI with `uniffi.toml` so Kotlin stays in `blue.catbird.mls`
4. Applies a deterministic Kotlin post-process for UniFFI exception variants whose Rust field name is `message`
5. Deletes legacy top-level Android staging directories from previous workflows so only the canonical staged layout remains
6. Stages the generated artifacts in `build/android/mlsffi/`
7. Syncs `src/main/kotlin` and `src/main/jniLibs` into `../android/Catbird/mlsffi/` when that module exists

### From the Android module

```bash
cd android/Catbird/mlsffi
./regenerate.sh
```

That wrapper simply delegates back to `catbird-mls/build-android.sh --android-module-dir ...`, so there is still exactly one canonical generation path.

## Output layout

After a successful run:

```text
catbird-mls/build/android/mlsffi/
└── src/
    └── main/
        ├── AndroidManifest.xml
        ├── jniLibs/
        │   ├── arm64-v8a/libcatbird_mls.so
        │   ├── armeabi-v7a/libcatbird_mls.so
        │   ├── x86/libcatbird_mls.so
        │   └── x86_64/libcatbird_mls.so
        └── kotlin/
            └── blue/
                └── catbird/
                    └── mls/
                        └── catbird_mls.kt
```

Those staged files are the exact artifacts copied into `android/Catbird/mlsffi/src/main/`.

## Package and library names

These values are the Android seam contract and should stay aligned:

- Kotlin package: `blue.catbird.mls`
- Android module: `android/Catbird/mlsffi`
- Native library name: `libcatbird_mls.so`
- UniFFI config source: `catbird-mls/uniffi.toml`
- Kotlin compatibility patch: `build-android.sh` rewrites `OrchestratorBridgeException` constructor fields from ``message`` to ``errorMessage`` after generation so Kotlin 2 does not collide with `Throwable.message`

## Prerequisites

### Android NDK

Install the NDK with Android Studio (`Tools > SDK Manager > SDK Tools > NDK (Side by side)`) or set `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` to an existing install.

The build script no longer requires you to manually prepend the NDK toolchain to `PATH`; it does that itself.

### Rust Android targets

The script installs missing Rust targets automatically, but you can preinstall them if preferred:

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

## Validation

Build the Android wrapper module after regenerating artifacts:

```bash
cd android/Catbird
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
./gradlew :mlsffi:assembleDebug
```

If you specifically want the release variant:

```bash
./gradlew :mlsffi:assembleRelease
```

## Troubleshooting

### `OrchestratorBridgeException` fails to compile because of `message`

Kotlin 2 rejects generated exception subclasses that both declare a constructor property named `message` and inherit from `Throwable`. `build-android.sh` now patches that generated UniFFI block immediately after generation, so a fresh regeneration should remove those errors.

### `arm-linux-androideabi-clang` not found

`build-android.sh` now exports target-specific `CC_*`, `CXX_*`, `AR_*`, and `CARGO_TARGET_*_LINKER` values for each Android ABI. If you still see this error, confirm the detected NDK contains the LLVM toolchain:

```bash
ls "$HOME/Library/Android/sdk/ndk"/*/toolchains/llvm/prebuilt
```

### Need to stage artifacts without touching `android/Catbird/mlsffi`

```bash
cd catbird-mls
./build-android.sh --no-sync-android-module
```

### Need to sync a different Android module path

```bash
cd catbird-mls
./build-android.sh --android-module-dir /absolute/path/to/mlsffi
```
