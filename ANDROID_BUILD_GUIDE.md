# Android Build Guide for MLS FFI

This guide explains how to build the MLS FFI library for Android and generate Kotlin bindings.

## Prerequisites

### 1. Install Android NDK

**Option A: Via Android Studio**
1. Open Android Studio
2. Go to `Tools > SDK Manager`
3. Select `SDK Tools` tab
4. Check `NDK (Side by side)` and click Apply
5. Default location: `~/Library/Android/sdk/ndk/<version>/` (macOS)

**Option B: Direct Download**
Download from: https://developer.android.com/ndk/downloads

### 2. Set Environment Variables

Add to your `~/.zshrc` or `~/.bash_profile`:

```bash
# Android NDK (adjust version as needed)
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/26.1.10909125
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
```

Then reload:
```bash
source ~/.zshrc  # or ~/.bash_profile
```

### 3. Configure Cargo for Android Cross-Compilation

The build script will automatically add Android targets, but you can also add them manually:

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

### 4. Create Cargo Config (Optional but Recommended)

Create `.cargo/config.toml` in the `mls-ffi` directory:

```toml
[target.aarch64-linux-android]
linker = "aarch64-linux-android21-clang"

[target.armv7-linux-androideabi]
linker = "armv7a-linux-androideabi21-clang"

[target.i686-linux-android]
linker = "i686-linux-android21-clang"

[target.x86_64-linux-android]
linker = "x86_64-linux-android21-clang"
```

## Building

### Quick Build

Simply run:

```bash
./build-android.sh
```

This will:
1. ✅ Check and install Android Rust targets
2. ✅ Build native libraries for all Android architectures
3. ✅ Generate Kotlin bindings via UniFFI
4. ✅ Create a complete Kotlin package structure
5. ✅ Package everything in `build/android/mlsffi-kotlin/`

### Build Output Structure

```
build/android/mlsffi-kotlin/
├── build.gradle.kts              # Gradle build configuration
├── src/
│   └── main/
│       ├── AndroidManifest.xml
│       └── kotlin/
│           └── blue/
│               └── catbird/
│                   └── mlsffi/
│                       └── *.kt  # Generated Kotlin bindings
└── jniLibs/
    ├── arm64-v8a/
    │   └── libmls_ffi.so        # ARM64 native library
    ├── armeabi-v7a/
    │   └── libmls_ffi.so        # ARMv7 native library
    ├── x86/
    │   └── libmls_ffi.so        # x86 native library (emulator)
    └── x86_64/
        └── libmls_ffi.so        # x86_64 native library (emulator)
```

## Integration with Android Project

### Method 1: Gradle Module (Recommended)

1. Copy the `mlsffi-kotlin` directory to your Android project root:
   ```bash
   cp -r build/android/mlsffi-kotlin /path/to/your/android/project/
   ```

2. Add to `settings.gradle.kts`:
   ```kotlin
   include(":app", ":mlsffi-kotlin")
   ```

3. Add to your app's `build.gradle.kts`:
   ```kotlin
   dependencies {
       implementation(project(":mlsffi-kotlin"))
   }
   ```

4. Sync Gradle and you're ready to use!

### Method 2: Manual Integration

1. Copy JNI libraries to your app:
   ```bash
   cp -r build/android/mlsffi-kotlin/jniLibs/* app/src/main/jniLibs/
   ```

2. Copy Kotlin source files:
   ```bash
   cp -r build/android/mlsffi-kotlin/src/main/kotlin/* app/src/main/kotlin/
   ```

3. Add JNA dependency to `build.gradle.kts`:
   ```kotlin
   dependencies {
       implementation("net.java.dev.jna:jna:5.14.0@aar")
   }
   ```

## Usage Example

```kotlin
import blue.catbird.mlsffi.*

class MLSManager(context: Context) {
    private val mlsContext: Long

    init {
        // Initialize MLS with database path
        val dbPath = File(context.filesDir, "mls.sqlite").absolutePath
        mlsContext = mlsInit(databasePath = dbPath)
    }

    suspend fun createGroup(conversationId: String): String {
        return withContext(Dispatchers.IO) {
            mlsCreateGroup(
                context = mlsContext,
                conversationId = conversationId
            )
        }
    }

    suspend fun sendMessage(groupId: String, message: String): ByteArray {
        return withContext(Dispatchers.IO) {
            mlsEncryptMessage(
                context = mlsContext,
                groupId = groupId,
                message = message.toByteArray()
            )
        }
    }

    suspend fun receiveMessage(groupId: String, ciphertext: ByteArray): String {
        return withContext(Dispatchers.IO) {
            val plaintext = mlsDecryptMessage(
                context = mlsContext,
                groupId = groupId,
                ciphertext = ciphertext
            )
            String(plaintext)
        }
    }

    fun cleanup() {
        mlsDestroy(mlsContext)
    }
}
```

## Troubleshooting

### Error: ANDROID_NDK_HOME not set

Make sure you've set the environment variable and reloaded your shell:
```bash
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/26.1.10909125
source ~/.zshrc
```

### Error: linker not found

Your NDK path might be wrong. Check:
```bash
ls $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/
```

You should see files like `aarch64-linux-android21-clang`.

### Library not loading on device

Make sure you've copied the JNI libraries to the correct architecture folder. Android will automatically select the right one based on the device.

### Build fails with "undefined reference to..."

This usually means a dependency issue. Try:
```bash
cargo clean
./build-android.sh
```

## Regenerating Bindings Only

If you only need to regenerate Kotlin bindings (without rebuilding Rust):

```bash
cargo build --bin uniffi-bindgen
./target/debug/uniffi-bindgen generate \
    --library target/aarch64-linux-android/release/libmls_ffi.so \
    --language kotlin \
    --out-dir build/android/kotlin
```

## Architecture Support

| Architecture | ABI            | Devices                          |
|--------------|----------------|----------------------------------|
| ARM64        | arm64-v8a      | Modern phones/tablets (2015+)    |
| ARMv7        | armeabi-v7a    | Older phones/tablets             |
| x86          | x86            | 32-bit emulators                 |
| x86_64       | x86_64         | 64-bit emulators, Chromebooks    |

## Performance Notes

- **Release builds** are optimized with `-O` flag
- Libraries are stripped of debug symbols for smaller size
- ARM64 provides best performance on modern devices
- Include only the architectures you need to reduce APK size

## Next Steps

1. **Testing**: Test on real devices and emulators
2. **ProGuard**: Add ProGuard rules if using code shrinking
3. **Publishing**: Consider publishing to Maven Central or JitPack
4. **CI/CD**: Automate builds in GitHub Actions or similar

## Additional Resources

- [UniFFI Book](https://mozilla.github.io/uniffi-rs/)
- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [Rust Android Targets](https://doc.rust-lang.org/rustc/platform-support.html)
