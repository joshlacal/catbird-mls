#!/bin/bash
set -e

# Build MLS FFI for Android and generate Kotlin bindings
# This script builds for all Android architectures and packages into a Kotlin library

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building MLS FFI for Android...${NC}"

# Check for Android NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo -e "${RED}Error: ANDROID_NDK_HOME not set${NC}"
    echo "Please install Android NDK and set ANDROID_NDK_HOME"
    echo "You can install via Android Studio or download from:"
    echo "https://developer.android.com/ndk/downloads"
    echo ""
    echo "Example setup:"
    echo "  export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/26.1.10909125"
    echo "  export PATH=\$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:\$PATH"
    exit 1
fi

echo -e "${GREEN}Found Android NDK: $ANDROID_NDK_HOME${NC}"

# Android targets
ANDROID_TARGETS=(
    "aarch64-linux-android"   # ARM64
    "armv7-linux-androideabi" # ARMv7
    "i686-linux-android"      # x86
    "x86_64-linux-android"    # x86_64
)

# Check if targets are installed
echo -e "${YELLOW}Checking Rust Android targets...${NC}"
for target in "${ANDROID_TARGETS[@]}"; do
    if ! rustup target list | grep -q "$target (installed)"; then
        echo -e "${YELLOW}Installing $target...${NC}"
        rustup target add "$target"
    else
        echo -e "${GREEN}✓ $target installed${NC}"
    fi
done

# Create output directories
OUTPUT_DIR="$SCRIPT_DIR/build/android"
KOTLIN_DIR="$OUTPUT_DIR/kotlin"
JNI_DIR="$OUTPUT_DIR/jniLibs"

mkdir -p "$KOTLIN_DIR"
mkdir -p "$JNI_DIR"/{arm64-v8a,armeabi-v7a,x86,x86_64}

# Build for each Android architecture
echo -e "${GREEN}Building for Android architectures...${NC}"

build_for_target() {
    local target=$1
    local jni_arch=$2

    echo -e "${YELLOW}Building for $target...${NC}"

    cargo build --release --target "$target"

    # Copy the library to the appropriate JNI directory
    local lib_name="libcatbird_mls.so"
    local source_path="target/$target/release/$lib_name"
    local dest_path="$JNI_DIR/$jni_arch/$lib_name"

    if [ -f "$source_path" ]; then
        cp "$source_path" "$dest_path"
        echo -e "${GREEN}✓ Copied $lib_name to $jni_arch${NC}"
    else
        echo -e "${RED}Error: Library not found at $source_path${NC}"
        exit 1
    fi
}

# Build for each target
build_for_target "aarch64-linux-android" "arm64-v8a"
build_for_target "armv7-linux-androideabi" "armeabi-v7a"
build_for_target "i686-linux-android" "x86"
build_for_target "x86_64-linux-android" "x86_64"

# Generate Kotlin bindings
echo -e "${GREEN}Generating Kotlin bindings...${NC}"

# Build the uniffi-bindgen tool
cargo build --bin uniffi-bindgen

# Generate Kotlin bindings
./target/debug/uniffi-bindgen generate \
    --library target/aarch64-linux-android/release/libcatbird_mls.so \
    --language kotlin \
    --out-dir "$KOTLIN_DIR"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Kotlin bindings generated in $KOTLIN_DIR${NC}"
else
    echo -e "${RED}Error generating Kotlin bindings${NC}"
    exit 1
fi

# Create package structure
PACKAGE_DIR="$OUTPUT_DIR/mlsffi-kotlin"
mkdir -p "$PACKAGE_DIR"

# Copy Kotlin files
echo -e "${GREEN}Creating Kotlin package structure...${NC}"
cp -r "$KOTLIN_DIR"/* "$PACKAGE_DIR/"
cp -r "$JNI_DIR" "$PACKAGE_DIR/"

# Create build.gradle.kts for the package
cat > "$PACKAGE_DIR/build.gradle.kts" << 'EOF'
plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "blue.catbird.mlsffi"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        targetSdk = 34

        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("jniLibs")
        }
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
EOF

# Create AndroidManifest.xml
mkdir -p "$PACKAGE_DIR/src/main"
cat > "$PACKAGE_DIR/src/main/AndroidManifest.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
</manifest>
EOF

# Move Kotlin source files to proper location
mkdir -p "$PACKAGE_DIR/src/main/kotlin/blue/catbird/mlsffi"
find "$PACKAGE_DIR" -maxdepth 1 -name "*.kt" -exec mv {} "$PACKAGE_DIR/src/main/kotlin/blue/catbird/mlsffi/" \;

# Create README for the package
cat > "$PACKAGE_DIR/README.md" << 'EOF'
# MLS FFI Kotlin Bindings

Kotlin bindings for the MLS (Messaging Layer Security) FFI library.

## Installation

### Option 1: Gradle (Local)

1. Copy this `mlsffi-kotlin` directory to your Android project's root directory.

2. In your `settings.gradle.kts`:
```kotlin
include(":mlsffi-kotlin")
```

3. In your app's `build.gradle.kts`:
```kotlin
dependencies {
    implementation(project(":mlsffi-kotlin"))
}
```

### Option 2: Manual JNI Libraries

1. Copy the `jniLibs` directory to your app's `src/main/jniLibs/`

2. Add the generated Kotlin files to your project

3. Add JNA dependency:
```kotlin
dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
```

## Usage

```kotlin
import blue.catbird.mlsffi.*

// Initialize MLS context
val context = mlsInit(databasePath = "/path/to/db.sqlite")

// Generate key package
val keyPackage = mlsGenerateKeyPackage(
    context = context,
    userId = "user123",
    identityKey = identityKeyBytes
)

// Create group
val groupId = mlsCreateGroup(
    context = context,
    conversationId = "conv123"
)

// Add members
mlsAddMembers(
    context = context,
    groupId = groupId,
    keyPackages = listOf(keyPackage)
)

// Send message
val ciphertext = mlsEncryptMessage(
    context = context,
    groupId = groupId,
    message = "Hello from MLS!".toByteArray()
)

// Process incoming message
val plaintext = mlsDecryptMessage(
    context = context,
    groupId = groupId,
    ciphertext = ciphertext
)
```

## Architecture Support

This library includes native binaries for:
- ARM64 (arm64-v8a) - 64-bit ARM devices
- ARMv7 (armeabi-v7a) - 32-bit ARM devices
- x86 - 32-bit x86 emulators
- x86_64 - 64-bit x86 emulators

## Requirements

- Android API 26+ (Android 8.0 Oreo)
- Kotlin 1.9+

## License

See parent project LICENSE
EOF

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Build complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Package location: ${YELLOW}$PACKAGE_DIR${NC}"
echo ""
echo "Next steps:"
echo "1. Copy the mlsffi-kotlin directory to your Android project"
echo "2. Add to settings.gradle.kts: include(':mlsffi-kotlin')"
echo "3. Add to app dependencies: implementation(project(':mlsffi-kotlin'))"
echo ""
echo "Or publish to Maven:"
echo "  cd $PACKAGE_DIR"
echo "  ./gradlew publish"
