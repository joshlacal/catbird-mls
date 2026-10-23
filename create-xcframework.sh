#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Keep Cargo's output selection and the packaging inputs identical. This
# permits an isolated release cache without mixing another target directory's
# stale libraries into the generated framework.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export CATBIRD_MLS_APPLE_SCOPE="${CATBIRD_MLS_APPLE_SCOPE:-apple-all-targets}"
case "$CATBIRD_MLS_APPLE_SCOPE" in
    apple-all-targets) FRAMEWORK_NAME="CatbirdMLSFFI.xcframework" ;;
    ios-arm64-simulator-only) FRAMEWORK_NAME="CatbirdMLSFFISimulator.xcframework" ;;
    *) echo "Unsupported Apple artifact scope: $CATBIRD_MLS_APPLE_SCOPE" >&2; exit 1 ;;
esac

echo "📦 Building CatbirdMLS with UniFFI for iOS"
echo "========================================"
echo ""

# Keep Cargo from falling back to iOS 10/macOS 10 era link targets when
# compiling C dependencies for the XCFramework.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"

# Cargo features of the shipped library. Labyrinth history backup is on: it
# does nothing until the account enables it on a device. Set
# CATBIRD_MLS_FEATURES="" to build without it.
CATBIRD_MLS_FEATURES="${CATBIRD_MLS_FEATURES-labyrinth}"
FEATURE_ARGS=()
if [ -n "$CATBIRD_MLS_FEATURES" ]; then
    FEATURE_ARGS=(--features "$CATBIRD_MLS_FEATURES")
fi

# Clean previous builds
rm -rf "$FRAMEWORK_NAME"
rm -rf build/frameworks
rm -rf build/bindings

# Detect host architecture
HOST_ARCH=$(uname -m)
if [ "$HOST_ARCH" = "arm64" ]; then
    HOST_TARGET="aarch64-apple-darwin"
else
    HOST_TARGET="x86_64-apple-darwin"
fi

echo "🔧 Step 1: Build host library for metadata extraction"
echo "Target: $HOST_TARGET"
cargo build --locked --release --target "$HOST_TARGET" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo ""
echo "🧠 Step 2: Generate Swift bindings from compiled library"
mkdir -p build/bindings

# Read the same target directory selected for every Cargo invocation.
LIBRARY_PATH="$CARGO_TARGET_DIR/$HOST_TARGET/release/libcatbird_mls.dylib"

# Use the in-workspace uniffi-bindgen binary
cargo run --locked --bin uniffi-bindgen generate \
    --library "$LIBRARY_PATH" \
    --language swift \
    --out-dir build/bindings \
    --config uniffi.toml

# This deliberately separate artifact lets simulator verification overlap the
# remaining release targets. It cannot satisfy the full release matrix.
if [ "$CATBIRD_MLS_APPLE_SCOPE" = "ios-arm64-simulator-only" ]; then
    rustup target add aarch64-apple-ios-sim
    cargo build --locked --release --target aarch64-apple-ios-sim ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}
    mkdir -p build/libs/ios-arm64-simulator/Headers
    cp "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libcatbird_mls.a" \
        build/libs/ios-arm64-simulator/libCatbirdMLSFFI.a
    cp build/bindings/CatbirdMLSFFI.h build/libs/ios-arm64-simulator/Headers/
    cp build/bindings/CatbirdMLSFFI.modulemap build/libs/ios-arm64-simulator/Headers/module.modulemap
    xcodebuild -create-xcframework \
        -library build/libs/ios-arm64-simulator/libCatbirdMLSFFI.a \
        -headers build/libs/ios-arm64-simulator/Headers \
        -output "$FRAMEWORK_NAME"
    python3 scripts/normalize_xcframework_plist.py "$FRAMEWORK_NAME/Info.plist"
    echo "Simulator-only artifact complete: $FRAMEWORK_NAME (not a release framework)"
    exit 0
fi

echo ""
echo "📦 Step 3: Add iOS and macOS targets"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-ios-macabi x86_64-apple-ios-macabi aarch64-apple-darwin x86_64-apple-darwin

echo ""
echo "🏗️  Step 4: Build static libraries"
echo "Building for iOS Device (ARM64)..."
cargo build --locked --release --target aarch64-apple-ios ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "Building for iOS Simulator (ARM64)..."
cargo build --locked --release --target aarch64-apple-ios-sim ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "Building for iOS Simulator (x86_64)..."
cargo build --locked --release --target x86_64-apple-ios ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "Building for Mac Catalyst (arm64)..."
cargo build --locked --release --target aarch64-apple-ios-macabi ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "Building for Mac Catalyst (x86_64)..."
cargo build --locked --release --target x86_64-apple-ios-macabi ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "Building for macOS (arm64)..."
cargo build --locked --release --target aarch64-apple-darwin ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "Building for macOS (x86_64)..."
cargo build --locked --release --target x86_64-apple-darwin ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo ""
echo "📦 Step 5: Create XCFramework structure"

# Create library structure for device
mkdir -p build/libs/ios-arm64/Headers
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libcatbird_mls.a" \
   build/libs/ios-arm64/libCatbirdMLSFFI.a

# Create library structure for simulator (fat binary)
mkdir -p build/libs/ios-simulator/Headers
lipo -create \
    "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libcatbird_mls.a" \
    "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libcatbird_mls.a" \
    -output build/libs/ios-simulator/libCatbirdMLSFFI.a

# Create library structure for macOS (fat binary)
mkdir -p build/libs/macos/Headers
lipo -create \
    "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libcatbird_mls.a" \
    "$CARGO_TARGET_DIR/x86_64-apple-darwin/release/libcatbird_mls.a" \
    -output build/libs/macos/libCatbirdMLSFFI.a

# Create library structure for Mac Catalyst (fat binary)
mkdir -p build/libs/ios-maccatalyst/Headers
lipo -create \
    "$CARGO_TARGET_DIR/aarch64-apple-ios-macabi/release/libcatbird_mls.a" \
    "$CARGO_TARGET_DIR/x86_64-apple-ios-macabi/release/libcatbird_mls.a" \
    -output build/libs/ios-maccatalyst/libCatbirdMLSFFI.a

# Copy generated headers and modulemap
for LIB_DIR in build/libs/*; do
    cp build/bindings/CatbirdMLSFFI.h "$LIB_DIR/Headers/"
    # Use standard module map (not framework module)
    cp build/bindings/CatbirdMLSFFI.modulemap "$LIB_DIR/Headers/module.modulemap"
done

echo ""
echo "🎁 Step 6: Create XCFramework"
# Note: Debug symbols are embedded in the static libraries (.a files)
# Xcode will generate dSYMs for the final app binary when archiving
xcodebuild -create-xcframework \
    -library build/libs/ios-arm64/libCatbirdMLSFFI.a \
    -headers build/libs/ios-arm64/Headers \
    -library build/libs/ios-simulator/libCatbirdMLSFFI.a \
    -headers build/libs/ios-simulator/Headers \
    -library build/libs/ios-maccatalyst/libCatbirdMLSFFI.a \
    -headers build/libs/ios-maccatalyst/Headers \
    -library build/libs/macos/libCatbirdMLSFFI.a \
    -headers build/libs/macos/Headers \
    -output CatbirdMLSFFI.xcframework

# Xcode 27 can emit AvailableLibraries in nondeterministic order. Normalize the
# generated plist so identical inputs produce byte-identical XCFrameworks.
python3 scripts/normalize_xcframework_plist.py CatbirdMLSFFI.xcframework/Info.plist

echo ""
echo "✅ Build complete!"
echo ""
echo "📍 Generated files:"
echo "   - XCFramework:     CatbirdMLSFFI.xcframework/"
echo "   - Swift bindings:  build/bindings/CatbirdMLS.swift"
echo "   - C headers:       build/bindings/CatbirdMLSFFI.h"
echo "   - Module map:      build/bindings/CatbirdMLSFFI.modulemap"
echo ""
echo "🎯 Next steps:"
echo "   1. Add CatbirdMLSFFI.xcframework to your Xcode project"
echo "   2. Copy build/bindings/CatbirdMLS.swift to your Swift sources"
echo "   3. Import CatbirdMLS in your Swift code"
echo ""
