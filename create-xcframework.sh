#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "📦 Building CatbirdMLS with UniFFI for iOS"
echo "========================================"
echo ""

# Clean previous builds
rm -rf CatbirdMLSFFI.xcframework
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
cargo build --release --target "$HOST_TARGET"

echo ""
echo "🧠 Step 2: Generate Swift bindings from compiled library"
mkdir -p build/bindings

# The target directory is local to catbird-mls crate
LIBRARY_PATH="target/$HOST_TARGET/release/libcatbird_mls.dylib"

# Use the in-workspace uniffi-bindgen binary
cargo run --bin uniffi-bindgen generate \
    --library "$LIBRARY_PATH" \
    --language swift \
    --out-dir build/bindings \
    --config uniffi.toml

echo ""
echo "📦 Step 3: Add iOS and macOS targets"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-ios-macabi x86_64-apple-ios-macabi aarch64-apple-darwin x86_64-apple-darwin

echo ""
echo "🏗️  Step 4: Build static libraries"
echo "Building for iOS Device (ARM64)..."
cargo build --release --target aarch64-apple-ios

echo "Building for iOS Simulator (ARM64)..."
cargo build --release --target aarch64-apple-ios-sim

echo "Building for iOS Simulator (x86_64)..."
cargo build --release --target x86_64-apple-ios

echo "Building for Mac Catalyst (arm64)..."
cargo build --release --target aarch64-apple-ios-macabi

echo "Building for Mac Catalyst (x86_64)..."
cargo build --release --target x86_64-apple-ios-macabi

echo "Building for macOS (arm64)..."
cargo build --release --target aarch64-apple-darwin

echo "Building for macOS (x86_64)..."
cargo build --release --target x86_64-apple-darwin

echo ""
echo "📦 Step 5: Create XCFramework structure"

# Create library structure for device
mkdir -p build/libs/ios-arm64/Headers
cp target/aarch64-apple-ios/release/libcatbird_mls.a \
   build/libs/ios-arm64/libCatbirdMLSFFI.a

# Create library structure for simulator (fat binary)
mkdir -p build/libs/ios-simulator/Headers
lipo -create \
    target/aarch64-apple-ios-sim/release/libcatbird_mls.a \
    target/x86_64-apple-ios/release/libcatbird_mls.a \
    -output build/libs/ios-simulator/libCatbirdMLSFFI.a

# Create library structure for macOS (fat binary)
mkdir -p build/libs/macos/Headers
lipo -create \
    target/aarch64-apple-darwin/release/libcatbird_mls.a \
    target/x86_64-apple-darwin/release/libcatbird_mls.a \
    -output build/libs/macos/libCatbirdMLSFFI.a

# Create library structure for Mac Catalyst (fat binary)
mkdir -p build/libs/ios-maccatalyst/Headers
lipo -create \
    target/aarch64-apple-ios-macabi/release/libcatbird_mls.a \
    target/x86_64-apple-ios-macabi/release/libcatbird_mls.a \
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
