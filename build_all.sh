#!/bin/bash
# MLS FFI Build Script
# Builds static libraries for iOS (device and simulator)

set -e

echo "🔧 Building MLS FFI for iOS..."

# iOS targets
IOS_TARGETS=(
    "aarch64-apple-ios"          # iOS devices (ARM64)
    "x86_64-apple-ios"           # iOS simulator (Intel)
    "aarch64-apple-ios-sim"      # iOS simulator (Apple Silicon)
)

# Ensure targets are installed
echo "📦 Ensuring Rust targets are installed..."
for target in "${IOS_TARGETS[@]}"; do
    rustup target add "$target"
done

# Build for each target
for target in "${IOS_TARGETS[@]}"; do
    echo "🏗️  Building for $target..."
    cargo build --release --target "$target"
done

# Create output directory
mkdir -p build/ios

# Copy libraries
echo "📋 Copying libraries..."
for target in "${IOS_TARGETS[@]}"; do
    cp "target/$target/release/libcatbird_mls.a" "build/ios/libcatbird_mls_${target}.a"
done

# Copy header
cp include/catbird_mls.h build/ios/

echo "✅ Build complete!"
echo "📍 Output location: build/ios/"
echo ""
echo "Libraries built:"
for target in "${IOS_TARGETS[@]}"; do
    ls -lh "build/ios/libcatbird_mls_${target}.a"
done
