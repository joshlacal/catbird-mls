#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "🐍 Generating Python bindings for catbird-mls"
echo "============================================="

# Detect host architecture
HOST_ARCH=$(uname -m)
if [ "$HOST_ARCH" = "arm64" ]; then
    HOST_TARGET="aarch64-apple-darwin"
else
    HOST_TARGET="x86_64-apple-darwin"
fi

# Build release if needed
echo "📦 Step 1: Building release library..."
cargo build --release --target "$HOST_TARGET"

LIBRARY_PATH="target/$HOST_TARGET/release/libcatbird_mls.dylib"

# Generate Python bindings
echo "🐍 Step 2: Generating Python bindings..."
mkdir -p build/python/catbird_mls
cargo run --bin uniffi-bindgen generate \
    --library "$LIBRARY_PATH" \
    --language python \
    --out-dir build/python/catbird_mls

echo ""
echo "✅ Python bindings generated!"
echo "📍 Output: build/python/catbird_mls/"
echo ""
echo "🎯 Next steps:"
echo "   1. cd build/python"
echo "   2. pip install -e ."
echo "   3. python -c 'import catbird_mls; print(\"OK\")'"
