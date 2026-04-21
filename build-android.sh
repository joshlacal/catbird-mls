#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}$1${NC}"
}

log_warn() {
  echo -e "${YELLOW}$1${NC}"
}

log_error() {
  echo -e "${RED}$1${NC}" >&2
}

usage() {
  cat <<'EOF'
Build catbird-mls for Android and sync the generated UniFFI artifacts.

Usage:
  ./build-android.sh [--android-module-dir <path>] [--output-dir <path>] [--no-sync-android-module]

Options:
  --android-module-dir <path>  Sync generated Kotlin + jniLibs into this Android module.
  --output-dir <path>          Override the staging directory root (default: build/android).
  --no-sync-android-module     Build and stage artifacts without syncing them into android/Catbird/mlsffi.
  --help                       Show this help text.

By default the script auto-detects the latest Android NDK in ~/Library/Android/sdk/ndk
and, when present, syncs artifacts into ../android/Catbird/mlsffi.
EOF
}

OUTPUT_ROOT="$SCRIPT_DIR/build/android"
DEFAULT_ANDROID_MODULE_DIR="$SCRIPT_DIR/../android/Catbird/mlsffi"
ANDROID_MODULE_DIR=""
SYNC_TO_ANDROID_MODULE="auto"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --android-module-dir)
      ANDROID_MODULE_DIR="$2"
      SYNC_TO_ANDROID_MODULE="yes"
      shift 2
      ;;
    --output-dir)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --no-sync-android-module)
      SYNC_TO_ANDROID_MODULE="no"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ANDROID_MODULE_DIR" && "$SYNC_TO_ANDROID_MODULE" != "no" && -d "$DEFAULT_ANDROID_MODULE_DIR" ]]; then
  ANDROID_MODULE_DIR="$DEFAULT_ANDROID_MODULE_DIR"
fi

resolve_ndk_dir() {
  local direct_candidates=(
    "${ANDROID_NDK_HOME:-}"
    "${ANDROID_NDK_ROOT:-}"
  )
  local dir_candidates=(
    "${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk"
    "${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}/ndk"
  )

  local candidate
  for candidate in "${direct_candidates[@]}"; do
    if [[ -n "$candidate" && -d "$candidate/toolchains/llvm/prebuilt" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  for candidate in "${dir_candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      local latest
      latest="$(find "$candidate" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
      if [[ -n "$latest" && -d "$latest/toolchains/llvm/prebuilt" ]]; then
        printf '%s\n' "$latest"
        return 0
      fi
    fi
  done

  return 1
}

ANDROID_NDK_DIR="$(resolve_ndk_dir || true)"
if [[ -z "$ANDROID_NDK_DIR" ]]; then
  log_error "Unable to locate an Android NDK installation. Install the NDK via Android Studio or set ANDROID_NDK_HOME."
  exit 1
fi

TOOLCHAIN_DIR="$(find "$ANDROID_NDK_DIR/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1)"
if [[ -z "$TOOLCHAIN_DIR" ]]; then
  log_error "Unable to locate the NDK LLVM toolchain under $ANDROID_NDK_DIR"
  exit 1
fi

export ANDROID_NDK_HOME="$ANDROID_NDK_DIR"
export ANDROID_NDK_ROOT="$ANDROID_NDK_DIR"
export PATH="$TOOLCHAIN_DIR/bin:$PATH"

log_info "Building catbird-mls for Android"
log_info "Using Android NDK: $ANDROID_NDK_DIR"
log_info "Using LLVM toolchain: $TOOLCHAIN_DIR"

ANDROID_TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"
  "i686-linux-android"
  "x86_64-linux-android"
)

log_warn "Checking Rust Android targets..."
for target in "${ANDROID_TARGETS[@]}"; do
  if ! rustup target list | grep -q "$target (installed)"; then
    log_warn "Installing $target..."
    rustup target add "$target"
  else
    log_info "✓ $target installed"
  fi
done

STAGING_DIR="$OUTPUT_ROOT/mlsffi"
KOTLIN_DIR="$STAGING_DIR/src/main/kotlin"
JNI_DIR="$STAGING_DIR/src/main/jniLibs"

find "$OUTPUT_ROOT" -mindepth 1 -maxdepth 1 -type d \
  \( -name "kotlin" -o -name "jniLibs" -o -name "*-kotlin" \) \
  -exec rm -rf {} +
rm -rf "$STAGING_DIR"
mkdir -p "$KOTLIN_DIR" \
  "$JNI_DIR/arm64-v8a" \
  "$JNI_DIR/armeabi-v7a" \
  "$JNI_DIR/x86" \
  "$JNI_DIR/x86_64"

cat > "$STAGING_DIR/src/main/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
</manifest>
EOF

build_for_target() {
  local target="$1"
  local abi="$2"
  local clang_triple="$3"
  local normalized_target="${target//-/_}"
  local upper_target
  upper_target="$(printf '%s' "$normalized_target" | tr '[:lower:]' '[:upper:]')"
  local linker="$TOOLCHAIN_DIR/bin/${clang_triple}-clang"
  local cxx="$TOOLCHAIN_DIR/bin/${clang_triple}-clang++"
  local ar="$TOOLCHAIN_DIR/bin/llvm-ar"
  local ranlib="$TOOLCHAIN_DIR/bin/llvm-ranlib"
  local source_path="target/$target/release/libcatbird_mls.so"
  local dest_path="$JNI_DIR/$abi/libcatbird_mls.so"

  if [[ ! -x "$linker" ]]; then
    log_error "Expected linker not found: $linker"
    exit 1
  fi

  log_warn "Building for $target ($abi)..."
  env \
    "CC_${target}=$linker" \
    "CC_${normalized_target}=$linker" \
    "CXX_${target}=$cxx" \
    "CXX_${normalized_target}=$cxx" \
    "AR_${target}=$ar" \
    "AR_${normalized_target}=$ar" \
    "RANLIB_${target}=$ranlib" \
    "RANLIB_${normalized_target}=$ranlib" \
    "CARGO_TARGET_${upper_target}_LINKER=$linker" \
    cargo build --release --target "$target"

  if [[ ! -f "$source_path" ]]; then
    log_error "Expected library not found: $source_path"
    exit 1
  fi

  cp "$source_path" "$dest_path"
  log_info "✓ Copied $(basename "$source_path") to $abi"
}

build_for_target "aarch64-linux-android" "arm64-v8a" "aarch64-linux-android21"
build_for_target "armv7-linux-androideabi" "armeabi-v7a" "armv7a-linux-androideabi21"
build_for_target "i686-linux-android" "x86" "i686-linux-android21"
build_for_target "x86_64-linux-android" "x86_64" "x86_64-linux-android21"

log_warn "Generating Kotlin bindings..."
cargo run --bin uniffi-bindgen -- generate \
  --library target/aarch64-linux-android/release/libcatbird_mls.so \
  --language kotlin \
  --config uniffi.toml \
  --out-dir "$KOTLIN_DIR"

KOTLIN_BINDINGS_FILE="$KOTLIN_DIR/blue/catbird/mls/catbird_mls.kt"
python3 - "$KOTLIN_BINDINGS_FILE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
original = path.read_text()
text = original

# Rename `message` → `errorMessage` ONLY inside OrchestratorBridgeException's
# sealed class body AND its FfiConverter. Do NOT apply globally — other
# exception types (e.g. MlsCommitException) legitimately own a `message`
# field and their converters reference `value.`message``; a global rewrite
# corrupts them (the field stays `message` but the converter references
# `errorMessage`, which won't compile).

def rescope(text, head, tail):
    """Replace `message` → `errorMessage` inside [head..tail] only."""
    start = text.find(head)
    if start == -1:
        raise SystemExit(f"missing head marker: {head!r}")
    end = text.find(tail, start)
    if end == -1:
        raise SystemExit(f"missing tail marker after {head!r}: {tail!r}")
    block = text[start:end]
    updated = block.replace('`message`', '`errorMessage`')
    return text[:start] + updated + text[end:]

# Block 1: the sealed class body (ends where ErrorHandler companion object begins).
text = rescope(
    text,
    'sealed class OrchestratorBridgeException: kotlin.Exception() {',
    '\n\n    companion object ErrorHandler',
)

# Block 2: the FfiConverter for OrchestratorBridgeError (separate top-level object).
text = rescope(
    text,
    'public object FfiConverterTypeOrchestratorBridgeError',
    '\npublic object ',
)

if text != original:
    path.write_text(text)
PY
log_info "✓ Kotlin bindings generated under $KOTLIN_DIR"
log_info "✓ Patched OrchestratorBridgeException.message field names for Kotlin compatibility"

if [[ "$SYNC_TO_ANDROID_MODULE" == "yes" || ( "$SYNC_TO_ANDROID_MODULE" == "auto" && -n "$ANDROID_MODULE_DIR" ) ]]; then
  if [[ -z "$ANDROID_MODULE_DIR" ]]; then
    log_error "Sync requested, but no Android module directory was provided."
    exit 1
  fi

  mkdir -p "$ANDROID_MODULE_DIR/src/main/kotlin" "$ANDROID_MODULE_DIR/src/main/jniLibs"
  rsync -a --delete "$KOTLIN_DIR/" "$ANDROID_MODULE_DIR/src/main/kotlin/"
  rsync -a --delete "$JNI_DIR/" "$ANDROID_MODULE_DIR/src/main/jniLibs/"
  log_info "✓ Synced generated artifacts into $ANDROID_MODULE_DIR"
else
  log_warn "Skipped syncing into android/Catbird/mlsffi"
fi

cat <<EOF

═══════════════════════════════════════════════════════════
✓ Android MLS artifacts are ready
═══════════════════════════════════════════════════════════
Staged artifacts: $STAGING_DIR
Kotlin package:   blue.catbird.mls
Native library:   libcatbird_mls.so
EOF

if [[ -n "$ANDROID_MODULE_DIR" && "$SYNC_TO_ANDROID_MODULE" != "no" ]]; then
  cat <<EOF
Synced module:    $ANDROID_MODULE_DIR
EOF
fi
