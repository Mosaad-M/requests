#!/bin/bash
# Build a Mojo file and run it. No C wrappers needed — tls_pure is pure Mojo.
# Usage: ./build_and_run.sh <file.mojo> [args...]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOJO_FILE="$1"
shift

BASENAME="$(basename "$MOJO_FILE" .mojo)"
BUILD_DIR="$SCRIPT_DIR/.build"
mkdir -p "$BUILD_DIR"

# Use mojo-pkg flags if available (CI), else fall back to TLS_PURE (local dev)
if [ -f "$SCRIPT_DIR/.mojo_flags" ]; then
    FLAGS=$(cat "$SCRIPT_DIR/.mojo_flags")
else
    TLS_PURE="${TLS_PURE:-$(cd "$SCRIPT_DIR/../tls_pure" 2>/dev/null && pwd || echo "$SCRIPT_DIR/../tls_pure")}"
    FLAGS="-I $TLS_PURE"
fi

mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" $FLAGS -Xlinker -lz

"$BUILD_DIR/$BASENAME" "$@"
