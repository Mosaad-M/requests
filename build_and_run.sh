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

TLS_PURE="${TLS_PURE:-$(cd "$SCRIPT_DIR/../tls" 2>/dev/null && pwd || echo "$SCRIPT_DIR/../tls")}"
mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" \
    -I "$TLS_PURE"

"$BUILD_DIR/$BASENAME" "$@"
