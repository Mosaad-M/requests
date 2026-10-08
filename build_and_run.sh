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

# When tls_pure is available locally, prepend it so it takes precedence over
# any installed tls package — required for ALPN support (tls_pure >=1.3.0).
TLS_PURE_ABS="${TLS_PURE:-$(cd "$SCRIPT_DIR/../tls_pure" 2>/dev/null && pwd || echo "")}"
if [ -d "$TLS_PURE_ABS" ]; then
    FLAGS="-I $TLS_PURE_ABS $FLAGS"
fi

# No -Xlinker flags: zlib, libzstd and libbrotlidec are opened at runtime
# (codecs.mojo). Mojo's rpath to the env's lib dir lets dlopen find the env's
# libzstd and (if the brotli package is installed) libbrotlidec.
mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" $FLAGS

"$BUILD_DIR/$BASENAME" "$@"
