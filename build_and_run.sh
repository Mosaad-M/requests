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

# Add pixi env lib to linker search path and rpath so brotli/zstd are found in
# both local conda env (dev) and system install (CI).
PIXI_LIB="$SCRIPT_DIR/.pixi/envs/default/lib"
if [ -d "$PIXI_LIB" ]; then
    COMPRESSION_FLAGS="-Xlinker -L$PIXI_LIB -Xlinker -lbrotlidec -Xlinker -lzstd -Xlinker -rpath -Xlinker $PIXI_LIB"
else
    COMPRESSION_FLAGS="-Xlinker -lbrotlidec -Xlinker -lzstd"
fi

mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" $FLAGS -Xlinker -lz $COMPRESSION_FLAGS

"$BUILD_DIR/$BASENAME" "$@"
