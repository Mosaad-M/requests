#!/bin/bash
# Mutation fuzzers for the parsers a hostile server reaches: HTTP/1.1 framing
# and response parsing, the chunk decoder, HPACK, h2 frames, the cookie jar.
# Usage: bash fuzz/run.sh [iterations=100000] [seeds=3]
# A crash (abort, memory fault or hang) fails the run; parse errors are the
# expected outcome and are only counted. fuzz_ascii mutates 7-bit bytes (it
# reaches deeper into the text protocols); fuzz_bytes mutates all 256 values.
set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ITERS="${1:-100000}"
SEEDS="${2:-3}"
FLAGS=$(cat .mojo_flags 2>/dev/null || true)
mkdir -p .build
for f in fuzz_ascii fuzz_bytes; do
    mojo build $FLAGS -I . "fuzz/$f.mojo" -o ".build/$f"
done
for seed in $(seq 1 "$SEEDS"); do
    for mode in h1 hpack h2 cookie; do
        for f in fuzz_ascii fuzz_bytes; do
            # cookie rounds build a String from the mutated bytes; invalid UTF-8
            # trips the stdlib's codepoint assert, which says nothing about the jar
            [ "$mode" = cookie ] && [ "$f" = fuzz_bytes ] && continue
            # perl alarm: macOS has no timeout(1)
            perl -e 'alarm 600; exec @ARGV' ".build/$f" "$ITERS" "$seed" "$mode" all | tail -1
        done
    done
done
