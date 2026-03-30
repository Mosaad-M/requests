# ============================================================================
# zstd_decompress.mojo — Zstandard decompression via libzstd
# ============================================================================
#
# API used:
#   unsigned long long ZSTD_getFrameContentSize(const void* src, size_t srcSize);
#     Returns exact decompressed size stored in the frame header, or:
#       ZSTD_CONTENTSIZE_UNKNOWN = 0xFFFFFFFFFFFFFFFF  (size not stored)
#       ZSTD_CONTENTSIZE_ERROR   = 0xFFFFFFFFFFFFFFFE  (invalid input)
#
#   size_t ZSTD_decompress(void* dst, size_t dstCapacity,
#                          const void* src, size_t srcSize);
#     Returns bytes written on success, or an error code.
#
#   unsigned ZSTD_isError(size_t code);
#     Returns non-zero if code is an error value.
#
# Decompression safety limits (zip-bomb protection):
#   _MAX_DECOMP_RATIO = 256   (max output/input ratio)
#   _MAX_DECOMP_BYTES = 512 MB (absolute cap)
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import alloc

alias _MAX_DECOMP_RATIO: Int = 256
alias _MAX_DECOMP_BYTES: Int = 512 * 1024 * 1024

# ZSTD_CONTENTSIZE_UNKNOWN = 0ULL - 1 = max UInt64
# ZSTD_CONTENTSIZE_ERROR   = 0ULL - 2 = max UInt64 - 1
# Both are sentinel values — any valid content size will be < _MAX_DECOMP_BYTES.
alias _ZSTD_SIZE_SENTINEL: UInt64 = UInt64(18446744073709551614)  # >= this = sentinel


def zstd_decompress(data: List[UInt8]) raises -> List[UInt8]:
    """Decompress Zstandard-encoded data using libzstd.

    Uses ZSTD_getFrameContentSize for exact-size allocation when possible,
    falls back to 4× input with doubling loop when size is not in the header.
    """
    var in_size = len(data)
    if in_size == 0:
        return List[UInt8]()

    # Copy input to heap buffer
    var in_buf = alloc[UInt8](in_size)
    for i in range(in_size):
        (in_buf + i)[] = data[i]

    # Try to get exact decompressed size from frame header
    var frame_size = external_call["ZSTD_getFrameContentSize", UInt64](
        Int(in_buf), Int(in_size)
    )

    var out_capacity: Int
    var out_buf = alloc[UInt8](1)  # placeholder

    if frame_size < _ZSTD_SIZE_SENTINEL:
        # Exact size known — apply limits and allocate precisely
        var cap_limit = in_size * _MAX_DECOMP_RATIO
        if cap_limit > _MAX_DECOMP_BYTES:
            cap_limit = _MAX_DECOMP_BYTES
        var wanted = Int(frame_size)
        if wanted > cap_limit:
            in_buf.free()
            out_buf.free()
            raise Error("zstd decompression ratio limit exceeded")
        out_capacity = wanted
        out_buf.free()
        out_buf = alloc[UInt8](out_capacity)
        var written = external_call["ZSTD_decompress", Int](
            Int(out_buf), Int(out_capacity), Int(in_buf), Int(in_size)
        )
        var is_err = external_call["ZSTD_isError", UInt32](Int(written))
        in_buf.free()
        if is_err != UInt32(0):
            out_buf.free()
            raise Error("ZSTD_decompress error (exact path), code=" + String(written))
        var result = List[UInt8](capacity=written + 1)
        result.resize(written, 0)
        _ = external_call["memcpy", Int](Int(result.unsafe_ptr()), Int(out_buf), written)
        out_buf.free()
        return result^
    else:
        # Size unknown — use 4× input with doubling loop (same as brotli)
        out_buf.free()
        out_capacity = in_size * 4
        if out_capacity < 4096:
            out_capacity = 4096
        out_buf = alloc[UInt8](out_capacity)

        var written = -1
        var is_err = UInt32(1)

        while True:
            written = external_call["ZSTD_decompress", Int](
                Int(out_buf), Int(out_capacity), Int(in_buf), Int(in_size)
            )
            is_err = external_call["ZSTD_isError", UInt32](Int(written))
            if is_err == UInt32(0):
                break
            # Check if it might be a too-small output buffer.
            # Grow and retry if still within limits.
            var new_cap = out_capacity * 2
            var cap_limit = in_size * _MAX_DECOMP_RATIO
            if cap_limit > _MAX_DECOMP_BYTES:
                cap_limit = _MAX_DECOMP_BYTES
            if new_cap > cap_limit:
                in_buf.free()
                out_buf.free()
                raise Error("zstd decompression ratio limit exceeded")
            var new_buf = alloc[UInt8](new_cap)
            _ = external_call["memcpy", Int](Int(new_buf), Int(out_buf), out_capacity)
            out_buf.free()
            out_buf = new_buf
            out_capacity = new_cap

        in_buf.free()

        var result = List[UInt8](capacity=written + 1)
        result.resize(written, 0)
        _ = external_call["memcpy", Int](Int(result.unsafe_ptr()), Int(out_buf), written)
        out_buf.free()
        return result^
