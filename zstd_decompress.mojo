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
#
# libzstd is opened with dlopen (codecs.mojo), so programs need no -lzstd.
# ============================================================================

from std.ffi import external_call, OwnedDLHandle
from codecs import open_zstd, missing_library
from std.memory import alloc

comptime _MAX_DECOMP_RATIO: Int = 256
comptime _MAX_DECOMP_BYTES: Int = 512 * 1024 * 1024

# ZSTD_CONTENTSIZE_UNKNOWN = 0ULL - 1 = max UInt64
# ZSTD_CONTENTSIZE_ERROR   = 0ULL - 2 = max UInt64 - 1
# Both are sentinel values — any valid content size will be < _MAX_DECOMP_BYTES.
comptime _ZSTD_SIZE_SENTINEL: UInt64 = UInt64(18446744073709551614)  # >= this = sentinel


def zstd_decode(zstd: OwnedDLHandle, data_addr: Int, data_len: Int) raises -> List[UInt8]:
    """Decompress Zstandard data from a raw address+length (no List copy)
    with an opened libzstd (codecs.open_zstd)."""
    if data_len == 0:
        return List[UInt8]()

    var frame_size = zstd.call["ZSTD_getFrameContentSize", UInt64](
        data_addr, Int(data_len)
    )

    if frame_size < _ZSTD_SIZE_SENTINEL:
        var cap_limit = data_len * _MAX_DECOMP_RATIO
        if cap_limit > _MAX_DECOMP_BYTES:
            cap_limit = _MAX_DECOMP_BYTES
        var wanted = Int(frame_size)
        if wanted > cap_limit:
            raise Error("zstd decompression ratio limit exceeded")
        var out_buf = alloc[UInt8](wanted)
        var written = zstd.call["ZSTD_decompress", Int](
            Int(out_buf), Int(wanted), data_addr, Int(data_len)
        )
        var is_err = zstd.call["ZSTD_isError", UInt32](Int(written))
        if is_err != UInt32(0):
            out_buf.free()
            raise Error("ZSTD_decompress error (exact path), code=" + String(written))
        var result = List[UInt8](capacity=written + 1)
        result.resize(written, 0)
        _ = external_call["memcpy", Int](Int(result.unsafe_ptr()), Int(out_buf), written)
        out_buf.free()
        return result^
    else:
        var out_capacity = data_len * 4
        if out_capacity < 4096:
            out_capacity = 4096
        var out_buf = alloc[UInt8](out_capacity)
        var written = -1
        var is_err = UInt32(1)
        while True:
            written = zstd.call["ZSTD_decompress", Int](
                Int(out_buf), Int(out_capacity), data_addr, Int(data_len)
            )
            is_err = zstd.call["ZSTD_isError", UInt32](Int(written))
            if is_err == UInt32(0):
                break
            var new_cap = out_capacity * 2
            var cap_limit = data_len * _MAX_DECOMP_RATIO
            if cap_limit > _MAX_DECOMP_BYTES:
                cap_limit = _MAX_DECOMP_BYTES
            if new_cap > cap_limit:
                out_buf.free()
                raise Error("zstd decompression ratio limit exceeded")
            var new_buf = alloc[UInt8](new_cap)
            _ = external_call["memcpy", Int](Int(new_buf), Int(out_buf), out_capacity)
            out_buf.free()
            out_buf = new_buf
            out_capacity = new_cap
        var result = List[UInt8](capacity=written + 1)
        result.resize(written, 0)
        _ = external_call["memcpy", Int](Int(result.unsafe_ptr()), Int(out_buf), written)
        out_buf.free()
        return result^


def zstd_decompress_ptr(data_addr: Int, data_len: Int) raises -> List[UInt8]:
    """Decompress Zstandard data from a raw address+length (no List copy)."""
    if data_len == 0:
        return List[UInt8]()
    var lib = open_zstd()
    if not lib:
        raise missing_library("zstd")
    return zstd_decode(lib.value(), data_addr, data_len)


def zstd_decompress(data: List[UInt8]) raises -> List[UInt8]:
    """Decompress Zstandard-encoded data using libzstd."""
    return zstd_decompress_ptr(Int(data.unsafe_ptr()), len(data))
