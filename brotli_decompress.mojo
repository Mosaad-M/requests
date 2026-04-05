# ============================================================================
# brotli_decompress.mojo — Brotli decompression via libbrotlidec
# ============================================================================
#
# Uses the one-shot BrotliDecoderDecompress API:
#   BrotliDecoderResult BrotliDecoderDecompress(
#     size_t encoded_size,
#     const uint8_t* encoded_buffer,
#     size_t* decoded_size,    /* in: capacity; out: bytes written */
#     uint8_t* decoded_buffer);
#
# Return values:
#   BROTLI_DECODER_RESULT_SUCCESS       = 1
#   BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3 (buffer too small → retry 2x)
#   BROTLI_DECODER_RESULT_ERROR         = 0
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc

# Decompression safety limits (zip-bomb protection)
alias _MAX_DECOMP_RATIO: Int = 256          # max output/input ratio
alias _MAX_DECOMP_BYTES: Int = 512 * 1024 * 1024  # absolute 512 MB cap


def brotli_decompress_ptr(data_addr: Int, data_len: Int) raises -> List[UInt8]:
    """Decompress Brotli data from a raw address+length (no List copy)."""
    if data_len == 0:
        return List[UInt8]()

    var out_capacity = data_len * 8
    if out_capacity < 4096:
        out_capacity = 4096
    var out_buf = alloc[UInt8](out_capacity)
    var out_size_ptr = alloc[Int](1)

    var result = Int32(3)
    while result == Int32(3):
        out_size_ptr[] = out_capacity
        result = external_call["BrotliDecoderDecompress", Int32](
            Int(data_len),
            data_addr,
            Int(out_size_ptr),
            Int(out_buf),
        )
        if result == Int32(3):
            var new_cap = out_capacity * 2
            var cap_limit = data_len * _MAX_DECOMP_RATIO
            if cap_limit > _MAX_DECOMP_BYTES:
                cap_limit = _MAX_DECOMP_BYTES
            if new_cap > cap_limit:
                out_buf.free()
                out_size_ptr.free()
                raise Error("brotli decompression ratio limit exceeded")
            var new_buf = alloc[UInt8](new_cap)
            _ = external_call["memcpy", Int](Int(new_buf), Int(out_buf), out_capacity)
            out_buf.free()
            out_buf = new_buf
            out_capacity = new_cap

    if result != Int32(1):
        out_size_ptr.free()
        out_buf.free()
        raise Error("BrotliDecodeError: result=" + String(Int(result)))

    var written = out_size_ptr[]
    out_size_ptr.free()
    var out = List[UInt8](capacity=written + 1)
    out.resize(written, 0)
    _ = external_call["memcpy", Int](Int(out.unsafe_ptr()), Int(out_buf), written)
    out_buf.free()
    return out^


def brotli_decompress(data: List[UInt8]) raises -> List[UInt8]:
    """Decompress Brotli-encoded data using libbrotlidec (one-shot API).

    Grows the output buffer on BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT (=3).
    """
    var in_size = len(data)
    if in_size == 0:
        return List[UInt8]()

    # Copy input to heap buffer (data may be on stack or moved elsewhere)
    var in_buf = alloc[UInt8](in_size)
    for i in range(in_size):
        (in_buf + i)[] = data[i]

    # Initial output buffer: 8× input, at least 4 KB
    var out_capacity = in_size * 8
    if out_capacity < 4096:
        out_capacity = 4096
    var out_buf = alloc[UInt8](out_capacity)

    # size_t* for decoded_size (in: capacity, out: bytes written)
    var out_size_ptr = alloc[Int](1)

    var result = Int32(3)  # start as NEEDS_MORE_OUTPUT to enter loop
    while result == Int32(3):
        out_size_ptr[] = out_capacity
        result = external_call["BrotliDecoderDecompress", Int32](
            Int(in_size),
            Int(in_buf),
            Int(out_size_ptr),
            Int(out_buf),
        )
        if result == Int32(3):  # NEEDS_MORE_OUTPUT — double and retry
            var new_cap = out_capacity * 2
            var cap_limit = in_size * _MAX_DECOMP_RATIO
            if cap_limit > _MAX_DECOMP_BYTES:
                cap_limit = _MAX_DECOMP_BYTES
            if new_cap > cap_limit:
                in_buf.free()
                out_buf.free()
                out_size_ptr.free()
                raise Error("brotli decompression ratio limit exceeded")
            var new_buf = alloc[UInt8](new_cap)
            _ = external_call["memcpy", Int](Int(new_buf), Int(out_buf), out_capacity)
            out_buf.free()
            out_buf = new_buf
            out_capacity = new_cap

    in_buf.free()

    if result != Int32(1):  # not SUCCESS
        out_size_ptr.free()
        out_buf.free()
        raise Error("BrotliDecodeError: result=" + String(Int(result)))

    var written = out_size_ptr[]
    out_size_ptr.free()

    var out = List[UInt8](capacity=written + 1)
    out.resize(written, 0)
    _ = external_call["memcpy", Int](Int(out.unsafe_ptr()), Int(out_buf), written)
    out_buf.free()
    return out^
