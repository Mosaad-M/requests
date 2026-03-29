# ============================================================================
# zlib_decompress.mojo — gzip/deflate decompression via system zlib
# ============================================================================
#
# Uses the z_stream streaming inflate API:
#   inflateInit2_(strm, windowBits, version, stream_size) — init
#   inflate(strm, Z_NO_FLUSH)                             — decompress loop
#   inflateEnd(strm)                                      — cleanup
#
# z_stream layout on 64-bit Linux (gcc ABI, sizeof = 112):
#   [0..8)    next_in   (ptr)
#   [8..12)   avail_in  (uint32)
#   [12..16)  padding
#   [16..24)  total_in  (uint64)
#   [24..32)  next_out  (ptr)
#   [32..36)  avail_out (uint32)
#   [36..40)  padding
#   [40..48)  total_out (uint64)
#   [48..88)  msg/state/zalloc/zfree/opaque  (NULL = use malloc/free)
#   [88..112) data_type/adler/reserved
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc

alias _ZSTREAM_SIZE: Int = 112
alias _ZSTREAM_NEXT_IN: Int = 0
alias _ZSTREAM_AVAIL_IN: Int = 8
alias _ZSTREAM_NEXT_OUT: Int = 24
alias _ZSTREAM_AVAIL_OUT: Int = 32
alias _ZSTREAM_TOTAL_OUT: Int = 40

alias _Z_OK = Int32(0)
alias _Z_STREAM_END = Int32(1)
alias _Z_NO_FLUSH = Int32(0)

# ZLIB_VERSION string required by inflateInit2_ — must match the installed libz
alias _ZLIB_VERSION = "1.2.11"

# Decompression safety limits (zip-bomb protection)
alias _MAX_DECOMP_RATIO: Int = 256          # max output/input ratio
alias _MAX_DECOMP_BYTES: Int = 512 * 1024 * 1024  # absolute 512 MB cap


def zlib_decompress(data: List[UInt8], is_gzip: Bool) raises -> List[UInt8]:
    """Decompress gzip or zlib-deflate data using system zlib.

    Args:
        data:    Compressed input bytes.
        is_gzip: True for gzip (Content-Encoding: gzip),
                 False for zlib deflate (Content-Encoding: deflate).

    Returns:
        Decompressed bytes.
    """
    if len(data) == 0:
        return List[UInt8]()

    # Copy input to a heap buffer that outlives the zlib session
    var in_buf = alloc[UInt8](len(data))
    for i in range(len(data)):
        (in_buf + i)[] = data[i]

    # Allocate z_stream; zero-init so zalloc/zfree/opaque = NULL (→ malloc/free)
    var zs = alloc[UInt8](_ZSTREAM_SIZE)
    for i in range(_ZSTREAM_SIZE):
        (zs + i)[] = UInt8(0)

    # windowBits: 47 = (16+31) for gzip, 15 for zlib-deflate
    var window_bits = Int32(47) if is_gzip else Int32(15)

    # inflateInit2 is a C macro that expands to inflateInit2_(strm, wbits, ver, sz)
    var ver = String(_ZLIB_VERSION)
    var ver_ptr = ver.as_c_string_slice().unsafe_ptr()

    var init_ret = external_call["inflateInit2_", Int32](
        Int(zs), window_bits, ver_ptr, Int32(_ZSTREAM_SIZE)
    )
    if init_ret != _Z_OK:
        in_buf.free()
        zs.free()
        raise Error("inflateInit2_ returned " + String(init_ret))

    # Initialise input fields in z_stream
    (zs + _ZSTREAM_NEXT_IN).bitcast[Int]()[] = Int(in_buf)
    (zs + _ZSTREAM_AVAIL_IN).bitcast[UInt32]()[] = UInt32(len(data))

    # Output buffer: 4× input size initial capacity, grows as needed
    var out_cap = len(data) * 4
    if out_cap < 4096:
        out_cap = 4096
    var out_buf = alloc[UInt8](out_cap)
    var out_used = 0

    while True:
        # Point z_stream at unused space in out_buf
        (zs + _ZSTREAM_NEXT_OUT).bitcast[Int]()[] = Int(out_buf + out_used)
        (zs + _ZSTREAM_AVAIL_OUT).bitcast[UInt32]()[] = UInt32(out_cap - out_used)

        var ret = external_call["inflate", Int32](Int(zs), _Z_NO_FLUSH)

        # total_out = cumulative bytes written since inflateInit
        out_used = Int((zs + _ZSTREAM_TOTAL_OUT).bitcast[UInt64]()[])

        if ret == _Z_STREAM_END:
            break
        if ret != _Z_OK:
            _ = external_call["inflateEnd", Int32](Int(zs))
            out_buf.free()
            in_buf.free()
            zs.free()
            raise Error("inflate returned " + String(ret))

        # Output buffer exhausted — double capacity and retry
        if out_used >= out_cap:
            var new_cap = out_cap * 2
            var cap_limit = len(data) * _MAX_DECOMP_RATIO
            if cap_limit < _MAX_DECOMP_BYTES:
                cap_limit = _MAX_DECOMP_BYTES
            if new_cap > cap_limit:
                _ = external_call["inflateEnd", Int32](Int(zs))
                out_buf.free()
                in_buf.free()
                zs.free()
                raise Error("decompression ratio limit exceeded")
            var new_buf = alloc[UInt8](new_cap)
            _ = external_call["memcpy", Int](Int(new_buf), Int(out_buf), out_used)
            out_buf.free()
            out_buf = new_buf
            out_cap = new_cap

    _ = external_call["inflateEnd", Int32](Int(zs))
    in_buf.free()
    zs.free()

    # Materialise result as List[UInt8] using memcpy (avoids byte-by-byte loop)
    var result = List[UInt8](capacity=out_used + 1)
    result.resize(out_used, 0)
    _ = external_call["memcpy", Int](Int(result.unsafe_ptr()), Int(out_buf), out_used)
    out_buf.free()
    return result^
