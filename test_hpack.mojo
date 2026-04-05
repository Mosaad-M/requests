# ============================================================================
# test_hpack.mojo — Unit tests for HPACK (RFC 7541) codec
# ============================================================================
# No HTTP test server required — pure unit tests.
# Run: pixi run test-hpack
# ============================================================================

from hpack import (
    hpack_encode_int, hpack_decode_int,
    hpack_encode_str_literal, hpack_decode_str,
    huffman_encode, huffman_decode,
    hpack_encode_str,
    static_table_get, static_table_find,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def assert_eq_int(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected " + String(expected) + ", got " + String(actual)
        )


def assert_eq_bytes(actual: List[UInt8], expected: List[UInt8], label: String) raises:
    if len(actual) != len(expected):
        raise Error(
            label + ": length mismatch: expected "
            + String(len(expected)) + " bytes, got " + String(len(actual))
        )
    for i in range(len(expected)):
        if actual[i] != expected[i]:
            raise Error(
                label + ": byte[" + String(i) + "] expected "
                + String(Int(expected[i])) + ", got " + String(Int(actual[i]))
            )


# ── 15B-1: Integer Codec ───────────────────────────────────────────────────

def test_int_encode_small() raises:
    """Value < 2^prefix_bits - 1 fits in one byte."""
    var result = hpack_encode_int(5, 5)
    var expected = List[UInt8]()
    expected.append(UInt8(5))
    assert_eq_bytes(result, expected, "encode(5, prefix=5)")


def test_int_encode_zero() raises:
    """Zero encodes to a single zero byte."""
    var result = hpack_encode_int(0, 5)
    var expected = List[UInt8]()
    expected.append(UInt8(0))
    assert_eq_bytes(result, expected, "encode(0, prefix=5)")


def test_int_encode_sentinel_exact() raises:
    """Value == sentinel (2^prefix_bits - 1) needs continuation byte 0x00."""
    # prefix=5: sentinel = 31
    var result = hpack_encode_int(31, 5)
    var expected = List[UInt8]()
    expected.append(UInt8(31))
    expected.append(UInt8(0))
    assert_eq_bytes(result, expected, "encode(31, prefix=5)")


def test_int_encode_1337() raises:
    """RFC 7541 §C.1.1: value=1337, prefix=5 → [0x1F, 0x9A, 0x0A]."""
    var result = hpack_encode_int(1337, 5)
    var expected = List[UInt8]()
    expected.append(UInt8(0x1F))
    expected.append(UInt8(0x9A))
    expected.append(UInt8(0x0A))
    assert_eq_bytes(result, expected, "encode(1337, prefix=5)")


def test_int_encode_42_prefix8() raises:
    """RFC 7541 §C.1.3: value=42, prefix=8 → [0x2A]."""
    var result = hpack_encode_int(42, 8)
    var expected = List[UInt8]()
    expected.append(UInt8(42))
    assert_eq_bytes(result, expected, "encode(42, prefix=8)")


def test_int_decode_small() raises:
    """Decode single-byte small integer."""
    var data = List[UInt8]()
    data.append(UInt8(5))
    var res = hpack_decode_int(data, 0, 5)
    assert_eq_int(res[0], 5, "decoded value")
    assert_eq_int(res[1], 1, "new offset")


def test_int_decode_zero() raises:
    """Decode zero."""
    var data = List[UInt8]()
    data.append(UInt8(0))
    var res = hpack_decode_int(data, 0, 5)
    assert_eq_int(res[0], 0, "decoded value")
    assert_eq_int(res[1], 1, "new offset")


def test_int_decode_1337() raises:
    """RFC 7541 §C.1.1: decode [0x1F, 0x9A, 0x0A] with prefix=5 → 1337."""
    var data = List[UInt8]()
    data.append(UInt8(0x1F))
    data.append(UInt8(0x9A))
    data.append(UInt8(0x0A))
    var res = hpack_decode_int(data, 0, 5)
    assert_eq_int(res[0], 1337, "decoded value")
    assert_eq_int(res[1], 3, "new offset")


def test_int_decode_sentinel_continuation_zero() raises:
    """Value == sentinel with continuation byte 0x00 → value == sentinel."""
    var data = List[UInt8]()
    data.append(UInt8(31))
    data.append(UInt8(0))
    var res = hpack_decode_int(data, 0, 5)
    assert_eq_int(res[0], 31, "decoded value")
    assert_eq_int(res[1], 2, "new offset")


def test_int_decode_offset() raises:
    """Decode starting at non-zero offset."""
    var data = List[UInt8]()
    data.append(UInt8(0xFF))  # ignored prefix
    data.append(UInt8(42))
    var res = hpack_decode_int(data, 1, 8)
    assert_eq_int(res[0], 42, "decoded value at offset 1")
    assert_eq_int(res[1], 2, "new offset")


def test_int_roundtrip() raises:
    """Encode then decode for values 0..300 and a large value, prefix_bits 1..8."""
    var test_values = List[Int]()
    for v in range(301):
        test_values.append(v)
    test_values.append(16383)
    test_values.append(1 << 14)
    for pb in range(1, 9):
        for vi in range(len(test_values)):
            var v = test_values[vi]
            var encoded = hpack_encode_int(v, pb)
            var res = hpack_decode_int(encoded, 0, pb)
            if res[0] != v:
                raise Error(
                    "roundtrip failed: prefix=" + String(pb)
                    + " value=" + String(v)
                    + " decoded=" + String(res[0])
                )
            if res[1] != len(encoded):
                raise Error(
                    "roundtrip offset wrong: prefix=" + String(pb)
                    + " value=" + String(v)
                )


# ── 15B-2: String Codec (literal, no Huffman) ─────────────────────────────

def test_str_encode_literal_empty() raises:
    """Empty string → [0x00] (H=0, length=0)."""
    var result = hpack_encode_str_literal(String(""))
    var expected = List[UInt8]()
    expected.append(UInt8(0))
    assert_eq_bytes(result, expected, "encode_str_literal('')")


def test_str_encode_literal_custom_key() raises:
    """'custom-key' (10 bytes) → [0x0A, <10 ASCII bytes>]."""
    var result = hpack_encode_str_literal(String("custom-key"))
    var expected = List[UInt8]()
    expected.append(UInt8(10))
    var name = String("custom-key").as_bytes()
    for i in range(len(name)):
        expected.append(name[i])
    assert_eq_bytes(result, expected, "encode_str_literal('custom-key')")


def test_str_encode_literal_long() raises:
    """String of 130 bytes needs 2-byte length header (prefix overflow)."""
    var s = String("")
    for _ in range(130):
        s += String("a")
    var result = hpack_encode_str_literal(s)
    # length=130: sentinel byte (127=0x7F) + continuation byte (3)
    if len(result) != 132:
        raise Error(
            "expected 132 bytes for 130-char string, got " + String(len(result))
        )
    if result[0] != UInt8(0x7F):
        raise Error("expected sentinel 0x7F in first byte")
    if result[1] != UInt8(3):
        raise Error("expected continuation byte 3, got " + String(Int(result[1])))


def test_str_decode_literal() raises:
    """Decode a literal string from wire bytes."""
    var data = List[UInt8]()
    data.append(UInt8(10))  # H=0, length=10
    var name = String("custom-key").as_bytes()
    for i in range(len(name)):
        data.append(name[i])
    var res = hpack_decode_str(data, 0)
    if res[0] != String("custom-key"):
        raise Error("expected 'custom-key', got '" + res[0] + "'")
    assert_eq_int(res[1], 11, "new offset after decode")


def test_str_decode_empty() raises:
    """Decode empty literal string."""
    var data = List[UInt8]()
    data.append(UInt8(0))
    var res = hpack_decode_str(data, 0)
    if res[0] != String(""):
        raise Error("expected empty string, got '" + res[0] + "'")
    assert_eq_int(res[1], 1, "new offset")


def test_str_decode_at_offset() raises:
    """Decode starting at non-zero offset."""
    var data = List[UInt8]()
    data.append(UInt8(0xFF))  # skip byte
    data.append(UInt8(2))
    data.append(UInt8(ord("h")))
    data.append(UInt8(ord("i")))
    var res = hpack_decode_str(data, 1)
    if res[0] != String("hi"):
        raise Error("expected 'hi', got '" + res[0] + "'")
    assert_eq_int(res[1], 4, "new offset")


def test_str_roundtrip_literal() raises:
    """Encode then decode various strings."""
    var strings = List[String]()
    strings.append(String(""))
    strings.append(String("x"))
    strings.append(String(":method"))
    strings.append(String("custom-header-value-here"))
    for i in range(len(strings)):
        var s = strings[i]
        var encoded = hpack_encode_str_literal(s)
        var res = hpack_decode_str(encoded, 0)
        if res[0] != s:
            raise Error(
                "roundtrip failed: input='" + s + "' decoded='" + res[0] + "'"
            )
        assert_eq_int(res[1], len(encoded), "offset after roundtrip")


# ── 15B-3: Huffman Codec ──────────────────────────────────────────────────

def _bytes_from_hex(h: String) raises -> List[UInt8]:
    var raw = h.as_bytes()
    var n = len(raw) // 2
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var hi = raw[i * 2]
        var lo = raw[i * 2 + 1]
        var hv: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var lv: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((hv << 4) | lv)
    return out^


def test_huffman_encode_www() raises:
    """RFC 7541 §C.4.1: 'www.example.com' Huffman encodes to known bytes."""
    # From RFC 7541 Appendix C.4.1: value of ':authority' header
    var expected_hex = String("f1e3c2e5f23a6ba0ab90f4ff")
    var expected = _bytes_from_hex(expected_hex)
    var result = huffman_encode(String("www.example.com"))
    assert_eq_bytes(result, expected, "huffman_encode('www.example.com')")


def test_huffman_encode_no_cache() raises:
    """RFC 7541 §C.4.2: 'no-cache' Huffman encodes to known bytes."""
    # From RFC 7541 Appendix C.4.2: value of 'cache-control' header
    var expected_hex = String("a8eb10649cbf")
    var expected = _bytes_from_hex(expected_hex)
    var result = huffman_encode(String("no-cache"))
    assert_eq_bytes(result, expected, "huffman_encode('no-cache')")


def test_huffman_encode_custom_value() raises:
    """RFC 7541 §C.4.3: 'custom-value' Huffman encodes to known bytes."""
    # From RFC 7541 Appendix C.4.3: value field of custom-key:custom-value header
    var expected_hex = String("25a849e95bb8e8b4bf")
    var expected = _bytes_from_hex(expected_hex)
    var result = huffman_encode(String("custom-value"))
    assert_eq_bytes(result, expected, "huffman_encode('custom-value')")


def test_huffman_decode_www() raises:
    """Decode 'www.example.com' Huffman bytes → correct string."""
    var data = _bytes_from_hex(String("f1e3c2e5f23a6ba0ab90f4ff"))
    var result = huffman_decode(data)
    if result != String("www.example.com"):
        raise Error("expected 'www.example.com', got '" + result + "'")


def test_huffman_decode_no_cache() raises:
    """Decode 'no-cache' Huffman bytes → correct string."""
    var data = _bytes_from_hex(String("a8eb10649cbf"))
    var result = huffman_decode(data)
    if result != String("no-cache"):
        raise Error("expected 'no-cache', got '" + result + "'")


def test_huffman_roundtrip() raises:
    """Encode then decode various strings."""
    var strings = List[String]()
    strings.append(String(""))
    strings.append(String("a"))
    strings.append(String("GET"))
    strings.append(String("/index.html"))
    strings.append(String("application/json"))
    strings.append(String("no-cache"))
    strings.append(String("www.example.com"))
    for i in range(len(strings)):
        var s = strings[i]
        var encoded = huffman_encode(s)
        var decoded = huffman_decode(encoded)
        if decoded != s:
            raise Error(
                "roundtrip failed: input='" + s + "' decoded='" + decoded + "'"
            )


def test_hpack_encode_str_huffman_flag() raises:
    """hpack_encode_str with huffman=True sets H bit in first byte."""
    var result = hpack_encode_str(String("no-cache"), True)
    if (Int(result[0]) & 0x80) == 0:
        raise Error("H bit not set: first byte = " + String(Int(result[0])))


def test_hpack_encode_str_literal_no_huffman_flag() raises:
    """hpack_encode_str with huffman=False: H bit clear, same as encode_str_literal."""
    var r1 = hpack_encode_str(String("no-cache"), False)
    var r2 = hpack_encode_str_literal(String("no-cache"))
    assert_eq_bytes(r1, r2, "hpack_encode_str(huffman=False) vs encode_str_literal")


def test_hpack_decode_str_huffman() raises:
    """hpack_decode_str correctly decodes a Huffman-encoded string (H=1)."""
    # Encode 'no-cache' with H=1 using hpack_encode_str
    var wire = hpack_encode_str(String("no-cache"), True)
    var res = hpack_decode_str(wire, 0)
    if res[0] != String("no-cache"):
        raise Error("expected 'no-cache', got '" + res[0] + "'")
    assert_eq_int(res[1], len(wire), "offset after Huffman decode")


# ── 15B-3 extended: edge cases, single chars, additional RFC vectors ────────

def test_huffman_encode_empty() raises:
    """Empty string encodes to zero bytes."""
    var result = huffman_encode(String(""))
    if len(result) != 0:
        raise Error("expected 0 bytes, got " + String(len(result)))


def test_huffman_decode_empty() raises:
    """Zero bytes decode to empty string."""
    var data = List[UInt8]()
    var result = huffman_decode(data)
    if result != String(""):
        raise Error("expected empty string, got '" + result + "'")


def test_huffman_encode_single_a() raises:
    """'a' (5-bit code 00011) pads to [0x1F] = 00011|111."""
    # code 0x3, 5 bits: 00011. Pad 3 bits with 1s: 00011111 = 0x1F
    var result = huffman_encode(String("a"))
    var expected = List[UInt8]()
    expected.append(UInt8(0x1F))
    assert_eq_bytes(result, expected, "huffman_encode('a')")


def test_huffman_decode_single_a() raises:
    """[0x1F] decodes to 'a'."""
    var data = List[UInt8]()
    data.append(UInt8(0x1F))
    var result = huffman_decode(data)
    if result != String("a"):
        raise Error("expected 'a', got '" + result + "'")


def test_huffman_encode_space() raises:
    """' ' (6-bit code 010100) pads to [0x53] = 010100|11."""
    # code 0x14, 6 bits: 010100. Pad 2 bits with 1s: 01010011 = 0x53
    var result = huffman_encode(String(" "))
    var expected = List[UInt8]()
    expected.append(UInt8(0x53))
    assert_eq_bytes(result, expected, "huffman_encode(' ')")


def test_huffman_decode_space() raises:
    """[0x53] decodes to ' '."""
    var data = List[UInt8]()
    data.append(UInt8(0x53))
    var result = huffman_decode(data)
    if result != String(" "):
        raise Error("expected ' ', got '" + result + "'")


def test_huffman_encode_zero_digit() raises:
    """'0' (5-bit code 00000) pads to [0x07] = 00000|111."""
    # code 0x0, 5 bits: 00000. Pad 3 bits with 1s: 00000111 = 0x07
    var result = huffman_encode(String("0"))
    var expected = List[UInt8]()
    expected.append(UInt8(0x07))
    assert_eq_bytes(result, expected, "huffman_encode('0')")


def test_huffman_decode_zero_digit() raises:
    """[0x07] decodes to '0'."""
    var data = List[UInt8]()
    data.append(UInt8(0x07))
    var result = huffman_decode(data)
    if result != String("0"):
        raise Error("expected '0', got '" + result + "'")


def test_huffman_encode_custom_key() raises:
    """RFC 7541 §C.4.1/C.4.3: 'custom-key' Huffman encodes to known bytes."""
    # From RFC 7541 Appendix C.4.1 header block (literal name field)
    var expected = _bytes_from_hex(String("25a849e95ba97d7f"))
    var result = huffman_encode(String("custom-key"))
    assert_eq_bytes(result, expected, "huffman_encode('custom-key')")


def test_huffman_decode_custom_key() raises:
    """Decode RFC 'custom-key' bytes → 'custom-key'."""
    var data = _bytes_from_hex(String("25a849e95ba97d7f"))
    var result = huffman_decode(data)
    if result != String("custom-key"):
        raise Error("expected 'custom-key', got '" + result + "'")


def test_huffman_roundtrip_all_printable_ascii() raises:
    """Roundtrip every printable ASCII character individually (0x20-0x7E)."""
    for code in range(32, 127):
        var b = List[UInt8]()
        b.append(UInt8(code))
        var s = String(unsafe_from_utf8=b^)
        var encoded = huffman_encode(s)
        var decoded = huffman_decode(encoded)
        if decoded != s:
            raise Error(
                "roundtrip failed for char " + String(code)
                + ": got '" + decoded + "'"
            )


def test_huffman_roundtrip_http_headers() raises:
    """Roundtrip typical HTTP header names and values."""
    var headers = List[String]()
    headers.append(String("content-type"))
    headers.append(String("application/json"))
    headers.append(String("accept-encoding"))
    headers.append(String("gzip, deflate, br"))
    headers.append(String("authorization"))
    headers.append(String(":method"))
    headers.append(String("GET"))
    headers.append(String(":path"))
    headers.append(String("/api/v1/users?page=1"))
    headers.append(String("cache-control"))
    headers.append(String("max-age=0"))
    for i in range(len(headers)):
        var s = headers[i]
        var encoded = huffman_encode(s)
        var decoded = huffman_decode(encoded)
        if decoded != s:
            raise Error(
                "roundtrip failed for '" + s + "': got '" + decoded + "'"
            )


def test_huffman_compression_ratio() raises:
    """Huffman-encoded common strings are shorter than literal."""
    # "www.example.com": 15 bytes in → 12 bytes Huffman
    var r1 = huffman_encode(String("www.example.com"))
    if len(r1) >= 15:
        raise Error("no compression for 'www.example.com': " + String(len(r1)))
    # "no-cache": 8 bytes in → 6 bytes Huffman
    var r2 = huffman_encode(String("no-cache"))
    if len(r2) >= 8:
        raise Error("no compression for 'no-cache': " + String(len(r2)))


def test_huffman_decode_zero_padding_error() raises:
    """Padding must be EOS-prefix (all 1s); zero bits in padding → Error."""
    # 0x08 = 00001000: decodes sym '1' (00001), then padding 000 ≠ 111 → error
    var data = List[UInt8]()
    data.append(UInt8(0x08))
    var raised = False
    try:
        _ = huffman_decode(data)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for zero-padded byte [0x08]")


def test_huffman_decode_padding_too_long_error() raises:
    """Padding > 7 bits is a decoding error per RFC 7541 §5.2."""
    # 'a' encodes to [0x1F] (valid, 3-bit EOS padding).
    # Appending 0xFF adds 8 more 1-bits → 11 total padding bits → error.
    var data = List[UInt8]()
    data.append(UInt8(0x1F))
    data.append(UInt8(0xFF))
    var raised = False
    try:
        _ = huffman_decode(data)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for overlong padding [0x1F, 0xFF]")


def test_huffman_encode_decode_exact_byte_boundary() raises:
    """Two chars whose combined code fills bytes exactly (no padding needed)."""
    # ':' = code 0x5c, 7 bits. Two ':' = 14 bits. Pad 2 ones → 16 bits.
    # 0x5c = 1011100. Two: 1011100|1011100 pad 11 → 10111001 01110011
    var result = huffman_encode(String("::"))
    assert_eq_int(len(result), 2, "huffman_encode('::') byte count")
    var decoded = huffman_decode(result)
    if decoded != String("::"):
        raise Error("expected '::', got '" + decoded + "'")


# ── 15B-4: Static Table (RFC 7541 Appendix A) ──────────────────────────────

def assert_eq_str(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected '" + expected + "', got '" + actual + "'")


# ── get: pseudo-headers ────────────────────────────────────────────────────

def test_static_get_1() raises:
    """Entry 1: :authority, empty value."""
    var r = static_table_get(1)
    assert_eq_str(r[0], String(":authority"), "idx 1 name")
    assert_eq_str(r[1], String(""), "idx 1 value")


def test_static_get_2_method_get() raises:
    """Entry 2: :method GET."""
    var r = static_table_get(2)
    assert_eq_str(r[0], String(":method"), "idx 2 name")
    assert_eq_str(r[1], String("GET"), "idx 2 value")


def test_static_get_3_method_post() raises:
    """Entry 3: :method POST."""
    var r = static_table_get(3)
    assert_eq_str(r[0], String(":method"), "idx 3 name")
    assert_eq_str(r[1], String("POST"), "idx 3 value")


def test_static_get_4_path_root() raises:
    """Entry 4: :path /."""
    var r = static_table_get(4)
    assert_eq_str(r[0], String(":path"), "idx 4 name")
    assert_eq_str(r[1], String("/"), "idx 4 value")


def test_static_get_5_path_index() raises:
    """Entry 5: :path /index.html."""
    var r = static_table_get(5)
    assert_eq_str(r[0], String(":path"), "idx 5 name")
    assert_eq_str(r[1], String("/index.html"), "idx 5 value")


def test_static_get_6_scheme_http() raises:
    """Entry 6: :scheme http."""
    var r = static_table_get(6)
    assert_eq_str(r[0], String(":scheme"), "idx 6 name")
    assert_eq_str(r[1], String("http"), "idx 6 value")


def test_static_get_7_scheme_https() raises:
    """Entry 7: :scheme https."""
    var r = static_table_get(7)
    assert_eq_str(r[0], String(":scheme"), "idx 7 name")
    assert_eq_str(r[1], String("https"), "idx 7 value")


# ── get: :status entries ───────────────────────────────────────────────────

def test_static_get_8_status_200() raises:
    """Entry 8: :status 200."""
    var r = static_table_get(8)
    assert_eq_str(r[0], String(":status"), "idx 8 name")
    assert_eq_str(r[1], String("200"), "idx 8 value")


def test_static_get_9_status_204() raises:
    """Entry 9: :status 204."""
    var r = static_table_get(9)
    assert_eq_str(r[1], String("204"), "idx 9 value")


def test_static_get_11_status_304() raises:
    """Entry 11: :status 304."""
    var r = static_table_get(11)
    assert_eq_str(r[1], String("304"), "idx 11 value")


def test_static_get_12_status_400() raises:
    """Entry 12: :status 400."""
    var r = static_table_get(12)
    assert_eq_str(r[1], String("400"), "idx 12 value")


def test_static_get_13_status_404() raises:
    """Entry 13: :status 404."""
    var r = static_table_get(13)
    assert_eq_str(r[1], String("404"), "idx 13 value")


def test_static_get_14_status_500() raises:
    """Entry 14: :status 500."""
    var r = static_table_get(14)
    assert_eq_str(r[0], String(":status"), "idx 14 name")
    assert_eq_str(r[1], String("500"), "idx 14 value")


# ── get: mid-table header names ────────────────────────────────────────────

def test_static_get_16_accept_encoding() raises:
    """Entry 16: accept-encoding gzip, deflate (non-empty value)."""
    var r = static_table_get(16)
    assert_eq_str(r[0], String("accept-encoding"), "idx 16 name")
    assert_eq_str(r[1], String("gzip, deflate"), "idx 16 value")


def test_static_get_24_cache_control() raises:
    """Entry 24: cache-control, empty value."""
    var r = static_table_get(24)
    assert_eq_str(r[0], String("cache-control"), "idx 24 name")
    assert_eq_str(r[1], String(""), "idx 24 value")


def test_static_get_28_content_length() raises:
    """Entry 28: content-length, empty value."""
    var r = static_table_get(28)
    assert_eq_str(r[0], String("content-length"), "idx 28 name")
    assert_eq_str(r[1], String(""), "idx 28 value")


def test_static_get_31_content_type() raises:
    """Entry 31: content-type, empty value."""
    var r = static_table_get(31)
    assert_eq_str(r[0], String("content-type"), "idx 31 name")
    assert_eq_str(r[1], String(""), "idx 31 value")


def test_static_get_32_cookie() raises:
    """Entry 32: cookie, empty value."""
    var r = static_table_get(32)
    assert_eq_str(r[0], String("cookie"), "idx 32 name")


def test_static_get_38_host() raises:
    """Entry 38: host, empty value."""
    var r = static_table_get(38)
    assert_eq_str(r[0], String("host"), "idx 38 name")


# ── get: boundary entries ──────────────────────────────────────────────────

def test_static_get_61_www_authenticate() raises:
    """Entry 61 (last): www-authenticate, empty value."""
    var r = static_table_get(61)
    assert_eq_str(r[0], String("www-authenticate"), "idx 61 name")
    assert_eq_str(r[1], String(""), "idx 61 value")


def test_static_get_oob_zero() raises:
    """Index 0 is out of range → Error."""
    var raised = False
    try:
        _ = static_table_get(0)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for index 0")


def test_static_get_oob_62() raises:
    """Index 62 is out of range → Error."""
    var raised = False
    try:
        _ = static_table_get(62)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for index 62")


def test_static_get_oob_negative() raises:
    """Negative index is out of range → Error."""
    var raised = False
    try:
        _ = static_table_get(-1)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for index -1")


def test_static_get_all_names_non_empty() raises:
    """All 61 entries have non-empty header names."""
    for i in range(1, 62):
        var r = static_table_get(i)
        if len(r[0]) == 0:
            raise Error("entry " + String(i) + " has empty name")


def test_static_get_pseudo_headers_at_front() raises:
    """Entries 1-14 are pseudo-headers (:authority, :method, :path, :scheme, :status)."""
    for i in range(1, 15):
        var r = static_table_get(i)
        var name = r[0]
        if not name.startswith(":"):
            raise Error("expected pseudo-header at idx " + String(i) + ", got '" + name + "'")


# ── find: exact matches ────────────────────────────────────────────────────

def test_static_find_exact_authority() raises:
    """':authority' with empty value → exact match at index 1."""
    var r = static_table_find(String(":authority"), String(""))
    assert_eq_int(r[0], 1, "find ':authority' index")
    if not r[1]:
        raise Error("expected exact match for ':authority'")


def test_static_find_exact_method_get() raises:
    """':method GET' → exact match at index 2."""
    var r = static_table_find(String(":method"), String("GET"))
    assert_eq_int(r[0], 2, "find ':method GET' index")
    if not r[1]:
        raise Error("expected exact match for ':method GET'")


def test_static_find_exact_method_post() raises:
    """':method POST' → exact match at index 3."""
    var r = static_table_find(String(":method"), String("POST"))
    assert_eq_int(r[0], 3, "find ':method POST' index")
    if not r[1]:
        raise Error("expected exact match for ':method POST'")


def test_static_find_exact_path_root() raises:
    """':path /' → exact match at index 4."""
    var r = static_table_find(String(":path"), String("/"))
    assert_eq_int(r[0], 4, "find ':path /' index")
    if not r[1]:
        raise Error("expected exact match for ':path /'")


def test_static_find_exact_path_index() raises:
    """':path /index.html' → exact match at index 5."""
    var r = static_table_find(String(":path"), String("/index.html"))
    assert_eq_int(r[0], 5, "find ':path /index.html' index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_scheme_http() raises:
    """':scheme http' → exact match at index 6."""
    var r = static_table_find(String(":scheme"), String("http"))
    assert_eq_int(r[0], 6, "find ':scheme http' index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_scheme_https() raises:
    """':scheme https' → exact match at index 7."""
    var r = static_table_find(String(":scheme"), String("https"))
    assert_eq_int(r[0], 7, "find ':scheme https' index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_status_200() raises:
    """':status 200' → exact match at index 8."""
    var r = static_table_find(String(":status"), String("200"))
    assert_eq_int(r[0], 8, "find ':status 200' index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_status_404() raises:
    """':status 404' → exact match at index 13."""
    var r = static_table_find(String(":status"), String("404"))
    assert_eq_int(r[0], 13, "find ':status 404' index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_status_500() raises:
    """':status 500' → exact match at index 14."""
    var r = static_table_find(String(":status"), String("500"))
    assert_eq_int(r[0], 14, "find ':status 500' index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_accept_encoding() raises:
    """'accept-encoding gzip, deflate' → exact match at index 16."""
    var r = static_table_find(String("accept-encoding"), String("gzip, deflate"))
    assert_eq_int(r[0], 16, "find accept-encoding index")
    if not r[1]:
        raise Error("expected exact match")


def test_static_find_exact_content_type_empty() raises:
    """'content-type' with empty value → exact match at index 31."""
    var r = static_table_find(String("content-type"), String(""))
    assert_eq_int(r[0], 31, "find 'content-type' index")
    if not r[1]:
        raise Error("expected exact match for 'content-type' empty value")


# ── find: name-only matches (value differs) ────────────────────────────────

def test_static_find_name_only_method() raises:
    """':method DELETE' → name match at 2, no exact match."""
    var r = static_table_find(String(":method"), String("DELETE"))
    assert_eq_int(r[0], 2, "name-only ':method' → first match is idx 2")
    if r[1]:
        raise Error("expected no exact match")


def test_static_find_name_only_status() raises:
    """':status 201' → name match at 8 (first :status entry), no exact."""
    var r = static_table_find(String(":status"), String("201"))
    assert_eq_int(r[0], 8, "name-only ':status' → first match is idx 8")
    if r[1]:
        raise Error("expected no exact match")


def test_static_find_name_only_cache_control() raises:
    """'cache-control no-cache' → name match at 24, no exact."""
    var r = static_table_find(String("cache-control"), String("no-cache"))
    assert_eq_int(r[0], 24, "name-only 'cache-control' index")
    if r[1]:
        raise Error("expected no exact match")


def test_static_find_name_only_content_type() raises:
    """'content-type application/json' → name match at 31, no exact."""
    var r = static_table_find(String("content-type"), String("application/json"))
    assert_eq_int(r[0], 31, "name-only 'content-type' index")
    if r[1]:
        raise Error("expected no exact match")


def test_static_find_name_only_path() raises:
    """':path /api/v1' → name match at 4 (first :path entry), no exact."""
    var r = static_table_find(String(":path"), String("/api/v1"))
    assert_eq_int(r[0], 4, "name-only ':path' → first match is idx 4")
    if r[1]:
        raise Error("expected no exact match")


# ── find: not found ────────────────────────────────────────────────────────

def test_static_find_not_found_custom() raises:
    """'x-custom-header' is not in the static table → (0, False)."""
    var r = static_table_find(String("x-custom-header"), String("val"))
    assert_eq_int(r[0], 0, "not-found index should be 0")
    if r[1]:
        raise Error("expected no match")


def test_static_find_not_found_empty_name() raises:
    """Empty name is not in the static table → (0, False)."""
    var r = static_table_find(String(""), String(""))
    assert_eq_int(r[0], 0, "empty name not found")
    if r[1]:
        raise Error("expected no match")


def test_static_find_not_found_uppercase() raises:
    """Header names are lowercase — 'Content-Type' is not in table → (0, False)."""
    var r = static_table_find(String("Content-Type"), String(""))
    assert_eq_int(r[0], 0, "uppercase name not found")
    if r[1]:
        raise Error("expected no match for uppercase 'Content-Type'")


# ── main ───────────────────────────────────────────────────────────────────

def main() raises:
    var passed = 0
    var failed = 0

    print("=== HPACK Tests ===")
    print()
    print("── 15B-1: Integer Codec ──")
    run_test("encode(5, prefix=5) → [0x05]", passed, failed, test_int_encode_small)
    run_test("encode(0, prefix=5) → [0x00]", passed, failed, test_int_encode_zero)
    run_test("encode(31, prefix=5) → [0x1F, 0x00] (sentinel)", passed, failed, test_int_encode_sentinel_exact)
    run_test("encode(1337, prefix=5) → [0x1F, 0x9A, 0x0A] (RFC §C.1.1)", passed, failed, test_int_encode_1337)
    run_test("encode(42, prefix=8) → [0x2A] (RFC §C.1.3)", passed, failed, test_int_encode_42_prefix8)
    run_test("decode [0x05] prefix=5 → (5, 1)", passed, failed, test_int_decode_small)
    run_test("decode [0x00] prefix=5 → (0, 1)", passed, failed, test_int_decode_zero)
    run_test("decode [0x1F,0x9A,0x0A] prefix=5 → (1337, 3) (RFC §C.1.1)", passed, failed, test_int_decode_1337)
    run_test("decode sentinel+0x00 → sentinel value", passed, failed, test_int_decode_sentinel_continuation_zero)
    run_test("decode at non-zero offset", passed, failed, test_int_decode_offset)
    run_test("roundtrip: encode→decode, values 0..300 + large, prefix 1..8", passed, failed, test_int_roundtrip)

    print()
    print("── 15B-2: String Codec (literal) ──")
    run_test("encode_str_literal('') → [0x00]", passed, failed, test_str_encode_literal_empty)
    run_test("encode_str_literal('custom-key') → [0x0A, ...]", passed, failed, test_str_encode_literal_custom_key)
    run_test("encode_str_literal(130-char) → 2-byte length header", passed, failed, test_str_encode_literal_long)
    run_test("decode_str literal 'custom-key'", passed, failed, test_str_decode_literal)
    run_test("decode_str empty string", passed, failed, test_str_decode_empty)
    run_test("decode_str at non-zero offset", passed, failed, test_str_decode_at_offset)
    run_test("roundtrip: encode_str_literal → decode_str", passed, failed, test_str_roundtrip_literal)

    print()
    print("── 15B-3: Huffman Codec ──")
    run_test("huffman_encode('www.example.com') RFC §C.4.1", passed, failed, test_huffman_encode_www)
    run_test("huffman_encode('no-cache') RFC §C.4.2", passed, failed, test_huffman_encode_no_cache)
    run_test("huffman_encode('custom-value') RFC §C.4.3", passed, failed, test_huffman_encode_custom_value)
    run_test("huffman_decode('www.example.com')", passed, failed, test_huffman_decode_www)
    run_test("huffman_decode('no-cache')", passed, failed, test_huffman_decode_no_cache)
    run_test("huffman roundtrip: encode→decode various strings", passed, failed, test_huffman_roundtrip)
    run_test("hpack_encode_str(huffman=True) sets H bit", passed, failed, test_hpack_encode_str_huffman_flag)
    run_test("hpack_encode_str(huffman=False) matches encode_str_literal", passed, failed, test_hpack_encode_str_literal_no_huffman_flag)
    run_test("hpack_decode_str decodes H=1 Huffman string", passed, failed, test_hpack_decode_str_huffman)
    run_test("huffman_encode('') → []", passed, failed, test_huffman_encode_empty)
    run_test("huffman_decode([]) → ''", passed, failed, test_huffman_decode_empty)
    run_test("huffman_encode('a') → [0x1F]", passed, failed, test_huffman_encode_single_a)
    run_test("huffman_decode([0x1F]) → 'a'", passed, failed, test_huffman_decode_single_a)
    run_test("huffman_encode(' ') → [0x53]", passed, failed, test_huffman_encode_space)
    run_test("huffman_decode([0x53]) → ' '", passed, failed, test_huffman_decode_space)
    run_test("huffman_encode('0') → [0x07]", passed, failed, test_huffman_encode_zero_digit)
    run_test("huffman_decode([0x07]) → '0'", passed, failed, test_huffman_decode_zero_digit)
    run_test("huffman_encode('custom-key') RFC §C.4.1", passed, failed, test_huffman_encode_custom_key)
    run_test("huffman_decode RFC 'custom-key' bytes → 'custom-key'", passed, failed, test_huffman_decode_custom_key)
    run_test("roundtrip all printable ASCII chars (0x20-0x7E)", passed, failed, test_huffman_roundtrip_all_printable_ascii)
    run_test("roundtrip typical HTTP header names/values", passed, failed, test_huffman_roundtrip_http_headers)
    run_test("Huffman shorter than literal for common HTTP strings", passed, failed, test_huffman_compression_ratio)
    run_test("zero-padded byte raises decode error", passed, failed, test_huffman_decode_zero_padding_error)
    run_test("padding > 7 bits raises decode error", passed, failed, test_huffman_decode_padding_too_long_error)
    run_test("encode/decode '::'  at exact byte boundary", passed, failed, test_huffman_encode_decode_exact_byte_boundary)

    print()
    print("── 15B-4: Static Table ──")
    run_test("static_table_get(1) → :authority/''", passed, failed, test_static_get_1)
    run_test("static_table_get(2) → :method/GET", passed, failed, test_static_get_2_method_get)
    run_test("static_table_get(3) → :method/POST", passed, failed, test_static_get_3_method_post)
    run_test("static_table_get(4) → :path/'/", passed, failed, test_static_get_4_path_root)
    run_test("static_table_get(5) → :path//index.html", passed, failed, test_static_get_5_path_index)
    run_test("static_table_get(6) → :scheme/http", passed, failed, test_static_get_6_scheme_http)
    run_test("static_table_get(7) → :scheme/https", passed, failed, test_static_get_7_scheme_https)
    run_test("static_table_get(8) → :status/200", passed, failed, test_static_get_8_status_200)
    run_test("static_table_get(9) → :status/204", passed, failed, test_static_get_9_status_204)
    run_test("static_table_get(11) → :status/304", passed, failed, test_static_get_11_status_304)
    run_test("static_table_get(12) → :status/400", passed, failed, test_static_get_12_status_400)
    run_test("static_table_get(13) → :status/404", passed, failed, test_static_get_13_status_404)
    run_test("static_table_get(14) → :status/500", passed, failed, test_static_get_14_status_500)
    run_test("static_table_get(16) → accept-encoding/gzip, deflate", passed, failed, test_static_get_16_accept_encoding)
    run_test("static_table_get(24) → cache-control/''", passed, failed, test_static_get_24_cache_control)
    run_test("static_table_get(28) → content-length/''", passed, failed, test_static_get_28_content_length)
    run_test("static_table_get(31) → content-type/''", passed, failed, test_static_get_31_content_type)
    run_test("static_table_get(32) → cookie/''", passed, failed, test_static_get_32_cookie)
    run_test("static_table_get(38) → host/''", passed, failed, test_static_get_38_host)
    run_test("static_table_get(61) → www-authenticate/''", passed, failed, test_static_get_61_www_authenticate)
    run_test("static_table_get(0) raises OOB", passed, failed, test_static_get_oob_zero)
    run_test("static_table_get(62) raises OOB", passed, failed, test_static_get_oob_62)
    run_test("static_table_get(-1) raises OOB", passed, failed, test_static_get_oob_negative)
    run_test("all 61 entries have non-empty names", passed, failed, test_static_get_all_names_non_empty)
    run_test("entries 1–14 are pseudo-headers", passed, failed, test_static_get_pseudo_headers_at_front)
    run_test("find ':authority'/'' → exact idx=1", passed, failed, test_static_find_exact_authority)
    run_test("find ':method'/GET → exact idx=2", passed, failed, test_static_find_exact_method_get)
    run_test("find ':method'/POST → exact idx=3", passed, failed, test_static_find_exact_method_post)
    run_test("find ':path'/'/' → exact idx=4", passed, failed, test_static_find_exact_path_root)
    run_test("find ':path'//index.html → exact idx=5", passed, failed, test_static_find_exact_path_index)
    run_test("find ':scheme'/http → exact idx=6", passed, failed, test_static_find_exact_scheme_http)
    run_test("find ':scheme'/https → exact idx=7", passed, failed, test_static_find_exact_scheme_https)
    run_test("find ':status'/200 → exact idx=8", passed, failed, test_static_find_exact_status_200)
    run_test("find ':status'/404 → exact idx=13", passed, failed, test_static_find_exact_status_404)
    run_test("find ':status'/500 → exact idx=14", passed, failed, test_static_find_exact_status_500)
    run_test("find 'accept-encoding'/'gzip, deflate' → exact idx=16", passed, failed, test_static_find_exact_accept_encoding)
    run_test("find 'content-type'/'' → exact idx=31", passed, failed, test_static_find_exact_content_type_empty)
    run_test("find ':method'/DELETE → name-only idx=2", passed, failed, test_static_find_name_only_method)
    run_test("find ':status'/201 → name-only idx=8", passed, failed, test_static_find_name_only_status)
    run_test("find 'cache-control'/no-cache → name-only idx=24", passed, failed, test_static_find_name_only_cache_control)
    run_test("find 'content-type'/application/json → name-only idx=31", passed, failed, test_static_find_name_only_content_type)
    run_test("find ':path'/custom → name-only idx=4", passed, failed, test_static_find_name_only_path)
    run_test("find 'x-custom-header' → not found (0, False)", passed, failed, test_static_find_not_found_custom)
    run_test("find '' → not found (0, False)", passed, failed, test_static_find_not_found_empty_name)
    run_test("find 'Content-Type' (uppercase) → not found", passed, failed, test_static_find_not_found_uppercase)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
