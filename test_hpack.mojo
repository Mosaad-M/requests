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
    HpackDynTable,
    HpackHeader, hpack_decode_block,
    hpack_encode_block,
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


# ── 15B-5: Dynamic Table ───────────────────────────────────────────────────

def test_dyntable_default_init() raises:
    """HpackDynTable() has max_size=4096, len=0, current_size=0."""
    var t = HpackDynTable()
    if t.len() != 0:
        raise Error("expected len=0, got " + String(t.len()))
    if t.current_size != 0:
        raise Error("expected current_size=0, got " + String(t.current_size))
    if t.max_size != 4096:
        raise Error("expected max_size=4096, got " + String(t.max_size))


def test_dyntable_insert_one() raises:
    """Insert one entry: len=1, current_size = name_len + value_len + 32."""
    var t = HpackDynTable()
    t.insert("x-foo", "bar")
    if t.len() != 1:
        raise Error("expected len=1, got " + String(t.len()))
    var expected_size = len("x-foo") + len("bar") + 32
    if t.current_size != expected_size:
        raise Error("expected current_size=" + String(expected_size) + ", got " + String(t.current_size))


def test_dyntable_get_most_recent_first() raises:
    """get(1) returns most recently inserted, get(2) returns second-most-recent."""
    var t = HpackDynTable()
    t.insert("name-a", "val-a")
    t.insert("name-b", "val-b")
    var r1 = t.get(1)
    if r1[0] != "name-b" or r1[1] != "val-b":
        raise Error("expected get(1)=(name-b,val-b), got (" + r1[0] + "," + r1[1] + ")")
    var r2 = t.get(2)
    if r2[0] != "name-a" or r2[1] != "val-a":
        raise Error("expected get(2)=(name-a,val-a), got (" + r2[0] + "," + r2[1] + ")")


def test_dyntable_get_oob() raises:
    """get() with out-of-range index raises Error."""
    var t = HpackDynTable()
    t.insert("k", "v")
    var raised = False
    try:
        _ = t.get(2)
    except:
        raised = True
    if not raised:
        raise Error("expected OOB error from get(2) on single-entry table")


def test_dyntable_eviction_on_insert() raises:
    """Inserting an entry that would exceed max_size evicts oldest entries."""
    # max_size=100; entry size = 3+3+32 = 38
    # After 3 inserts: insert #3 triggers eviction of oldest; 38+38=76 ≤ 100, 2 entries remain
    var t = HpackDynTable(100)
    t.insert("key", "val")   # size=38, total=38, len=1
    t.insert("key", "val")   # size=38, total=76, len=2
    t.insert("key", "val")   # 76+38=114>100 → evict oldest → total=38, then insert → 76, len=2
    if t.len() != 2:
        raise Error("expected 2 entries after eviction, got " + String(t.len()))
    if t.current_size != 76:
        raise Error("expected current_size=76, got " + String(t.current_size))


def test_dyntable_eviction_large_entry() raises:
    """Inserting an entry larger than max_size empties the table (RFC §4.4)."""
    var t = HpackDynTable(50)
    t.insert("k", "v")   # size=34, fits
    if t.len() != 1:
        raise Error("expected 1 entry before large insert")
    # entry size = 10+10+32 = 52 > max_size=50 → table must be empty after
    t.insert("0123456789", "0123456789")
    if t.len() != 0:
        raise Error("expected table empty after oversized insert, got len=" + String(t.len()))
    if t.current_size != 0:
        raise Error("expected current_size=0, got " + String(t.current_size))


def test_dyntable_size_accounting() raises:
    """current_size tracks sum of (name + value + 32) for all entries."""
    var t = HpackDynTable()
    t.insert("a", "b")       # 1+1+32 = 34
    t.insert("ab", "cd")     # 2+2+32 = 36
    var expected = 34 + 36
    if t.current_size != expected:
        raise Error("expected current_size=" + String(expected) + ", got " + String(t.current_size))


def test_dyntable_combined_static() raises:
    """combined_get(idx) for idx 1–61 returns static table entry."""
    var t = HpackDynTable()
    var r = t.combined_get(2)
    if r[0] != ":method" or r[1] != "GET":
        raise Error("expected (:method,GET), got (" + r[0] + "," + r[1] + ")")
    var r2 = t.combined_get(61)
    if r2[0] != "www-authenticate":
        raise Error("expected www-authenticate, got " + r2[0])


def test_dyntable_combined_dynamic() raises:
    """combined_get(62) returns first dynamic entry (most recently inserted)."""
    var t = HpackDynTable()
    t.insert("x-foo", "bar")
    var r = t.combined_get(62)
    if r[0] != "x-foo" or r[1] != "bar":
        raise Error("expected (x-foo,bar), got (" + r[0] + "," + r[1] + ")")


def test_dyntable_combined_dynamic_ordering() raises:
    """After two inserts: combined_get(62) → newest, combined_get(63) → older."""
    var t = HpackDynTable()
    t.insert("first", "one")
    t.insert("second", "two")
    var r62 = t.combined_get(62)
    if r62[0] != "second" or r62[1] != "two":
        raise Error("expected combined_get(62)=(second,two), got (" + r62[0] + "," + r62[1] + ")")
    var r63 = t.combined_get(63)
    if r63[0] != "first" or r63[1] != "one":
        raise Error("expected combined_get(63)=(first,one), got (" + r63[0] + "," + r63[1] + ")")


def test_dyntable_combined_oob() raises:
    """combined_get with idx=0 or beyond dynamic table raises Error."""
    var t = HpackDynTable()
    var raised = False
    try:
        _ = t.combined_get(0)
    except:
        raised = True
    if not raised:
        raise Error("expected OOB error for combined_get(0)")
    # dynamic table empty; combined_get(62) should raise
    raised = False
    try:
        _ = t.combined_get(62)
    except:
        raised = True
    if not raised:
        raise Error("expected OOB error for combined_get(62) with empty dyn table")


def test_dyntable_update_max_size_shrink() raises:
    """update_max_size evicts entries until current_size <= new_max."""
    var t = HpackDynTable()
    t.insert("ab", "cd")   # 36
    t.insert("ab", "cd")   # 36, total=72
    t.insert("ab", "cd")   # 36, total=108
    t.update_max_size(50)
    # must evict until current_size <= 50
    # after 2 evictions: 36 ≤ 50 ✓
    if t.current_size > 50:
        raise Error("expected current_size ≤ 50 after update_max_size(50), got " + String(t.current_size))
    if t.max_size != 50:
        raise Error("expected max_size=50, got " + String(t.max_size))


def test_dyntable_update_max_size_zero() raises:
    """update_max_size(0) empties the table entirely."""
    var t = HpackDynTable()
    t.insert("k", "v")
    t.insert("k", "v")
    t.update_max_size(0)
    if t.len() != 0:
        raise Error("expected len=0 after update_max_size(0), got " + String(t.len()))
    if t.current_size != 0:
        raise Error("expected current_size=0, got " + String(t.current_size))


def test_dyntable_insert_after_size_zero() raises:
    """After update_max_size(0) then update_max_size(200), inserts work again."""
    var t = HpackDynTable()
    t.insert("x", "y")
    t.update_max_size(0)
    t.update_max_size(200)
    t.insert("a", "b")   # 1+1+32=34 ≤ 200
    if t.len() != 1:
        raise Error("expected len=1 after re-insert, got " + String(t.len()))


def test_dyntable_rfc_example_c3() raises:
    """RFC §C.3 dynamic table state after first request header block."""
    # First request adds :path /my-example and custom-key:custom-header
    # After: dyn table = [("custom-key","custom-header"), (":path","/my-example")]
    #        sizes: (10+13+32)=55, (5+11+32)=48; total=103
    var t = HpackDynTable()
    t.insert(":path", "/my-example")
    t.insert("custom-key", "custom-header")
    if t.len() != 2:
        raise Error("expected 2 entries, got " + String(t.len()))
    var expected_size = (10 + 13 + 32) + (5 + 11 + 32)
    if t.current_size != expected_size:
        raise Error("expected current_size=" + String(expected_size) + ", got " + String(t.current_size))
    # newest is custom-key (index 62), older is :path (index 63)
    var r62 = t.combined_get(62)
    if r62[0] != "custom-key" or r62[1] != "custom-header":
        raise Error("expected combined_get(62)=(custom-key,custom-header)")
    var r63 = t.combined_get(63)
    if r63[0] != ":path" or r63[1] != "/my-example":
        raise Error("expected combined_get(63)=(:path,/my-example)")


# ── 15B-6: Header Block Decode ─────────────────────────────────────────────

fn _hex_digit(b: UInt8) -> UInt8:
    if b >= 48 and b <= 57:   # '0'-'9'
        return b - 48
    if b >= 97 and b <= 102:  # 'a'-'f'
        return b - 97 + 10
    return b - 65 + 10        # 'A'-'F'


fn _hex_bytes(s: String) -> List[UInt8]:
    """Convert a lowercase hex string (no spaces) to List[UInt8]."""
    var raw = s.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    var i   = 0
    while i + 1 < len(raw):
        var hi = _hex_digit(raw[i])
        var lo = _hex_digit(raw[i + 1])
        out.append((hi << 4) | lo)
        i += 2
    return out^


def test_decode_empty_block() raises:
    """Empty data yields empty header list, dyn table unchanged."""
    var dt      = HpackDynTable()
    var data    = List[UInt8]()
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 0:
        raise Error("expected 0 headers, got " + String(len(headers)))
    if dt.len() != 0:
        raise Error("expected dyn table empty, got len=" + String(dt.len()))


def test_decode_single_indexed() raises:
    """0x82 → indexed idx=2 → (:method, GET); dyn table unchanged."""
    var dt      = HpackDynTable()
    var data    = _hex_bytes("82")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 1:
        raise Error("expected 1 header, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":method", "name")
    assert_eq_str(headers[0].value, "GET", "value")
    if dt.len() != 0:
        raise Error("indexed must not add to dyn table")


def test_decode_multiple_indexed() raises:
    """0x82 0x86 0x84 → [(:method,GET), (:scheme,http), (:path,/)]."""
    var dt      = HpackDynTable()
    var data    = _hex_bytes("828684")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 3:
        raise Error("expected 3 headers, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":method", "h0.name")
    assert_eq_str(headers[0].value, "GET", "h0.value")
    assert_eq_str(headers[1].name, ":scheme", "h1.name")
    assert_eq_str(headers[1].value, "http", "h1.value")
    assert_eq_str(headers[2].name, ":path", "h2.name")
    assert_eq_str(headers[2].value, "/", "h2.value")


def test_decode_literal_incr_indexed_name() raises:
    """0x41 = literal+incr, name_idx=1 (:authority), value 'www.example.com'; added to dyn table."""
    var dt   = HpackDynTable()
    var data = _hex_bytes("410f7777772e6578616d706c652e636f6d")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 1:
        raise Error("expected 1 header, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":authority", "name")
    assert_eq_str(headers[0].value, "www.example.com", "value")
    if dt.len() != 1:
        raise Error("expected 1 dyn entry after incr indexing, got " + String(dt.len()))
    var e = dt.get(1)
    assert_eq_str(e[0], ":authority", "dyn.name")
    assert_eq_str(e[1], "www.example.com", "dyn.value")


def test_decode_literal_incr_new_name() raises:
    """0x40 = literal+incr, new name 'custom-key', value 'custom-value'; added to dyn table."""
    # 40 0a "custom-key" 0c "custom-value"
    var data = _hex_bytes("400a637573746f6d2d6b65790c637573746f6d2d76616c7565")
    var dt      = HpackDynTable()
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 1:
        raise Error("expected 1 header, got " + String(len(headers)))
    assert_eq_str(headers[0].name, "custom-key", "name")
    assert_eq_str(headers[0].value, "custom-value", "value")
    if dt.len() != 1:
        raise Error("expected 1 dyn entry after incr indexing")


def test_decode_literal_no_index_indexed_name() raises:
    """Without-indexing (0x04=:path) + value '/': header returned, dyn table unchanged."""
    # 04 01 2f  (without-index, name_idx=4=:path, value length=1, '/')
    var data    = _hex_bytes("04012f")
    var dt      = HpackDynTable()
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 1:
        raise Error("expected 1 header, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":path", "name")
    assert_eq_str(headers[0].value, "/", "value")
    if dt.len() != 0:
        raise Error("without-indexing must NOT add to dyn table")


def test_decode_literal_never_indexed() raises:
    """Never-indexed (0x14=:path) + value '/': header returned, dyn table unchanged."""
    # 14 01 2f  (never-index, name_idx=4=:path, value length=1, '/')
    var data    = _hex_bytes("14012f")
    var dt      = HpackDynTable()
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 1:
        raise Error("expected 1 header, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":path", "name")
    assert_eq_str(headers[0].value, "/", "value")
    if dt.len() != 0:
        raise Error("never-indexed must NOT add to dyn table")


def test_decode_size_update_zero() raises:
    """0x20 = size update new_max=0: empties pre-populated dyn table."""
    var dt = HpackDynTable()
    dt.insert("k", "v")
    var data    = _hex_bytes("20")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 0:
        raise Error("size update emits no headers, got " + String(len(headers)))
    if dt.len() != 0:
        raise Error("size update(0) must empty dyn table, got len=" + String(dt.len()))
    if dt.max_size != 0:
        raise Error("expected max_size=0, got " + String(dt.max_size))


def test_decode_size_update_nonzero() raises:
    """0x3e = size update new_max=30: max_size updated, existing entries evicted if needed."""
    # 0x3e = 0b00111110 → 5-bit value = 0x1e = 30
    var dt   = HpackDynTable(4096)
    var data = _hex_bytes("3e")
    _ = hpack_decode_block(data, dt)
    if dt.max_size != 30:
        raise Error("expected max_size=30, got " + String(dt.max_size))


def test_decode_rfc_c3_req1() raises:
    """RFC §C.3.1 — first request (no Huffman); dyn table gains :authority entry."""
    # 82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
    var data    = _hex_bytes("828684410f7777772e6578616d706c652e636f6d")
    var dt      = HpackDynTable()
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 4:
        raise Error("expected 4 headers, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":method",    "h0.name");  assert_eq_str(headers[0].value, "GET",             "h0.value")
    assert_eq_str(headers[1].name, ":scheme",    "h1.name");  assert_eq_str(headers[1].value, "http",            "h1.value")
    assert_eq_str(headers[2].name, ":path",      "h2.name");  assert_eq_str(headers[2].value, "/",               "h2.value")
    assert_eq_str(headers[3].name, ":authority", "h3.name");  assert_eq_str(headers[3].value, "www.example.com", "h3.value")
    if dt.len() != 1:
        raise Error("expected 1 dyn entry, got " + String(dt.len()))
    var e = dt.get(1)
    assert_eq_str(e[0], ":authority", "dyn[1].name")
    assert_eq_str(e[1], "www.example.com", "dyn[1].value")


def test_decode_rfc_c3_req2() raises:
    """RFC §C.3.2 — second request uses dyn idx 62 (:authority); adds cache-control."""
    var dt = HpackDynTable()
    # Simulate state after request 1
    dt.insert(":authority", "www.example.com")
    # 82 86 84 be 58 08 6e 6f 2d 63 61 63 68 65
    var data    = _hex_bytes("828684be58086e6f2d6361636865")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 5:
        raise Error("expected 5 headers, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":method",      "h0.name"); assert_eq_str(headers[0].value, "GET",             "h0.value")
    assert_eq_str(headers[1].name, ":scheme",      "h1.name"); assert_eq_str(headers[1].value, "http",            "h1.value")
    assert_eq_str(headers[2].name, ":path",        "h2.name"); assert_eq_str(headers[2].value, "/",               "h2.value")
    assert_eq_str(headers[3].name, ":authority",   "h3.name"); assert_eq_str(headers[3].value, "www.example.com", "h3.value")
    assert_eq_str(headers[4].name, "cache-control","h4.name"); assert_eq_str(headers[4].value, "no-cache",        "h4.value")
    # Dyn table after: [(cache-control,no-cache), (:authority,www.example.com)]
    if dt.len() != 2:
        raise Error("expected 2 dyn entries, got " + String(dt.len()))
    var e1 = dt.get(1); assert_eq_str(e1[0], "cache-control", "dyn[1].name")
    var e2 = dt.get(2); assert_eq_str(e2[0], ":authority",    "dyn[2].name")


def test_decode_rfc_c3_req3() raises:
    """RFC §C.3.3 — third request uses dyn idx 63 (:authority); new 'custom-key' entry."""
    var dt = HpackDynTable()
    # Simulate state after request 2
    dt.insert(":authority", "www.example.com")
    dt.insert("cache-control", "no-cache")
    # 82 87 85 bf 40 0a custom-key 0c custom-value
    var data = _hex_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 5:
        raise Error("expected 5 headers, got " + String(len(headers)))
    assert_eq_str(headers[0].name, ":method",     "h0.name"); assert_eq_str(headers[0].value, "GET",             "h0.value")
    assert_eq_str(headers[1].name, ":scheme",     "h1.name"); assert_eq_str(headers[1].value, "https",           "h1.value")
    assert_eq_str(headers[2].name, ":path",       "h2.name"); assert_eq_str(headers[2].value, "/index.html",     "h2.value")
    assert_eq_str(headers[3].name, ":authority",  "h3.name"); assert_eq_str(headers[3].value, "www.example.com", "h3.value")
    assert_eq_str(headers[4].name, "custom-key",  "h4.name"); assert_eq_str(headers[4].value, "custom-value",    "h4.value")
    if dt.len() != 3:
        raise Error("expected 3 dyn entries, got " + String(dt.len()))
    assert_eq_str(dt.get(1)[0], "custom-key",   "dyn[1].name")
    assert_eq_str(dt.get(2)[0], "cache-control","dyn[2].name")
    assert_eq_str(dt.get(3)[0], ":authority",   "dyn[3].name")


def test_decode_rfc_c4_req1() raises:
    """RFC §C.4.1 — first request with Huffman strings."""
    # 82 86 84 41 8c f1e3c2e5f23a6ba0ab90f4ff
    var data    = _hex_bytes("828684418cf1e3c2e5f23a6ba0ab90f4ff")
    var dt      = HpackDynTable()
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 4:
        raise Error("expected 4 headers, got " + String(len(headers)))
    assert_eq_str(headers[3].name, ":authority", "h3.name")
    assert_eq_str(headers[3].value, "www.example.com", "h3.value")
    if dt.len() != 1:
        raise Error("expected 1 dyn entry, got " + String(dt.len()))


def test_decode_rfc_c4_req2() raises:
    """RFC §C.4.2 — second request with Huffman; uses dyn table from c4 req1."""
    var dt = HpackDynTable()
    dt.insert(":authority", "www.example.com")
    # 82 86 84 be 58 86 a8eb10649cbf
    var data    = _hex_bytes("828684be5886a8eb10649cbf")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 5:
        raise Error("expected 5 headers, got " + String(len(headers)))
    assert_eq_str(headers[4].name, "cache-control", "h4.name")
    assert_eq_str(headers[4].value, "no-cache", "h4.value")


def test_decode_rfc_c4_req3() raises:
    """RFC §C.4.3 — third request with Huffman strings for custom-key/custom-value."""
    var dt = HpackDynTable()
    dt.insert(":authority", "www.example.com")
    dt.insert("cache-control", "no-cache")
    # 82 87 85 bf 40 88 25a849e95ba97d7f 89 25a849e95bb8e8b4bf
    var data    = _hex_bytes("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")
    var headers = hpack_decode_block(data, dt)
    if len(headers) != 5:
        raise Error("expected 5 headers, got " + String(len(headers)))
    assert_eq_str(headers[4].name, "custom-key", "h4.name")
    assert_eq_str(headers[4].value, "custom-value", "h4.value")


# ── 15B-7: Header Block Encode ─────────────────────────────────────────────

fn _assert_bytes_eq(got: List[UInt8], expected: List[UInt8], label: String) raises:
    """Fail with a descriptive message if byte sequences differ."""
    if len(got) != len(expected):
        raise Error(
            label + ": length mismatch — expected "
            + String(len(expected)) + " bytes, got " + String(len(got))
        )
    for i in range(len(got)):
        if got[i] != expected[i]:
            raise Error(
                label + ": byte[" + String(i) + "] expected 0x"
                + String(Int(expected[i])) + " got 0x" + String(Int(got[i]))
            )


def test_encode_empty_headers() raises:
    """Empty header list encodes to empty byte sequence."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    var out     = hpack_encode_block(headers, dt)
    if len(out) != 0:
        raise Error("expected 0 bytes, got " + String(len(out)))


def test_encode_indexed_exact_static() raises:
    """(:method,GET) has static exact match at idx=2 → single byte 0x82."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":method", "GET"))
    var out = hpack_encode_block(headers, dt)
    _assert_bytes_eq(out, _hex_bytes("82"), "encode(:method,GET)")
    if dt.len() != 0:
        raise Error("indexed must not add to dyn table")


def test_encode_multiple_indexed_static() raises:
    """(:method,GET) (:scheme,http) (:path,/) → [0x82, 0x86, 0x84]."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":method", "GET"))
    headers.append(HpackHeader(":scheme", "http"))
    headers.append(HpackHeader(":path", "/"))
    var out = hpack_encode_block(headers, dt)
    _assert_bytes_eq(out, _hex_bytes("828684"), "3 indexed headers")


def test_encode_literal_incr_static_name_only() raises:
    """(:authority,www.example.com): static idx=1 name-only → [0x41, 0x0f, ...15 bytes...]."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":authority", "www.example.com"))
    var out = hpack_encode_block(headers, dt)
    # 0x41 = literal+incr name_idx=1, 0x0f = length 15
    _assert_bytes_eq(out, _hex_bytes("410f7777772e6578616d706c652e636f6d"), "authority")
    if dt.len() != 1:
        raise Error("literal+incr must add to dyn table")


def test_encode_literal_incr_new_name() raises:
    """(x-custom,foo): no static/dyn match → 0x40 + name_str + value_str."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader("x-custom", "foo"))
    var out = hpack_encode_block(headers, dt)
    # 40 08 "x-custom" 03 "foo"
    # 40 08 78 2d 63 75 73 74 6f 6d 03 66 6f 6f
    _assert_bytes_eq(out, _hex_bytes("4008782d637573746f6d03666f6f"), "new-name")


def test_encode_dynamic_reuse() raises:
    """After inserting (custom-key,custom-value) in req1, req2 encodes it as indexed (0xbe)."""
    var dt = HpackDynTable()
    # First request: encodes literal → adds to dyn table at idx 62
    var h1 = List[HpackHeader]()
    h1.append(HpackHeader("custom-key", "custom-value"))
    _ = hpack_encode_block(h1, dt)
    if dt.len() != 1:
        raise Error("expected 1 dyn entry after req1")
    # Second request: same header → should now be indexed at combined_idx=62 → 0xbe
    var h2 = List[HpackHeader]()
    h2.append(HpackHeader("custom-key", "custom-value"))
    var out = hpack_encode_block(h2, dt)
    _assert_bytes_eq(out, _hex_bytes("be"), "indexed dyn entry")


def test_encode_huffman_flag() raises:
    """use_huffman=True sets H bit in string length byte for literal strings."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":authority", "www.example.com"))
    var out = hpack_encode_block(headers, dt, True)
    # 0x41 = literal+incr name_idx=1, then 0x8c = H=1 len=12, then 12 Huffman bytes
    _assert_bytes_eq(out, _hex_bytes("418cf1e3c2e5f23a6ba0ab90f4ff"), "huffman authority")


def test_encode_decode_roundtrip() raises:
    """Encode a 4-header block then decode it: output matches input."""
    var dt_enc  = HpackDynTable()
    var dt_dec  = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":method", "POST"))
    headers.append(HpackHeader(":path", "/submit"))
    headers.append(HpackHeader("content-type", "application/json"))
    headers.append(HpackHeader("x-request-id", "abc123"))
    var encoded = hpack_encode_block(headers, dt_enc)
    var decoded = hpack_decode_block(encoded, dt_dec)
    if len(decoded) != 4:
        raise Error("expected 4 decoded headers, got " + String(len(decoded)))
    assert_eq_str(decoded[0].name, ":method", "h0.name")
    assert_eq_str(decoded[0].value, "POST", "h0.value")
    assert_eq_str(decoded[1].name, ":path", "h1.name")
    assert_eq_str(decoded[1].value, "/submit", "h1.value")
    assert_eq_str(decoded[2].name, "content-type", "h2.name")
    assert_eq_str(decoded[2].value, "application/json", "h2.value")
    assert_eq_str(decoded[3].name, "x-request-id", "h3.name")
    assert_eq_str(decoded[3].value, "abc123", "h3.value")


def test_encode_rfc_c3_req1() raises:
    """RFC §C.3.1 — encode first request; byte-for-byte match."""
    var dt      = HpackDynTable()
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":method", "GET"))
    headers.append(HpackHeader(":scheme", "http"))
    headers.append(HpackHeader(":path", "/"))
    headers.append(HpackHeader(":authority", "www.example.com"))
    var out = hpack_encode_block(headers, dt)
    _assert_bytes_eq(out, _hex_bytes("828684410f7777772e6578616d706c652e636f6d"), "RFC §C.3.1")


def test_encode_rfc_c3_sequential() raises:
    """RFC §C.3 — encode all three requests with shared dyn table; all match spec byte-for-byte."""
    var dt = HpackDynTable()

    var h1 = List[HpackHeader]()
    h1.append(HpackHeader(":method",    "GET"));       h1.append(HpackHeader(":scheme", "http"))
    h1.append(HpackHeader(":path",      "/"));         h1.append(HpackHeader(":authority", "www.example.com"))
    _assert_bytes_eq(
        hpack_encode_block(h1, dt),
        _hex_bytes("828684410f7777772e6578616d706c652e636f6d"),
        "RFC §C.3 req1",
    )

    var h2 = List[HpackHeader]()
    h2.append(HpackHeader(":method",       "GET"));    h2.append(HpackHeader(":scheme", "http"))
    h2.append(HpackHeader(":path",         "/"));      h2.append(HpackHeader(":authority", "www.example.com"))
    h2.append(HpackHeader("cache-control", "no-cache"))
    _assert_bytes_eq(
        hpack_encode_block(h2, dt),
        _hex_bytes("828684be58086e6f2d6361636865"),
        "RFC §C.3 req2",
    )

    var h3 = List[HpackHeader]()
    h3.append(HpackHeader(":method",   "GET"));        h3.append(HpackHeader(":scheme", "https"))
    h3.append(HpackHeader(":path",     "/index.html")); h3.append(HpackHeader(":authority", "www.example.com"))
    h3.append(HpackHeader("custom-key", "custom-value"))
    _assert_bytes_eq(
        hpack_encode_block(h3, dt),
        _hex_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"),
        "RFC §C.3 req3",
    )


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
    print("── 15B-5: Dynamic Table ──")
    run_test("HpackDynTable() default: max_size=4096, len=0", passed, failed, test_dyntable_default_init)
    run_test("insert one entry: len=1, correct current_size", passed, failed, test_dyntable_insert_one)
    run_test("get(1)=newest, get(2)=second-newest", passed, failed, test_dyntable_get_most_recent_first)
    run_test("get() OOB raises Error", passed, failed, test_dyntable_get_oob)
    run_test("eviction on insert when max_size exceeded", passed, failed, test_dyntable_eviction_on_insert)
    run_test("oversized entry empties table (RFC §4.4)", passed, failed, test_dyntable_eviction_large_entry)
    run_test("current_size tracks name + value + 32 per entry", passed, failed, test_dyntable_size_accounting)
    run_test("combined_get(1–61) returns static table entry", passed, failed, test_dyntable_combined_static)
    run_test("combined_get(62) returns first dynamic entry", passed, failed, test_dyntable_combined_dynamic)
    run_test("combined_get ordering: 62=newest, 63=older", passed, failed, test_dyntable_combined_dynamic_ordering)
    run_test("combined_get(0) and beyond dyn table raise Error", passed, failed, test_dyntable_combined_oob)
    run_test("update_max_size evicts until current_size ≤ new_max", passed, failed, test_dyntable_update_max_size_shrink)
    run_test("update_max_size(0) clears table entirely", passed, failed, test_dyntable_update_max_size_zero)
    run_test("insert works after update_max_size(0) then re-expand", passed, failed, test_dyntable_insert_after_size_zero)
    run_test("RFC §C.3 dynamic table state matches spec", passed, failed, test_dyntable_rfc_example_c3)

    print()
    print("── 15B-6: Header Block Decode ──")
    run_test("empty block → 0 headers", passed, failed, test_decode_empty_block)
    run_test("0x82 indexed → (:method,GET), no dyn change", passed, failed, test_decode_single_indexed)
    run_test("0x82 0x86 0x84 → 3 indexed headers", passed, failed, test_decode_multiple_indexed)
    run_test("literal+incr indexed-name → added to dyn table", passed, failed, test_decode_literal_incr_indexed_name)
    run_test("literal+incr new-name → added to dyn table", passed, failed, test_decode_literal_incr_new_name)
    run_test("literal-no-index → header returned, dyn unchanged", passed, failed, test_decode_literal_no_index_indexed_name)
    run_test("literal-never-indexed → header returned, dyn unchanged", passed, failed, test_decode_literal_never_indexed)
    run_test("size update 0x20 → empties dyn table", passed, failed, test_decode_size_update_zero)
    run_test("size update 0x3e → max_size=30", passed, failed, test_decode_size_update_nonzero)
    run_test("RFC §C.3.1 — request 1 (no Huffman)", passed, failed, test_decode_rfc_c3_req1)
    run_test("RFC §C.3.2 — request 2 uses dyn idx 62", passed, failed, test_decode_rfc_c3_req2)
    run_test("RFC §C.3.3 — request 3 uses dyn idx 63", passed, failed, test_decode_rfc_c3_req3)
    run_test("RFC §C.4.1 — request 1 Huffman strings", passed, failed, test_decode_rfc_c4_req1)
    run_test("RFC §C.4.2 — request 2 Huffman strings", passed, failed, test_decode_rfc_c4_req2)
    run_test("RFC §C.4.3 — request 3 Huffman strings", passed, failed, test_decode_rfc_c4_req3)

    print()
    print("── 15B-7: Header Block Encode ──")
    run_test("empty headers → []", passed, failed, test_encode_empty_headers)
    run_test("(:method,GET) → [0x82] indexed static exact", passed, failed, test_encode_indexed_exact_static)
    run_test(":method :scheme :path → [82 86 84]", passed, failed, test_encode_multiple_indexed_static)
    run_test(":authority/www.example.com → literal+incr static name [41 0f ...]", passed, failed, test_encode_literal_incr_static_name_only)
    run_test("(x-custom,foo) → literal+incr new name [40 08 ...]", passed, failed, test_encode_literal_incr_new_name)
    run_test("second occurrence reuses dyn table index → [0xbe]", passed, failed, test_encode_dynamic_reuse)
    run_test("use_huffman=True sets H bit in value length byte", passed, failed, test_encode_huffman_flag)
    run_test("encode→decode roundtrip: 4-header block identical", passed, failed, test_encode_decode_roundtrip)
    run_test("RFC §C.3.1 first request byte-for-byte", passed, failed, test_encode_rfc_c3_req1)
    run_test("RFC §C.3 three requests sequential — byte-for-byte", passed, failed, test_encode_rfc_c3_sequential)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
