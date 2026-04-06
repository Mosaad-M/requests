# ============================================================================
# test_h2.mojo — Unit tests for HTTP/2 frame layer (RFC 7540)
# ============================================================================
# No network required — pure frame encode/decode tests.
# Run: pixi run test-h2
# ============================================================================

from h2 import (
    # Frame type constants
    H2_DATA, H2_HEADERS, H2_PRIORITY, H2_RST_STREAM, H2_SETTINGS,
    H2_PUSH_PROMISE, H2_PING, H2_GOAWAY, H2_WINDOW_UPDATE, H2_CONTINUATION,
    # Flag constants
    H2_FLAG_END_STREAM, H2_FLAG_END_HEADERS, H2_FLAG_PADDED,
    H2_FLAG_PRIORITY, H2_FLAG_ACK,
    # Setting IDs
    H2_SETTING_HEADER_TABLE_SIZE, H2_SETTING_ENABLE_PUSH,
    H2_SETTING_MAX_CONCURRENT_STREAMS, H2_SETTING_INITIAL_WINDOW_SIZE,
    H2_SETTING_MAX_FRAME_SIZE, H2_SETTING_MAX_HEADER_LIST_SIZE,
    # Error codes
    H2_ERR_NO_ERROR, H2_ERR_PROTOCOL_ERROR, H2_ERR_INTERNAL_ERROR,
    H2_ERR_FLOW_CONTROL_ERROR, H2_ERR_COMPRESSION_ERROR,
    H2_ERR_HTTP_1_1_REQUIRED,
    # Frame struct + encode/decode
    Http2Frame, h2_frame_encode, h2_frame_decode,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

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
        print("  FAIL:", name, "-", e)
        failed += 1


fn assert_eq_int(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected " + String(expected) + ", got " + String(actual))


fn assert_eq_u8(actual: UInt8, expected: UInt8, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected 0x" + String(Int(expected))
            + ", got 0x" + String(Int(actual))
        )


fn _hex_digit(b: UInt8) -> UInt8:
    if b >= 48 and b <= 57:
        return b - 48
    if b >= 97 and b <= 102:
        return b - 97 + 10
    return b - 65 + 10


fn _hex_bytes(s: String) -> List[UInt8]:
    var raw = s.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    var i   = 0
    while i + 1 < len(raw):
        var hi = _hex_digit(raw[i])
        var lo = _hex_digit(raw[i + 1])
        out.append((hi << 4) | lo)
        i += 2
    return out^


fn _assert_bytes_eq(got: List[UInt8], expected: List[UInt8], label: String) raises:
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


fn _make_payload(size: Int, fill: UInt8 = 0xAB) -> List[UInt8]:
    var p = List[UInt8](capacity=size)
    for _ in range(size):
        p.append(fill)
    return p^


# ── 15C-1: Frame Header + Http2Frame ────────────────────────────────────────

def test_frame_type_constants() raises:
    """Frame type constants match RFC 7540 §6."""
    assert_eq_u8(H2_DATA,          0, "DATA")
    assert_eq_u8(H2_HEADERS,       1, "HEADERS")
    assert_eq_u8(H2_PRIORITY,      2, "PRIORITY")
    assert_eq_u8(H2_RST_STREAM,    3, "RST_STREAM")
    assert_eq_u8(H2_SETTINGS,      4, "SETTINGS")
    assert_eq_u8(H2_PUSH_PROMISE,  5, "PUSH_PROMISE")
    assert_eq_u8(H2_PING,          6, "PING")
    assert_eq_u8(H2_GOAWAY,        7, "GOAWAY")
    assert_eq_u8(H2_WINDOW_UPDATE, 8, "WINDOW_UPDATE")
    assert_eq_u8(H2_CONTINUATION,  9, "CONTINUATION")


def test_frame_flag_constants() raises:
    """Flag constants have correct bit values."""
    assert_eq_u8(H2_FLAG_END_STREAM,  0x01, "END_STREAM")
    assert_eq_u8(H2_FLAG_END_HEADERS, 0x04, "END_HEADERS")
    assert_eq_u8(H2_FLAG_PADDED,      0x08, "PADDED")
    assert_eq_u8(H2_FLAG_PRIORITY,    0x20, "PRIORITY")
    assert_eq_u8(H2_FLAG_ACK,         0x01, "ACK")


def test_frame_encode_empty_payload() raises:
    """SETTINGS ACK (no payload): 9 bytes with correct header fields."""
    var frame   = Http2Frame(H2_SETTINGS, H2_FLAG_ACK, 0, List[UInt8]())
    var encoded = h2_frame_encode(frame)
    # 00 00 00  04  01  00 00 00 00
    _assert_bytes_eq(encoded, _hex_bytes("000000040100000000"), "SETTINGS ACK")


def test_frame_encode_with_payload() raises:
    """DATA frame with 4-byte payload: 13 bytes total."""
    var payload = List[UInt8]()
    payload.append(0xDE); payload.append(0xAD); payload.append(0xBE); payload.append(0xEF)
    var frame   = Http2Frame(H2_DATA, H2_FLAG_END_STREAM, 1, payload)
    var encoded = h2_frame_encode(frame)
    assert_eq_int(len(encoded), 13, "total length")
    # length=4: bytes 0-2
    assert_eq_u8(encoded[0], 0x00, "len[0]")
    assert_eq_u8(encoded[1], 0x00, "len[1]")
    assert_eq_u8(encoded[2], 0x04, "len[2]")
    assert_eq_u8(encoded[3], 0x00, "type=DATA")
    assert_eq_u8(encoded[4], 0x01, "flags=END_STREAM")
    assert_eq_u8(encoded[5], 0x00, "sid[0]")
    assert_eq_u8(encoded[6], 0x00, "sid[1]")
    assert_eq_u8(encoded[7], 0x00, "sid[2]")
    assert_eq_u8(encoded[8], 0x01, "sid[3]=1")
    assert_eq_u8(encoded[9],  0xDE, "payload[0]")
    assert_eq_u8(encoded[10], 0xAD, "payload[1]")
    assert_eq_u8(encoded[11], 0xBE, "payload[2]")
    assert_eq_u8(encoded[12], 0xEF, "payload[3]")


def test_frame_decode_settings_ack() raises:
    """Decode a 9-byte SETTINGS ACK frame."""
    var data = _hex_bytes("000000040100000000")
    var r    = h2_frame_decode(data, 0)
    var f    = r[0].copy()
    assert_eq_u8(f.frame_type, H2_SETTINGS, "type")
    assert_eq_u8(f.flags, H2_FLAG_ACK, "flags")
    assert_eq_int(f.stream_id, 0, "stream_id")
    assert_eq_int(len(f.payload), 0, "payload length")
    assert_eq_int(r[1], 9, "new_offset")


def test_frame_decode_data() raises:
    """Decode DATA frame with payload; offset advances correctly."""
    var data = _hex_bytes("00000400010000000112345678")
    # length=4, type=DATA, flags=END_STREAM, stream_id=1, payload=12345678
    var r = h2_frame_decode(data, 0)
    var f = r[0].copy()
    assert_eq_u8(f.frame_type, H2_DATA, "type")
    assert_eq_u8(f.flags, H2_FLAG_END_STREAM, "flags")
    assert_eq_int(f.stream_id, 1, "stream_id")
    assert_eq_int(len(f.payload), 4, "payload len")
    assert_eq_u8(f.payload[0], 0x12, "p[0]")
    assert_eq_u8(f.payload[3], 0x78, "p[3]")
    assert_eq_int(r[1], 13, "new_offset")


def test_frame_decode_at_offset() raises:
    """Decode a frame starting at a non-zero offset in the buffer."""
    # Prepend 3 junk bytes, then a SETTINGS ACK
    var data = _hex_bytes("AABBCC000000040100000000")
    var r    = h2_frame_decode(data, 3)
    var f    = r[0].copy()
    assert_eq_u8(f.frame_type, H2_SETTINGS, "type")
    assert_eq_int(r[1], 12, "new_offset")


def test_frame_roundtrip_headers() raises:
    """Encode then decode HEADERS frame; all fields identical."""
    var hpack_block = _hex_bytes("828684410f7777772e6578616d706c652e636f6d")
    var frame   = Http2Frame(H2_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 3, hpack_block)
    var encoded = h2_frame_encode(frame)
    var r       = h2_frame_decode(encoded, 0)
    var decoded = r[0].copy()
    assert_eq_u8(decoded.frame_type, H2_HEADERS, "type")
    assert_eq_u8(decoded.flags, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, "flags")
    assert_eq_int(decoded.stream_id, 3, "stream_id")
    assert_eq_int(len(decoded.payload), len(hpack_block), "payload len")
    assert_eq_int(r[1], 9 + len(hpack_block), "new_offset")


def test_frame_stream_id_zero() raises:
    """Stream ID 0 encodes/decodes correctly (connection-level frames)."""
    var f = Http2Frame(H2_SETTINGS, UInt8(0), 0, List[UInt8]())
    var e = h2_frame_encode(f)
    # bytes 5-8 must all be 0x00
    assert_eq_u8(e[5], 0x00, "sid[0]")
    assert_eq_u8(e[6], 0x00, "sid[1]")
    assert_eq_u8(e[7], 0x00, "sid[2]")
    assert_eq_u8(e[8], 0x00, "sid[3]")
    var r = h2_frame_decode(e, 0)
    assert_eq_int(r[0].stream_id, 0, "decoded stream_id")


def test_frame_stream_id_large() raises:
    """Stream ID 0x1FFFFFFF (max 31-bit) encodes/decodes correctly."""
    var f = Http2Frame(H2_HEADERS, H2_FLAG_END_HEADERS, 0x1FFFFFFF, List[UInt8]())
    var e = h2_frame_encode(f)
    # bytes 5-8: 0x1F 0xFF 0xFF 0xFF
    assert_eq_u8(e[5], 0x1F, "sid[0]")
    assert_eq_u8(e[6], 0xFF, "sid[1]")
    assert_eq_u8(e[7], 0xFF, "sid[2]")
    assert_eq_u8(e[8], 0xFF, "sid[3]")
    var r = h2_frame_decode(e, 0)
    assert_eq_int(r[0].stream_id, 0x1FFFFFFF, "decoded stream_id")


def test_frame_reserved_bit_cleared_on_encode() raises:
    """Encoder always clears the reserved R bit in stream_id field."""
    # stream_id = 1 with R bit set (0x80000001) — encoder must mask it off
    var f = Http2Frame(H2_DATA, UInt8(0), 0x80000001, List[UInt8]())
    var e = h2_frame_encode(f)
    # byte 5 high bit must be 0
    if Int(e[5]) & 0x80 != 0:
        raise Error("R bit must be 0 in encoded frame")


def test_frame_reserved_bit_masked_on_decode() raises:
    """Decoder masks off the R bit so stream_id is always 0–2^31-1."""
    # Manually craft a frame with R bit set in stream_id field
    var data = List[UInt8]()
    data.append(0x00); data.append(0x00); data.append(0x00)  # length=0
    data.append(0x04)  # type=SETTINGS
    data.append(0x00)  # flags=0
    data.append(0x80)  # R=1, sid=0 → decoded stream_id should be 0
    data.append(0x00); data.append(0x00); data.append(0x00)
    var r = h2_frame_decode(data, 0)
    assert_eq_int(r[0].stream_id, 0, "R bit masked → stream_id=0")


def test_frame_decode_too_short() raises:
    """Buffer with fewer than 9 bytes raises Error."""
    var data  = _hex_bytes("00000004")  # only 4 bytes
    var raised = False
    try:
        _ = h2_frame_decode(data, 0)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for truncated header")


def test_frame_decode_truncated_payload() raises:
    """Header declares length=100 but only 9 bytes total → raises."""
    var data = List[UInt8]()
    data.append(0x00); data.append(0x00); data.append(0x64)  # length=100
    data.append(0x00); data.append(0x00)                      # type, flags
    data.append(0x00); data.append(0x00); data.append(0x00); data.append(0x01)  # stream_id=1
    # no payload bytes follow
    var raised = False
    try:
        _ = h2_frame_decode(data, 0)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for truncated payload")


def test_frame_length_24bit() raises:
    """Payload > 65535 bytes encodes the 24-bit length correctly."""
    var payload = _make_payload(70000, 0x42)
    var f       = Http2Frame(H2_DATA, UInt8(0), 1, payload)
    var e       = h2_frame_encode(f)
    assert_eq_int(len(e), 9 + 70000, "total bytes")
    # 70000 = 0x011170
    assert_eq_u8(e[0], 0x01, "len[0]")
    assert_eq_u8(e[1], 0x11, "len[1]")
    assert_eq_u8(e[2], 0x70, "len[2]")
    # Decode back and verify payload length
    var r = h2_frame_decode(e, 0)
    assert_eq_int(len(r[0].payload), 70000, "decoded payload len")


def test_frame_roundtrip_all_types() raises:
    """Encode and decode one frame of each type; type field preserved."""
    var types = List[UInt8]()
    types.append(H2_DATA);          types.append(H2_HEADERS)
    types.append(H2_PRIORITY);      types.append(H2_RST_STREAM)
    types.append(H2_SETTINGS);      types.append(H2_PUSH_PROMISE)
    types.append(H2_PING);          types.append(H2_GOAWAY)
    types.append(H2_WINDOW_UPDATE); types.append(H2_CONTINUATION)
    for i in range(len(types)):
        var t = types[i]
        var f = Http2Frame(t, UInt8(0), 0, List[UInt8]())
        var r = h2_frame_decode(h2_frame_encode(f), 0)
        if r[0].frame_type != t:
            raise Error("type " + String(Int(t)) + " roundtrip failed")


# ── main ─────────────────────────────────────────────────────────────────────

def main() raises:
    var passed = 0
    var failed = 0

    print("=== HTTP/2 Frame Layer Tests ===")
    print()
    print("── 15C-1: Frame Header + Http2Frame ──")
    run_test("frame type constants match RFC 7540 §6", passed, failed, test_frame_type_constants)
    run_test("flag constants have correct bit values", passed, failed, test_frame_flag_constants)
    run_test("SETTINGS ACK (no payload) → 9 correct bytes", passed, failed, test_frame_encode_empty_payload)
    run_test("DATA frame with 4-byte payload → 13 bytes", passed, failed, test_frame_encode_with_payload)
    run_test("decode 9-byte SETTINGS ACK", passed, failed, test_frame_decode_settings_ack)
    run_test("decode DATA frame with payload", passed, failed, test_frame_decode_data)
    run_test("decode frame at non-zero buffer offset", passed, failed, test_frame_decode_at_offset)
    run_test("encode→decode HEADERS frame: all fields identical", passed, failed, test_frame_roundtrip_headers)
    run_test("stream_id=0 encodes/decodes correctly", passed, failed, test_frame_stream_id_zero)
    run_test("stream_id=0x1FFFFFFF encodes/decodes correctly", passed, failed, test_frame_stream_id_large)
    run_test("encoder always clears R bit", passed, failed, test_frame_reserved_bit_cleared_on_encode)
    run_test("decoder masks R bit → stream_id always ≤ 2^31-1", passed, failed, test_frame_reserved_bit_masked_on_decode)
    run_test("< 9 bytes → raises Error", passed, failed, test_frame_decode_too_short)
    run_test("declared payload > available bytes → raises", passed, failed, test_frame_decode_truncated_payload)
    run_test("payload > 65535 bytes: 24-bit length correct", passed, failed, test_frame_length_24bit)
    run_test("roundtrip one frame of each type", passed, failed, test_frame_roundtrip_all_types)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
