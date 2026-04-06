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
    H2_ERR_FLOW_CONTROL_ERROR, H2_ERR_SETTINGS_TIMEOUT,
    H2_ERR_STREAM_CLOSED, H2_ERR_FRAME_SIZE_ERROR,
    H2_ERR_REFUSED_STREAM, H2_ERR_CANCEL,
    H2_ERR_COMPRESSION_ERROR, H2_ERR_CONNECT_ERROR,
    H2_ERR_ENHANCE_YOUR_CALM, H2_ERR_INADEQUATE_SECURITY,
    H2_ERR_HTTP_1_1_REQUIRED,
    # Frame struct + encode/decode
    Http2Frame, h2_frame_encode, h2_frame_decode,
    # SETTINGS + PING
    h2_settings_encode, h2_settings_decode,
    h2_make_settings_frame, h2_make_settings_ack,
    h2_make_ping_frame, h2_parse_ping_payload,
    # HEADERS, CONTINUATION, DATA
    h2_make_headers_frame, h2_make_continuation_frame, h2_make_data_frame,
    h2_get_hpack_block,
    h2_encode_request_headers, h2_encode_response_headers,
    # RST_STREAM, WINDOW_UPDATE, GOAWAY, PRIORITY
    h2_make_rst_stream, h2_parse_rst_stream,
    h2_make_window_update, h2_parse_window_update,
    h2_make_goaway, h2_parse_goaway,
    h2_make_priority_frame, h2_parse_priority_frame,
    # Connection preface + multi-frame stream
    h2_client_preface_bytes, h2_read_frames, h2_write_frames,
    h2_make_initial_settings,
)
from hpack import HpackHeader, HpackDynTable, hpack_decode_block


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


# ── 15C-2: SETTINGS + PING Tests ─────────────────────────────────────────────

def test_settings_encode_empty() raises:
    """h2_settings_encode with no pairs → empty payload."""
    var ids  = List[Int]()
    var vals = List[Int]()
    var p = h2_settings_encode(ids, vals)
    assert_eq_int(len(p), 0, "empty payload len")


def test_settings_encode_one() raises:
    """Single pair HEADER_TABLE_SIZE=4096 → 6 bytes."""
    var ids  = List[Int](); ids.append(H2_SETTING_HEADER_TABLE_SIZE)
    var vals = List[Int](); vals.append(4096)
    var p = h2_settings_encode(ids, vals)
    assert_eq_int(len(p), 6, "payload len")
    # id = 0x0001 big-endian
    assert_eq_u8(p[0], 0x00, "id hi")
    assert_eq_u8(p[1], 0x01, "id lo")
    # value = 0x00001000 big-endian
    assert_eq_u8(p[2], 0x00, "val[0]")
    assert_eq_u8(p[3], 0x00, "val[1]")
    assert_eq_u8(p[4], 0x10, "val[2]")
    assert_eq_u8(p[5], 0x00, "val[3]")


def test_settings_encode_multiple() raises:
    """Three pairs → 18 bytes."""
    var ids  = List[Int]()
    var vals = List[Int]()
    ids.append(H2_SETTING_HEADER_TABLE_SIZE);      vals.append(4096)
    ids.append(H2_SETTING_INITIAL_WINDOW_SIZE);    vals.append(65535)
    ids.append(H2_SETTING_MAX_FRAME_SIZE);         vals.append(16384)
    var p = h2_settings_encode(ids, vals)
    assert_eq_int(len(p), 18, "payload len")


def test_settings_decode_empty() raises:
    """Empty payload → ([], [])."""
    var p    = List[UInt8]()
    var r    = h2_settings_decode(p)
    assert_eq_int(len(r[0]), 0, "ids len")
    assert_eq_int(len(r[1]), 0, "vals len")


def test_settings_decode_one() raises:
    """6-byte payload → single (id, val) pair."""
    var p = List[UInt8]()
    p.append(0x00); p.append(0x04)  # id = INITIAL_WINDOW_SIZE
    p.append(0x00); p.append(0x00); p.append(0xFF); p.append(0xFF)  # val = 65535
    var r = h2_settings_decode(p)
    assert_eq_int(len(r[0]), 1, "ids len")
    assert_eq_int(r[0][0], H2_SETTING_INITIAL_WINDOW_SIZE, "id")
    assert_eq_int(r[1][0], 65535, "val")


def test_settings_roundtrip() raises:
    """Encode then decode; identical pairs."""
    var ids  = List[Int]()
    var vals = List[Int]()
    ids.append(H2_SETTING_HEADER_TABLE_SIZE);      vals.append(8192)
    ids.append(H2_SETTING_MAX_CONCURRENT_STREAMS); vals.append(100)
    ids.append(H2_SETTING_MAX_FRAME_SIZE);         vals.append(32768)
    var p  = h2_settings_encode(ids, vals)
    var r  = h2_settings_decode(p)
    assert_eq_int(len(r[0]), 3, "ids len")
    for i in range(3):
        assert_eq_int(r[0][i], ids[i], "id " + String(i))
        assert_eq_int(r[1][i], vals[i], "val " + String(i))


def test_settings_decode_bad_length() raises:
    """Payload not multiple of 6 → raises."""
    var p = List[UInt8]()
    p.append(0x00); p.append(0x01); p.append(0x00); p.append(0x00)
    p.append(0x10); p.append(0x00); p.append(0xFF)  # 7 bytes
    var raised = False
    try:
        _ = h2_settings_decode(p)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for 7-byte SETTINGS payload")


def test_make_settings_frame() raises:
    """h2_make_settings_frame: type=SETTINGS, stream_id=0, flags=0."""
    var ids  = List[Int](); ids.append(H2_SETTING_ENABLE_PUSH)
    var vals = List[Int](); vals.append(0)
    var f = h2_make_settings_frame(ids, vals)
    assert_eq_u8(f.frame_type, H2_SETTINGS, "type")
    assert_eq_u8(f.flags, UInt8(0), "flags")
    assert_eq_int(f.stream_id, 0, "stream_id")
    assert_eq_int(len(f.payload), 6, "payload len")


def test_make_settings_ack() raises:
    """h2_make_settings_ack: type=SETTINGS, flags=ACK, empty payload."""
    var f = h2_make_settings_ack()
    assert_eq_u8(f.frame_type, H2_SETTINGS, "type")
    assert_eq_u8(f.flags, H2_FLAG_ACK, "flags")
    assert_eq_int(f.stream_id, 0, "stream_id")
    assert_eq_int(len(f.payload), 0, "payload len")


def test_make_ping() raises:
    """PING frame with ack=False: 8-byte opaque, ACK flag clear."""
    var opaque = List[UInt8]()
    for i in range(8):
        opaque.append(UInt8(i + 1))
    var f = h2_make_ping_frame(opaque, False)
    assert_eq_u8(f.frame_type, H2_PING, "type")
    assert_eq_u8(f.flags, UInt8(0), "flags (no ack)")
    assert_eq_int(f.stream_id, 0, "stream_id")
    assert_eq_int(len(f.payload), 8, "payload len")
    assert_eq_u8(f.payload[0], 0x01, "p[0]")
    assert_eq_u8(f.payload[7], 0x08, "p[7]")


def test_make_ping_ack() raises:
    """PING frame with ack=True: ACK flag set."""
    var opaque = List[UInt8]()
    for i in range(8):
        opaque.append(UInt8(0xAA))
    var f = h2_make_ping_frame(opaque, True)
    assert_eq_u8(f.flags, H2_FLAG_ACK, "ACK flag set")


def test_make_ping_bad_length() raises:
    """PING opaque_data != 8 bytes → raises."""
    var opaque = List[UInt8]()
    opaque.append(0x01); opaque.append(0x02)  # only 2 bytes
    var raised = False
    try:
        _ = h2_make_ping_frame(opaque, False)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for non-8-byte PING payload")


def test_parse_ping_payload() raises:
    """h2_parse_ping_payload returns the 8 opaque bytes."""
    var opaque = List[UInt8]()
    for i in range(8):
        opaque.append(UInt8(0x10 + i))
    var f  = h2_make_ping_frame(opaque, False)
    var p  = h2_parse_ping_payload(f)
    assert_eq_int(len(p), 8, "len")
    for i in range(8):
        assert_eq_u8(p[i], UInt8(0x10 + i), "p[" + String(i) + "]")


# ── 15C-3: HEADERS, CONTINUATION, DATA Tests ─────────────────────────────────

def test_make_headers_frame_end_headers() raises:
    """HEADERS frame with END_HEADERS set, stream_id=1."""
    var block = _hex_bytes("828684410f7777772e6578616d706c652e636f6d")
    var f = h2_make_headers_frame(1, block, False, True)
    assert_eq_u8(f.frame_type, H2_HEADERS, "type")
    assert_eq_int(f.stream_id, 1, "stream_id")
    if Int(f.flags) & Int(H2_FLAG_END_HEADERS) == 0:
        raise Error("END_HEADERS flag must be set")
    if Int(f.flags) & Int(H2_FLAG_END_STREAM) != 0:
        raise Error("END_STREAM must be clear")
    assert_eq_int(len(f.payload), len(block), "payload len")


def test_make_headers_frame_end_stream() raises:
    """HEADERS frame with both END_STREAM and END_HEADERS."""
    var block = List[UInt8]()
    block.append(0x82)  # :method: GET
    var f = h2_make_headers_frame(3, block, True, True)
    if Int(f.flags) & Int(H2_FLAG_END_STREAM) == 0:
        raise Error("END_STREAM must be set")
    if Int(f.flags) & Int(H2_FLAG_END_HEADERS) == 0:
        raise Error("END_HEADERS must be set")


def test_make_continuation_frame() raises:
    """CONTINUATION frame: END_HEADERS flag matches argument."""
    var block = List[UInt8](); block.append(0x84)
    var f_end = h2_make_continuation_frame(5, block, True)
    assert_eq_u8(f_end.frame_type, H2_CONTINUATION, "type end")
    if Int(f_end.flags) & Int(H2_FLAG_END_HEADERS) == 0:
        raise Error("END_HEADERS must be set")
    var f_cont = h2_make_continuation_frame(5, block, False)
    if Int(f_cont.flags) & Int(H2_FLAG_END_HEADERS) != 0:
        raise Error("END_HEADERS must be clear")


def test_make_data_frame_no_end() raises:
    """DATA frame without END_STREAM."""
    var data = _hex_bytes("48656c6c6f")  # "Hello"
    var f = h2_make_data_frame(1, data, False)
    assert_eq_u8(f.frame_type, H2_DATA, "type")
    assert_eq_int(f.stream_id, 1, "stream_id")
    if Int(f.flags) & Int(H2_FLAG_END_STREAM) != 0:
        raise Error("END_STREAM must be clear")
    assert_eq_int(len(f.payload), 5, "payload len")


def test_make_data_frame_end_stream() raises:
    """DATA frame with END_STREAM set."""
    var data = List[UInt8](); data.append(0x42)
    var f = h2_make_data_frame(7, data, True)
    if Int(f.flags) & Int(H2_FLAG_END_STREAM) == 0:
        raise Error("END_STREAM must be set")


def test_data_frame_empty_payload() raises:
    """Empty DATA frame is valid."""
    var f = h2_make_data_frame(1, List[UInt8](), True)
    assert_eq_int(len(f.payload), 0, "payload len")
    assert_eq_u8(f.frame_type, H2_DATA, "type")


def test_get_hpack_block_no_priority() raises:
    """No PRIORITY flag → entire payload is the HPACK block."""
    var block = _hex_bytes("828684")
    var f = h2_make_headers_frame(1, block, False, True)
    var b = h2_get_hpack_block(f)
    assert_eq_int(len(b), 3, "block len")
    assert_eq_u8(b[0], 0x82, "b[0]")


def test_get_hpack_block_with_priority() raises:
    """PRIORITY flag set → skip 5-byte priority prefix."""
    # Build a HEADERS frame manually with PRIORITY flag and 5 priority bytes
    var priority_prefix = List[UInt8]()
    priority_prefix.append(0x00); priority_prefix.append(0x00)
    priority_prefix.append(0x00); priority_prefix.append(0x00)
    priority_prefix.append(0x0F)  # weight-1 = 15 → weight = 16
    var block = _hex_bytes("8286")
    var payload = List[UInt8]()
    for i in range(len(priority_prefix)):
        payload.append(priority_prefix[i])
    for i in range(len(block)):
        payload.append(block[i])
    var flags = H2_FLAG_END_HEADERS | H2_FLAG_PRIORITY
    var f = Http2Frame(H2_HEADERS, flags, 1, payload)
    var b = h2_get_hpack_block(f)
    assert_eq_int(len(b), 2, "block len (priority bytes skipped)")
    assert_eq_u8(b[0], 0x82, "b[0]")
    assert_eq_u8(b[1], 0x86, "b[1]")


def test_encode_request_headers_basic() raises:
    """GET / HTTP/2 → HPACK block decodes to 4 pseudo-headers."""
    var dyn = HpackDynTable(4096)
    var extra = List[HpackHeader]()
    var block = h2_encode_request_headers("GET", "/", "https", "example.com", dyn, extra, False)
    var dyn2 = HpackDynTable(4096)
    var headers = hpack_decode_block(block, dyn2)
    # Must have :method, :path, :scheme, :authority
    var found_method = False
    var found_path   = False
    var found_scheme = False
    var found_auth   = False
    for i in range(len(headers)):
        if headers[i].name == ":method" and headers[i].value == "GET":
            found_method = True
        if headers[i].name == ":path" and headers[i].value == "/":
            found_path = True
        if headers[i].name == ":scheme" and headers[i].value == "https":
            found_scheme = True
        if headers[i].name == ":authority" and headers[i].value == "example.com":
            found_auth = True
    if not found_method:
        raise Error(":method: GET not found")
    if not found_path:
        raise Error(":path: / not found")
    if not found_scheme:
        raise Error(":scheme: https not found")
    if not found_auth:
        raise Error(":authority: example.com not found")


def test_encode_request_headers_extra() raises:
    """Extra headers are included after pseudo-headers."""
    var dyn = HpackDynTable(4096)
    var extra = List[HpackHeader]()
    extra.append(HpackHeader("accept", "application/json"))
    extra.append(HpackHeader("x-custom", "value"))
    var block = h2_encode_request_headers("POST", "/api", "https", "api.example.com", dyn, extra, False)
    var dyn2 = HpackDynTable(4096)
    var headers = hpack_decode_block(block, dyn2)
    var found_accept = False
    var found_custom = False
    for i in range(len(headers)):
        if headers[i].name == "accept" and headers[i].value == "application/json":
            found_accept = True
        if headers[i].name == "x-custom" and headers[i].value == "value":
            found_custom = True
    if not found_accept:
        raise Error("accept header not found")
    if not found_custom:
        raise Error("x-custom header not found")


def test_encode_response_headers_200() raises:
    """:status=200 in response headers."""
    var dyn = HpackDynTable(4096)
    var extra = List[HpackHeader]()
    var block = h2_encode_response_headers(200, dyn, extra, False)
    var dyn2 = HpackDynTable(4096)
    var headers = hpack_decode_block(block, dyn2)
    var found = False
    for i in range(len(headers)):
        if headers[i].name == ":status" and headers[i].value == "200":
            found = True
    if not found:
        raise Error(":status: 200 not found")


def test_encode_response_headers_404() raises:
    """:status=404 in response headers."""
    var dyn = HpackDynTable(4096)
    var extra = List[HpackHeader]()
    extra.append(HpackHeader("content-length", "0"))
    var block = h2_encode_response_headers(404, dyn, extra, False)
    var dyn2 = HpackDynTable(4096)
    var headers = hpack_decode_block(block, dyn2)
    var found_status = False
    var found_len    = False
    for i in range(len(headers)):
        if headers[i].name == ":status" and headers[i].value == "404":
            found_status = True
        if headers[i].name == "content-length" and headers[i].value == "0":
            found_len = True
    if not found_status:
        raise Error(":status: 404 not found")
    if not found_len:
        raise Error("content-length not found")


def test_headers_roundtrip() raises:
    """encode_request_headers → h2_make_headers_frame → get_hpack_block → decode."""
    var dyn_enc = HpackDynTable(4096)
    var extra   = List[HpackHeader]()
    var block   = h2_encode_request_headers("GET", "/index.html", "https", "www.example.com", dyn_enc, extra, False)
    var f       = h2_make_headers_frame(1, block, True, True)
    var hb      = h2_get_hpack_block(f)
    var dyn_dec = HpackDynTable(4096)
    var headers = hpack_decode_block(hb, dyn_dec)
    var found_path = False
    for i in range(len(headers)):
        if headers[i].name == ":path" and headers[i].value == "/index.html":
            found_path = True
    if not found_path:
        raise Error(":path: /index.html not found in roundtrip")


def test_data_roundtrip() raises:
    """make_data_frame → h2_frame_encode → h2_frame_decode → payload matches."""
    var data = _hex_bytes("48656c6c6f20576f726c64")  # "Hello World"
    var f    = h2_make_data_frame(1, data, True)
    var enc  = h2_frame_encode(f)
    var r    = h2_frame_decode(enc, 0)
    var dec  = r[0].copy()
    assert_eq_u8(dec.frame_type, H2_DATA, "type")
    assert_eq_int(dec.stream_id, 1, "stream_id")
    assert_eq_int(len(dec.payload), 11, "payload len")
    assert_eq_u8(dec.payload[0], 0x48, "p[0] 'H'")
    assert_eq_u8(dec.payload[10], 0x64, "p[10] 'd'")


# ── 15C-4: RST_STREAM, WINDOW_UPDATE, GOAWAY, PRIORITY Tests ─────────────────

def test_rst_stream_encode() raises:
    """RST_STREAM with NO_ERROR → 4-byte big-endian error code."""
    var f = h2_make_rst_stream(1, H2_ERR_NO_ERROR)
    assert_eq_u8(f.frame_type, H2_RST_STREAM, "type")
    assert_eq_int(f.stream_id, 1, "stream_id")
    assert_eq_int(len(f.payload), 4, "payload len")
    assert_eq_u8(f.payload[0], 0x00, "ec[0]")
    assert_eq_u8(f.payload[1], 0x00, "ec[1]")
    assert_eq_u8(f.payload[2], 0x00, "ec[2]")
    assert_eq_u8(f.payload[3], 0x00, "ec[3]")


def test_rst_stream_decode() raises:
    """Parse RST_STREAM payload: CANCEL (0x8)."""
    var f = h2_make_rst_stream(3, H2_ERR_CANCEL)
    var ec = h2_parse_rst_stream(f)
    assert_eq_int(ec, H2_ERR_CANCEL, "error_code")


def test_rst_stream_roundtrip() raises:
    """Encode then parse RST_STREAM: PROTOCOL_ERROR."""
    var f  = h2_make_rst_stream(5, H2_ERR_PROTOCOL_ERROR)
    var ec = h2_parse_rst_stream(f)
    assert_eq_int(ec, H2_ERR_PROTOCOL_ERROR, "error_code")


def test_window_update_encode_stream() raises:
    """WINDOW_UPDATE for stream 1, increment=65535."""
    var f = h2_make_window_update(1, 65535)
    assert_eq_u8(f.frame_type, H2_WINDOW_UPDATE, "type")
    assert_eq_int(f.stream_id, 1, "stream_id")
    assert_eq_int(len(f.payload), 4, "payload len")
    # 65535 = 0x0000FFFF
    assert_eq_u8(f.payload[0], 0x00, "inc[0]")
    assert_eq_u8(f.payload[1], 0x00, "inc[1]")
    assert_eq_u8(f.payload[2], 0xFF, "inc[2]")
    assert_eq_u8(f.payload[3], 0xFF, "inc[3]")


def test_window_update_encode_connection() raises:
    """WINDOW_UPDATE for the connection (stream_id=0)."""
    var f = h2_make_window_update(0, 1048576)
    assert_eq_int(f.stream_id, 0, "stream_id=0")


def test_window_update_decode() raises:
    """Parse WINDOW_UPDATE increment correctly."""
    var f   = h2_make_window_update(1, 32768)
    var inc = h2_parse_window_update(f)
    assert_eq_int(inc, 32768, "increment")


def test_window_update_zero_increment() raises:
    """Increment=0 must raise (RFC §6.9.1)."""
    var raised = False
    try:
        _ = h2_make_window_update(1, 0)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for zero increment")


def test_window_update_overflow() raises:
    """Increment > 2^31-1 must raise."""
    var raised = False
    try:
        _ = h2_make_window_update(1, 0x80000000)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for overflow increment")


def test_goaway_no_debug() raises:
    """GOAWAY with empty debug_data."""
    var f = h2_make_goaway(3, H2_ERR_NO_ERROR, List[UInt8]())
    assert_eq_u8(f.frame_type, H2_GOAWAY, "type")
    assert_eq_int(f.stream_id, 0, "stream_id=0")
    assert_eq_int(len(f.payload), 8, "payload len (4 last_sid + 4 ec)")
    # last_stream_id = 3: 0x00 0x00 0x00 0x03
    assert_eq_u8(f.payload[3], 0x03, "last_sid")
    # error_code = 0: all zeros
    assert_eq_u8(f.payload[4], 0x00, "ec[0]")
    assert_eq_u8(f.payload[7], 0x00, "ec[3]")


def test_goaway_with_debug() raises:
    """GOAWAY with debug_data appended."""
    var debug = _hex_bytes("deadbeef")
    var f = h2_make_goaway(5, H2_ERR_PROTOCOL_ERROR, debug)
    assert_eq_int(len(f.payload), 12, "payload len (8 + 4 debug)")
    assert_eq_u8(f.payload[8],  0xDE, "debug[0]")
    assert_eq_u8(f.payload[11], 0xEF, "debug[3]")


def test_goaway_roundtrip() raises:
    """Encode then parse GOAWAY: last_stream_id, error_code, debug."""
    var debug = _hex_bytes("cafebabe")
    var f     = h2_make_goaway(7, H2_ERR_INTERNAL_ERROR, debug)
    var r     = h2_parse_goaway(f)
    assert_eq_int(r[0], 7, "last_stream_id")
    assert_eq_int(r[1], H2_ERR_INTERNAL_ERROR, "error_code")
    assert_eq_int(len(r[2]), 4, "debug len")
    assert_eq_u8(r[2][0], 0xCA, "debug[0]")


def test_priority_frame_exclusive() raises:
    """PRIORITY frame with exclusive bit set."""
    var f = h2_make_priority_frame(3, 1, True, 16)
    assert_eq_u8(f.frame_type, H2_PRIORITY, "type")
    assert_eq_int(f.stream_id, 3, "stream_id")
    assert_eq_int(len(f.payload), 5, "payload len")
    # exclusive bit = high bit of dep_stream_id word
    if Int(f.payload[0]) & 0x80 == 0:
        raise Error("exclusive bit must be set")


def test_priority_frame_non_exclusive() raises:
    """PRIORITY frame without exclusive bit."""
    var f = h2_make_priority_frame(5, 3, False, 32)
    if Int(f.payload[0]) & 0x80 != 0:
        raise Error("exclusive bit must be clear")


def test_priority_roundtrip() raises:
    """Encode then parse PRIORITY: dep_stream_id, exclusive, weight."""
    var f = h2_make_priority_frame(3, 1, True, 32)
    var r = h2_parse_priority_frame(f)
    assert_eq_int(r[0], 1, "dep_stream_id")
    if not r[1]:
        raise Error("exclusive must be True")
    assert_eq_int(r[2], 32, "weight")


# ── 15C-5: Connection Preface + Multi-frame Stream Tests ─────────────────────

def test_client_preface_bytes() raises:
    """Client preface is 24 bytes containing the magic string."""
    var p = h2_client_preface_bytes()
    assert_eq_int(len(p), 24, "length")
    # "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    var magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    var mb    = magic.as_bytes()
    for i in range(24):
        if p[i] != mb[i]:
            raise Error("preface byte " + String(i) + " mismatch")


def test_read_frames_single() raises:
    """One frame in buffer → list with 1 frame."""
    var f    = Http2Frame(H2_SETTINGS, H2_FLAG_ACK, 0, List[UInt8]())
    var buf  = h2_frame_encode(f)
    var frames = h2_read_frames(buf)
    assert_eq_int(len(frames), 1, "frame count")
    assert_eq_u8(frames[0].frame_type, H2_SETTINGS, "type")


def test_read_frames_multiple() raises:
    """Three concatenated frames → list with 3 frames."""
    var buf = List[UInt8]()
    var types = List[UInt8]()
    types.append(H2_SETTINGS); types.append(H2_PING); types.append(H2_DATA)
    for i in range(3):
        var payload = List[UInt8]()
        if types[i] == H2_PING:
            for _ in range(8):
                payload.append(UInt8(0xAA))
        var f   = Http2Frame(types[i], UInt8(0), 0, payload)
        var enc = h2_frame_encode(f)
        for j in range(len(enc)):
            buf.append(enc[j])
    var frames = h2_read_frames(buf)
    assert_eq_int(len(frames), 3, "frame count")
    assert_eq_u8(frames[0].frame_type, H2_SETTINGS, "f[0] type")
    assert_eq_u8(frames[1].frame_type, H2_PING,     "f[1] type")
    assert_eq_u8(frames[2].frame_type, H2_DATA,     "f[2] type")


def test_read_frames_empty() raises:
    """Empty buffer → empty list."""
    var buf    = List[UInt8]()
    var frames = h2_read_frames(buf)
    assert_eq_int(len(frames), 0, "frame count")


def test_read_frames_truncated() raises:
    """Buffer with < 9 bytes → raises."""
    var buf = _hex_bytes("000000")  # 3 bytes, not enough for a header
    var raised = False
    try:
        _ = h2_read_frames(buf)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for truncated header")


def test_read_frames_truncated_payload() raises:
    """Header declares payload but bytes are missing → raises."""
    var buf = List[UInt8]()
    buf.append(0x00); buf.append(0x00); buf.append(0x08)  # length=8
    buf.append(0x06); buf.append(0x00)                     # type=PING, flags=0
    buf.append(0x00); buf.append(0x00); buf.append(0x00); buf.append(0x00)  # stream_id=0
    # only 2 payload bytes follow (need 8)
    buf.append(0x01); buf.append(0x02)
    var raised = False
    try:
        _ = h2_read_frames(buf)
    except:
        raised = True
    if not raised:
        raise Error("expected Error for truncated payload")


def test_write_frames_single() raises:
    """h2_write_frames encodes one frame correctly."""
    var f = Http2Frame(H2_SETTINGS, H2_FLAG_ACK, 0, List[UInt8]())
    var frames = List[Http2Frame]()
    frames.append(f.copy())
    var buf = h2_write_frames(frames)
    assert_eq_int(len(buf), 9, "9 bytes for SETTINGS ACK")
    assert_eq_u8(buf[3], H2_SETTINGS, "type byte")
    assert_eq_u8(buf[4], H2_FLAG_ACK, "flags byte")


def test_write_frames_multiple() raises:
    """h2_write_frames concatenates 3 frames; h2_read_frames decodes back."""
    var frames = List[Http2Frame]()
    frames.append(Http2Frame(H2_SETTINGS, H2_FLAG_ACK, 0, List[UInt8]()))
    var ping_payload = List[UInt8]()
    for _ in range(8):
        ping_payload.append(UInt8(0x42))
    frames.append(Http2Frame(H2_PING, UInt8(0), 0, ping_payload))
    frames.append(Http2Frame(H2_DATA, H2_FLAG_END_STREAM, 1, _hex_bytes("deadbeef")))
    var buf    = h2_write_frames(frames)
    var result = h2_read_frames(buf)
    assert_eq_int(len(result), 3, "frame count")
    assert_eq_u8(result[2].frame_type, H2_DATA, "f[2] type")
    assert_eq_int(len(result[2].payload), 4, "f[2] payload len")


def test_roundtrip_stream() raises:
    """Write then read 5 frames of various types; all fields match."""
    var frames = List[Http2Frame]()
    var ping_p = List[UInt8]()
    for _ in range(8):
        ping_p.append(UInt8(0xFF))
    frames.append(Http2Frame(H2_SETTINGS,      UInt8(0),        0, List[UInt8]()))
    frames.append(Http2Frame(H2_PING,          UInt8(0),        0, ping_p))
    frames.append(Http2Frame(H2_HEADERS,       H2_FLAG_END_HEADERS, 1, _hex_bytes("8286")))
    frames.append(Http2Frame(H2_DATA,          H2_FLAG_END_STREAM,  1, _hex_bytes("01020304")))
    frames.append(Http2Frame(H2_WINDOW_UPDATE, UInt8(0),        0, _hex_bytes("00010000")))
    var buf    = h2_write_frames(frames)
    var result = h2_read_frames(buf)
    assert_eq_int(len(result), 5, "frame count")
    for i in range(5):
        if result[i].frame_type != frames[i].frame_type:
            raise Error("type mismatch at frame " + String(i))
        if result[i].stream_id != frames[i].stream_id:
            raise Error("stream_id mismatch at frame " + String(i))
        if len(result[i].payload) != len(frames[i].payload):
            raise Error("payload len mismatch at frame " + String(i))


def test_initial_settings() raises:
    """h2_make_initial_settings: type=SETTINGS, stream_id=0, flags=0."""
    var f = h2_make_initial_settings()
    assert_eq_u8(f.frame_type, H2_SETTINGS, "type")
    assert_eq_int(f.stream_id, 0, "stream_id")
    assert_eq_u8(f.flags, UInt8(0), "flags")
    # Must contain at least one setting parameter
    assert_eq_int(len(f.payload) % 6, 0, "payload multiple of 6")
    if len(f.payload) == 0:
        raise Error("initial SETTINGS must have at least one parameter")


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
    print("── 15C-2: SETTINGS + PING frames ──")
    run_test("settings_encode: no pairs → empty payload", passed, failed, test_settings_encode_empty)
    run_test("settings_encode: single pair correct bytes", passed, failed, test_settings_encode_one)
    run_test("settings_encode: 3 pairs → 18 bytes", passed, failed, test_settings_encode_multiple)
    run_test("settings_decode: empty payload → ([], [])", passed, failed, test_settings_decode_empty)
    run_test("settings_decode: single pair", passed, failed, test_settings_decode_one)
    run_test("settings roundtrip: encode then decode identical", passed, failed, test_settings_roundtrip)
    run_test("settings_decode: bad length → raises", passed, failed, test_settings_decode_bad_length)
    run_test("make_settings_frame: type/stream_id/flags correct", passed, failed, test_make_settings_frame)
    run_test("make_settings_ack: ACK flag, empty payload", passed, failed, test_make_settings_ack)
    run_test("make_ping: 8-byte opaque, no ACK flag", passed, failed, test_make_ping)
    run_test("make_ping ack=True: ACK flag set", passed, failed, test_make_ping_ack)
    run_test("make_ping: non-8-byte opaque → raises", passed, failed, test_make_ping_bad_length)
    run_test("parse_ping_payload: returns 8 opaque bytes", passed, failed, test_parse_ping_payload)

    print()
    print("── 15C-3: HEADERS, CONTINUATION, DATA frames ──")
    run_test("make_headers_frame: END_HEADERS flag set", passed, failed, test_make_headers_frame_end_headers)
    run_test("make_headers_frame: END_STREAM + END_HEADERS", passed, failed, test_make_headers_frame_end_stream)
    run_test("make_continuation_frame: END_HEADERS flag", passed, failed, test_make_continuation_frame)
    run_test("make_data_frame: payload + END_STREAM clear", passed, failed, test_make_data_frame_no_end)
    run_test("make_data_frame: END_STREAM set", passed, failed, test_make_data_frame_end_stream)
    run_test("make_data_frame: empty payload valid", passed, failed, test_data_frame_empty_payload)
    run_test("get_hpack_block: no PRIORITY flag → full payload", passed, failed, test_get_hpack_block_no_priority)
    run_test("get_hpack_block: PRIORITY flag → skip 5 bytes", passed, failed, test_get_hpack_block_with_priority)
    run_test("encode_request_headers: 4 pseudo-headers decode correctly", passed, failed, test_encode_request_headers_basic)
    run_test("encode_request_headers: extra headers included", passed, failed, test_encode_request_headers_extra)
    run_test("encode_response_headers: :status=200", passed, failed, test_encode_response_headers_200)
    run_test("encode_response_headers: :status=404", passed, failed, test_encode_response_headers_404)
    run_test("request headers roundtrip via HPACK decode", passed, failed, test_headers_roundtrip)
    run_test("data frame roundtrip: encode → decode → payload matches", passed, failed, test_data_roundtrip)

    print()
    print("── 15C-4: RST_STREAM, WINDOW_UPDATE, GOAWAY, PRIORITY ──")
    run_test("rst_stream encode: 4-byte error code", passed, failed, test_rst_stream_encode)
    run_test("rst_stream decode: error code correct", passed, failed, test_rst_stream_decode)
    run_test("rst_stream roundtrip: encode then parse", passed, failed, test_rst_stream_roundtrip)
    run_test("window_update encode: stream-level increment", passed, failed, test_window_update_encode_stream)
    run_test("window_update encode: connection-level (stream_id=0)", passed, failed, test_window_update_encode_connection)
    run_test("window_update decode: increment correct", passed, failed, test_window_update_decode)
    run_test("window_update: increment=0 → raises", passed, failed, test_window_update_zero_increment)
    run_test("window_update: increment > 2^31-1 → raises", passed, failed, test_window_update_overflow)
    run_test("goaway: no debug data", passed, failed, test_goaway_no_debug)
    run_test("goaway: with debug data", passed, failed, test_goaway_with_debug)
    run_test("goaway roundtrip: encode then parse", passed, failed, test_goaway_roundtrip)
    run_test("priority frame: exclusive bit set", passed, failed, test_priority_frame_exclusive)
    run_test("priority frame: exclusive bit clear", passed, failed, test_priority_frame_non_exclusive)
    run_test("priority roundtrip: encode then parse", passed, failed, test_priority_roundtrip)

    print()
    print("── 15C-5: Connection preface + multi-frame stream ──")
    run_test("client_preface_bytes: 24 bytes, correct content", passed, failed, test_client_preface_bytes)
    run_test("read_frames: single frame in buffer", passed, failed, test_read_frames_single)
    run_test("read_frames: 3 concatenated frames", passed, failed, test_read_frames_multiple)
    run_test("read_frames: empty buffer → 0 frames", passed, failed, test_read_frames_empty)
    run_test("read_frames: partial header → raises", passed, failed, test_read_frames_truncated)
    run_test("read_frames: partial payload → raises", passed, failed, test_read_frames_truncated_payload)
    run_test("write_frames: single frame encodes correctly", passed, failed, test_write_frames_single)
    run_test("write_frames: 3 frames concatenated", passed, failed, test_write_frames_multiple)
    run_test("roundtrip: write_frames then read_frames", passed, failed, test_roundtrip_stream)
    run_test("initial_settings: type=SETTINGS, stream_id=0", passed, failed, test_initial_settings)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
