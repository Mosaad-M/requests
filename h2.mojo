# ============================================================================
# h2.mojo — HTTP/2 Frame Layer (RFC 7540)
# ============================================================================
# Implements the binary framing layer required for HTTP/2:
#   - Frame header encode/decode (§4.1)
#   - SETTINGS + PING frames (§6.4, §6.7)
#   - HEADERS, CONTINUATION, DATA frames (§6.1, §6.2, §6.10)
#   - RST_STREAM, WINDOW_UPDATE, GOAWAY, PRIORITY (§6.3, §6.8, §6.9, §6.4)
#   - Connection preface + multi-frame stream helpers (§3.5)
#   - Http2Conn: TLS ALPN connect, request/response lifecycle (§3)
# ============================================================================

from hpack import (
    HpackHeader, HpackDynTable,
    hpack_encode_block, hpack_decode_block,
    static_table_find,
)


# ── Frame Type Constants (RFC 7540 §6) ──────────────────────────────────────

comptime H2_DATA          = UInt8(0x0)
comptime H2_HEADERS       = UInt8(0x1)
comptime H2_PRIORITY      = UInt8(0x2)
comptime H2_RST_STREAM    = UInt8(0x3)
comptime H2_SETTINGS      = UInt8(0x4)
comptime H2_PUSH_PROMISE  = UInt8(0x5)
comptime H2_PING          = UInt8(0x6)
comptime H2_GOAWAY        = UInt8(0x7)
comptime H2_WINDOW_UPDATE = UInt8(0x8)
comptime H2_CONTINUATION  = UInt8(0x9)


# ── Flag Constants ───────────────────────────────────────────────────────────

comptime H2_FLAG_END_STREAM  = UInt8(0x1)   # DATA, HEADERS
comptime H2_FLAG_END_HEADERS = UInt8(0x4)   # HEADERS, PUSH_PROMISE, CONTINUATION
comptime H2_FLAG_PADDED      = UInt8(0x8)   # DATA, HEADERS, PUSH_PROMISE
comptime H2_FLAG_PRIORITY    = UInt8(0x20)  # HEADERS
comptime H2_FLAG_ACK         = UInt8(0x1)   # SETTINGS, PING


# ── SETTINGS Parameter IDs (RFC 7540 §6.5.2) ───────────────────────────────

comptime H2_SETTING_HEADER_TABLE_SIZE      = 0x1
comptime H2_SETTING_ENABLE_PUSH            = 0x2
comptime H2_SETTING_MAX_CONCURRENT_STREAMS = 0x3
comptime H2_SETTING_INITIAL_WINDOW_SIZE    = 0x4
comptime H2_SETTING_MAX_FRAME_SIZE         = 0x5
comptime H2_SETTING_MAX_HEADER_LIST_SIZE   = 0x6


# ── Error Codes (RFC 7540 §7) ────────────────────────────────────────────────

comptime H2_ERR_NO_ERROR            = 0x0
comptime H2_ERR_PROTOCOL_ERROR      = 0x1
comptime H2_ERR_INTERNAL_ERROR      = 0x2
comptime H2_ERR_FLOW_CONTROL_ERROR  = 0x3
comptime H2_ERR_SETTINGS_TIMEOUT    = 0x4
comptime H2_ERR_STREAM_CLOSED       = 0x5
comptime H2_ERR_FRAME_SIZE_ERROR    = 0x6
comptime H2_ERR_REFUSED_STREAM      = 0x7
comptime H2_ERR_CANCEL              = 0x8
comptime H2_ERR_COMPRESSION_ERROR   = 0x9
comptime H2_ERR_CONNECT_ERROR       = 0xa
comptime H2_ERR_ENHANCE_YOUR_CALM   = 0xb
comptime H2_ERR_INADEQUATE_SECURITY = 0xc
comptime H2_ERR_HTTP_1_1_REQUIRED   = 0xd


# ── 15C-1: Frame Header + Http2Frame Struct (RFC 7540 §4.1) ────────────────

struct Http2Frame(Copyable, Movable):
    """A single HTTP/2 frame: 9-byte header + variable-length payload.

    Wire layout (9-byte header):
        byte 0-2 : payload length (24-bit big-endian)
        byte 3   : type
        byte 4   : flags
        byte 5-8 : R(1) + stream_id(31), big-endian (R bit masked on decode)
    """

    var frame_type: UInt8
    var flags:      UInt8
    var stream_id:  Int
    var payload:    List[UInt8]

    fn __init__(
        out self,
        frame_type: UInt8,
        flags:      UInt8,
        stream_id:  Int,
        payload:    List[UInt8],
    ):
        self.frame_type = frame_type
        self.flags      = flags
        self.stream_id  = stream_id
        self.payload    = payload.copy()

    fn __copyinit__(out self, copy: Self):
        self.frame_type = copy.frame_type
        self.flags      = copy.flags
        self.stream_id  = copy.stream_id
        self.payload    = copy.payload.copy()

    fn __moveinit__(out self, deinit take: Self):
        self.frame_type = take.frame_type
        self.flags      = take.flags
        self.stream_id  = take.stream_id
        self.payload    = take.payload^


fn h2_frame_encode(frame: Http2Frame) -> List[UInt8]:
    """Encode an HTTP/2 frame to bytes (9-byte header + payload).

    Args:
        frame: Frame to encode.

    Returns:
        9 + len(frame.payload) bytes.
    """
    var n   = len(frame.payload)
    var out = List[UInt8](capacity=9 + n)
    # 24-bit big-endian payload length
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8)  & 0xFF))
    out.append(UInt8( n        & 0xFF))
    out.append(frame.frame_type)
    out.append(frame.flags)
    # 31-bit stream_id (R bit = 0)
    out.append(UInt8((frame.stream_id >> 24) & 0x7F))
    out.append(UInt8((frame.stream_id >> 16) & 0xFF))
    out.append(UInt8((frame.stream_id >> 8)  & 0xFF))
    out.append(UInt8( frame.stream_id        & 0xFF))
    for i in range(n):
        out.append(frame.payload[i])
    return out^


fn h2_frame_decode(data: List[UInt8], off: Int) raises -> Tuple[Http2Frame, Int]:
    """Decode one HTTP/2 frame starting at data[off].

    Args:
        data: Byte buffer containing one or more frames.
        off:  Offset of the frame header within data.

    Returns:
        (frame, new_offset) where new_offset points past this frame's last byte.

    Raises:
        Error if fewer than 9 bytes remain (truncated header) or if the
        declared payload length exceeds available bytes (truncated payload).
    """
    var remaining = len(data) - off
    if remaining < 9:
        raise Error(
            "h2_frame_decode: need 9 bytes for header, have "
            + String(remaining)
        )
    var length = (Int(data[off])     << 16) \
               | (Int(data[off + 1]) << 8)  \
               |  Int(data[off + 2])
    var ftype  = data[off + 3]
    var flags  = data[off + 4]
    var sid    = (Int(data[off + 5] & 0x7F) << 24) \
               | (Int(data[off + 6])        << 16)  \
               | (Int(data[off + 7])        << 8)   \
               |  Int(data[off + 8])
    var payload_start = off + 9
    if len(data) - payload_start < length:
        raise Error(
            "h2_frame_decode: payload truncated — declared "
            + String(length) + " bytes but only "
            + String(len(data) - payload_start) + " available"
        )
    var payload = List[UInt8](capacity=length)
    for i in range(length):
        payload.append(data[payload_start + i])
    return (Http2Frame(ftype, flags, sid, payload^), payload_start + length)


# ── 15C-2: SETTINGS + PING frames (RFC 7540 §6.4, §6.7) ────────────────────

fn h2_settings_encode(ids: List[Int], vals: List[Int]) -> List[UInt8]:
    """Encode a SETTINGS payload: pairs of (id:16, val:32), big-endian.

    Args:
        ids:  List of 16-bit setting identifier values.
        vals: List of 32-bit setting values (parallel to ids).

    Returns:
        len(ids) * 6 bytes.
    """
    var n   = len(ids)
    var out = List[UInt8](capacity=n * 6)
    for i in range(n):
        var id  = ids[i]
        var val = vals[i]
        out.append(UInt8((id >> 8)  & 0xFF))
        out.append(UInt8( id        & 0xFF))
        out.append(UInt8((val >> 24) & 0xFF))
        out.append(UInt8((val >> 16) & 0xFF))
        out.append(UInt8((val >> 8)  & 0xFF))
        out.append(UInt8( val        & 0xFF))
    return out^


fn h2_settings_decode(payload: List[UInt8]) raises -> Tuple[List[Int], List[Int]]:
    """Decode a SETTINGS payload into parallel (ids, vals) lists.

    Args:
        payload: Raw SETTINGS payload bytes.

    Returns:
        (ids, vals) where each entry is one setting parameter.

    Raises:
        Error if payload length is not a multiple of 6.
    """
    var n = len(payload)
    if n % 6 != 0:
        raise Error(
            "h2_settings_decode: payload length must be multiple of 6, got "
            + String(n)
        )
    var count = n // 6
    var ids  = List[Int](capacity=count)
    var vals = List[Int](capacity=count)
    for i in range(count):
        var base = i * 6
        var id   = (Int(payload[base])     << 8) | Int(payload[base + 1])
        var val  = (Int(payload[base + 2]) << 24) \
                 | (Int(payload[base + 3]) << 16) \
                 | (Int(payload[base + 4]) << 8)  \
                 |  Int(payload[base + 5])
        ids.append(id)
        vals.append(val)
    return (ids^, vals^)


fn h2_make_settings_frame(ids: List[Int], vals: List[Int]) -> Http2Frame:
    """Build a SETTINGS frame (stream_id=0, flags=0).

    Args:
        ids:  Setting identifier list.
        vals: Setting value list (parallel to ids).

    Returns:
        Http2Frame ready to encode.
    """
    return Http2Frame(H2_SETTINGS, UInt8(0), 0, h2_settings_encode(ids, vals))


fn h2_make_settings_ack() -> Http2Frame:
    """Build a SETTINGS ACK frame (stream_id=0, flags=ACK, empty payload).

    Returns:
        Http2Frame ready to encode.
    """
    return Http2Frame(H2_SETTINGS, H2_FLAG_ACK, 0, List[UInt8]())


fn h2_make_ping_frame(opaque_data: List[UInt8], ack: Bool) raises -> Http2Frame:
    """Build a PING frame (stream_id=0, 8-byte opaque payload).

    Args:
        opaque_data: Exactly 8 bytes of opaque data.
        ack:         True to set the ACK flag.

    Returns:
        Http2Frame ready to encode.

    Raises:
        Error if opaque_data is not exactly 8 bytes.
    """
    if len(opaque_data) != 8:
        raise Error(
            "h2_make_ping_frame: opaque_data must be 8 bytes, got "
            + String(len(opaque_data))
        )
    var flags = H2_FLAG_ACK if ack else UInt8(0)
    return Http2Frame(H2_PING, flags, 0, opaque_data.copy())


fn h2_parse_ping_payload(frame: Http2Frame) raises -> List[UInt8]:
    """Extract the 8-byte opaque data from a PING frame.

    Args:
        frame: A PING frame (type must be H2_PING, payload must be 8 bytes).

    Returns:
        8-byte opaque data.

    Raises:
        Error if payload is not 8 bytes.
    """
    if len(frame.payload) != 8:
        raise Error(
            "h2_parse_ping_payload: expected 8-byte payload, got "
            + String(len(frame.payload))
        )
    return frame.payload.copy()


# ── 15C-3: HEADERS, CONTINUATION, DATA frames (RFC 7540 §6.1, §6.2, §6.10) ─

fn h2_make_headers_frame(
    stream_id:   Int,
    hpack_block: List[UInt8],
    end_stream:  Bool,
    end_headers: Bool,
) -> Http2Frame:
    """Build a HEADERS frame.

    Args:
        stream_id:   Client stream ID (must be odd for client-initiated).
        hpack_block: HPACK-encoded header block.
        end_stream:  True to set END_STREAM flag.
        end_headers: True to set END_HEADERS flag.

    Returns:
        Http2Frame ready to encode.
    """
    var flags = UInt8(0)
    if end_stream:
        flags = flags | H2_FLAG_END_STREAM
    if end_headers:
        flags = flags | H2_FLAG_END_HEADERS
    return Http2Frame(H2_HEADERS, flags, stream_id, hpack_block.copy())


fn h2_make_continuation_frame(
    stream_id:   Int,
    hpack_block: List[UInt8],
    end_headers: Bool,
) -> Http2Frame:
    """Build a CONTINUATION frame.

    Args:
        stream_id:   Stream ID (same as the preceding HEADERS/PUSH_PROMISE).
        hpack_block: Continuation of the HPACK header block.
        end_headers: True to set END_HEADERS flag.

    Returns:
        Http2Frame ready to encode.
    """
    var flags = H2_FLAG_END_HEADERS if end_headers else UInt8(0)
    return Http2Frame(H2_CONTINUATION, flags, stream_id, hpack_block.copy())


fn h2_make_data_frame(
    stream_id:  Int,
    data:       List[UInt8],
    end_stream: Bool,
) -> Http2Frame:
    """Build a DATA frame.

    Args:
        stream_id:  Stream ID.
        data:       Raw payload bytes.
        end_stream: True to set END_STREAM flag.

    Returns:
        Http2Frame ready to encode.
    """
    var flags = H2_FLAG_END_STREAM if end_stream else UInt8(0)
    return Http2Frame(H2_DATA, flags, stream_id, data.copy())


fn h2_get_hpack_block(frame: Http2Frame) raises -> List[UInt8]:
    """Extract the HPACK block from a HEADERS or CONTINUATION frame.

    Handles the PRIORITY flag: if set on a HEADERS frame, the first 5 bytes of
    the payload are a priority prefix (exclusive+dep_stream_id:32, weight:8)
    and must be skipped.

    Args:
        frame: A HEADERS or CONTINUATION frame.

    Returns:
        The HPACK-encoded header block bytes.

    Raises:
        Error if PRIORITY flag is set but payload is shorter than 5 bytes.
    """
    var has_priority = (Int(frame.flags) & Int(H2_FLAG_PRIORITY)) != 0
    if has_priority:
        if len(frame.payload) < 5:
            raise Error(
                "h2_get_hpack_block: PRIORITY flag set but payload too short ("
                + String(len(frame.payload)) + " bytes)"
            )
        var skip = 5
        var n    = len(frame.payload) - skip
        var out  = List[UInt8](capacity=n)
        for i in range(n):
            out.append(frame.payload[skip + i])
        return out^
    return frame.payload.copy()


fn h2_encode_request_headers(
    method:        String,
    path:          String,
    scheme:        String,
    authority:     String,
    mut dyn_table: HpackDynTable,
    extra:         List[HpackHeader],
    use_huffman:   Bool,
) raises -> List[UInt8]:
    """Build an HPACK-encoded header block for an HTTP/2 request.

    Pseudo-headers (:method, :path, :scheme, :authority) are prepended first
    per RFC 7540 §8.1.2.1. Extra headers follow in the order provided.

    Args:
        method:      HTTP method (e.g. "GET").
        path:        Request path (e.g. "/").
        scheme:      URI scheme ("http" or "https").
        authority:   Host[:port] (e.g. "example.com").
        dyn_table:   Encoder dynamic table (mutated as headers are indexed).
        extra:       Additional headers appended after pseudo-headers.
        use_huffman: True to Huffman-encode literal strings.

    Returns:
        HPACK-encoded byte block.
    """
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":method",    method))
    headers.append(HpackHeader(":path",      path))
    headers.append(HpackHeader(":scheme",    scheme))
    headers.append(HpackHeader(":authority", authority))
    for i in range(len(extra)):
        headers.append(HpackHeader(extra[i].name, extra[i].value))
    return hpack_encode_block(headers, dyn_table, use_huffman)


fn h2_encode_response_headers(
    status:        Int,
    mut dyn_table: HpackDynTable,
    extra:         List[HpackHeader],
    use_huffman:   Bool,
) raises -> List[UInt8]:
    """Build an HPACK-encoded header block for an HTTP/2 response.

    :status pseudo-header is first per RFC 7540 §8.1.2.3.

    Args:
        status:      HTTP status code (e.g. 200).
        dyn_table:   Encoder dynamic table (mutated).
        extra:       Additional headers appended after :status.
        use_huffman: True to Huffman-encode literal strings.

    Returns:
        HPACK-encoded byte block.
    """
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":status", String(status)))
    for i in range(len(extra)):
        headers.append(HpackHeader(extra[i].name, extra[i].value))
    return hpack_encode_block(headers, dyn_table, use_huffman)
