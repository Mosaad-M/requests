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
