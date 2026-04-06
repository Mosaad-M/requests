# ============================================================================
# h2_conn.mojo — HTTP/2 Connection State Machine (RFC 7540 §3)
# ============================================================================
# Builds on h2.mojo (framing layer) to provide a full HTTP/2 client
# connection: TLS + ALPN "h2" negotiate, connection preface exchange,
# and sequential request/response lifecycle.
#
# Kept in a separate file from h2.mojo so that framing-layer unit tests
# (test_h2.mojo) can compile without requiring tls_pure >=1.3.0 ALPN support.
# ============================================================================

from h2 import (
    Http2Frame,
    H2_DATA, H2_HEADERS, H2_CONTINUATION, H2_SETTINGS,
    H2_PING, H2_GOAWAY, H2_RST_STREAM, H2_WINDOW_UPDATE,
    H2_FLAG_END_STREAM, H2_FLAG_END_HEADERS, H2_FLAG_ACK, H2_FLAG_PRIORITY,
    H2_SETTING_MAX_FRAME_SIZE, H2_SETTING_INITIAL_WINDOW_SIZE,
    H2_SETTING_HEADER_TABLE_SIZE,
    h2_frame_encode, h2_frame_decode,
    h2_client_preface_bytes, h2_make_initial_settings,
    h2_make_settings_ack, h2_settings_decode,
    h2_make_headers_frame, h2_make_data_frame, h2_get_hpack_block,
    h2_make_window_update, h2_parse_window_update,
    h2_make_ping_frame,
    h2_parse_goaway, h2_parse_rst_stream,
)
from hpack import (
    HpackHeader, HpackDynTable,
    hpack_encode_block, hpack_decode_block,
)
from tcp import TcpSocket
from tls.socket import TlsSocket, load_system_ca_bundle
from crypto.cert import X509Cert


# ── Http2Conn Struct ─────────────────────────────────────────────────────────

struct Http2Conn(Movable):
    """HTTP/2 connection state: TLS socket + stream counter + HPACK tables.

    Wraps a TlsSocket (Movable only) with the state needed to issue
    sequential HTTP/2 requests over a single TLS connection.
    """

    var _tls:                 TlsSocket
    var _next_stream:         Int          # next client-initiated stream ID (odd)
    var _hpack_enc:           HpackDynTable
    var _hpack_dec:           HpackDynTable
    var _peer_max_frame_size: Int          # from peer SETTINGS_MAX_FRAME_SIZE
    var _peer_initial_window: Int          # from peer SETTINGS_INITIAL_WINDOW_SIZE
    var _conn_window:         Int          # outbound connection-level flow-control window

    fn __init__(out self):
        """Create an Http2Conn with a placeholder TLS socket (fd=0).

        h2_connect() immediately overwrites _tls with the real connected
        socket before returning, so fd=0 is never used in practice.
        """
        self._tls                 = TlsSocket(Int32(0))
        self._next_stream         = 1
        self._hpack_enc           = HpackDynTable(4096)
        self._hpack_dec           = HpackDynTable(4096)
        self._peer_max_frame_size = 16384
        self._peer_initial_window = 65535
        self._conn_window         = 65535

    fn __moveinit__(out self, deinit take: Self):
        self._tls                 = take._tls^
        self._next_stream         = take._next_stream
        self._hpack_enc           = take._hpack_enc^
        self._hpack_dec           = take._hpack_dec^
        self._peer_max_frame_size = take._peer_max_frame_size
        self._peer_initial_window = take._peer_initial_window
        self._conn_window         = take._conn_window


# ── Private helpers ───────────────────────────────────────────────────────────

fn _read_one_frame(mut conn: Http2Conn) raises -> Http2Frame:
    """Read exactly one HTTP/2 frame from the TLS stream.

    Calls recv_exact(9) for the fixed header, then recv_exact(length)
    for the payload.  Never buffers beyond a single frame.

    Args:
        conn: Open Http2Conn.

    Returns:
        Decoded Http2Frame.

    Raises:
        Error if the TLS connection closes unexpectedly.
    """
    var hdr    = conn._tls.recv_exact(9)
    var length = (Int(hdr[0]) << 16) | (Int(hdr[1]) << 8) | Int(hdr[2])
    var ftype  = hdr[3]
    var flags  = hdr[4]
    var sid    = (Int(hdr[5] & 0x7F) << 24) \
               | (Int(hdr[6])        << 16) \
               | (Int(hdr[7])        << 8)  \
               |  Int(hdr[8])
    var payload = List[UInt8]()
    if length > 0:
        payload = conn._tls.recv_exact(length)
    return Http2Frame(ftype, flags, sid, payload^)


# ── Public API ────────────────────────────────────────────────────────────────

fn h2_connect(host: String, port: Int = 443) raises -> Http2Conn:
    """Establish an HTTP/2 connection via TLS + ALPN.

    1. Loads system CA bundle.
    2. Opens TCP connection to host:port.
    3. TLS handshake with ALPN ["h2"].
    4. Sends client connection preface (24-byte magic + SETTINGS).
    5. Reads server SETTINGS, applies peer parameters, sends SETTINGS ACK.

    Args:
        host: Hostname to connect to (e.g. "www.google.com").
        port: TCP port (default 443).

    Returns:
        Http2Conn ready for h2_request() calls.

    Raises:
        Error if TLS fails, server explicitly downgrades to HTTP/1.1,
        or the server SETTINGS exchange fails.
    """
    # 1. Load CA bundle
    var ca = load_system_ca_bundle()

    # 2. TCP connect
    var tcp = TcpSocket()
    tcp.connect(host, port)

    # 3. TLS handshake with ALPN
    var alpn = List[String]()
    alpn.append("h2")
    var tls = TlsSocket(tcp.fd)
    tls.connect(host, ca, alpn_protocols=alpn)

    # 4. Reject explicit HTTP/1.1 downgrade
    var proto = tls.negotiated_protocol()
    if proto == "http/1.1":
        raise Error(
            "h2_connect: server negotiated http/1.1 via ALPN, expected h2"
        )

    # 5. Send client connection preface (24-byte magic)
    var preface = h2_client_preface_bytes()
    _ = tls.send(preface)

    # 6. Send initial SETTINGS
    var init_settings_enc = h2_frame_encode(h2_make_initial_settings())
    _ = tls.send(init_settings_enc)

    # 7. Create conn; move real TLS socket in
    var conn  = Http2Conn()
    conn._tls = tls^

    # 8. Server SETTINGS exchange — loop until we receive the server's SETTINGS
    #    (skip WINDOW_UPDATE or other frames that may arrive first)
    var got_server_settings = False
    while not got_server_settings:
        var f = _read_one_frame(conn)
        if f.frame_type == H2_SETTINGS \
                and f.stream_id == 0 \
                and Int(f.flags) & Int(H2_FLAG_ACK) == 0:
            # Apply peer parameters
            if len(f.payload) >= 6:
                var r    = h2_settings_decode(f.payload)
                var ids  = r[0].copy()
                var vals = r[1].copy()
                for i in range(len(ids)):
                    if ids[i] == H2_SETTING_MAX_FRAME_SIZE:
                        conn._peer_max_frame_size = vals[i]
                    elif ids[i] == H2_SETTING_INITIAL_WINDOW_SIZE:
                        conn._peer_initial_window = vals[i]
                        conn._conn_window         = vals[i]
                    elif ids[i] == H2_SETTING_HEADER_TABLE_SIZE:
                        conn._hpack_enc.update_max_size(vals[i])
            # Send SETTINGS ACK
            _ = conn._tls.send(h2_frame_encode(h2_make_settings_ack()))
            got_server_settings = True

    return conn^


fn h2_request(
    mut conn:  Http2Conn,
    method:    String,
    path:      String,
    headers:   List[HpackHeader],
    body:      List[UInt8],
) raises -> Tuple[Int, List[HpackHeader], List[UInt8]]:
    """Send an HTTP/2 request and receive the complete response.

    The caller must include ":authority" in `headers`.  This function
    prepends :method, :path, :scheme pseudo-headers before the caller
    headers, so :authority appears immediately after the pseudo-headers.

    Args:
        conn:    Open Http2Conn (mutated: stream counter + HPACK tables advance).
        method:  HTTP method ("GET", "POST", etc.).
        path:    Request path (e.g. "/").
        headers: Additional headers including ":authority: host".
        body:    Request body bytes (empty for GET/HEAD).

    Returns:
        (status_code, response_headers, response_body).

    Raises:
        Error on GOAWAY, RST_STREAM, TLS failure, or protocol violation.
    """
    var stream_id      = conn._next_stream
    conn._next_stream += 2

    # ── Build request headers ────────────────────────────────────────────────
    # Prepend :method, :path, :scheme; append caller headers (incl. :authority)
    var req_headers = List[HpackHeader]()
    req_headers.append(HpackHeader(":method", method))
    req_headers.append(HpackHeader(":path",   path))
    req_headers.append(HpackHeader(":scheme", "https"))
    for i in range(len(headers)):
        req_headers.append(HpackHeader(headers[i].name, headers[i].value))

    var hpack_block = hpack_encode_block(req_headers, conn._hpack_enc, False)
    var end_stream  = len(body) == 0
    var hf          = h2_make_headers_frame(stream_id, hpack_block, end_stream, True)
    _ = conn._tls.send(h2_frame_encode(hf))

    # ── Send DATA frames if body non-empty ───────────────────────────────────
    if len(body) > 0:
        var max_chunk = conn._peer_max_frame_size
        var sent      = 0
        var total     = len(body)
        while sent < total:
            var chunk_len = total - sent
            if chunk_len > max_chunk:
                chunk_len = max_chunk
            var chunk = List[UInt8](capacity=chunk_len)
            for i in range(chunk_len):
                chunk.append(body[sent + i])
            var is_last = (sent + chunk_len >= total)
            _ = conn._tls.send(h2_frame_encode(h2_make_data_frame(stream_id, chunk, is_last)))
            sent += chunk_len

    # ── Receive response ─────────────────────────────────────────────────────
    var resp_status:  Int               = 0
    var resp_headers: List[HpackHeader] = List[HpackHeader]()
    var resp_body:    List[UInt8]       = List[UInt8]()
    var hpack_accum:  List[UInt8]       = List[UInt8]()
    var got_end_stream = False

    while not got_end_stream:
        var f = _read_one_frame(conn)

        if f.frame_type == H2_HEADERS and f.stream_id == stream_id:
            var block = h2_get_hpack_block(f)
            for i in range(len(block)):
                hpack_accum.append(block[i])
            if Int(f.flags) & Int(H2_FLAG_END_HEADERS) != 0:
                var decoded = hpack_decode_block(hpack_accum, conn._hpack_dec)
                hpack_accum = List[UInt8]()
                for i in range(len(decoded)):
                    if decoded[i].name == ":status":
                        var s  = decoded[i].value
                        var n  = 0
                        var sb = s.as_bytes()
                        for j in range(len(sb)):
                            n = n * 10 + Int(sb[j]) - 48
                        resp_status = n
                    else:
                        resp_headers.append(
                            HpackHeader(decoded[i].name, decoded[i].value)
                        )
            if Int(f.flags) & Int(H2_FLAG_END_STREAM) != 0:
                got_end_stream = True

        elif f.frame_type == H2_CONTINUATION and f.stream_id == stream_id:
            for i in range(len(f.payload)):
                hpack_accum.append(f.payload[i])
            if Int(f.flags) & Int(H2_FLAG_END_HEADERS) != 0:
                var decoded = hpack_decode_block(hpack_accum, conn._hpack_dec)
                hpack_accum = List[UInt8]()
                for i in range(len(decoded)):
                    if decoded[i].name == ":status":
                        var s  = decoded[i].value
                        var n  = 0
                        var sb = s.as_bytes()
                        for j in range(len(sb)):
                            n = n * 10 + Int(sb[j]) - 48
                        resp_status = n
                    else:
                        resp_headers.append(
                            HpackHeader(decoded[i].name, decoded[i].value)
                        )

        elif f.frame_type == H2_DATA and f.stream_id == stream_id:
            var data_len = len(f.payload)
            for i in range(data_len):
                resp_body.append(f.payload[i])
            # Restore flow-control windows immediately after consuming DATA
            if data_len > 0:
                _ = conn._tls.send(
                    h2_frame_encode(h2_make_window_update(stream_id, data_len))
                )
                _ = conn._tls.send(
                    h2_frame_encode(h2_make_window_update(0, data_len))
                )
            if Int(f.flags) & Int(H2_FLAG_END_STREAM) != 0:
                got_end_stream = True

        elif f.frame_type == H2_WINDOW_UPDATE and f.stream_id == 0:
            conn._conn_window += h2_parse_window_update(f)

        elif f.frame_type == H2_PING \
                and Int(f.flags) & Int(H2_FLAG_ACK) == 0:
            _ = conn._tls.send(
                h2_frame_encode(h2_make_ping_frame(f.payload.copy(), True))
            )

        elif f.frame_type == H2_GOAWAY:
            var r = h2_parse_goaway(f)
            raise Error(
                "h2_request: GOAWAY last_stream_id="
                + String(r[0]) + " error_code=" + String(r[1])
            )

        elif f.frame_type == H2_RST_STREAM and f.stream_id == stream_id:
            raise Error(
                "h2_request: RST_STREAM error_code="
                + String(h2_parse_rst_stream(f))
            )
        # All other frame types: silently ignore

    return (resp_status, resp_headers^, resp_body^)
