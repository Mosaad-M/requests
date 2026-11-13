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
    h2_make_headers_frame, h2_make_data_frame, h2_get_hpack_block, h2_content_bounds,
    h2_make_window_update, h2_parse_window_update,
    h2_make_ping_frame,
    h2_parse_goaway, h2_parse_rst_stream, h2_make_rst_stream,
    H2_SETTING_MAX_CONCURRENT_STREAMS, H2_PUSH_PROMISE, H2_ERR_CANCEL,
)
from hpack import (
    HpackHeader, HpackDynTable,
    hpack_encode_block, hpack_decode_block,
)
from std.time import perf_counter_ns
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
    var _peer_max_concurrent: Int          # from peer SETTINGS_MAX_CONCURRENT_STREAMS
    var _goaway:              Bool         # peer sent GOAWAY: open no new streams, drop after use
    var _timeout_secs:        Int          # per-read socket timeout (restored after a deadline)

    def __init__(out self):
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
        self._peer_max_concurrent = 100
        self._goaway              = False
        self._timeout_secs        = 30

    def __init__(out self, *, deinit move: Self):
        self._tls                 = move._tls^
        self._next_stream         = move._next_stream
        self._hpack_enc           = move._hpack_enc^
        self._hpack_dec           = move._hpack_dec^
        self._peer_max_frame_size = move._peer_max_frame_size
        self._peer_initial_window = move._peer_initial_window
        self._conn_window         = move._conn_window
        self._peer_max_concurrent = move._peer_max_concurrent
        self._goaway              = move._goaway
        self._timeout_secs        = move._timeout_secs

    def close(mut self) raises:
        """Close the underlying TLS connection."""
        self._tls.close()


# ── Private helpers ───────────────────────────────────────────────────────────

def _read_one_frame(mut conn: Http2Conn) raises -> Http2Frame:
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
    if length > 16384:
        # 16384 is the SETTINGS_MAX_FRAME_SIZE we advertise (RFC 9113 §4.2)
        raise Error("h2: frame exceeds SETTINGS_MAX_FRAME_SIZE")
    var ftype  = hdr[3]
    var flags  = hdr[4]
    var sid    = (Int(hdr[5] & 0x7F) << 24) \
               | (Int(hdr[6])        << 16) \
               | (Int(hdr[7])        << 8)  \
               |  Int(hdr[8])
    var payload = List[UInt8]()
    if length > 0:
        payload = conn._tls.recv_exact(length)
    return Http2Frame(ftype, flags, sid, payload)


def _apply_settings(mut conn: Http2Conn, payload: List[UInt8]) raises -> Int:
    """Apply a peer SETTINGS payload to conn. Returns the change in
    SETTINGS_INITIAL_WINDOW_SIZE, which the caller must add to the send window
    of every open stream (RFC 9113 §6.9.2). The connection-level window is not
    touched: only WINDOW_UPDATE on stream 0 changes it."""
    var delta = 0
    var window = conn._peer_initial_window
    if len(payload) >= 6:
        var r    = h2_settings_decode(payload)
        var ids  = r[0].copy()
        var vals = r[1].copy()
        for i in range(len(ids)):
            if ids[i] == H2_SETTING_MAX_FRAME_SIZE:
                if vals[i] < 16384 or vals[i] > 16777215:
                    raise Error("h2: invalid SETTINGS_MAX_FRAME_SIZE")
                conn._peer_max_frame_size = vals[i]
            elif ids[i] == H2_SETTING_INITIAL_WINDOW_SIZE:
                if vals[i] > 2147483647:
                    raise Error("h2: invalid SETTINGS_INITIAL_WINDOW_SIZE")
                delta += vals[i] - window
                window = vals[i]
                conn._peer_initial_window = vals[i]
            elif ids[i] == H2_SETTING_HEADER_TABLE_SIZE:
                conn._hpack_enc.update_max_size(vals[i])
            elif ids[i] == H2_SETTING_MAX_CONCURRENT_STREAMS:
                conn._peer_max_concurrent = vals[i] if vals[i] > 0 else 1
    return delta


# ── Public API ────────────────────────────────────────────────────────────────

def h2_preface_and_settings_exchange(mut conn: Http2Conn) raises:
    """Send client connection preface + initial SETTINGS; read and ACK server SETTINGS.

    Called on a fresh Http2Conn whose _tls is already TLS-connected.
    Mutates conn's peer parameters (_peer_max_frame_size, _peer_initial_window,
    _conn_window, _hpack_enc table size) from the server's SETTINGS payload.

    Used by both h2_connect() and HttpClient (which manages its own TLS socket).

    Args:
        conn: Http2Conn with _tls already connected (preface not yet sent).

    Raises:
        Error if the TLS connection closes before server SETTINGS is received.
    """
    # Send 24-byte client connection preface magic + initial SETTINGS frame
    _ = conn._tls.send(h2_client_preface_bytes())
    _ = conn._tls.send(h2_frame_encode(h2_make_initial_settings()))

    # Server SETTINGS exchange — skip WINDOW_UPDATE or other frames that may
    # arrive before the server's SETTINGS (RFC 7540 §3.5 allows this)
    var got_server_settings = False
    while not got_server_settings:
        var f = _read_one_frame(conn)
        if f.frame_type == H2_SETTINGS \
                and f.stream_id == 0 \
                and Int(f.flags) & Int(H2_FLAG_ACK) == 0:
            _ = _apply_settings(conn, f.payload)
            # Send SETTINGS ACK
            _ = conn._tls.send(h2_frame_encode(h2_make_settings_ack()))
            got_server_settings = True


def h2_connect(host: String, port: Int = 443) raises -> Http2Conn:
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

    # 3. TLS handshake with ALPN "h2"
    var alpn = List[String]()
    alpn.append("h2")
    var tls = TlsSocket(tcp.detach())
    tls.connect(host, ca, alpn_protocols=alpn)

    # 4. Reject explicit HTTP/1.1 downgrade
    var proto = tls.negotiated_protocol()
    if proto == "http/1.1":
        raise Error(
            "h2_connect: server negotiated http/1.1 via ALPN, expected h2"
        )

    # 5. Create conn; move real TLS socket in; run preface + SETTINGS exchange
    var conn  = Http2Conn()
    conn._tls = tls^
    h2_preface_and_settings_exchange(conn)
    return conn^




# ── Requests and responses ────────────────────────────────────────────────────

comptime H2_DEFAULT_MAX_BODY   = 100 * 1024 * 1024  # same as HttpClient.max_response_bytes
comptime H2_DEFAULT_MAX_HEADER = 1024 * 1024        # same as HttpClient.max_header_bytes


struct H2Request(Copyable, Movable):
    """One request for h2_request_many. `headers` carries ":authority"; the
    :method, :path and :scheme pseudo-headers are added by h2_request_many."""

    var method:  String
    var path:    String
    var headers: List[HpackHeader]
    var body:    List[UInt8]

    def __init__(
        out self,
        method: String,
        path: String,
        headers: List[HpackHeader],
        body: List[UInt8],
    ):
        self.method  = method
        self.path    = path
        self.headers = headers.copy()
        self.body    = body.copy()

    def __init__(out self, *, copy: Self):
        self.method  = copy.method
        self.path    = copy.path
        self.headers = copy.headers.copy()
        self.body    = copy.body.copy()

    def __init__(out self, *, deinit move: Self):
        self.method  = move.method^
        self.path    = move.path^
        self.headers = move.headers^
        self.body    = move.body^


struct H2Response(Copyable, Movable):
    """Outcome of one request in a batch. `error` is empty on success; a
    non-empty error (RST_STREAM, GOAWAY, size limit) fails only this stream.
    An error starting with "GOAWAY" or "REFUSED_STREAM" means the server did
    not process the request, so it is safe to send again on another connection."""

    var status:  Int
    var headers: List[HpackHeader]
    var body:    List[UInt8]
    var error:   String

    def __init__(out self):
        self.status  = 0
        self.headers = List[HpackHeader]()
        self.body    = List[UInt8]()
        self.error   = String("")

    def __init__(out self, *, copy: Self):
        self.status  = copy.status
        self.headers = copy.headers.copy()
        self.body    = copy.body.copy()
        self.error   = copy.error

    def __init__(out self, *, deinit move: Self):
        self.status  = move.status
        self.headers = move.headers^
        self.body    = move.body^
        self.error   = move.error^


def _arm_read(mut conn: Http2Conn, deadline_ns: Int) raises:
    """Before a read: fail once deadline_ns (perf_counter_ns instant, 0 = none)
    has passed, and cap the socket timeout to the time left."""
    if deadline_ns != 0:
        var left = deadline_ns - Int(perf_counter_ns())
        if left <= 0:
            raise Error("TimeoutError: total timeout exceeded")
        conn._tls.set_timeout(min(conn._timeout_secs, (left + 999_999_999) // 1_000_000_000))


def _status_of(headers: List[HpackHeader]) -> Int:
    for i in range(len(headers)):
        if headers[i].name == ":status":
            var n  = 0
            var sb = headers[i].value.as_bytes()
            if len(sb) != 3:
                return -1
            for j in range(len(sb)):
                if sb[j] < 48 or sb[j] > 57:
                    return -1
                n = n * 10 + Int(sb[j]) - 48
            return n
    return 0


def _send_frame(mut conn: Http2Conn, frame: Http2Frame) raises:
    """Write one frame. A frame with a full 16384-byte payload is 16393 bytes
    with its header, over TLS's 16384-byte plaintext record limit, so it goes
    out in pieces (the peer reassembles the byte stream)."""
    var wire = h2_frame_encode(frame)
    var n = len(wire)
    if n <= 16384:
        _ = conn._tls.send(wire)
        return
    var off = 0
    while off < n:
        var take = min(16384, n - off)
        var piece = List[UInt8](capacity=take)
        for i in range(take):
            piece.append(wire[off + i])
        _ = conn._tls.send(piece)
        off += take


def _read_frame_by(mut conn: Http2Conn, deadline_ns: Int) raises -> Http2Frame:
    """Read one frame, failing with TimeoutError once deadline_ns passes. The
    socket timeout is whole seconds, so a read can time out a hair before the
    deadline instant: a timeout within a second of it counts as the deadline."""
    _arm_read(conn, deadline_ns)
    try:
        return _read_one_frame(conn)
    except e:
        var es = String(e)
        if deadline_ns != 0 and not es.startswith("TimeoutError"):
            var now = Int(perf_counter_ns())
            if now >= deadline_ns or (now + 1_000_000_000 >= deadline_ns and "timed out" in es):
                raise Error("TimeoutError: total timeout exceeded (" + es + ")")
        raise e^


def h2_request_many(
    mut conn:    Http2Conn,
    reqs:        List[H2Request],
    max_body:    Int = H2_DEFAULT_MAX_BODY,
    max_header:  Int = H2_DEFAULT_MAX_HEADER,
    deadline_ns: Int = 0,
    max_total:   Int = 0,
) raises -> List[H2Response]:
    """Send several requests at once on one connection and collect the responses.

    Streams are opened in order, up to the peer's SETTINGS_MAX_CONCURRENT_STREAMS
    at a time, and their frames interleave on the wire. Request bodies obey the
    peer's flow-control windows. A stream that fails (RST_STREAM, GOAWAY for
    streams the peer did not accept, a body over max_body) gets its own
    H2Response.error and does not disturb the others. A connection-level
    failure (TLS error, malformed frame, header block over max_header, deadline)
    raises and leaves conn unusable.

    Args:
        conn:        Open Http2Conn (stream counter, HPACK tables and windows advance).
        reqs:        Requests; responses come back in the same order.
        max_body:    Largest response body per stream.
        max_header:  Largest header block per response (compressed and decoded).
        deadline_ns: perf_counter_ns() instant by which everything must finish (0 = none).
        max_total:   Most response body bytes held across the whole batch (0 = no
                     limit); the stream that would pass it fails with "batch size limit".
    """
    var n = len(reqs)
    var out = List[H2Response]()
    var started  = List[Bool]()
    var done     = List[Bool]()
    var sent     = List[Int]()     # request body bytes already sent
    var swin     = List[Int]()     # outbound stream window
    var got_hdrs = List[Bool]()    # final (non-1xx) response headers seen
    var hsize    = List[Int]()     # decoded header bytes kept per stream (trailers included)
    var total    = 0               # body bytes held across the batch
    for _ in range(n):
        out.append(H2Response())
        started.append(False)
        done.append(False)
        sent.append(0)
        swin.append(0)
        got_hdrs.append(False)
        hsize.append(0)

    var first_id  = conn._next_stream
    var nstart    = 0               # streams opened so far; stream id of i is first_id + 2*i
    var ndone     = 0
    var active    = 0
    var uploading = 0               # started streams whose request body is not fully sent
    var pend_sid  = 0               # header block in progress (HEADERS + CONTINUATION)
    var pend_es   = False
    var pend_acc  = List[UInt8]()
    var have_pend = False

    while ndone < n:
        # ── Open streams ────────────────────────────────────────────────
        while nstart < n and active < conn._peer_max_concurrent and not conn._goaway:
            var i = nstart
            var sid = conn._next_stream
            conn._next_stream += 2
            var req_headers = List[HpackHeader]()
            req_headers.append(HpackHeader(":method", reqs[i].method))
            req_headers.append(HpackHeader(":path",   reqs[i].path))
            req_headers.append(HpackHeader(":scheme", "https"))
            for k in range(len(reqs[i].headers)):
                req_headers.append(
                    HpackHeader(reqs[i].headers[k].name, reqs[i].headers[k].value)
                )
            var block = hpack_encode_block(req_headers, conn._hpack_enc, False)
            if len(block) > conn._peer_max_frame_size:
                # No CONTINUATION on send. Streams already opened must keep their
                # turn in the HPACK state, which this block already advanced.
                raise Error("h2: request headers exceed the peer's maximum frame size")
            var no_body = len(reqs[i].body) == 0
            _send_frame(conn, h2_make_headers_frame(sid, block, no_body, True))
            started[i] = True
            swin[i] = conn._peer_initial_window
            if not no_body:
                uploading += 1
            nstart += 1
            active += 1

        if conn._goaway:
            # Streams the peer never saw: report them so the caller can resend.
            for i in range(nstart, n):
                out[i].error = String("GOAWAY: stream not opened")
                done[i] = True
                ndone += 1
            nstart = n

        # ── Send request bodies as far as the windows allow ──────────────
        if uploading > 0:
            for i in range(nstart):
                if done[i] or sent[i] >= len(reqs[i].body):
                    continue
                var sid = first_id + 2 * i
                while sent[i] < len(reqs[i].body):
                    var chunk_len = len(reqs[i].body) - sent[i]
                    chunk_len = min(chunk_len, conn._peer_max_frame_size)
                    chunk_len = min(chunk_len, conn._conn_window)
                    chunk_len = min(chunk_len, swin[i])
                    if chunk_len <= 0:
                        break
                    var chunk = List[UInt8](capacity=chunk_len)
                    for k in range(chunk_len):
                        chunk.append(reqs[i].body[sent[i] + k])
                    var last = sent[i] + chunk_len >= len(reqs[i].body)
                    _send_frame(conn, h2_make_data_frame(sid, chunk, last))
                    sent[i] += chunk_len
                    swin[i] -= chunk_len
                    conn._conn_window -= chunk_len
                    if last:
                        uploading -= 1

        if ndone >= n:
            break

        # ── Read one frame and route it ───────────────────────────────────
        var f = _read_frame_by(conn, deadline_ns)
        var sid = f.stream_id
        var idx = -1
        if sid > 0 and (sid & 1) == 1 and sid >= first_id:
            var k = (sid - first_id) // 2
            if k < nstart:
                idx = k

        if have_pend and f.frame_type != H2_CONTINUATION:
            raise Error("h2: header block interrupted by another frame")

        if f.frame_type == H2_HEADERS or f.frame_type == H2_CONTINUATION:
            if f.frame_type == H2_HEADERS:
                have_pend = True
                pend_sid  = sid
                pend_es   = Int(f.flags) & Int(H2_FLAG_END_STREAM) != 0
                pend_acc  = List[UInt8]()
            elif not have_pend or sid != pend_sid:
                raise Error("h2: unexpected CONTINUATION")
            var part = h2_get_hpack_block(f)
            if len(pend_acc) + len(part) > max_header:
                raise Error("h2: response headers exceed size limit")
            for k in range(len(part)):
                pend_acc.append(part[k])
            if Int(f.flags) & Int(H2_FLAG_END_HEADERS) != 0:
                have_pend = False
                # Always decode: the HPACK table must see every block, even for
                # streams already finished.
                var decoded = hpack_decode_block(pend_acc, conn._hpack_dec, max_header)
                pend_acc = List[UInt8]()
                if idx >= 0 and not done[idx]:
                    var status = _status_of(decoded)
                    if status < 0:
                        raise Error("h2: malformed :status")
                    if status >= 100 and status < 200:
                        pass  # interim response: the final one follows
                    else:
                        if not got_hdrs[idx]:
                            out[idx].status = status
                        got_hdrs[idx] = True
                        for k in range(len(decoded)):
                            if decoded[k].name != ":status":
                                hsize[idx] += decoded[k].name.byte_length() + decoded[k].value.byte_length() + 32
                                out[idx].headers.append(
                                    HpackHeader(decoded[k].name, decoded[k].value)
                                )
                        if hsize[idx] > max_header:
                            # Trailer blocks each fit the limit; together they must too.
                            out[idx].error = String("response headers exceed size limit")
                            _send_frame(conn, h2_make_rst_stream(sid, H2_ERR_CANCEL))
                            done[idx] = True
                            ndone += 1
                            active -= 1
                            if sent[idx] < len(reqs[idx].body):
                                uploading -= 1
                            continue
                    if pend_es:
                        if not got_hdrs[idx]:
                            out[idx].error = String("response ended without headers")
                        done[idx] = True
                        ndone += 1
                        active -= 1
                        if sent[idx] < len(reqs[idx].body):
                            # Answered before the upload finished (e.g. 413): tell
                            # the peer to stop, or it keeps counting the stream.
                            uploading -= 1
                            _send_frame(conn, h2_make_rst_stream(sid, 0))

        elif f.frame_type == H2_DATA:
            # padding is not data (RFC 9113 §6.1), but counts for flow control
            var data_len = len(f.payload)
            var ends = Int(f.flags) & Int(H2_FLAG_END_STREAM) != 0
            if data_len > 0:
                _send_frame(conn, h2_make_window_update(0, data_len))
                if idx >= 0 and not done[idx] and not ends:
                    _send_frame(conn, h2_make_window_update(sid, data_len))
            if idx >= 0 and not done[idx]:
                var b = h2_content_bounds(f)
                var over_total = max_total > 0 and total + (b[1] - b[0]) > max_total
                if over_total or len(out[idx].body) + (b[1] - b[0]) > max_body:
                    out[idx].error = (
                        String("batch size limit") if over_total
                        else String("response body exceeds size limit")
                    )
                    _send_frame(conn, h2_make_rst_stream(sid, H2_ERR_CANCEL))
                    done[idx] = True
                    ndone += 1
                    active -= 1
                    if sent[idx] < len(reqs[idx].body):
                        uploading -= 1
                else:
                    total += b[1] - b[0]
                    for k in range(b[0], b[1]):
                        out[idx].body.append(f.payload[k])
                    if ends:
                        done[idx] = True
                        ndone += 1
                        active -= 1
                        if sent[idx] < len(reqs[idx].body):
                            uploading -= 1
                            _send_frame(conn, h2_make_rst_stream(sid, 0))

        elif f.frame_type == H2_WINDOW_UPDATE:
            var inc = h2_parse_window_update(f)
            if sid == 0:
                conn._conn_window += inc
                if conn._conn_window > 2147483647:
                    raise Error("h2: connection flow-control window overflow")
            elif idx >= 0:
                swin[idx] += inc
                if swin[idx] > 2147483647:
                    raise Error("h2: stream flow-control window overflow")

        elif f.frame_type == H2_SETTINGS:
            if Int(f.flags) & Int(H2_FLAG_ACK) == 0:
                var delta = _apply_settings(conn, f.payload)
                if delta != 0:
                    for i in range(nstart):
                        if not done[i]:
                            swin[i] += delta
                _send_frame(conn, h2_make_settings_ack())

        elif f.frame_type == H2_PING:
            if Int(f.flags) & Int(H2_FLAG_ACK) == 0:
                _ = conn._tls.send(
                    h2_frame_encode(h2_make_ping_frame(f.payload.copy(), True))
                )

        elif f.frame_type == H2_GOAWAY:
            var r = h2_parse_goaway(f)
            conn._goaway = True
            for i in range(nstart):
                if not done[i] and first_id + 2 * i > r[0]:
                    out[i].error = (
                        String("GOAWAY last_stream_id=") + String(r[0])
                        + " error_code=" + String(r[1])
                    )
                    done[i] = True
                    ndone += 1
                    active -= 1
                    if sent[i] < len(reqs[i].body):
                        uploading -= 1

        elif f.frame_type == H2_RST_STREAM:
            if idx >= 0 and not done[idx]:
                var code = h2_parse_rst_stream(f)
                out[idx].error = (
                    String("REFUSED_STREAM error_code=7") if code == 7
                    else String("RST_STREAM error_code=") + String(code)
                )
                done[idx] = True
                ndone += 1
                active -= 1
                if sent[idx] < len(reqs[idx].body):
                    uploading -= 1

        elif f.frame_type == H2_PUSH_PROMISE:
            # We sent ENABLE_PUSH=0, and a promise cannot be skipped without
            # decoding its header block.
            raise Error("h2: PUSH_PROMISE received although push is disabled")
        # PRIORITY and unknown frame types: ignored (RFC 9113 §4.1)

    if deadline_ns != 0:
        conn._tls.set_timeout(conn._timeout_secs)
    return out^


def h2_request(
    mut conn:    Http2Conn,
    method:      String,
    path:        String,
    headers:     List[HpackHeader],
    body:        List[UInt8],
    max_body:    Int = H2_DEFAULT_MAX_BODY,
    max_header:  Int = H2_DEFAULT_MAX_HEADER,
    deadline_ns: Int = 0,
) raises -> Tuple[Int, List[HpackHeader], List[UInt8]]:
    """Send an HTTP/2 request and receive the complete response.

    The caller must include ":authority" in `headers`.  This function
    prepends :method, :path, :scheme pseudo-headers before the caller
    headers, so :authority appears immediately after the pseudo-headers.
    A one-request h2_request_many.

    Args:
        conn:    Open Http2Conn (mutated: stream counter + HPACK tables advance).
        method:  HTTP method ("GET", "POST", etc.).
        path:    Request path (e.g. "/").
        headers: Additional headers including ":authority: host".
        body:    Request body bytes (empty for GET/HEAD).
        max_body, max_header, deadline_ns: as for h2_request_many.

    Returns:
        (status_code, response_headers, response_body).

    Raises:
        Error on GOAWAY, RST_STREAM, a size limit, TLS failure, or protocol violation.
    """
    var reqs = List[H2Request]()
    reqs.append(H2Request(method, path, headers, body))
    var res = h2_request_many(conn, reqs, max_body, max_header, deadline_ns)
    if res[0].error.byte_length() > 0:
        raise Error("h2_request: " + res[0].error)
    return (res[0].status, res[0].headers.copy(), res[0].body.copy())
