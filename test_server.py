"""Simple HTTP test server for Mojo HTTP client tests.

Runs on localhost:18080 and handles various test endpoints.
Start before running test_client.mojo.

Usage: python test_server.py
"""

import http.server
import time
import json
import sys
import threading
import time
import urllib.parse

# Resilience endpoints (test_resilience.mojo): per-id hit counters.
_HITS = {}
_HITS_LOCK = threading.Lock()
_RESILIENCE_PATHS = (
    "/flaky", "/hits", "/slowdrip", "/delay", "/reset", "/bigbody",
    "/bigchunked", "/bigclose", "/bighdr", "/slow-redirect",
)


def _stale_keepalive_server(port=18082):
    """Raw HTTP/1.1 listener for pooled-connection tests (test_resilience.mojo).
    Most paths: answer one request, claim keep-alive, then close, so the client
    pools a dead connection. Paths starting /live keep the connection open;
    /live-stall then holds each reply for 6 s.
    Each request received bumps hit counter "ka" + path."""
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def one(conn):
        try:
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, rest = buf.partition(b"\r\n\r\n")
                lines = head.split(b"\r\n")
                path = lines[0].split(b" ")[1].decode()
                need = 0
                for ln in lines[1:]:
                    if ln.lower().startswith(b"content-length:"):
                        need = int(ln.split(b":")[1])
                while len(rest) < need:
                    rest += conn.recv(4096)
                buf = rest[need:]
                _hit("ka" + path)
                if path.startswith("/live-stall"):
                    time.sleep(6)  # a pooled connection that stalls mid-request
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
                if not path.startswith("/live"):
                    return  # claimed keep-alive, but closes: the next request finds a dead socket
        except OSError:
            pass
        finally:
            conn.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def _framing_server(port=18083):
    """Raw keep-alive listener for response-framing tests (test_framing.mojo).
    Each path sends one crafted response and keeps the connection open. A float
    in a response is a pause in seconds: the head and the body are then written
    separately, so a client cannot get the right body by luck (head and body in
    the same read)."""
    import socket
    H = b"HTTP/1.1 200 OK\r\n"
    CH = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    Y = b"y" * 100000
    R = {
        "/ok": [H + b"Content-Length: 2\r\n\r\nok"],
        # must keep working
        "/val-cl": [H + b"X-Note: see content-length: 5\r\nContent-Length: 100000\r\n\r\n" + Y],
        "/val-te": [H + b"Set-Cookie: a=b; note=transfer-encoding: chunked\r\nContent-Length: 3000\r\n\r\n" + b"a" * 3000],
        "/fold": [H + b"X-Long: a\r\n content-length: 5\r\nContent-Length: 100000\r\n\r\n" + Y],
        "/mixed-case": [H + b"X-A: 1\r\nCoNtEnT-LeNgTh: 100000\r\n\r\n" + Y],
        "/cl-first": [H + b"Content-Length: 100000\r\nX-A: 1\r\n\r\n" + Y],
        "/te-last": [H + b"X-A: 1\r\nTransfer-Encoding: chunked\r\n\r\n" + CH],
        "/te-mid": [H + b"Transfer-Encoding: chunked\r\nX-A: 1\r\n\r\n" + CH],
        "/te-upper": [H + b"TRANSFER-ENCODING: Chunked\r\n\r\n" + CH],
        "/te-identity-chunked": [H + b"Transfer-Encoding: identity, chunked\r\n\r\n" + CH],
        "/te-identity-cl": [H + b"Transfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nhello"],
        "/dup-cl-same": [H + b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello"],
        "/cl-list": [H + b"Content-Length: 5, 5\r\n\r\nhello"],
        # must now be rejected
        "/dup-cl-diff": [H + b"Content-Length: 5\r\nContent-Length: 100000\r\n\r\n", 0.2, Y],
        "/cl-list-diff": [H + b"Content-Length: 5, 6\r\n\r\n", 0.2, b"hello!"],
        "/cl-abc": [H + b"Content-Length: abc\r\n\r\n", 0.2, b"hello"],
        "/cl-plus": [H + b"Content-Length: +5\r\n\r\n", 0.2, b"hello"],
        "/cl-neg": [H + b"Content-Length: -1\r\n\r\n", 0.2, b"hello"],
        "/cl-empty": [H + b"Content-Length:\r\n\r\n", 0.2, b"hello"],
        "/cl-space-colon": [H + b"Content-Length : 5\r\n\r\n", 0.2, b"hello"],
        "/te-space-colon": [H + b"Transfer-Encoding : chunked\r\n\r\n", 0.2, CH],
        "/fold-in-cl": [H + b"Content-Length: 5\r\n 5\r\n\r\n", 0.2, b"hello"],
        "/te-gzip-chunked": [H + b"Transfer-Encoding: gzip, chunked\r\n\r\n", 0.2, CH],
        "/te-notchunked": [H + b"Transfer-Encoding: notchunked\r\n\r\n", 0.2, CH],
        # accepted, with a safe outcome
        "/cl-and-te": [H + b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", 0.2, CH],
        "/cl-and-te-stray": [H + b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", 0.2, CH, 0.2, b"zz"],
        # announces 200 MB, sends 10 bytes: shows which limit stops the client
        "/cl-huge": [H + b"Content-Length: 200000000\r\n\r\n", 0.2, b"x" * 10],
        "/extra-after-body": [H + b"Content-Length: 5\r\n\r\nhello\r\n"],
        # a second response starts inside the first one and ends later
        "/smuggled": [H + b"Content-Length: 5\r\n\r\nhello" + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", 0.2, b"ok"],
        "/trailers": [H + b"Transfer-Encoding: chunked\r\n\r\n", 0.2,
                      b"5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n"],
        # the trailer section arrives in two pieces
        "/trailers-split": [H + b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-", 0.2,
                            b"Trailer: 1\r\n\r\n"],
    }
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def one(conn):
        try:
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b"\r\n\r\n")
                method = head.split(b"\r\n")[0].split(b" ")[0].decode()
                path = head.split(b"\r\n")[0].split(b" ")[1].decode()
                need = 0
                for ln in head.split(b"\r\n")[1:]:
                    if ln.lower().startswith(b"content-length:"):
                        need = int(ln.split(b":")[1])
                while len(buf) < need:
                    buf += conn.recv(4096)
                buf = buf[need:]
                if method == "HEAD":  # headers only, with the length a GET would have
                    conn.sendall(H + b"Content-Length: 5\r\nTransfer-Encoding-Test: 1\r\n\r\n")
                    continue
                for part in R.get(path, R["/ok"]):
                    if isinstance(part, float):
                        time.sleep(part)
                    else:
                        conn.sendall(part)
        except OSError:
            pass
        finally:
            conn.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def _hit(key):
    with _HITS_LOCK:
        _HITS[key] = _HITS.get(key, 0) + 1
        return _HITS[key]


class TestHandler(http.server.BaseHTTPRequestHandler):
    def _resilience(self):
        """Endpoints for retry / deadline / size-limit tests. Query: id, n, ms, ..."""
        url = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        path = url.path
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        ident = q.get("id", "default")

        def reply(code, body=b"{}", headers=()):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        if path == "/hits":
            with _HITS_LOCK:
                reply(200, json.dumps({"hits": _HITS.get(ident, 0)}).encode())
        elif path == "/flaky":
            # First n requests with this id fail with `code` (default 503), then 200.
            hit = _hit(ident)
            if hit <= int(q.get("n", 1)):
                extra = [("Retry-After", q["retry_after"])] if "retry_after" in q else []
                reply(int(q.get("code", 503)), b'{"flaky":true}', extra)
            else:
                reply(200, json.dumps({"attempts": hit}).encode())
        elif path == "/reset":
            # Promise a body, send part of it, then drop the connection.
            hit = _hit(ident)
            if hit <= int(q.get("n", 1)):
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"partial")
                self.wfile.flush()
                self.connection.shutdown(2)
            else:
                reply(200, b'{"recovered":true}')
        elif path == "/delay":
            time.sleep(int(q.get("ms", 0)) / 1000.0)
            reply(200, b'{"delayed":true}')
        elif path == "/slowdrip":
            # Chunked body, one chunk every gap_ms: it never stalls, so only a
            # total deadline (not a socket timeout) can stop the client.
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for _ in range(int(q.get("chunks", 10))):
                    self.wfile.write(b"1\r\nx\r\n")
                    self.wfile.flush()
                    time.sleep(int(q.get("gap_ms", 100)) / 1000.0)
                self.wfile.write(b"0\r\n\r\n")
            except OSError:
                pass
        elif path == "/slow-redirect":
            time.sleep(int(q.get("ms", 0)) / 1000.0)
            hops = int(q.get("hops", 0))
            if hops > 0:
                nxt = "/slow-redirect?hops=%d&ms=%s" % (hops - 1, q.get("ms", 0))
                reply(302, b"", [("Location", nxt)])
            else:
                reply(200, b'{"arrived":true}')
        elif path == "/bigbody":
            reply(200, b"x" * (int(q.get("kb", 1)) * 1024))
        elif path == "/bigchunked":
            kb = int(q.get("kb", 1))
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            for _ in range(kb):
                self.wfile.write(b"400\r\n" + b"x" * 1024 + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/bigclose":
            # No Content-Length, not chunked: the body ends when the socket closes.
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"x" * (int(q.get("kb", 1)) * 1024))
        elif path == "/bighdr":
            reply(200, b"{}", [("X-Big", "a" * (int(q.get("kb", 1)) * 1024))])
        else:
            reply(404)

    def do_GET(self):
        if self.path.startswith(_RESILIENCE_PATHS):
            self._resilience()
        elif self.path == "/":
            self._respond(200, "OK", {"message": "hello from test server"})
        elif self.path == "/status/200":
            self._respond(200, "OK", {"status": 200})
        elif self.path == "/status/404":
            self._respond(404, "Not Found", {"error": "not found"})
        elif self.path == "/status/500":
            self._respond(500, "Internal Server Error", {"error": "server error"})
        elif self.path == "/headers":
            # Echo back all request headers
            headers = {}
            for key, value in self.headers.items():
                headers[key] = value
            self._respond(200, "OK", {"headers": headers})
        elif self.path == "/large":
            # Return a large response body
            body = "x" * 100000
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
            return
        elif self.path == "/chunked":
            body = json.dumps({"message": "chunked response", "count": 42})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.end_headers()
            # Send body in two chunks
            mid = len(body) // 2
            chunk1 = body[:mid]
            chunk2 = body[mid:]
            self.wfile.write(f"{len(chunk1):x}\r\n".encode())
            self.wfile.write(chunk1.encode() + b"\r\n")
            self.wfile.write(f"{len(chunk2):x}\r\n".encode())
            self.wfile.write(chunk2.encode() + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        elif self.path.startswith("/echo?"):
            # Echo back query string
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            self._respond(200, "OK", {"query": query})
        elif self.path == "/method":
            self._respond(200, "OK", {"method": "GET"})
        elif self.path == "/meta-content-length":
            # A header whose name *ends* in Content-Length, sent first, with a
            # body too large to arrive in the first read.
            body = b"y" * 100000
            self.send_response(200)
            self.send_header("X-Amz-Meta-Content-Length", "5")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/chunked-te-last":
            # Transfer-Encoding as the *last* header (S3 orders it so), on a
            # connection the server keeps open: the client must stop at the
            # last chunk, not wait for the close.
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            )
            self.wfile.flush()
            time.sleep(4)
            self.close_connection = True
        elif self.path == "/redirect/301":
            self.send_response(301, "Moved Permanently")
            self.send_header("Location", "/redirect/target")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/302":
            self.send_response(302, "Found")
            self.send_header("Location", "/redirect/target")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/303":
            self.send_response(303, "See Other")
            self.send_header("Location", "/redirect/target")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/307":
            self.send_response(307, "Temporary Redirect")
            self.send_header("Location", "/redirect/target")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/308":
            self.send_response(308, "Permanent Redirect")
            self.send_header("Location", "/redirect/target")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/target":
            self._respond(200, "OK", {"message": "redirect target", "method": "GET"})
        elif self.path == "/redirect/multi":
            # First hop of a 2-hop chain: /redirect/multi → /redirect/301 → /redirect/target
            self.send_response(302, "Found")
            self.send_header("Location", "/redirect/301")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/loop":
            self.send_response(302, "Found")
            self.send_header("Location", "/redirect/loop")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/auth-strip":
            # Redirect to a different host (simulated as relative, check headers)
            self.send_response(302, "Found")
            self.send_header("Location", "/headers")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/gzip":
            import gzip as _gzip
            body = json.dumps({"encoding": "gzip", "message": "hello compressed"})
            compressed = _gzip.compress(body.encode())
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(compressed)))
            self.send_header("Connection", "close")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.end_headers()
            self.wfile.write(compressed)
        elif self.path == "/gzip-large":
            import gzip as _gzip
            # 50 KB of semi-random printable ASCII — compresses to ~60-70%
            # (ratio ~1.5–2:1, well under the 256× decompression cap)
            import string as _string
            chars = (_string.ascii_letters + _string.digits + " .,;:!?") * 800
            large_body = chars[:50000]
            compressed = _gzip.compress(large_body.encode())
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(compressed)))
            self.send_header("Connection", "close")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.end_headers()
            self.wfile.write(compressed)
        elif self.path == "/deflate":
            import zlib as _zlib
            body = json.dumps({"encoding": "deflate", "message": "hello compressed"})
            compressed = _zlib.compress(body.encode())
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "deflate")
            self.send_header("Content-Length", str(len(compressed)))
            self.send_header("Connection", "close")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.end_headers()
            self.wfile.write(compressed)
        elif self.path == "/identity":
            body = json.dumps({"encoding": "identity", "message": "plain text"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "identity")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/accept-encoding":
            ae = self.headers.get("Accept-Encoding", "")
            self._respond(200, "OK", {"accept_encoding": ae})
        elif self.path == "/set-cookie":
            body = json.dumps({"message": "cookie set"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=abc123")
            self.send_header("Connection", "close")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/check-cookie":
            cookie = self.headers.get("Cookie", "")
            self._respond(200, "OK", {"cookie": cookie})
        elif self.path == "/set-cookie-max-age":
            body = json.dumps({"message": "cookie with max-age set"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "temp=xyz; Max-Age=3600")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-zero":
            body = json.dumps({"message": "delete cookie"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=abc123; Max-Age=0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-path":
            body = json.dumps({"message": "cookie with path set"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "pathcookie=yes; Path=/api")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/api/check-cookie":
            cookie = self.headers.get("Cookie", "")
            self._respond(200, "OK", {"cookie": cookie})
        elif self.path == "/set-cookie-secure":
            body = json.dumps({"message": "secure cookie set"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "securecookie=yes; Secure")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-samesite":
            body = json.dumps({"message": "samesite strict cookie set"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "samesite_cookie=yes; SameSite=Strict")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-samesite-none":
            body = json.dumps({"message": "samesite none cookie set"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "none_cookie=yes; SameSite=None; Secure")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/brotli":
            try:
                import brotli as _brotli
                body = json.dumps({"encoding": "brotli", "message": "hello brotli"})
                compressed = _brotli.compress(body.encode())
                self.send_response(200, "OK")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Encoding", "br")
                self.send_header("Content-Length", str(len(compressed)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(compressed)
            except ImportError:
                self._respond(503, "Service Unavailable", {"error": "brotli not installed"})
        elif self.path == "/zstd":
            try:
                import zstandard as _zstd
                body = json.dumps({"encoding": "zstd", "message": "hello zstd"})
                cctx = _zstd.ZstdCompressor()
                compressed = cctx.compress(body.encode())
                self.send_response(200, "OK")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Encoding", "zstd")
                self.send_header("Content-Length", str(len(compressed)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(compressed)
            except ImportError:
                self._respond(503, "Service Unavailable", {"error": "zstandard not installed"})
        elif self.path == "/stream/medium":
            body = b"A" * (256 * 1024)
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        elif self.path == "/redirect/to-private":
            # Redirect to a private IP with no open port — connection refused
            # 10.255.255.254 is reachable (private range) but port 80 is closed
            self.send_response(302, "Found")
            self.send_header("Location", "http://10.255.255.254/")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/set-cookie-tld":
            # Set-Cookie with a single-label (TLD) domain — should be rejected
            body = json.dumps({"message": "tld domain cookie"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "bad=1; Domain=.com")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-psl-co-uk":
            # Set-Cookie with a PSL public suffix domain — should be rejected
            body = json.dumps({"message": "psl co.uk cookie"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "psl=1; Domain=.co.uk")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-psl-github-io":
            # Set-Cookie with a PSL hosting suffix — should be rejected
            body = json.dumps({"message": "psl github.io cookie"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "psl=1; Domain=.github.io")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-psl-example-co-uk":
            # Set-Cookie with a valid registrable domain under a PSL suffix — accepted
            body = json.dumps({"message": "psl example.co.uk cookie"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "psl=1; Domain=.example.co.uk")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-httponly":
            body = json.dumps({"message": "httponly cookie"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "secret=abc; HttpOnly")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/set-cookie-samesite-strict":
            body = json.dumps({"message": "samesite strict normalized"})
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "ss=1; SameSite=STRICT")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/oversized-cl":
            # Claim a Content-Length far larger than MAX_RESPONSE_BYTES to trigger limit
            body = b"small"
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "999999999")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/shutdown":
            self._respond(200, "OK", {"message": "shutting down"})
            # Schedule shutdown
            import threading
            threading.Thread(target=self.server.shutdown).start()
        else:
            self._respond(404, "Not Found", {"error": "unknown path"})

    def _handle_echo(self):
        """Handle /echo endpoint — echo back method, body, and content-type."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        content_type = self.headers.get("Content-Type", "")
        self._respond(200, "OK", {
            "method": self.command,
            "body": body,
            "content_type": content_type,
        })

    def _handle_method(self):
        """Handle /method endpoint — return the HTTP method used."""
        self._respond(200, "OK", {"method": self.command})

    def _route_non_get(self):
        """Route POST/PUT/DELETE/PATCH requests."""
        if self.path.startswith(_RESILIENCE_PATHS):
            self._resilience()
        elif self.path == "/echo":
            self._handle_echo()
        elif self.path == "/method":
            self._handle_method()
        elif self.path == "/redirect/307":
            self.send_response(307, "Temporary Redirect")
            self.send_header("Location", "/echo")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/redirect/308":
            self.send_response(308, "Permanent Redirect")
            self.send_header("Location", "/echo")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            self._respond(404, "Not Found", {"error": "unknown path"})

    def do_HEAD(self):
        # HEAD returns same headers as GET but no body
        if self.path == "/":
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Test-Server", "mojo-test/1.0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif self.path == "/status/200":
            self.send_response(200, "OK")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            self.send_response(404, "Not Found")
            self.send_header("Connection", "close")
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200, "OK")
        self.send_header("Allow", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.send_header("X-Test-Server", "mojo-test/1.0")
        self.end_headers()

    def do_POST(self):
        self._route_non_get()

    def do_PUT(self):
        self._route_non_get()

    def do_DELETE(self):
        self._route_non_get()

    def do_PATCH(self):
        self._route_non_get()

    def _respond(self, code, message, body_dict):
        body = json.dumps(body_dict)
        self.send_response(code, message)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Test-Server", "mojo-test/1.0")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        # Suppress default logging
        pass


def main():
    port = 18080
    threading.Thread(target=_stale_keepalive_server, daemon=True).start()
    threading.Thread(target=_framing_server, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), TestHandler)
    print(f"Test server running on http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop, or GET /shutdown to stop programmatically")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print("Server stopped")


if __name__ == "__main__":
    main()
