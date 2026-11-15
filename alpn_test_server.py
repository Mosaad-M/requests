"""HTTPS test server that negotiates no ALPN protocol (like TLS 1.2 servers
and HTTP/1.1-only TLS 1.3 servers). Serves keep-alive HTTP/1.1; GET
/connections answers how many TCP connections it has accepted.

Usage: python alpn_test_server.py <cert.pem> <key.pem> [port]  (also serves TLS 1.2 only on port+4)
"""
import http.server
import ssl
import sys
import threading

ACCEPTED = {}  # per listening port
LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        with LOCK:
            port = self.server.server_address[1]
            ACCEPTED[port] = ACCEPTED.get(port, 0) + 1
        super().setup()

    def do_GET(self):
        if self.path == "/connections":
            with LOCK:
                body = str(ACCEPTED.get(self.server.server_address[1], 0)).encode()
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def serve(cert, key, port, tls12):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)  # no set_alpn_protocols: no ALPN answer
    if tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main():
    cert, key = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 18443
    # port: TLS 1.3 (Python's default); port + 4: TLS 1.2 only
    threading.Thread(target=serve, args=(cert, key, port + 4, True), daemon=True).start()
    serve(cert, key, port, False)


if __name__ == "__main__":
    main()
