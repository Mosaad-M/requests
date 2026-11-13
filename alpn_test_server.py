"""HTTPS test server that negotiates no ALPN protocol (like TLS 1.2 servers
and HTTP/1.1-only TLS 1.3 servers). Serves keep-alive HTTP/1.1; GET
/connections answers how many TCP connections it has accepted.

Usage: python alpn_test_server.py <cert.pem> <key.pem> [port]
"""
import http.server
import ssl
import sys
import threading

ACCEPTED = [0]
LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        with LOCK:
            ACCEPTED[0] += 1
        super().setup()

    def do_GET(self):
        if self.path == "/connections":
            with LOCK:
                body = str(ACCEPTED[0]).encode()
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    cert, key = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 18443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)  # no set_alpn_protocols: no ALPN answer
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
