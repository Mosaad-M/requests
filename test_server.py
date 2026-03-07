"""Simple HTTP test server for Mojo HTTP client tests.

Runs on localhost:18080 and handles various test endpoints.
Start before running test_client.mojo.

Usage: python test_server.py
"""

import http.server
import json
import sys


class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
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
        if self.path == "/echo":
            self._handle_echo()
        elif self.path == "/method":
            self._handle_method()
        else:
            self._respond(404, "Not Found", {"error": "unknown path"})

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
    server = http.server.HTTPServer(("127.0.0.1", port), TestHandler)
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
