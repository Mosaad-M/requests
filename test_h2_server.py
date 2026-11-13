"""Local HTTP/2 test server (TLS + ALPN h2) for test_h2_local.mojo.

Three listeners on localhost:
  18443  normal: stream window 16384 (forces many WINDOW_UPDATEs on uploads)
  18444  SETTINGS_MAX_CONCURRENT_STREAMS = 2
  18445  sends GOAWAY (last stream = 3rd) when the 4th request arrives, and never
         answers requests after that

Paths (all ports; ?ms= delays the response without blocking other streams):
  /n/<i>             200, body "resp-<i>"
  /large?kb=N        200, body of N KB (obeys the client's flow control)
  /echo              200, JSON {"len": bytes received, "ok": body is the pattern a,b,..,z,a,..}
  /rst               RST_STREAM(INTERNAL_ERROR) on that stream only
  /hdrbig?kb=N       200, with an N KB response header (needs CONTINUATION)
  /hdrtrailer?kb=N   N KB response header plus N KB trailer
  /midsettings       sends a new SETTINGS mid-connection, then 200
  /acked             200 "yes" if the client acknowledged that SETTINGS, else "no"
  /interim           1xx interim response before the 200
  /trailers          200 with a trailer block
  /status/<code>     that status, empty body

Uses the `h2` package (a test-only pixi dependency). Generates certs/ (git-ignored) with openssl on first run. Usage: python test_h2_server.py
"""

import heapq
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings
from hyperframe.frame import GoAwayFrame

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.pem")
KEY = os.path.join(HERE, "certs", "server.key")

PORT_NORMAL, PORT_LIMITED, PORT_GOAWAY = 18443, 18444, 18445


def ensure_certs():
    """Generate a throwaway CA and a localhost server cert in certs/ (git-ignored) if missing."""
    if all(os.path.exists(f) for f in (CERT, KEY, os.path.join(HERE, "certs", "ca.pem"))):
        return
    d = os.path.join(HERE, "certs")
    os.makedirs(d, exist_ok=True)

    def ssl_(*args):
        subprocess.run(["openssl", *args], cwd=d, check=True, stderr=subprocess.DEVNULL)

    ssl_("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key")
    ssl_("req", "-new", "-x509", "-key", "ca.key", "-out", "ca.pem", "-days", "1826",
         "-subj", "/CN=TLS Test CA", "-addext", "basicConstraints=critical,CA:TRUE")
    ssl_("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key")
    ssl_("req", "-new", "-key", "server.key", "-out", "server.csr", "-subj", "/CN=localhost")
    with tempfile.NamedTemporaryFile("w", suffix=".ext", dir=d, delete=False) as ext:
        ext.write("subjectAltName=DNS:localhost\n")
    try:
        ssl_("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
             "-CAcreateserial", "-out", "server.pem", "-days", "1826", "-extfile", ext.name)
    finally:
        for f in (ext.name, os.path.join(d, "server.csr"), os.path.join(d, "ca.srl")):
            if os.path.exists(f):
                os.remove(f)


class Connection:
    def __init__(self, sock, mode):
        self.sock = sock
        self.mode = mode
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        self.streams = {}       # stream_id -> dict(method, path, query, body_len, ok, ended)
        self.pending = {}       # stream_id -> [bytes, offset, trailers]
        self.timers = []        # heap of (due, seq, stream_id)
        self.seq = 0
        self.requests = 0
        self.mid_settings_acked = False
        self.mid_settings_sent = False
        self.goaway_sent = False
        self.unacked = []         # (flow-controlled length, stream) not yet credited back
        self.ack_scheduled = False

    # -- helpers --------------------------------------------------------------
    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def respond_later(self, stream_id, ms):
        self.seq += 1
        heapq.heappush(self.timers, (time.time() + ms / 1000.0, self.seq, stream_id))

    def send_response(self, stream_id, status, headers, body, trailers=None):
        self.conn.send_headers(
            stream_id,
            [(":status", str(status)), ("content-length", str(len(body)))] + headers,
            end_stream=(len(body) == 0 and not trailers),
        )
        if body:
            self.pending[stream_id] = [body, 0, trailers]
            self.pump(stream_id)
        elif trailers:
            self.conn.send_headers(stream_id, trailers, end_stream=True)

    def pump(self, stream_id):
        entry = self.pending.get(stream_id)
        if entry is None:
            return
        body, off, trailers = entry
        while off < len(body):
            n = min(
                self.conn.local_flow_control_window(stream_id),
                self.conn.max_outbound_frame_size,
                len(body) - off,
            )
            if n <= 0:
                break
            end = off + n == len(body) and not trailers
            self.conn.send_data(stream_id, body[off:off + n], end_stream=end)
            off += n
        entry[1] = off
        if off == len(body):
            del self.pending[stream_id]
            if trailers:
                self.conn.send_headers(stream_id, trailers, end_stream=True)

    # -- request handling -------------------------------------------------------
    def handle(self, stream_id):
        st = self.streams[stream_id]
        path, q = st["path"], st["query"]
        try:
            if path.startswith("/n/"):
                self.send_response(stream_id, 200, [], ("resp-" + path[3:]).encode())
            elif path == "/large":
                self.send_response(stream_id, 200, [], b"x" * (int(q.get("kb", "1")) * 1024))
            elif path == "/echo":
                body = json.dumps({"len": st["body_len"], "ok": st["ok"]}).encode()
                self.send_response(stream_id, 200, [("content-type", "application/json")], body)
            elif path == "/rst":
                self.conn.reset_stream(stream_id, error_code=2)
            elif path == "/hdrbig":
                big = "a" * (int(q.get("kb", "1")) * 1024)
                self.send_response(stream_id, 200, [("x-big", big)], b"{}")
            elif path == "/hdrtrailer":
                # N KB of response header AND N KB of trailer: each block is under a
                # limit that the two together exceed.
                kb = "a" * (int(q.get("kb", "1")) * 1024)
                self.send_response(stream_id, 200, [("x-big", kb)], b"{}", trailers=[("x-t", kb)])
            elif path == "/midsettings":
                self.mid_settings_sent = True
                self.conn.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 50})
                self.send_response(stream_id, 200, [], b"settings-sent")
            elif path == "/acked":
                self.send_response(stream_id, 200, [], b"yes" if self.mid_settings_acked else b"no")
            elif path == "/interim":
                self.conn.send_headers(stream_id, [(":status", "103"), ("link", "</x>; rel=preload")])
                self.send_response(stream_id, 200, [], b"after-interim")
            elif path == "/trailers":
                self.send_response(stream_id, 200, [], b"with-trailers", trailers=[("x-trailer", "1")])
            elif path.startswith("/status/"):
                self.send_response(stream_id, int(path[8:]), [], b"")
            else:
                self.send_response(stream_id, 404, [], b"not found")
        except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
            pass  # the client reset the stream (e.g. it hit a size limit)

    # -- main loop --------------------------------------------------------------
    def serve(self):
        self.conn.initiate_connection()
        if self.mode == "normal":
            self.conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 16384})
        elif self.mode == "limited":
            self.conn.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 2})
        self.flush()
        while True:
            timeout = None
            if self.timers:
                timeout = max(0.001, self.timers[0][0] - time.time())  # 0 would make the socket non-blocking
            self.sock.settimeout(timeout)
            try:
                data = self.sock.recv(65535)
                if not data:
                    return
                events = self.conn.receive_data(data)
            except (socket.timeout, ssl.SSLWantReadError):
                events = []
            except (ssl.SSLError, ConnectionError, h2.exceptions.ProtocolError) as exc:
                if os.environ.get("H2_DEBUG"):
                    print("connection ended:", repr(exc), flush=True)
                return
            for ev in events:
                self.on_event(ev)
            now = time.time()
            while self.timers and self.timers[0][0] <= now:
                _, _, sid = heapq.heappop(self.timers)
                if sid == -1:
                    # Credit uploaded data back 30 ms late, so a client that ignores
                    # its flow-control window overruns it (the h2 library drops it).
                    for length, stream_id in self.unacked:
                        self.conn.acknowledge_received_data(length, stream_id)
                    self.unacked = []
                    self.ack_scheduled = False
                else:
                    self.handle(sid)
            self.flush()

    def on_event(self, ev):
        if isinstance(ev, h2.events.RequestReceived):
            headers = dict(ev.headers)
            url = urllib.parse.urlparse(headers[":path"])
            self.requests += 1
            if self.mode == "goaway" and self.requests == 4 and not self.goaway_sent:
                # Accepted: streams up to the 3rd. This one and later ones are ignored.
                self.goaway_sent = True
                last = 1 + 2 * 2
                self.sock.sendall(self.conn.data_to_send())
                self.sock.sendall(GoAwayFrame(0, last_stream_id=last, error_code=0).serialize())
            if self.goaway_sent and self.requests >= 4:
                return
            self.streams[ev.stream_id] = {
                "method": headers[":method"],
                "path": url.path,
                "query": {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()},
                "body_len": 0,
                "ok": True,
                "ended": False,
            }
        elif isinstance(ev, h2.events.DataReceived):
            st = self.streams.get(ev.stream_id)
            if st is not None:
                for b in ev.data:
                    if b != 97 + st["body_len"] % 26:
                        st["ok"] = False
                    st["body_len"] += 1
            self.unacked.append((ev.flow_controlled_length, ev.stream_id))
            if not self.ack_scheduled:
                self.ack_scheduled = True
                self.respond_later(-1, 30)
        elif isinstance(ev, h2.events.StreamEnded):
            st = self.streams.get(ev.stream_id)
            if st is not None:
                st["ended"] = True
                self.respond_later(ev.stream_id, int(st["query"].get("ms", "0")))
        elif isinstance(ev, h2.events.WindowUpdated):
            if ev.stream_id:
                self.pump(ev.stream_id)
            else:
                for sid in list(self.pending):
                    self.pump(sid)
        elif isinstance(ev, h2.events.SettingsAcknowledged):
            if self.mid_settings_sent:
                self.mid_settings_acked = True


def run(port, mode):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["h2"])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)

    def one(raw):
        try:
            with ctx.wrap_socket(raw, server_side=True) as tls:
                Connection(tls, mode).serve()
        except (ssl.SSLError, OSError, KeyError, h2.exceptions.H2Error):
            pass  # the client went away or reset a stream mid-response

    while True:
        raw, _ = srv.accept()
        threading.Thread(target=one, args=(raw,), daemon=True).start()


def main():
    ensure_certs()
    for port, mode in ((PORT_NORMAL, "normal"), (PORT_LIMITED, "limited"), (PORT_GOAWAY, "goaway")):
        threading.Thread(target=run, args=(port, mode), daemon=True).start()
    print("h2 test server on", PORT_NORMAL, PORT_LIMITED, PORT_GOAWAY, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
