# Lessons

- **Docs drift silently.** CLAUDE.md described a layout two major versions old. Before trusting it, check `mojoproject.toml`, `git log` and the file list.
- **A passing test that cannot fail is worthless.** Break the code on purpose and watch the test fail. Two flow-control tests passed against a client that ignored flow control until the server was changed to withhold window credit.
- **HttpClient hides failures by retrying on a fresh connection.** To assert a protocol-level failure, go below it (raw `h2_request` on a hand-made `Http2Conn`).
- **Python `ssl` sockets: `settimeout(0)` means non-blocking** and raises `SSLWantReadError`, not `socket.timeout`. A test server that did this dropped connections about 1 run in 6 and the client's fallback hid it. Run new network tests repeatedly (10x) before trusting them.
- **TLS record limit**: 16384 bytes of plaintext. An HTTP/2 DATA frame of 16384 bytes plus its 9-byte header does not fit in one `TlsSocket.send`.
- **Mojo 1.2**: `len(String)` is an error; `mut self` methods cannot be called inside an expression that also borrows `self` fields.
