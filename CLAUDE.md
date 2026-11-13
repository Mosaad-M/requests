# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A **pure-Mojo HTTP client** with no Python interop, no C wrappers and no OpenSSL. HTTP/1.1 and HTTP/2 (negotiated by ALPN over TLS), GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS, JSON responses, cookies, redirects, an HTTP CONNECT proxy, transparent gzip/deflate/zstd/brotli decompression.

Mojo `>=1.2.0` (stable channel `https://conda.modular.com/max`), managed with **pixi**. Packages are published as `requests` in the [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg) registry (`mojoproject.toml` is the package manifest; `pixi.toml` is the dev environment). Releases are git tags `vX.Y.Z`; the registry entry lives in `mojo-pkg-index`.

## Ecosystem

Sibling repos under `Mosaad-M/` (cloned next to this one in `~/Documents/github/`), consumed through `mojo-pkg`, **not** symlinks:

```
tcp ──► tls ──► requests        url, json ──► requests
tcp + tls + url ──► websocket ──► cdp      tcp + tls ──► pg
flatbuffers ──► arrow ──► fhir-arrow, hl7-arrow, 1brc_arrow
```

- `mojoproject.toml` declares `tls`, `tcp`, `url`, `json` with minimum versions; `mojo.lock` pins them.
- `mojo-pkg install` downloads them to `~/.mojo/packages/<name>/<version>` and writes `.mojo_flags` (git-ignored, machine-local `-I` paths). `build_and_run.sh` passes `.mojo_flags` to `mojo build`.
- A change that needs new upstream behaviour means a new tcp/tls release first, then bump the floor here.
- Only `requests` and `websocket`/`pg`/`cdp` share tcp/tls: a tls/tcp API change affects them all.

## Files

| File | Purpose |
|------|---------|
| `http_client.mojo` | `HttpClient` (+ `Session`, `StreamResponse`, `HttpResponse`, `HttpHeaders`, auth helpers), HTTP/1.1 protocol, pools, cookies, redirects, deadline/retries, `get_many` |
| `h2.mojo` | HTTP/2 framing (RFC 9113) |
| `h2_conn.mojo` | HTTP/2 connection: preface/SETTINGS, `h2_request`, `h2_request_many` (multiplexing), flow control |
| `hpack.mojo` | HPACK (RFC 7541) encode/decode, `hpack_decode_block(..., max_list)` |
| `codecs.mojo`, `zlib_decompress.mojo`, `zstd_decompress.mojo`, `brotli_decompress.mojo` | Compression libraries opened at runtime with `dlopen` (no linker flags) |
| `psl.mojo` | Curated public-suffix list for cookie domain checks |
| `main.mojo` | Demo (needs internet) |
| `bench_profile.mojo`, `bench_h2.mojo` | Benchmarks (`bench_h2` needs the local test servers) |
| `test_*.mojo`, `test_*server.py`, `certs/` | Tests and their servers; `certs/` (git-ignored) holds a throwaway test CA and localhost cert that `test_h2_server.py` generates with openssl on first run; never commit it |

## Build & Test

```bash
pixi run run               # demo
pixi run test              # test_resilience (38) + test_client (114 HTTP + 4 HTTPS) against test_server.py
pixi run test-h2-local     # 28 HTTP/2 tests against test_h2_server.py (python `h2` package, ports 18443-18445)
pixi run test-hpack        # 128
pixi run test-h2           # 70 (framing)
pixi run test-h2-conn      # 4  (public internet)
pixi run test-h2-client    # 3  (public internet)
pixi run test-std-compat   # 1
pixi run bash build_and_run.sh bench_h2.mojo   # with both test servers running
```

- `mojo run` (JIT) is not used; everything goes through `mojo build` via `build_and_run.sh`.
- `test_client` ends by calling `/shutdown` on `test_server.py`, so `test_resilience` runs first in the `test` task.
- Tests that must prove a *negative* (flow control, deadlines) are verified by mutation: break the code, confirm the test fails. The h2 server credits uploaded data back 30 ms late on purpose, so a client that ignores flow control gets dropped. HttpClient silently retries a failed pooled request on a fresh connection, so a test that must see a protocol failure should use the raw `h2_request` on a hand-made `Http2Conn` (see `test_raw_upload_obeys_peer_windows`).
- `test-h2-conn`/`test-h2-client`/HTTPS tests use the public internet and can flake.

## Public settings on `HttpClient` (all default to the previous behaviour)

| Field | Default | Meaning |
|-------|---------|---------|
| `allow_private_ips` (ctor) | `False` | Block loopback/private/link-local/CGNAT targets, checked on the **resolved** address at connect time (rebinding-safe) |
| `timeout_secs` (ctor) | 30 | Per-socket send/recv timeout |
| `total_timeout_secs` | 0 (off) | Deadline for a whole call incl. redirects, retries and body reads. Raises `TimeoutError`. Every read (HTTP, HTTPS, h2, pooled or fresh) is capped to the time left, 1 s granularity. If a retry's wait would pass the deadline, the last response is returned instead |
| `max_retries` / `retry_backoff_ms` / `retry_non_idempotent` | 0 / 200 / False | Retry connect/read failures and 429/502/503/504; idempotent methods only unless opted in; exponential backoff with jitter capped at 30 s; `Retry-After` (seconds) honoured up to 60 s |
| `max_response_bytes` | 100 MB | Body cap, HTTP/1.1 (Content-Length, chunked, close-delimited) and HTTP/2 |
| `max_header_bytes` | 1 MB | Header block cap (HTTP/1.1 and HTTP/2, compressed, decoded, and cumulative with trailers) |
| `max_batch_bytes` | 1 GB | Body bytes one `get_many` batch may hold; a stream past it is re-fetched alone |
| `max_redirects`, `follow_redirects`, `redirect_same_host_only`, `pool_idle_timeout_secs`, `proxy_url` | | as before |

`get_many(urls, headers)` multiplexes URLs on the same HTTPS host that speaks HTTP/2 (first URL of a host goes alone to open the connection). It does not need threads. Streams that fail or redirect are re-fetched with `get()`.

## Key Design Decisions

- **Pure Mojo stack**: TLS is the `tls` package (no OpenSSL); sockets are the `tcp` package. Compression libs are loaded with `dlopen` at runtime, so programs need no linker flags.
- **UnsafePointer-based parsing** for HTTP/URL/JSON hot paths, materialising `String` once. `String(unsafe_from_utf8=list^)` (no NUL terminator).
- **Keep-alive pools**: LRU-4 per scheme (HTTP, TLS/HTTP1, HTTP/2). A request that fails on a pooled connection is replayed on a fresh one only if it is idempotent (or `retry_non_idempotent`), as in Go; deadline expiry and size-limit violations are never replayed.
- **HTTP/2**: one connection per host:port, up to 4 pooled. `h2_request` is `h2_request_many` with one request. Stream state lives in parallel lists indexed by request; stream id of request `i` is `first_id + 2*i`. Header blocks are always HPACK-decoded, even for finished streams, to keep the dynamic table in sync. DATA frames are split into TLS records of at most 16384 bytes (a full 16384-byte frame plus its 9-byte header exceeds the TLS record limit).
- **Conn-level send window** is changed only by WINDOW_UPDATE on stream 0, never by SETTINGS_INITIAL_WINDOW_SIZE (that only moves stream windows).
- **Error categories** (`String(e).startswith(...)`): `HTTPError`, `ConnectionError`, `TooManyRedirects`, `ValidationError`, `ParseError`, `ChunkedBodyError`, `TimeoutError`. Raw `tcp:`/`tls:` errors can also surface from lower layers.
- **Mojo 1.2 gotchas**: `def` not `fn`; `len(String)` is an error (use `byte_length()`); methods that mutate the client (`_accept_encoding`, `_jar_cookie_for`) need `mut self`; do not pass `self.field` and `self.method()` as two arguments of one call.

## Security

- **Input validation**: CRLF injection rejected in header keys/values and paths; method must be A-Z; port 1-65535; hosts reject NUL/CR/LF/space/slash.
- **Response hardening**: chunk-size caps, truncation detection, status/version validation, header and body caps (above), HPACK decoded-list cap (`max_list`), decompression ratio (256x) and absolute (512 MB) caps, h2 frames above 16384 bytes rejected, PUSH_PROMISE refused (we send ENABLE_PUSH=0).
- **Network**: SSRF filter on resolved addresses, TLS certificate and hostname verification (tls package), `Authorization` stripped on cross-host redirects, cookie jar checks the public-suffix list.
- Known gaps: no revocation checking and no session resumption (tls package); decompression caps are constants; `Retry-After` HTTP-date form is not parsed; h2 request header blocks larger than the peer's max frame size are rejected (no CONTINUATION on send); plain-TCP deadline capping uses tcp's private `_set_socket_timeouts` (no public setter yet).
