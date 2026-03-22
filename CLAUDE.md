# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A **native Mojo HTTP/HTTPS client** — no Python interop. Built from scratch using POSIX socket FFI calls and OpenSSL FFI for TLS. Supports HTTP and HTTPS requests (GET, POST, PUT, DELETE, PATCH) with JSON response parsing.

Uses **pixi** for dependency/environment management with Mojo 0.25.7 from the `max-nightly` channel.

## Modular Architecture

This project uses a **modular monorepo** layout. Core modules live as sibling repos under `~/mojo_pg/` and are linked into `requests/` via symlinks:

```
~/mojo_pg/
├── url/          ← URL parser (standalone)
├── json/         ← JSON parser (standalone)
├── tcp/          ← TCP socket wrapper (standalone)
├── tls/          ← TLS/SSL + OpenSSL FFI + build tools (depends on tcp)
├── websocket/    ← WebSocket protocol (depends on url, tcp, tls)
└── requests/     ← HTTP client (this repo, depends on all above)
    ├── http_client.mojo    (HTTP protocol + HttpClient API)
    ├── main.mojo           (demo)
    ├── test_client.mojo    (integration tests)
    ├── test_server.py      (Python HTTP test server)
    ├── bench_profile.mojo  (benchmarks)
    ├── build_and_run.sh    (build helper)
    ├── url.mojo → ../url/url.mojo           (symlink)
    ├── json.mojo → ../json/json.mojo        (symlink)
    ├── tcp.mojo → ../tcp/tcp.mojo           (symlink)
    ├── tls.mojo → ../tls/tls.mojo           (symlink)
    ├── ssl_wrapper.c → ../tls/ssl_wrapper.c (symlink)
    └── .build_tools → ../tls/.build_tools   (symlink)
```

## Files

| File | Purpose |
|------|---------|
| `http_client.mojo` | HTTP/1.1 protocol + high-level `HttpClient` API (GET/POST/PUT/DELETE/PATCH) + `response.json()` |
| `main.mojo` | Demo: fetch HTTP and HTTPS URLs |
| `test_client.mojo` | HTTP + HTTPS integration tests (27 tests) |
| `test_server.py` | Python HTTP test server for HTTP integration tests |
| `bench_profile.mojo` | Comprehensive performance benchmarks |
| `build_and_run.sh` | Build helper — `mojo build` with SSL linking, then run |
| `tcp.mojo` | Symlink → `../tcp/tcp.mojo` — TCP socket wrapper via C FFI |
| `tls.mojo` | Symlink → `../tls/tls.mojo` — TLS/SSL wrapper via OpenSSL FFI |
| `url.mojo` | Symlink → `../url/url.mojo` — URL parser |
| `json.mojo` | Symlink → `../json/json.mojo` — JSON parser |
| `ssl_wrapper.c` | Symlink → `../tls/ssl_wrapper.c` — C wrapper for OpenSSL |
| `.build_tools/` | Symlink → `../tls/.build_tools` — Linker wrapper |

## Build & Run Commands

```bash
pixi run run             # Run the demo (fetches HTTP + HTTPS URLs)
pixi run test            # Run HTTP + HTTPS integration tests
pixi run format          # Format Mojo files
pixi run compile-ssl     # Compile libssl_wrapper.so (auto dependency of run/test)
# Benchmarks (needs mojo build for SSL):
pixi run bash build_and_run.sh bench_profile.mojo
```

Module-specific tests live in their own repos:
```bash
cd ~/mojo_pg/url  && pixi run test-url    # 19 URL parser tests
cd ~/mojo_pg/json && pixi run test-json   # 39 JSON parser tests
cd ~/mojo_pg/tcp  && pixi run test-tcp    # 3 TCP socket tests
cd ~/mojo_pg/tls  && pixi run test        # 2 TLS connectivity tests
```

## Key Design Decisions

- **Connection: close** — simplifies response reading (read until EOF, no chunked encoding)
- **getaddrinfo for DNS** — handles both hostnames and IP addresses
- **String(unsafe_from_utf8=list^)** — NO null terminator; `String(bytes=...)` renamed in 0.26+
- **UnsafePointer-based parsing** — all parsers (HTTP, JSON, URL) convert input to `UnsafePointer[UInt8]` once at the top, use pointer arithmetic throughout (`(ptr + i)[]`), and only materialize Strings via `_ptr_to_string()` when storing final values
- **Alias byte constants** — frequently used byte values (e.g. `_QUOTE`, `_LBRACE`, `_ZERO`) are `alias` constants to avoid repeated `ord()` calls
- **Zero-copy send** — `send()` passes the string's internal pointer directly to C `send()`/`SSL_write()` via `unsafe_cstr_ptr()`
- **64KB growing recv buffer** — `recv_all()` uses a 64KB heap-allocated buffer that doubles on overflow, recv directly into it, single conversion at end
- **`_eq_ignore_case`** — allocation-free case-insensitive compare for HTTP headers (5x faster than `_to_lower()` pairs)
- **Buffer-based request building** — `List[UInt8]` append (linear) instead of `String +=` (quadratic)
- **C wrapper for OpenSSL** — Mojo's `external_call` resolves symbols at link/JIT time; since `mojo build` has no `-l` flags, a thin C shared library (`ssl_wrapper.c` → `libssl_wrapper.so`) re-exports OpenSSL functions under `mojo_ssl_*` names, linked via a PATH-based `c++` wrapper (`.build_tools/c++`)
- **SNI via SSL_set_tlsext_host_name** — required by most HTTPS servers; the C macro is wrapped directly in `ssl_wrapper.c`
- **CA cert bundle** — uses pixi's bundled certs at `.pixi/envs/default/ssl/cert.pem`
- **mojo build, not mojo run** — `mojo run` (JIT) cannot resolve SSL symbols; all tasks that use TLS go through `build_and_run.sh`
- **JSON parser — recursive descent** — `JsonValue` tagged union (kind field: NULL/BOOL/NUMBER/STRING/ARRAY/OBJECT) with `UnsafePointer` for recursive types (array, object) to break circular dependency. `JsonObject` uses parallel lists pattern (same as `HttpHeaders`). Parser dispatches on first non-whitespace byte. String parsing handles all JSON escape sequences (`\"`, `\\`, `\n`, `\t`, etc.); `\uXXXX` emits `?` placeholder. Integer fast path via multiply-accumulate; float path via inline mantissa/exponent parser (no `atof`)
- **Leaf accessors** — `get_string(key)`, `get_int(key)`, `get_number(key)`, `get_bool(key)` extract primitives without deep-copying the entire JsonValue tree
- **`response.json()`** — `HttpResponse.json()` calls `parse_json(self.body)`, returning a `JsonValue` tree. Access nested data via `val.get_string("name")` (no copy) or `val.get("key").get("nested").as_string()` (full tree copy)

## Performance

Benchmarked on Linux x86_64 (WSL2), Mojo 0.25.7:

| Operation | Throughput |
|-----------|-----------|
| URL parsing | 128-178 ns per URL |
| JSON parsing (small, 44B) | 241 ns (183 MB/s) |
| JSON parsing (medium, 297B) | 1.7 us (175 MB/s) |
| JSON parsing (large, 16KB) | 59 us (284 MB/s) |
| JSON parsing (float-heavy) | 6.7 us (379 MB/s) |
| JSON serialization (16KB) | 67 us (250 MB/s) |
| HTTP response parsing (100KB) | 40 us (2,528 MB/s) |
| Chunked transfer decode | 561 ns |

## Security

The client implements defense-in-depth across all layers:

### Input Validation
- **CRLF injection prevention** — header keys/values and request paths are validated to reject `\r`/`\n` characters
- **HTTP method validation** — only uppercase ASCII letters (A-Z) allowed
- **Port range validation** — enforces 1-65535 with max 5 digit limit
- **Host validation** — rejects null bytes, CR/LF, spaces, and slashes in hostnames

### Response Parsing Hardening
- **Chunk size overflow protection** — 256 MB cap, max 16 hex digits
- **Chunked body truncation detection** — raises error instead of silently truncating
- **Status code validation** — max 3 digits
- **HTTP version validation** — verifies `HTTP/` prefix in response
- **Pointer bounds safety** — `_ptr_to_string()` guards against negative start indices

### Network Layer
- **Socket timeouts** — 30-second SO_RCVTIMEO/SO_SNDTIMEO on all connections
- **Response size limit** — 100 MB cap on `recv_all()` (configurable)
- **TLS certificate verification** — `SSL_CTX_set_verify(SSL_VERIFY_PEER)` + `SSL_set1_host()` for hostname verification
- **SSRF protection** — opt-in private IP blocking via `allow_private_ips = False` on `HttpClient`. Blocks 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 0.0.0.0/8

### Usage
```mojo
# Default: allows private IPs (backward compatible)
var client = HttpClient()

# SSRF-safe: blocks connections to private/reserved IPs
var safe_client = HttpClient()
safe_client.allow_private_ips = False
```

## Future Work

- Redirect following
- Cookie handling
- Connection pooling
