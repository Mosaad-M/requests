# requests 1.12.0 — bytes bodies and a public request() (#37)

Branch `bytes-bodies-1.12.0`. Additive: the request path takes `Span[Byte, _]`; new `List[UInt8]`/`Span[UInt8]` overloads on post/put/patch/delete; `request(method, url, [body], [headers])` on HttpClient and Session; `HttpResponse.content()` (view) and `to_bytes()` (copy).
- [x] Tests (binary round trip over HTTP/1.1 and h2, request() redirects, response accessors, retry after 503 with a binary body). Mutation-checked: Content-Length off by one, 303/302 body and header handling, h2 body byte flipped
- [x] `pixi run test`: resilience 40, framing 51, client 143 + 4 HTTPS; test-h2-local 30; hpack 130; h2 70; alpn 1; std-compat 1
- [x] Perf vs v1.11.1: e2e small/medium/large/chunked within noise; bench_h2/profile within noise; 3 x 32 MiB upload+echo: String body 192 ms -> 76-103 ms (memcpy instead of a byte loop), Span body 75-80 ms with 147 MB peak RSS (String paths 148-215 MB before, 181 MB after)
- [x] Reviewer subagent: request() rewrote every method to GET on 301/302/303 and kept Content-Type after a dropped body: fixed (Python requests rules), tests added; retry test now checks bytes across 503 retries
- [x] fuzz 3 seeds x 100000 clean
- Not run: PoCs (they need per-PoC servers; no parser change), public-internet h2 tests

---

# requests 1.11.1 — chunked bodies obey max_response_bytes (#28)

Branch `fix/chunked-limit-1.11.1`. `_decode_chunked` (via `_parse_response`) compared the decoded size with the 100 MB constant, so a chunked body over 100 MB failed whatever `max_response_bytes` was. Both now take the client's limit.
- [x] Tests fail before the fix, pass after (mutation): `_decode_chunked` with a limit, and a 101 MB chunked body with the limit raised (and refused at the default)
- [x] `pixi run test`: resilience 38, framing 51, client 136 + 4 HTTPS
- [x] Perf: bench_e2e large/chunked vs v1.11.0 within noise (chunked RSS 82-98 MB in both, 6 interleaved runs)
- Not run: fuzz, PoCs, h2 suites (only a parameter threaded into the HTTP/1.1 decoder)

---

# requests 1.11.0 — no HTTP/2 probe (#48), tls >= 1.11.0

Branch `release-1.11.0`. #48 cherry-picked (authorship kept) onto 1.10.0 and ported: the `proto == ""` branch is gone, so no ALPN answer is HTTP/1.1 on the connection we have.
- [x] tls floor 1.11.0 (TLS 1.2 ALPN reporting), mojo.lock updated
- [x] test-alpn (PR's test): 4 requests, 1 connection
- [x] New: test_h2_server.py port 18446 is TLS 1.2 only; a TLS 1.2 server selecting h2 still gets h2 (fails on tls 1.10.0, passes on 1.11.0)
- [x] Real hosts: sha256.badssl.com and tls-v1-2.badssl.com 2 requests = 1 connection (v1.10.0: 2); cloudflare, example.com, github.com, httpbin h2 with 1 connection
- [x] Profiles vs v1.10.0: e2e/h2/profile within noise (h2 4 MB median 15.38 vs 15.09 ms, 12 runs); PoCs unchanged; fuzz 8 runs x 300k clean; reviewer: no bugs, test gaps fixed (TLS 1.2 no-ALPN case, CI step)

---

# requests 1.10.0 — security hardening

Branch `release-1.10.0`; each item a commit with its test (verified failing first).
- [x] Cookies: `Domain` must cover the request host (IP hosts exact), PSL check after lowercasing, control chars rejected, 4096-byte pair and 3000-cookie caps
- [x] Redirects: Authorization/Cookie/Proxy-Authorization dropped on scheme, host or port change (`_redirect_headers`)
- [x] Chunked body cut before the terminal chunk raises `ChunkedBodyError`; `get_stream` short Content-Length body and read timeouts raise; 204/304 streams end at once
- [x] Decompression capped by `max_response_bytes`; zstd frame-size guard
- [x] Control characters (incl. NUL) rejected in header names, values and paths
- [x] HPACK: size update above our advertised limit (65536) is an error. The O(n) table insert stays: the limit bounds n (~2000 entries)
- [x] Proxy SSRF policy: left unchanged and documented as a known gap (only IP literals could be checked; blocking would break proxies to internal hosts); opt-in setting if wanted
- Reviewer pass found: uppercase `Domain=CO.UK` bypassing the PSL, HPACK limit below the advertised table size (broke all h2-local tests), 304 streams waiting for a body, zstd frame-size cast: all fixed. Left: jar cap has no eviction, initial decompression buffer can exceed a tiny cap.
- Perf vs 1.9.0: small 155 ms, medium 356 ms, large 248 ms, chunked 173 ms (unchanged)

---

# requests 1.9.0 — contributor batch (#40, #41, #42, #46, #28 remainder) and trust_env (#36)

Branch `release-1.9.0`. Contributor commits cherry-picked (authorship kept) and ported onto 1.8.1.

- [x] #40: interim 1xx skipped, 204/304 end at the headers in the HTTP and TLS receive loops
- [x] #42: `connections_opened`
- [x] #41: `default_content_type`, `Content-Length: 0` for empty POST/PUT/PATCH
- [x] #46: caller headers replace Host/User-Agent/Connection defaults; `decompress=False`; h2 drops Host and connection-specific headers
- [x] #28 remainder: `get_stream` header block capped by `max_header_bytes` (its body stays uncapped); PR #43 otherwise superseded by 1.7.0/1.8.0
- [x] #36: `trust_env`
- [ ] #48 (no ALPN answer -> HTTP/1.1) DEFERRED: tls 1.10.0 never reports an ALPN result for TLS 1.2 (`negotiated_protocol()` returns "" when `_is12`) though the ClientHello offers h2, so a TLS 1.2 server that picks h2 would get HTTP/1.1 bytes. Needs tls to parse ALPN from the 1.2 ServerHello first (tls release, bump the floor), then #48
- [x] `pixi run test` 38 + 48 + 126 + 4

---

# requests 1.8.1 — brotli output buffer, response copies (PRs #45, #47)

Branch `patch-1.8.1`. Contributor commits kept; merged cleanly except an adjacent-lines test conflict.

- [x] #45: brotli bodies inflating more than 8x failed with `BrotliDecodeError: result=0` (the one-shot decoder returns ERROR, never NEEDS_MORE_OUTPUT, when the buffer is too small); buffer now grows on either result up to the ratio cap
- [x] Review: PR looped on `while result != 1`, which would spin forever on any other result code; now `while result == 3 or result == 0`
- [x] Test: corrupt brotli data fails fast (guard test, passes on old code too); over-8x test fails on 1.8.0 code
- [x] #47: `List.extend(Span)` instead of per-byte appends; 64 MiB GET 982 -> 1475 MiB/s on this machine
- [x] Security (found by profiling, see below): `_buf_parse_hex` rejects non-hex/oversized chunk sizes (7FFF.. used to abort the process; now `ChunkedBodyError`); `hpack_decode_str` bounds-checks the length (abort on a malicious h2 server's block)
- [x] Perf: `_buf_chunked_complete` resumes from the last whole chunk (was quadratic: 8 MiB of 1 KB chunks 79 -> 15 ms, 2 MiB of 16-byte chunks 226 -> 8 ms); `_connection_reusable` checked before the String is built (peak RSS of a 64 MiB body 269 -> 214 MB, the 1.8.0 regression)
- [x] Tests: hostile chunk sizes, resumable scan, hpack string bounds
- [x] `pixi run test` 38 + 46 + 118 + 4, test-hpack 129
- [ ] PR, CI, merge, tag `v1.8.1`, mojo-pkg-index

---

# requests 1.8.0 — parse the response header block once (issue #52)

Plan: `~/.claude/plans/shimmering-skipping-lobster.md`. Branch `framing-1.8.0`.

- [x] Tests first: raw keep-alive listener (port 18083) + `test_framing.mojo`; on 1.7.1 code 17 of 28 fail
- [x] `_frame_from_headers` / `_Framing`; receive loops, `get_stream`, `_parse_response` use it; old scanners deleted
- [x] `_connection_reusable` eviction; trailer-aware `_buf_chunked_complete`
- [x] Parser unit tests (44 total); mutation-checked trailers, eviction and the 100 MB constant
- [x] Real servers: S3 listings, chunked/Content-Length sites, redirects, HEAD, keep-alive
- [ ] Reviewer pass, fix findings
- [ ] Version 1.8.0, PR, CI, merge, tag, index

Deviation from the plan: `Transfer-Encoding: gzip, chunked` raises `ParseError` (unsupported coding) instead of being decoded, because decoding only the chunking would return still-gzipped bytes silently.

---

# requests 1.7.0 — docs, limits, deadline + retries, HTTP/2 multiplexing, benchmarks

Plan: `~/.claude/plans/shimmering-skipping-lobster.md`. Branch `requests-1.7.0`.

- [x] Baseline on master: test 114+4, hpack 128, h2 70, h2-conn 4, h2-client 3, std-compat 1
- [x] Docs: CLAUDE.md rewritten (was describing the pre-1.0 OpenSSL/symlink layout), README, versions aligned (pixi.toml 2.0.0 -> 1.7.0)
- [x] Limits: `max_response_bytes`, `max_header_bytes` (HTTP/1.1 header cap was effectively 100 MB; chunked / close-delimited bodies had no cap)
- [x] Deadline `total_timeout_secs` + retries (`max_retries`, `retry_backoff_ms`, `retry_non_idempotent`), `TimeoutError`
- [x] HTTP/2: response/header caps, flow-controlled uploads, SETTINGS ACK, GOAWAY per stream, `h2_request_many`, `HttpClient.get_many`
- [x] Bugs found on the way: h2 uploads > ~16 KB failed (DATA frame + header > TLS record limit); conn window was set from SETTINGS_INITIAL_WINDOW_SIZE; `main.mojo` and `bench_profile.mojo` did not run on current defaults
- [x] Tests: test_resilience (38), test_h2_local (28); old suites unchanged and green
- [x] Benchmarks: bench_h2.mojo, master vs branch
- [x] Reviewer pass: fixed h2 slot left open after a failed fresh-connection request, early-END_STREAM during upload (RST_STREAM NO_ERROR), SETTINGS validation and summed window delta, malformed :status, get_many ignoring retries; left as documented limits: plain-HTTP stall overshoot, POST replay on a fresh connection after a pooled failure, unbounded trailers and n x max_body memory across a batch
- [x] Limits from the review fixed: plain-TCP reads capped to the deadline, no replay of POST/PATCH on a stale pooled connection (behaviour change), `max_batch_bytes` + cumulative header/trailer cap, Retry-After past the deadline returns the response
- [ ] Tag `v1.7.0`, update mojo-pkg-index (separate repo, needs approval)

---

# Phase 15E — ALPN "" H2 Probe + H1 Fallback

## Commit 1 — http_client.mojo: proto=="" probe H2, fallback to fresh H1 ✅
- [x] Add `elif len(proto) == 0:` branch in Phase 3 of `_do_request`
- [x] Probe H2 with try/except around `h2_preface_and_settings_exchange`
- [x] On success: store in H2 pool, return response
- [x] On failure: close `new_h2`, open fresh TCP+TLS (no ALPN), do H1
- [x] `proto == "http/1.1"` branch unchanged (uses existing `new_tls`)
- [x] `pixi run test` — 113/113 pass
- [x] `pixi run test-h2-client` — 3/3 pass
- [x] httpbin.org GET via HttpClient returns 200 (verified manually)
- [x] Commit, push PR, CI green, merge, tag v2.0.1
