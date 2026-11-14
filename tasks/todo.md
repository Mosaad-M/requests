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
