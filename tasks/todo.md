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
