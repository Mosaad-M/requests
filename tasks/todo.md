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
