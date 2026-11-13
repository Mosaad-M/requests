# ============================================================================
# test_resilience.mojo — limits, total deadline, retries, get_many fallback
# ============================================================================
#
# Requires test_server.py on localhost:18080 (pixi run test starts it).
# Each test uses its own `id` so the server's hit counters never collide.
#
# ============================================================================

from std.time import perf_counter_ns
from http_client import (
    HttpClient,
    HttpHeaders,
    MAX_RESPONSE_BYTES,
    MAX_HEADER_BYTES,
    _backoff_ms,
    _retry_after_ms,
    _is_transient,
    _is_idempotent,
    _is_retryable_status,
)

comptime BASE = "http://127.0.0.1:18080"
comptime KA = "http://127.0.0.1:18082"


def assert_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected " + String(expected) + ", got " + String(actual))


def assert_true(condition: Bool, label: String) raises:
    if not condition:
        raise Error(label + ": expected True")


def new_client() raises -> HttpClient:
    var c = HttpClient(allow_private_ips=True)
    return c^


def now_ms() -> Int:
    return Int(perf_counter_ns()) // 1_000_000


def hits(ident: String) raises -> Int:
    var c = new_client()
    return c.get(BASE + "/hits?id=" + ident).json().get_int("hits")


def expect_error(prefix: String, got: String, label: String) raises:
    if not got.startswith(prefix):
        raise Error(label + ": expected error starting with '" + prefix + "', got '" + got + "'")


# ── Defaults and validation ──────────────────────────────────────────────────


def test_defaults_keep_old_behaviour() raises:
    var c = new_client()
    assert_eq(c.total_timeout_secs, 0, "total_timeout_secs")
    assert_eq(c.max_retries, 0, "max_retries")
    assert_eq(c.max_response_bytes, MAX_RESPONSE_BYTES, "max_response_bytes")
    assert_eq(c.max_header_bytes, MAX_HEADER_BYTES, "max_header_bytes")
    assert_true(not c.retry_non_idempotent, "retry_non_idempotent")
    assert_eq(MAX_RESPONSE_BYTES, 100 * 1024 * 1024, "100 MB body cap unchanged")


def _invalid(field: Int) raises:
    var c = new_client()
    if field == 0:
        c.total_timeout_secs = -1
    elif field == 1:
        c.max_retries = -1
    elif field == 2:
        c.retry_backoff_ms = -1
    elif field == 3:
        c.max_response_bytes = 0
    elif field == 4:
        c.max_batch_bytes = 0
    else:
        c.max_header_bytes = 0
    var raised = False
    try:
        _ = c.get(BASE + "/")
    except e:
        raised = True
        expect_error("ValidationError", String(e), "field " + String(field))
    if not raised:
        raise Error("field " + String(field) + ": expected ValidationError")


def test_invalid_settings_rejected() raises:
    for f in range(6):
        _invalid(f)


# ── Size limits ──────────────────────────────────────────────────────────────


def test_body_limit_content_length() raises:
    var c = new_client()
    c.max_response_bytes = 1024
    assert_eq(c.get(BASE + "/bigbody?kb=1").status_code, 200, "exactly at limit")
    var raised = False
    try:
        _ = c.get(BASE + "/bigbody?kb=2")
    except e:
        raised = True
        expect_error("ConnectionError", String(e), "content-length")
    assert_true(raised, "2 KB body over a 1 KB limit must raise")


def test_body_limit_chunked() raises:
    var c = new_client()
    c.max_response_bytes = 2048
    var raised = False
    try:
        _ = c.get(BASE + "/bigchunked?kb=64")
    except e:
        raised = True
        expect_error("ConnectionError", String(e), "chunked")
    assert_true(raised, "chunked body over the limit must raise")
    # and the same client still works (the pool slot was not left half-read)
    c.max_response_bytes = MAX_RESPONSE_BYTES
    assert_eq(c.get(BASE + "/bigchunked?kb=4").status_code, 200, "recovers")


def test_body_limit_close_delimited() raises:
    var c = new_client()
    c.max_response_bytes = 2048
    var raised = False
    try:
        _ = c.get(BASE + "/bigclose?kb=64")
    except e:
        raised = True
        expect_error("ConnectionError", String(e), "close-delimited")
    assert_true(raised, "close-delimited body over the limit must raise")


def test_header_limit() raises:
    var c = new_client()
    c.max_header_bytes = 4096
    assert_eq(c.get(BASE + "/bighdr?kb=1").status_code, 200, "1 KB header under a 4 KB limit")
    var raised = False
    try:
        _ = c.get(BASE + "/bighdr?kb=8")
    except e:
        raised = True
        expect_error("ConnectionError", String(e), "header")
    assert_true(raised, "8 KB header over a 4 KB limit must raise")


def test_default_header_limit_allows_normal_headers() raises:
    var c = new_client()
    assert_eq(c.get(BASE + "/bighdr?kb=60").status_code, 200, "60 KB header under the 1 MB default")


# ── Total deadline ───────────────────────────────────────────────────────────


def test_deadline_stops_slow_drip_chunked() raises:
    # 20 chunks * 200 ms = 4 s of steady progress: no read ever stalls.
    var c = new_client()
    c.total_timeout_secs = 1
    var t0 = now_ms()
    var raised = False
    try:
        _ = c.get(BASE + "/slowdrip?chunks=20&gap_ms=200")
    except e:
        raised = True
        expect_error("TimeoutError", String(e), "slowdrip")
    var took = now_ms() - t0
    assert_true(raised, "slow drip must hit the deadline")
    assert_true(took < 2500, "stopped near the 1 s deadline, took " + String(took) + " ms")


def test_deadline_not_hit_when_fast() raises:
    var c = new_client()
    c.total_timeout_secs = 5
    assert_eq(c.get(BASE + "/").status_code, 200, "fast request under a 5 s deadline")
    # the deadline is per call: a second call gets a fresh clock
    assert_eq(c.get(BASE + "/").status_code, 200, "second call")


def test_deadline_stall_reported_as_timeout() raises:
    # A stalled server: the 2 s socket timeout fires after the 1 s deadline.
    var c = HttpClient(allow_private_ips=True, timeout_secs=2)
    c.total_timeout_secs = 1
    var t0 = now_ms()
    var raised = False
    try:
        _ = c.get(BASE + "/delay?ms=5000")
    except e:
        raised = True
        expect_error("TimeoutError", String(e), "stall")
    var took = now_ms() - t0
    assert_true(raised, "stall must raise")
    assert_true(took < 3500, "bounded by the socket timeout, took " + String(took) + " ms")


def test_deadline_caps_plain_http_stall() raises:
    # Default 30 s socket timeout, 1 s deadline: the read timeout is cut to the deadline.
    var c = new_client()
    c.total_timeout_secs = 1
    var t0 = now_ms()
    var raised = False
    try:
        _ = c.get(BASE + "/delay?ms=6000")
    except e:
        raised = True
        expect_error("TimeoutError", String(e), "plain stall")
    assert_true(raised, "stall must raise")
    assert_true(now_ms() - t0 < 2500, "stopped near the deadline, took " + String(now_ms() - t0) + " ms")
    # the pooled socket's normal timeout comes back after a successful call
    c.total_timeout_secs = 5
    assert_eq(c.get(BASE + "/").status_code, 200, "fast call under a deadline")
    c.total_timeout_secs = 0
    assert_eq(c.get(BASE + "/delay?ms=1500").status_code, 200, "no stale 5 s cap afterwards")


def test_deadline_caps_stall_on_pooled_connection() raises:
    # A fresh connection gets its socket timeout from connect(); a pooled one
    # keeps whatever it had, so the deadline has to cut its read timeout itself.
    var c = new_client()
    assert_eq(c.get(KA + "/live-ok").status_code, 200, "warm the pool")
    c.total_timeout_secs = 1
    var t0 = now_ms()
    var raised = False
    try:
        _ = c.get(KA + "/live-stall")
    except e:
        raised = True
        expect_error("TimeoutError", String(e), "pooled stall")
    assert_true(raised, "stall must raise")
    assert_true(now_ms() - t0 < 2500, "stopped near the deadline, took " + String(now_ms() - t0) + " ms")


def test_deadline_spans_redirects() raises:
    var c = new_client()
    c.total_timeout_secs = 1
    var raised = False
    try:
        # 6 hops * 400 ms: every hop is fast enough alone.
        _ = c.get(BASE + "/slow-redirect?hops=5&ms=400")
    except e:
        raised = True
        expect_error("TimeoutError", String(e), "redirects")
    assert_true(raised, "redirect chain must share one deadline")


def test_deadline_spans_retries() raises:
    var c = new_client()
    c.total_timeout_secs = 1
    c.max_retries = 50
    c.retry_backoff_ms = 300
    var t0 = now_ms()
    # Retries stop when the next wait would pass the deadline; the last 503 comes back.
    var r = c.get(BASE + "/flaky?id=dl-retry&n=1000")
    var took = now_ms() - t0
    assert_eq(r.status_code, 503, "last response returned")
    assert_true(took < 2500, "took " + String(took) + " ms")
    assert_true(hits("dl-retry") < 10, "did not hammer the server")
    assert_true(hits("dl-retry") >= 2, "but did retry")


def test_deadline_resets_after_error() raises:
    var c = new_client()
    c.total_timeout_secs = 1
    try:
        _ = c.get(BASE + "/slowdrip?chunks=20&gap_ms=200")
    except:
        pass
    c.total_timeout_secs = 0
    assert_eq(c.get(BASE + "/delay?ms=1200").status_code, 200, "no stale deadline after a failure")


# ── Retries ──────────────────────────────────────────────────────────────────


def test_no_retry_by_default() raises:
    var c = new_client()
    var r = c.get(BASE + "/flaky?id=r-default&n=1")
    assert_eq(r.status_code, 503, "503 returned as is")
    assert_eq(hits("r-default"), 1, "one attempt")


def test_retry_recovers() raises:
    var c = new_client()
    c.max_retries = 3
    c.retry_backoff_ms = 10
    var r = c.get(BASE + "/flaky?id=r-ok&n=2")
    assert_eq(r.status_code, 200, "third attempt succeeds")
    assert_eq(hits("r-ok"), 3, "three attempts")


def test_retry_exhausted_returns_last_response() raises:
    var c = new_client()
    c.max_retries = 2
    c.retry_backoff_ms = 10
    var r = c.get(BASE + "/flaky?id=r-exh&n=100")
    assert_eq(r.status_code, 503, "last 503 returned")
    assert_eq(hits("r-exh"), 3, "1 + 2 retries")


def test_post_not_retried_by_default() raises:
    var c = new_client()
    c.max_retries = 3
    c.retry_backoff_ms = 10
    var r = c.post(BASE + "/flaky?id=r-post&n=1", "{}")
    assert_eq(r.status_code, 503, "POST 503 returned")
    assert_eq(hits("r-post"), 1, "POST sent once")


def test_post_retried_when_opted_in() raises:
    var c = new_client()
    c.max_retries = 3
    c.retry_backoff_ms = 10
    c.retry_non_idempotent = True
    var r = c.post(BASE + "/flaky?id=r-post2&n=1", "{}")
    assert_eq(r.status_code, 200, "POST retried")
    assert_eq(hits("r-post2"), 2, "two attempts")


def test_put_and_delete_are_idempotent() raises:
    var c = new_client()
    c.max_retries = 2
    c.retry_backoff_ms = 10
    assert_eq(c.put(BASE + "/flaky?id=r-put&n=1", "{}").status_code, 200, "PUT retried")
    assert_eq(c.delete(BASE + "/flaky?id=r-del&n=1").status_code, 200, "DELETE retried")


def test_non_retryable_status_not_retried() raises:
    var c = new_client()
    c.max_retries = 3
    c.retry_backoff_ms = 10
    var r = c.get(BASE + "/flaky?id=r-404&n=5&code=404")
    assert_eq(r.status_code, 404, "404 returned")
    assert_eq(hits("r-404"), 1, "404 is not retried")


def test_retry_after_honoured() raises:
    var c = new_client()
    c.max_retries = 1
    c.retry_backoff_ms = 10
    var t0 = now_ms()
    var r = c.get(BASE + "/flaky?id=r-after&n=1&retry_after=1")
    var took = now_ms() - t0
    assert_eq(r.status_code, 200, "retried after Retry-After")
    assert_true(took >= 900, "waited for Retry-After, took " + String(took) + " ms")


def test_retry_after_past_deadline_returns_response() raises:
    var c = new_client()
    c.max_retries = 1
    c.total_timeout_secs = 2
    var t0 = now_ms()
    var r = c.get(BASE + "/flaky?id=r-ra-dl&n=5&retry_after=30")
    assert_eq(r.status_code, 503, "the 503 itself, not a TimeoutError")
    assert_true(now_ms() - t0 < 1500, "did not wait for Retry-After")
    assert_eq(hits("r-ra-dl"), 1, "no retry was possible")


def ka_hits(path: String) raises -> Int:
    var c = new_client()
    return c.get(BASE + "/hits?id=ka" + path).json().get_int("hits")


def test_post_not_replayed_on_stale_pooled_connection() raises:
    var c = new_client()
    assert_eq(c.post(KA + "/stale-post", "{}").status_code, 200, "first POST")
    var raised = False
    try:
        _ = c.post(KA + "/stale-post", "{}")   # pooled connection is dead
    except:
        raised = True
    assert_true(raised, "POST must not be silently sent again")
    assert_eq(ka_hits("/stale-post"), 1, "the server saw it once")


def test_post_replayed_when_opted_in() raises:
    var c = new_client()
    c.retry_non_idempotent = True
    assert_eq(c.post(KA + "/stale-post2", "{}").status_code, 200, "first POST")
    assert_eq(c.post(KA + "/stale-post2", "{}").status_code, 200, "replayed on a new connection")
    assert_eq(ka_hits("/stale-post2"), 2, "two requests reached the server")


def test_get_replayed_on_stale_pooled_connection() raises:
    var c = new_client()
    assert_eq(c.get(KA + "/stale-get").status_code, 200, "first GET")
    assert_eq(c.get(KA + "/stale-get").status_code, 200, "GET quietly replayed")


def test_connection_reset_retried() raises:
    var c = new_client()
    c.max_retries = 2
    c.retry_backoff_ms = 10
    var r = c.get(BASE + "/reset?id=r-reset&n=1")
    assert_eq(r.status_code, 200, "recovered after a dropped connection")
    assert_eq(hits("r-reset"), 2, "two attempts")


def test_connection_reset_raises_without_retries() raises:
    var c = new_client()
    var raised = False
    try:
        _ = c.get(BASE + "/reset?id=r-reset2&n=1")
    except:
        raised = True
    assert_true(raised, "no retries: the failure surfaces")


def test_validation_error_not_retried() raises:
    var c = new_client()
    c.max_retries = 3
    var h = HttpHeaders()
    h.add("X-Bad", "a\r\nInjected: 1")
    var raised = False
    try:
        _ = c.get(BASE + "/", h)
    except e:
        raised = True
        expect_error("ValidationError", String(e), "crlf")
    assert_true(raised, "CRLF header must raise ValidationError")


def test_retry_with_deadline_validation() raises:
    # retries and deadline together: success inside the deadline
    var c = new_client()
    c.max_retries = 3
    c.retry_backoff_ms = 10
    c.total_timeout_secs = 5
    assert_eq(c.get(BASE + "/flaky?id=r-both&n=2").status_code, 200, "retry within deadline")


# ── Retry helpers (pure functions) ───────────────────────────────────────────


def test_backoff_schedule() raises:
    for _ in range(50):
        var a = _backoff_ms(100, 0)
        assert_true(a >= 50 and a <= 100, "attempt 0 in [50,100]: " + String(a))
        var b = _backoff_ms(100, 3)
        assert_true(b >= 400 and b <= 800, "attempt 3 in [400,800]: " + String(b))
        var capped = _backoff_ms(100, 40)
        assert_true(capped >= 15000 and capped <= 30000, "capped at 30 s: " + String(capped))
    assert_eq(_backoff_ms(0, 5), 0, "zero base means no wait")


def test_retry_after_parse() raises:
    assert_eq(_retry_after_ms("5"), 5000, "5 s")
    assert_eq(_retry_after_ms("0"), 0, "0 s")
    assert_eq(_retry_after_ms("999"), 60000, "clamped to 60 s")
    assert_eq(_retry_after_ms(""), -1, "absent")
    assert_eq(_retry_after_ms("abc"), -1, "garbage")
    assert_eq(_retry_after_ms("Wed, 21 Oct 2026 07:28:00 GMT"), -1, "HTTP-date falls back to backoff")
    assert_eq(_retry_after_ms("-5"), -1, "negative")


def test_transient_classification() raises:
    assert_true(_is_transient("ConnectionError: empty response from server"), "empty response")
    assert_true(_is_transient("tcp: recv timed out"), "tcp timeout")
    assert_true(_is_transient("tcp: connection reset by peer"), "reset")
    assert_true(_is_transient("tcp: cannot connect to x:1 (refused)"), "refused")
    assert_true(not _is_transient("TimeoutError: total timeout exceeded"), "deadline is final")
    assert_true(not _is_transient("ConnectionError: response headers exceed size limit"), "size limit")
    assert_true(not _is_transient("ValidationError: bad header"), "validation")
    assert_true(not _is_transient("tls: certificate verify failed"), "certificate")
    assert_true(not _is_transient("tcp: cannot connect to 10.0.0.1:80 (private address blocked)"), "ssrf block")


def test_method_and_status_classification() raises:
    for m in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]:
        assert_true(_is_idempotent(String(m)), String(m))
    for m in ["POST", "PATCH"]:
        assert_true(not _is_idempotent(String(m)), String(m))
    for code in [429, 502, 503, 504]:
        assert_true(_is_retryable_status(code), String(code))
    for code in [200, 301, 400, 404, 500, 501]:
        assert_true(not _is_retryable_status(code), String(code))


# ── get_many over plain HTTP (sequential fallback) ───────────────────────────


def test_get_many_plain_http_in_order() raises:
    var c = new_client()
    var urls = List[String]()
    urls.append(BASE + "/echo?a=1")
    urls.append(BASE + "/status/404")
    urls.append(BASE + "/echo?c=3")
    var rs = c.get_many(urls)
    assert_eq(len(rs), 3, "three responses")
    assert_eq(rs[0].status_code, 200, "first")
    assert_eq(rs[1].status_code, 404, "second keeps its status")
    assert_eq(rs[2].status_code, 200, "third")
    assert_true("c=3" in rs[2].body or "3" in rs[2].body, "third body belongs to third url")


def test_get_many_empty() raises:
    var c = new_client()
    assert_eq(len(c.get_many(List[String]())), 0, "empty in, empty out")


def test_get_many_follows_redirects() raises:
    var c = new_client()
    var urls = List[String]()
    urls.append(BASE + "/redirect/302")
    var rs = c.get_many(urls)
    assert_eq(rs[0].status_code, 200, "redirect followed")


def main() raises:
    var passed = 0
    var failed = 0

    def run_test[test_fn: def () thin raises -> None](name: String, mut passed: Int, mut failed: Int):
        try:
            test_fn()
            print("  PASS:", name)
            passed += 1
        except e:
            print("  FAIL:", name, "-", String(e))
            failed += 1

    print("=== Resilience: limits, deadline, retries ===")
    print("(Requires test_server.py on localhost:18080)")
    print()

    run_test[test_defaults_keep_old_behaviour]("defaults keep old behaviour", passed, failed)
    run_test[test_invalid_settings_rejected]("invalid settings rejected", passed, failed)

    run_test[test_body_limit_content_length]("body limit (Content-Length)", passed, failed)
    run_test[test_body_limit_chunked]("body limit (chunked)", passed, failed)
    run_test[test_body_limit_close_delimited]("body limit (close-delimited)", passed, failed)
    run_test[test_header_limit]("header limit", passed, failed)
    run_test[test_default_header_limit_allows_normal_headers]("default header limit allows 60 KB", passed, failed)

    run_test[test_deadline_not_hit_when_fast]("deadline: fast request unaffected", passed, failed)
    run_test[test_deadline_stops_slow_drip_chunked]("deadline: slow drip stopped", passed, failed)
    run_test[test_deadline_stall_reported_as_timeout]("deadline: stall reported as TimeoutError", passed, failed)
    run_test[test_deadline_caps_plain_http_stall]("deadline: plain-HTTP stall capped", passed, failed)
    run_test[test_deadline_caps_stall_on_pooled_connection]("deadline: pooled-connection stall capped", passed, failed)
    run_test[test_deadline_spans_redirects]("deadline: spans redirects", passed, failed)
    run_test[test_deadline_spans_retries]("deadline: spans retries", passed, failed)
    run_test[test_deadline_resets_after_error]("deadline: no stale state after failure", passed, failed)

    run_test[test_no_retry_by_default]("retry: off by default", passed, failed)
    run_test[test_retry_recovers]("retry: recovers from 503", passed, failed)
    run_test[test_retry_exhausted_returns_last_response]("retry: exhausted returns last response", passed, failed)
    run_test[test_post_not_retried_by_default]("retry: POST not retried", passed, failed)
    run_test[test_post_retried_when_opted_in]("retry: POST retried when opted in", passed, failed)
    run_test[test_put_and_delete_are_idempotent]("retry: PUT and DELETE retried", passed, failed)
    run_test[test_non_retryable_status_not_retried]("retry: 404 not retried", passed, failed)
    run_test[test_retry_after_honoured]("retry: Retry-After honoured", passed, failed)
    run_test[test_retry_after_past_deadline_returns_response]("retry: Retry-After past deadline returns the response", passed, failed)
    run_test[test_post_not_replayed_on_stale_pooled_connection]("pool: POST not replayed on a stale connection", passed, failed)
    run_test[test_post_replayed_when_opted_in]("pool: POST replayed when opted in", passed, failed)
    run_test[test_get_replayed_on_stale_pooled_connection]("pool: GET replayed on a stale connection", passed, failed)
    run_test[test_connection_reset_retried]("retry: dropped connection retried", passed, failed)
    run_test[test_connection_reset_raises_without_retries]("retry: dropped connection raises when off", passed, failed)
    run_test[test_validation_error_not_retried]("retry: validation error not retried", passed, failed)
    run_test[test_retry_with_deadline_validation]("retry: with deadline", passed, failed)

    run_test[test_backoff_schedule]("helper: backoff schedule", passed, failed)
    run_test[test_retry_after_parse]("helper: Retry-After parsing", passed, failed)
    run_test[test_transient_classification]("helper: transient classification", passed, failed)
    run_test[test_method_and_status_classification]("helper: idempotent methods / retryable statuses", passed, failed)

    run_test[test_get_many_plain_http_in_order]("get_many: plain HTTP in order", passed, failed)
    run_test[test_get_many_empty]("get_many: empty list", passed, failed)
    run_test[test_get_many_follows_redirects]("get_many: follows redirects", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
