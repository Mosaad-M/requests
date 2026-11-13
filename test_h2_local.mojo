# ============================================================================
# test_h2_local.mojo — HTTP/2 against a local server (multiplexing, flow
# control, limits, GOAWAY, deadline). No public network needed.
# ============================================================================
#
# Requires test_h2_server.py (ports 18443-18445; needs the `h2` package).
# Run: pixi run test-h2-local
#
# ============================================================================

from std.time import perf_counter_ns
from tcp import TcpSocket
from tls.socket import TlsSocket
from crypto.cert import X509Cert, cert_parse
from crypto.pem import pem_decode
from hpack import HpackHeader, HpackDynTable, hpack_encode_block, hpack_decode_block
from h2_conn import (
    Http2Conn,
    H2Request,
    h2_preface_and_settings_exchange,
    h2_request,
    h2_request_many,
)
from http_client import HttpClient, HttpHeaders

comptime NORMAL = "https://localhost:18443"
comptime LIMITED = "https://localhost:18444"
comptime GOAWAY = "https://localhost:18445"


def assert_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected " + String(expected) + ", got " + String(actual))


def assert_str(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected '" + expected + "', got '" + actual + "'")


def assert_true(condition: Bool, label: String) raises:
    if not condition:
        raise Error(label + ": expected True")


def now_ms() -> Int:
    return Int(perf_counter_ns()) // 1_000_000


def test_ca() raises -> List[X509Cert]:
    var pem = String("")
    with open("certs/ca.pem", "r") as f:
        pem = f.read()
    var certs = List[X509Cert]()
    var ders = pem_decode(pem, "CERTIFICATE")
    for i in range(len(ders)):
        certs.append(cert_parse(ders[i]))
    return certs^


def local_client() raises -> HttpClient:
    var c = HttpClient(allow_private_ips=True)
    c._ca_bundle = test_ca()
    c._ca_loaded = True
    return c^


def raw_conn(port: Int) raises -> Http2Conn:
    """An h2 connection made by hand, for testing h2_request / h2_request_many."""
    var tcp = TcpSocket()
    tcp.connect("localhost", port, reject_private_ips=False)
    var tls = TlsSocket(tcp.detach())
    var alpn = List[String]()
    alpn.append("h2")
    tls.connect("localhost", test_ca(), alpn_protocols=alpn)
    var conn = Http2Conn()
    conn._tls = tls^
    h2_preface_and_settings_exchange(conn)
    return conn^


def req(path: String, port: Int = 18443) -> H2Request:
    var h = List[HpackHeader]()
    h.append(HpackHeader(":authority", "localhost:" + String(port)))
    return H2Request("GET", path, h^, List[UInt8]())


def pattern(n: Int) -> String:
    """n bytes of a,b,..,z,a,.. (matches the server's check)."""
    var b = List[UInt8](capacity=n)
    for i in range(n):
        b.append(UInt8(97 + i % 26))
    return String(unsafe_from_utf8=b^)


# ── HttpClient over HTTP/2 ───────────────────────────────────────────────────


def test_single_get_over_h2() raises:
    var c = local_client()
    var r = c.get(NORMAL + "/n/1")
    assert_eq(r.status_code, 200, "status")
    assert_str(r.body, "resp-1", "body")
    assert_str(r.status_text, "", "HTTP/2 has no reason phrase")


def test_get_many_in_order() raises:
    var c = local_client()
    var urls = List[String]()
    for i in range(8):
        urls.append(NORMAL + "/n/" + String(i))
    var rs = c.get_many(urls)
    assert_eq(len(rs), 8, "count")
    for i in range(8):
        assert_str(rs[i].body, "resp-" + String(i), "body " + String(i))
        assert_str(rs[i].status_text, "", "stream " + String(i) + " served over h2")


def test_get_many_is_concurrent() raises:
    # 5 requests, each held 400 ms by the server. Sequential: 2000 ms.
    # First goes alone (400), the other four overlap (400): about 800 ms.
    var c = local_client()
    var urls = List[String]()
    for i in range(5):
        urls.append(NORMAL + "/n/" + String(i) + "?ms=400")
    var t0 = now_ms()
    var rs = c.get_many(urls)
    var took = now_ms() - t0
    assert_eq(len(rs), 5, "count")
    for i in range(5):
        assert_str(rs[i].body, "resp-" + String(i), "body " + String(i))
    assert_true(took < 1500, "requests overlapped, took " + String(took) + " ms")


def test_get_many_beyond_concurrent_stream_limit() raises:
    # Server allows 2 concurrent streams; 12 URLs must still all arrive in order.
    var c = local_client()
    var urls = List[String]()
    for i in range(12):
        urls.append(LIMITED + "/n/" + String(i) + "?ms=50")
    var rs = c.get_many(urls)
    assert_eq(len(rs), 12, "count")
    for i in range(12):
        assert_str(rs[i].body, "resp-" + String(i), "body " + String(i))


def test_get_many_mixed_statuses() raises:
    var c = local_client()
    var urls = List[String]()
    urls.append(NORMAL + "/n/0")
    urls.append(NORMAL + "/status/404")
    urls.append(NORMAL + "/status/204")
    urls.append(NORMAL + "/n/3")
    var rs = c.get_many(urls)
    assert_eq(rs[0].status_code, 200, "0")
    assert_eq(rs[1].status_code, 404, "1")
    assert_eq(rs[2].status_code, 204, "2")
    assert_eq(rs[3].status_code, 200, "3")


def test_get_many_two_hosts() raises:
    var c = local_client()
    var urls = List[String]()
    urls.append(NORMAL + "/n/a")
    urls.append(LIMITED + "/n/b")
    urls.append(NORMAL + "/n/c")
    urls.append(LIMITED + "/n/d")
    var rs = c.get_many(urls)
    assert_str(rs[0].body, "resp-a", "a")
    assert_str(rs[1].body, "resp-b", "b")
    assert_str(rs[2].body, "resp-c", "c")
    assert_str(rs[3].body, "resp-d", "d")


def test_large_download_with_flow_control() raises:
    var c = local_client()
    var r = c.get(NORMAL + "/large?kb=600")
    assert_eq(r.status_code, 200, "status")
    assert_eq(r.body.byte_length(), 600 * 1024, "all 600 KB arrived")


def test_upload_respects_flow_control() raises:
    # The server's stream window is 16384 and the connection window 65535:
    # 200 KB cannot go out without waiting for WINDOW_UPDATEs.
    var c = local_client()
    var sizes = List[Int]()
    sizes.append(1)
    sizes.append(16384)
    sizes.append(16385)
    sizes.append(65535)
    sizes.append(65536)
    sizes.append(200000)
    for k in range(len(sizes)):
        var n = sizes[k]
        var r = c.post(NORMAL + "/echo", pattern(n))
        assert_eq(r.status_code, 200, "status for " + String(n))
        var j = r.json()
        assert_eq(j.get_int("len"), n, "server received all " + String(n) + " bytes")
        assert_true(j.get_bool("ok"), "payload intact for " + String(n))


def test_interim_response_skipped() raises:
    var c = local_client()
    var r = c.get(NORMAL + "/interim")
    assert_eq(r.status_code, 200, "final status, not 103")
    assert_str(r.body, "after-interim", "body")


def test_trailers_do_not_break_response() raises:
    var c = local_client()
    var r = c.get(NORMAL + "/trailers")
    assert_eq(r.status_code, 200, "status")
    assert_str(r.body, "with-trailers", "body")


def test_mid_connection_settings_acknowledged() raises:
    var c = local_client()
    assert_str(c.get(NORMAL + "/midsettings").body, "settings-sent", "first")
    assert_str(c.get(NORMAL + "/acked").body, "yes", "server saw our SETTINGS ACK")


def test_stream_reset_fails_only_that_request() raises:
    var c = local_client()
    var raised = False
    try:
        _ = c.get(NORMAL + "/rst")
    except e:
        raised = True
        assert_true("RST_STREAM" in String(e), "error names RST_STREAM: " + String(e))
    assert_true(raised, "reset stream must raise")
    assert_str(c.get(NORMAL + "/n/ok").body, "resp-ok", "client still works")


# ── Limits ───────────────────────────────────────────────────────────────────


def test_h2_body_limit() raises:
    var c = local_client()
    c.max_response_bytes = 100 * 1024
    var raised = False
    try:
        _ = c.get(NORMAL + "/large?kb=300")
    except e:
        raised = True
        assert_true("size limit" in String(e), "error mentions the limit: " + String(e))
    assert_true(raised, "300 KB over a 100 KB limit must raise")
    assert_eq(c.get(NORMAL + "/large?kb=50").status_code, 200, "under the limit still works")


def test_h2_header_limit_and_continuation() raises:
    var c = local_client()
    c.max_header_bytes = 100 * 1024
    var r = c.get(NORMAL + "/hdrbig?kb=40")
    assert_eq(r.status_code, 200, "40 KB header block (CONTINUATION) accepted")
    assert_eq(r.headers.get("x-big").byte_length(), 40 * 1024, "header value intact")
    var c2 = local_client()
    c2.max_header_bytes = 16 * 1024
    var raised = False
    try:
        _ = c2.get(NORMAL + "/hdrbig?kb=40")
    except e:
        raised = True
        assert_true("size limit" in String(e), "error mentions the limit: " + String(e))
    assert_true(raised, "40 KB header block over a 16 KB limit must raise")


def test_hpack_decode_limit() raises:
    # 3000 copies of one 1 KB header: the compressed block is ~1 KB + 3000 index
    # bytes, the decoded list is ~3 MB.
    var enc = HpackDynTable(65536)
    var headers = List[HpackHeader]()
    var big = String("")
    for _ in range(1024):
        big += "a"
    for _ in range(3000):
        headers.append(HpackHeader("x-bomb", big))
    var block = hpack_encode_block(headers, enc, False)
    assert_true(len(block) < 6000, "block is small: " + String(len(block)))
    var dec = HpackDynTable(65536)
    var raised = False
    try:
        _ = hpack_decode_block(block, dec, 64 * 1024)
    except e:
        raised = True
        assert_true("size limit" in String(e), String(e))
    assert_true(raised, "decoded list over the limit must raise")
    var dec2 = HpackDynTable(65536)
    assert_eq(len(hpack_decode_block(block, dec2)), 3000, "no limit: decodes everything")


# ── h2_request_many directly ─────────────────────────────────────────────────


def test_request_many_isolates_failures() raises:
    var conn = raw_conn(18443)
    var reqs = List[H2Request]()
    reqs.append(req("/n/0"))
    reqs.append(req("/rst"))
    reqs.append(req("/n/2"))
    var rs = h2_request_many(conn, reqs)
    assert_str(rs[0].error, "", "stream 0 ok")
    assert_eq(rs[0].status, 200, "stream 0 status")
    assert_true("RST_STREAM" in rs[1].error, "stream 1 reset: " + rs[1].error)
    assert_str(rs[2].error, "", "stream 2 ok")
    assert_eq(len(rs[2].body), 6, "stream 2 body")
    # the connection survives
    var again = h2_request_many(conn, [req("/n/3")])
    assert_eq(again[0].status, 200, "connection reusable")


def test_request_many_keeps_h2_request_signature() raises:
    var conn = raw_conn(18443)
    var h = List[HpackHeader]()
    h.append(HpackHeader(":authority", "localhost:18443"))
    var r = h2_request(conn, "GET", "/n/9", h, List[UInt8]())
    assert_eq(r[0], 200, "status")
    assert_eq(len(r[2]), 6, "body")


def test_raw_upload_obeys_peer_windows() raises:
    # No client-level retry here: a window overrun makes the server drop the
    # connection and h2_request raise. The first request lets the server's
    # 16384-byte stream window (sent after its first SETTINGS) take effect.
    var conn = raw_conn(18443)
    var h = List[HpackHeader]()
    h.append(HpackHeader(":authority", "localhost:18443"))
    _ = h2_request(conn, "GET", "/n/0", h, List[UInt8]())
    var body = List[UInt8](capacity=200000)
    for i in range(200000):
        body.append(UInt8(97 + i % 26))
    var r = h2_request(conn, "POST", "/echo", h, body)
    assert_eq(r[0], 200, "status")
    var text = String(unsafe_from_utf8=r[2].copy())
    assert_true("\"len\": 200000" in text and "true" in text, "server got every byte intact: " + text)


def test_request_many_goaway_marks_unopened_streams() raises:
    var conn = raw_conn(18445)
    var reqs = List[H2Request]()
    for i in range(6):
        reqs.append(req("/n/" + String(i) + "?ms=100", 18445))
    var rs = h2_request_many(conn, reqs)
    var ok = 0
    var goaway = 0
    for i in range(6):
        if rs[i].error == "":
            ok += 1
        elif rs[i].error.startswith("GOAWAY"):
            goaway += 1
    assert_eq(ok, 3, "first three streams answered")
    assert_eq(goaway, 3, "the rest report GOAWAY (safe to resend)")
    assert_true(conn._goaway, "connection flagged so it is not reused")


def test_request_many_deadline() raises:
    var conn = raw_conn(18443)
    var reqs = List[H2Request]()
    reqs.append(req("/n/0?ms=3000"))
    var raised = False
    var t0 = now_ms()
    try:
        _ = h2_request_many(conn, reqs, deadline_ns=Int(perf_counter_ns()) + 1_000_000_000)
    except e:
        raised = True
        assert_true(String(e).startswith("TimeoutError"), String(e))
    assert_true(raised, "must time out")
    assert_true(now_ms() - t0 < 2500, "near the deadline")


# ── GOAWAY, deadline and retries through HttpClient ──────────────────────────


def test_get_many_survives_goaway() raises:
    var c = local_client()
    var urls = List[String]()
    for i in range(6):
        urls.append(GOAWAY + "/n/" + String(i) + "?ms=100")
    var rs = c.get_many(urls)
    assert_eq(len(rs), 6, "count")
    for i in range(6):
        assert_str(rs[i].body, "resp-" + String(i), "body " + String(i))


def test_h2_deadline() raises:
    var c = local_client()
    c.total_timeout_secs = 1
    var t0 = now_ms()
    var raised = False
    try:
        _ = c.get(NORMAL + "/n/1?ms=3000")
    except e:
        raised = True
        assert_true(String(e).startswith("TimeoutError"), String(e))
    assert_true(raised, "must time out")
    assert_true(now_ms() - t0 < 2500, "near the deadline")
    # a later call on the same client is not poisoned
    c.total_timeout_secs = 0
    assert_str(c.get(NORMAL + "/n/ok").body, "resp-ok", "client usable afterwards")


def test_get_many_deadline() raises:
    var c = local_client()
    c.total_timeout_secs = 1
    var urls = List[String]()
    for i in range(4):
        urls.append(NORMAL + "/n/" + String(i) + "?ms=3000")
    var raised = False
    var t0 = now_ms()
    try:
        _ = c.get_many(urls)
    except e:
        raised = True
        assert_true(String(e).startswith("TimeoutError"), String(e))
    assert_true(raised, "must time out")
    assert_true(now_ms() - t0 < 2500, "near the deadline")


def test_h2_retry_on_503() raises:
    var c = local_client()
    c.max_retries = 2
    c.retry_backoff_ms = 100
    var t0 = now_ms()
    var r = c.get(NORMAL + "/status/503")
    var took = now_ms() - t0
    assert_eq(r.status_code, 503, "last 503 returned")
    assert_true(took >= 140, "waited between attempts, took " + String(took) + " ms")


def test_header_and_trailer_limit_is_cumulative() raises:
    var c = local_client()
    c.max_header_bytes = 16 * 1024
    var raised = False
    try:
        _ = c.get(NORMAL + "/hdrtrailer?kb=10")   # 10 KB header + 10 KB trailer
    except e:
        raised = True
        assert_true("size limit" in String(e), String(e))
    assert_true(raised, "two 10 KB blocks over a 16 KB limit must raise")
    var c2 = local_client()
    c2.max_header_bytes = 64 * 1024
    assert_eq(c2.get(NORMAL + "/hdrtrailer?kb=10").status_code, 200, "fits a 64 KB limit")


def test_batch_total_limit() raises:
    var conn = raw_conn(18443)
    var reqs = List[H2Request]()
    for i in range(4):
        reqs.append(req("/large?kb=100"))
    var rs = h2_request_many(conn, reqs, max_total=250 * 1024)
    var ok = 0
    var capped = 0
    for i in range(4):
        if rs[i].error == "":
            ok += 1
        elif rs[i].error == "batch size limit":
            capped += 1
    assert_true(capped >= 1, "some stream hit the batch cap")
    assert_true(ok >= 1, "others finished")


def test_get_many_batch_limit_falls_back() raises:
    var c = local_client()
    c.max_batch_bytes = 250 * 1024
    var urls = List[String]()
    for _ in range(5):
        urls.append(NORMAL + "/large?kb=100")
    var rs = c.get_many(urls)
    for i in range(5):
        assert_eq(rs[i].body.byte_length(), 100 * 1024, "body " + String(i) + " complete")


def test_get_many_retries_503() raises:
    var c = local_client()
    c.max_retries = 1
    c.retry_backoff_ms = 100
    var urls = List[String]()
    urls.append(NORMAL + "/n/0")
    urls.append(NORMAL + "/status/503")
    var t0 = now_ms()
    var rs = c.get_many(urls)
    assert_eq(rs[1].status_code, 503, "last 503 returned after the retry")
    assert_true(now_ms() - t0 >= 45, "waited before retrying")


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

    print("=== HTTP/2 local-server tests ===")
    print("(Requires test_h2_server.py on localhost:18443-18445)")
    print()

    run_test[test_single_get_over_h2]("single GET over h2", passed, failed)
    run_test[test_get_many_in_order]("get_many: in order", passed, failed)
    run_test[test_get_many_is_concurrent]("get_many: requests overlap", passed, failed)
    run_test[test_get_many_beyond_concurrent_stream_limit]("get_many: beyond MAX_CONCURRENT_STREAMS", passed, failed)
    run_test[test_get_many_mixed_statuses]("get_many: mixed statuses", passed, failed)
    run_test[test_get_many_two_hosts]("get_many: two hosts interleaved", passed, failed)
    run_test[test_large_download_with_flow_control]("600 KB download", passed, failed)
    run_test[test_upload_respects_flow_control]("uploads 1 B .. 200 KB respect flow control", passed, failed)
    run_test[test_interim_response_skipped]("1xx interim response skipped", passed, failed)
    run_test[test_trailers_do_not_break_response]("trailers do not break the response", passed, failed)
    run_test[test_mid_connection_settings_acknowledged]("mid-connection SETTINGS acknowledged", passed, failed)
    run_test[test_stream_reset_fails_only_that_request]("RST_STREAM fails only that request", passed, failed)

    run_test[test_h2_body_limit]("h2 body limit", passed, failed)
    run_test[test_h2_header_limit_and_continuation]("h2 header limit + CONTINUATION", passed, failed)
    run_test[test_hpack_decode_limit]("HPACK decode limit (indexed-field amplification)", passed, failed)

    run_test[test_request_many_isolates_failures]("h2_request_many: failure isolation", passed, failed)
    run_test[test_request_many_keeps_h2_request_signature]("h2_request keeps its signature", passed, failed)
    run_test[test_raw_upload_obeys_peer_windows]("h2_request: upload obeys peer windows", passed, failed)
    run_test[test_request_many_goaway_marks_unopened_streams]("h2_request_many: GOAWAY", passed, failed)
    run_test[test_request_many_deadline]("h2_request_many: deadline", passed, failed)

    run_test[test_get_many_survives_goaway]("get_many survives GOAWAY", passed, failed)
    run_test[test_h2_deadline]("h2 total deadline", passed, failed)
    run_test[test_get_many_deadline]("get_many total deadline", passed, failed)
    run_test[test_h2_retry_on_503]("h2 retry on 503", passed, failed)
    run_test[test_header_and_trailer_limit_is_cumulative]("h2 header+trailer limit is cumulative", passed, failed)
    run_test[test_batch_total_limit]("h2_request_many: batch total limit", passed, failed)
    run_test[test_get_many_batch_limit_falls_back]("get_many: batch limit falls back to single GETs", passed, failed)
    run_test[test_get_many_retries_503]("get_many retries 503", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
