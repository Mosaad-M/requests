# ============================================================================
# test_h2_conn.mojo — Integration tests for Http2Conn (RFC 7540 §3)
# ============================================================================
# Requires network access. Tests make real HTTP/2 connections.
# Run: pixi run test-h2-conn
# ============================================================================

from h2_conn import Http2Conn, h2_connect, h2_request
from hpack import HpackHeader


# ── Helpers ──────────────────────────────────────────────────────────────────

def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "—", String(e))
        failed += 1


fn assert_eq_int(got: Int, expected: Int, label: String) raises:
    if got != expected:
        raise Error(label + ": expected " + String(expected) + " got " + String(got))


fn assert_true(cond: Bool, label: String) raises:
    if not cond:
        raise Error(label + ": expected True")


fn _bytes_contain_str(haystack: List[UInt8], needle: String) -> Bool:
    """Return True if haystack bytes contain the ASCII string needle."""
    var nb   = needle.as_bytes()
    var nlen = len(nb)
    var hlen = len(haystack)
    if nlen == 0 or hlen < nlen:
        return False
    for i in range(hlen - nlen + 1):
        var found = True
        for j in range(nlen):
            if haystack[i + j] != nb[j]:
                found = False
                break
        if found:
            return True
    return False


# ── 15C-6: Http2Conn Integration Tests ───────────────────────────────────────

def test_h2_connect() raises:
    """Connect to www.google.com:443 via TLS ALPN h2 without error."""
    var conn = h2_connect("www.google.com", 443)
    # If we get here the preface + SETTINGS exchange succeeded
    assert_true(conn._next_stream == 1, "next_stream starts at 1")


def test_h2_get_google() raises:
    """GET www.google.com / → status 200 or 301, non-empty body."""
    var conn    = h2_connect("www.google.com", 443)
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":authority", "www.google.com"))
    headers.append(HpackHeader("user-agent", "mojo-h2/0.1"))
    var r      = h2_request(conn, "GET", "/", headers, List[UInt8]())
    var status = r[0]
    var body   = r[2].copy()
    assert_true(status == 200 or status == 301, "status 200 or 301")
    assert_true(len(body) > 0, "non-empty body")


def test_h2_get_httpbin() raises:
    """GET httpbin.org/get → status 200, body contains 'headers'."""
    var conn    = h2_connect("httpbin.org", 443)
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":authority", "httpbin.org"))
    headers.append(HpackHeader("user-agent",  "mojo-h2/0.1"))
    headers.append(HpackHeader("accept",      "application/json"))
    var r      = h2_request(conn, "GET", "/get", headers, List[UInt8]())
    assert_eq_int(r[0], 200, "status")
    assert_true(
        _bytes_contain_str(r[2], "headers"),
        "body contains 'headers' key"
    )


def test_h2_custom_headers() raises:
    """Custom headers are reflected in the JSON response body."""
    var conn    = h2_connect("httpbin.org", 443)
    var headers = List[HpackHeader]()
    headers.append(HpackHeader(":authority",  "httpbin.org"))
    headers.append(HpackHeader("user-agent",  "mojo-h2/0.1"))
    headers.append(HpackHeader("accept",      "application/json"))
    headers.append(HpackHeader("x-test-id",   "mojo42"))
    var r = h2_request(conn, "GET", "/get", headers, List[UInt8]())
    assert_eq_int(r[0], 200, "status")
    assert_true(
        _bytes_contain_str(r[2], "mojo42"),
        "body contains x-test-id value 'mojo42'"
    )


# ── main ─────────────────────────────────────────────────────────────────────

def main() raises:
    var passed = 0
    var failed = 0

    print("=== HTTP/2 Connection Integration Tests ===")
    print("(Requires network access)")
    print()
    print("── 15C-6: Http2Conn ──")
    run_test("h2_connect to www.google.com:443", passed, failed, test_h2_connect)
    run_test("GET www.google.com / → 200 or 301, non-empty body", passed, failed, test_h2_get_google)
    run_test("GET httpbin.org/get → 200, body has 'headers'", passed, failed, test_h2_get_httpbin)
    run_test("custom header x-test-id echoed in response body", passed, failed, test_h2_custom_headers)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
