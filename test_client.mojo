# ============================================================================
# test_client.mojo — Integration Tests for HTTP Client
# ============================================================================
#
# Requires test_server.py running on localhost:18080.
# Start it before running: pixi run python test_server.py &
#
# ============================================================================

from http_client import HttpClient, HttpHeaders, HttpResponse
from json import JsonValue


# ============================================================================
# Test Helpers
# ============================================================================


def assert_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected " + String(expected) + ", got " + String(actual)
        )


def assert_str_eq(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected '" + expected + "', got '" + actual + "'"
        )


def assert_true(condition: Bool, label: String) raises:
    if not condition:
        raise Error(label + ": expected True")


def assert_contains(haystack: String, needle: String, label: String) raises:
    """Check that haystack contains needle."""
    var h_bytes = haystack.as_bytes()
    var n_bytes = needle.as_bytes()
    var n_len = len(needle)
    var h_len = len(haystack)
    if n_len > h_len:
        raise Error(label + ": '" + needle + "' not found in response")
    for i in range(h_len - n_len + 1):
        var found = True
        for j in range(n_len):
            if h_bytes[i + j] != n_bytes[j]:
                found = False
                break
        if found:
            return
    raise Error(label + ": '" + needle + "' not found in response")


# ============================================================================
# Tests — all use localhost:18080 test server
# ============================================================================

alias BASE = "http://127.0.0.1:18080"


def test_get_root() raises:
    """GET / should return 200 with JSON body."""
    var client = HttpClient()
    var resp = client.get(BASE + "/")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")
    assert_contains(resp.body, "hello from test server", "body")


def test_status_200() raises:
    var client = HttpClient()
    var resp = client.get(BASE + "/status/200")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")


def test_status_404() raises:
    var client = HttpClient()
    var resp = client.get(BASE + "/status/404")
    assert_eq(resp.status_code, 404, "status_code")
    assert_true(not resp.ok, "not ok")
    assert_contains(resp.body, "not found", "body")


def test_status_500() raises:
    var client = HttpClient()
    var resp = client.get(BASE + "/status/500")
    assert_eq(resp.status_code, 500, "status_code")
    assert_true(not resp.ok, "not ok")


def test_response_headers() raises:
    var client = HttpClient()
    var resp = client.get(BASE + "/")
    assert_str_eq(
        resp.headers.get("Content-Type"), "application/json", "content-type"
    )
    assert_true(resp.headers.has("Content-Length"), "has content-length")
    assert_str_eq(
        resp.headers.get("X-Test-Server"), "mojo-test/1.0", "x-test-server"
    )


def test_custom_headers() raises:
    """Custom headers should be sent and echoed back by /headers endpoint."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("X-My-Header", "TestValue123")
    var resp = client.get(BASE + "/headers", headers)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "X-My-Header", "header key echoed")
    assert_contains(resp.body, "TestValue123", "header value echoed")


def test_user_agent() raises:
    """Default User-Agent should be MojoHTTP/0.1."""
    var client = HttpClient()
    var resp = client.get(BASE + "/headers")
    assert_contains(resp.body, "MojoHTTP/0.1", "user-agent")


def test_large_response() raises:
    """Test receiving a large response body (100KB)."""
    var client = HttpClient()
    var resp = client.get(BASE + "/large")
    assert_eq(resp.status_code, 200, "status_code")
    assert_eq(len(resp.body), 100000, "body length")


def test_query_string() raises:
    """Query string should be sent correctly."""
    var client = HttpClient()
    var resp = client.get(BASE + "/echo?foo=bar&baz=42")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "foo=bar&baz=42", "query echoed")


def test_case_insensitive_headers() raises:
    """Header lookup should be case-insensitive."""
    var client = HttpClient()
    var resp = client.get(BASE + "/")
    # Server sends "Content-Type", but we look up with different case
    var ct = resp.headers.get("content-type")
    assert_str_eq(ct, "application/json", "case-insensitive lookup")


def test_chunked_response() raises:
    """GET /chunked should decode chunked transfer-encoding and return clean JSON."""
    var client = HttpClient()
    var resp = client.get(BASE + "/chunked")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")
    # Body should be clean JSON (no chunk framing)
    var data = resp.json()
    assert_str_eq(data["message"].as_string(), "chunked response", "message")
    assert_eq(data["count"].as_int(), 42, "count")


# ============================================================================
# POST / PUT / DELETE / PATCH Tests
# ============================================================================


def test_post_json() raises:
    """POST /echo with JSON body should echo back method and body."""
    var client = HttpClient()
    var body = String('{"name":"mojo","version":1}')
    var resp = client.post(BASE + "/echo", body)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "POST", "method")
    assert_contains(data["body"].as_string(), "mojo", "body echoed")
    assert_str_eq(
        data["content_type"].as_string(), "application/json", "auto content-type"
    )


def test_post_custom_content_type() raises:
    """POST with custom Content-Type should use that instead of default."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("Content-Type", "text/plain")
    var resp = client.post(BASE + "/echo", "hello world", headers)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "POST", "method")
    assert_str_eq(data["body"].as_string(), "hello world", "body")
    assert_str_eq(data["content_type"].as_string(), "text/plain", "custom content-type")


def test_put_json() raises:
    """PUT /echo with JSON body should echo back method and body."""
    var client = HttpClient()
    var body = String('{"id":42,"updated":true}')
    var resp = client.put(BASE + "/echo", body)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "PUT", "method")
    assert_contains(data["body"].as_string(), "42", "body echoed")


def test_delete_no_body() raises:
    """DELETE /method with no body should return method=DELETE."""
    var client = HttpClient()
    var resp = client.delete(BASE + "/method")
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "DELETE", "method")


def test_delete_with_body() raises:
    """DELETE /echo with body should echo back method and body."""
    var client = HttpClient()
    var headers = HttpHeaders()
    var body = String('{"id":99}')
    var resp = client.delete(BASE + "/echo", body, headers)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "DELETE", "method")
    assert_contains(data["body"].as_string(), "99", "body echoed")


def test_patch_json() raises:
    """PATCH /echo with JSON body should echo back method and body."""
    var client = HttpClient()
    var body = String('{"field":"patched"}')
    var resp = client.patch(BASE + "/echo", body)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "PATCH", "method")
    assert_contains(data["body"].as_string(), "patched", "body echoed")


def test_post_empty_body() raises:
    """POST /echo with empty body should still work."""
    var client = HttpClient()
    var resp = client.post(BASE + "/echo", String(""))
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "POST", "method")
    assert_str_eq(data["body"].as_string(), "", "empty body")


def test_post_custom_headers() raises:
    """POST /echo with extra custom headers should work."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("X-Request-ID", "abc-123")
    var body = String('{"test":true}')
    var resp = client.post(BASE + "/echo", body, headers)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "POST", "method")
    assert_contains(data["body"].as_string(), "test", "body echoed")


# ============================================================================
# Security Validation Tests (no server needed — validation rejects early)
# ============================================================================


def test_crlf_header_value_rejected() raises:
    """Header values containing CRLF should be rejected."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("X-Evil", "value\r\nInjected: header")
    var raised = False
    try:
        _ = client.get(BASE + "/", headers)
    except:
        raised = True
    if not raised:
        raise Error("expected error for CRLF in header value")


def test_crlf_header_key_rejected() raises:
    """Header keys containing CRLF should be rejected."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("X-Evil\r\nInjected", "value")
    var raised = False
    try:
        _ = client.get(BASE + "/", headers)
    except:
        raised = True
    if not raised:
        raise Error("expected error for CRLF in header key")


def test_header_key_with_colon_rejected() raises:
    """Header keys containing colon should be rejected."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("X-Evil:Extra", "value")
    var raised = False
    try:
        _ = client.get(BASE + "/", headers)
    except:
        raised = True
    if not raised:
        raise Error("expected error for colon in header key")


def test_ssrf_private_ip_blocked() raises:
    """Client with allow_private_ips=False should reject connections to 127.0.0.1."""
    var client = HttpClient()
    client.allow_private_ips = False
    var raised = False
    try:
        _ = client.get(BASE + "/")
    except:
        raised = True
    if not raised:
        raise Error("expected error for private IP when allow_private_ips=False")


# ============================================================================
# HTTPS Tests — use jsonplaceholder.typicode.com (no local server needed)
# ============================================================================

alias HTTPS_BASE = "https://jsonplaceholder.typicode.com"


def test_https_get() raises:
    """HTTPS GET should return 200 with JSON body."""
    var client = HttpClient()
    var resp = client.get(HTTPS_BASE + "/posts/1")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")
    assert_contains(resp.body, "userId", "body has userId")
    assert_contains(resp.body, "title", "body has title")


def test_https_large() raises:
    """HTTPS GET /posts should return a large JSON array."""
    var client = HttpClient()
    var resp = client.get(HTTPS_BASE + "/posts")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(len(resp.body) > 1000, "body length > 1000")


def test_https_custom_headers() raises:
    """HTTPS GET with custom Accept header."""
    var client = HttpClient()
    var headers = HttpHeaders()
    headers.add("Accept", "application/json")
    var resp = client.get(HTTPS_BASE + "/posts/1", headers)
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")


def test_https_json_parse() raises:
    """HTTPS GET /posts/1 should parse as JSON with correct fields."""
    var client = HttpClient()
    var resp = client.get(HTTPS_BASE + "/posts/1")
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_eq(data["userId"].as_int(), 1, "userId")
    assert_eq(data["id"].as_int(), 1, "id")
    assert_true(len(data["title"].as_string()) > 0, "title non-empty")


# ============================================================================
# Test Runner
# ============================================================================


def main() raises:
    var passed = 0
    var failed = 0

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
            print("  FAIL:", name, "-", String(e))
            failed += 1

    print("=== HTTP Client Integration Tests ===")
    print("(Requires test_server.py on localhost:18080)")
    print()

    run_test("GET /", passed, failed, test_get_root)
    run_test("status 200", passed, failed, test_status_200)
    run_test("status 404", passed, failed, test_status_404)
    run_test("status 500", passed, failed, test_status_500)
    run_test("response headers", passed, failed, test_response_headers)
    run_test("custom headers", passed, failed, test_custom_headers)
    run_test("user-agent", passed, failed, test_user_agent)
    run_test("large response (100KB)", passed, failed, test_large_response)
    run_test("query string", passed, failed, test_query_string)
    run_test(
        "case-insensitive headers",
        passed,
        failed,
        test_case_insensitive_headers,
    )
    run_test("chunked response", passed, failed, test_chunked_response)

    # POST / PUT / DELETE / PATCH tests
    run_test("POST JSON", passed, failed, test_post_json)
    run_test("POST custom Content-Type", passed, failed, test_post_custom_content_type)
    run_test("PUT JSON", passed, failed, test_put_json)
    run_test("DELETE no body", passed, failed, test_delete_no_body)
    run_test("DELETE with body", passed, failed, test_delete_with_body)
    run_test("PATCH JSON", passed, failed, test_patch_json)
    run_test("POST empty body", passed, failed, test_post_empty_body)
    run_test("POST custom headers", passed, failed, test_post_custom_headers)

    # Security validation tests
    run_test(
        "CRLF header value rejected",
        passed,
        failed,
        test_crlf_header_value_rejected,
    )
    run_test(
        "CRLF header key rejected",
        passed,
        failed,
        test_crlf_header_key_rejected,
    )
    run_test(
        "header key with colon rejected",
        passed,
        failed,
        test_header_key_with_colon_rejected,
    )
    run_test(
        "SSRF private IP blocked",
        passed,
        failed,
        test_ssrf_private_ip_blocked,
    )

    print()
    print("Results:", passed, "passed,", failed, "failed")

    # Shutdown the test server
    var client = HttpClient()
    try:
        _ = client.get(BASE + "/shutdown")
    except:
        pass  # Server may close before response completes

    if failed > 0:
        raise Error(String(failed) + " test(s) failed")

    # --- HTTPS Tests (no local server needed) ---
    var https_passed = 0
    var https_failed = 0

    print()
    print("=== HTTPS Integration Tests ===")
    print("(Using jsonplaceholder.typicode.com)")
    print()

    run_test("HTTPS GET /posts/1", https_passed, https_failed, test_https_get)
    run_test(
        "HTTPS GET /posts (large)",
        https_passed,
        https_failed,
        test_https_large,
    )
    run_test(
        "HTTPS custom headers",
        https_passed,
        https_failed,
        test_https_custom_headers,
    )
    run_test(
        "HTTPS JSON parse",
        https_passed,
        https_failed,
        test_https_json_parse,
    )

    print()
    print("Results:", https_passed, "passed,", https_failed, "failed")

    if https_failed > 0:
        raise Error(String(https_failed) + " HTTPS test(s) failed")
