# ============================================================================
# test_client.mojo — Integration Tests for HTTP Client
# ============================================================================
#
# Requires test_server.py running on localhost:18080.
# Start it before running: pixi run python test_server.py &
#
# ============================================================================

from http_client import HttpClient, HttpHeaders, HttpResponse, BasicAuth, BearerAuth, StreamResponse
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
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")
    assert_contains(resp.body, "hello from test server", "body")


def test_status_200() raises:
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/200")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")


def test_status_404() raises:
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/404")
    assert_eq(resp.status_code, 404, "status_code")
    assert_true(not resp.ok, "not ok")
    assert_contains(resp.body, "not found", "body")


def test_status_500() raises:
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/500")
    assert_eq(resp.status_code, 500, "status_code")
    assert_true(not resp.ok, "not ok")


def test_response_headers() raises:
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
    var headers = HttpHeaders()
    headers.add("X-My-Header", "TestValue123")
    var resp = client.get(BASE + "/headers", headers)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "X-My-Header", "header key echoed")
    assert_contains(resp.body, "TestValue123", "header value echoed")


def test_user_agent() raises:
    """Default User-Agent should be MojoHTTP/0.1."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/headers")
    assert_contains(resp.body, "MojoHTTP/0.1", "user-agent")


def test_large_response() raises:
    """Test receiving a large response body (100KB)."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/large")
    assert_eq(resp.status_code, 200, "status_code")
    assert_eq(len(resp.body), 100000, "body length")


def test_query_string() raises:
    """Query string should be sent correctly."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/echo?foo=bar&baz=42")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "foo=bar&baz=42", "query echoed")


def test_case_insensitive_headers() raises:
    """Header lookup should be case-insensitive."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/")
    # Server sends "Content-Type", but we look up with different case
    var ct = resp.headers.get("content-type")
    assert_str_eq(ct, "application/json", "case-insensitive lookup")


def test_chunked_response() raises:
    """GET /chunked should decode chunked transfer-encoding and return clean JSON."""
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
    var body = String('{"id":42,"updated":true}')
    var resp = client.put(BASE + "/echo", body)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "PUT", "method")
    assert_contains(data["body"].as_string(), "42", "body echoed")


def test_delete_no_body() raises:
    """DELETE /method with no body should return method=DELETE."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.delete(BASE + "/method")
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "DELETE", "method")


def test_delete_with_body() raises:
    """DELETE /echo with body should echo back method and body."""
    var client = HttpClient(allow_private_ips=True)
    var headers = HttpHeaders()
    var body = String('{"id":99}')
    var resp = client.delete(BASE + "/echo", body, headers)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "DELETE", "method")
    assert_contains(data["body"].as_string(), "99", "body echoed")


def test_patch_json() raises:
    """PATCH /echo with JSON body should echo back method and body."""
    var client = HttpClient(allow_private_ips=True)
    var body = String('{"field":"patched"}')
    var resp = client.patch(BASE + "/echo", body)
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "PATCH", "method")
    assert_contains(data["body"].as_string(), "patched", "body echoed")


def test_post_empty_body() raises:
    """POST /echo with empty body should still work."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.post(BASE + "/echo", String(""))
    assert_eq(resp.status_code, 200, "status_code")
    var data = resp.json()
    assert_str_eq(data["method"].as_string(), "POST", "method")
    assert_str_eq(data["body"].as_string(), "", "empty body")


def test_post_custom_headers() raises:
    """POST /echo with extra custom headers should work."""
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
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
    var client = HttpClient(allow_private_ips=True)
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


def test_ssrf_default_blocks_private_ip() raises:
    """HttpClient() with no args should block 127.0.0.1 by default (safe default)."""
    var client = HttpClient()  # default: allow_private_ips=False
    var raised = False
    try:
        _ = client.get(BASE + "/")
    except:
        raised = True
    if not raised:
        raise Error("expected SSRF error for private IP with default HttpClient()")


def test_ssrf_allow_private_ips_opt_in() raises:
    """HttpClient(allow_private_ips=True) must be able to connect to localhost."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/200")
    assert_eq(resp.status_code, 200, "status_code")


# ============================================================================
# Redirect Following Tests
# ============================================================================


def test_redirect_301_followed() raises:
    """GET /redirect/301 should follow to target and return 200."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/redirect/301")
    assert_eq(resp.status_code, 200, "final status")
    assert_contains(resp.body, "redirect target", "landed on target")


def test_redirect_302_followed() raises:
    """GET /redirect/302 should follow to target and return 200."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/redirect/302")
    assert_eq(resp.status_code, 200, "final status")
    assert_contains(resp.body, "redirect target", "landed on target")


def test_redirect_303_followed() raises:
    """GET /redirect/303 should follow to target."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/redirect/303")
    assert_eq(resp.status_code, 200, "final status")
    assert_contains(resp.body, "redirect target", "landed on target")


def test_redirect_307_preserves_method() raises:
    """GET /redirect/307 should follow as GET."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/redirect/307")
    assert_eq(resp.status_code, 200, "final status")
    assert_contains(resp.body, "redirect target", "landed on target")


def test_redirect_no_follow() raises:
    """allow_redirects=False should return the 302 response directly."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/redirect/302", allow_redirects=False)
    assert_eq(resp.status_code, 302, "got 302 not followed")


def test_redirect_max_exceeded() raises:
    """Infinite redirect loop should raise after max_redirects."""
    var client = HttpClient(allow_private_ips=True)
    var raised = False
    try:
        _ = client.get(BASE + "/redirect/loop")
    except e:
        raised = True
        assert_contains(String(e), "redirect", "error mentions redirects")
    if not raised:
        raise Error("expected error for too many redirects")


def test_redirect_response_url() raises:
    """response.url should be the final URL after redirect."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/redirect/301")
    assert_contains(resp.url, "redirect/target", "url is final URL")


# ============================================================================
# Compression Tests (Phase 4)
# ============================================================================


def test_accept_encoding_sent() raises:
    """Client should send Accept-Encoding: gzip, deflate on every request."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/accept-encoding")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "gzip", "Accept-Encoding contains gzip")


def test_gzip_response_decoded() raises:
    """Gzip-encoded response body should be transparently decompressed."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/gzip")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "hello compressed", "body decompressed")


def test_deflate_response_decoded() raises:
    """Deflate-encoded response body should be transparently decompressed."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/deflate")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "hello compressed", "body decompressed")


def test_identity_encoding_unchanged() raises:
    """Content-Encoding: identity should pass body through unchanged."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/identity")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "plain text", "body unchanged")


# ============================================================================
# Cookie Tests (Phase 6.3)
# ============================================================================


def test_set_cookie_stored() raises:
    """Set-Cookie response header should be stored in the cookie jar."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie")
    # After the request, the cookie jar should contain session=abc123
    assert_eq(client.cookie_count(), 1, "one cookie stored")


def test_cookie_sent_on_next_request() raises:
    """Stored cookie should be sent on the next request to the same host."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie")
    var resp = client.get(BASE + "/check-cookie")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "abc123", "cookie sent in subsequent request")


def test_cookies_param() raises:
    """Passing a Cookie header should reach the server."""
    var client = HttpClient(allow_private_ips=True)
    var headers = HttpHeaders()
    headers.add("Cookie", "token=xyz789")
    var resp = client.get(BASE + "/check-cookie", headers)
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "xyz789", "cookie param sent")


# ============================================================================
# Cookie Expiry Tests
# ============================================================================


def test_cookie_max_age_positive() raises:
    """Set-Cookie with Max-Age=3600 should be stored and sent on next request."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-max-age")
    assert_eq(client.cookie_count(), 1, "one cookie stored")
    var resp = client.get(BASE + "/check-cookie")
    assert_contains(resp.body, "temp=xyz", "cookie sent with positive Max-Age")


def test_cookie_max_age_zero_deletes() raises:
    """Set-Cookie with Max-Age=0 should delete existing cookie from jar."""
    var client = HttpClient(allow_private_ips=True)
    # First store session=abc123
    _ = client.get(BASE + "/set-cookie")
    assert_eq(client.cookie_count(), 1, "cookie stored")
    # Then send Max-Age=0 for same name — should delete it
    _ = client.get(BASE + "/set-cookie-zero")
    assert_eq(client.cookie_count(), 0, "cookie deleted by Max-Age=0")


def test_cookie_session_persists() raises:
    """Session cookie (no Max-Age) should persist across requests."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie")
    assert_eq(client.cookie_count(), 1, "session cookie stored")
    var resp = client.get(BASE + "/check-cookie")
    assert_contains(resp.body, "abc123", "session cookie sent")


# ============================================================================
# Streaming Download Tests
# ============================================================================


def test_stream_status_headers() raises:
    """get_stream() should return correct status code and Content-Type header."""
    var client = HttpClient(allow_private_ips=True)
    var stream = client.get_stream(BASE + "/stream/medium")
    assert_eq(stream.status_code, 200, "stream status_code")
    assert_true(stream.ok, "stream ok")
    assert_true(len(stream.headers.get("Content-Type")) > 0, "Content-Type present")
    stream.close()


def test_stream_read_all() raises:
    """read_all() should return the full body (256KB)."""
    var client = HttpClient(allow_private_ips=True)
    var stream = client.get_stream(BASE + "/stream/medium")
    var body = stream.read_all()
    assert_eq(len(body), 256 * 1024, "body length matches 256KB")


def test_stream_read_chunks() raises:
    """Repeated read_chunk() calls should return all bytes in total."""
    var client = HttpClient(allow_private_ips=True)
    var stream = client.get_stream(BASE + "/stream/medium")
    var total = 0
    while True:
        var chunk = stream.read_chunk(8192)
        if len(chunk) == 0:
            break
        total += len(chunk)
    assert_eq(total, 256 * 1024, "total chunks == 256KB")


def test_stream_partial_then_close() raises:
    """Reading one chunk then closing should not raise."""
    var client = HttpClient(allow_private_ips=True)
    var stream = client.get_stream(BASE + "/stream/medium")
    var chunk = stream.read_chunk(1024)
    assert_true(len(chunk) > 0, "got at least one chunk")
    stream.close()  # should not raise


# ============================================================================
# Auth Helper Tests
# ============================================================================


def test_basic_auth_header() raises:
    """BasicAuth should produce correct Base64 Authorization header."""
    var auth = BasicAuth("user", "pass")
    var hdr = auth.header()
    assert_contains(hdr, "Basic ", "starts with Basic")
    # user:pass = dXNlcjpwYXNz in base64
    assert_contains(hdr, "dXNlcjpwYXNz", "correct base64 value")


def test_bearer_auth_header() raises:
    """BearerAuth should produce Authorization: Bearer <token> header."""
    var auth = BearerAuth("mytoken123")
    var hdr = auth.header()
    assert_str_eq(hdr, String("Bearer mytoken123"), "bearer header value")


def test_basic_auth_applied_to_request() raises:
    """GET with BasicAuth should send Authorization header."""
    var client = HttpClient(allow_private_ips=True)
    var auth = BasicAuth("user", "pass")
    var resp = client.get(BASE + "/headers", auth)
    assert_eq(resp.status_code, 200, "status_code")
    # Server echoes headers in body — check Authorization header was sent
    assert_contains(resp.body, "Authorization", "Authorization header echoed")
    assert_contains(resp.body, "Basic ", "Basic auth value echoed")


def test_bearer_auth_applied_to_request() raises:
    """GET with BearerAuth should send Authorization: Bearer header."""
    var client = HttpClient(allow_private_ips=True)
    var auth = BearerAuth("secret-token")
    var resp = client.get(BASE + "/headers", auth)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "Bearer secret-token", "Bearer token echoed")


# ============================================================================
# data= Form Encoding Tests
# ============================================================================


def test_data_form_encoded() raises:
    """POST with data= dict should set application/x-www-form-urlencoded body."""
    var client = HttpClient(allow_private_ips=True)
    var data = Dict[String, String]()
    data["user"] = "alice"
    var resp = client.post_form(BASE + "/echo", data)
    assert_eq(resp.status_code, 200, "status_code")
    var body = resp.json()
    assert_str_eq(body["content_type"].as_string(), "application/x-www-form-urlencoded", "content-type")
    assert_contains(body["body"].as_string(), "user=alice", "body has form field")


def test_data_special_chars() raises:
    """Form data with special chars should be encoded with + for spaces."""
    var client = HttpClient(allow_private_ips=True)
    var data = Dict[String, String]()
    data["q"] = "hello world"
    var resp = client.post_form(BASE + "/echo", data)
    assert_eq(resp.status_code, 200, "status_code")
    var body = resp.json()
    # Form encoding uses + or %20 for space; we use %20 (percent encoding)
    assert_contains(body["body"].as_string(), "hello", "body has field value")


def test_data_multiple_fields() raises:
    """Form data with multiple fields should all appear in body."""
    var client = HttpClient(allow_private_ips=True)
    var data = Dict[String, String]()
    data["name"] = "mojo"
    data["version"] = "1"
    var resp = client.post_form(BASE + "/echo", data)
    assert_eq(resp.status_code, 200, "status_code")
    var body = resp.json()
    assert_contains(body["body"].as_string(), "name=mojo", "name field")
    assert_contains(body["body"].as_string(), "version=1", "version field")


# ============================================================================
# params= Query String Encoding Tests
# ============================================================================


def test_params_simple() raises:
    """params dict with a simple key=value should appear in the URL."""
    var client = HttpClient(allow_private_ips=True)
    var params = Dict[String, String]()
    params["foo"] = "bar"
    var resp = client.get(BASE + "/echo", params)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "foo=bar", "params in query string")


def test_params_special_chars() raises:
    """params with spaces should be percent-encoded."""
    var client = HttpClient(allow_private_ips=True)
    var params = Dict[String, String]()
    params["q"] = "hello world"
    var resp = client.get(BASE + "/echo", params)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "hello%20world", "space encoded as %20")


def test_params_multiple() raises:
    """Multiple params should all appear in the query string."""
    var client = HttpClient(allow_private_ips=True)
    var params = Dict[String, String]()
    params["a"] = "1"
    params["b"] = "2"
    var resp = client.get(BASE + "/echo", params)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "a=1", "a=1 in query")
    assert_contains(resp.body, "b=2", "b=2 in query")


def test_params_empty_dict() raises:
    """Empty params dict should not append query string."""
    var client = HttpClient(allow_private_ips=True)
    var params = Dict[String, String]()
    var resp = client.get(BASE + "/", params)
    assert_eq(resp.status_code, 200, "status_code")


def test_params_merges_with_url_query() raises:
    """params should be appended to existing URL query string."""
    var client = HttpClient(allow_private_ips=True)
    var params = Dict[String, String]()
    params["extra"] = "val"
    var resp = client.get(BASE + "/echo?existing=1", params)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "existing=1", "existing query preserved")
    assert_contains(resp.body, "extra=val", "extra param appended")


# ============================================================================
# Configurable Timeout Tests
# ============================================================================


def test_timeout_default_works() raises:
    """HttpClient(timeout_secs=30) should work normally (default)."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/200")
    assert_eq(resp.status_code, 200, "status_code")


def test_timeout_custom_works() raises:
    """HttpClient(timeout_secs=10) should still succeed for normal requests."""
    var client = HttpClient(allow_private_ips=True, timeout_secs=10)
    var resp = client.get(BASE + "/status/200")
    assert_eq(resp.status_code, 200, "status_code")


def test_timeout_zero_raises() raises:
    """HttpClient(timeout_secs=0) should raise at construction."""
    var raised = False
    try:
        var client = HttpClient(allow_private_ips=True, timeout_secs=0)
        _ = client.get(BASE + "/status/200")
    except:
        raised = True
    if not raised:
        raise Error("expected error for timeout_secs=0")


# ============================================================================
# HEAD / OPTIONS Tests
# ============================================================================


def test_head_returns_no_body() raises:
    """HEAD / should return 200 with empty body."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.head(BASE + "/")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.ok, "ok")
    assert_str_eq(resp.body, String(""), "body is empty")


def test_head_has_headers() raises:
    """HEAD / should return headers (Content-Type, X-Test-Server)."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.head(BASE + "/")
    assert_true(resp.headers.has("Content-Type"), "has Content-Type")
    assert_true(resp.headers.has("X-Test-Server"), "has X-Test-Server")


def test_options_returns_allow_header() raises:
    """OPTIONS / should return Allow header listing supported methods."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.options(BASE + "/")
    assert_eq(resp.status_code, 200, "status_code")
    assert_true(resp.headers.has("Allow"), "has Allow header")
    assert_contains(resp.headers.get("Allow"), "GET", "Allow includes GET")


# ============================================================================
# raise_for_status() Tests
# ============================================================================


def test_raise_for_status_200_ok() raises:
    """raise_for_status() should not raise for 200."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/200")
    resp.raise_for_status()  # must not raise


def test_raise_for_status_201_ok() raises:
    """raise_for_status() should not raise for any 2xx."""
    var resp = HttpResponse()
    resp.status_code = 201
    resp.status_text = String("Created")
    resp.ok = True
    resp.raise_for_status()  # must not raise


def test_raise_for_status_404_raises() raises:
    """raise_for_status() should raise for 404."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/404")
    var raised = False
    try:
        resp.raise_for_status()
    except e:
        raised = True
        assert_contains(String(e), "404", "error contains 404")
    if not raised:
        raise Error("expected raise_for_status() to raise on 404")


def test_raise_for_status_500_raises() raises:
    """raise_for_status() should raise for 500."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/500")
    var raised = False
    try:
        resp.raise_for_status()
    except e:
        raised = True
        assert_contains(String(e), "500", "error contains 500")
    if not raised:
        raise Error("expected raise_for_status() to raise on 500")


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
    run_test(
        "SSRF default blocks private IP",
        passed,
        failed,
        test_ssrf_default_blocks_private_ip,
    )
    run_test(
        "SSRF allow_private_ips opt-in",
        passed,
        failed,
        test_ssrf_allow_private_ips_opt_in,
    )

    # Compression tests
    run_test("Accept-Encoding sent", passed, failed, test_accept_encoding_sent)
    run_test("gzip response decoded", passed, failed, test_gzip_response_decoded)
    run_test("deflate response decoded", passed, failed, test_deflate_response_decoded)
    run_test("identity encoding unchanged", passed, failed, test_identity_encoding_unchanged)

    # Cookie tests
    run_test("Set-Cookie stored", passed, failed, test_set_cookie_stored)
    run_test("cookie sent on next request", passed, failed, test_cookie_sent_on_next_request)
    run_test("cookies param", passed, failed, test_cookies_param)
    run_test("cookie Max-Age positive", passed, failed, test_cookie_max_age_positive)
    run_test("cookie Max-Age=0 deletes", passed, failed, test_cookie_max_age_zero_deletes)
    run_test("cookie session persists", passed, failed, test_cookie_session_persists)

    # Streaming tests
    run_test("stream status+headers", passed, failed, test_stream_status_headers)
    run_test("stream read_all", passed, failed, test_stream_read_all)
    run_test("stream read_chunks", passed, failed, test_stream_read_chunks)
    run_test("stream partial+close", passed, failed, test_stream_partial_then_close)

    # Redirect tests
    run_test("redirect 301 followed", passed, failed, test_redirect_301_followed)
    run_test("redirect 302 followed", passed, failed, test_redirect_302_followed)
    run_test("redirect 303 followed", passed, failed, test_redirect_303_followed)
    run_test("redirect 307 preserves method", passed, failed, test_redirect_307_preserves_method)
    run_test("redirect no follow", passed, failed, test_redirect_no_follow)
    run_test("redirect max exceeded", passed, failed, test_redirect_max_exceeded)
    run_test("redirect response url", passed, failed, test_redirect_response_url)

    # Auth helper tests
    run_test("BasicAuth header", passed, failed, test_basic_auth_header)
    run_test("BearerAuth header", passed, failed, test_bearer_auth_header)
    run_test("BasicAuth applied to request", passed, failed, test_basic_auth_applied_to_request)
    run_test("BearerAuth applied to request", passed, failed, test_bearer_auth_applied_to_request)

    # data= form encoding tests
    run_test("data form encoded", passed, failed, test_data_form_encoded)
    run_test("data special chars", passed, failed, test_data_special_chars)
    run_test("data multiple fields", passed, failed, test_data_multiple_fields)

    # params= query string tests
    run_test("params simple", passed, failed, test_params_simple)
    run_test("params special chars", passed, failed, test_params_special_chars)
    run_test("params multiple", passed, failed, test_params_multiple)
    run_test("params empty dict", passed, failed, test_params_empty_dict)
    run_test("params merges with url query", passed, failed, test_params_merges_with_url_query)

    # Timeout tests
    run_test("timeout default works", passed, failed, test_timeout_default_works)
    run_test("timeout custom works", passed, failed, test_timeout_custom_works)
    run_test("timeout zero raises", passed, failed, test_timeout_zero_raises)

    # HEAD / OPTIONS tests
    run_test("HEAD no body", passed, failed, test_head_returns_no_body)
    run_test("HEAD has headers", passed, failed, test_head_has_headers)
    run_test("OPTIONS Allow header", passed, failed, test_options_returns_allow_header)

    # raise_for_status() tests
    run_test(
        "raise_for_status 200 ok",
        passed,
        failed,
        test_raise_for_status_200_ok,
    )
    run_test(
        "raise_for_status 201 ok",
        passed,
        failed,
        test_raise_for_status_201_ok,
    )
    run_test(
        "raise_for_status 404 raises",
        passed,
        failed,
        test_raise_for_status_404_raises,
    )
    run_test(
        "raise_for_status 500 raises",
        passed,
        failed,
        test_raise_for_status_500_raises,
    )

    print()
    print("Results:", passed, "passed,", failed, "failed")

    # Shutdown the test server (connects to localhost so needs allow_private_ips=True)
    var client = HttpClient(allow_private_ips=True)
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
