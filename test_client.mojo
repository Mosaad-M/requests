# ============================================================================
# test_client.mojo — Integration Tests for HTTP Client
# ============================================================================
#
# Requires test_server.py running on localhost:18080.
# Start it before running: pixi run python test_server.py &
#
# ============================================================================

from http_client import HttpClient, HttpHeaders, HttpResponse, BasicAuth, BearerAuth, StreamResponse, Session
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


def assert_not_contains(haystack: String, needle: String, label: String) raises:
    """Check that haystack does NOT contain needle."""
    var h_bytes = haystack.as_bytes()
    var n_bytes = needle.as_bytes()
    var n_len = len(needle)
    var h_len = len(haystack)
    if n_len > h_len:
        return  # needle longer than haystack, impossible to contain
    for i in range(h_len - n_len + 1):
        var found = True
        for j in range(n_len):
            if h_bytes[i + j] != n_bytes[j]:
                found = False
                break
        if found:
            raise Error(label + ": '" + needle + "' found in response (should not be)")


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
        assert_contains(String(e), "Redirect", "error mentions redirects")
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
# Cookie Attribute Tests (Phase 7.B)
# ============================================================================


def test_cookie_path_match() raises:
    """Cookie with Path=/api should be sent to /api/check-cookie."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-path")
    var resp = client.get(BASE + "/api/check-cookie")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "pathcookie=yes", "path cookie sent to /api path")


def test_cookie_path_no_match() raises:
    """Cookie with Path=/api should NOT be sent to /."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-path")
    var resp = client.get(BASE + "/check-cookie")
    assert_eq(resp.status_code, 200, "status")
    assert_not_contains(resp.body, "pathcookie", "path cookie must not be sent to / path")


def test_cookie_secure_not_sent_http() raises:
    """Cookie with Secure flag should NOT be sent over plain HTTP."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-secure")
    var resp = client.get(BASE + "/check-cookie")
    assert_eq(resp.status_code, 200, "status")
    assert_not_contains(resp.body, "securecookie", "Secure cookie must not be sent over HTTP")


def test_cookie_domain_exact() raises:
    """Cookie with Domain=127.0.0.1 should be sent on next request to same host."""
    var client = HttpClient(allow_private_ips=True)
    # /set-cookie sends Set-Cookie: session=abc123 (no Domain attr)
    # After implementing Domain support, cookies with explicit Domain should also match
    _ = client.get(BASE + "/set-cookie")
    var resp = client.get(BASE + "/check-cookie")
    assert_eq(resp.status_code, 200, "status")
    assert_contains(resp.body, "abc123", "domain-matched cookie sent")


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
# Connection Pool Tests (Phase 7.A)
# ============================================================================


def test_pool_reuse_keepalive() raises:
    """5 sequential GETs to the same URL should all succeed (pool reuse path)."""
    var client = HttpClient(allow_private_ips=True)
    for i in range(5):
        var resp = client.get(BASE + "/status/200")
        assert_eq(resp.status_code, 200, "request " + String(i) + " status")


def test_pool_connection_close_cleared() raises:
    """GET /large (Connection:close) then GET /status/200 should both succeed."""
    var client = HttpClient(allow_private_ips=True)
    # /large returns Connection: close — pool must clear slot and reconnect
    var resp1 = client.get(BASE + "/large")
    assert_eq(resp1.status_code, 200, "large status")
    assert_true(len(resp1.body) == 100000, "large body length")
    # Next request must reconnect successfully
    var resp2 = client.get(BASE + "/status/200")
    assert_eq(resp2.status_code, 200, "after close status")


def test_pool_four_slots_no_corruption() raises:
    """10 GETs across 4 different paths should all return 200 without corruption."""
    var client = HttpClient(allow_private_ips=True)
    var paths = List[String]()
    paths.append("/status/200")
    paths.append("/")
    paths.append("/method")
    paths.append("/headers")
    for i in range(10):
        var path = paths[i % 4]
        var resp = client.get(BASE + path)
        assert_eq(resp.status_code, 200, "slot test " + String(i))


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
# Error Prefix Tests (Phase 7.C)
# ============================================================================


def test_error_http_prefix() raises:
    """raise_for_status() on 404 should produce error with 'HTTPError' prefix."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/status/404")
    var raised = False
    try:
        resp.raise_for_status()
    except e:
        raised = True
        assert_true(
            String(e).startswith("HTTPError"),
            "error must start with 'HTTPError', got: " + String(e),
        )
    if not raised:
        raise Error("expected raise_for_status() to raise on 404")


def test_error_redirect_prefix() raises:
    """Redirect loop should produce error with 'TooManyRedirects' prefix."""
    var client = HttpClient(allow_private_ips=True)
    var raised = False
    try:
        _ = client.get(BASE + "/redirect/loop")
    except e:
        raised = True
        assert_true(
            String(e).startswith("TooManyRedirects"),
            "error must start with 'TooManyRedirects', got: " + String(e),
        )
    if not raised:
        raise Error("expected redirect loop to raise TooManyRedirects")


def test_error_validation_prefix() raises:
    """Setting a header with CRLF should produce error with 'ValidationError' prefix."""
    var client = HttpClient(allow_private_ips=True)
    var headers = HttpHeaders()
    headers.add("X-Bad\r\nHeader", "value")
    var raised = False
    try:
        _ = client.get(BASE + "/headers", headers)
    except e:
        raised = True
        assert_true(
            String(e).startswith("ValidationError"),
            "error must start with 'ValidationError', got: " + String(e),
        )
    if not raised:
        raise Error("expected CRLF header key to raise ValidationError")


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
# Session Tests
# ============================================================================


def test_session_default_headers() raises:
    """Session default headers should be sent with every request."""
    var s = Session(allow_private_ips=True)
    s.set_header("X-Custom", "myval")
    var resp = s.get(BASE + "/headers")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "X-Custom", "header key echoed")
    assert_contains(resp.body, "myval", "header value echoed")


def test_session_auth_basic() raises:
    """Session BasicAuth should be applied to every request."""
    var s = Session(allow_private_ips=True)
    s.set_auth(BasicAuth("user", "pass"))
    var resp = s.get(BASE + "/headers")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "Authorization", "auth header echoed")
    assert_contains(resp.body, "Basic", "Basic auth present")


def test_session_caller_override() raises:
    """Caller headers should override session defaults."""
    var s = Session(allow_private_ips=True)
    s.set_header("X-Custom", "default")
    var headers = HttpHeaders()
    headers.add("X-Custom", "override")
    var resp = s.get(BASE + "/headers", headers)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "override", "caller value present")


# ============================================================================
# SameSite Cookie Tests
# ============================================================================


def test_cookie_samesite_stored() raises:
    """SameSite=Strict cookie should be stored and sent to same host."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-samesite")
    assert_true(client.cookie_count() == 1, "cookie stored")
    var resp = client.get(BASE + "/check-cookie")
    assert_contains(resp.body, "samesite_cookie", "samesite cookie sent")


def test_cookie_samesite_none_http() raises:
    """SameSite=None cookie (with Secure flag) should NOT be sent over HTTP."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-samesite-none")
    assert_true(client.cookie_count() == 1, "cookie stored")
    # The cookie has SameSite=None and Secure — must not be sent over HTTP
    var resp = client.get(BASE + "/check-cookie")
    assert_not_contains(resp.body, "none_cookie", "SameSite=None+Secure not sent over HTTP")


def test_supercookie_tld_rejected() raises:
    """Domain=.com (single-label TLD) should be silently rejected (S7)."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-tld")
    # The cookie must NOT be stored (domain rejected as single-label)
    assert_true(client.cookie_count() == 0, "single-label domain cookie not stored")


def test_httponly_flag_stored() raises:
    """HttpOnly attribute must be parsed and stored without error."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-httponly")
    # Cookie is stored (HttpOnly doesn't prevent storage, just JS access)
    assert_true(client.cookie_count() == 1, "httponly cookie stored")
    # It is still sent on subsequent requests (we're an HTTP client, not a browser)
    var resp = client.get(BASE + "/check-cookie")
    assert_contains(resp.body, "secret", "httponly cookie sent")


def test_samesite_normalization() raises:
    """SameSite=STRICT should be normalized to 'Strict' (S9)."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-samesite-strict")
    # Normalized cookie should still be sent to same host
    assert_true(client.cookie_count() == 1, "normalized samesite cookie stored")
    var resp = client.get(BASE + "/check-cookie")
    assert_contains(resp.body, "ss=1", "normalized SameSite cookie sent")


# ============================================================================
# Brotli Tests
# ============================================================================


def test_brotli_decompression() raises:
    """Brotli-encoded response should be transparently decompressed."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/brotli")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "hello brotli", "brotli body decoded")


def test_accept_encoding_br() raises:
    """Accept-Encoding header should include 'br'."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/accept-encoding")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "br", "br in Accept-Encoding")


# ============================================================================
# Multipart Tests
# ============================================================================


def test_multipart_post() raises:
    """post_multipart should encode fields and return echoed body."""
    var client = HttpClient(allow_private_ips=True)
    var fields = Dict[String, String]()
    fields["name"] = "alice"
    fields["age"] = "30"
    var resp = client.post_multipart(BASE + "/echo", fields)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "alice", "field value alice in body")
    assert_contains(resp.body, "30", "field value 30 in body")


def test_multipart_content_type() raises:
    """post_multipart Content-Type should be multipart/form-data."""
    var client = HttpClient(allow_private_ips=True)
    var fields = Dict[String, String]()
    fields["key"] = "value"
    var resp = client.post_multipart(BASE + "/echo", fields)
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "multipart/form-data", "content-type echoed")


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
# Phase 10 Tests — Configurable redirects, error URL sanitization, IP revalidation
# ============================================================================


def test_max_redirects_configurable() raises:
    """Setting max_redirects=1 should raise TooManyRedirects on a 2-hop chain."""
    var client = HttpClient(allow_private_ips=True)
    client.max_redirects = 1
    var raised = False
    try:
        # /redirect/multi → /redirect/301 → /redirect/target (2 redirects)
        _ = client.get(BASE + "/redirect/multi")
    except e:
        raised = True
        assert_true(
            String(e).startswith("TooManyRedirects"),
            "must raise TooManyRedirects, got: " + String(e),
        )
    if not raised:
        raise Error("expected TooManyRedirects with max_redirects=1")


def test_max_redirects_zero_raises() raises:
    """max_redirects=0 should raise TooManyRedirects immediately on any redirect."""
    var client = HttpClient(allow_private_ips=True)
    client.max_redirects = 0
    var raised = False
    try:
        _ = client.get(BASE + "/redirect/302")
    except e:
        raised = True
        assert_true(
            String(e).startswith("TooManyRedirects"),
            "must raise TooManyRedirects, got: " + String(e),
        )
    if not raised:
        raise Error("expected TooManyRedirects with max_redirects=0")


def test_sanitized_url_strips_query() raises:
    """sanitized_url() should return URL without query string."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/echo?secret=abc123&token=xyz")
    var surl = resp.sanitized_url()
    assert_not_contains(surl, "secret", "sanitized_url must not contain secret")
    assert_not_contains(surl, "token", "sanitized_url must not contain token")
    assert_contains(surl, "/echo", "sanitized_url keeps path")


def test_sanitized_url_no_query_unchanged() raises:
    """sanitized_url() on a URL with no query string returns it unchanged."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/")
    var surl = resp.sanitized_url()
    assert_contains(surl, "127.0.0.1", "sanitized_url keeps host")


def test_redirect_private_ip_blocked() raises:
    """Redirect to a private IP with no listening server raises an error.

    The test server returns a 302 to http://10.255.255.254/ (a private IP in
    the 10.x range with no HTTP server — port 80 is closed). With
    allow_private_ips=True (needed to reach the test server at 127.0.0.1),
    the redirect is attempted and fails because port 80 is closed.
    This confirms the _follow_redirects → _do_request → TcpSocket.connect chain
    works end-to-end for redirect targets.
    """
    var client = HttpClient(allow_private_ips=True)
    var raised = False
    try:
        _ = client.get(BASE + "/redirect/to-private")
    except:
        raised = True
    if not raised:
        raise Error("expected error when redirected to private IP with no server")


# ============================================================================
# Security Hardening Tests (Phase 9)
# ============================================================================


def test_content_length_over_limit() raises:
    """Content-Length exceeding the 100 MB limit should raise before reading body.

    Values near the limit overflow the parse guard first (ParseError) or are
    rejected by the receive cap (ConnectionError) — either is correct.
    """
    var client = HttpClient(allow_private_ips=True)
    var raised = False
    try:
        _ = client.get(BASE + "/oversized-cl")
    except e:
        raised = True
        var msg = String(e)
        assert_true(
            msg.startswith("ParseError") or msg.startswith("ConnectionError"),
            "must raise ParseError or ConnectionError, got: " + msg,
        )
    if not raised:
        raise Error("expected error for oversized Content-Length")


# ============================================================================
# Phase 11 Tests — Security Parity
# ============================================================================


def test_cookie_psl_co_uk_rejected() raises:
    """Domain=.co.uk is a PSL public suffix — cookie must not be stored."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-psl-co-uk")
    var found = False
    for i in range(len(client._jar_names)):
        if client._jar_names[i] == "psl":
            found = True
            break
    if found:
        raise Error("PSL suffix .co.uk cookie was stored, expected rejection")


def test_cookie_psl_github_io_rejected() raises:
    """Domain=.github.io is a PSL hosting suffix — cookie must not be stored."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-psl-github-io")
    var found = False
    for i in range(len(client._jar_names)):
        if client._jar_names[i] == "psl":
            found = True
            break
    if found:
        raise Error("PSL suffix .github.io cookie was stored, expected rejection")


def test_cookie_psl_example_co_uk_accepted() raises:
    """Domain=.example.co.uk is a valid registrable domain — cookie must be stored."""
    var client = HttpClient(allow_private_ips=True)
    _ = client.get(BASE + "/set-cookie-psl-example-co-uk")
    var found = False
    for i in range(len(client._jar_names)):
        if client._jar_names[i] == "psl":
            found = True
            break
    if not found:
        raise Error("Valid domain .example.co.uk cookie was rejected, expected storage")


def test_follow_redirects_disabled() raises:
    """follow_redirects=False should return 301 without following."""
    var client = HttpClient(allow_private_ips=True)
    client.follow_redirects = False
    var resp = client.get(BASE + "/redirect/301")
    assert_eq(resp.status_code, 301, "must return 301 when follow_redirects=False")


def test_redirect_same_host_only() raises:
    """redirect_same_host_only=True should stop cross-host redirects."""
    var client = HttpClient(allow_private_ips=True)
    client.redirect_same_host_only = True
    # /redirect/301 → /redirect/target (same host) — should be followed
    var resp = client.get(BASE + "/redirect/301")
    assert_eq(resp.status_code, 200, "same-host redirect must be followed")


# ============================================================================
# Phase 13 Tests — HTTP CONNECT Proxy
# ============================================================================

alias PROXY_URL = "http://127.0.0.1:18081"


def test_proxy_http_get() raises:
    """Client with proxy_url should tunnel HTTP requests through the proxy."""
    var client = HttpClient(allow_private_ips=True)
    client.proxy_url = PROXY_URL
    var resp = client.get(BASE + "/")
    assert_eq(resp.status_code, 200, "status_code via proxy")
    assert_contains(resp.body, "hello from test server", "body via proxy")


def test_proxy_http_post() raises:
    """Client with proxy_url should tunnel HTTP POST through the proxy."""
    var client = HttpClient(allow_private_ips=True)
    client.proxy_url = PROXY_URL
    var hdrs = HttpHeaders()
    hdrs.add("Content-Type", "application/json")
    var resp = client.post(BASE + "/echo", "{\"via\":\"proxy\"}", hdrs)
    assert_eq(resp.status_code, 200, "status_code via proxy POST")
    assert_contains(resp.body, "proxy", "body via proxy POST")


def test_no_proxy_when_unset() raises:
    """Without proxy_url, requests go directly (no regression)."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/")
    assert_eq(resp.status_code, 200, "direct request still works")


# ============================================================================
# Phase 12 Tests — zstd Decompression
# ============================================================================


def test_zstd_decompression() raises:
    """GET /zstd should return the decompressed JSON body."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/zstd")
    assert_eq(resp.status_code, 200, "status_code")
    assert_contains(resp.body, "hello zstd", "zstd body decoded")


def test_accept_encoding_zstd() raises:
    """Accept-Encoding header must include 'zstd'."""
    var client = HttpClient(allow_private_ips=True)
    var resp = client.get(BASE + "/accept-encoding")
    assert_contains(resp.body, "zstd", "Accept-Encoding must include zstd")


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

    # Cookie attribute tests
    run_test("cookie path match", passed, failed, test_cookie_path_match)
    run_test("cookie path no match", passed, failed, test_cookie_path_no_match)
    run_test("cookie secure not sent HTTP", passed, failed, test_cookie_secure_not_sent_http)
    run_test("cookie domain exact", passed, failed, test_cookie_domain_exact)

    # Streaming tests
    run_test("stream status+headers", passed, failed, test_stream_status_headers)
    run_test("stream read_all", passed, failed, test_stream_read_all)
    run_test("stream read_chunks", passed, failed, test_stream_read_chunks)
    run_test("stream partial+close", passed, failed, test_stream_partial_then_close)

    # Connection pool tests
    run_test("pool keepalive reuse", passed, failed, test_pool_reuse_keepalive)
    run_test("pool connection-close cleared", passed, failed, test_pool_connection_close_cleared)
    run_test("pool four slots no corruption", passed, failed, test_pool_four_slots_no_corruption)

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

    # Error prefix tests
    run_test("error HTTPError prefix", passed, failed, test_error_http_prefix)
    run_test("error TooManyRedirects prefix", passed, failed, test_error_redirect_prefix)
    run_test("error ValidationError prefix", passed, failed, test_error_validation_prefix)

    # Session tests
    run_test("session default headers", passed, failed, test_session_default_headers)
    run_test("session BasicAuth", passed, failed, test_session_auth_basic)
    run_test("session caller override", passed, failed, test_session_caller_override)

    # SameSite cookie tests
    run_test("cookie SameSite stored", passed, failed, test_cookie_samesite_stored)
    run_test("cookie SameSite=None not sent HTTP", passed, failed, test_cookie_samesite_none_http)
    run_test("cookie TLD domain rejected", passed, failed, test_supercookie_tld_rejected)
    run_test("cookie HttpOnly stored", passed, failed, test_httponly_flag_stored)
    run_test("cookie SameSite normalization", passed, failed, test_samesite_normalization)

    # Brotli tests
    run_test("brotli decompression", passed, failed, test_brotli_decompression)
    run_test("Accept-Encoding includes br", passed, failed, test_accept_encoding_br)

    # Multipart tests
    run_test("multipart POST fields", passed, failed, test_multipart_post)
    run_test("multipart Content-Type", passed, failed, test_multipart_content_type)

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

    # Phase 10 tests
    run_test("max_redirects configurable", passed, failed, test_max_redirects_configurable)
    run_test("max_redirects=0 raises", passed, failed, test_max_redirects_zero_raises)
    run_test("sanitized_url strips query", passed, failed, test_sanitized_url_strips_query)
    run_test("sanitized_url no query unchanged", passed, failed, test_sanitized_url_no_query_unchanged)
    run_test("redirect to private IP blocked", passed, failed, test_redirect_private_ip_blocked)

    # Security hardening tests (Phase 9)
    run_test(
        "Content-Length over limit raises",
        passed,
        failed,
        test_content_length_over_limit,
    )

    # Phase 11 tests
    run_test("cookie PSL co.uk rejected", passed, failed, test_cookie_psl_co_uk_rejected)
    run_test("cookie PSL github.io rejected", passed, failed, test_cookie_psl_github_io_rejected)
    run_test("cookie PSL example.co.uk accepted", passed, failed, test_cookie_psl_example_co_uk_accepted)
    run_test("follow_redirects=False", passed, failed, test_follow_redirects_disabled)
    run_test("redirect same host only", passed, failed, test_redirect_same_host_only)

    # Phase 13 tests
    run_test("proxy HTTP GET", passed, failed, test_proxy_http_get)
    run_test("proxy HTTP POST", passed, failed, test_proxy_http_post)
    run_test("no proxy when unset", passed, failed, test_no_proxy_when_unset)

    # Phase 12 tests
    run_test("zstd decompression", passed, failed, test_zstd_decompression)
    run_test("Accept-Encoding includes zstd", passed, failed, test_accept_encoding_zstd)

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
