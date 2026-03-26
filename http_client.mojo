# ============================================================================
# http_client.mojo — HTTP/1.1 Client
# ============================================================================
#
# Combines the URL parser and TCP socket layer into a high-level HTTP client.
#
# Architecture:
#   HttpClient.get/post/put/delete/patch(url) -> HttpResponse
#     1. parse_url(url) -> Url (scheme, host, port, path, query)
#     2. TcpSocket.connect(host, port)
#     3. Build HTTP/1.1 request string
#     4. Send request, receive response
#     5. Parse response (status line, headers, body)
#
# Uses Connection: keep-alive and a single-entry connection cache per scheme
# to reuse TCP+TLS connections across sequential requests to the same host.
#
# ============================================================================

from tcp import TcpSocket
from tls.socket import TlsSocket, load_system_ca_bundle
from crypto.cert import X509Cert
from crypto.base64 import base64_encode
from url import Url, parse_url
from json import JsonValue, parse_json
from zlib_decompress import zlib_decompress


# ============================================================================
# HttpHeaders — Key-Value Header Storage
# ============================================================================


struct HttpHeaders(Copyable, Movable, Sized):
    """HTTP headers stored as parallel lists of keys and values.

    Case-insensitive get() for header lookup (HTTP headers are case-insensitive).
    """

    var _keys: List[String]
    var _values: List[String]

    def __init__(out self):
        self._keys = List[String]()
        self._values = List[String]()

    def __copyinit__(out self, copy: Self):
        self._keys = copy._keys.copy()
        self._values = copy._values.copy()

    def __moveinit__(out self, deinit take: Self):
        self._keys = take._keys^
        self._values = take._values^

    def add(mut self, key: String, value: String):
        """Add a header key-value pair."""
        self._keys.append(key)
        self._values.append(value)

    def get(self, key: String) -> String:
        """Get header value by key (case-insensitive). Returns empty string if not found."""
        for i in range(len(self._keys)):
            if _eq_ignore_case(self._keys[i], key):
                return self._values[i]
        return String("")

    def has(self, key: String) -> Bool:
        """Check if a header exists (case-insensitive)."""
        for i in range(len(self._keys)):
            if _eq_ignore_case(self._keys[i], key):
                return True
        return False

    def __len__(self) -> Int:
        return len(self._keys)


# ============================================================================
# HttpResponse — Response Container
# ============================================================================


struct HttpResponse(Copyable, Movable):
    """HTTP response with status, headers, and body."""

    var status_code: Int
    var status_text: String
    var headers: HttpHeaders
    var body: String
    # WARNING: url stores the full request URL including any query parameters.
    # Error messages may also include the URL. Do not pass secrets in query strings
    # — use request headers or a POST body instead.
    var url: String
    var ok: Bool  # True if status_code is 200-299
    var history: List[HttpResponse]  # intermediate redirect responses (empty if no redirects)

    def __init__(out self):
        self.status_code = 0
        self.status_text = String("")
        self.headers = HttpHeaders()
        self.body = String("")
        self.url = String("")
        self.ok = False
        self.history = List[HttpResponse]()

    def __copyinit__(out self, copy: Self):
        self.status_code = copy.status_code
        self.status_text = copy.status_text
        self.headers = copy.headers.copy()
        self.body = copy.body
        self.url = copy.url
        self.ok = copy.ok
        self.history = copy.history.copy()

    def __moveinit__(out self, deinit take: Self):
        self.status_code = take.status_code
        self.status_text = take.status_text^
        self.headers = take.headers^
        self.body = take.body^
        self.url = take.url^
        self.ok = take.ok
        self.history = take.history^

    def raise_for_status(self) raises:
        """Raise an error if the response status code is 4xx or 5xx.

        Raises:
            Error with message "HTTP <code> <reason>" if status_code >= 400.
        """
        if self.status_code >= 400:
            raise Error(
                "HTTP " + String(self.status_code) + " " + self.status_text
            )

    def json(self) raises -> JsonValue:
        """Parse response body as JSON.

        Returns:
            JsonValue tree parsed from body.

        Raises:
            Error if body is not valid JSON.
        """
        return parse_json(self.body)


# ============================================================================
# Auth Helpers
# ============================================================================


struct BasicAuth(Copyable, Movable):
    """HTTP Basic Authentication (RFC 7617).

    Encodes credentials as Base64(username:password) and adds the
    Authorization: Basic <credentials> header to requests.
    """

    var username: String
    var password: String

    def __init__(out self, username: String, password: String):
        self.username = username
        self.password = password

    def __copyinit__(out self, copy: Self):
        self.username = copy.username
        self.password = copy.password

    def __moveinit__(out self, deinit take: Self):
        self.username = take.username^
        self.password = take.password^

    def header(self) -> String:
        """Return the Authorization header value: 'Basic <base64(user:pass)>'."""
        var credentials = self.username + ":" + self.password
        var span = credentials.as_bytes()
        var cred_bytes = List[UInt8](capacity=len(span))
        for i in range(len(span)):
            cred_bytes.append(span[i])
        var encoded = base64_encode(cred_bytes^)
        return "Basic " + encoded


struct BearerAuth(Copyable, Movable):
    """HTTP Bearer Token Authentication (RFC 6750).

    Adds the Authorization: Bearer <token> header to requests.
    """

    var token: String

    def __init__(out self, token: String):
        self.token = token

    def __copyinit__(out self, copy: Self):
        self.token = copy.token

    def __moveinit__(out self, deinit take: Self):
        self.token = take.token^

    def header(self) -> String:
        """Return the Authorization header value: 'Bearer <token>'."""
        return "Bearer " + self.token


# ============================================================================
# HttpClient — High-Level HTTP Client
# ============================================================================


struct HttpClient(Movable):
    """HTTP client for making HTTP requests (GET, POST, PUT, DELETE, PATCH).

    Caches the CA bundle after the first HTTPS request and maintains a
    single-entry connection pool per scheme to reuse keep-alive connections.

    Usage:
        var client = HttpClient()
        var response = client.get("http://httpbin.org/get")
        print(response.status_code)
        print(response.body)
    """

    var user_agent: String
    var allow_private_ips: Bool
    var _timeout_secs: Int  # socket send/recv timeout (seconds)

    # CA bundle cache — loaded once on first HTTPS request
    var _ca_bundle: List[X509Cert]
    var _ca_loaded: Bool

    # HTTP connection pool (one entry)
    var _http_key: String    # "host:port" or empty = no cache
    var _http_sock: TcpSocket
    var _http_valid: Bool    # True if _http_sock is usable

    # HTTPS connection pool (one entry)
    var _tls_key: String     # "host:port" or empty = no cache
    var _tls_sock: TlsSocket
    var _tls_valid: Bool     # True if _tls_sock is usable

    # Cookie jar: parallel lists of (domain, name, value)
    var _jar_domains: List[String]
    var _jar_names: List[String]
    var _jar_values: List[String]

    def __init__(
        out self,
        allow_private_ips: Bool = False,
        timeout_secs: Int = 30,
    ) raises:
        if timeout_secs <= 0:
            raise Error(
                "HttpClient: timeout_secs must be > 0, got " + String(timeout_secs)
            )
        self.user_agent = String("MojoHTTP/0.1")
        self.allow_private_ips = allow_private_ips
        self._timeout_secs = timeout_secs
        self._ca_bundle = List[X509Cert]()
        self._ca_loaded = False
        self._http_key = String("")
        self._http_sock = TcpSocket()
        self._http_valid = False
        self._tls_key = String("")
        self._tls_sock = TlsSocket(0)
        self._tls_valid = False
        self._jar_domains = List[String]()
        self._jar_names = List[String]()
        self._jar_values = List[String]()

    def __moveinit__(out self, deinit take: Self):
        self.user_agent = take.user_agent^
        self.allow_private_ips = take.allow_private_ips
        self._timeout_secs = take._timeout_secs
        self._ca_bundle = take._ca_bundle^
        self._ca_loaded = take._ca_loaded
        self._http_key = take._http_key^
        self._http_sock = take._http_sock^
        self._http_valid = take._http_valid
        self._tls_key = take._tls_key^
        self._tls_sock = take._tls_sock^
        self._tls_valid = take._tls_valid
        self._jar_domains = take._jar_domains^
        self._jar_names = take._jar_names^
        self._jar_values = take._jar_values^

    # === GET ===

    def get(mut self, url: String) raises -> HttpResponse:
        """Perform an HTTP GET request, following redirects."""
        var headers = HttpHeaders()
        return self._follow_redirects("GET", url, String(""), headers, True, 10)

    def get(mut self, url: String, headers: HttpHeaders) raises -> HttpResponse:
        """Perform an HTTP GET request with custom headers."""
        return self._follow_redirects("GET", url, String(""), headers, True, 10)

    def get(mut self, url: String, params: Dict[String, String]) raises -> HttpResponse:
        """Perform an HTTP GET request with URL query parameters."""
        var headers = HttpHeaders()
        return self._follow_redirects("GET", _append_params_to_url(url, params), String(""), headers, True, 10)

    def get(
        mut self, url: String, headers: HttpHeaders, params: Dict[String, String]
    ) raises -> HttpResponse:
        """Perform an HTTP GET request with custom headers and URL query parameters."""
        return self._follow_redirects("GET", _append_params_to_url(url, params), String(""), headers, True, 10)

    def get(mut self, url: String, auth: BasicAuth) raises -> HttpResponse:
        """Perform an HTTP GET request with Basic Authentication."""
        var headers = HttpHeaders()
        headers.add("Authorization", auth.header())
        return self._follow_redirects("GET", url, String(""), headers, True, 10)

    def get(mut self, url: String, auth: BearerAuth) raises -> HttpResponse:
        """Perform an HTTP GET request with Bearer Token Authentication."""
        var headers = HttpHeaders()
        headers.add("Authorization", auth.header())
        return self._follow_redirects("GET", url, String(""), headers, True, 10)

    def get(
        mut self, url: String, allow_redirects: Bool
    ) raises -> HttpResponse:
        """Perform an HTTP GET request, optionally not following redirects."""
        var headers = HttpHeaders()
        return self._follow_redirects("GET", url, String(""), headers, allow_redirects, 10)

    def cookie_count(self) -> Int:
        """Return the number of cookies stored in the cookie jar."""
        return len(self._jar_names)

    # === POST ===

    def post(mut self, url: String, body: String) raises -> HttpResponse:
        """Perform an HTTP POST request."""
        var headers = HttpHeaders()
        return self._do_request("POST", url, body, headers)

    def post(
        mut self, url: String, body: String, headers: HttpHeaders
    ) raises -> HttpResponse:
        """Perform an HTTP POST request with custom headers."""
        return self._do_request("POST", url, body, headers)

    def post_form(
        mut self, url: String, data: Dict[String, String]
    ) raises -> HttpResponse:
        """Perform an HTTP POST with application/x-www-form-urlencoded body."""
        var form_body = _encode_params(data)
        var headers = HttpHeaders()
        headers.add("Content-Type", "application/x-www-form-urlencoded")
        return self._do_request("POST", url, form_body, headers)

    # === PUT ===

    def put(mut self, url: String, body: String) raises -> HttpResponse:
        """Perform an HTTP PUT request."""
        var headers = HttpHeaders()
        return self._do_request("PUT", url, body, headers)

    def put(
        mut self, url: String, body: String, headers: HttpHeaders
    ) raises -> HttpResponse:
        """Perform an HTTP PUT request with custom headers."""
        return self._do_request("PUT", url, body, headers)

    # === DELETE ===

    def delete(mut self, url: String) raises -> HttpResponse:
        """Perform an HTTP DELETE request with no body."""
        var headers = HttpHeaders()
        return self._do_request("DELETE", url, String(""), headers)

    def delete(mut self, url: String, headers: HttpHeaders) raises -> HttpResponse:
        """Perform an HTTP DELETE request with custom headers."""
        return self._do_request("DELETE", url, String(""), headers)

    def delete(
        mut self, url: String, body: String, headers: HttpHeaders
    ) raises -> HttpResponse:
        """Perform an HTTP DELETE request with body and custom headers."""
        return self._do_request("DELETE", url, body, headers)

    # === PATCH ===

    def patch(mut self, url: String, body: String) raises -> HttpResponse:
        """Perform an HTTP PATCH request."""
        var headers = HttpHeaders()
        return self._do_request("PATCH", url, body, headers)

    def patch(
        mut self, url: String, body: String, headers: HttpHeaders
    ) raises -> HttpResponse:
        """Perform an HTTP PATCH request with custom headers."""
        return self._do_request("PATCH", url, body, headers)

    # === HEAD ===

    def head(mut self, url: String) raises -> HttpResponse:
        """Perform an HTTP HEAD request. Returns headers with empty body."""
        var headers = HttpHeaders()
        return self._do_request("HEAD", url, String(""), headers)

    def head(mut self, url: String, headers: HttpHeaders) raises -> HttpResponse:
        """Perform an HTTP HEAD request with custom headers."""
        return self._do_request("HEAD", url, String(""), headers)

    # === OPTIONS ===

    def options(mut self, url: String) raises -> HttpResponse:
        """Perform an HTTP OPTIONS request."""
        var headers = HttpHeaders()
        return self._do_request("OPTIONS", url, String(""), headers)

    def options(mut self, url: String, headers: HttpHeaders) raises -> HttpResponse:
        """Perform an HTTP OPTIONS request with custom headers."""
        return self._do_request("OPTIONS", url, String(""), headers)

    # === Internal ===

    def _follow_redirects(
        mut self,
        method: String,
        url: String,
        body: String,
        headers: HttpHeaders,
        allow_redirects: Bool,
        max_redirects: Int,
    ) raises -> HttpResponse:
        """Perform a request and follow HTTP redirects up to max_redirects hops.

        Redirect semantics:
        - 301/302/303: follow with GET, discard body
        - 307/308:     follow with original method and body
        - Authorization header is stripped when the host changes
        - response.history contains all intermediate responses
        - response.url is the final URL after all redirects
        """
        if not allow_redirects:
            return self._do_request(method, url, body, headers)

        var current_method = method
        var current_url = url
        var current_body = body
        var current_headers = headers.copy()
        var history = List[HttpResponse]()

        for _ in range(max_redirects + 1):
            var resp = self._do_request(
                current_method, current_url, current_body, current_headers
            )
            var sc = resp.status_code
            if sc != 301 and sc != 302 and sc != 303 and sc != 307 and sc != 308:
                resp.history = history^
                return resp^

            var location = resp.headers.get("Location")
            if len(location) == 0:
                # No Location header — return as-is
                resp.history = history^
                return resp^

            var next_url = _resolve_url(current_url, location)

            # Determine next method and body
            var next_method = current_method
            var next_body = current_body
            if sc == 301 or sc == 302 or sc == 303:
                # Convert to GET, drop body (python requests behaviour)
                next_method = "GET"
                next_body = String("")

            # Strip Authorization when host changes
            var next_headers = current_headers.copy()
            var base_parsed = parse_url(current_url)
            var next_parsed = parse_url(next_url)
            if base_parsed.host != next_parsed.host:
                var stripped = HttpHeaders()
                for i in range(len(next_headers)):
                    if not _eq_ignore_case(next_headers._keys[i], "Authorization"):
                        stripped.add(next_headers._keys[i], next_headers._values[i])
                next_headers = stripped^

            history.append(resp^)
            current_method = next_method
            current_url = next_url
            current_body = next_body
            current_headers = next_headers^

        raise Error(
            "Too many redirects (max " + String(max_redirects) + ")"
        )

    def _do_request(
        mut self,
        method: String,
        url_str: String,
        body: String,
        extra_headers: HttpHeaders,
    ) raises -> HttpResponse:
        """Internal implementation for all HTTP methods."""

        # Step 0: Validate inputs to prevent injection attacks
        _validate_method(method)
        for i in range(len(extra_headers)):
            _validate_header_key(extra_headers._keys[i])
            _validate_header_value(extra_headers._values[i])

        # Step 1: Parse URL
        var url = parse_url(url_str)
        _validate_path(url.request_path())

        # Step 2: Build HTTP request into a byte buffer (linear, not quadratic)
        var req_buf = List[UInt8](capacity=512)
        _append_str(req_buf, method)
        _append_str(req_buf, " ")
        _append_str(req_buf, url.request_path())
        _append_str(req_buf, " HTTP/1.1\r\n")
        _append_str(req_buf, "Host: ")
        _append_str(req_buf, url.host_header())
        _append_str(req_buf, "\r\n")
        _append_str(req_buf, "User-Agent: ")
        _append_str(req_buf, self.user_agent)
        _append_str(req_buf, "\r\n")
        if not extra_headers.has("Accept"):
            _append_str(req_buf, "Accept: */*\r\n")
        if not extra_headers.has("Accept-Encoding"):
            _append_str(req_buf, "Accept-Encoding: gzip, deflate\r\n")
        _append_str(req_buf, "Connection: keep-alive\r\n")

        # Add Content-Length and Content-Type for non-empty bodies
        if len(body) > 0:
            _append_str(req_buf, "Content-Length: ")
            _append_str(req_buf, String(len(body)))
            _append_str(req_buf, "\r\n")
            if not extra_headers.has("Content-Type"):
                _append_str(req_buf, "Content-Type: application/json\r\n")

        # Auto-send cookies from jar for this host
        var jar_cookie = self._jar_cookie_for(url.host)
        if len(jar_cookie) > 0 and not extra_headers.has("Cookie"):
            _append_str(req_buf, "Cookie: ")
            _append_str(req_buf, jar_cookie)
            _append_str(req_buf, "\r\n")

        # Add extra headers
        for i in range(len(extra_headers)):
            _append_str(req_buf, extra_headers._keys[i])
            _append_str(req_buf, ": ")
            _append_str(req_buf, extra_headers._values[i])
            _append_str(req_buf, "\r\n")

        _append_str(req_buf, "\r\n")  # End of headers

        # Append body if present
        if len(body) > 0:
            _append_str(req_buf, body)

        # Step 3: Send request and receive response (TLS or plain TCP)
        var raw_bytes = List[UInt8]()
        var conn_key = url.host + ":" + String(url.port)
        # HEAD responses have no body — stop reading after headers
        var skip_body = (method == "HEAD")

        if url.scheme == "https":
            # Lazy-load CA bundle (once per HttpClient lifetime)
            if not self._ca_loaded:
                self._ca_bundle = load_system_ca_bundle()
                self._ca_loaded = True

            # Try reusing cached TLS connection
            var reused = False
            if self._tls_valid and self._tls_key == conn_key:
                try:
                    _ = self._tls_sock.send(req_buf.copy())
                    raw_bytes = _recv_tls_keepalive(self._tls_sock, skip_body)
                    reused = True
                except:
                    try:
                        self._tls_sock.close()
                    except:
                        pass
                    self._tls_valid = False

            if not reused:
                # New TCP+TLS connection
                var tcp_sock = TcpSocket()
                tcp_sock.connect(
                    url.host,
                    url.port,
                    reject_private_ips=not self.allow_private_ips,
                    timeout_secs=self._timeout_secs,
                )
                var new_tls = TlsSocket(tcp_sock.fd)
                new_tls.connect(url.host, self._ca_bundle.copy())
                _ = new_tls.send(req_buf)
                raw_bytes = _recv_tls_keepalive(new_tls, skip_body)
                # Evict old cached connection (different host)
                if self._tls_valid:
                    try:
                        self._tls_sock.close()
                    except:
                        pass
                self._tls_sock = new_tls^
                self._tls_key = conn_key
                self._tls_valid = True
        else:
            # Plain HTTP
            var reused = False
            if self._http_valid and self._http_key == conn_key:
                try:
                    var request = String(unsafe_from_utf8=req_buf.copy())
                    _ = self._http_sock.send(request)
                    raw_bytes = _recv_http_keepalive(self._http_sock, skip_body)
                    reused = True
                except:
                    self._http_sock.close()
                    self._http_valid = False

            if not reused:
                var new_sock = TcpSocket()
                new_sock.connect(
                    url.host,
                    url.port,
                    reject_private_ips=not self.allow_private_ips,
                    timeout_secs=self._timeout_secs,
                )
                var request = String(unsafe_from_utf8=req_buf^)
                _ = new_sock.send(request)
                raw_bytes = _recv_http_keepalive(new_sock, skip_body)
                # Evict old cached connection
                if self._http_valid:
                    self._http_sock.close()
                self._http_sock = new_sock^
                self._http_key = conn_key
                self._http_valid = True

        if len(raw_bytes) == 0:
            raise Error("empty response from server")

        # Convert to string and parse
        var raw_response = String(unsafe_from_utf8=raw_bytes^)
        var parsed = _parse_response(raw_response, url_str)

        # Decompress body if Content-Encoding: gzip or deflate
        var ce = parsed.headers.get("Content-Encoding")
        if _eq_ignore_case(ce, "gzip") or _eq_ignore_case(ce, "x-gzip"):
            var body_bytes = parsed.body.as_bytes()
            var compressed = List[UInt8](capacity=len(body_bytes))
            for i in range(len(body_bytes)):
                compressed.append(body_bytes[i])
            var decompressed = zlib_decompress(compressed^, True)
            parsed.body = String(unsafe_from_utf8=decompressed^)
        elif _eq_ignore_case(ce, "deflate"):
            var body_bytes = parsed.body.as_bytes()
            var compressed = List[UInt8](capacity=len(body_bytes))
            for i in range(len(body_bytes)):
                compressed.append(body_bytes[i])
            var decompressed = zlib_decompress(compressed^, False)
            parsed.body = String(unsafe_from_utf8=decompressed^)

        # Store Set-Cookie headers in the cookie jar
        var set_cookie = parsed.headers.get("Set-Cookie")
        if len(set_cookie) > 0:
            self._jar_store(url.host, set_cookie)

        # If server requested connection close, invalidate cache
        var conn_hdr = parsed.headers.get("Connection")
        if _eq_ignore_case(conn_hdr, "close"):
            if url.scheme == "https" and self._tls_valid:
                try:
                    self._tls_sock.close()
                except:
                    pass
                self._tls_valid = False
            elif url.scheme != "https" and self._http_valid:
                self._http_sock.close()
                self._http_valid = False

        return parsed^

    def _jar_store(mut self, domain: String, set_cookie: String):
        """Parse Set-Cookie header value and store name=value in the jar."""
        var bytes = set_cookie.as_bytes()
        var n = len(bytes)
        # Find '=' (name/value separator)
        var eq = -1
        var semi = n  # end of name=value before first ';'
        for i in range(n):
            if bytes[i] == UInt8(61) and eq < 0:  # '='
                eq = i
            if bytes[i] == UInt8(59):  # ';'
                semi = i
                break
        if eq < 0:
            return  # no name=value, skip
        var name_buf = List[UInt8](capacity=eq)
        for i in range(eq):
            name_buf.append(bytes[i])
        var val_buf = List[UInt8](capacity=semi - eq - 1)
        for i in range(eq + 1, semi):
            val_buf.append(bytes[i])
        var name = String(unsafe_from_utf8=name_buf^)
        var value = String(unsafe_from_utf8=val_buf^)
        # Update if name already exists for this domain, else append
        for i in range(len(self._jar_names)):
            if self._jar_domains[i] == domain and self._jar_names[i] == name:
                self._jar_values[i] = value
                return
        self._jar_domains.append(domain)
        self._jar_names.append(name)
        self._jar_values.append(value)

    def _jar_cookie_for(self, domain: String) -> String:
        """Build Cookie header value from jar entries matching domain."""
        var result = List[UInt8](capacity=64)
        var first = True
        for i in range(len(self._jar_names)):
            if self._jar_domains[i] == domain:
                if not first:
                    result.append(UInt8(59))  # ';'
                    result.append(UInt8(32))  # ' '
                first = False
                _append_str(result, self._jar_names[i])
                result.append(UInt8(61))  # '='
                _append_str(result, self._jar_values[i])
        if len(result) == 0:
            return String("")
        return String(unsafe_from_utf8=result^)


# ============================================================================
# Module-Level Convenience Functions (Phase 6.1)
# ============================================================================


def http_get(url: String) raises -> HttpResponse:
    """One-shot HTTP GET with a default client."""
    var client = HttpClient()
    return client.get(url)


def http_post(url: String, body: String) raises -> HttpResponse:
    """One-shot HTTP POST with a default client."""
    var client = HttpClient()
    return client.post(url, body)


def http_put(url: String, body: String) raises -> HttpResponse:
    """One-shot HTTP PUT with a default client."""
    var client = HttpClient()
    return client.put(url, body)


def http_delete(url: String) raises -> HttpResponse:
    """One-shot HTTP DELETE with a default client."""
    var client = HttpClient()
    return client.delete(url)


def http_patch(url: String, body: String) raises -> HttpResponse:
    """One-shot HTTP PATCH with a default client."""
    var client = HttpClient()
    return client.patch(url, body)


# ============================================================================
# Keep-Alive Recv Helpers
# ============================================================================


def _list_append(mut out: List[UInt8], src: List[UInt8]):
    """Append src bytes to out with pre-reservation."""
    out.reserve(len(out) + len(src))
    for i in range(len(src)):
        out.append(src[i])


def _buf_find_crlf_crlf(buf: List[UInt8]) -> Int:
    """Find \\r\\n\\r\\n in a List[UInt8]. Returns index of \\r or -1."""
    var n = len(buf)
    for i in range(n - 3):
        if buf[i] == 13 and buf[i + 1] == 10 and buf[i + 2] == 13 and buf[i + 3] == 10:
            return i
    return -1


def _buf_find_crlf(buf: List[UInt8], start: Int) -> Int:
    """Find \\r\\n in List[UInt8] starting at start. Returns index of \\r or -1."""
    var n = len(buf)
    for i in range(start, n - 1):
        if buf[i] == 13 and buf[i + 1] == 10:
            return i
    return -1


def _buf_parse_hex(buf: List[UInt8], start: Int, end: Int) -> Int:
    """Parse hex integer from buf[start..end). Stops at non-hex or ';'."""
    var result = 0
    for i in range(start, end):
        var c = buf[i]
        if c >= 48 and c <= 57:  # 0-9
            result = result * 16 + Int(c - 48)
        elif c >= 97 and c <= 102:  # a-f
            result = result * 16 + Int(c - 97) + 10
        elif c >= 65 and c <= 70:  # A-F
            result = result * 16 + Int(c - 65) + 10
        else:
            break  # chunk extension, whitespace, or CR
    return result


def _buf_chunked_complete(buf: List[UInt8], start: Int) -> Bool:
    """Check if buf[start..] contains a complete chunked body.

    Parses chunk boundaries until terminal 0-size chunk is found and confirmed.
    """
    var pos = start
    while True:
        # Need at least "0\r\n" (3 bytes)
        if pos >= len(buf) - 2:
            return False
        # Find end of chunk-size line
        var crlf = _buf_find_crlf(buf, pos)
        if crlf < 0:
            return False  # incomplete line
        var chunk_size = _buf_parse_hex(buf, pos, crlf)
        pos = crlf + 2  # skip \r\n after size
        if chunk_size == 0:
            # Terminal chunk — need trailing \r\n (already at pos)
            return pos + 2 <= len(buf)
        # Need chunk_size data bytes + trailing \r\n
        if pos + chunk_size + 2 > len(buf):
            return False
        pos = pos + chunk_size + 2  # skip data + \r\n


def _lc(b: UInt8) -> UInt8:
    """Convert a byte to lowercase (ASCII A-Z only)."""
    if b >= 65 and b <= 90:
        return b + 32
    return b


def _buf_content_length(buf: List[UInt8], header_end: Int) -> Int:
    """Scan buf[0..header_end] case-insensitively for 'content-length: N'.

    Returns N or -1 if not found.
    "content-length:" is 15 bytes.
    """
    var i = 0
    while i <= header_end - 15:
        if (
            _lc(buf[i]) == 99        # c
            and _lc(buf[i+1]) == 111 # o
            and _lc(buf[i+2]) == 110 # n
            and _lc(buf[i+3]) == 116 # t
            and _lc(buf[i+4]) == 101 # e
            and _lc(buf[i+5]) == 110 # n
            and _lc(buf[i+6]) == 116 # t
            and buf[i+7] == 45       # -
            and _lc(buf[i+8]) == 108 # l
            and _lc(buf[i+9]) == 101 # e
            and _lc(buf[i+10]) == 110 # n
            and _lc(buf[i+11]) == 103 # g
            and _lc(buf[i+12]) == 116 # t
            and _lc(buf[i+13]) == 104 # h
            and buf[i+14] == 58      # :
        ):
            # Found — parse decimal after ':'
            var pos = i + 15
            while pos < header_end and buf[pos] == 32:
                pos += 1
            var result = 0
            while pos < header_end:
                var c = buf[pos]
                if c < 48 or c > 57:
                    break
                result = result * 10 + Int(c - 48)
                pos += 1
            return result
        i += 1
    return -1


def _buf_has_chunked(buf: List[UInt8], header_end: Int) -> Bool:
    """Check if Transfer-Encoding: chunked is present in buf[0..header_end].

    "transfer-encoding:" is 18 bytes; "chunked" is 7 bytes.
    """
    var i = 0
    while i <= header_end - 18:
        if (
            _lc(buf[i]) == 116       # t
            and _lc(buf[i+1]) == 114 # r
            and _lc(buf[i+2]) == 97  # a
            and _lc(buf[i+3]) == 110 # n
            and _lc(buf[i+4]) == 115 # s
            and _lc(buf[i+5]) == 102 # f
            and _lc(buf[i+6]) == 101 # e
            and _lc(buf[i+7]) == 114 # r
            and buf[i+8] == 45       # -
            and _lc(buf[i+9]) == 101  # e
            and _lc(buf[i+10]) == 110 # n
            and _lc(buf[i+11]) == 99  # c
            and _lc(buf[i+12]) == 111 # o
            and _lc(buf[i+13]) == 100 # d
            and _lc(buf[i+14]) == 105 # i
            and _lc(buf[i+15]) == 110 # n
            and _lc(buf[i+16]) == 103 # g
            and buf[i+17] == 58      # :
        ):
            # Found Transfer-Encoding: — skip spaces, find end of line
            var pos = i + 18
            while pos < header_end and buf[pos] == 32:
                pos += 1
            var line_end = pos
            while line_end < header_end - 1:
                if buf[line_end] == 13 and buf[line_end + 1] == 10:
                    break
                line_end += 1
            # Search "chunked" (7 bytes) case-insensitively in [pos..line_end)
            var j = pos
            while j <= line_end - 7:
                if (
                    _lc(buf[j]) == 99      # c
                    and _lc(buf[j+1]) == 104 # h
                    and _lc(buf[j+2]) == 117 # u
                    and _lc(buf[j+3]) == 110 # n
                    and _lc(buf[j+4]) == 107 # k
                    and _lc(buf[j+5]) == 101 # e
                    and _lc(buf[j+6]) == 100 # d
                ):
                    return True
                j += 1
            break
        i += 1
    return False


def _str_contains(haystack: String, needle: String) -> Bool:
    """Check if haystack string contains needle (simple byte scan)."""
    var h = haystack.as_bytes()
    var n = needle.as_bytes()
    var h_len = len(h)
    var n_len = len(n)
    if n_len > h_len:
        return False
    for i in range(h_len - n_len + 1):
        var ok = True
        for j in range(n_len):
            if h[i + j] != n[j]:
                ok = False
                break
        if ok:
            return True
    return False


def _recv_tls_keepalive(
    mut sock: TlsSocket, skip_body: Bool = False
) raises -> List[UInt8]:
    """Read exactly one complete HTTP response from a TLS keep-alive connection.

    Phase 1: accumulate data until \\r\\n\\r\\n (end of headers) is found.
    Phase 2: determine body transfer mode and read exactly the right amount:
      - Content-Length: N  → read exactly N body bytes
      - Transfer-Encoding: chunked → read until terminal 0-chunk
      - Neither → read until connection closes (graceful fallback)

    Args:
        skip_body: If True, stop after headers (used for HEAD responses).
    """
    var buf = List[UInt8]()

    # Phase 1: read until headers complete
    var header_end = -1
    while header_end < 0:
        var chunk = sock.recv(4096)
        if len(chunk) == 0:
            raise Error("http: connection closed before response headers")
        _list_append(buf, chunk)
        header_end = _buf_find_crlf_crlf(buf)

    # HEAD response: no body — return headers only
    if skip_body:
        var headers_only = List[UInt8](capacity=header_end + 4)
        for i in range(header_end + 4):
            headers_only.append(buf[i])
        return headers_only^

    # Phase 2: read body based on transfer mode
    var cl = _buf_content_length(buf, header_end)
    if cl >= 0:
        # Pre-allocate to avoid reallocs for known body size (Phase 5.1)
        buf.reserve(header_end + 4 + cl)
        var body_start = header_end + 4
        var have = len(buf) - body_start
        if cl > have:
            var more = sock.recv_exact(cl - have)
            _list_append(buf, more)
        return buf^
    elif _buf_has_chunked(buf, header_end):
        while not _buf_chunked_complete(buf, header_end + 4):
            try:
                var chunk = sock.recv(4096)
                if len(chunk) == 0:
                    break
                _list_append(buf, chunk)
            except e:
                var es = String(e)
                if _str_contains(es, "close_notify") or _str_contains(
                    es, "connection closed"
                ):
                    break
                raise Error(es)
        return buf^
    else:
        # No Content-Length or chunked — read until connection closes
        while True:
            try:
                var chunk = sock.recv(4096)
                if len(chunk) == 0:
                    break
                _list_append(buf, chunk)
            except e:
                var es = String(e)
                if _str_contains(es, "close_notify") or _str_contains(
                    es, "connection closed"
                ):
                    break
                raise Error(es)
        return buf^


def _recv_http_keepalive(
    mut sock: TcpSocket, skip_body: Bool = False
) raises -> List[UInt8]:
    """Read exactly one complete HTTP response from a TCP keep-alive connection.

    Same phase logic as _recv_tls_keepalive but uses TcpSocket primitives.

    Args:
        skip_body: If True, stop after headers (used for HEAD responses).
    """
    var buf = List[UInt8]()

    # Phase 1: read until headers complete
    var header_end = -1
    while header_end < 0:
        var chunk = sock.recv_bytes(4096)
        if len(chunk) == 0:
            raise Error("http: connection closed before response headers")
        _list_append(buf, chunk)
        header_end = _buf_find_crlf_crlf(buf)

    # HEAD response: no body — return headers only
    if skip_body:
        var headers_only = List[UInt8](capacity=header_end + 4)
        for i in range(header_end + 4):
            headers_only.append(buf[i])
        return headers_only^

    # Phase 2: read body based on transfer mode
    var cl = _buf_content_length(buf, header_end)
    if cl >= 0:
        # Pre-allocate to avoid reallocs for known body size (Phase 5.1)
        buf.reserve(header_end + 4 + cl)
        var body_start = header_end + 4
        var have = len(buf) - body_start
        if cl > have:
            var more = sock.recv_bytes_exact(cl - have)
            _list_append(buf, more)
        return buf^
    elif _buf_has_chunked(buf, header_end):
        while not _buf_chunked_complete(buf, header_end + 4):
            var chunk = sock.recv_bytes(4096)
            if len(chunk) == 0:
                break
            _list_append(buf, chunk)
        return buf^
    else:
        # No Content-Length or chunked — read until connection closes
        while True:
            var chunk = sock.recv_bytes(4096)
            if len(chunk) == 0:
                break
            _list_append(buf, chunk)
        return buf^


# ============================================================================
# Input Validation
# ============================================================================


def _validate_method(method: String) raises:
    """Validate HTTP method contains only uppercase ASCII letters (A-Z)."""
    if len(method) == 0:
        raise Error("HTTP method must not be empty")
    var bytes = method.as_bytes()
    for i in range(len(method)):
        var b = bytes[i]
        if b < UInt8(ord("A")) or b > UInt8(ord("Z")):
            raise Error("invalid HTTP method: must be uppercase ASCII letters")


def _validate_header_key(key: String) raises:
    """Validate header key contains no CR, LF, or colon characters."""
    var bytes = key.as_bytes()
    for i in range(len(key)):
        var b = bytes[i]
        if b == 13 or b == 10 or b == 58:  # \r, \n, :
            raise Error("invalid header key: contains CR, LF, or colon")


def _validate_header_value(value: String) raises:
    """Validate header value contains no CR or LF characters."""
    var bytes = value.as_bytes()
    for i in range(len(value)):
        var b = bytes[i]
        if b == 13 or b == 10:  # \r, \n
            raise Error("invalid header value: contains CR or LF")


def _validate_path(path: String) raises:
    """Validate request path contains no CR or LF characters."""
    var bytes = path.as_bytes()
    for i in range(len(path)):
        var b = bytes[i]
        if b == 13 or b == 10:  # \r, \n
            raise Error("invalid request path: contains CR or LF")


# ============================================================================
# Query String / Params Encoding
# ============================================================================


def _is_unreserved(c: UInt8) -> Bool:
    """RFC 3986: unreserved characters don't need percent-encoding."""
    # A-Z, a-z, 0-9, -, _, ., ~
    if c >= UInt8(65) and c <= UInt8(90):   # A-Z
        return True
    if c >= UInt8(97) and c <= UInt8(122):  # a-z
        return True
    if c >= UInt8(48) and c <= UInt8(57):   # 0-9
        return True
    if c == UInt8(45) or c == UInt8(95) or c == UInt8(46) or c == UInt8(126):
        return True  # - _ . ~
    return False


alias _HEX_CHARS = "0123456789ABCDEF"


def _percent_encode(s: String) -> String:
    """Percent-encode a string per RFC 3986 (for query string values)."""
    var bytes = s.as_bytes()
    var result = List[UInt8](capacity=len(s) * 3)
    var hex = _HEX_CHARS.as_bytes()
    for i in range(len(bytes)):
        var c = bytes[i]
        if _is_unreserved(c):
            result.append(c)
        else:
            result.append(UInt8(37))  # '%'
            result.append(hex[(Int(c) >> 4) & 0xF])
            result.append(hex[Int(c) & 0xF])
    return String(unsafe_from_utf8=result^)


def _encode_params(params: Dict[String, String]) raises -> String:
    """Encode a Dict[String, String] as a URL query string (key=value&key2=value2)."""
    var result = List[UInt8](capacity=128)
    var first = True
    for key in params.keys():
        if not first:
            result.append(UInt8(38))  # '&'
        first = False
        var encoded_key = _percent_encode(key)
        try:
            var encoded_val = _percent_encode(params[key])
            _append_str(result, encoded_key)
            result.append(UInt8(61))  # '='
            _append_str(result, encoded_val)
        except:
            pass
    return String(unsafe_from_utf8=result^)


def _append_params_to_url(url: String, params: Dict[String, String]) raises -> String:
    """Append encoded params to a URL, merging with existing query string."""
    if len(params) == 0:
        return url
    var query = _encode_params(params)
    if len(query) == 0:
        return url
    # Check if URL already has a query string (contains '?')
    var url_bytes = url.as_bytes()
    var has_query = False
    for i in range(len(url_bytes)):
        if url_bytes[i] == UInt8(63):  # '?'
            has_query = True
            break
    if has_query:
        return url + "&" + query
    else:
        return url + "?" + query


def _encode_cookie_header(cookies: Dict[String, String]) raises -> String:
    """Encode a Dict[String, String] as a Cookie header value (name=value; name2=value2)."""
    var result = List[UInt8](capacity=64)
    var first = True
    for key in cookies.keys():
        if not first:
            result.append(UInt8(59))  # ';'
            result.append(UInt8(32))  # ' '
        first = False
        _append_str(result, key)
        result.append(UInt8(61))  # '='
        try:
            _append_str(result, cookies[key])
        except:
            pass
    return String(unsafe_from_utf8=result^)


def _resolve_url(base_url: String, location: String) raises -> String:
    """Resolve a redirect Location against the base URL.

    Handles:
    - Absolute URLs (start with http:// or https://) — returned as-is
    - Root-relative paths (start with /) — prepend scheme+host from base_url
    - Relative paths — prepend scheme+host+directory from base_url
    """
    var loc_bytes = location.as_bytes()
    if len(loc_bytes) == 0:
        return base_url

    # Absolute URL check: starts with "http://" or "https://"
    var is_abs = False
    if len(location) >= 7:
        var h = loc_bytes
        if (
            h[0] == UInt8(ord("h"))
            and h[1] == UInt8(ord("t"))
            and h[2] == UInt8(ord("t"))
            and h[3] == UInt8(ord("p"))
        ):
            if h[4] == UInt8(ord(":")) and h[5] == UInt8(ord("/")) and h[6] == UInt8(ord("/")):
                is_abs = True
            elif (
                len(location) >= 8
                and h[4] == UInt8(ord("s"))
                and h[5] == UInt8(ord(":"))
                and h[6] == UInt8(ord("/"))
                and h[7] == UInt8(ord("/"))
            ):
                is_abs = True
    if is_abs:
        return location

    # Extract origin (scheme://host[:port]) from base_url
    # Find "://" then find next "/" after that
    var base_bytes = base_url.as_bytes()
    var origin_end = -1
    var i = 0
    while i < len(base_bytes) - 2:
        if (
            base_bytes[i] == UInt8(ord(":"))
            and base_bytes[i + 1] == UInt8(ord("/"))
            and base_bytes[i + 2] == UInt8(ord("/"))
        ):
            # Skip "://" then find next "/"
            var j = i + 3
            while j < len(base_bytes):
                if base_bytes[j] == UInt8(ord("/")):
                    origin_end = j
                    break
                j += 1
            if origin_end < 0:
                origin_end = len(base_bytes)
            break
        i += 1

    if origin_end < 0:
        return location

    # Build origin string: base_url[0..origin_end)
    var origin_buf = List[UInt8](capacity=origin_end)
    for k in range(origin_end):
        origin_buf.append(base_bytes[k])
    var origin = String(unsafe_from_utf8=origin_buf^)

    # Root-relative path (starts with /)
    if loc_bytes[0] == UInt8(ord("/")):
        return origin + location

    # Relative path — strip last component from base_url path
    var base_path_end = len(base_url)
    var j = len(base_bytes) - 1
    while j >= origin_end:
        if base_bytes[j] == UInt8(ord("/")):
            base_path_end = j + 1
            break
        j -= 1
    var prefix_buf = List[UInt8](capacity=base_path_end)
    for k in range(base_path_end):
        prefix_buf.append(base_bytes[k])
    return String(unsafe_from_utf8=prefix_buf^) + location


# ============================================================================
# Response Parsing
# ============================================================================


def _to_lower(s: String) -> String:
    """Convert string to lowercase (ASCII only)."""
    var s_bytes = s.as_bytes()
    var result = List[UInt8](capacity=len(s))
    for i in range(len(s)):
        var c = s_bytes[i]
        if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
            result.append(c + UInt8(32))
        else:
            result.append(c)
    return String(unsafe_from_utf8=result^)


def _eq_ignore_case(a: String, b: String) -> Bool:
    """Case-insensitive string comparison. Zero allocations."""
    if len(a) != len(b):
        return False
    var a_bytes = a.as_bytes()
    var b_bytes = b.as_bytes()
    for i in range(len(a)):
        var ca = a_bytes[i]
        var cb = b_bytes[i]
        if ca >= UInt8(ord("A")) and ca <= UInt8(ord("Z")):
            ca = ca + 32
        if cb >= UInt8(ord("A")) and cb <= UInt8(ord("Z")):
            cb = cb + 32
        if ca != cb:
            return False
    return True


def _append_str(mut buf: List[UInt8], s: String):
    """Append all bytes of a string to a byte buffer."""
    var s_bytes = s.as_bytes()
    for i in range(len(s)):
        buf.append(s_bytes[i])


def _ptr_to_string(
    data_ptr: UnsafePointer[UInt8, _], start: Int, end: Int
) -> String:
    """Materialize a String from a pointer byte range [start, end).

    This replaces _substring() — takes a pointer instead of String,
    avoiding intermediate String creation during parsing.
    """
    if start < 0 or start >= end:
        return String("")
    var result = List[UInt8](capacity=end - start)
    for i in range(start, end):
        result.append((data_ptr + i)[])
    return String(unsafe_from_utf8=result^)


def _find_crlf_crlf(data_ptr: UnsafePointer[UInt8, _], data_len: Int) -> Int:
    """Find \\r\\n\\r\\n (header/body separator) in pointer data.

    Returns the index of the first \\r in the separator, or -1 if not found.
    """
    if data_len < 4:
        return -1
    for i in range(data_len - 3):
        if (
            (data_ptr + i)[] == 13
            and (data_ptr + i + 1)[] == 10
            and (data_ptr + i + 2)[] == 13
            and (data_ptr + i + 3)[] == 10
        ):
            return i
    return -1


def _find_crlf(data_ptr: UnsafePointer[UInt8, _], data_len: Int, start: Int) -> Int:
    """Find \\r\\n starting from start in pointer data.

    Returns the index of \\r, or -1 if not found.
    """
    if data_len < 2:
        return -1
    for i in range(start, data_len - 1):
        if (data_ptr + i)[] == 13 and (data_ptr + i + 1)[] == 10:
            return i
    return -1


def _find_char(
    data_ptr: UnsafePointer[UInt8, _],
    data_len: Int,
    c: UInt8,
    start: Int = 0,
) -> Int:
    """Find first occurrence of byte c in pointer data starting at start."""
    for i in range(start, data_len):
        if (data_ptr + i)[] == c:
            return i
    return -1


def _hex_to_int(
    data_ptr: UnsafePointer[UInt8, _], start: Int, end: Int
) raises -> Int:
    """Parse a hex string from pointer range [start, end) to integer.

    Guards against integer overflow with a 256 MB cap and max 16 hex digits.
    """
    var MAX_CHUNK = 268435456  # 256 MB
    if end - start > 16:
        raise Error("chunk size hex string too long")
    var result = 0
    for i in range(start, end):
        if result > MAX_CHUNK:
            raise Error("chunk size too large (exceeds 256 MB)")
        var c = (data_ptr + i)[]
        result = result * 16
        if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
            result += Int(c - UInt8(ord("0")))
        elif c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
            result += Int(c - UInt8(ord("a"))) + 10
        elif c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
            result += Int(c - UInt8(ord("A"))) + 10
        else:
            raise Error(
                "invalid hex character in chunk size: "
                + _ptr_to_string(data_ptr, start, end)
            )
    return result


def _decode_chunked(body: String) raises -> String:
    """Decode a chunked transfer-encoded body.

    Format: <hex-size>\\r\\n<data>\\r\\n ... 0\\r\\n\\r\\n

    Uses UnsafePointer for zero-copy parsing — only materializes the
    final decoded body string.
    """
    var result = List[UInt8](capacity=len(body))
    var body_copy = body
    var ptr = body_copy.as_c_string_slice().unsafe_ptr().bitcast[UInt8]()
    var body_len = len(body)
    var pos = 0
    while pos < body_len:
        # Find end of chunk size line
        var crlf = _find_crlf(ptr, body_len, pos)
        if crlf < 0:
            break
        # Check for chunk extensions (semicolon) within [pos..crlf)
        var size_end = crlf
        var semi = _find_char(ptr, crlf, UInt8(ord(";")), pos)
        if semi >= 0:
            size_end = semi
        # Parse hex chunk size directly from pointer
        var chunk_size = _hex_to_int(ptr, pos, size_end)
        if chunk_size == 0:
            break  # Final chunk
        # Copy chunk data directly from pointer to result
        var data_start = crlf + 2  # skip \r\n after size
        if data_start + chunk_size > body_len:
            raise Error(
                "chunked body truncated: expected "
                + String(chunk_size)
                + " bytes, only "
                + String(body_len - data_start)
                + " available"
            )
        for i in range(chunk_size):
            result.append((ptr + data_start + i)[])
        pos = data_start + chunk_size + 2  # skip data + trailing \r\n
    return String(unsafe_from_utf8=result^)


def _parse_response(raw: String, url: String) raises -> HttpResponse:
    """Parse a raw HTTP response string into an HttpResponse.

    Uses UnsafePointer for zero-copy parsing — converts the raw response
    to a pointer once and uses pointer arithmetic throughout. Strings are
    only materialized when storing into response fields.

    Expected format:
        HTTP/1.1 200 OK\\r\\n
        Header: Value\\r\\n
        ...\\r\\n
        \\r\\n
        body...
    """
    var response = HttpResponse()
    response.url = url

    # Convert to pointer once — all parsing uses pointer arithmetic
    var raw_copy = raw
    var ptr = raw_copy.as_c_string_slice().unsafe_ptr().bitcast[UInt8]()
    var raw_len = len(raw)

    # Find header/body separator (\r\n\r\n)
    var separator = _find_crlf_crlf(ptr, raw_len)
    if separator < 0:
        raise Error("malformed HTTP response: no header/body separator found")

    # Extract body — single String materialization
    var body_start = separator + 4  # skip \r\n\r\n
    response.body = _ptr_to_string(ptr, body_start, raw_len)

    # Parse status line: find first \r\n within headers [0..separator)
    var first_crlf = _find_crlf(ptr, separator, 0)
    var status_end = first_crlf if first_crlf >= 0 else separator

    # Validate HTTP version prefix
    if status_end < 5 or (ptr + 0)[] != UInt8(ord("H")) or (ptr + 1)[] != UInt8(ord(
        "T"
    )) or (ptr + 2)[] != UInt8(ord("T")) or (ptr + 3)[] != UInt8(ord("P")) or (
        ptr + 4
    )[] != UInt8(ord("/")):
        raise Error(
            "response is not HTTP: " + _ptr_to_string(ptr, 0, status_end)
        )

    # Parse "HTTP/1.1 200 OK" — find spaces within [0..status_end)
    var sp1 = _find_char(ptr, status_end, UInt8(ord(" ")), 0)
    if sp1 < 0:
        raise Error(
            "malformed status line: " + _ptr_to_string(ptr, 0, status_end)
        )

    # Find second space (after status code)
    var sp2 = _find_char(ptr, status_end, UInt8(ord(" ")), sp1 + 1)
    if sp2 < 0:
        # Some responses may not have a status text
        sp2 = status_end

    # Parse status code directly from pointer bytes
    response.status_code = _parse_status_code(ptr, sp1 + 1, sp2)
    if sp2 < status_end:
        response.status_text = _ptr_to_string(ptr, sp2 + 1, status_end)
    else:
        response.status_text = String("")

    response.ok = response.status_code >= 200 and response.status_code < 300

    # Parse headers — only materialize key/value Strings at add()
    if first_crlf >= 0:
        var pos = first_crlf + 2  # skip past first \r\n
        while pos < separator:
            var line_end = _find_crlf(ptr, separator, pos)
            if line_end < 0:
                line_end = separator

            # Empty line = end of headers
            if line_end == pos:
                break

            # Find colon within line [pos..line_end)
            var colon = _find_char(ptr, line_end, UInt8(ord(":")), pos)
            if colon >= 0:
                var key = _ptr_to_string(ptr, pos, colon)
                var value_start = colon + 1
                # Skip leading spaces
                while value_start < line_end and (ptr + value_start)[] == UInt8(ord(
                    " "
                )):
                    value_start += 1
                var val = _ptr_to_string(ptr, value_start, line_end)
                response.headers.add(key, val)

            if line_end >= separator:
                break
            pos = line_end + 2  # skip \r\n

    # Decode chunked body if needed
    var te = response.headers.get("Transfer-Encoding")
    if _eq_ignore_case(te, String("chunked")):
        response.body = _decode_chunked(response.body)

    return response^


def _parse_status_code(
    data_ptr: UnsafePointer[UInt8, _], start: Int, end: Int
) raises -> Int:
    """Parse HTTP status code from pointer range [start, end).

    Enforces max 3 digits (valid HTTP status codes are 100-599).
    """
    if end - start > 3:
        raise Error("status code too long (max 3 digits)")
    var result: Int = 0
    for i in range(start, end):
        var c = (data_ptr + i)[]
        if c < UInt8(ord("0")) or c > UInt8(ord("9")):
            raise Error(
                "invalid status code: " + _ptr_to_string(data_ptr, start, end)
            )
        result = result * 10 + Int(c - UInt8(ord("0")))
    return result
