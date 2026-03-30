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
# Uses Connection: keep-alive and an LRU-4 connection pool per scheme
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
from brotli_decompress import brotli_decompress
from zstd_decompress import zstd_decompress
from psl import is_public_suffix
from std.ffi import external_call
from std.memory.unsafe_pointer import alloc


# ============================================================================
# Time Helper
# ============================================================================


fn _getenv(name: String) -> String:
    """Read an environment variable by name. Returns empty string if not set."""
    var nb = name.as_bytes()
    var nlen = len(nb)
    var name_buf = alloc[Int8](nlen + 1)
    for i in range(nlen):
        (name_buf + i)[] = Int8(nb[i])
    (name_buf + nlen)[] = Int8(0)
    var val_ptr = external_call["getenv", Int](Int(name_buf))
    name_buf.free()
    if val_ptr == 0:
        return String("")
    var length = external_call["strlen", Int](val_ptr)
    if length == 0:
        return String("")
    var out_buf = alloc[UInt8](length)
    _ = external_call["memcpy", Int](Int(out_buf), val_ptr, length)
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append((out_buf + i)[])
    out_buf.free()
    return String(unsafe_from_utf8=out^)


fn _no_proxy_matches(host: String, no_proxy: String) -> Bool:
    """Return True if host matches the NO_PROXY env var value.

    Formats supported:
      *              — bypass proxy for all hosts
      hostname       — exact match
      .suffix.com    — suffix match (matches api.suffix.com)
      192.168.1.1    — exact IP match
    Entries are comma-separated; leading/trailing whitespace is ignored.
    """
    if len(no_proxy) == 0:
        return False
    var np_bytes = no_proxy.as_bytes()
    var start = 0
    var n = len(np_bytes)
    # Iterate comma-separated entries
    for i in range(n + 1):
        if i == n or np_bytes[i] == UInt8(44):  # ',' or end
            if i > start:
                # Trim whitespace
                var lo = start
                var hi = i
                while lo < hi and np_bytes[lo] == UInt8(32):
                    lo += 1
                while hi > lo and np_bytes[hi - 1] == UInt8(32):
                    hi -= 1
                if lo < hi:
                    var entry_bytes = List[UInt8](capacity=hi - lo)
                    for j in range(lo, hi):
                        entry_bytes.append(np_bytes[j])
                    var entry = String(unsafe_from_utf8=entry_bytes^)
                    if entry == "*":
                        return True
                    if entry == host:
                        return True
                    # Suffix match: ".suffix" matches "api.suffix"
                    if entry.startswith(".") and host.endswith(entry):
                        return True
            start = i + 1
    return False


fn _unix_time_secs() -> Int64:
    """Return current Unix time in seconds via clock_gettime(CLOCK_REALTIME)."""
    # struct timespec { int64_t tv_sec; int64_t tv_nsec; }  (16 bytes on 64-bit)
    var ts = alloc[UInt8](16)
    for i in range(16):
        (ts + i)[] = UInt8(0)
    _ = external_call["clock_gettime", Int32](Int32(0), Int(ts))
    var t = ts.bitcast[Int64]()[]
    ts.free()
    return t


# ============================================================================
# Error Prefix Constants and Helpers
# ============================================================================
#
# All raise sites use these helpers so callers can distinguish error categories
# via String(e).startswith("HTTPError:") etc.
#
# Categories:
#   HTTPError        — non-2xx status (raise_for_status)
#   ConnectionError  — socket / DNS / TLS failure
#   TooManyRedirects — redirect limit exceeded
#   ValidationError  — bad input (header keys/values, method, port, host)
#   ParseError       — malformed HTTP response
#   ChunkedBodyError — chunked encoding protocol violation


alias ERR_HTTP = "HTTPError"
alias ERR_CONNECTION = "ConnectionError"
alias ERR_REDIRECT = "TooManyRedirects"
alias ERR_VALIDATION = "ValidationError"
alias ERR_PARSE = "ParseError"
alias ERR_CHUNKED = "ChunkedBodyError"

# Maximum bytes allowed in a single response (headers + body).
# Prevents memory exhaustion from malicious or runaway servers.
alias MAX_RESPONSE_BYTES = 100 * 1024 * 1024  # 100 MB


def _err_http(status: Int, text: String) -> Error:
    return Error(ERR_HTTP + ": " + String(status) + " " + text)


def _err_connection(msg: String) -> Error:
    return Error(ERR_CONNECTION + ": " + msg)


def _err_redirect(max: Int) -> Error:
    return Error(ERR_REDIRECT + ": max " + String(max))


def _err_validation(msg: String) -> Error:
    return Error(ERR_VALIDATION + ": " + msg)


def _err_parse(msg: String) -> Error:
    return Error(ERR_PARSE + ": " + msg)


def _err_chunked(msg: String) -> Error:
    return Error(ERR_CHUNKED + ": " + msg)


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
            raise _err_http(self.status_code, self.status_text)

    def sanitized_url(self) -> String:
        """Return the response URL with the query string removed.

        Use this instead of `.url` when logging errors, to avoid accidentally
        leaking secrets embedded in query parameters (e.g. API keys).

        Example:
            http://api.example.com/data?api_key=SECRET  →  http://api.example.com/data
        """
        var u = self.url
        var u_bytes = u.as_bytes()
        for i in range(len(u_bytes)):
            if u_bytes[i] == UInt8(63):  # '?'
                var trimmed = List[UInt8](capacity=i)
                for j in range(i):
                    trimmed.append(u_bytes[j])
                return String(unsafe_from_utf8=trimmed^)
        return u

    def error_without_url(self) raises:
        """Like raise_for_status() but omits the URL from the error message.

        Use when the request URL contains secrets in query parameters.

        Raises:
            Error with message "HTTP <code> <reason>" if status_code >= 400.
        """
        if self.status_code >= 400:
            raise _err_http(self.status_code, self.status_text)

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

    Caches the CA bundle after the first HTTPS request and maintains an
    LRU-4 connection pool per scheme to reuse keep-alive connections.

    Usage:
        var client = HttpClient()
        var response = client.get("http://httpbin.org/get")
        print(response.status_code)
        print(response.body)
    """

    var user_agent: String
    var allow_private_ips: Bool
    var max_redirects: Int              # maximum redirects to follow (default 10)
    var follow_redirects: Bool          # if False, return first redirect response as-is
    var redirect_same_host_only: Bool   # if True, stop following cross-host redirects
    var pool_idle_timeout_secs: Int     # evict pool connections idle longer than this (default 300)
    var proxy_url: String               # HTTP proxy URL, e.g. "http://host:port" (empty = no proxy)
    var _timeout_secs: Int              # socket send/recv timeout (seconds)

    # CA bundle cache — loaded once on first HTTPS request
    var _ca_bundle: List[X509Cert]
    var _ca_loaded: Bool

    # HTTP connection pool — LRU-4
    # Metadata in List[String]/List[Int64] (CollectionElement); sockets as flat fields
    # _http_times[i] == 0 means slot unused; >0 == last-used Unix timestamp
    var _http_keys: List[String]
    var _http_times: List[Int64]
    var _http_sock0: TcpSocket
    var _http_sock1: TcpSocket
    var _http_sock2: TcpSocket
    var _http_sock3: TcpSocket

    # HTTPS connection pool — LRU-4 (same pattern)
    var _tls_keys: List[String]
    var _tls_times: List[Int64]
    var _tls_sock0: TlsSocket
    var _tls_sock1: TlsSocket
    var _tls_sock2: TlsSocket
    var _tls_sock3: TlsSocket

    # Cookie jar: parallel lists (RFC 6265 attributes per entry)
    # expiry == 0 means session cookie (no expiry); >0 means Unix timestamp
    # path defaults to "/" if not set; secure=True → HTTPS only; host_only=True → exact host match
    var _jar_domains: List[String]
    var _jar_names: List[String]
    var _jar_values: List[String]
    var _jar_expiries: List[Int64]
    var _jar_paths: List[String]
    var _jar_secure: List[Bool]
    var _jar_host_only: List[Bool]
    var _jar_samesite: List[String]
    var _jar_httponly: List[Bool]

    def __init__(
        out self,
        allow_private_ips: Bool = False,
        timeout_secs: Int = 30,
    ) raises:
        if timeout_secs <= 0:
            raise _err_validation("timeout_secs must be > 0, got " + String(timeout_secs))
        self.user_agent = String("MojoHTTP/0.1")
        self.allow_private_ips = allow_private_ips
        self.max_redirects = 10
        self.follow_redirects = True
        self.redirect_same_host_only = False
        self.pool_idle_timeout_secs = 300
        self.proxy_url = String("")
        self._timeout_secs = timeout_secs
        self._ca_bundle = List[X509Cert]()
        self._ca_loaded = False
        # HTTP pool — 4 slots, all unused
        self._http_keys = List[String]()
        self._http_times = List[Int64]()
        for _ in range(4):
            self._http_keys.append(String(""))
            self._http_times.append(Int64(0))
        self._http_sock0 = TcpSocket()
        self._http_sock1 = TcpSocket()
        self._http_sock2 = TcpSocket()
        self._http_sock3 = TcpSocket()
        # TLS pool — 4 slots, all unused
        self._tls_keys = List[String]()
        self._tls_times = List[Int64]()
        for _ in range(4):
            self._tls_keys.append(String(""))
            self._tls_times.append(Int64(0))
        self._tls_sock0 = TlsSocket(0)
        self._tls_sock1 = TlsSocket(0)
        self._tls_sock2 = TlsSocket(0)
        self._tls_sock3 = TlsSocket(0)
        self._jar_domains = List[String]()
        self._jar_names = List[String]()
        self._jar_values = List[String]()
        self._jar_expiries = List[Int64]()
        self._jar_paths = List[String]()
        self._jar_secure = List[Bool]()
        self._jar_host_only = List[Bool]()
        self._jar_samesite = List[String]()
        self._jar_httponly = List[Bool]()

    def __moveinit__(out self, deinit take: Self):
        self.user_agent = take.user_agent^
        self.allow_private_ips = take.allow_private_ips
        self.max_redirects = take.max_redirects
        self.follow_redirects = take.follow_redirects
        self.redirect_same_host_only = take.redirect_same_host_only
        self.pool_idle_timeout_secs = take.pool_idle_timeout_secs
        self.proxy_url = take.proxy_url^
        self._timeout_secs = take._timeout_secs
        self._ca_bundle = take._ca_bundle^
        self._ca_loaded = take._ca_loaded
        self._http_keys = take._http_keys^
        self._http_times = take._http_times^
        self._http_sock0 = take._http_sock0^
        self._http_sock1 = take._http_sock1^
        self._http_sock2 = take._http_sock2^
        self._http_sock3 = take._http_sock3^
        self._tls_keys = take._tls_keys^
        self._tls_times = take._tls_times^
        self._tls_sock0 = take._tls_sock0^
        self._tls_sock1 = take._tls_sock1^
        self._tls_sock2 = take._tls_sock2^
        self._tls_sock3 = take._tls_sock3^
        self._jar_domains = take._jar_domains^
        self._jar_names = take._jar_names^
        self._jar_values = take._jar_values^
        self._jar_expiries = take._jar_expiries^
        self._jar_paths = take._jar_paths^
        self._jar_secure = take._jar_secure^
        self._jar_host_only = take._jar_host_only^
        self._jar_samesite = take._jar_samesite^
        self._jar_httponly = take._jar_httponly^

    # === GET ===

    def get(mut self, url: String) raises -> HttpResponse:
        """Perform an HTTP GET request, following redirects."""
        var headers = HttpHeaders()
        return self._follow_redirects("GET", url, String(""), headers, True, self.max_redirects)

    def get(mut self, url: String, headers: HttpHeaders) raises -> HttpResponse:
        """Perform an HTTP GET request with custom headers."""
        return self._follow_redirects("GET", url, String(""), headers, True, self.max_redirects)

    def get(mut self, url: String, params: Dict[String, String]) raises -> HttpResponse:
        """Perform an HTTP GET request with URL query parameters."""
        var headers = HttpHeaders()
        return self._follow_redirects("GET", _append_params_to_url(url, params), String(""), headers, True, self.max_redirects)

    def get(
        mut self, url: String, headers: HttpHeaders, params: Dict[String, String]
    ) raises -> HttpResponse:
        """Perform an HTTP GET request with custom headers and URL query parameters."""
        return self._follow_redirects("GET", _append_params_to_url(url, params), String(""), headers, True, self.max_redirects)

    def get(mut self, url: String, auth: BasicAuth) raises -> HttpResponse:
        """Perform an HTTP GET request with Basic Authentication."""
        var headers = HttpHeaders()
        headers.add("Authorization", auth.header())
        return self._follow_redirects("GET", url, String(""), headers, True, self.max_redirects)

    def get(mut self, url: String, auth: BearerAuth) raises -> HttpResponse:
        """Perform an HTTP GET request with Bearer Token Authentication."""
        var headers = HttpHeaders()
        headers.add("Authorization", auth.header())
        return self._follow_redirects("GET", url, String(""), headers, True, self.max_redirects)

    def get(
        mut self, url: String, allow_redirects: Bool
    ) raises -> HttpResponse:
        """Perform an HTTP GET request, optionally not following redirects."""
        var headers = HttpHeaders()
        return self._follow_redirects("GET", url, String(""), headers, allow_redirects, self.max_redirects)

    def cookie_count(self) -> Int:
        """Return the number of cookies stored in the cookie jar."""
        return len(self._jar_names)

    # === STREAM ===

    def get_stream(mut self, url_str: String) raises -> StreamResponse:
        """Perform a GET and return a StreamResponse for incremental body reading.

        Always opens a fresh connection (does not reuse the keep-alive pool).
        The returned StreamResponse owns the socket. Consume with read_chunk()
        or read_all(), then call close() when done.
        """
        _validate_method("GET")
        var url = parse_url(url_str)
        _validate_path(url.request_path())

        # Build request — Connection: close so server signals EOF
        var req_buf = List[UInt8](capacity=512)
        _append_str(req_buf, "GET ")
        _append_str(req_buf, url.request_path())
        _append_str(req_buf, " HTTP/1.1\r\nHost: ")
        _append_str(req_buf, url.host_header())
        _append_str(req_buf, "\r\nUser-Agent: ")
        _append_str(req_buf, self.user_agent)
        _append_str(req_buf, "\r\nAccept: */*\r\nConnection: close\r\n\r\n")

        var is_tls = (url.scheme == "https")
        var http_sock = TcpSocket()
        var tls_sock = TlsSocket(0)
        var raw_buf = List[UInt8]()

        var header_end = -1

        if is_tls:
            if not self._ca_loaded:
                self._ca_bundle = load_system_ca_bundle()
                self._ca_loaded = True
            http_sock.connect(
                url.host, url.port,
                reject_private_ips=not self.allow_private_ips,
                timeout_secs=self._timeout_secs,
            )
            tls_sock = TlsSocket(http_sock.fd)
            tls_sock.connect(url.host, self._ca_bundle)
            _ = tls_sock.send(req_buf)
            while header_end < 0:
                var chunk = tls_sock.recv(4096)
                if len(chunk) == 0:
                    raise _err_connection("stream: connection closed before headers")
                _list_append(raw_buf, chunk)
                header_end = _buf_find_crlf_crlf(raw_buf)
        else:
            http_sock.connect(
                url.host, url.port,
                reject_private_ips=not self.allow_private_ips,
                timeout_secs=self._timeout_secs,
            )
            var request = String(unsafe_from_utf8=req_buf^)
            _ = http_sock.send(request)
            while header_end < 0:
                var chunk = http_sock.recv_bytes(4096)
                if len(chunk) == 0:
                    raise _err_connection("stream: connection closed before headers")
                _list_append(raw_buf, chunk)
                header_end = _buf_find_crlf_crlf(raw_buf)

        var hdr_str = _buf_to_string(raw_buf, header_end + 4)
        var parsed = _parse_response(hdr_str, url_str)
        var cl = _buf_content_length(raw_buf, header_end)
        var leftover = _buf_leftover(raw_buf, header_end + 4)

        var stream = StreamResponse()
        stream.status_code = parsed.status_code
        stream.ok = parsed.ok
        stream.status_text = parsed.status_text
        stream.headers = parsed.headers.copy()
        stream.url = url_str
        stream._leftover = leftover^
        stream._leftover_pos = 0
        stream._content_length = cl
        stream._body_read = 0
        stream._is_tls = is_tls
        stream._done = False
        stream._http_sock = http_sock^
        stream._tls_sock = tls_sock^
        return stream^

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

    def post_multipart(
        mut self, url: String, fields: Dict[String, String]
    ) raises -> HttpResponse:
        """POST multipart/form-data with string fields.

        Each field in `fields` is encoded as a form-data part. The boundary is
        generated from the current Unix timestamp to ensure uniqueness.
        """
        var boundary = "MojoHTTPBoundary" + String(_unix_time_secs())
        var buf = List[UInt8](capacity=512)
        for key in fields.keys():
            var value = fields[key]
            _append_str(buf, "--")
            _append_str(buf, boundary)
            _append_str(buf, "\r\nContent-Disposition: form-data; name=\"")
            _append_str(buf, key)
            _append_str(buf, "\"\r\n\r\n")
            _append_str(buf, value)
            _append_str(buf, "\r\n")
        _append_str(buf, "--")
        _append_str(buf, boundary)
        _append_str(buf, "--\r\n")
        var body = String(unsafe_from_utf8=buf^)
        var headers = HttpHeaders()
        headers.add("Content-Type", "multipart/form-data; boundary=" + boundary)
        return self._do_request("POST", url, body, headers)

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

            # Phase 11B: if follow_redirects=False, return the redirect response as-is
            if not self.follow_redirects:
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
                # Phase 11B: redirect_same_host_only — stop on cross-host redirects
                if self.redirect_same_host_only:
                    resp.history = history^
                    return resp^
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

        raise _err_redirect(max_redirects)

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
            _append_str(req_buf, "Accept-Encoding: gzip, deflate, br, zstd\r\n")
        _append_str(req_buf, "Connection: keep-alive\r\n")

        # Add Content-Length and Content-Type for non-empty bodies
        if len(body) > 0:
            _append_str(req_buf, "Content-Length: ")
            _append_str(req_buf, String(len(body)))
            _append_str(req_buf, "\r\n")
            if not extra_headers.has("Content-Type"):
                _append_str(req_buf, "Content-Type: application/json\r\n")

        # Auto-send cookies from jar for this host
        var jar_cookie = self._jar_cookie_for(url.host, url.request_path(), url.scheme == "https")
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

        var tls_hit = -1
        var http_hit = -1

        if url.scheme == "https":
            # Lazy-load CA bundle (once per HttpClient lifetime)
            if not self._ca_loaded:
                self._ca_bundle = load_system_ca_bundle()
                self._ca_loaded = True

            # Phase 1: try to reuse a cached TLS slot (skip idle-expired slots)
            var now_tls = _unix_time_secs()
            for i in range(4):
                if self._tls_keys[i] == conn_key and self._tls_times[i] > Int64(0):
                    var idle_secs = Int(now_tls - self._tls_times[i])
                    if idle_secs > self.pool_idle_timeout_secs:
                        self._tls_close_slot(i)
                        continue
                    tls_hit = i
                    break
            if tls_hit >= 0:
                try:
                    raw_bytes = self._tls_try_reuse(tls_hit, req_buf, skip_body)
                    self._tls_times[tls_hit] = _unix_time_secs()
                except:
                    self._tls_close_slot(tls_hit)
                    tls_hit = -1

            # Phase 2: new TLS connection if no reuse
            if tls_hit < 0:
                var tcp_sock = self._tcp_connect(url.host, url.port, "https")
                var new_tls = TlsSocket(tcp_sock.fd)
                new_tls.connect(url.host, self._ca_bundle)
                _ = new_tls.send(req_buf)
                raw_bytes = _recv_tls_keepalive(new_tls, skip_body)
                var evict = self._tls_evict_slot()
                if self._tls_times[evict] > Int64(0):
                    self._tls_close_slot(evict)
                # Store new socket into evicted slot
                self._tls_keys[evict] = conn_key
                self._tls_times[evict] = _unix_time_secs()
                if evict == 0:
                    self._tls_sock0 = new_tls^
                elif evict == 1:
                    self._tls_sock1 = new_tls^
                elif evict == 2:
                    self._tls_sock2 = new_tls^
                else:
                    self._tls_sock3 = new_tls^
                tls_hit = evict
        else:
            # Plain HTTP
            # Phase 1: try to reuse a cached HTTP slot (skip idle-expired slots)
            var now_http = _unix_time_secs()
            for i in range(4):
                if self._http_keys[i] == conn_key and self._http_times[i] > Int64(0):
                    var idle_secs = Int(now_http - self._http_times[i])
                    if idle_secs > self.pool_idle_timeout_secs:
                        self._http_close_slot(i)
                        continue
                    http_hit = i
                    break
            if http_hit >= 0:
                try:
                    var request = String(unsafe_from_utf8=req_buf.copy())
                    raw_bytes = self._http_try_reuse(http_hit, request, skip_body)
                    self._http_times[http_hit] = _unix_time_secs()
                except:
                    self._http_close_slot(http_hit)
                    http_hit = -1

            # Phase 2: new HTTP connection if no reuse
            if http_hit < 0:
                var new_sock = self._tcp_connect(url.host, url.port)
                var request = String(unsafe_from_utf8=req_buf^)
                _ = new_sock.send(request)
                raw_bytes = _recv_http_keepalive(new_sock, skip_body)
                var evict = self._http_evict_slot()
                if self._http_times[evict] > Int64(0):
                    self._http_close_slot(evict)
                # Store new socket into evicted slot
                self._http_keys[evict] = conn_key
                self._http_times[evict] = _unix_time_secs()
                if evict == 0:
                    self._http_sock0 = new_sock^
                elif evict == 1:
                    self._http_sock1 = new_sock^
                elif evict == 2:
                    self._http_sock2 = new_sock^
                else:
                    self._http_sock3 = new_sock^
                http_hit = evict

        if len(raw_bytes) == 0:
            raise _err_connection("empty response from server")

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
        elif _eq_ignore_case(ce, "br"):
            var body_bytes = parsed.body.as_bytes()
            var compressed = List[UInt8](capacity=len(body_bytes))
            for i in range(len(body_bytes)):
                compressed.append(body_bytes[i])
            var decompressed = brotli_decompress(compressed^)
            parsed.body = String(unsafe_from_utf8=decompressed^)
        elif _eq_ignore_case(ce, "zstd"):
            var body_bytes = parsed.body.as_bytes()
            var compressed = List[UInt8](capacity=len(body_bytes))
            for i in range(len(body_bytes)):
                compressed.append(body_bytes[i])
            var decompressed = zstd_decompress(compressed^)
            parsed.body = String(unsafe_from_utf8=decompressed^)

        # Store Set-Cookie headers in the cookie jar
        var set_cookie = parsed.headers.get("Set-Cookie")
        if len(set_cookie) > 0:
            self._jar_store(url.host, url.request_path(), url.scheme == "https", set_cookie)

        # If server requested connection close, evict the slot we just used
        var conn_hdr = parsed.headers.get("Connection")
        if _eq_ignore_case(conn_hdr, "close"):
            if url.scheme == "https":
                self._tls_close_slot(tls_hit)
            else:
                self._http_close_slot(http_hit)

        return parsed^

    # -------------------------------------------------------------------------
    # LRU-4 Pool Helpers — HTTP
    # -------------------------------------------------------------------------

    def _http_evict_slot(self) -> Int:
        """Return index of best HTTP pool slot to evict.

        Priority: (1) unused slot, (2) idle-expired slot, (3) LRU slot.
        """
        var now = _unix_time_secs()
        for i in range(4):
            if self._http_times[i] == Int64(0):
                return i
        for i in range(4):
            if Int(now - self._http_times[i]) > self.pool_idle_timeout_secs:
                return i
        var lru = 0
        for i in range(1, 4):
            if self._http_times[i] < self._http_times[lru]:
                lru = i
        return lru

    def _http_close_slot(mut self, i: Int):
        """Close socket in HTTP pool slot i and mark slot unused."""
        try:
            if i == 0:
                self._http_sock0.close()
            elif i == 1:
                self._http_sock1.close()
            elif i == 2:
                self._http_sock2.close()
            else:
                self._http_sock3.close()
        except:
            pass
        self._http_times[i] = Int64(0)
        self._http_keys[i] = String("")

    def _http_try_reuse(
        mut self, i: Int, request: String, skip_body: Bool
    ) raises -> List[UInt8]:
        """Send request and recv response on HTTP pool slot i (raises on failure)."""
        if i == 0:
            _ = self._http_sock0.send(request)
            return _recv_http_keepalive(self._http_sock0, skip_body)
        elif i == 1:
            _ = self._http_sock1.send(request)
            return _recv_http_keepalive(self._http_sock1, skip_body)
        elif i == 2:
            _ = self._http_sock2.send(request)
            return _recv_http_keepalive(self._http_sock2, skip_body)
        else:
            _ = self._http_sock3.send(request)
            return _recv_http_keepalive(self._http_sock3, skip_body)

    # -------------------------------------------------------------------------
    # LRU-4 Pool Helpers — TLS
    # -------------------------------------------------------------------------

    def _tls_evict_slot(self) -> Int:
        """Return index of best TLS pool slot to evict.

        Priority: (1) unused slot, (2) idle-expired slot, (3) LRU slot.
        """
        var now = _unix_time_secs()
        for i in range(4):
            if self._tls_times[i] == Int64(0):
                return i
        for i in range(4):
            if Int(now - self._tls_times[i]) > self.pool_idle_timeout_secs:
                return i
        var lru = 0
        for i in range(1, 4):
            if self._tls_times[i] < self._tls_times[lru]:
                lru = i
        return lru

    def _tls_close_slot(mut self, i: Int):
        """Close socket in TLS pool slot i and mark slot unused."""
        try:
            if i == 0:
                self._tls_sock0.close()
            elif i == 1:
                self._tls_sock1.close()
            elif i == 2:
                self._tls_sock2.close()
            else:
                self._tls_sock3.close()
        except:
            pass
        self._tls_times[i] = Int64(0)
        self._tls_keys[i] = String("")

    def _tls_try_reuse(
        mut self, i: Int, req_buf: List[UInt8], skip_body: Bool
    ) raises -> List[UInt8]:
        """Send request and recv response on TLS pool slot i (raises on failure)."""
        if i == 0:
            _ = self._tls_sock0.send(req_buf)
            return _recv_tls_keepalive(self._tls_sock0, skip_body)
        elif i == 1:
            _ = self._tls_sock1.send(req_buf)
            return _recv_tls_keepalive(self._tls_sock1, skip_body)
        elif i == 2:
            _ = self._tls_sock2.send(req_buf)
            return _recv_tls_keepalive(self._tls_sock2, skip_body)
        else:
            _ = self._tls_sock3.send(req_buf)
            return _recv_tls_keepalive(self._tls_sock3, skip_body)

    # -------------------------------------------------------------------------
    # Proxy CONNECT helper
    # -------------------------------------------------------------------------

    def _tcp_connect(
        self, target_host: String, target_port: Int, scheme: String = "http"
    ) raises -> TcpSocket:
        """Return a TcpSocket connected to target_host:target_port.

        If self.proxy_url is set, or if HTTP_PROXY / HTTPS_PROXY env vars are
        set (Phase 13B), connects through an HTTP CONNECT proxy tunnel.
        NO_PROXY env var is respected (comma-separated hostnames / .suffixes).

        If no proxy is configured, connects directly (normal behaviour).
        """
        # Determine effective proxy URL: field takes priority over env vars
        var effective_proxy = self.proxy_url
        if len(effective_proxy) == 0:
            # Phase 13B: auto-detect from environment
            if scheme == "https":
                effective_proxy = _getenv("HTTPS_PROXY")
                if len(effective_proxy) == 0:
                    effective_proxy = _getenv("https_proxy")
            if len(effective_proxy) == 0:
                effective_proxy = _getenv("HTTP_PROXY")
                if len(effective_proxy) == 0:
                    effective_proxy = _getenv("http_proxy")

        # Check NO_PROXY — bypass proxy for matching hosts
        if len(effective_proxy) > 0:
            var no_proxy = _getenv("NO_PROXY")
            if len(no_proxy) == 0:
                no_proxy = _getenv("no_proxy")
            if _no_proxy_matches(target_host, no_proxy):
                effective_proxy = String("")

        if len(effective_proxy) == 0:
            # Direct connection — existing behaviour
            var sock = TcpSocket()
            sock.connect(
                target_host,
                target_port,
                reject_private_ips=not self.allow_private_ips,
                timeout_secs=self._timeout_secs,
            )
            return sock^

        # Parse effective proxy URL → proxy host + port
        var proxy_parsed = parse_url(effective_proxy)
        var proxy_host = proxy_parsed.host
        var proxy_port = proxy_parsed.port

        # Connect TCP to the proxy (proxy itself is trusted — allow private IPs)
        var sock = TcpSocket()
        sock.connect(
            proxy_host,
            proxy_port,
            reject_private_ips=False,
            timeout_secs=self._timeout_secs,
        )

        # Send CONNECT request
        var connect_req = (
            "CONNECT "
            + target_host
            + ":"
            + String(target_port)
            + " HTTP/1.1\r\nHost: "
            + target_host
            + ":"
            + String(target_port)
            + "\r\n\r\n"
        )
        _ = sock.send(connect_req)

        # Read proxy response until "\r\n\r\n"
        var resp_buf = alloc[UInt8](4096)
        var resp_len = 0
        var found_end = False
        while not found_end and resp_len < 4096:
            var n = external_call["recv", Int](
                sock.fd, Int(resp_buf + resp_len), 4096 - resp_len, Int32(0)
            )
            if n <= 0:
                resp_buf.free()
                raise _err_connection("proxy CONNECT: connection closed before response")
            resp_len += n
            # Check for end of headers: \r\n\r\n
            if resp_len >= 4:
                for i in range(resp_len - 3):
                    if (
                        (resp_buf + i)[] == UInt8(13)       # \r
                        and (resp_buf + i + 1)[] == UInt8(10)  # \n
                        and (resp_buf + i + 2)[] == UInt8(13)  # \r
                        and (resp_buf + i + 3)[] == UInt8(10)  # \n
                    ):
                        found_end = True
                        break

        # Convert response to String and check for 200
        var resp_bytes = List[UInt8](capacity=resp_len)
        for i in range(resp_len):
            resp_bytes.append((resp_buf + i)[])
        resp_buf.free()
        var resp_str = String(unsafe_from_utf8=resp_bytes^)

        # Status line: "HTTP/1.x 200 ..."
        var status_ok = False
        if len(resp_str) >= 12:
            var resp_b = resp_str.as_bytes()
            # Check for "200" at position 9 (after "HTTP/1.x ")
            if (
                len(resp_b) >= 12
                and resp_b[9] == UInt8(50)   # '2'
                and resp_b[10] == UInt8(48)  # '0'
                and resp_b[11] == UInt8(48)  # '0'
            ):
                status_ok = True
        if not status_ok:
            var preview = resp_str
            raise _err_connection("proxy CONNECT failed: " + preview)

        return sock^

    # -------------------------------------------------------------------------

    def _jar_store(
        mut self, host: String, req_path: String, is_https: Bool, set_cookie: String
    ):
        """Parse Set-Cookie header value and store name=value in the jar (RFC 6265).

        Handles attributes:
          Max-Age=0  — delete existing cookie with same name (do not store)
          Max-Age=N  — store with expiry = now + N seconds
          Path=/foo  — store path scope (default "/")
          Secure     — only send over HTTPS
          Domain=foo — allow subdomain matching; host_only=False
          absent     — store as session cookie (expiry = 0, never expires)
        """
        var bytes = set_cookie.as_bytes()
        var n = len(bytes)
        # Find '=' (name/value separator) and first ';' (end of name=value pair)
        var eq = -1
        var semi = n
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

        # Scan attributes
        var expiry = Int64(0)   # 0 = session cookie
        var max_age_found = False
        var max_age_val = Int64(0)
        var cookie_path = String("/")
        var secure = False
        var httponly = False
        var cookie_domain = host
        var host_only = True
        var samesite = String("Lax")  # RFC 6265bis default

        var pos = semi + 1
        while pos < n:
            # skip whitespace
            while pos < n and bytes[pos] == UInt8(32):
                pos += 1
            # find end of this attribute
            var attr_end = n
            for j in range(pos, n):
                if bytes[j] == UInt8(59):  # ';'
                    attr_end = j
                    break
            var attr_len = attr_end - pos

            # Max-Age (7 chars)
            if attr_len >= 7:
                if (
                    _lc(bytes[pos]) == 109       # m
                    and _lc(bytes[pos+1]) == 97  # a
                    and _lc(bytes[pos+2]) == 120 # x
                    and bytes[pos+3] == 45       # -
                    and _lc(bytes[pos+4]) == 97  # a
                    and _lc(bytes[pos+5]) == 103 # g
                    and _lc(bytes[pos+6]) == 101 # e
                ):
                    var eq2 = -1
                    for j in range(pos, attr_end):
                        if bytes[j] == UInt8(61):
                            eq2 = j
                            break
                    if eq2 >= 0:
                        var npos = eq2 + 1
                        while npos < attr_end and bytes[npos] == UInt8(32):
                            npos += 1
                        var negative = False
                        if npos < attr_end and bytes[npos] == UInt8(45):  # '-'
                            negative = True
                            npos += 1
                        var age = Int64(0)
                        while npos < attr_end:
                            var c = bytes[npos]
                            if c < 48 or c > 57:
                                break
                            age = age * 10 + Int64(c - 48)
                            npos += 1
                        if negative:
                            age = -age
                        max_age_found = True
                        max_age_val = age

            # Path= (5 chars: "path=")
            if attr_len >= 5:
                if (
                    _lc(bytes[pos]) == 112       # p
                    and _lc(bytes[pos+1]) == 97  # a
                    and _lc(bytes[pos+2]) == 116 # t
                    and _lc(bytes[pos+3]) == 104 # h
                    and bytes[pos+4] == 61       # =
                ):
                    var path_start = pos + 5
                    var path_buf = List[UInt8](capacity=attr_end - path_start)
                    for j in range(path_start, attr_end):
                        path_buf.append(bytes[j])
                    if len(path_buf) > 0:
                        cookie_path = String(unsafe_from_utf8=path_buf^)
                    else:
                        cookie_path = String("/")

            # Domain= (7 chars: "domain=")
            if attr_len >= 7:
                if (
                    _lc(bytes[pos]) == 100       # d
                    and _lc(bytes[pos+1]) == 111 # o
                    and _lc(bytes[pos+2]) == 109 # m
                    and _lc(bytes[pos+3]) == 97  # a
                    and _lc(bytes[pos+4]) == 105 # i
                    and _lc(bytes[pos+5]) == 110 # n
                    and bytes[pos+6] == 61       # =
                ):
                    var dom_start = pos + 7
                    # skip leading dot
                    if dom_start < attr_end and bytes[dom_start] == UInt8(46):
                        dom_start += 1
                    var dom_buf = List[UInt8](capacity=attr_end - dom_start)
                    for j in range(dom_start, attr_end):
                        dom_buf.append(bytes[j])
                    if len(dom_buf) > 0:
                        var d = String(unsafe_from_utf8=dom_buf^)
                        # Reject single-label domains (e.g. ".com") to prevent
                        # supercookies that match any host under a TLD (S7).
                        # A valid cookie domain must contain at least one embedded dot.
                        var has_inner_dot = False
                        var d_bytes = d.as_bytes()
                        for j in range(len(d_bytes)):
                            if d_bytes[j] == UInt8(46):  # '.'
                                has_inner_dot = True
                                break
                        if not has_inner_dot:
                            return  # reject entire cookie — invalid Domain attr
                        # Reject public suffixes (e.g. .co.uk, .github.io)
                        # to prevent supercookies that match any registrant
                        # under the suffix (Phase 11A — PSL validation).
                        if is_public_suffix(d):
                            return  # reject entire cookie — public suffix Domain
                        cookie_domain = d
                        host_only = False

            # Secure (6 chars, boolean flag — no '=')
            if attr_len == 6:
                if (
                    _lc(bytes[pos]) == 115       # s
                    and _lc(bytes[pos+1]) == 101 # e
                    and _lc(bytes[pos+2]) == 99  # c
                    and _lc(bytes[pos+3]) == 117 # u
                    and _lc(bytes[pos+4]) == 114 # r
                    and _lc(bytes[pos+5]) == 101 # e
                ):
                    secure = True

            # HttpOnly (8 chars, boolean flag — no '=')
            if attr_len == 8:
                if (
                    _lc(bytes[pos]) == 104       # h
                    and _lc(bytes[pos+1]) == 116 # t
                    and _lc(bytes[pos+2]) == 116 # t
                    and _lc(bytes[pos+3]) == 112 # p
                    and _lc(bytes[pos+4]) == 111 # o
                    and _lc(bytes[pos+5]) == 110 # n
                    and _lc(bytes[pos+6]) == 108 # l
                    and _lc(bytes[pos+7]) == 121 # y
                ):
                    httponly = True

            # SameSite= (9 chars: "samesite=")
            # Normalize to "Strict" / "Lax" / "None"; default "Lax" for unknown values
            if attr_len >= 9:
                if (
                    _lc(bytes[pos]) == 115       # s
                    and _lc(bytes[pos+1]) == 97  # a
                    and _lc(bytes[pos+2]) == 109 # m
                    and _lc(bytes[pos+3]) == 101 # e
                    and _lc(bytes[pos+4]) == 115 # s
                    and _lc(bytes[pos+5]) == 105 # i
                    and _lc(bytes[pos+6]) == 116 # t
                    and _lc(bytes[pos+7]) == 101 # e
                    and bytes[pos+8] == 61       # =
                ):
                    var v_start = pos + 9
                    var v_len = attr_end - v_start
                    # Normalize: "strict" → "Strict", "lax" → "Lax", "none" → "None"
                    if v_len == 6 and _lc(bytes[v_start]) == 115 and _lc(bytes[v_start+1]) == 116:
                        samesite = String("Strict")  # "strict"
                    elif v_len == 3 and _lc(bytes[v_start]) == 108:
                        samesite = String("Lax")     # "lax"
                    elif v_len == 4 and _lc(bytes[v_start]) == 110:
                        samesite = String("None")    # "none"
                    # else: leave as default "Lax" for unknown values

            pos = attr_end + 1

        if max_age_found:
            if max_age_val <= 0:
                # Max-Age=0 → delete existing cookie with same name/domain
                for i in range(len(self._jar_names)):
                    if self._jar_domains[i] == cookie_domain and self._jar_names[i] == name:
                        var last = len(self._jar_names) - 1
                        if i != last:
                            self._jar_domains[i] = self._jar_domains[last]
                            self._jar_names[i] = self._jar_names[last]
                            self._jar_values[i] = self._jar_values[last]
                            self._jar_expiries[i] = self._jar_expiries[last]
                            self._jar_paths[i] = self._jar_paths[last]
                            self._jar_secure[i] = self._jar_secure[last]
                            self._jar_host_only[i] = self._jar_host_only[last]
                            self._jar_samesite[i] = self._jar_samesite[last]
                            self._jar_httponly[i] = self._jar_httponly[last]
                        _ = self._jar_domains.pop()
                        _ = self._jar_names.pop()
                        _ = self._jar_values.pop()
                        _ = self._jar_expiries.pop()
                        _ = self._jar_paths.pop()
                        _ = self._jar_secure.pop()
                        _ = self._jar_host_only.pop()
                        _ = self._jar_samesite.pop()
                        _ = self._jar_httponly.pop()
                        break
                return  # don't store a new entry
            else:
                expiry = _unix_time_secs() + max_age_val

        # Purge expired cookies before inserting (S11)
        var now_purge = _unix_time_secs()
        var pi = 0
        while pi < len(self._jar_names):
            var exp = self._jar_expiries[pi]
            if exp > 0 and now_purge > exp:
                var last = len(self._jar_names) - 1
                if pi != last:
                    self._jar_domains[pi] = self._jar_domains[last]
                    self._jar_names[pi] = self._jar_names[last]
                    self._jar_values[pi] = self._jar_values[last]
                    self._jar_expiries[pi] = self._jar_expiries[last]
                    self._jar_paths[pi] = self._jar_paths[last]
                    self._jar_secure[pi] = self._jar_secure[last]
                    self._jar_host_only[pi] = self._jar_host_only[last]
                    self._jar_samesite[pi] = self._jar_samesite[last]
                    self._jar_httponly[pi] = self._jar_httponly[last]
                _ = self._jar_domains.pop()
                _ = self._jar_names.pop()
                _ = self._jar_values.pop()
                _ = self._jar_expiries.pop()
                _ = self._jar_paths.pop()
                _ = self._jar_secure.pop()
                _ = self._jar_host_only.pop()
                _ = self._jar_samesite.pop()
                _ = self._jar_httponly.pop()
                # don't increment pi — the slot now holds what was the last element
            else:
                pi += 1

        # Update if name already exists for this domain, else append
        for i in range(len(self._jar_names)):
            if self._jar_domains[i] == cookie_domain and self._jar_names[i] == name:
                self._jar_values[i] = value
                self._jar_expiries[i] = expiry
                self._jar_paths[i] = cookie_path
                self._jar_secure[i] = secure
                self._jar_host_only[i] = host_only
                self._jar_samesite[i] = samesite
                self._jar_httponly[i] = httponly
                return
        self._jar_domains.append(cookie_domain)
        self._jar_names.append(name)
        self._jar_values.append(value)
        self._jar_expiries.append(expiry)
        self._jar_paths.append(cookie_path)
        self._jar_secure.append(secure)
        self._jar_host_only.append(host_only)
        self._jar_samesite.append(samesite)
        self._jar_httponly.append(httponly)

    def _jar_cookie_for(self, host: String, req_path: String, is_https: Bool) -> String:
        """Build Cookie header value from jar entries matching host, path, and scheme.

        Filters by:
          - expiry: skips expired cookies (expiry > 0 and now > expiry)
          - path: req_path must be under the cookie's Path
          - secure: Secure cookies not sent over HTTP
          - domain: exact match (host_only) or suffix match
        """
        var now = _unix_time_secs()
        var result = List[UInt8](capacity=64)
        var first = True
        for i in range(len(self._jar_names)):
            var exp = self._jar_expiries[i]
            if exp > 0 and now > exp:
                continue  # expired
            if self._jar_secure[i] and not is_https:
                continue  # Secure cookie not sent over HTTP
            if not _path_matches(req_path, self._jar_paths[i]):
                continue  # path doesn't match
            if not _domain_matches(host, self._jar_domains[i], self._jar_host_only[i]):
                continue  # domain doesn't match
            if self._jar_samesite[i] == "None" and not is_https:
                continue  # SameSite=None requires Secure (HTTPS)
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
# StreamResponse — Incremental Body Reading
# ============================================================================


struct StreamResponse(Movable):
    """HTTP response for streaming / incremental body reading.

    Holds the socket after headers are parsed. Call read_chunk() repeatedly
    until it returns an empty list, then close() to release the connection.

    Unlike HttpResponse this struct is Movable only (socket ownership).
    """

    var status_code: Int
    var status_text: String
    var headers: HttpHeaders
    var url: String
    var ok: Bool
    var _leftover: List[UInt8]  # body bytes already recv'd with the headers
    var _leftover_pos: Int
    var _content_length: Int  # -1 = unknown length, read until EOF
    var _body_read: Int       # total body bytes returned via read_chunk so far
    var _is_tls: Bool
    var _done: Bool
    var _http_sock: TcpSocket
    var _tls_sock: TlsSocket

    def __init__(out self):
        self.status_code = 0
        self.status_text = String("")
        self.headers = HttpHeaders()
        self.url = String("")
        self.ok = False
        self._leftover = List[UInt8]()
        self._leftover_pos = 0
        self._content_length = -1
        self._body_read = 0
        self._is_tls = False
        self._done = True  # default to done until properly initialized
        self._http_sock = TcpSocket()
        self._tls_sock = TlsSocket(0)

    def __moveinit__(out self, deinit take: Self):
        self.status_code = take.status_code
        self.status_text = take.status_text^
        self.headers = take.headers^
        self.url = take.url^
        self.ok = take.ok
        self._leftover = take._leftover^
        self._leftover_pos = take._leftover_pos
        self._content_length = take._content_length
        self._body_read = take._body_read
        self._is_tls = take._is_tls
        self._done = take._done
        self._http_sock = take._http_sock^
        self._tls_sock = take._tls_sock^

    def read_chunk(mut self, size: Int = 8192) raises -> List[UInt8]:
        """Read up to size bytes of the response body.

        Returns an empty list when the body is fully consumed.
        """
        if self._done:
            return List[UInt8]()

        var result = List[UInt8](capacity=size)

        # Drain leftover bytes from initial header recv first
        var leftover_avail = len(self._leftover) - self._leftover_pos
        if leftover_avail > 0:
            var take_n = min(size, leftover_avail)
            for i in range(take_n):
                result.append(self._leftover[self._leftover_pos + i])
            self._leftover_pos += take_n

        # Fetch more from the socket if we still need bytes
        var got = len(result)
        if got < size and not self._done:
            var need = size - got
            # Cap by remaining Content-Length
            if self._content_length >= 0:
                var remaining_cl = self._content_length - self._body_read - got
                if remaining_cl <= 0:
                    self._done = True
                    need = 0
                else:
                    need = min(need, remaining_cl)
            if need > 0:
                var chunk: List[UInt8]
                try:
                    if self._is_tls:
                        chunk = self._tls_sock.recv(need)
                    else:
                        chunk = self._http_sock.recv_bytes(need)
                except:
                    self._done = True
                    chunk = List[UInt8]()
                if len(chunk) == 0:
                    self._done = True
                else:
                    for i in range(len(chunk)):
                        result.append(chunk[i])

        self._body_read += len(result)
        if len(result) == 0:
            self._done = True
        elif self._content_length >= 0 and self._body_read >= self._content_length:
            self._done = True
        return result^

    def read_all(mut self) raises -> String:
        """Read and return the entire remaining response body as a String."""
        var buf = List[UInt8]()
        while True:
            var chunk = self.read_chunk(65536)
            if len(chunk) == 0:
                break
            for i in range(len(chunk)):
                buf.append(chunk[i])
        return String(unsafe_from_utf8=buf^)

    def close(mut self) raises:
        """Close the underlying socket and mark the stream as done."""
        self._done = True
        if self._is_tls:
            try:
                self._tls_sock.close()
            except:
                pass
        else:
            try:
                self._http_sock.close()
            except:
                pass


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


def _buf_leftover(buf: List[UInt8], start: Int) -> List[UInt8]:
    """Return a copy of buf[start..] (bytes after header end)."""
    var n = len(buf)
    if start >= n:
        return List[UInt8]()
    var result = List[UInt8](capacity=n - start)
    for i in range(start, n):
        result.append(buf[i])
    return result^


def _buf_to_string(buf: List[UInt8], header_end: Int) -> String:
    """Build a String from buf[0..header_end] — used to pass headers-only to _parse_response."""
    var copy_buf = List[UInt8](capacity=header_end)
    for i in range(header_end):
        copy_buf.append(buf[i])
    return String(unsafe_from_utf8=copy_buf^)


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


def _buf_content_length(buf: List[UInt8], header_end: Int) raises -> Int:
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
                var digit = Int(c - 48)
                if result > (MAX_RESPONSE_BYTES - digit) // 10:
                    raise _err_parse("Content-Length value overflows response size limit")
                result = result * 10 + digit
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
            raise _err_connection("connection closed before response headers")
        _list_append(buf, chunk)
        if len(buf) > MAX_RESPONSE_BYTES:
            raise _err_connection("response headers exceed size limit")
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
        if cl > MAX_RESPONSE_BYTES:
            raise _err_connection("Content-Length exceeds response size limit")
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
                raise _err_connection(es)
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
                raise _err_connection(es)
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
            raise _err_connection("connection closed before response headers")
        _list_append(buf, chunk)
        if len(buf) > MAX_RESPONSE_BYTES:
            raise _err_connection("response headers exceed size limit")
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
        if cl > MAX_RESPONSE_BYTES:
            raise _err_connection("Content-Length exceeds response size limit")
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
        raise _err_validation("HTTP method must not be empty")
    var bytes = method.as_bytes()
    for i in range(len(method)):
        var b = bytes[i]
        if b < UInt8(ord("A")) or b > UInt8(ord("Z")):
            raise _err_validation("invalid HTTP method: must be uppercase ASCII letters")


def _validate_header_key(key: String) raises:
    """Validate header key contains no CR, LF, or colon characters."""
    var bytes = key.as_bytes()
    for i in range(len(key)):
        var b = bytes[i]
        if b == 13 or b == 10 or b == 58:  # \r, \n, :
            raise _err_validation("invalid header key: contains CR, LF, or colon")


def _validate_header_value(value: String) raises:
    """Validate header value contains no CR or LF characters."""
    var bytes = value.as_bytes()
    for i in range(len(value)):
        var b = bytes[i]
        if b == 13 or b == 10:  # \r, \n
            raise _err_validation("invalid header value: contains CR or LF")


def _validate_path(path: String) raises:
    """Validate request path contains no CR or LF characters."""
    var bytes = path.as_bytes()
    for i in range(len(path)):
        var b = bytes[i]
        if b == 13 or b == 10:  # \r, \n
            raise _err_validation("invalid request path: contains CR or LF")


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


def _path_matches(req_path: String, cookie_path: String) -> Bool:
    """Return True if req_path is under cookie_path (RFC 6265 §5.1.4).

    cookie_path must be a prefix of req_path AND one of:
      - req_path == cookie_path (exact match)
      - cookie_path ends with '/'
      - next char in req_path is '/'
    """
    var cp_len = len(cookie_path)
    var rp_len = len(req_path)
    if cp_len == 0:
        return True  # empty cookie path matches everything
    var cp_bytes = cookie_path.as_bytes()
    var rp_bytes = req_path.as_bytes()
    if rp_len < cp_len:
        return False
    for i in range(cp_len):
        if rp_bytes[i] != cp_bytes[i]:
            return False
    # req_path starts with cookie_path; check boundary
    if rp_len == cp_len:
        return True
    if cp_bytes[cp_len - 1] == UInt8(47):  # cookie_path ends with '/'
        return True
    if rp_bytes[cp_len] == UInt8(47):  # next char is '/'
        return True
    return False


def _domain_matches(host: String, cookie_domain: String, host_only: Bool) -> Bool:
    """Return True if host matches cookie_domain (RFC 6265 §5.1.3).

    host_only=True  → exact match only (no Domain attribute was set)
    host_only=False → host == cookie_domain OR host ends with "." + cookie_domain
    """
    if host == cookie_domain:
        return True
    if host_only:
        return False
    # Subdomain match: host ends with "." + cookie_domain
    var suffix = "." + cookie_domain
    var h_len = len(host)
    var s_len = len(suffix)
    if h_len <= s_len:
        return False
    var h_bytes = host.as_bytes()
    var s_bytes = suffix.as_bytes()
    var offset = h_len - s_len
    for i in range(s_len):
        if h_bytes[offset + i] != s_bytes[i]:
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
    var size = end - start
    var result = List[UInt8](capacity=size + 1)
    result.resize(size, 0)
    _ = external_call["memcpy", Int](Int(result.unsafe_ptr()), Int(data_ptr + start), size)
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
        raise _err_chunked("chunk size hex string too long")
    var result = 0
    for i in range(start, end):
        if result > MAX_CHUNK // 16:
            raise _err_chunked("chunk size too large (exceeds 256 MB)")
        var c = (data_ptr + i)[]
        result = result * 16
        if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
            result += Int(c - UInt8(ord("0")))
        elif c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
            result += Int(c - UInt8(ord("a"))) + 10
        elif c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
            result += Int(c - UInt8(ord("A"))) + 10
        else:
            raise _err_chunked(
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
    var total_decoded = 0
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
            raise _err_chunked(
                "chunked body truncated: expected "
                + String(chunk_size)
                + " bytes, only "
                + String(body_len - data_start)
                + " available"
            )
        total_decoded += chunk_size
        if total_decoded > MAX_RESPONSE_BYTES:
            raise _err_connection("chunked body exceeds response size limit")
        var current_len = len(result)
        result.resize(current_len + chunk_size, 0)
        _ = external_call["memcpy", Int](
            Int(result.unsafe_ptr()) + current_len, Int(ptr + data_start), chunk_size
        )
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
        raise _err_parse("malformed HTTP response: no header/body separator found")

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
        raise _err_parse(
            "response is not HTTP: " + _ptr_to_string(ptr, 0, status_end)
        )

    # Parse "HTTP/1.1 200 OK" — find spaces within [0..status_end)
    var sp1 = _find_char(ptr, status_end, UInt8(ord(" ")), 0)
    if sp1 < 0:
        raise _err_parse(
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
        raise _err_parse("status code too long (max 3 digits)")
    var result: Int = 0
    for i in range(start, end):
        var c = (data_ptr + i)[]
        if c < UInt8(ord("0")) or c > UInt8(ord("9")):
            raise _err_parse(
                "invalid status code: " + _ptr_to_string(data_ptr, start, end)
            )
        result = result * 10 + Int(c - UInt8(ord("0")))
    return result


# ============================================================================
# Session — Persistent Default Headers and Auth
# ============================================================================


struct Session(Movable):
    """HTTP session with persistent default headers and optional authentication.

    Default headers and auth are merged into every request. Caller-supplied
    headers override session defaults (last value wins on the server).

    Usage:
        var s = Session(allow_private_ips=True)
        s.set_header("X-API-Key", "abc123")
        s.set_auth(BasicAuth("user", "pass"))
        var r = s.get("http://example.com/api")
    """

    var client: HttpClient
    var default_headers: HttpHeaders
    var _auth_basic: BasicAuth
    var _auth_bearer: BearerAuth
    var _auth_mode: Int  # 0=none, 1=basic, 2=bearer

    def __init__(
        out self,
        allow_private_ips: Bool = False,
        timeout_secs: Int = 30,
    ) raises:
        self.client = HttpClient(
            allow_private_ips=allow_private_ips, timeout_secs=timeout_secs
        )
        self.default_headers = HttpHeaders()
        self._auth_basic = BasicAuth(String(""), String(""))
        self._auth_bearer = BearerAuth(String(""))
        self._auth_mode = 0

    def __moveinit__(out self, deinit take: Self):
        self.client = take.client^
        self.default_headers = take.default_headers^
        self._auth_basic = take._auth_basic^
        self._auth_bearer = take._auth_bearer^
        self._auth_mode = take._auth_mode

    def set_header(mut self, key: String, value: String):
        """Add or update a default header sent with every request."""
        for i in range(len(self.default_headers)):
            if _eq_ignore_case(self.default_headers._keys[i], key):
                self.default_headers._values[i] = value
                return
        self.default_headers.add(key, value)

    def set_auth(mut self, auth: BasicAuth):
        """Set Basic authentication applied to every request."""
        self._auth_basic = auth.copy()
        self._auth_mode = 1

    def set_auth(mut self, auth: BearerAuth):
        """Set Bearer token authentication applied to every request."""
        self._auth_bearer = auth.copy()
        self._auth_mode = 2

    def _merged(self, caller_headers: HttpHeaders) -> HttpHeaders:
        """Return merged headers: defaults + auth + caller (caller wins)."""
        var merged = HttpHeaders()
        for i in range(len(self.default_headers)):
            merged.add(self.default_headers._keys[i], self.default_headers._values[i])
        if self._auth_mode == 1 and not caller_headers.has("Authorization"):
            merged.add("Authorization", self._auth_basic.header())
        elif self._auth_mode == 2 and not caller_headers.has("Authorization"):
            merged.add("Authorization", self._auth_bearer.header())
        for i in range(len(caller_headers)):
            merged.add(caller_headers._keys[i], caller_headers._values[i])
        return merged^

    def get(mut self, url: String) raises -> HttpResponse:
        """Perform a GET request with session headers."""
        var empty = HttpHeaders()
        var h = self._merged(empty)
        return self.client._do_request("GET", url, String(""), h)

    def get(mut self, url: String, headers: HttpHeaders) raises -> HttpResponse:
        """Perform a GET request merging caller headers with session defaults."""
        var h = self._merged(headers)
        return self.client._do_request("GET", url, String(""), h)

    def post(mut self, url: String, body: String) raises -> HttpResponse:
        """Perform a POST request with session headers."""
        var empty = HttpHeaders()
        var h = self._merged(empty)
        return self.client._do_request("POST", url, body, h)

    def post(
        mut self, url: String, body: String, headers: HttpHeaders
    ) raises -> HttpResponse:
        """Perform a POST request merging caller headers with session defaults."""
        var h = self._merged(headers)
        return self.client._do_request("POST", url, body, h)

    def put(mut self, url: String, body: String) raises -> HttpResponse:
        """Perform a PUT request with session headers."""
        var empty = HttpHeaders()
        var h = self._merged(empty)
        return self.client._do_request("PUT", url, body, h)

    def put(
        mut self, url: String, body: String, headers: HttpHeaders
    ) raises -> HttpResponse:
        """Perform a PUT request merging caller headers with session defaults."""
        var h = self._merged(headers)
        return self.client._do_request("PUT", url, body, h)

    def delete(mut self, url: String) raises -> HttpResponse:
        """Perform a DELETE request with session headers."""
        var empty = HttpHeaders()
        var h = self._merged(empty)
        return self.client._do_request("DELETE", url, String(""), h)

    def patch(mut self, url: String, body: String) raises -> HttpResponse:
        """Perform a PATCH request with session headers."""
        var empty = HttpHeaders()
        var h = self._merged(empty)
        return self.client._do_request("PATCH", url, body, h)
