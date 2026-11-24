# requests

A pure [Mojo](https://www.modular.com/mojo) HTTP/1.1 and HTTP/2 client with HTTPS. No
OpenSSL and no libcurl: TLS comes from the [tls](https://github.com/Mosaad-M/tls) package
and sockets from [tcp](https://github.com/Mosaad-M/tcp).

- `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD` and `OPTIONS`, with custom headers and bodies
- TLS 1.3 and 1.2; HTTP/2 is negotiated with ALPN
- Keep-alive connection pooling, redirects, cookies and an HTTP CONNECT proxy
- `get_many` and `request_many` run several requests to one HTTP/2 host at once
- A deadline for the whole call, opt-in retries with backoff, and size limits
- Transparent gzip, deflate, zstd and brotli decompression

## Usage

```mojo
from http_client import HttpClient, HttpHeaders

var client = HttpClient()

# Simple GET
var resp = client.get("https://api.example.com/data")
print(resp.status_code)  # 200
print(resp.body)

# POST with a JSON body (Content-Type defaults to application/json)
var resp2 = client.post("https://api.example.com/items", '{"name": "test"}')

# or with your own headers
var h = HttpHeaders()
h.add("X-Request-Id", "42")
var resp3 = client.post("https://api.example.com/items", '{"name": "test"}', h)

# Parse a JSON response
var data = resp.json()        # mutable JsonValue tree
var doc = resp.json_doc()     # read-only JsonDoc: faster, compact, lookups are views
print(doc.get_string("name"))
```

## Binary bodies and any method

```mojo
var data = List[UInt8]()   # Parquet, an image, ...
...
var h = HttpHeaders()
h.add("Content-Type", "application/octet-stream")

# List[UInt8] or Span[UInt8]: no String wrapping, no copy on the way in
var r = client.put("https://store.example.com/obj", data, h)

# any method; follows redirects like get() (a 303 turns it into a GET)
var r2 = client.request("PUT", "https://store.example.com/obj", Span(data), h)

# the response body as bytes: a view of `body` (no copy), or an owned copy
var bytes_view = r.content()
var owned = r.to_bytes()
```

A body sent without a `Content-Type` gets `default_content_type` ("application/json").
Set it to `""` for binary uploads that set their own.

## Deadlines, retries and limits

By default there is no total deadline and no retries. Size limits are 100 MB for the body and 1 MB for headers. Set any of these on the client:

```mojo
var client = HttpClient()
client.total_timeout_secs = 10      # whole call: redirects, retries, body (TimeoutError)
client.total_timeout_ms = 250       # same in milliseconds; wins over total_timeout_secs
client.max_retries = 3              # connect/read failures and 429/502/503/504
client.retry_backoff_ms = 200       # doubles per attempt, jittered, capped at 30 s
# Retry-After (seconds) is honoured. POST/PATCH are retried only with
# client.retry_non_idempotent = True (a retry can repeat side effects).
client.max_response_bytes = 10 * 1024 * 1024   # default 100 MB
client.max_header_bytes = 64 * 1024            # default 1 MB
```

`HttpClient(timeout_secs=30)` sets the timeout of each socket read and write. In
milliseconds it is `HttpClient(timeout_ms=500)`, which wins when both are given. The
total deadline caps every read to the time left. The kernel rounds timeouts to its tick,
a few milliseconds. If a retry's wait would pass the deadline, the last response is
returned.

A request that fails on a pooled keep-alive connection is sent again on a new one only
if it is idempotent (GET, HEAD, OPTIONS, PUT, DELETE) or `retry_non_idempotent` is set,
because the server may already have processed it.

## Many requests at once

Requests to one HTTP/2 host share a connection and run concurrently:

```mojo
var urls = List[String]()
urls.append("https://example.com/a")
urls.append("https://example.com/b")
var responses = client.get_many(urls)   # same order as urls

# Each request with its own method, headers and body (a Range read per request):
var reqs = List[Request]()
for i in range(16):
    var h = HttpHeaders()
    h.add("Range", "bytes=" + String(i * 1048576) + "-" + String((i + 1) * 1048576 - 1))
    reqs.append(Request("GET", "https://example.com/big.parquet", h))
var parts = client.request_many(reqs)   # same order as reqs
```

`request_many` multiplexes GET, HEAD and OPTIONS to one HTTPS host that speaks HTTP/2.
Every other method, plain HTTP and HTTP/1.1-only hosts are sent one by one in order,
like `request()`. Redirects, retries and the total deadline behave as in `request()`,
and the first failing request raises. `max_batch_bytes` (default 1 GB) bounds the
bodies one `get_many` holds.

## Private addresses and proxies

By default the client refuses to connect to loopback, private, link-local and CGNAT
addresses. The check runs on the address the name resolved to, so DNS rebinding cannot
get around it. To call a service on localhost or a private network, opt in:

```mojo
var client = HttpClient(allow_private_ips=True)
```

The client reads `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from the environment. Set
`trust_env = False` to ignore them, or `proxy_url = "http://host:port"` to choose a proxy
explicitly. The private-address check does not cover the target of a proxied request,
because the proxy resolves it.

## Certificates

Server certificates are always verified against the trust anchors tls loads: the file
named by `SSL_CERT_FILE`, else the platform's bundle (`/etc/ssl/cert.pem` on macOS, the
distribution's file on Linux). The client parses the bundle once.

macOS's `cert.pem` is a trimmed export of the system keychain and lacks some roots, such
as the Comodo AAA Certificate Services root behind `example.com`'s chain. A site like
that fails with `chain not trusted (no path to a trust anchor)`, although curl, which
reads the keychain, connects. Set `SSL_CERT_FILE` to a fuller bundle, such as Mozilla's.

## Compression

Responses in gzip, deflate, zstd and brotli are decompressed transparently. The
libraries are opened at runtime, so a program using requests needs no linker flags:

- gzip and deflate use the system zlib
- zstd uses libzstd from the Mojo environment, or the system
- brotli uses libbrotlidec, only when installed (`pixi add brotli`,
  `apt install libbrotli1` or `brew install brotli`)

`Accept-Encoding` lists only the encodings whose library loaded, so a server never sends
one the client cannot decode.

## Requirements

- Mojo >= 1.2.0
- [tls](https://github.com/Mosaad-M/tls) >= 1.12.0, [tcp](https://github.com/Mosaad-M/tcp) >= 2.2.0,
  [url](https://github.com/Mosaad-M/url) >= 1.2.0 and [json](https://github.com/Mosaad-M/json) >= 3.1.0,
  all pure Mojo and installed by [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg)
- No C compiler or linker flags

## Testing

```bash
pixi run test            # resilience (46) + framing (51) + client (144 HTTP, 4 HTTPS)
pixi run test-h2-local   # HTTP/2 against a local server (41); needs the python `h2` package (pixi installs it)
pixi run test-hpack      # 130
pixi run test-h2         # 70
```

Release history is in [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
