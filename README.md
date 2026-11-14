# requests — Pure Mojo HTTP Client

A pure-[Mojo](https://www.modular.com/mojo) HTTP/1.1 and HTTP/2 client with HTTPS support.
No OpenSSL, no libcurl — TLS is handled entirely by the [tls](https://github.com/Mosaad-M/tls) package.

## Features

- `GET`, `POST`, `PUT`, `DELETE`, `PATCH`
- HTTP and HTTPS (TLS 1.3 + TLS 1.2); HTTP/2 over TLS is negotiated with ALPN
- `get_many`: several URLs on one HTTP/2 host in flight at once
- Total request deadline, opt-in retries with backoff, configurable size limits
- Custom headers and request body
- Connection pooling (keep-alive) for repeated requests to the same host
- CA bundle loaded from system (`/etc/ssl/certs/ca-certificates.crt` or `/etc/ssl/cert.pem`)
- `HttpClient` with lazy-loaded, cached CA bundle (146 system certs parsed once per client)

## Usage

```mojo
from http_client import HttpClient

var client = HttpClient()

# Simple GET
var resp = client.get("https://api.example.com/data")
print(resp.status_code)  # 200
print(resp.body)

# POST with JSON body
var resp2 = client.post(
    "https://api.example.com/items",
    body='{"name": "test"}',
    headers='Content-Type: application/json\r\n'
)

# Parse a JSON response
var data = resp.json()        # mutable JsonValue tree
var doc = resp.json_doc()     # read-only JsonDoc: faster, compact, lookups are views
print(doc.get_string("name"))
```

## Deadlines, retries and limits

All off or at their old values by default; set them on the client:

```mojo
var client = HttpClient()
client.total_timeout_secs = 10      # whole call: redirects, retries, body (TimeoutError)
client.max_retries = 3              # connect/read failures and 429/502/503/504
client.retry_backoff_ms = 200       # doubles per attempt, jittered, capped at 30 s
# Retry-After (seconds) is honoured. POST/PATCH are retried only with
# client.retry_non_idempotent = True (a retry can repeat side effects).
client.max_response_bytes = 10 * 1024 * 1024   # default 100 MB
client.max_header_bytes = 64 * 1024            # default 1 MB

# Several URLs on one HTTP/2 host share a connection and run concurrently:
var urls = List[String]()
urls.append("https://example.com/a")
urls.append("https://example.com/b")
var responses = client.get_many(urls)   # same order as urls
```

`total_timeout_secs` caps every read to the time left (whole seconds). If a
retry's wait would pass the deadline, the last response is returned.
A request that fails on a pooled keep-alive connection is sent again on a new
one only if it is idempotent (GET, HEAD, OPTIONS, PUT, DELETE) or
`retry_non_idempotent` is set: the server may already have processed it.
`max_batch_bytes` (default 1 GB) bounds the bodies one `get_many` holds.

## Dependencies

- [tls](https://github.com/Mosaad-M/tls) — Pure Mojo TLS 1.3 + 1.2
- [tcp](https://github.com/Mosaad-M/tcp) — TCP socket layer
- [url](https://github.com/Mosaad-M/url) — URL parser
- [json](https://github.com/Mosaad-M/json) — JSON parser (>= 3.0.1)

## Compression

Responses in gzip, deflate, zstd and brotli are decompressed transparently. The
libraries are opened at runtime, so a program using requests needs **no linker
flags**:

- gzip / deflate: the system zlib
- zstd: libzstd from the Mojo environment (or the system)
- brotli: libbrotlidec, used only when installed (`pixi add brotli`,
  `apt install libbrotli1` or `brew install brotli`)

`Accept-Encoding` lists only the encodings whose library loaded, so a server
never sends one the client cannot decode.

## Requirements

- Mojo `>=1.2.0` (for Mojo 1.0 / 1.1, use requests 1.5.0)
- No C compiler or linker flags: every dependency is pure Mojo, and the
  compression libraries are opened at runtime (see Compression)

## Testing

```bash
pixi run test            # resilience (38) + framing (44) + client (116 HTTP, 4 HTTPS)
pixi run test-h2-local   # HTTP/2 against a local server (28); needs the python `h2` package (pixi installs it)
pixi run test-hpack      # 128
pixi run test-h2         # 70
```

## License

MIT — see [LICENSE](LICENSE)
