# requests — Pure Mojo HTTP Client

A pure-[Mojo](https://www.modular.com/mojo) HTTP/1.1 client with HTTPS support.
No OpenSSL, no libcurl — TLS is handled entirely by the [tls](https://github.com/Mosaad-M/tls) package.

## Features

- `GET`, `POST`, `PUT`, `DELETE`, `PATCH`
- HTTP and HTTPS (TLS 1.3 + TLS 1.2)
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

- Mojo `>=1.0.0`
- No C compiler or linker flags: every dependency is pure Mojo, and the
  compression libraries are opened at runtime (see Compression)

## Testing

```bash
pixi run test
# 27/27 tests pass
```

## License

MIT — see [LICENSE](LICENSE)
