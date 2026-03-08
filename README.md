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
```

## Dependencies

- [tls](https://github.com/Mosaad-M/tls) — Pure Mojo TLS 1.3 + 1.2
- [tcp](https://github.com/Mosaad-M/tcp) — TCP socket layer
- [url](https://github.com/Mosaad-M/url) — URL parser
- [json](https://github.com/Mosaad-M/json) — JSON parser

## Requirements

- Mojo `>=0.26.1`
- GCC or Clang (for `errno_helper.c` from the `tcp` dependency)

## Testing

```bash
pixi run test
# 27/27 tests pass
```

## License

MIT — see [LICENSE](LICENSE)
