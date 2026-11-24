# Changelog

Notes for each release are on the [releases page](https://github.com/Mosaad-M/requests/releases).
This file records changes that affect which version you should use.

- 1.14.0: millisecond timeouts (`timeout_ms`, `total_timeout_ms`). Needs tls >= 1.12.0 and tcp >= 2.2.0.
- 1.13.0: `request_many`, which runs requests with their own methods, headers and bodies on one HTTP/2 connection.
- 1.6.0 and later need Mojo >= 1.2.0. On Mojo 1.0 or 1.1, use 1.5.0.
