# ============================================================================
# bench_profile.mojo — Comprehensive Profiling Benchmark
# ============================================================================
#
# Measures wall-clock time for every layer of the HTTP client pipeline.
# Uses direct inline timing to avoid closure capture issues with non-copyable
# types (JsonValue, HttpResponse, etc.).
#
# Usage:
#   pixi run mojo run bench_profile.mojo        (URL + JSON + HTTP parse only)
#   bash build_and_run.sh bench_profile.mojo     (includes network tests)
#
# ============================================================================

from time import perf_counter_ns
from url import parse_url
from json import parse_json, JsonValue
from http_client import (
    HttpClient,
    HttpHeaders,
    HttpResponse,
    _parse_response,
    _decode_chunked,
    _eq_ignore_case,
    _to_lower,
)


# ============================================================================
# Helpers
# ============================================================================


def format_ns(ns: Int) -> String:
    if ns >= 1_000_000_000:
        return String(Float64(ns) / 1_000_000_000.0) + " s"
    elif ns >= 1_000_000:
        return String(Float64(ns) / 1_000_000.0) + " ms"
    elif ns >= 1_000:
        return String(Float64(ns) / 1_000.0) + " us"
    return String(ns) + " ns"


def report(name: String, total_ns: Int, iters: Int):
    var avg = total_ns // iters
    print(
        "  " + name + ": avg=" + format_ns(avg) + " total=" + format_ns(
            total_ns
        ) + " (n=" + String(iters) + ")"
    )


def _append(mut buf: List[UInt8], s: String):
    var sb = s.as_bytes()
    for i in range(len(s)):
        buf.append(sb[i])


# ============================================================================
# Test Data Generators
# ============================================================================


def make_small_json() -> String:
    return '{"name": "Alice", "age": 30, "active": true}'


def make_medium_json() -> String:
    return String(
        '{"users": [{"id": 1, "name": "Alice", "email": "alice@example.com",'
        ' "scores": [95, 87, 92, 88, 91], "address": {"city": "NYC",'
        ' "zip": "10001"}}, {"id": 2, "name": "Bob", "email":'
        ' "bob@example.com", "scores": [78, 82, 90, 85, 88], "address":'
        ' {"city": "LA", "zip": "90001"}}], "total": 2, "page": 1}'
    )


def make_large_json() -> String:
    var parts = List[UInt8](capacity=12000)
    _append(parts, "[")
    for i in range(100):
        if i > 0:
            _append(parts, ", ")
        _append(
            parts,
            '{"id": '
            + String(i)
            + ', "title": "Post number '
            + String(i)
            + '", "body": "This is the body of post '
            + String(i)
            + ' with some filler text to make it realistic.", "userId": '
            + String(i % 10 + 1)
            + ", "
            + '"likes": '
            + String(i * 7)
            + ", "
            + '"published": true}',
        )
    _append(parts, "]")
    return String(unsafe_from_utf8=parts^)


def make_integer_heavy_json() -> String:
    var parts = List[UInt8](capacity=5000)
    _append(parts, "[")
    for i in range(500):
        if i > 0:
            _append(parts, ", ")
        _append(parts, String(i * 13 + 7))
    _append(parts, "]")
    return String(unsafe_from_utf8=parts^)


def make_string_heavy_json() -> String:
    var parts = List[UInt8](capacity=10000)
    _append(parts, "{")
    for i in range(100):
        if i > 0:
            _append(parts, ", ")
        _append(
            parts,
            '"key_'
            + String(i)
            + '": "value_string_number_'
            + String(i)
            + '_with_extra_padding"',
        )
    _append(parts, "}")
    return String(unsafe_from_utf8=parts^)


def make_float_heavy_json() -> String:
    var parts = List[UInt8](capacity=5000)
    _append(parts, "[")
    for i in range(200):
        if i > 0:
            _append(parts, ", ")
        _append(parts, String(Float64(i) * 3.14159 + 0.001))
    _append(parts, "]")
    return String(unsafe_from_utf8=parts^)


def make_raw_http_response(body_size: Int) -> String:
    var body_bytes = List[UInt8](capacity=body_size)
    for i in range(body_size):
        body_bytes.append(ord("A") + UInt8(i % 26))
    var body = String(unsafe_from_utf8=body_bytes^)
    var parts = List[UInt8](capacity=body_size + 500)
    _append(parts, "HTTP/1.1 200 OK\r\n")
    _append(parts, "Content-Type: application/json\r\n")
    _append(parts, "Content-Length: " + String(body_size) + "\r\n")
    _append(parts, "Server: nginx/1.24\r\n")
    _append(parts, "X-Request-Id: abc123def456\r\n")
    _append(parts, "Cache-Control: no-cache\r\n")
    _append(parts, "Connection: close\r\n")
    _append(parts, "Date: Thu, 12 Feb 2026 12:00:00 GMT\r\n")
    _append(parts, "X-Custom-1: value1\r\n")
    _append(parts, "X-Custom-2: value2\r\n")
    _append(parts, "X-Custom-3: value3\r\n")
    _append(parts, "X-Custom-4: value4\r\n")
    _append(parts, "X-Custom-5: value5\r\n")
    _append(parts, "\r\n")
    _append(parts, body)
    return String(unsafe_from_utf8=parts^)


def make_chunked_body() -> String:
    var parts = List[UInt8](capacity=2000)
    _append(parts, "100\r\n")
    for _ in range(256):
        parts.append(ord("X"))
    _append(parts, "\r\n")
    _append(parts, "200\r\n")
    for _ in range(512):
        parts.append(ord("Y"))
    _append(parts, "\r\n")
    _append(parts, "80\r\n")
    for _ in range(128):
        parts.append(ord("Z"))
    _append(parts, "\r\n")
    _append(parts, "0\r\n\r\n")
    return String(unsafe_from_utf8=parts^)


# ============================================================================
# Benchmark Sections
# ============================================================================


def bench_url_parsing() raises:
    print("\n=== URL Parsing ===")
    alias N = 10000

    var urls = List[String]()
    urls.append("http://example.com")
    urls.append("http://example.com/path/to/resource")
    urls.append("https://api.example.com:8443/v2/users?page=1&limit=50")
    urls.append("http://192.168.1.1:3000/api/data?key=value&foo=bar")
    urls.append("https://very-long-subdomain.api.example.com/a/b/c/d/e/f")

    for idx in range(len(urls)):
        var url = urls[idx]
        var total: Int = 0
        for _ in range(N):
            var start = perf_counter_ns()
            _ = parse_url(url)
            total += Int(perf_counter_ns() - start)
        report("parse '" + url + "'", total, N)


def bench_json_parsing() raises:
    print("\n=== JSON Parsing ===")

    # Small JSON
    var small = make_small_json()
    print("  [small: " + String(len(small)) + " bytes]")
    var total: Int = 0
    alias N_SMALL = 10000
    for _ in range(N_SMALL):
        var start = perf_counter_ns()
        _ = parse_json(small)
        total += Int(perf_counter_ns() - start)
    report("small JSON", total, N_SMALL)

    # Medium JSON
    var medium = make_medium_json()
    print("  [medium: " + String(len(medium)) + " bytes]")
    total = 0
    alias N_MED = 5000
    for _ in range(N_MED):
        var start = perf_counter_ns()
        _ = parse_json(medium)
        total += Int(perf_counter_ns() - start)
    report("medium JSON", total, N_MED)

    # Large JSON
    var large = make_large_json()
    print("  [large: " + String(len(large)) + " bytes]")
    total = 0
    alias N_LRG = 500
    for _ in range(N_LRG):
        var start = perf_counter_ns()
        _ = parse_json(large)
        total += Int(perf_counter_ns() - start)
    report("large JSON", total, N_LRG)

    # Integer-heavy JSON
    var int_json = make_integer_heavy_json()
    print("  [integer-heavy: " + String(len(int_json)) + " bytes]")
    total = 0
    alias N_INT = 2000
    for _ in range(N_INT):
        var start = perf_counter_ns()
        _ = parse_json(int_json)
        total += Int(perf_counter_ns() - start)
    report("integer-heavy JSON", total, N_INT)

    # Float-heavy JSON
    var float_json = make_float_heavy_json()
    print("  [float-heavy: " + String(len(float_json)) + " bytes]")
    total = 0
    alias N_FLT = 2000
    for _ in range(N_FLT):
        var start = perf_counter_ns()
        _ = parse_json(float_json)
        total += Int(perf_counter_ns() - start)
    report("float-heavy JSON", total, N_FLT)

    # String-heavy JSON
    var str_json = make_string_heavy_json()
    print("  [string-heavy: " + String(len(str_json)) + " bytes]")
    total = 0
    alias N_STR = 2000
    for _ in range(N_STR):
        var start = perf_counter_ns()
        _ = parse_json(str_json)
        total += Int(perf_counter_ns() - start)
    report("string-heavy JSON", total, N_STR)


def bench_json_access() raises:
    """Benchmark accessing values after parsing (copy overhead)."""
    print("\n=== JSON Value Access ===")
    alias N = 10000

    var medium = make_medium_json()
    var parsed = parse_json(medium)

    # Nested access
    var total: Int = 0
    for _ in range(N):
        var start = perf_counter_ns()
        var users = parsed.get("users")
        var first = users.get(0)
        var name = first.get("name").as_string()
        var scores = first.get("scores")
        var s0 = scores.get(0).as_int()
        var addr = first.get("address")
        var city = addr.get("city").as_string()
        total += Int(perf_counter_ns() - start)
    report("nested access (7 lookups + deep copy)", total, N)

    # Contains checks
    total = 0
    for _ in range(N):
        var start = perf_counter_ns()
        var has_users = "users" in parsed
        var has_total = "total" in parsed
        var has_missing = "missing" in parsed
        total += Int(perf_counter_ns() - start)
    report("contains check (3 checks)", total, N)


def bench_json_stringify() raises:
    """Benchmark JSON serialization."""
    print("\n=== JSON Serialization ===")

    var medium = make_medium_json()
    var parsed_med = parse_json(medium)
    var total: Int = 0
    alias N_MED = 5000
    for _ in range(N_MED):
        var start = perf_counter_ns()
        var s = String(parsed_med)
        total += Int(perf_counter_ns() - start)
    report("String(medium_json)", total, N_MED)

    var large = make_large_json()
    var parsed_lg = parse_json(large)
    total = 0
    alias N_LRG = 500
    for _ in range(N_LRG):
        var start = perf_counter_ns()
        var s = String(parsed_lg)
        total += Int(perf_counter_ns() - start)
    report("String(large_json)", total, N_LRG)


def bench_http_parsing() raises:
    print("\n=== HTTP Response Parsing ===")

    # Small response (~500 byte body)
    var small_resp = make_raw_http_response(500)
    print("  [small response: " + String(len(small_resp)) + " bytes]")
    var total: Int = 0
    alias N_SM = 5000
    for _ in range(N_SM):
        var start = perf_counter_ns()
        _ = _parse_response(small_resp, "http://example.com/test")
        total += Int(perf_counter_ns() - start)
    report("parse small response", total, N_SM)

    # Medium response (~10KB body)
    var med_resp = make_raw_http_response(10000)
    print("  [medium response: " + String(len(med_resp)) + " bytes]")
    total = 0
    alias N_MD = 2000
    for _ in range(N_MD):
        var start = perf_counter_ns()
        _ = _parse_response(med_resp, "http://example.com/test")
        total += Int(perf_counter_ns() - start)
    report("parse medium response", total, N_MD)

    # Large response (~100KB body)
    var large_resp = make_raw_http_response(100000)
    print("  [large response: " + String(len(large_resp)) + " bytes]")
    total = 0
    alias N_LG = 500
    for _ in range(N_LG):
        var start = perf_counter_ns()
        _ = _parse_response(large_resp, "http://example.com/test")
        total += Int(perf_counter_ns() - start)
    report("parse large response", total, N_LG)


def bench_chunked_decoding() raises:
    print("\n=== Chunked Transfer Decoding ===")

    var chunked = make_chunked_body()
    print(
        "  [chunked body: " + String(len(chunked)) + " bytes -> 896 decoded]"
    )
    var total: Int = 0
    alias N = 5000
    for _ in range(N):
        var start = perf_counter_ns()
        _ = _decode_chunked(chunked)
        total += Int(perf_counter_ns() - start)
    report("decode chunked", total, N)


def bench_case_insensitive() raises:
    print("\n=== Case-Insensitive Compare ===")
    alias N = 50000

    # _eq_ignore_case (allocation-free)
    var total: Int = 0
    for _ in range(N):
        var start = perf_counter_ns()
        _ = _eq_ignore_case("Content-Type", "content-type")
        _ = _eq_ignore_case("X-Request-Id", "X-REQUEST-ID")
        _ = _eq_ignore_case("Accept", "Accept")
        total += Int(perf_counter_ns() - start)
    report("_eq_ignore_case (3 short)", total, N)

    # _to_lower (allocating) for comparison
    total = 0
    for _ in range(N):
        var start = perf_counter_ns()
        _ = _to_lower("Content-Type")
        _ = _to_lower("X-Request-Id")
        _ = _to_lower("Accept")
        total += Int(perf_counter_ns() - start)
    report("_to_lower (3 short, allocating)", total, N)

    # Header lookups in a real parsed response
    var resp_raw = make_raw_http_response(100)
    var resp = _parse_response(resp_raw, "http://test.com")
    alias N2 = 10000
    total = 0
    for _ in range(N2):
        var start = perf_counter_ns()
        _ = resp.headers.get("content-type")
        _ = resp.headers.get("X-Request-Id")
        _ = resp.headers.get("Cache-Control")
        _ = resp.headers.get("nonexistent-header")
        _ = resp.headers.has("Server")
        total += Int(perf_counter_ns() - start)
    report("header lookups (5 lookups, 13 headers)", total, N2)


def bench_scaling() raises:
    """Measure how parsing time scales with input size."""
    print("\n=== Scaling Analysis ===")

    print("  HTTP response parse scaling:")
    var sizes = List[Int]()
    sizes.append(100)
    sizes.append(500)
    sizes.append(1000)
    sizes.append(5000)
    sizes.append(10000)
    sizes.append(50000)
    sizes.append(100000)

    for idx in range(len(sizes)):
        var size = sizes[idx]
        var resp_data = make_raw_http_response(size)
        var iters = 100000 // size
        if iters < 10:
            iters = 10
        var total_ns: Int = 0
        for _ in range(iters):
            var start = perf_counter_ns()
            _ = _parse_response(resp_data, "http://test.com")
            total_ns += Int(perf_counter_ns() - start)
        var avg_ns = total_ns // iters
        var throughput_mbs = Float64(size) / Float64(avg_ns) * 1000.0
        print(
            "    "
            + String(size)
            + " bytes: avg="
            + format_ns(avg_ns)
            + " throughput="
            + String(Int(throughput_mbs))
            + " MB/s"
        )

    print("  JSON parse scaling:")
    var json_counts = List[Int]()
    json_counts.append(10)
    json_counts.append(50)
    json_counts.append(100)
    json_counts.append(500)
    json_counts.append(1000)

    for idx in range(len(json_counts)):
        var n = json_counts[idx]
        var buf = List[UInt8](capacity=n * 50)
        _append(buf, "[")
        for i in range(n):
            if i > 0:
                _append(buf, ", ")
            _append(
                buf,
                '{"id": '
                + String(i)
                + ', "name": "item_'
                + String(i)
                + '"}',
            )
        _append(buf, "]")
        var json_str = String(unsafe_from_utf8=buf^)
        var json_bytes = len(json_str)

        var iters = 10000 // n
        if iters < 10:
            iters = 10
        var total_ns: Int = 0
        for _ in range(iters):
            var start = perf_counter_ns()
            _ = parse_json(json_str)
            total_ns += Int(perf_counter_ns() - start)
        var avg_ns = total_ns // iters
        var throughput_mbs = Float64(json_bytes) / Float64(avg_ns) * 1000.0
        print(
            "    "
            + String(n)
            + " objects ("
            + String(json_bytes)
            + " bytes): avg="
            + format_ns(avg_ns)
            + " throughput="
            + String(Int(throughput_mbs))
            + " MB/s"
        )


def bench_full_pipeline_local() raises:
    """Benchmark full HTTP GET to local test server (if running)."""
    print("\n=== Full HTTP Pipeline (localhost) ===")
    print("  (Requires test_server.py on localhost:18080)")

    var client = HttpClient()

    try:
        var test_resp = client.get("http://127.0.0.1:18080/")
        if test_resp.status_code != 200:
            print("  SKIP: test server not responding correctly")
            return
    except:
        print("  SKIP: test server not running")
        return

    # GET / (small JSON)
    alias N1 = 100
    var total: Int = 0
    for _ in range(N1):
        var start = perf_counter_ns()
        _ = client.get("http://127.0.0.1:18080/")
        total += Int(perf_counter_ns() - start)
    report("GET / (small JSON)", total, N1)

    # GET /large (100KB)
    alias N2 = 50
    total = 0
    for _ in range(N2):
        var start = perf_counter_ns()
        _ = client.get("http://127.0.0.1:18080/large")
        total += Int(perf_counter_ns() - start)
    report("GET /large (100KB)", total, N2)

    # GET /headers
    alias N3 = 100
    total = 0
    for _ in range(N3):
        var start = perf_counter_ns()
        _ = client.get("http://127.0.0.1:18080/headers")
        total += Int(perf_counter_ns() - start)
    report("GET /headers", total, N3)

    # GET /chunked
    alias N4 = 100
    total = 0
    for _ in range(N4):
        var start = perf_counter_ns()
        _ = client.get("http://127.0.0.1:18080/chunked")
        total += Int(perf_counter_ns() - start)
    report("GET /chunked", total, N4)

    # GET + JSON parse
    alias N5 = 100
    total = 0
    for _ in range(N5):
        var start = perf_counter_ns()
        var resp = client.get("http://127.0.0.1:18080/")
        _ = resp.json()
        total += Int(perf_counter_ns() - start)
    report("GET / + json()", total, N5)


# ============================================================================
# Main
# ============================================================================


def main() raises:
    print("=" * 60)
    print("  PERFORMANCE PROFILING — Mojo HTTP Client")
    print("=" * 60)

    bench_url_parsing()
    bench_json_parsing()
    bench_json_access()
    bench_json_stringify()
    bench_http_parsing()
    bench_chunked_decoding()
    bench_case_insensitive()
    bench_scaling()
    bench_full_pipeline_local()

    print()
    print("=" * 60)
    print("  PROFILING COMPLETE")
    print("=" * 60)
