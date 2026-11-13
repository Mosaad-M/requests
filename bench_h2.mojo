# ============================================================================
# bench_h2.mojo — HTTP/2 and pooling benchmarks against the local test servers
# ============================================================================
#
# Needs test_h2_server.py (HTTP/2, TLS) and test_server.py (HTTP/1.1) running:
#   python test_h2_server.py & python test_server.py &
#   bash build_and_run.sh bench_h2.mojo
#
# Loopback has ~0 network latency, so multiplexing shows up mainly through the
# server-side delay (?ms=) that stands in for a slow upstream. Real networks add
# a round trip per sequential request, which only widens the gap.
# ============================================================================

from std.time import perf_counter_ns
from crypto.cert import X509Cert, cert_parse
from crypto.pem import pem_decode
from http_client import HttpClient

comptime H2 = "https://localhost:18443"
comptime H1 = "http://127.0.0.1:18080"


def ca() raises -> List[X509Cert]:
    var pem = String("")
    with open("certs/ca.pem", "r") as f:
        pem = f.read()
    var out = List[X509Cert]()
    var ders = pem_decode(pem, "CERTIFICATE")
    for i in range(len(ders)):
        out.append(cert_parse(ders[i]))
    return out^


def client() raises -> HttpClient:
    var c = HttpClient(allow_private_ips=True)
    c._ca_bundle = ca()
    c._ca_loaded = True
    return c^


def ms(ns: Int) -> String:
    return String(Float64(ns) / 1_000_000.0)


def row(label: String, total_ns: Int, n: Int):
    print("  " + label + ": " + ms(total_ns) + " ms total, " + ms(total_ns // n) + " ms/request (n=" + String(n) + ")")


def urls(path: String, n: Int) -> List[String]:
    var out = List[String]()
    for i in range(n):
        out.append(H2 + path.replace("{i}", String(i)))
    return out^


def main() raises:
    print("=== HTTP/2 + pooling (localhost) ===")
    try:
        var probe = client()
        _ = probe.get(H2 + "/n/0")
    except e:
        print("  SKIP: h2 test server not running:", String(e))
        return

    # Connection setup cost: a new client per request pays TCP + TLS + h2 SETTINGS each time.
    var n = 20
    var t0 = Int(perf_counter_ns())
    for i in range(n):
        var c = client()
        _ = c.get(H2 + "/n/" + String(i))
    row("new client per request (TCP+TLS+h2 handshake)", Int(perf_counter_ns()) - t0, n)

    n = 100
    var pooled = client()
    _ = pooled.get(H2 + "/n/0")
    t0 = Int(perf_counter_ns())
    for i in range(n):
        _ = pooled.get(H2 + "/n/" + String(i))
    row("pooled client, sequential, no server delay", Int(perf_counter_ns()) - t0, n)

    # Server holds each response for 20 ms: sequential pays it N times.
    n = 20
    t0 = Int(perf_counter_ns())
    for i in range(n):
        _ = pooled.get(H2 + "/n/" + String(i) + "?ms=20")
    row("pooled client, sequential, 20 ms server delay", Int(perf_counter_ns()) - t0, n)

    # MANY-BEGIN
    var batch = pooled.get_many(urls("/n/{i}", 100))
    _ = batch^
    t0 = Int(perf_counter_ns())
    batch = pooled.get_many(urls("/n/{i}", 100))
    row("get_many, no server delay", Int(perf_counter_ns()) - t0, 100)
    t0 = Int(perf_counter_ns())
    batch = pooled.get_many(urls("/n/{i}?ms=20", 20))
    row("get_many, 20 ms server delay", Int(perf_counter_ns()) - t0, 20)
    # MANY-END

    # Bulk transfer: 4 MB over h2 and over plain HTTP/1.1.
    n = 5
    t0 = Int(perf_counter_ns())
    for _ in range(n):
        _ = pooled.get(H2 + "/large?kb=4096")
    var dt = Int(perf_counter_ns()) - t0
    print("  4 MB download over h2: " + ms(dt // n) + " ms each, " + String(Int(Float64(4 * n) * 1_000_000_000.0 / Float64(dt))) + " MB/s")
    var h1 = HttpClient(allow_private_ips=True)
    try:
        _ = h1.get(H1 + "/large")
        t0 = Int(perf_counter_ns())
        for _ in range(n):
            _ = h1.get(H1 + "/large")
        dt = Int(perf_counter_ns()) - t0
        print("  /large over HTTP/1.1 (plain): " + ms(dt // n) + " ms each")
    except:
        print("  SKIP: HTTP/1.1 server not running")
