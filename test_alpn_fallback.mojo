# One connection per request to an HTTPS server that answers no ALPN
# protocol: HTTP/1.1 on that connection, not an HTTP/2 probe and a second
# handshake, on TLS 1.3 and TLS 1.2. Needs alpn_test_server.py on 127.0.0.1:18443 and :18447 with the cert from
# `pixi run test-alpn` (see pixi.toml).

from http_client import HttpClient
from crypto.cert import cert_parse
from crypto.pem import pem_decode
from std.os import getenv


def main() raises:
    var pem: String
    with open(getenv("ALPN_TEST_CA", ".build/alpn/cert.pem"), "r") as f:
        pem = f.read()
    # 18443: TLS 1.3 server, 18447: TLS 1.2 only (the case tls < 1.11 could not report)
    for port in ["18443", "18447"]:
        var client = HttpClient(allow_private_ips=True)
        var ders = pem_decode(pem, "CERTIFICATE")
        for i in range(len(ders)):
            client._ca_bundle.append(cert_parse(ders[i]))
        client._ca_loaded = True
        var base = "https://127.0.0.1:" + port
        for _ in range(3):
            var resp = client.get(base + "/")
            if resp.status_code != 200 or resp.body != "ok":
                raise Error(port + ": unexpected response " + String(resp.status_code))
        # Counted by the server: a probe would show up as a second connection.
        var seen = client.get(base + "/connections").body
        if seen != "1":
            raise Error(port + ": expected 1 connection for 4 requests, server saw " + seen)
    print("test_alpn_fallback: PASS (TLS 1.3 and TLS 1.2: 4 requests, 1 connection each)")
