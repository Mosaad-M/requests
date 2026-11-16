from std.sys import argv
from http_client import (
    _frame_from_headers, _parse_response, _decode_chunked,
    _buf_chunked_complete, _buf_find_crlf_crlf,
)
from http_client import HttpClient
from hpack import hpack_decode_block, HpackDynTable
from h2 import (
    h2_frame_decode, h2_read_frames, h2_parse_ping_payload, h2_parse_rst_stream,
    h2_parse_window_update, h2_parse_goaway, h2_parse_priority_frame,
)

struct Rng(Movable):
    var s: UInt64
    def __init__(out self, seed: UInt64):
        self.s = seed if seed != 0 else UInt64(88172645463325252)
    def next(mut self) -> Int:
        self.s ^= self.s << 13
        self.s ^= self.s >> 7
        self.s ^= self.s << 17
        return Int(self.s >> 1)

def to_list(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^

def mutate(seed: List[UInt8], mut r: Rng) -> List[UInt8]:
    var out = seed.copy()
    var n = 1 + r.next() % 4
    for _ in range(n):
        if len(out) == 0:
            out.append(UInt8(r.next() % 128))
            continue
        var pos = r.next() % len(out)
        var op = r.next() % 7
        if op == 0:
            out[pos] = UInt8(r.next() % 128)
        elif op == 1:
            out[pos] = (out[pos] ^ UInt8(1 << (r.next() % 7))) & 127
        elif op == 2:
            out.insert(pos, UInt8(r.next() % 128))
        elif op == 3:
            var k = 1 + r.next() % 8
            var e = min(len(out), pos + k)
            var tmp = List[UInt8]()
            for i in range(len(out)):
                if i < pos or i >= e:
                    tmp.append(out[i])
            out = tmp^
        elif op == 4:
            out.resize(pos, 0)
        elif op == 5:
            var k = 1 + r.next() % 16
            var e = min(len(out), pos + k)
            var chunk = List[UInt8]()
            for i in range(pos, e):
                chunk.append(out[i])
            var at = r.next() % (len(out) + 1)
            for i in range(len(chunk)):
                out.insert(at + i, chunk[i])
        else:
            # interesting bytes: digits, separators, whitespace, high bytes
            var pick = r.next() % 8
            var vals = List[UInt8]()
            vals.append(13); vals.append(10); vals.append(58); vals.append(32)
            vals.append(44); vals.append(48); vals.append(127); vals.append(0)
            out[pos] = vals[pick]
    return out^

def http1_round(b: List[UInt8], mut stats: List[Int], sub: String):
    var he = _buf_find_crlf_crlf(b)
    if he >= 0:
        if sub == "all" or sub == "frame":
          try:
            _ = _frame_from_headers(b, he)
            stats[0] += 1
          except:
            stats[1] += 1
          try:
            var scan = he + 4
            _ = _buf_chunked_complete(b, scan)
          except:
            pass
        if sub == "all" or sub == "decode":
          try:
            var body = List[UInt8]()
            for i in range(he + 4, len(b)):
                body.append(b[i])
            _ = _decode_chunked(String(unsafe_from_utf8=body))
            stats[2] += 1
          except:
            stats[3] += 1
    if sub == "all" or sub == "parse":
      try:
        _ = _parse_response(String(unsafe_from_utf8=b), "http://x/")
        stats[4] += 1
      except:
        stats[5] += 1

def cookie_round(b: List[UInt8], mut client: HttpClient, mut stats: List[Int]):
    var sc = String(unsafe_from_utf8=b)
    var hosts = List[String]()
    hosts.append("example.com"); hosts.append("a.b.example.co.uk"); hosts.append("localhost"); hosts.append("co.uk"); hosts.append("127.0.0.1")
    client._jar_store(hosts[len(b) % 5], "/a/b", len(b) % 2 == 0, sc)
    _ = client._jar_cookie_for(hosts[(len(b) + 1) % 5], "/a/b/c", True)
    stats[12] += 1

def hpack_round(b: List[UInt8], mut stats: List[Int]):
    var dt = HpackDynTable()
    try:
        _ = hpack_decode_block(b, dt, 1 << 20)
        stats[6] += 1
    except:
        stats[7] += 1

def h2_round(b: List[UInt8], mut stats: List[Int]):
    try:
        var f = h2_frame_decode(b, 0)
        stats[8] += 1
        try:
            _ = h2_parse_ping_payload(f[0])
        except:
            pass
        try:
            _ = h2_parse_rst_stream(f[0])
        except:
            pass
        try:
            _ = h2_parse_window_update(f[0])
        except:
            pass
        try:
            _ = h2_parse_goaway(f[0])
        except:
            pass
        try:
            _ = h2_parse_priority_frame(f[0])
        except:
            pass
    except:
        stats[9] += 1
    try:
        _ = h2_read_frames(b)
        stats[10] += 1
    except:
        stats[11] += 1

def main() raises:
    var iters = Int(atol(String(argv()[1])))
    var seed = UInt64(atol(String(argv()[2])))
    var mode = String(argv()[3])
    var sub = String(argv()[4])
    var r = Rng(seed)
    var h1 = List[List[UInt8]]()
    h1.append(to_list("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhello"))
    h1.append(to_list("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"))
    h1.append(to_list("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=b; Path=/; Secure\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n"))
    h1.append(to_list("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello"))
    h1.append(to_list("HTTP/1.1 301 Moved\r\nLocation: http://a/b\r\nContent-Length : 0\r\n X: y\r\n\r\n"))
    h1.append(to_list("HTTP/1.1 204 No Content\r\n\r\n"))
    h1.append(to_list("HTTP/1.0 200\r\nContent-Length: 99999999999999999999\r\n\r\n"))
    var hp = List[List[UInt8]]()
    var a = List[UInt8]()
    a.append(0x82); a.append(0x86); a.append(0x84); a.append(0x41); a.append(0x8c)
    for v in [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]:
        a.append(UInt8(v))
    hp.append(a^)
    var b = List[UInt8]()
    b.append(0x40); b.append(0x03); b.append(0x61); b.append(0x62); b.append(0x63)
    b.append(0x03); b.append(0x78); b.append(0x79); b.append(0x7a); b.append(0x3f); b.append(0xe1); b.append(0x1f)
    hp.append(b^)
    var h2s = List[List[UInt8]]()
    var f = List[UInt8]()
    for v in [0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]:
        f.append(UInt8(v))
    h2s.append(f^)
    var g = List[UInt8]()
    for v in [0, 0, 10, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 1, 2]:
        g.append(UInt8(v))
    h2s.append(g^)
    var stats = List[Int]()
    for _ in range(14):
        stats.append(0)
    var cl = HttpClient(allow_private_ips=True)
    var ck = List[List[UInt8]]()
    ck.append(to_list("sid=abc123; Path=/; Domain=.example.com; Secure; HttpOnly; Max-Age=3600; SameSite=Lax"))
    ck.append(to_list("a=b; Domain=co.uk; Path=/x; Expires=Wed, 21 Oct 2026 07:28:00 GMT"))
    ck.append(to_list("=; ; ;;; Max-Age=-1; Domain=; Path="))
    ck.append(to_list("k=v; Domain=localhost; Max-Age=99999999999999999999"))
    for i in range(iters):
        if i % 100000 == 0:
            print("iter " + String(i))
        var k = r.next() % 3
        if mode == "h1":
            k = 0
        elif mode == "hpack":
            k = 1
        elif mode == "h2":
            k = 2
        elif mode == "cookie":
            k = 3
        if k == 3:
            cookie_round(mutate(ck[r.next() % len(ck)], r), cl, stats)
        elif k == 0:
            http1_round(mutate(h1[r.next() % len(h1)], r), stats, sub)
        elif k == 1:
            hpack_round(mutate(hp[r.next() % len(hp)], r), stats)
        else:
            h2_round(mutate(h2s[r.next() % len(h2s)], r), stats)
    print("DONE iters=" + String(iters) + " frame ok/err=" + String(stats[0]) + "/" + String(stats[1]) + " chunk-decode ok/err=" + String(stats[2]) + "/" + String(stats[3]) + " parse_response ok/err=" + String(stats[4]) + "/" + String(stats[5]) + " hpack ok/err=" + String(stats[6]) + "/" + String(stats[7]) + " h2frame ok/err=" + String(stats[8]) + "/" + String(stats[9]) + " cookie=" + String(stats[12]) + " h2read ok/err=" + String(stats[10]) + "/" + String(stats[11]))
