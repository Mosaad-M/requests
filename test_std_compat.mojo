# test_std_compat.mojo — requests must not break programs that use Mojo's std
#
# A Mojo program may declare each C function with one signature only. std
# declares getenv, clock_gettime, open/read/write and errno access itself.
# requests 1.2.2 declared getenv and clock_gettime with other types (and tls
# before 1.7.0 declared open/read and errno access), so any program combining
# HttpClient with std.os.getenv, open(), listdir() or the time functions
# failed to compile ("existing function with conflicting signature").
#
# Compiling this file is the test: it reaches HttpClient's request, proxy,
# cookie, pool and multipart paths together with those std APIs. Running it
# exercises the std calls only.

from std.collections import Dict
from std.ffi import get_errno
from std.os import getenv, listdir
from std.sys import argv
from std.time import monotonic, perf_counter_ns
from http_client import HttpClient

comptime PATH = "/tmp/mojo_requests_std_compat.txt"


def network_paths() raises:
    """Never run: compiled so that HttpClient's C declarations are present."""
    var c = HttpClient()
    _ = c.get("https://example.com/")
    var fields = Dict[String, String]()
    fields["a"] = "b"
    _ = c.post_multipart("https://example.com/upload", fields)


def main() raises:
    print("test_std_compat")
    if len(argv()) > 1000:
        network_paths()
    with open(PATH, "w") as f:
        f.write("std open() next to requests\n")
    with open(PATH, "r") as f:
        if not f.read().startswith("std open()"):
            raise Error("std open()/read() round trip failed")
    _ = listdir("/tmp")
    _ = getenv("HTTPS_PROXY")
    _ = get_errno()
    _ = perf_counter_ns() + monotonic()
    print("  PASS: HttpClient compiles next to std open/listdir/getenv/get_errno/clocks")
    print("Results: 1 passed, 0 failed")
