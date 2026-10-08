# ============================================================================
# codecs.mojo — compression libraries, loaded at runtime
# ============================================================================
#
# zlib (gzip, deflate), libzstd and libbrotlidec are opened with dlopen when
# first needed instead of being linked: a program using requests builds with
# no -Xlinker flags. Only the encodings whose library loaded are advertised
# in Accept-Encoding, so a server never sends one we cannot decode.
#
#   zlib    the system library (macOS, Linux)
#   zstd    the Mojo environment ships it (the binary's rpath), or the system
#   brotli  only if installed: pixi add brotli / apt install libbrotli1 /
#           brew install brotli
# ============================================================================

from std.ffi import OwnedDLHandle
from std.sys.info import CompilationTarget


def _open_first(names: List[String], symbol: String) -> Optional[OwnedDLHandle]:
    """The first library in `names` that loads and exports `symbol`."""
    for name in names:
        try:
            var h = OwnedDLHandle(name)
            if h.check_symbol(symbol):
                return h^
        except:
            pass
    return None


def zlib_names() -> List[String]:
    comptime if CompilationTarget.is_macos():
        return ["libz.dylib", "libz.1.dylib"]
    else:
        return ["libz.so.1", "libz.so"]


def zstd_names() -> List[String]:
    comptime if CompilationTarget.is_macos():
        return [
            "libzstd.dylib", "libzstd.1.dylib",
            "/opt/homebrew/lib/libzstd.dylib", "/usr/local/lib/libzstd.dylib",
        ]
    else:
        return ["libzstd.so.1", "libzstd.so"]


def brotli_names() -> List[String]:
    comptime if CompilationTarget.is_macos():
        return [
            "libbrotlidec.dylib", "libbrotlidec.1.dylib",
            "/opt/homebrew/lib/libbrotlidec.dylib", "/usr/local/lib/libbrotlidec.dylib",
        ]
    else:
        return ["libbrotlidec.so.1", "libbrotlidec.so"]


def open_zlib() -> Optional[OwnedDLHandle]:
    return _open_first(zlib_names(), "inflate")


def open_zstd() -> Optional[OwnedDLHandle]:
    return _open_first(zstd_names(), "ZSTD_decompress")


def open_brotli() -> Optional[OwnedDLHandle]:
    return _open_first(brotli_names(), "BrotliDecoderDecompress")


def missing_library(encoding: String) -> Error:
    """The error for a response in an encoding whose library is not loaded."""
    if encoding == "br":
        return Error(
            "requests: response is brotli-encoded but libbrotlidec could not be loaded"
            + " (install it: pixi add brotli / apt install libbrotli1 / brew install brotli)"
        )
    if encoding == "zstd":
        return Error(
            "requests: response is zstd-encoded but libzstd could not be loaded"
            + " (install it: pixi add zstd / apt install libzstd1 / brew install zstd)"
        )
    return Error(
        "requests: response is " + encoding + "-encoded but zlib could not be loaded"
        + " (install it: apt install zlib1g)"
    )


def accept_encoding(has_zlib: Bool, has_brotli: Bool, has_zstd: Bool) -> String:
    """Accept-Encoding value for the decoders available (empty: none)."""
    var parts = List[String]()
    if has_zlib:
        parts.append("gzip")
        parts.append("deflate")
    if has_brotli:
        parts.append("br")
    if has_zstd:
        parts.append("zstd")
    return String(", ").join(parts)


struct Codecs(Movable):
    """The decompression libraries this process could load (each optional)."""
    var zlib: Optional[OwnedDLHandle]
    var brotli: Optional[OwnedDLHandle]
    var zstd: Optional[OwnedDLHandle]

    def __init__(out self):
        """Load every library that is available."""
        self.zlib = open_zlib()
        self.brotli = open_brotli()
        self.zstd = open_zstd()

    def __init__(out self, *, zlib: Bool, brotli: Bool, zstd: Bool):
        """Load only the selected libraries (tests: simulate a missing one)."""
        self.zlib = open_zlib() if zlib else None
        self.brotli = open_brotli() if brotli else None
        self.zstd = open_zstd() if zstd else None

    def accept_encoding(self) -> String:
        return accept_encoding(Bool(self.zlib), Bool(self.brotli), Bool(self.zstd))
