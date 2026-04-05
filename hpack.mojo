# ============================================================================
# hpack.mojo — HPACK Header Compression (RFC 7541)
# ============================================================================
# Implements the full HPACK codec required for HTTP/2:
#   - Integer encoding/decoding (§5.1)
#   - String encoding/decoding — literal and Huffman (§5.2)
#   - Static table — 61 entries (Appendix A)
#   - Dynamic table — FIFO with byte-count eviction (§4)
#   - Header block decode (§6) — all 5 representation types
#   - Header block encode (§6)
# ============================================================================


# ── 15B-1: Integer Codec (RFC 7541 §5.1) ───────────────────────────────────

fn hpack_encode_int(value: Int, prefix_bits: Int) -> List[UInt8]:
    """Encode an HPACK integer with the given prefix bit width.

    Returns only the value bytes. The caller is responsible for ORing any
    opcode bits into the first byte before appending to the output stream.

    Args:
        value:       Non-negative integer to encode.
        prefix_bits: Number of prefix bits (1–8).

    Returns:
        Encoded bytes (1 or more).
    """
    var out = List[UInt8](capacity=4)
    var max_first = (1 << prefix_bits) - 1
    if value < max_first:
        out.append(UInt8(value))
        return out^
    # Overflow: emit sentinel, then 7-bit continuation bytes
    out.append(UInt8(max_first))
    var remaining = value - max_first
    while remaining >= 128:
        out.append(UInt8((remaining & 0x7F) | 0x80))
        remaining >>= 7
    out.append(UInt8(remaining))
    return out^


fn _append_bytes(mut out: List[UInt8], src: List[UInt8]):
    for i in range(len(src)):
        out.append(src[i])


fn hpack_decode_int(data: List[UInt8], off: Int, prefix_bits: Int) -> Tuple[Int, Int]:
    """Decode an HPACK integer starting at data[off].

    The caller must have already consumed any opcode bits in the first byte
    before calling (i.e., data[off] should be masked to prefix_bits bits).

    Args:
        data:        Input byte buffer.
        off:         Starting offset within data.
        prefix_bits: Number of prefix bits (1–8).

    Returns:
        (decoded_value, new_offset_after_consumed_bytes)
    """
    var mask = (1 << prefix_bits) - 1
    var first = Int(data[off]) & mask
    var pos = off + 1
    var max_first = mask
    if first < max_first:
        return (first, pos)
    # Continuation bytes (7-bit little-endian)
    var value = first
    var shift = 0
    while pos < len(data):
        var b = Int(data[pos])
        pos += 1
        value += (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    return (value, pos)


# ── 15B-2: String Codec — literal (RFC 7541 §5.2) ──────────────────────────

fn hpack_encode_str_literal(s: String) -> List[UInt8]:
    """Encode a string as an HPACK literal string (H=0, no Huffman).

    Format: [ H=0 | length (7-bit prefix integer) ] [ raw UTF-8 bytes ]
    """
    var raw = s.as_bytes()
    var n = len(raw)
    var len_bytes = hpack_encode_int(n, 7)
    # H bit is 0 — first byte of len_bytes already has bit 7 clear
    var out = List[UInt8](capacity=1 + n)
    _append_bytes(out, len_bytes)
    for i in range(n):
        out.append(raw[i])
    return out^


fn hpack_decode_str(data: List[UInt8], off: Int) raises -> Tuple[String, Int]:
    """Decode an HPACK string starting at data[off].

    Reads the H flag and length, then decodes the string bytes.
    If H=1 (Huffman), raises Error("huffman not implemented") until 15B-3.

    Returns:
        (decoded_string, new_offset)
    """
    var huffman = (Int(data[off]) & 0x80) != 0
    # Decode length as 7-bit prefix integer (H bit is not part of the value)
    var len_res = hpack_decode_int(data, off, 7)
    var str_len = len_res[0]
    var str_off = len_res[1]
    if huffman:
        var huff_data = List[UInt8](capacity=str_len)
        for i in range(str_len):
            huff_data.append(data[str_off + i])
        var decoded = huffman_decode(huff_data)
        return (decoded^, str_off + str_len)
    # Literal: copy raw bytes
    var bytes = List[UInt8](capacity=str_len + 1)
    for i in range(str_len):
        bytes.append(data[str_off + i])
    var result = String(unsafe_from_utf8=bytes^)
    return (result^, str_off + str_len)


# ── 15B-3: Huffman Codec (RFC 7541 Appendix B) ──────────────────────────────

fn _huff_tables() -> Tuple[List[UInt32], List[UInt8]]:
    """Return (codes, lengths) for RFC 7541 Huffman symbols 0-256 (EOS=256).

    Using var lists because comptime arrays cannot be subscripted at runtime.
    """
    var codes = List[UInt32](capacity=257)
    var lens  = List[UInt8](capacity=257)
    # ── symbols 0-31 (control chars) ────────────────────────────────────────
    codes.append(UInt32(0x1ff8));    lens.append(UInt8(13))   # 0
    codes.append(UInt32(0x7fffd8));  lens.append(UInt8(23))   # 1
    codes.append(UInt32(0xfffffe2)); lens.append(UInt8(28))   # 2
    codes.append(UInt32(0xfffffe3)); lens.append(UInt8(28))   # 3
    codes.append(UInt32(0xfffffe4)); lens.append(UInt8(28))   # 4
    codes.append(UInt32(0xfffffe5)); lens.append(UInt8(28))   # 5
    codes.append(UInt32(0xfffffe6)); lens.append(UInt8(28))   # 6
    codes.append(UInt32(0xfffffe7)); lens.append(UInt8(28))   # 7
    codes.append(UInt32(0xfffffe8)); lens.append(UInt8(28))   # 8
    codes.append(UInt32(0xffffea));  lens.append(UInt8(24))   # 9
    codes.append(UInt32(0x3ffffffc));lens.append(UInt8(30))   # 10
    codes.append(UInt32(0xfffffe9)); lens.append(UInt8(28))   # 11
    codes.append(UInt32(0xfffffea)); lens.append(UInt8(28))   # 12
    codes.append(UInt32(0x3ffffffd));lens.append(UInt8(30))   # 13
    codes.append(UInt32(0xfffffeb)); lens.append(UInt8(28))   # 14
    codes.append(UInt32(0xfffffec)); lens.append(UInt8(28))   # 15
    codes.append(UInt32(0xfffffed)); lens.append(UInt8(28))   # 16
    codes.append(UInt32(0xfffffee)); lens.append(UInt8(28))   # 17
    codes.append(UInt32(0xfffffef)); lens.append(UInt8(28))   # 18
    codes.append(UInt32(0xffffff0)); lens.append(UInt8(28))   # 19
    codes.append(UInt32(0xffffff1)); lens.append(UInt8(28))   # 20
    codes.append(UInt32(0xffffff2)); lens.append(UInt8(28))   # 21
    codes.append(UInt32(0x3ffffffe));lens.append(UInt8(30))   # 22
    codes.append(UInt32(0xffffff3)); lens.append(UInt8(28))   # 23
    codes.append(UInt32(0xffffff4)); lens.append(UInt8(28))   # 24
    codes.append(UInt32(0xffffff5)); lens.append(UInt8(28))   # 25
    codes.append(UInt32(0xffffff6)); lens.append(UInt8(28))   # 26
    codes.append(UInt32(0xffffff7)); lens.append(UInt8(28))   # 27
    codes.append(UInt32(0xffffff8)); lens.append(UInt8(28))   # 28
    codes.append(UInt32(0xffffff9)); lens.append(UInt8(28))   # 29
    codes.append(UInt32(0xffffffa)); lens.append(UInt8(28))   # 30
    codes.append(UInt32(0xffffffb)); lens.append(UInt8(28))   # 31
    # ── symbols 32-47 (punctuation/digits) ──────────────────────────────────
    codes.append(UInt32(0x14));     lens.append(UInt8(6))    # 32 ' '
    codes.append(UInt32(0x3f8));    lens.append(UInt8(10))   # 33 !
    codes.append(UInt32(0x3f9));    lens.append(UInt8(10))   # 34 "
    codes.append(UInt32(0xffa));    lens.append(UInt8(12))   # 35 #
    codes.append(UInt32(0x1ff9));   lens.append(UInt8(13))   # 36 $
    codes.append(UInt32(0x15));     lens.append(UInt8(6))    # 37 %
    codes.append(UInt32(0xf8));     lens.append(UInt8(8))    # 38 &
    codes.append(UInt32(0x7fa));    lens.append(UInt8(11))   # 39 '
    codes.append(UInt32(0x3fa));    lens.append(UInt8(10))   # 40 (
    codes.append(UInt32(0x3fb));    lens.append(UInt8(10))   # 41 )
    codes.append(UInt32(0xf9));     lens.append(UInt8(8))    # 42 *
    codes.append(UInt32(0x7fb));    lens.append(UInt8(11))   # 43 +
    codes.append(UInt32(0xfa));     lens.append(UInt8(8))    # 44 ,
    codes.append(UInt32(0x16));     lens.append(UInt8(6))    # 45 -
    codes.append(UInt32(0x17));     lens.append(UInt8(6))    # 46 .
    codes.append(UInt32(0x18));     lens.append(UInt8(6))    # 47 /
    # ── symbols 48-57 (digits 0-9) ──────────────────────────────────────────
    codes.append(UInt32(0x0));      lens.append(UInt8(5))    # 48 0
    codes.append(UInt32(0x1));      lens.append(UInt8(5))    # 49 1
    codes.append(UInt32(0x2));      lens.append(UInt8(5))    # 50 2
    codes.append(UInt32(0x19));     lens.append(UInt8(6))    # 51 3
    codes.append(UInt32(0x1a));     lens.append(UInt8(6))    # 52 4
    codes.append(UInt32(0x1b));     lens.append(UInt8(6))    # 53 5
    codes.append(UInt32(0x1c));     lens.append(UInt8(6))    # 54 6
    codes.append(UInt32(0x1d));     lens.append(UInt8(6))    # 55 7
    codes.append(UInt32(0x1e));     lens.append(UInt8(6))    # 56 8
    codes.append(UInt32(0x1f));     lens.append(UInt8(6))    # 57 9
    # ── symbols 58-90 ───────────────────────────────────────────────────────
    codes.append(UInt32(0x5c));     lens.append(UInt8(7))    # 58 :
    codes.append(UInt32(0xfb));     lens.append(UInt8(8))    # 59 ;
    codes.append(UInt32(0x7ffc));   lens.append(UInt8(15))   # 60 <
    codes.append(UInt32(0x20));     lens.append(UInt8(6))    # 61 =
    codes.append(UInt32(0xffb));    lens.append(UInt8(12))   # 62 >
    codes.append(UInt32(0x3fc));    lens.append(UInt8(10))   # 63 ?
    codes.append(UInt32(0x1ffa));   lens.append(UInt8(13))   # 64 @
    codes.append(UInt32(0x21));     lens.append(UInt8(6))    # 65 A
    codes.append(UInt32(0x5d));     lens.append(UInt8(7))    # 66 B
    codes.append(UInt32(0x5e));     lens.append(UInt8(7))    # 67 C
    codes.append(UInt32(0x5f));     lens.append(UInt8(7))    # 68 D
    codes.append(UInt32(0x60));     lens.append(UInt8(7))    # 69 E
    codes.append(UInt32(0x61));     lens.append(UInt8(7))    # 70 F
    codes.append(UInt32(0x62));     lens.append(UInt8(7))    # 71 G
    codes.append(UInt32(0x63));     lens.append(UInt8(7))    # 72 H
    codes.append(UInt32(0x64));     lens.append(UInt8(7))    # 73 I
    codes.append(UInt32(0x65));     lens.append(UInt8(7))    # 74 J
    codes.append(UInt32(0x66));     lens.append(UInt8(7))    # 75 K
    codes.append(UInt32(0x67));     lens.append(UInt8(7))    # 76 L
    codes.append(UInt32(0x68));     lens.append(UInt8(7))    # 77 M
    codes.append(UInt32(0x69));     lens.append(UInt8(7))    # 78 N
    codes.append(UInt32(0x6a));     lens.append(UInt8(7))    # 79 O
    codes.append(UInt32(0x6b));     lens.append(UInt8(7))    # 80 P
    codes.append(UInt32(0x6c));     lens.append(UInt8(7))    # 81 Q
    codes.append(UInt32(0x6d));     lens.append(UInt8(7))    # 82 R
    codes.append(UInt32(0x6e));     lens.append(UInt8(7))    # 83 S
    codes.append(UInt32(0x6f));     lens.append(UInt8(7))    # 84 T
    codes.append(UInt32(0x70));     lens.append(UInt8(7))    # 85 U
    codes.append(UInt32(0x71));     lens.append(UInt8(7))    # 86 V
    codes.append(UInt32(0x72));     lens.append(UInt8(7))    # 87 W
    codes.append(UInt32(0xfc));     lens.append(UInt8(8))    # 88 X
    codes.append(UInt32(0x73));     lens.append(UInt8(7))    # 89 Y
    codes.append(UInt32(0xfd));     lens.append(UInt8(8))    # 90 Z
    # ── symbols 91-96 ───────────────────────────────────────────────────────
    codes.append(UInt32(0x1ffb));   lens.append(UInt8(13))   # 91 [
    codes.append(UInt32(0x7fff0));  lens.append(UInt8(19))   # 92 backslash
    codes.append(UInt32(0x1ffc));   lens.append(UInt8(13))   # 93 ]
    codes.append(UInt32(0x3ffc));   lens.append(UInt8(14))   # 94 ^
    codes.append(UInt32(0x22));     lens.append(UInt8(6))    # 95 _
    codes.append(UInt32(0x7ffd));   lens.append(UInt8(15))   # 96 `
    # ── symbols 97-122 (lowercase a-z) ──────────────────────────────────────
    codes.append(UInt32(0x3));      lens.append(UInt8(5))    # 97  a
    codes.append(UInt32(0x23));     lens.append(UInt8(6))    # 98  b
    codes.append(UInt32(0x4));      lens.append(UInt8(5))    # 99  c
    codes.append(UInt32(0x24));     lens.append(UInt8(6))    # 100 d
    codes.append(UInt32(0x5));      lens.append(UInt8(5))    # 101 e
    codes.append(UInt32(0x25));     lens.append(UInt8(6))    # 102 f
    codes.append(UInt32(0x26));     lens.append(UInt8(6))    # 103 g
    codes.append(UInt32(0x27));     lens.append(UInt8(6))    # 104 h
    codes.append(UInt32(0x6));      lens.append(UInt8(5))    # 105 i
    codes.append(UInt32(0x74));     lens.append(UInt8(7))    # 106 j
    codes.append(UInt32(0x75));     lens.append(UInt8(7))    # 107 k
    codes.append(UInt32(0x28));     lens.append(UInt8(6))    # 108 l
    codes.append(UInt32(0x29));     lens.append(UInt8(6))    # 109 m
    codes.append(UInt32(0x2a));     lens.append(UInt8(6))    # 110 n
    codes.append(UInt32(0x7));      lens.append(UInt8(5))    # 111 o
    codes.append(UInt32(0x2b));     lens.append(UInt8(6))    # 112 p
    codes.append(UInt32(0x76));     lens.append(UInt8(7))    # 113 q
    codes.append(UInt32(0x2c));     lens.append(UInt8(6))    # 114 r
    codes.append(UInt32(0x8));      lens.append(UInt8(5))    # 115 s
    codes.append(UInt32(0x9));      lens.append(UInt8(5))    # 116 t
    codes.append(UInt32(0x2d));     lens.append(UInt8(6))    # 117 u
    codes.append(UInt32(0x77));     lens.append(UInt8(7))    # 118 v
    codes.append(UInt32(0x78));     lens.append(UInt8(7))    # 119 w
    codes.append(UInt32(0x79));     lens.append(UInt8(7))    # 120 x
    codes.append(UInt32(0x7a));     lens.append(UInt8(7))    # 121 y
    codes.append(UInt32(0x7b));     lens.append(UInt8(7))    # 122 z
    # ── symbols 123-127 ─────────────────────────────────────────────────────
    codes.append(UInt32(0x7ffe));   lens.append(UInt8(15))   # 123 {
    codes.append(UInt32(0x7fc));    lens.append(UInt8(11))   # 124 |
    codes.append(UInt32(0x3ffd));   lens.append(UInt8(14))   # 125 }
    codes.append(UInt32(0x1ffd));   lens.append(UInt8(13))   # 126 ~
    codes.append(UInt32(0x0ffffffc));lens.append(UInt8(28))  # 127 DEL
    # ── symbols 128-191 ─────────────────────────────────────────────────────
    codes.append(UInt32(0xfffe6));  lens.append(UInt8(20))   # 128
    codes.append(UInt32(0x3fffd2)); lens.append(UInt8(22))   # 129
    codes.append(UInt32(0xfffe7));  lens.append(UInt8(20))   # 130
    codes.append(UInt32(0xfffe8));  lens.append(UInt8(20))   # 131
    codes.append(UInt32(0x3fffd3)); lens.append(UInt8(22))   # 132
    codes.append(UInt32(0x3fffd4)); lens.append(UInt8(22))   # 133
    codes.append(UInt32(0x3fffd5)); lens.append(UInt8(22))   # 134
    codes.append(UInt32(0x7fffd9)); lens.append(UInt8(23))   # 135
    codes.append(UInt32(0x3fffd6)); lens.append(UInt8(22))   # 136
    codes.append(UInt32(0x7fffda)); lens.append(UInt8(23))   # 137
    codes.append(UInt32(0x7fffdb)); lens.append(UInt8(23))   # 138
    codes.append(UInt32(0x7fffdc)); lens.append(UInt8(23))   # 139
    codes.append(UInt32(0x7fffdd)); lens.append(UInt8(23))   # 140
    codes.append(UInt32(0x7fffde)); lens.append(UInt8(23))   # 141
    codes.append(UInt32(0xffffeb)); lens.append(UInt8(24))   # 142
    codes.append(UInt32(0x7fffdf)); lens.append(UInt8(23))   # 143
    codes.append(UInt32(0xffffec)); lens.append(UInt8(24))   # 144
    codes.append(UInt32(0xffffed)); lens.append(UInt8(24))   # 145
    codes.append(UInt32(0x3fffd7)); lens.append(UInt8(22))   # 146
    codes.append(UInt32(0x7fffe0)); lens.append(UInt8(23))   # 147
    codes.append(UInt32(0xffffee)); lens.append(UInt8(24))   # 148
    codes.append(UInt32(0x7fffe1)); lens.append(UInt8(23))   # 149
    codes.append(UInt32(0x7fffe2)); lens.append(UInt8(23))   # 150
    codes.append(UInt32(0x7fffe3)); lens.append(UInt8(23))   # 151
    codes.append(UInt32(0x7fffe4)); lens.append(UInt8(23))   # 152
    codes.append(UInt32(0x1fffdc)); lens.append(UInt8(21))   # 153
    codes.append(UInt32(0x3fffd8)); lens.append(UInt8(22))   # 154
    codes.append(UInt32(0x7fffe5)); lens.append(UInt8(23))   # 155
    codes.append(UInt32(0x3fffd9)); lens.append(UInt8(22))   # 156
    codes.append(UInt32(0x7fffe6)); lens.append(UInt8(23))   # 157
    codes.append(UInt32(0x7fffe7)); lens.append(UInt8(23))   # 158
    codes.append(UInt32(0xffffef)); lens.append(UInt8(24))   # 159
    codes.append(UInt32(0x3fffda)); lens.append(UInt8(22))   # 160
    codes.append(UInt32(0x1fffdd)); lens.append(UInt8(21))   # 161
    codes.append(UInt32(0xfffe9));  lens.append(UInt8(20))   # 162
    codes.append(UInt32(0x3fffdb)); lens.append(UInt8(22))   # 163
    codes.append(UInt32(0x3fffdc)); lens.append(UInt8(22))   # 164
    codes.append(UInt32(0x7fffe8)); lens.append(UInt8(23))   # 165
    codes.append(UInt32(0x7fffe9)); lens.append(UInt8(23))   # 166
    codes.append(UInt32(0x1fffde)); lens.append(UInt8(21))   # 167
    codes.append(UInt32(0x7fffea)); lens.append(UInt8(23))   # 168
    codes.append(UInt32(0x3fffdd)); lens.append(UInt8(22))   # 169
    codes.append(UInt32(0x3fffde)); lens.append(UInt8(22))   # 170
    codes.append(UInt32(0xfffff0)); lens.append(UInt8(24))   # 171
    codes.append(UInt32(0x1fffdf)); lens.append(UInt8(21))   # 172
    codes.append(UInt32(0x3fffdf)); lens.append(UInt8(22))   # 173
    codes.append(UInt32(0x7fffeb)); lens.append(UInt8(23))   # 174
    codes.append(UInt32(0x7fffec)); lens.append(UInt8(23))   # 175
    codes.append(UInt32(0x1fffe0)); lens.append(UInt8(21))   # 176
    codes.append(UInt32(0x1fffe1)); lens.append(UInt8(21))   # 177
    codes.append(UInt32(0x3fffe0)); lens.append(UInt8(22))   # 178
    codes.append(UInt32(0x1fffe2)); lens.append(UInt8(21))   # 179
    codes.append(UInt32(0x7fffed)); lens.append(UInt8(23))   # 180
    codes.append(UInt32(0x3fffe1)); lens.append(UInt8(22))   # 181
    codes.append(UInt32(0x7fffee)); lens.append(UInt8(23))   # 182
    codes.append(UInt32(0x7fffef)); lens.append(UInt8(23))   # 183
    codes.append(UInt32(0xfffea));  lens.append(UInt8(20))   # 184
    codes.append(UInt32(0x3fffe2)); lens.append(UInt8(22))   # 185
    codes.append(UInt32(0x3fffe3)); lens.append(UInt8(22))   # 186
    codes.append(UInt32(0x3fffe4)); lens.append(UInt8(22))   # 187
    codes.append(UInt32(0x7ffff0)); lens.append(UInt8(23))   # 188
    codes.append(UInt32(0x3fffe5)); lens.append(UInt8(22))   # 189
    codes.append(UInt32(0x3fffe6)); lens.append(UInt8(22))   # 190
    codes.append(UInt32(0x7ffff1)); lens.append(UInt8(23))   # 191
    # ── symbols 192-255 ─────────────────────────────────────────────────────
    codes.append(UInt32(0x3ffffe0));lens.append(UInt8(26))   # 192
    codes.append(UInt32(0x3ffffe1));lens.append(UInt8(26))   # 193
    codes.append(UInt32(0xfffeb));  lens.append(UInt8(20))   # 194
    codes.append(UInt32(0x7fff1));  lens.append(UInt8(19))   # 195
    codes.append(UInt32(0x3fffe7)); lens.append(UInt8(22))   # 196
    codes.append(UInt32(0x7ffff2)); lens.append(UInt8(23))   # 197
    codes.append(UInt32(0x3fffe8)); lens.append(UInt8(22))   # 198
    codes.append(UInt32(0x1ffffec));lens.append(UInt8(25))   # 199
    codes.append(UInt32(0x3ffffe2));lens.append(UInt8(26))   # 200
    codes.append(UInt32(0x3ffffe3));lens.append(UInt8(26))   # 201
    codes.append(UInt32(0x3ffffe4));lens.append(UInt8(26))   # 202
    codes.append(UInt32(0x7ffffde));lens.append(UInt8(27))   # 203
    codes.append(UInt32(0x7ffffdf));lens.append(UInt8(27))   # 204
    codes.append(UInt32(0x3ffffe5));lens.append(UInt8(26))   # 205
    codes.append(UInt32(0xfffff1)); lens.append(UInt8(24))   # 206
    codes.append(UInt32(0x1ffffed));lens.append(UInt8(25))   # 207
    codes.append(UInt32(0x7fff2));  lens.append(UInt8(19))   # 208
    codes.append(UInt32(0x1fffe3)); lens.append(UInt8(21))   # 209
    codes.append(UInt32(0x3ffffe6));lens.append(UInt8(26))   # 210
    codes.append(UInt32(0x7ffffe0));lens.append(UInt8(27))   # 211
    codes.append(UInt32(0x7ffffe1));lens.append(UInt8(27))   # 212
    codes.append(UInt32(0x3ffffe7));lens.append(UInt8(26))   # 213
    codes.append(UInt32(0x7ffffe2));lens.append(UInt8(27))   # 214
    codes.append(UInt32(0xfffff2)); lens.append(UInt8(24))   # 215
    codes.append(UInt32(0x1fffe4)); lens.append(UInt8(21))   # 216
    codes.append(UInt32(0x1fffe5)); lens.append(UInt8(21))   # 217
    codes.append(UInt32(0x3ffffe8));lens.append(UInt8(26))   # 218
    codes.append(UInt32(0x3ffffe9));lens.append(UInt8(26))   # 219
    codes.append(UInt32(0x0ffffffd));lens.append(UInt8(28))  # 220
    codes.append(UInt32(0x7ffffe3));lens.append(UInt8(27))   # 221
    codes.append(UInt32(0x7ffffe4));lens.append(UInt8(27))   # 222
    codes.append(UInt32(0x7ffffe5));lens.append(UInt8(27))   # 223
    codes.append(UInt32(0xfffec));  lens.append(UInt8(20))   # 224
    codes.append(UInt32(0xfffff3)); lens.append(UInt8(24))   # 225
    codes.append(UInt32(0xfffed));  lens.append(UInt8(20))   # 226
    codes.append(UInt32(0x1fffe6)); lens.append(UInt8(21))   # 227
    codes.append(UInt32(0x3fffe9)); lens.append(UInt8(22))   # 228
    codes.append(UInt32(0x1fffe7)); lens.append(UInt8(21))   # 229
    codes.append(UInt32(0x1fffe8)); lens.append(UInt8(21))   # 230
    codes.append(UInt32(0x7ffff3)); lens.append(UInt8(23))   # 231
    codes.append(UInt32(0x3fffea)); lens.append(UInt8(22))   # 232
    codes.append(UInt32(0x3fffeb)); lens.append(UInt8(22))   # 233
    codes.append(UInt32(0x1ffffee));lens.append(UInt8(25))   # 234
    codes.append(UInt32(0x1ffffef));lens.append(UInt8(25))   # 235
    codes.append(UInt32(0xfffff4)); lens.append(UInt8(24))   # 236
    codes.append(UInt32(0xfffff5)); lens.append(UInt8(24))   # 237
    codes.append(UInt32(0x3ffffea));lens.append(UInt8(26))   # 238
    codes.append(UInt32(0x7ffff4)); lens.append(UInt8(23))   # 239
    codes.append(UInt32(0x3ffffeb));lens.append(UInt8(26))   # 240
    codes.append(UInt32(0x7ffffe6));lens.append(UInt8(27))   # 241
    codes.append(UInt32(0x3ffffec));lens.append(UInt8(26))   # 242
    codes.append(UInt32(0x3ffffed));lens.append(UInt8(26))   # 243
    codes.append(UInt32(0x7ffffe7));lens.append(UInt8(27))   # 244
    codes.append(UInt32(0x7ffffe8));lens.append(UInt8(27))   # 245
    codes.append(UInt32(0x7ffffe9));lens.append(UInt8(27))   # 246
    codes.append(UInt32(0x7ffffea));lens.append(UInt8(27))   # 247
    codes.append(UInt32(0x7ffffeb));lens.append(UInt8(27))   # 248
    codes.append(UInt32(0x0ffffffe));lens.append(UInt8(28))  # 249
    codes.append(UInt32(0x7ffffec));lens.append(UInt8(27))   # 250
    codes.append(UInt32(0x7ffffed));lens.append(UInt8(27))   # 251
    codes.append(UInt32(0x7ffffee));lens.append(UInt8(27))   # 252
    codes.append(UInt32(0x7ffffef));lens.append(UInt8(27))   # 253
    codes.append(UInt32(0x7fffff0));lens.append(UInt8(27))   # 254
    codes.append(UInt32(0x3ffffee));lens.append(UInt8(26))   # 255
    # ── EOS (symbol 256) ────────────────────────────────────────────────────
    codes.append(UInt32(0x3fffffff));lens.append(UInt8(30))  # 256 EOS
    return (codes^, lens^)


fn huffman_encode(s: String) -> List[UInt8]:
    """Encode string using RFC 7541 Huffman codes.

    Returns raw Huffman bytes (no length prefix or H flag — those are added by
    hpack_encode_str). The last byte is padded with the high bits of EOS (all 1s).
    Empty string returns empty list.
    """
    var tables = _huff_tables()
    var codes = tables[0].copy()
    var lens  = tables[1].copy()
    var out   = List[UInt8](capacity=len(s))
    var acc:  Int = 0   # bit accumulator (Int is 64-bit; max 37 bits used before flush)
    var bits: Int = 0   # bits currently in accumulator
    var raw = s.as_bytes()
    for i in range(len(raw)):
        var sym  = Int(raw[i])
        var code = Int(codes[sym])
        var l    = Int(lens[sym])
        acc   = (acc << l) | code
        bits += l
        while bits >= 8:
            bits -= 8
            out.append(UInt8((acc >> bits) & 0xFF))
    if bits > 0:
        # Pad remaining bits with 1s (high bits of EOS = 0x3fffffff = all 1s)
        var pad = 8 - bits
        out.append(UInt8(((acc << pad) | ((1 << pad) - 1)) & 0xFF))
    return out^


fn _build_huff_trie() -> Tuple[List[Int], List[Int], List[Int]]:
    """Build Huffman decode trie as three parallel index arrays.

    NL[i] = left child (bit=0) of node i, or -1 if absent.
    NR[i] = right child (bit=1) of node i, or -1 if absent.
    NS[i] = decoded symbol at leaf node i, or -1 for internal nodes.

    A canonical HPACK Huffman trie with 257 leaves has at most ~513 nodes.
    """
    var tables = _huff_tables()
    var codes = tables[0].copy()
    var lens  = tables[1].copy()
    var NL = List[Int](capacity=600)
    var NR = List[Int](capacity=600)
    var NS = List[Int](capacity=600)
    # Root node at index 0
    NL.append(-1); NR.append(-1); NS.append(-1)
    for sym in range(257):
        var code   = Int(codes[sym])
        var length = Int(lens[sym])
        var node   = 0
        for bp in range(length):
            var bit = (code >> (length - 1 - bp)) & 1
            if bit == 0:
                if NL[node] == -1:
                    NL.append(-1); NR.append(-1); NS.append(-1)
                    NL[node] = len(NL) - 1
                node = NL[node]
            else:
                if NR[node] == -1:
                    NL.append(-1); NR.append(-1); NS.append(-1)
                    NR[node] = len(NR) - 1
                node = NR[node]
        NS[node] = sym
    return (NL^, NR^, NS^)


fn huffman_decode(data: List[UInt8]) raises -> String:
    """Decode RFC 7541 Huffman bytes into a String.

    Raises Error on:
    - Invalid Huffman code (no path in trie).
    - Trailing padding not consisting of all 1-bits (not EOS prefix).
    - Trailing padding longer than 7 bits.
    EOS symbol (256) terminates decoding early.
    """
    var trie = _build_huff_trie()
    var NL = trie[0].copy()
    var NR = trie[1].copy()
    var NS = trie[2].copy()
    var out = List[UInt8](capacity=len(data))
    var node     = 0     # current trie node (0 = root)
    var pad_bits = 0     # bits consumed since last complete symbol
    var pad_ones = True  # whether those bits were all 1s (EOS prefix)
    for i in range(len(data)):
        var byte = Int(data[i])
        for b in range(8):
            var bit = (byte >> (7 - b)) & 1
            pad_bits += 1
            if bit == 0:
                pad_ones = False
                if NL[node] == -1:
                    raise Error("huffman decode: invalid code")
                node = NL[node]
            else:
                if NR[node] == -1:
                    raise Error("huffman decode: invalid code")
                node = NR[node]
            var sym = NS[node]
            if sym != -1:
                if sym == 256:  # EOS — stop decoding
                    return String(unsafe_from_utf8=out^)
                out.append(UInt8(sym))
                node     = 0
                pad_bits = 0
                pad_ones = True
    # Validate trailing padding: must be ≤ 7 bits and all 1s (EOS prefix).
    if node != 0:
        if pad_bits > 7:
            raise Error("huffman decode: padding longer than 7 bits")
        if pad_ones == False:
            raise Error("huffman decode: padding not EOS prefix (must be all 1s)")
    return String(unsafe_from_utf8=out^)


fn hpack_encode_str(s: String, huffman: Bool) -> List[UInt8]:
    """Encode a string as an HPACK string field (RFC 7541 §5.2).

    If huffman=True: H=1 bit set, content is Huffman-encoded.
    If huffman=False: H=0, content is literal UTF-8.
    """
    if not huffman:
        return hpack_encode_str_literal(s)
    var huff_bytes = huffman_encode(s)
    var n          = len(huff_bytes)
    var len_bytes  = hpack_encode_int(n, 7)
    var out        = List[UInt8](capacity=1 + len(len_bytes) - 1 + n)
    _append_bytes(out, len_bytes)
    # Set H bit (bit 7) in the first byte of the length field
    var first = Int(out[0]) | 0x80
    out[0] = UInt8(first)
    _append_bytes(out, huff_bytes)
    return out^


# ── 15B-4: Static Table (RFC 7541 Appendix A, 61 entries) ──────────────────

fn _static_table() -> Tuple[List[String], List[String]]:
    """Return (names, values) lists with 62 entries (index 0 unused; 1–61 per RFC)."""
    var names  = List[String](capacity=62)
    var values = List[String](capacity=62)
    # Index 0 — unused sentinel
    names.append("")
    values.append("")
    # 1–61 per RFC 7541 Appendix A
    names.append(":authority");          values.append("")
    names.append(":method");             values.append("GET")
    names.append(":method");             values.append("POST")
    names.append(":path");               values.append("/")
    names.append(":path");               values.append("/index.html")
    names.append(":scheme");             values.append("http")
    names.append(":scheme");             values.append("https")
    names.append(":status");             values.append("200")
    names.append(":status");             values.append("204")
    names.append(":status");             values.append("206")
    names.append(":status");             values.append("304")
    names.append(":status");             values.append("400")
    names.append(":status");             values.append("404")
    names.append(":status");             values.append("500")
    names.append("accept-charset");      values.append("")
    names.append("accept-encoding");     values.append("gzip, deflate")
    names.append("accept-language");     values.append("")
    names.append("accept-ranges");       values.append("")
    names.append("accept");              values.append("")
    names.append("access-control-allow-origin"); values.append("")
    names.append("age");                 values.append("")
    names.append("allow");               values.append("")
    names.append("authorization");       values.append("")
    names.append("cache-control");       values.append("")
    names.append("content-disposition"); values.append("")
    names.append("content-encoding");    values.append("")
    names.append("content-language");    values.append("")
    names.append("content-length");      values.append("")
    names.append("content-location");    values.append("")
    names.append("content-range");       values.append("")
    names.append("content-type");        values.append("")
    names.append("cookie");              values.append("")
    names.append("date");                values.append("")
    names.append("etag");                values.append("")
    names.append("expect");              values.append("")
    names.append("expires");             values.append("")
    names.append("from");                values.append("")
    names.append("host");                values.append("")
    names.append("if-match");            values.append("")
    names.append("if-modified-since");   values.append("")
    names.append("if-none-match");       values.append("")
    names.append("if-range");            values.append("")
    names.append("if-unmodified-since"); values.append("")
    names.append("last-modified");       values.append("")
    names.append("link");                values.append("")
    names.append("location");            values.append("")
    names.append("max-forwards");        values.append("")
    names.append("proxy-authenticate");  values.append("")
    names.append("proxy-authorization"); values.append("")
    names.append("range");               values.append("")
    names.append("referer");             values.append("")
    names.append("refresh");             values.append("")
    names.append("retry-after");         values.append("")
    names.append("server");              values.append("")
    names.append("set-cookie");          values.append("")
    names.append("strict-transport-security"); values.append("")
    names.append("transfer-encoding");   values.append("")
    names.append("user-agent");          values.append("")
    names.append("vary");                values.append("")
    names.append("via");                 values.append("")
    names.append("www-authenticate");    values.append("")
    return (names^, values^)


fn static_table_get(idx: Int) raises -> Tuple[String, String]:
    """Return the (name, value) pair at the given 1-based static table index.

    Args:
        idx: 1-based index (1–61 per RFC 7541 Appendix A).

    Returns:
        (name, value) tuple.

    Raises:
        Error if idx is out of range [1, 61].
    """
    if idx < 1 or idx > 61:
        raise Error("static_table_get: index out of range: " + String(idx))
    var tables = _static_table()
    var names  = tables[0].copy()
    var values = tables[1].copy()
    return (names[idx], values[idx])


fn static_table_find(name: String, value: String) -> Tuple[Int, Bool]:
    """Search the static table for a header name/value pair.

    Args:
        name:  Header name (lowercase).
        value: Header value.

    Returns:
        (idx, exact): idx is the 1-based index (0 if not found).
                      exact=True if both name and value matched.
                      exact=False if only name matched.
    """
    var tables      = _static_table()
    var names       = tables[0].copy()
    var values      = tables[1].copy()
    var name_match  = 0   # first index where name matched (value did not)
    for i in range(1, 62):
        if names[i] == name:
            if values[i] == value:
                return (i, True)
            if name_match == 0:
                name_match = i
    if name_match != 0:
        return (name_match, False)
    return (0, False)
