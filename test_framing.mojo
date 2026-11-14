# ============================================================================
# test_framing.mojo — where an HTTP/1.1 response body ends (RFC 9112 §6.3)
# ============================================================================
#
# Requires test_server.py (raw keep-alive listener on localhost:18083;
# pixi run test starts it). Every case is followed by a second request on the
# same client: bytes left on a pooled connection by a wrong framing decision
# show up there as "response is not HTTP". Responses that must be rejected
# send the head and the body separately (a pause between), so a client cannot
# get the body right just because both arrived in the same read.
#
# ============================================================================

from http_client import (
    HttpClient,
    _frame_from_headers,
    _Framing,
    FRAME_LENGTH,
    FRAME_CHUNKED,
    FRAME_UNTIL_CLOSE,
)

comptime FR = "http://127.0.0.1:18083"


def assert_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected " + String(expected) + ", got " + String(actual))


def assert_str_eq(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected '" + expected + "', got '" + actual + "'")


def assert_true(condition: Bool, label: String) raises:
    if not condition:
        raise Error(label + ": expected True")


def new_client() raises -> HttpClient:
    return HttpClient(allow_private_ips=True, timeout_secs=3)


def next_request_works(mut c: HttpClient, label: String) raises:
    # A POST: a failed GET on a pooled connection is replayed on a fresh one
    # (that would hide the very leftovers this check looks for); a POST is not.
    var r = c.post(FR + "/ok", "x")
    assert_str_eq(r.body, "ok", label + ": next request on the same client")


def expect_body(path: String, length: Int) raises:
    var c = new_client()
    var r = c.get(FR + path)
    assert_eq(r.status_code, 200, path + " status")
    assert_eq(r.body.byte_length(), length, path + " body length")
    next_request_works(c, path)


def expect_text(path: String, text: String) raises:
    var c = new_client()
    var r = c.get(FR + path)
    assert_str_eq(r.body, text, path + " body")
    next_request_works(c, path)


def expect_rejected(path: String, needle: String) raises:
    var c = new_client()
    var msg = String()
    var raised = False
    try:
        _ = c.get(FR + path)
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, path + ": expected an error")
    assert_true(msg.startswith("ParseError"), path + ": expected ParseError, got '" + msg + "'")
    assert_true(msg.find(needle) >= 0, path + ": error should mention '" + needle + "', got '" + msg + "'")
    next_request_works(c, path)


# ── Must keep working ────────────────────────────────────────────────────────


def test_value_containing_content_length() raises:
    expect_body("/val-cl", 100000)


def test_value_containing_transfer_encoding() raises:
    expect_body("/val-te", 3000)


def test_continuation_line_is_not_a_header() raises:
    expect_body("/fold", 100000)


def test_odd_case_content_length() raises:
    expect_body("/mixed-case", 100000)


def test_content_length_first_header() raises:
    expect_body("/cl-first", 100000)


def test_chunked_last() raises:
    expect_text("/te-last", "hello world")


def test_chunked_middle() raises:
    expect_text("/te-mid", "hello world")


def test_chunked_odd_case() raises:
    expect_text("/te-upper", "hello world")


def test_identity_then_chunked() raises:
    expect_text("/te-identity-chunked", "hello world")


def test_duplicate_equal_content_length() raises:
    expect_text("/dup-cl-same", "hello")


def test_content_length_list_of_equal_values() raises:
    expect_text("/cl-list", "hello")


# ── Must be rejected ─────────────────────────────────────────────────────────


def test_duplicate_differing_content_length() raises:
    expect_rejected("/dup-cl-diff", "Content-Length")


def test_content_length_list_with_differing_values() raises:
    expect_rejected("/cl-list-diff", "Content-Length")


def test_content_length_letters() raises:
    expect_rejected("/cl-abc", "Content-Length")


def test_content_length_plus_sign() raises:
    expect_rejected("/cl-plus", "Content-Length")


def test_content_length_negative() raises:
    expect_rejected("/cl-neg", "Content-Length")


def test_content_length_empty() raises:
    expect_rejected("/cl-empty", "Content-Length")


def test_space_before_colon_content_length() raises:
    expect_rejected("/cl-space-colon", "whitespace")


def test_space_before_colon_transfer_encoding() raises:
    expect_rejected("/te-space-colon", "whitespace")


def test_continuation_inside_content_length() raises:
    expect_rejected("/fold-in-cl", "Content-Length")


def test_unsupported_transfer_coding_before_chunked() raises:
    expect_rejected("/te-gzip-chunked", "Transfer-Encoding")


def test_unknown_transfer_coding() raises:
    expect_rejected("/te-notchunked", "Transfer-Encoding")


# ── Accepted, with a safe outcome ────────────────────────────────────────────


def test_content_length_and_transfer_encoding() raises:
    # Transfer-Encoding wins (RFC 9112 6.3); the connection is not reused.
    expect_text("/cl-and-te", "hello world")


def test_content_length_and_transfer_encoding_connection_not_reused() raises:
    expect_text("/cl-and-te-stray", "hello world")


def test_response_smuggled_after_content_length_body() raises:
    expect_text("/smuggled", "hello")


def test_extra_bytes_after_content_length_body() raises:
    expect_text("/extra-after-body", "hello")


def test_chunked_trailers_are_consumed() raises:
    expect_text("/trailers", "hello")


def test_chunked_trailers_split_across_reads() raises:
    expect_text("/trailers-split", "hello")


# ── The parser on its own ────────────────────────────────────────────────────


def frame(head: String) raises -> _Framing:
    """head is a status line and headers, without the blank line."""
    var bytes = List[UInt8]()
    for b in (head + "\r\n\r\n").as_bytes():
        bytes.append(b)
    return _frame_from_headers(bytes, len(bytes) - 4)


def parse_fails(head: String) raises -> Bool:
    try:
        _ = frame(head)
    except e:
        return String(e).startswith("ParseError")
    return False


def test_unit_length_beyond_the_old_100mb_constant() raises:
    var f = frame("HTTP/1.1 200 OK\r\nContent-Length: 200000000")
    assert_eq(f.kind, FRAME_LENGTH, "kind")
    assert_eq(f.length, 200000000, "length")


def test_unit_absurd_length_is_rejected() raises:
    assert_true(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999"), "26 digits")
    assert_true(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 100000000000000000"), "at the cap")
    assert_eq(frame("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999").length, 99999999999999999, "just under")


def test_unit_leading_zeros() raises:
    assert_eq(frame("HTTP/1.1 200 OK\r\nContent-Length: 0005").length, 5, "0005")
    assert_eq(frame("HTTP/1.1 200 OK\r\nContent-Length: 00000000000000000000000005").length, 5, "many zeros")


def test_unit_identity_keeps_content_length() raises:
    var f = frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nContent-Length: 5")
    assert_eq(f.kind, FRAME_LENGTH, "kind")
    assert_eq(f.length, 5, "length")
    assert_true(not f.conflict, "identity is not a conflict")
    assert_eq(frame("HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\nContent-Length: 5").kind, FRAME_LENGTH, "empty TE")


def test_unit_status_line_and_last_header_edges() raises:
    assert_eq(frame("HTTP/1.1 200 OK\r\nContent-Length: 7").length, 7, "last header, no trailing CRLF")
    assert_eq(frame("HTTP/1.1 200 OK\nContent-Length: 7").kind, FRAME_UNTIL_CLOSE, "bare LF is not split")


def test_unit_tab_around_value() raises:
    assert_eq(frame("HTTP/1.1 200 OK\r\nContent-Length:\t 5 \t").length, 5, "length")


def test_identity_with_content_length() raises:
    expect_text("/te-identity-cl", "hello")


def test_head_with_content_length_then_get() raises:
    var c = new_client()
    var h = c.head(FR + "/ok")
    assert_eq(h.status_code, 200, "HEAD status")
    assert_eq(h.body.byte_length(), 0, "HEAD has no body")
    next_request_works(c, "after HEAD")
    var h2 = c.head(FR + "/ok")
    assert_eq(h2.status_code, 200, "second HEAD on the same client")


def test_unit_both_headers() raises:
    var f = frame("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked")
    assert_eq(f.kind, FRAME_CHUNKED, "transfer-encoding wins")
    assert_true(f.conflict, "conflict flagged")
    assert_true(not frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked").conflict, "no conflict alone")


def test_unit_no_framing_headers() raises:
    assert_eq(frame("HTTP/1.1 200 OK\r\nX-A: 1").kind, FRAME_UNTIL_CLOSE, "headers without framing")
    assert_eq(frame("HTTP/1.1 200 OK").kind, FRAME_UNTIL_CLOSE, "status line only")


def test_unit_identity_alone_is_not_chunked() raises:
    assert_eq(frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: identity").kind, FRAME_UNTIL_CLOSE, "kind")


def test_unit_chunked_must_be_last() raises:
    assert_true(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity"), "chunked then identity")
    assert_true(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity"), "split across lines")


def test_unit_line_without_colon_is_ignored() raises:
    assert_eq(frame("HTTP/1.1 200 OK\r\nnot a header\r\nContent-Length: 3").length, 3, "length")


def test_unit_conflicting_values_across_lines() raises:
    assert_true(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6"), "5 then 6")
    assert_true(not parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5"), "5 then 5")


# ── The size limit is the client's, not a constant in the parser (#28) ───────


def test_default_limit_stops_a_200mb_body() raises:
    var c = new_client()
    var msg = String()
    try:
        _ = c.get(FR + "/cl-huge")
    except e:
        msg = String(e)
    assert_true(msg.find("size limit") >= 0, "default 100 MB limit: expected a size-limit error, got '" + msg + "'")


def test_raised_limit_lets_a_200mb_body_through_the_header_check() raises:
    var c = new_client()
    c.max_response_bytes = 300_000_000
    var msg = String()
    try:
        _ = c.get(FR + "/cl-huge")
    except e:
        msg = String(e)
    # The server sends 10 bytes, so this ends in a timeout, not a size error.
    assert_true(msg.byte_length() > 0, "expected the read to time out")
    assert_true(msg.find("size limit") < 0, "raised limit must not trip a size limit, got '" + msg + "'")


def main() raises:
    var passed = 0
    var failed = 0

    def run_test[test_fn: def () thin raises -> None](name: String, mut passed: Int, mut failed: Int):
        try:
            test_fn()
            print("  PASS:", name)
            passed += 1
        except e:
            print("  FAIL:", name, "-", String(e))
            failed += 1

    print("=== Response framing (RFC 9112 6.3) ===")
    print("(Requires test_server.py on localhost:18083)")
    print()

    run_test[test_value_containing_content_length]("keeps working: content-length: in another header's value", passed, failed)
    run_test[test_value_containing_transfer_encoding]("keeps working: transfer-encoding: in another header's value", passed, failed)
    run_test[test_continuation_line_is_not_a_header]("keeps working: continuation line", passed, failed)
    run_test[test_odd_case_content_length]("keeps working: odd-case Content-Length", passed, failed)
    run_test[test_content_length_first_header]("keeps working: Content-Length first", passed, failed)
    run_test[test_chunked_last]("keeps working: chunked, Transfer-Encoding last", passed, failed)
    run_test[test_chunked_middle]("keeps working: chunked, Transfer-Encoding in the middle", passed, failed)
    run_test[test_chunked_odd_case]("keeps working: chunked, odd case", passed, failed)
    run_test[test_identity_then_chunked]("keeps working: identity, chunked", passed, failed)
    run_test[test_duplicate_equal_content_length]("keeps working: duplicate equal Content-Length", passed, failed)
    run_test[test_content_length_list_of_equal_values]("keeps working: Content-Length: 5, 5", passed, failed)

    run_test[test_duplicate_differing_content_length]("rejects: differing duplicate Content-Length", passed, failed)
    run_test[test_content_length_list_with_differing_values]("rejects: Content-Length: 5, 6", passed, failed)
    run_test[test_content_length_letters]("rejects: Content-Length: abc", passed, failed)
    run_test[test_content_length_plus_sign]("rejects: Content-Length: +5", passed, failed)
    run_test[test_content_length_negative]("rejects: Content-Length: -1", passed, failed)
    run_test[test_content_length_empty]("rejects: empty Content-Length", passed, failed)
    run_test[test_space_before_colon_content_length]("rejects: space before colon (Content-Length)", passed, failed)
    run_test[test_space_before_colon_transfer_encoding]("rejects: space before colon (Transfer-Encoding)", passed, failed)
    run_test[test_continuation_inside_content_length]("rejects: continuation inside Content-Length", passed, failed)
    run_test[test_unsupported_transfer_coding_before_chunked]("rejects: Transfer-Encoding: gzip, chunked", passed, failed)
    run_test[test_unknown_transfer_coding]("rejects: Transfer-Encoding: notchunked", passed, failed)

    run_test[test_content_length_and_transfer_encoding]("safe: Content-Length and Transfer-Encoding together", passed, failed)
    run_test[test_content_length_and_transfer_encoding_connection_not_reused]("safe: Content-Length and Transfer-Encoding: connection not reused", passed, failed)
    run_test[test_response_smuggled_after_content_length_body]("safe: second response after the body, connection not reused", passed, failed)
    run_test[test_extra_bytes_after_content_length_body]("safe: extra bytes after the body", passed, failed)
    run_test[test_chunked_trailers_are_consumed]("safe: chunked trailers consumed", passed, failed)
    run_test[test_chunked_trailers_split_across_reads]("safe: chunked trailers split across reads", passed, failed)

    run_test[test_unit_length_beyond_the_old_100mb_constant]("parser: length above 100 MB", passed, failed)
    run_test[test_unit_absurd_length_is_rejected]("parser: absurd length rejected", passed, failed)
    run_test[test_unit_leading_zeros]("parser: leading zeros", passed, failed)
    run_test[test_unit_identity_keeps_content_length]("parser: identity keeps Content-Length", passed, failed)
    run_test[test_unit_status_line_and_last_header_edges]("parser: header block edges", passed, failed)
    run_test[test_identity_with_content_length]("keeps working: Transfer-Encoding: identity with Content-Length", passed, failed)
    run_test[test_head_with_content_length_then_get]("keeps working: HEAD with Content-Length, then more requests", passed, failed)
    run_test[test_unit_tab_around_value]("parser: tab around the value", passed, failed)
    run_test[test_unit_both_headers]("parser: Content-Length and Transfer-Encoding", passed, failed)
    run_test[test_unit_no_framing_headers]("parser: no framing headers", passed, failed)
    run_test[test_unit_identity_alone_is_not_chunked]("parser: identity alone", passed, failed)
    run_test[test_unit_chunked_must_be_last]("parser: chunked must be the last coding", passed, failed)
    run_test[test_unit_line_without_colon_is_ignored]("parser: line without a colon", passed, failed)
    run_test[test_unit_conflicting_values_across_lines]("parser: values across lines", passed, failed)
    run_test[test_default_limit_stops_a_200mb_body]("limit: default stops a 200 MB Content-Length", passed, failed)
    run_test[test_raised_limit_lets_a_200mb_body_through_the_header_check]("limit: raised max_response_bytes is honoured", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
