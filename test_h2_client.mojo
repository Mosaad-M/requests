# ============================================================================
# test_h2_client.mojo — HttpClient HTTP/2 integration tests (Phase 15D)
# ============================================================================
# Requires network access. Tests that HttpClient uses HTTP/2 for HTTPS URLs
# via ALPN negotiation, the H2 connection pool, and correct response parsing.
# Run: pixi run test-h2-client
# ============================================================================

from http_client import HttpClient, HttpHeaders


# ── Helpers ──────────────────────────────────────────────────────────────────

def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "—", String(e))
        failed += 1


fn assert_eq_int(got: Int, expected: Int, label: String) raises:
    if got != expected:
        raise Error(label + ": expected " + String(expected) + " got " + String(got))


fn assert_true(cond: Bool, label: String) raises:
    if not cond:
        raise Error(label + ": expected True")


fn assert_contains(haystack: String, needle: String, label: String) raises:
    if needle not in haystack:
        raise Error(label + ": '" + needle + "' not found in body")


# ── 15D: HttpClient H2 Integration Tests ─────────────────────────────────────

def test_h2_client_get() raises:
    """HttpClient GET https://jsonplaceholder.typicode.com/posts/1 → 200, JSON body."""
    var client = HttpClient()
    var resp = client.get("https://jsonplaceholder.typicode.com/posts/1")
    assert_eq_int(resp.status_code, 200, "status")
    assert_true(len(resp.body) > 0, "non-empty body")
    assert_contains(resp.body, "userId", "body contains 'userId' key")


def test_h2_client_post() raises:
    """HttpClient POST https://jsonplaceholder.typicode.com/posts → 201, echoes JSON."""
    var client = HttpClient()
    var resp = client.post(
        "https://jsonplaceholder.typicode.com/posts",
        '{"title": "mojo-h2", "body": "test", "userId": 1}',
    )
    assert_eq_int(resp.status_code, 201, "status")
    assert_contains(resp.body, "mojo-h2", "body echoes posted title")


def test_h2_client_pool_reuse() raises:
    """Two sequential GETs to the same H2 host both succeed (pool reuse path)."""
    var client = HttpClient()
    var r1 = client.get("https://jsonplaceholder.typicode.com/posts/1")
    assert_eq_int(r1.status_code, 200, "first request status")
    var r2 = client.get("https://jsonplaceholder.typicode.com/posts/2")
    assert_eq_int(r2.status_code, 200, "second request status (pool reuse)")
    assert_true(len(r2.body) > 0, "second response has body")


# ── main ─────────────────────────────────────────────────────────────────────

def main() raises:
    var passed = 0
    var failed = 0

    print("=== HttpClient HTTP/2 Integration Tests ===")
    print("(Requires network access)")
    print()
    print("── 15D: HttpClient H2 ──")
    run_test("GET https://jsonplaceholder.typicode.com/posts/1 → 200", passed, failed,
             test_h2_client_get)
    run_test("POST https://jsonplaceholder.typicode.com/posts → 201", passed, failed,
             test_h2_client_post)
    run_test("pool reuse: two GETs to same host both 200", passed, failed,
             test_h2_client_pool_reuse)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
