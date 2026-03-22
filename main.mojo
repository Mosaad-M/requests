# ============================================================================
# main.mojo — HTTP Client Demo
# ============================================================================
#
# Fetches a URL using the native Mojo HTTP client and prints the response.
# No Python interop — pure Mojo + C FFI.
#
# Usage: pixi run mojo run main.mojo
#
# ============================================================================

from http_client import HttpClient, HttpHeaders
from json import JsonValue, parse_json


def main() raises:
    print("=== Mojo Native HTTP Client ===")
    print()

    var client = HttpClient()

    # Simple GET request
    print("Fetching http://httpbin.org/get ...")
    var response = client.get("http://httpbin.org/get")

    print("Status:", response.status_code, response.status_text)
    print("OK:", response.ok)
    print()

    # Print response headers
    print("--- Response Headers ---")
    for i in range(len(response.headers)):
        print(" ", response.headers._keys[i] + ":", response.headers._values[i])
    print()

    # Print response body
    print("--- Response Body ---")
    print(response.body)
    print()

    # GET with custom headers
    print("Fetching with custom headers ...")
    var headers = HttpHeaders()
    headers.add("X-Custom-Header", "MojoTest")
    headers.add("Accept", "application/json")

    var response2 = client.get("http://httpbin.org/headers", headers)
    print("Status:", response2.status_code)
    print("Body:")
    print(response2.body)

    # POST request
    print()
    print("--- POST Demo ---")
    print("POST to http://httpbin.org/post ...")
    var post_body = String('{"name": "Mojo", "version": 1}')
    var post_resp = client.post("http://httpbin.org/post", post_body)
    print("Status:", post_resp.status_code, post_resp.status_text)
    print("Body (first 200 chars):")
    if len(post_resp.body) > 200:
        var truncated = List[UInt8](capacity=200)
        var b = post_resp.body.as_bytes()
        for i in range(200):
            truncated.append(b[i])
        print(String(unsafe_from_utf8=truncated^) + "...")
    else:
        print(post_resp.body)

    # HTTPS GET Request + Pythonic JSON API
    print()
    print("--- HTTPS + JSON Demo ---")
    var url = "https://jsonplaceholder.typicode.com/posts"
    var response3 = client.get(url)
    print("Status:", response3.status_code)

    # Parse JSON response
    var data = response3.json()
    print("Posts count:", len(data))
    print("First post:", data[0])
    print("Title:", data[0]["title"])
    print("User ID:", data[0]["userId"])
