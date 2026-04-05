"""Minimal HTTP CONNECT proxy server for testing Mojo HTTP client proxy support.

Listens on localhost:18081 and handles CONNECT tunnels to any target.
Only for testing — no auth, no ACL.

Usage: python test_proxy_server.py
"""

import socket
import select
import threading
import sys


PROXY_PORT = 18081
BUFSIZE = 65536


def tunnel(src, dst):
    """Forward data between two sockets until one closes."""
    sockets = [src, dst]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], sockets, 5.0)
            if not readable:
                break
            for s in readable:
                other = dst if s is src else src
                try:
                    data = s.recv(BUFSIZE)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return
    except Exception:
        pass


def handle_connect(client_sock, target_host, target_port):
    """Establish tunnel to target and forward traffic."""
    try:
        target_sock = socket.create_connection((target_host, target_port), timeout=5)
    except OSError as e:
        response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        try:
            client_sock.sendall(response)
        except OSError:
            pass
        client_sock.close()
        return

    response = b"HTTP/1.1 200 Connection established\r\n\r\n"
    try:
        client_sock.sendall(response)
    except OSError:
        target_sock.close()
        client_sock.close()
        return

    tunnel(client_sock, target_sock)
    target_sock.close()
    client_sock.close()


def handle_client(client_sock):
    """Parse CONNECT request and dispatch tunnel."""
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client_sock.recv(4096)
            if not chunk:
                client_sock.close()
                return
            data += chunk
            if len(data) > 8192:
                client_sock.close()
                return

        request_line = data.split(b"\r\n")[0].decode("ascii", errors="replace")
        parts = request_line.split()
        if len(parts) < 3 or parts[0].upper() != "CONNECT":
            response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            client_sock.sendall(response)
            client_sock.close()
            return

        host_port = parts[1]
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 80

        handle_connect(client_sock, host, port)
    except Exception:
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", PROXY_PORT))
    server_sock.listen(10)
    server_sock.settimeout(1.0)
    print(f"Proxy server running on http://127.0.0.1:{PROXY_PORT}")
    try:
        while True:
            try:
                client_sock, _ = server_sock.accept()
                t = threading.Thread(target=handle_client, args=(client_sock,), daemon=True)
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        pass
    server_sock.close()
    print("Proxy server stopped")


if __name__ == "__main__":
    main()
