"""Regression tests for the sandbox MITM proxy's HTTPS tunnel."""

from __future__ import annotations

import importlib.util
import socket
import sys
import threading
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROXY_PATH = REPO_ROOT / "scripts" / "sandbox" / "proxy.py"
SPEC = importlib.util.spec_from_file_location("sandbox_proxy", PROXY_PATH)
assert SPEC and SPEC.loader
proxy = importlib.util.module_from_spec(SPEC)
_original_argv = sys.argv
try:
    sys.argv = [str(PROXY_PATH), "/tmp/proxy-root", "/tmp/proxy-certs", "/tmp/real-ca.pem"]
    SPEC.loader.exec_module(proxy)
finally:
    sys.argv = _original_argv


class _FakeUpstream:
    """One keep-alive upstream that waits for the second client request."""

    def __init__(self, first_response: bytes, second_response: bytes) -> None:
        self.first_response = first_response
        self.second_response = second_response
        self.sent: list[bytes] = []
        self.second_request = threading.Event()
        self.error: str | None = None
        self._response_number = 0

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if len(self.sent) >= 2:
            self.second_request.set()

    def recv(self, _size: int) -> bytes:
        if self._response_number == 0:
            self._response_number += 1
            return self.first_response
        if self._response_number == 1:
            if not self.second_request.wait(timeout=5):
                self.error = "proxy did not forward the second request"
                return b""
            self._response_number += 1
            return self.second_response
        return b""

    def shutdown(self, _how: int) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeTLSContext:
    def __init__(self, upstream: _FakeUpstream) -> None:
        self.upstream = upstream

    def wrap_socket(self, _raw: object, *, server_hostname: str) -> _FakeUpstream:
        assert server_hostname == "registry.example"
        return self.upstream


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        assert chunk, "proxy closed the client side before the full response"
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def test_https_connect_forwards_multiple_keepalive_requests(monkeypatch) -> None:
    """A reused CONNECT tunnel must carry every request, not only the first."""

    first_request = (
        b"GET /one HTTP/1.1\r\n"
        b"Host: registry.example\r\n"
        b"Proxy-Connection: keep-alive\r\n\r\n"
    )
    second_request = (
        b"GET /two HTTP/1.1\r\n"
        b"Host: registry.example\r\n"
        b"Connection: keep-alive\r\n"
        b"Proxy-Connection: keep-alive\r\n\r\n"
    )
    first_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
    second_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo"
    upstream = _FakeUpstream(first_response, second_response)

    monkeypatch.setattr(
        proxy.socket,
        "create_connection",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        proxy.ssl,
        "create_default_context",
        lambda *, cafile: _FakeTLSContext(upstream),
    )

    client, proxy_side = socket.socketpair()
    client.settimeout(5)
    worker = threading.Thread(
        target=proxy.forward_https,
        args=(proxy_side, "registry.example", 443, first_request),
    )
    worker.start()
    try:
        assert _read_exact(client, len(first_response)) == first_response
        client.sendall(second_request)
        client.shutdown(socket.SHUT_WR)
        assert _read_exact(client, len(second_response)) == second_response
        assert client.recv(1) == b""
    finally:
        client.close()
        proxy_side.close()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert upstream.error is None
    assert upstream.sent == [
        proxy.strip_proxy_headers(first_request),
        proxy.strip_proxy_headers(second_request),
    ]
    assert all(b"Proxy-Connection:" not in request for request in upstream.sent)
