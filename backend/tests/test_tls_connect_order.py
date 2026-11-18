"""TLS scanner connects over IPv4 before IPv6 (offline, mocked sockets).

Regression for a slow-network bug: on a network without working IPv6,
socket.create_connection tried each AAAA address first and waited the full
8 s timeout on each, per handshake (example.com: ~32 s per TLS scan).
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from app.scanners import tls_scanner

V6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:10::6814:179a", 443, 0, 0))
V6B = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:10::ac42:93f3", 443, 0, 0))
V4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.20.23.154", 443))
V4B = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.66.147.243", 443))


class _FakeSocket:
    """Records connect attempts; addresses in `failing` raise TimeoutError."""

    attempts: list[str] = []
    failing: set[str] = set()

    def __init__(self, family, socktype, proto):
        self.closed = False

    def settimeout(self, t):
        pass

    def connect(self, addr):
        _FakeSocket.attempts.append(addr[0])
        if addr[0] in _FakeSocket.failing:
            raise TimeoutError("timed out")

    def close(self):
        self.closed = True


@pytest.fixture
def fake_net():
    _FakeSocket.attempts = []
    _FakeSocket.failing = set()
    with patch.object(tls_scanner.socket, "socket", _FakeSocket):
        yield _FakeSocket


def test_ipv4_tried_before_ipv6(fake_net):
    with patch.object(tls_scanner.socket, "getaddrinfo", return_value=[V6, V6B, V4, V4B]):
        tls_scanner._open_tcp("example.com", 443, 8.0)
    assert fake_net.attempts == ["104.20.23.154"]  # no IPv6 attempt at all


def test_falls_back_to_next_ipv4_then_ipv6(fake_net):
    fake_net.failing = {"104.20.23.154", "172.66.147.243"}
    with patch.object(tls_scanner.socket, "getaddrinfo", return_value=[V6, V4, V4B]):
        tls_scanner._open_tcp("example.com", 443, 8.0)
    assert fake_net.attempts == ["104.20.23.154", "172.66.147.243", "2606:4700:10::6814:179a"]


def test_ipv6_only_host_still_works(fake_net):
    with patch.object(tls_scanner.socket, "getaddrinfo", return_value=[V6]):
        tls_scanner._open_tcp("v6only.example", 443, 8.0)
    assert fake_net.attempts == ["2606:4700:10::6814:179a"]


def test_all_addresses_fail_raises_last_error(fake_net):
    fake_net.failing = {"104.20.23.154", "2606:4700:10::6814:179a"}
    with patch.object(tls_scanner.socket, "getaddrinfo", return_value=[V6, V4]):
        with pytest.raises(TimeoutError):
            tls_scanner._open_tcp("example.com", 443, 8.0)


def test_localhost_keeps_os_order(fake_net):
    """Local test servers bind to whatever 'localhost' resolves to first."""
    lo6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))
    lo4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    with patch.object(tls_scanner.socket, "getaddrinfo", return_value=[lo6, lo4]):
        tls_scanner._open_tcp("localhost", 443, 8.0)
    assert fake_net.attempts == ["::1"]
