"""SSRF guard: never connect to private/internal addresses.

A public name can point at 192.168.x.x etc. Connecting to it would probe the
scanner's own network. Such hosts must be reported (info leak) but never
TLS-handshaked, HTTP-fetched or port-scanned. All I/O is mocked.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.discovery.enumerator import DiscoveredHost
from app.main import app
from app.utils.netsafety import is_public_ip, non_public_ips

client = TestClient(app)

TLS_OK = [{"id": "tls.cert_valid", "category": "tls", "title": "ok", "passed": True,
           "severity": "info", "evidence": "", "remediation": ""}]


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True),
    ("202.28.46.8", True),
    ("192.168.0.3", False),      # RFC 1918
    ("10.1.2.3", False),
    ("172.16.5.5", False),
    ("127.0.0.1", False),        # loopback
    ("169.254.169.254", False),  # link-local / cloud metadata
    ("100.64.0.1", False),       # CGNAT
    ("0.0.0.0", False),
    ("224.0.0.1", False),        # multicast
    ("", False),
    ("not-an-ip", False),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public


async def test_non_public_ips_checks_every_record():
    with patch("app.utils.netsafety.resolve_ipv4",
               AsyncMock(return_value=["202.28.46.8", "10.0.0.5"])):
        assert await non_public_ips("mixed.example.com") == ["10.0.0.5"]


def test_full_scan_never_connects_to_private_hosts():
    discovered = [
        DiscoveredHost(hostname="example.com", ip="93.184.216.34"),
        DiscoveredHost(hostname="ns1.example.com", ip="192.168.0.3"),
    ]

    async def fake_non_public(host, known_ip=None):
        return ["192.168.0.3"] if host == "ns1.example.com" else []

    tls = AsyncMock(return_value=TLS_OK)
    headers = AsyncMock(return_value=[])
    ports = AsyncMock(return_value=[])
    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.non_public_ips", side_effect=fake_non_public),
        patch("app.api.routes.scan_dns", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_tls", tls),
        patch("app.api.routes.scan_headers", headers),
        patch("app.api.routes.scan_email", AsyncMock(return_value=[])),
        patch("app.api.routes.lookup_many", AsyncMock(return_value={})),
        patch("app.api.routes.scan_ports", ports),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    touched = {c.args[0] for m in (tls, headers, ports) for c in m.call_args_list}
    assert "ns1.example.com" not in touched
    assert "192.168.0.3" not in touched
    assert [h["host"] for h in data["hosts"]] == ["example.com"]
    # port scan targets the vetted public IP, not the hostname
    assert ports.call_args_list[0].args[0] == "93.184.216.34"
    # info leak reported on the apex, without affecting the score
    leak = [f for f in data["findings"] if f["id"] == "dns.private_ip_exposed"]
    assert leak and "ns1.example.com -> 192.168.0.3" in leak[0]["evidence"]
    assert "skipped 1 on private IPs" in data["summary"]


def test_single_scan_of_private_host_skips_connections():
    tls = AsyncMock(return_value=TLS_OK)
    headers = AsyncMock(return_value=[])
    with (
        patch("app.api.routes.non_public_ips", AsyncMock(return_value=["10.0.0.7"])),
        patch("app.api.routes.scan_dns", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_tls", tls),
        patch("app.api.routes.scan_headers", headers),
        patch("app.api.routes.scan_email", AsyncMock(return_value=[])),
    ):
        resp = client.post("/api/scan", json={"domain": "intranet.example.com"})

    assert resp.status_code == 200
    assert tls.await_count == 0 and headers.await_count == 0
    ids = {f["id"] for f in resp.json()["findings"]}
    assert {"tls.handshake", "headers.fetch", "dns.private_ip_exposed"} <= ids
