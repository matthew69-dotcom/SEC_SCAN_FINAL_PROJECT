"""Guard-rail tests for mode="full": host cap + bounded slow phases.

Regression for "Full scan is slow / hangs": one slow third-party service
(crt.sh, ip-api.com, OpenAI) or a large crt.sh result set must not stall
the whole request. All external I/O is mocked so these run offline.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.api import routes
from app.discovery.enumerator import DiscoveredHost
from app.main import app

client = TestClient(app)

_CHECKS = [
    {"id": "tls.cert_valid", "category": "tls", "title": "TLS cert valid",
     "passed": True, "severity": "critical", "evidence": "", "remediation": ""},
]


def _scanner_patches():
    return (
        patch("app.api.routes.scan_dns", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=_CHECKS)),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=[])),
    )


def test_prioritize_hosts_keeps_apex_and_www_first():
    hosts = [DiscoveredHost(hostname=h, ip="1.1.1.1") for h in (
        "a.b.c.example.com", "zz.example.com", "www.example.com", "example.com", "api.example.com",
    )]
    picked = routes._prioritize_hosts(hosts, "example.com", 3)
    assert [h.hostname for h in picked] == ["example.com", "www.example.com", "zz.example.com"]


def test_full_scan_caps_number_of_hosts():
    discovered = [DiscoveredHost(hostname="example.com", ip="1.1.1.1")] + [
        DiscoveredHost(hostname=f"h{i}.example.com", ip="1.1.1.1") for i in range(100)
    ]
    p1, p2, p3, p4 = _scanner_patches()
    with (
        p1, p2, p3, p4,
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.lookup_many", AsyncMock(return_value={})),
        patch("app.api.routes.scan_ports", AsyncMock(return_value=[])),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["hosts_scanned"] == routes.MAX_HOSTS
    assert any(h["host"] == "example.com" for h in data["hosts"])
    assert "Discovered 101 host(s)" in data["summary"]


def test_full_scan_survives_slow_phases(monkeypatch):
    """Slow discovery, geo-ip, ports and AI must each be cut off, not hang."""
    monkeypatch.setattr(routes, "DISCOVERY_TIMEOUT", 0.2)
    monkeypatch.setattr(routes, "GEOIP_TIMEOUT", 0.2)
    monkeypatch.setattr(routes, "PORT_SCAN_TIMEOUT", 0.2)
    monkeypatch.setattr(routes, "AI_TIMEOUT", 0.2)

    async def slow(*_a, **_k):
        await asyncio.sleep(30)

    p1, p2, p3, p4 = _scanner_patches()
    with (
        p1, p2, p3, p4,
        patch("app.api.routes.enumerate_hosts", side_effect=slow),
        patch("app.api.routes.lookup_many", side_effect=slow),
        patch("app.api.routes.scan_ports", side_effect=slow),
        patch("app.ai.analyzer.analyze_findings", side_effect=slow),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    # discovery timed out -> falls back to scanning the apex only
    assert [h["host"] for h in data["hosts"]] == ["example.com"]
    assert data["ai_summary"] is None
