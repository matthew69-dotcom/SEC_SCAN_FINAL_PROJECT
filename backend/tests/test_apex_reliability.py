"""The report headline must always describe the apex itself.

Regression: when youtube.com's own scan timed out, the report silently showed
a subdomain's findings ("no MX", "no CAA") under the youtube.com name, so two
scans minutes apart gave A and D. Now: the apex gets a longer budget + one
retry, and is never substituted. All I/O is mocked.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api import routes
from app.discovery.enumerator import DiscoveredHost
from app.main import app
from app.scanners.header_scanner import scan_headers
from app.utils.netsafety import non_public_ips

client = TestClient(app)


def _chk(cid: str, cat: str, passed: bool) -> dict:
    return {"id": cid, "category": cat, "title": cid, "passed": passed,
            "severity": "info" if passed else "medium", "evidence": "", "remediation": ""}


SUB_ONLY = _chk("dns.caa", "dns", False)  # a finding only the subdomain has

DISCOVERED = [
    DiscoveredHost(hostname="example.com", ip="93.184.216.34"),
    DiscoveredHost(hostname="sub.example.com", ip="93.184.216.35"),
]


def _run(dns_side_effect, monkeypatch, apex_timeout=0.2, attempts=2):
    monkeypatch.setattr(routes, "APEX_SCAN_TIMEOUT", apex_timeout)
    monkeypatch.setattr(routes, "APEX_SCAN_ATTEMPTS", attempts)
    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=DISCOVERED)),
        patch("app.api.routes.scan_dns", side_effect=dns_side_effect),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=[])),
        patch("app.api.routes.lookup_many", AsyncMock(return_value={})),
        patch("app.api.routes.scan_ports", AsyncMock(return_value=[])),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com", "mode": "full"})
    assert resp.status_code == 200
    return resp.json()


def test_apex_timeout_is_never_replaced_by_another_host(monkeypatch):
    async def dns(host):
        if host == "example.com":
            await asyncio.sleep(5)  # apex always too slow
        return [SUB_ONLY]

    data = _run(dns, monkeypatch)
    ids = [f["id"] for f in data["findings"]]
    assert "scan.apex_unavailable" in ids
    assert "dns.caa" not in ids            # subdomain findings NOT shown as apex's
    assert data["breakdown"] == []
    assert data["score"] == data["domain_score"]
    assert "Could not scan example.com itself" in data["summary"]
    assert "timed out: example.com" in data["summary"]
    assert data["ai_summary"] is None      # AI must not describe the wrong host


def test_apex_is_retried_once(monkeypatch):
    calls = {"n": 0}

    async def dns(host):
        if host == "example.com":
            calls["n"] += 1
            if calls["n"] == 1:
                await asyncio.sleep(5)     # first attempt times out
        return []

    data = _run(dns, monkeypatch)
    assert calls["n"] == 2
    assert "scan.apex_unavailable" not in [f["id"] for f in data["findings"]]
    assert any(h["host"] == "example.com" for h in data["hosts"])


async def test_empty_known_ip_is_not_treated_as_private():
    # discovery-timeout fallback creates DiscoveredHost(ip="")
    with patch("app.utils.netsafety.resolve_ipv4", AsyncMock(return_value=["93.184.216.34"])):
        assert await non_public_ips("example.com", "") == []


async def test_headers_scanner_reads_headers_without_body(monkeypatch):
    body_read = {"done": False}

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            body_read["done"] = True
            yield b"x" * 10

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
        }, stream=Body())

    real_client = httpx.AsyncClient

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real_client(*a, **kw)

    monkeypatch.setattr("app.scanners.header_scanner.httpx.AsyncClient", fake_client)
    results = {r["id"]: r for r in await scan_headers("example.com")}
    assert results["headers.hsts"]["passed"] is True
    assert results["headers.nosniff"]["passed"] is True
    assert body_read["done"] is False      # body never downloaded


@pytest.mark.parametrize("host", ["example.com"])
def test_single_mode_unchanged(host):
    with (
        patch("app.api.routes.scan_dns", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=[])),
    ):
        resp = client.post("/api/scan", json={"domain": host})
    assert resp.status_code == 200
    assert resp.json()["domain"] == host
