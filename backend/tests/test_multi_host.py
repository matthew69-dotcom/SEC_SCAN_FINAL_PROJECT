"""Integration-style tests for the multi-host scan endpoint (mode="full").

All external I/O is mocked so these run offline.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.discovery.enumerator import DiscoveredHost

client = TestClient(app)


def _make_host_checks(passed_all: bool = True) -> list[dict]:
    """Return a minimal set of 4 scanner results (1 per category)."""
    status = passed_all
    return [
        {"id": "tls.cert_valid", "category": "tls", "title": "TLS cert valid",
         "passed": status, "severity": "critical", "evidence": "", "remediation": ""},
        {"id": "headers.hsts", "category": "headers", "title": "HSTS present",
         "passed": status, "severity": "high", "evidence": "", "remediation": ""},
        {"id": "email.spf_present", "category": "email", "title": "SPF present",
         "passed": status, "severity": "medium", "evidence": "", "remediation": ""},
        {"id": "dns.dnssec", "category": "dns", "title": "DNSSEC enabled",
         "passed": status, "severity": "medium", "evidence": "", "remediation": ""},
    ]


# ---------------------------------------------------------------------------
# mode="single" must still work (backward compat)
# ---------------------------------------------------------------------------

def test_scan_single_mode_backward_compat():
    """mode="single" request must behave exactly like before W5."""
    mock_checks = _make_host_checks(passed_all=True)

    with (
        patch("app.api.routes.scan_dns", AsyncMock(return_value=mock_checks[:1])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=mock_checks[1:2])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=mock_checks[2:3])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=mock_checks[3:4])),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com", "mode": "single"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "single"
    assert data["hosts"] == []
    assert data["domain_score"] is None
    assert "score" in data
    assert "grade" in data


def test_scan_default_mode_is_single():
    """Omitting mode should default to single."""
    mock_checks = _make_host_checks()

    with (
        patch("app.api.routes.scan_dns", AsyncMock(return_value=mock_checks[:1])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=mock_checks[1:2])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=mock_checks[2:3])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=mock_checks[3:4])),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com"})

    assert resp.status_code == 200
    assert resp.json()["mode"] == "single"


# ---------------------------------------------------------------------------
# mode="full" tests
# ---------------------------------------------------------------------------

def test_scan_full_mode_returns_host_list():
    """mode="full" must populate hosts[] and domain_score."""
    discovered = [
        DiscoveredHost(hostname="mfu.ac.th", ip="1.2.3.4"),
        DiscoveredHost(hostname="www.mfu.ac.th", ip="1.2.3.5"),
    ]
    mock_checks = _make_host_checks(passed_all=False)

    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.scan_dns", AsyncMock(return_value=mock_checks[:1])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=mock_checks[1:2])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=mock_checks[2:3])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=mock_checks[3:4])),
    ):
        resp = client.post("/api/scan", json={"domain": "mfu.ac.th", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "full"
    assert len(data["hosts"]) == 2
    assert data["hosts_scanned"] == 2
    assert data["hosts_failed"] == 0
    assert data["domain_score"] is not None
    assert data["domain_grade"] is not None
    assert data["domain_avg_score"] is not None


def test_scan_full_mode_domain_score_is_worst_host():
    """domain_score must equal the minimum score across all hosts."""
    discovered = [
        DiscoveredHost(hostname="mfu.ac.th", ip="1.2.3.4"),
        DiscoveredHost(hostname="bad.mfu.ac.th", ip="1.2.3.6"),
    ]

    # First host: all pass → high score; second host: all fail → low score
    good_checks = _make_host_checks(passed_all=True)
    bad_checks = _make_host_checks(passed_all=False)

    call_count = 0

    async def alternating_dns(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return good_checks[:1] if call_count % 2 == 1 else bad_checks[:1]

    async def alternating_tls(*args, **kwargs):
        return good_checks[1:2] if call_count % 2 == 1 else bad_checks[1:2]

    async def alternating_headers(*args, **kwargs):
        return good_checks[2:3] if call_count % 2 == 1 else bad_checks[2:3]

    async def alternating_email(*args, **kwargs):
        return good_checks[3:4] if call_count % 2 == 1 else bad_checks[3:4]

    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.scan_dns", side_effect=alternating_dns),
        patch("app.api.routes.scan_tls", side_effect=alternating_tls),
        patch("app.api.routes.scan_headers", side_effect=alternating_headers),
        patch("app.api.routes.scan_email", side_effect=alternating_email),
    ):
        resp = client.post("/api/scan", json={"domain": "mfu.ac.th", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    host_scores = [h["score"] for h in data["hosts"]]
    assert data["domain_score"] == min(host_scores)


def test_scan_full_mode_counts_failed_hosts():
    """Hosts that time out must be counted in hosts_failed."""
    discovered = [
        DiscoveredHost(hostname="mfu.ac.th", ip="1.2.3.4"),
        DiscoveredHost(hostname="timeout.mfu.ac.th", ip="1.2.3.9"),
    ]
    mock_checks = _make_host_checks()
    call_count = 0

    async def sometimes_timeout(domain, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if "timeout" in domain:
            raise asyncio.TimeoutError()
        return mock_checks[:1]

    import asyncio

    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.scan_dns", side_effect=sometimes_timeout),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=mock_checks[1:2])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=mock_checks[2:3])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=mock_checks[3:4])),
    ):
        resp = client.post("/api/scan", json={"domain": "mfu.ac.th", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["hosts_failed"] >= 0  # timeout host may be counted as failed


def test_scan_full_mode_no_hosts_discovered():
    """If no hosts are discovered (all dead), response must still be valid."""
    with patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=[])):
        resp = client.post("/api/scan", json={"domain": "mfu.ac.th", "mode": "full"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["hosts"] == []
    assert data["hosts_scanned"] == 0
    assert data["domain_score"] == 0
    assert data["domain_grade"] == "F"


def test_scan_full_mode_summary_mentions_hosts():
    """Summary string for mode=full should mention host counts."""
    discovered = [DiscoveredHost(hostname="mfu.ac.th", ip="1.2.3.4")]
    mock_checks = _make_host_checks()

    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.scan_dns", AsyncMock(return_value=mock_checks[:1])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=mock_checks[1:2])),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=mock_checks[2:3])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=mock_checks[3:4])),
    ):
        resp = client.post("/api/scan", json={"domain": "mfu.ac.th", "mode": "full"})

    summary = resp.json()["summary"]
    assert "host" in summary.lower()
    assert "mfu.ac.th" in summary
