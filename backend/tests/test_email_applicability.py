"""Email auth (SPF/DMARC/DKIM) is only graded where it applies.

Subdomains without their own MX record don't handle mail, so in Full scan
they are scored on TLS + headers + DNS only (rescaled to 100), and get an
info-only "email.not_applicable" finding explaining why.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.discovery.enumerator import DiscoveredHost
from app.main import app
from app.scoring import score_checks

client = TestClient(app)


def _c(cid: str, cat: str, passed: bool) -> dict:
    return {"id": cid, "category": cat, "title": cid, "passed": passed,
            "severity": "info" if passed else "medium", "evidence": "", "remediation": ""}


TLS_ALL = [_c(i, "tls", True) for i in (
    "tls.cert_valid", "tls.modern_protocol", "tls.strong_ciphers",
    "tls.cert_renewal_buffer", "tls.hostname_match")]
EMAIL_NONE = [_c(i, "email", False) for i in (
    "email.spf_present", "email.dmarc_present", "email.spf_hardfail",
    "email.dmarc_strict_policy", "email.dkim_detected")]


# ---------------------------------------------------------------- engine

def test_engine_default_unchanged():
    r = score_checks(TLS_ALL)
    assert r["score"] == 30
    assert {c["name"] for c in r["breakdown"]} == {"tls", "headers", "email", "dns"}


def test_engine_not_applicable_rescales_and_drops_category():
    # 30 earned out of 75 applicable points (100 - email 25) -> 40
    r = score_checks(TLS_ALL, not_applicable=("email",))
    assert r["score"] == 40
    assert "email" not in {c["name"] for c in r["breakdown"]}


def test_engine_not_applicable_ignores_email_results():
    with_email = score_checks(TLS_ALL + EMAIL_NONE, not_applicable=("email",))
    without = score_checks(TLS_ALL, not_applicable=("email",))
    assert with_email["score"] == without["score"]


def test_engine_rejects_unknown_category():
    with pytest.raises(ValueError):
        score_checks(TLS_ALL, not_applicable=("emial",))


# ---------------------------------------------------------------- full scan

def _run_full(mx_by_host: dict[str, bool | None]):
    discovered = [DiscoveredHost(hostname=h, ip="1.1.1.1") for h in
                  ("example.com", "www.example.com", "mail.example.com")]
    email_mock = AsyncMock(return_value=EMAIL_NONE)

    async def fake_has_mx(host: str):
        return mx_by_host[host]

    with (
        patch("app.api.routes.enumerate_hosts", AsyncMock(return_value=discovered)),
        patch("app.api.routes.scan_dns", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=TLS_ALL)),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_email", email_mock),
        patch("app.api.routes.has_mx", side_effect=fake_has_mx),
        patch("app.api.routes.lookup_many", AsyncMock(return_value={})),
        patch("app.api.routes.scan_ports", AsyncMock(return_value=[])),
    ):
        resp = client.post("/api/scan", json={"domain": "example.com", "mode": "full"})
    assert resp.status_code == 200
    hosts = {h["host"]: h for h in resp.json()["hosts"]}
    scanned_email = sorted(c.args[0] for c in email_mock.call_args_list)
    return hosts, scanned_email


def test_full_scan_skips_email_on_subdomain_without_mx():
    hosts, scanned = _run_full({"www.example.com": False, "mail.example.com": True})

    # apex always graded on email; mail.* has MX; www.* does not
    assert scanned == ["example.com", "mail.example.com"]

    www = hosts["www.example.com"]
    assert www["score"] == 40   # 30/75 rescaled, not 30/100
    assert "email" not in {c["name"] for c in www["breakdown"]}
    assert any(f["id"] == "email.not_applicable" for f in www["findings"])

    assert hosts["example.com"]["score"] == 30
    assert hosts["mail.example.com"]["score"] == 30


def test_full_scan_keeps_email_when_mx_lookup_fails():
    # None = lookup error -> conservative: still grade email
    hosts, scanned = _run_full({"www.example.com": None, "mail.example.com": None})
    assert scanned == ["example.com", "mail.example.com", "www.example.com"]
    assert hosts["www.example.com"]["score"] == 30


def test_single_mode_always_grades_email():
    with (
        patch("app.api.routes.scan_dns", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_tls", AsyncMock(return_value=TLS_ALL)),
        patch("app.api.routes.scan_headers", AsyncMock(return_value=[])),
        patch("app.api.routes.scan_email", AsyncMock(return_value=EMAIL_NONE)) as em,
    ):
        resp = client.post("/api/scan", json={"domain": "www.example.com", "mode": "single"})
    assert resp.status_code == 200
    assert em.await_count == 1
    assert resp.json()["score"] == 30
