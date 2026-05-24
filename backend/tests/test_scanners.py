"""Integration-ish tests for the Week 2-3 scanners.

These tests hit real DNS/TLS/HTTP endpoints (google.com), so they require network
and will be skipped in CI later. For now, run them locally to verify the scanners
actually behave correctly against well-known domains.
"""
import pytest

from app.scanners.dns_scanner import scan_dns
from app.scanners.email_scanner import scan_email
from app.scanners.header_scanner import scan_headers
from app.scanners.tls_scanner import scan_tls


# All scanner checks must produce these keys, regardless of pass/fail
REQUIRED_KEYS = {"id", "category", "title", "passed", "severity", "evidence", "remediation"}


@pytest.mark.asyncio
async def test_dns_google():
    results = await scan_dns("google.com")
    assert len(results) >= 4
    for r in results:
        assert REQUIRED_KEYS.issubset(r.keys()), f"missing keys in {r}"
        assert r["category"] == "dns"

    by_id = {r["id"]: r for r in results}
    # google.com definitely has A, NS, MX
    assert by_id["dns.a_record"]["passed"] is True
    assert by_id["dns.ns_redundancy"]["passed"] is True
    assert by_id["dns.mx_record"]["passed"] is True


@pytest.mark.asyncio
async def test_dns_nonexistent_domain_doesnt_raise():
    """A made-up domain should produce failed checks, never raise."""
    results = await scan_dns("this-domain-definitely-does-not-exist-xyz123.invalid")
    assert isinstance(results, list)
    assert all("passed" in r for r in results)
    # A record check should fail
    a = next(r for r in results if r["id"] == "dns.a_record")
    assert a["passed"] is False


@pytest.mark.asyncio
async def test_tls_google():
    results = await scan_tls("google.com")
    assert len(results) >= 4
    for r in results:
        assert REQUIRED_KEYS.issubset(r.keys()), f"missing keys in {r}"
        assert r["category"] == "tls"

    by_id = {r["id"]: r for r in results}
    assert by_id["tls.handshake"]["passed"] is True
    assert by_id["tls.cert_valid"]["passed"] is True
    assert by_id["tls.hostname_match"]["passed"] is True
    assert by_id["tls.modern_protocol"]["passed"] is True


@pytest.mark.asyncio
async def test_tls_unreachable_doesnt_raise():
    """Unreachable host should produce a failed handshake check, never raise."""
    results = await scan_tls("does-not-exist-abcxyz.invalid")
    assert isinstance(results, list)
    assert results[0]["id"] == "tls.handshake"
    assert results[0]["passed"] is False


@pytest.mark.asyncio
async def test_headers_google():
    results = await scan_headers("google.com")
    assert len(results) >= 6
    for r in results:
        assert REQUIRED_KEYS.issubset(r.keys()), f"missing keys in {r}"
        assert r["category"] == "headers"

    by_id = {r["id"]: r for r in results}
    # Google sets HSTS and nosniff on its root
    assert by_id["headers.hsts"]["passed"] is True
    assert by_id["headers.nosniff"]["passed"] is True


@pytest.mark.asyncio
async def test_headers_unreachable_doesnt_raise():
    results = await scan_headers("does-not-exist-abcxyz.invalid")
    assert isinstance(results, list)
    assert results[0]["id"] == "headers.fetch"
    assert results[0]["passed"] is False


@pytest.mark.asyncio
async def test_email_google():
    results = await scan_email("google.com")
    assert len(results) >= 5
    for r in results:
        assert REQUIRED_KEYS.issubset(r.keys()), f"missing keys in {r}"
        assert r["category"] == "email"

    by_id = {r["id"]: r for r in results}
    # google.com publishes SPF and DMARC
    assert by_id["email.spf_present"]["passed"] is True
    assert by_id["email.dmarc_present"]["passed"] is True


@pytest.mark.asyncio
async def test_email_nonexistent_doesnt_raise():
    results = await scan_email("this-domain-definitely-does-not-exist-xyz123.invalid")
    assert isinstance(results, list)
    by_id = {r["id"]: r for r in results}
    assert by_id["email.spf_present"]["passed"] is False
    assert by_id["email.dmarc_present"]["passed"] is False
