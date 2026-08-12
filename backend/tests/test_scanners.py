"""Integration-ish tests for the Week 2-3 scanners.

These tests hit real DNS/TLS/HTTP endpoints (google.com), so they require network
and will be skipped in CI later. For now, run them locally to verify the scanners
actually behave correctly against well-known domains.

The tls.strong_ciphers tests at the bottom are fully offline (mocked handshake).
"""
from unittest.mock import patch

import pytest

from app.scanners.dns_scanner import scan_dns
from app.scanners.email_scanner import scan_email
from app.scanners.header_scanner import scan_headers
from app.scanners.tls_scanner import _judge_cipher, scan_tls

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
    assert by_id["tls.strong_ciphers"]["passed"] is True  # google negotiates TLS 1.3 AEAD


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
    # Don't assert pass/fail of specific headers on a third-party site —
    # google.com's response headers changed under us twice (HSTS, then
    # nosniff, July 2026). This is a smoke test: the scan ran against a real
    # site and every rubric header check was emitted with a verdict.
    for check_id in (
        "headers.hsts", "headers.csp", "headers.frame_protection",
        "headers.nosniff", "headers.referrer_policy", "headers.permissions_policy",
    ):
        assert check_id in by_id, f"{check_id} not emitted"
        assert isinstance(by_id[check_id]["passed"], bool)


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


# ── tls.strong_ciphers (offline — pure rule + mocked handshake) ─────────────


@pytest.mark.parametrize(
    ("protocol", "name", "bits", "expected"),
    [
        # TLS 1.3 suites are always AEAD + forward secrecy
        ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, True),
        ("TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256", 256, True),
        # Good TLS 1.2: ECDHE/DHE + AEAD
        ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", 128, True),
        ("TLSv1.2", "DHE-RSA-CHACHA20-POLY1305", 256, True),
        # CBC (non-AEAD) fails
        ("TLSv1.2", "ECDHE-RSA-AES256-SHA384", 256, False),
        # Static RSA key exchange (no forward secrecy) fails
        ("TLSv1.2", "AES128-GCM-SHA256", 128, False),
        # Legacy algorithms always fail
        ("TLSv1.2", "ECDHE-RSA-RC4-SHA", 128, False),
        ("TLSv1.2", "DES-CBC3-SHA", 112, False),
        # Weak key strength fails
        ("TLSv1.2", "ECDHE-RSA-AES-GCM", 112, False),
        # Unknown cipher fails safe
        ("TLSv1.2", None, None, False),
    ],
)
def test_judge_cipher(protocol, name, bits, expected):
    passed, reason = _judge_cipher(protocol, name, bits)
    assert passed is expected, f"{name}: {reason}"
    assert reason  # always explains itself


def _fake_cert_der(hostname: str = "example.com") -> bytes:
    """Generate a throwaway self-signed cert so scan_tls can run offline."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


@pytest.mark.asyncio
async def test_tls_strong_ciphers_offline_strong():
    fake = {
        "cert_der": _fake_cert_der(),
        "protocol": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    }
    with patch("app.scanners.tls_scanner._connect_and_inspect", return_value=fake):
        results = await scan_tls("example.com")
    by_id = {r["id"]: r for r in results}
    sc = by_id["tls.strong_ciphers"]
    assert sc["passed"] is True
    assert REQUIRED_KEYS.issubset(sc.keys())
    assert "TLS_AES_256_GCM_SHA384" in sc["evidence"]


@pytest.mark.asyncio
async def test_tls_strong_ciphers_offline_weak():
    fake = {
        "cert_der": _fake_cert_der(),
        "protocol": "TLSv1.2",
        "cipher": ("AES256-SHA", "TLSv1.2", 256),  # static RSA + CBC
    }
    with patch("app.scanners.tls_scanner._connect_and_inspect", return_value=fake):
        results = await scan_tls("example.com")
    by_id = {r["id"]: r for r in results}
    sc = by_id["tls.strong_ciphers"]
    assert sc["passed"] is False
    assert sc["severity"] == "medium"
    assert sc["remediation"]


@pytest.mark.asyncio
async def test_tls_strong_ciphers_missing_cipher_fails_safe():
    fake = {"cert_der": _fake_cert_der(), "protocol": "TLSv1.2", "cipher": None}
    with patch("app.scanners.tls_scanner._connect_and_inspect", return_value=fake):
        results = await scan_tls("example.com")
    by_id = {r["id"]: r for r in results}
    assert by_id["tls.strong_ciphers"]["passed"] is False
