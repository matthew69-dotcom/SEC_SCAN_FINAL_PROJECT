"""Regression tests for bugs found by the validation harness (2026-10).

1. tls.cert_valid passed for a self-signed certificate (only expiry was
   checked). Now a second, verifying handshake judges the trust chain.
   These tests use a REAL local TLS server so the actual ssl code runs.
2. A single ConnectTimeout on the headers fetch wiped out all 6 header checks
   (thaigov.go.th C73 -> D51). The fetch is now retried once — but never for
   TLS/certificate errors, which are deterministic.
3. A duplicated header ("X-Content-Type-Options: nosniff" sent twice ->
   "nosniff, nosniff") failed headers.nosniff.
"""
from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.scanners import header_scanner, tls_scanner
from app.scanners.header_scanner import _check_nosniff, _check_referrer_policy, scan_headers
from app.scanners.tls_scanner import _verify_chain, scan_tls

HOST = "localhost"


# ─────────────────────────── certificate helpers ────────────────────────────

def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca():
    key = _key()
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Test Root CA")).issuer_name(_name("Test Root CA"))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(issuer_key=None, issuer_cert=None, expired: bool = False):
    """Leaf cert for localhost. No issuer -> self-signed."""
    key = _key()
    now = datetime.now(timezone.utc)
    if expired:
        nb, na = now - timedelta(days=400), now - timedelta(days=30)
    else:
        nb, na = now - timedelta(days=1), now + timedelta(days=90)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(HOST))
        .issuer_name(issuer_cert.subject if issuer_cert else _name(HOST))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return key, cert


def _pem_files(tmp_path, key, cert, name: str):
    cert_path = tmp_path / f"{name}.crt"
    key_path = tmp_path / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class _TLSServer:
    """Tiny TLS server on localhost that completes handshakes then closes."""

    def __init__(self, cert_path, key_path):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.sock = socket.create_server((HOST, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.settimeout(2)
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass  # client rejected our cert — expected in some tests
            finally:
                conn.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


@pytest.fixture
def trust_only(monkeypatch, tmp_path):
    """Make the verifying handshake trust ONLY a test CA (not the OS store).

    Returns (ca_key, ca_cert). Keeps the tests independent of the machine's
    certificate store and of the network.
    """
    ca_key, ca_cert = _make_ca()
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    real = ssl.create_default_context

    def fake_default_context(*args, **kwargs):
        ctx = real(cafile=str(ca_path))
        return ctx

    monkeypatch.setattr(tls_scanner.ssl, "create_default_context", fake_default_context)
    return ca_key, ca_cert


def _by_id(results):
    return {r["id"]: r for r in results}


# ───────────────────────────── 1. trust chain ───────────────────────────────

async def test_trusted_chain_passes(tmp_path, trust_only):
    ca_key, ca_cert = trust_only
    key, cert = _make_leaf(ca_key, ca_cert)
    with _TLSServer(*_pem_files(tmp_path, key, cert, "leaf")) as srv:
        assert _verify_chain(HOST, srv.port) == (True, "")
        results = _by_id(await scan_tls(HOST, srv.port))
    cv = results["tls.cert_valid"]
    assert cv["passed"] is True
    assert "chain trusted" in cv["evidence"]
    assert results["tls.hostname_match"]["passed"] is True


async def test_self_signed_fails_cert_valid(tmp_path, trust_only):
    key, cert = _make_leaf()  # self-signed, not expired, correct hostname
    with _TLSServer(*_pem_files(tmp_path, key, cert, "self")) as srv:
        ok, reason = _verify_chain(HOST, srv.port)
        results = _by_id(await scan_tls(HOST, srv.port))
    assert ok is False
    assert "self" in reason.lower()  # OpenSSL: "self-signed certificate" / "self signed certificate"
    cv = results["tls.cert_valid"]
    assert cv["passed"] is False
    assert cv["severity"] == "critical"
    assert cv["title"] == "Certificate is not trusted"
    assert "self" in cv["evidence"].lower()
    assert "trusted CA" in cv["remediation"]
    # The observation handshake still worked: other checks are reported, and
    # a self-signed cert for the right name is NOT also a hostname failure.
    assert results["tls.handshake"]["passed"] is True
    assert results["tls.hostname_match"]["passed"] is True
    assert results["tls.cert_renewal_buffer"]["passed"] is True


async def test_expired_chain_reports_expiry(tmp_path, trust_only):
    ca_key, ca_cert = trust_only
    key, cert = _make_leaf(ca_key, ca_cert, expired=True)
    with _TLSServer(*_pem_files(tmp_path, key, cert, "expired")) as srv:
        ok, reason = _verify_chain(HOST, srv.port)
        results = _by_id(await scan_tls(HOST, srv.port))
    assert ok is False and "expired" in reason.lower()
    cv = results["tls.cert_valid"]
    assert cv["passed"] is False
    assert cv["title"] == "Certificate is EXPIRED"   # expiry wins over generic "not trusted"
    assert "tls.cert_renewal_buffer" not in results


async def test_wrong_hostname_is_not_double_penalised(tmp_path, trust_only):
    """Trusted chain but scanned under another name -> hostname_match fails,
    cert_valid still passes (hostname checking is off in the trust probe)."""
    ca_key, ca_cert = trust_only
    key, cert = _make_leaf(ca_key, ca_cert)
    with _TLSServer(*_pem_files(tmp_path, key, cert, "leaf")) as srv:
        ok, _ = _verify_chain("127.0.0.1", srv.port)
    assert ok is True


async def test_incomplete_chain_hint():
    fake = {"cert_der": _make_leaf()[1].public_bytes(serialization.Encoding.DER),
            "protocol": "TLSv1.3", "cipher": ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)}
    with patch("app.scanners.tls_scanner._connect_and_inspect", return_value=fake), \
         patch("app.scanners.tls_scanner._verify_chain",
               return_value=(False, "unable to get local issuer certificate")):
        cv = _by_id(await scan_tls(HOST))["tls.cert_valid"]
    assert cv["passed"] is False
    assert "intermediate" in cv["remediation"]


async def test_trust_unknown_does_not_fail_but_says_so():
    """If the verifying handshake itself errors (not a cert error), we do not
    invent a failure — cert_valid passes on expiry and the evidence says
    trust was not verified."""
    fake = {"cert_der": _make_leaf()[1].public_bytes(serialization.Encoding.DER),
            "protocol": "TLSv1.3", "cipher": ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)}
    with patch("app.scanners.tls_scanner._connect_and_inspect", return_value=fake), \
         patch("app.scanners.tls_scanner._verify_chain", return_value=(None, "TimeoutError: timed out")):
        cv = _by_id(await scan_tls(HOST))["tls.cert_valid"]
    assert cv["passed"] is True
    assert "not verified" in cv["evidence"]


async def test_verify_chain_never_raises_on_closed_port():
    s = socket.create_server((HOST, 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    ok, reason = _verify_chain(HOST, port, timeout=2)
    assert ok is None and reason


# ────────────────────────── 2. headers retry ────────────────────────────────

_GOOD = header_scanner._Fetched(httpx.Headers({"x-content-type-options": "nosniff"}),
                                200, "https://example.com/")


@pytest.fixture
def no_delay(monkeypatch):
    monkeypatch.setattr(header_scanner, "_RETRY_DELAY", 0)


async def test_headers_retry_once_on_connect_timeout(no_delay):
    fetch = AsyncMock(side_effect=[httpx.ConnectTimeout("timed out"), _GOOD])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        results = _by_id(await scan_headers("example.com"))
    assert fetch.await_count == 2
    assert results["headers.nosniff"]["passed"] is True
    assert "headers.fetch" not in results


async def test_headers_retry_once_on_connect_error(no_delay):
    fetch = AsyncMock(side_effect=[httpx.ConnectError("connection reset"), _GOOD])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        results = _by_id(await scan_headers("example.com"))
    assert fetch.await_count == 2
    assert len(results) == 6


async def test_headers_gives_up_after_second_failure(no_delay):
    fetch = AsyncMock(side_effect=[httpx.ConnectTimeout("t1"), httpx.ConnectTimeout("t2")])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        results = await scan_headers("example.com")
    assert fetch.await_count == 2
    assert [r["id"] for r in results] == ["headers.fetch"]
    assert "after 2 attempts" in results[0]["evidence"]


async def test_headers_cert_error_not_retried(no_delay):
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
    err.__cause__ = ssl.SSLCertVerificationError(1, "certificate verify failed")
    fetch = AsyncMock(side_effect=[err, _GOOD])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        results = await scan_headers("self-signed.example")
    assert fetch.await_count == 1
    assert results[0]["id"] == "headers.fetch"
    assert "after" not in results[0]["evidence"]


async def test_headers_cert_error_detected_from_message_only(no_delay):
    """Even without an exception chain, an ssl message means: don't retry."""
    fetch = AsyncMock(side_effect=[httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] expired"), _GOOD])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        await scan_headers("expired.example")
    assert fetch.await_count == 1


async def test_headers_other_http_errors_not_retried(no_delay):
    fetch = AsyncMock(side_effect=[httpx.ReadTimeout("read"), _GOOD])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        results = await scan_headers("example.com")
    assert fetch.await_count == 1
    assert results[0]["id"] == "headers.fetch"


async def test_retry_uses_shorter_timeout(no_delay):
    fetch = AsyncMock(side_effect=[httpx.ConnectTimeout("t"), _GOOD])
    with patch("app.scanners.header_scanner._fetch_headers", fetch):
        await scan_headers("example.com")
    first, second = (c.args[1] for c in fetch.await_args_list)
    assert first == header_scanner._FETCH_TIMEOUT
    assert second == header_scanner._RETRY_TIMEOUT
    # worst case must fit the 20s per-host budget of a full scan
    assert first + header_scanner._RETRY_DELAY + second < 20


# ───────────────────────── 3. duplicated headers ────────────────────────────

def _h(*pairs):
    return httpx.Headers(list(pairs))


@pytest.mark.parametrize("pairs,expected", [
    ((("x-content-type-options", "nosniff"),), True),
    ((("x-content-type-options", "nosniff"), ("x-content-type-options", "nosniff")), True),  # thaigov.go.th
    ((("x-content-type-options", "NoSniff"),), True),
    ((("x-content-type-options", "nosniff"), ("x-content-type-options", "sniff")), False),
    ((("x-content-type-options", "sniff"),), False),
    ((), False),
])
def test_nosniff_handles_duplicates(pairs, expected):
    assert _check_nosniff(_h(*pairs))["passed"] is expected


@pytest.mark.parametrize("value,expected", [
    ("strict-origin-when-cross-origin", True),
    ("unsafe-url", False),
    ("no-referrer, unsafe-url", False),           # last value is the effective one
    ("unsafe-url, strict-origin-when-cross-origin", True),
    ("origin-when-cross-origin, strict-origin-when-cross-origin", True),  # github.com
])
def test_referrer_policy_uses_effective_value(value, expected):
    assert _check_referrer_policy(_h(("referrer-policy", value)))["passed"] is expected


# ───────────────────── 4. history timestamps carry UTC ──────────────────────

def test_history_naive_timestamp_serialised_as_utc():
    """SQLite returns naive datetimes; the API must still say they are UTC."""
    from datetime import datetime as _dt

    from app.api.schemas import ScanHistoryItem

    item = ScanHistoryItem(scan_id="x", domain="example.com", mode="single", score=70,
                           grade="C", findings_count=3, created_at=_dt(2026, 10, 20, 3, 0, 0))
    js = item.model_dump_json()
    assert '"created_at":"2026-10-20T03:00:00Z"' in js


def test_history_aware_timestamp_unchanged():
    from datetime import datetime as _dt
    from datetime import timedelta as _td
    from datetime import timezone as _tz

    from app.api.schemas import ScanHistoryItem

    bkk = _tz(_td(hours=7))
    item = ScanHistoryItem(scan_id="x", domain="example.com", mode="single", score=70,
                           grade="C", findings_count=3, created_at=_dt(2026, 10, 20, 10, 0, tzinfo=bkk))
    assert item.created_at.utcoffset() == _td(hours=7)


# ─────────────── 5. evidence says which response was judged ─────────────────

async def test_failing_checks_show_status_and_final_url():
    fetched = header_scanner._Fetched(httpx.Headers({"x-frame-options": "DENY"}),
                                      403, "https://www.wikipedia.org/")
    with patch("app.scanners.header_scanner._fetch_headers", AsyncMock(return_value=fetched)):
        results = _by_id(await scan_headers("wikipedia.org"))
    assert "(HTTP 403 at https://www.wikipedia.org/)" in results["headers.hsts"]["evidence"]
    # passing checks keep their evidence unchanged
    assert results["headers.frame_protection"]["evidence"] == "X-Frame-Options='DENY'"


async def test_real_fetch_records_status_and_final_url():
    """_fetch_headers fills status + final URL from the actual response."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(301, headers={"location": "https://www.example.com/home"})
        return httpx.Response(200, headers={"strict-transport-security": "max-age=31536000"})

    real_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    with patch("app.scanners.header_scanner.httpx.AsyncClient", fake_client):
        fetched = await header_scanner._fetch_headers("https://example.com/")
    assert fetched.status == 200
    assert fetched.final_url == "https://www.example.com/home"
    assert fetched.headers["strict-transport-security"] == "max-age=31536000"


# ─────────── 6. User-Agent carries a contact URL (bot policies) ─────────────

async def test_headers_request_sends_policy_compliant_user_agent():
    """wikipedia.org answered 403 ("Please respect our robot policy") to a
    User-Agent without contact info; the scanner must identify itself."""
    from app.config import SCANNER_USER_AGENT

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ua"] = request.headers.get("user-agent")
        return httpx.Response(200)

    real_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    with patch("app.scanners.header_scanner.httpx.AsyncClient", fake_client):
        await header_scanner._fetch_headers("https://example.com/")
    assert seen["ua"] == SCANNER_USER_AGENT
    assert "https://" in SCANNER_USER_AGENT  # contact URL required by e.g. Wikimedia
