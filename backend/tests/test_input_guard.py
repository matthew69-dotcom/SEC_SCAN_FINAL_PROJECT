"""Input and abuse guards for POST /api/scan.

- Gibberish that looks like a domain ("ivjowsefhvwieh.com") must not be
  graded: an NXDOMAIN answer rejects the request before any scan or save.
- Domain syntax follows RFC 1123; Thai (IDN) names are converted to punycode.
- Each client is rate-limited per mode, and concurrent Full scans are capped.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.exception
import dns.resolver
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.requests import Request

from app.api.schemas import ScanRequest, ScanResponse, VersionInfo
from app.main import app
from app.utils import ratelimit
from app.utils.netsafety import domain_exists
from app.utils.ratelimit import ScanRateLimiter, client_ip

client = TestClient(app)


def _fake_response(domain: str = "example.com", mode: str = "single") -> ScanResponse:
    return ScanResponse(scan_id="t", domain=domain, mode=mode, score=50, grade="D",
                        version=VersionInfo(app="t", model="t", rubric=1))


@pytest.fixture
def fast_scan():
    """Replace the actual scanning with an instant fake result."""
    async def _fake(req, session):
        return _fake_response(req.domain, req.mode)
    with patch("app.api.routes._scan", side_effect=_fake) as m:
        yield m


# ───────────────────────────── domain syntax ────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  HTTPS://Example.COM/  ", "example.com"),
    ("example.com.", "example.com"),                    # trailing root dot
    ("www.mfu.ac.th", "www.mfu.ac.th"),
    ("a-b.example.com", "a-b.example.com"),
    ("ไทย.com", "xn--o3cw4h.com"),                      # Thai IDN -> punycode
    ("มหาวิทยาลัย.ไทย", "xn--o3cteaoj1a6cedt.xn--o3cw4h"),  # Thai TLD too
    ("xn--o3cw4h.com", "xn--o3cw4h.com"),
])
def test_valid_domains_are_normalised(raw, expected):
    assert ScanRequest(domain=raw).domain == expected


@pytest.mark.parametrize("raw", [
    "ivjowsefhvwieh",               # no dot
    "not a domain",
    "-bad.com", "bad-.com",         # label starts/ends with hyphen
    "x" * 64 + ".com",              # label longer than 63
    "a..com",
    "127.0.0.1", "192.168.1.1",     # bare IPs (no alphabetic TLD)
    "localhost",
    "google.com/path", "google.com:8080", "ftp://google.com",
    "user@google.com", "*.google.com",
    "<script>alert(1)</script>", "google.com; rm -rf /",
])
def test_invalid_domains_are_rejected(raw):
    with pytest.raises(ValidationError) as e:
        ScanRequest(domain=raw)
    assert "Enter a domain name like example.com" in str(e.value) or "at least 3" in str(e.value)


def test_invalid_domain_message_reaches_the_api():
    r = client.post("/api/scan", json={"domain": "ivjowsefhvwieh"})
    assert r.status_code == 422
    assert "Enter a domain name like example.com" in r.json()["detail"][0]["msg"]


# ───────────────────────── domain must exist (NXDOMAIN) ─────────────────────

def test_nonexistent_domain_is_rejected_and_not_saved(_hermetic_domain_exists, fast_scan):
    _hermetic_domain_exists.return_value = False
    with patch("app.api.routes._save_scan", AsyncMock()) as save:
        r = client.post("/api/scan", json={"domain": "ivjowsefhvwieh.com"})
    assert r.status_code == 422
    assert "does not exist" in r.json()["detail"]
    fast_scan.assert_not_called()
    save.assert_not_awaited()


def test_nonexistent_idn_shown_in_its_own_script(_hermetic_domain_exists, fast_scan):
    _hermetic_domain_exists.return_value = False
    r = client.post("/api/scan", json={"domain": "ไทย.com"})
    assert r.status_code == 422
    assert r.json()["detail"].startswith("ไทย.com does not exist")


def test_unknown_dns_answer_still_scans(_hermetic_domain_exists, fast_scan):
    _hermetic_domain_exists.return_value = None    # e.g. DNS timeout
    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 200
    fast_scan.assert_called_once()




@pytest.mark.parametrize("exc,expected", [
    (dns.resolver.NXDOMAIN(), False),
    (dns.resolver.NoAnswer(), True),         # exists, just no A record
    (dns.exception.Timeout(), None),         # unknown -> never "does not exist"
    (dns.resolver.NoNameservers(), None),
])
async def test_domain_exists_classification(exc, expected):
    async def _r(self, name, rtype):
        raise exc
    with patch("dns.asyncresolver.Resolver.resolve", _r):
        assert await domain_exists("whatever.example") is expected


async def test_domain_exists_true_on_answer():
    async def _r(self, name, rtype):
        return ["93.184.216.34"]
    with patch("dns.asyncresolver.Resolver.resolve", _r):
        assert await domain_exists("example.com") is True


# ──────────────────────────────── rate limit ────────────────────────────────

def test_single_scans_limited_per_client(_no_rate_limit, fast_scan):
    _no_rate_limit.enabled = True
    for _ in range(ratelimit.LIMITS["single"]):
        assert client.post("/api/scan", json={"domain": "example.com"}).status_code == 200
    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 429
    assert "Too many single scans" in r.json()["detail"]
    assert int(r.headers["retry-after"]) >= 1


def test_full_scans_have_a_lower_limit(_no_rate_limit, fast_scan):
    _no_rate_limit.enabled = True
    for _ in range(ratelimit.LIMITS["full"]):
        assert client.post("/api/scan", json={"domain": "example.com", "mode": "full"}).status_code == 200
    assert client.post("/api/scan", json={"domain": "example.com", "mode": "full"}).status_code == 429
    # Single mode has its own budget
    assert client.post("/api/scan", json={"domain": "example.com"}).status_code == 200


def test_limits_are_per_client(_no_rate_limit, fast_scan):
    _no_rate_limit.enabled = True
    for _ in range(ratelimit.LIMITS["full"]):
        client.post("/api/scan", json={"domain": "example.com", "mode": "full"},
                    headers={"X-Real-IP": "203.0.113.1"})
    blocked = client.post("/api/scan", json={"domain": "example.com", "mode": "full"},
                          headers={"X-Real-IP": "203.0.113.1"})
    other = client.post("/api/scan", json={"domain": "example.com", "mode": "full"},
                        headers={"X-Real-IP": "203.0.113.2"})
    assert blocked.status_code == 429
    assert other.status_code == 200


def test_window_slides():
    lim = ScanRateLimiter()
    for i in range(ratelimit.LIMITS["full"]):
        lim.check("1.2.3.4", "full", now=100.0 + i)
    with pytest.raises(Exception) as e:
        lim.check("1.2.3.4", "full", now=110.0)
    assert e.value.status_code == 429
    lim.check("1.2.3.4", "full", now=100.0 + ratelimit.WINDOW_SECONDS + 1)  # oldest expired


def test_concurrent_full_scans_capped():
    lim = ScanRateLimiter()
    lim.full_running = ratelimit.MAX_CONCURRENT_FULL
    with pytest.raises(Exception) as e:
        lim.check("1.2.3.4", "full", now=1.0)
    assert e.value.status_code == 429
    assert "busy" in e.value.detail
    lim.check("1.2.3.4", "single", now=1.0)   # single scans unaffected


def test_full_running_counter_released_after_scan(_no_rate_limit, fast_scan):
    client.post("/api/scan", json={"domain": "example.com", "mode": "full"})
    assert _no_rate_limit.full_running == 0


def test_full_running_counter_released_after_error(_no_rate_limit):
    with patch("app.api.routes._scan", AsyncMock(side_effect=RuntimeError("boom"))):
        with pytest.raises(RuntimeError):
            client.post("/api/scan", json={"domain": "example.com", "mode": "full"})
    assert _no_rate_limit.full_running == 0


# ───────────────────────── client IP (proxy-aware) ──────────────────────────

def _req(host: str, headers: dict[str, str]) -> Request:
    return Request({"type": "http", "client": (host, 1234),
                    "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]})


def test_x_real_ip_trusted_from_local_proxy():
    assert client_ip(_req("127.0.0.1", {"X-Real-IP": "203.0.113.9"})) == "203.0.113.9"
    assert client_ip(_req("172.18.0.3", {"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})) == "203.0.113.9"


def test_x_real_ip_ignored_from_public_client():
    """A client on the internet cannot dodge its limit by sending X-Real-IP."""
    assert client_ip(_req("8.8.8.8", {"X-Real-IP": "203.0.113.9"})) == "8.8.8.8"
