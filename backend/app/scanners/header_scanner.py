"""HTTP Security Header Scanner.

Sends a single HTTPS GET to the target and inspects response headers. We follow
redirects so cdn-fronted sites are evaluated at their final destination.

Checks (per the project's Week 4 rubric):
- Strict-Transport-Security  (HSTS, max-age >= 15552000)
- Content-Security-Policy    (presence + not blanket unsafe-inline)
- X-Frame-Options OR CSP frame-ancestors
- X-Content-Type-Options: nosniff
- Referrer-Policy            (and not unsafe-url)
- Permissions-Policy         (presence)

We compare header names case-insensitively (HTTP headers are case-insensitive
per RFC 7230) and only consider the response after redirect chain.
"""
from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass

import httpx

from app.config import SCANNER_USER_AGENT
from app.scanners.base import CheckResult


_HSTS_MIN_MAX_AGE = 15_552_000  # 180 days, our policy threshold
_FETCH_TIMEOUT = 10.0
_RETRY_DELAY = 1.0     # seconds before the single retry
_RETRY_TIMEOUT = 6.0   # shorter, so worst case 10 + 1 + 6 = 17s stays under
                       # the 20s per-host budget in a full scan (routes.HOST_SCAN_TIMEOUT)


def _tokens(value: str) -> list[str]:
    """Split a header value that may hold several comma-joined copies.

    httpx joins repeated headers with ", " (RFC 9110 field combining), so a
    server that sends ``X-Content-Type-Options: nosniff`` twice shows up as
    ``"nosniff, nosniff"``.
    """
    return [t.strip() for t in value.split(",") if t.strip()]


def _is_tls_failure(exc: BaseException) -> bool:
    """True if a connect error was really a TLS/certificate failure.

    httpx wraps ssl errors (e.g. CERTIFICATE_VERIFY_FAILED) in ConnectError.
    Those are deterministic — retrying cannot fix a bad certificate — so we
    must not retry them.
    """
    seen: set[int] = set()
    e: BaseException | None = exc
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, ssl.SSLError):
            return True
        e = e.__cause__ or e.__context__
    text = str(exc)
    return "CERTIFICATE_VERIFY_FAILED" in text or "[SSL" in text


@dataclass
class _Fetched:
    """What we observed: final response headers + where they came from."""
    headers: httpx.Headers
    status: int | None = None
    final_url: str = ""

    def context(self) -> str:
        """e.g. "HTTP 403 at https://www.wikipedia.org/" — appended to failing
        checks so a missing header can be told apart from an error page."""
        parts = []
        if self.status is not None:
            parts.append(f"HTTP {self.status}")
        if self.final_url:
            parts.append(f"at {self.final_url}")
        return " ".join(parts)


async def _fetch_headers(url: str, timeout: float = _FETCH_TIMEOUT) -> _Fetched:
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": SCANNER_USER_AGENT},
        verify=True,
    ) as client:
        # Stream so we only read the response HEADERS and never download
        # the body. Large homepages (e.g. youtube.com) used to eat most of
        # the per-host time budget and made results vary run to run.
        async with client.stream("GET", url) as resp:
            return _Fetched(resp.headers, resp.status_code, str(resp.url))


def _get_header(headers: httpx.Headers, name: str) -> str | None:
    # httpx.Headers does case-insensitive lookup already, but we normalize for safety
    value = headers.get(name)
    return value.strip() if value else None


def _check_hsts(headers: httpx.Headers) -> CheckResult:
    val = _get_header(headers, "strict-transport-security")
    if not val:
        return {
            "id": "headers.hsts", "category": "headers",
            "title": "Missing HSTS header", "passed": False, "severity": "high",
            "evidence": "No Strict-Transport-Security header in response",
            "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        }
    m = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0
    if max_age >= _HSTS_MIN_MAX_AGE:
        return {
            "id": "headers.hsts", "category": "headers",
            "title": "HSTS configured with strong max-age", "passed": True, "severity": "info",
            "evidence": f"max-age={max_age} ({val})", "remediation": "",
        }
    return {
        "id": "headers.hsts", "category": "headers",
        "title": "HSTS max-age too short", "passed": False, "severity": "medium",
        "evidence": f"max-age={max_age} (need >= {_HSTS_MIN_MAX_AGE} = 180 days)",
        "remediation": "Increase max-age to at least 15552000 seconds (180 days). 31536000 (1 year) is recommended.",
    }


def _check_csp(headers: httpx.Headers) -> CheckResult:
    val = _get_header(headers, "content-security-policy")
    if not val:
        return {
            "id": "headers.csp", "category": "headers",
            "title": "Missing Content-Security-Policy", "passed": False, "severity": "high",
            "evidence": "No CSP header in response",
            "remediation": "Add a Content-Security-Policy header. Start with `default-src 'self'` and tighten.",
        }
    # Crude detection of blanket unsafe-inline across multiple directives.
    if val.lower().count("'unsafe-inline'") >= 2:
        return {
            "id": "headers.csp", "category": "headers",
            "title": "CSP relies on unsafe-inline", "passed": False, "severity": "medium",
            "evidence": "CSP allows 'unsafe-inline' in multiple directives",
            "remediation": "Replace 'unsafe-inline' with nonces or hashes to enable real XSS protection.",
        }
    return {
        "id": "headers.csp", "category": "headers",
        "title": "Content-Security-Policy configured", "passed": True, "severity": "info",
        "evidence": val[:140] + ("..." if len(val) > 140 else ""),
        "remediation": "",
    }


def _check_frame_options(headers: httpx.Headers) -> CheckResult:
    xfo = _get_header(headers, "x-frame-options")
    csp = _get_header(headers, "content-security-policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if xfo or has_frame_ancestors:
        return {
            "id": "headers.frame_protection", "category": "headers",
            "title": "Clickjacking protection in place", "passed": True, "severity": "info",
            "evidence": f"X-Frame-Options={xfo!r}" if xfo else "CSP has frame-ancestors directive",
            "remediation": "",
        }
    return {
        "id": "headers.frame_protection", "category": "headers",
        "title": "No clickjacking protection", "passed": False, "severity": "medium",
        "evidence": "Neither X-Frame-Options nor CSP frame-ancestors present",
        "remediation": "Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.",
    }


def _check_nosniff(headers: httpx.Headers) -> CheckResult:
    val = _get_header(headers, "x-content-type-options")
    # A duplicated header ("nosniff, nosniff") is still nosniff.
    if val and _tokens(val) and all(t.lower() == "nosniff" for t in _tokens(val)):
        return {
            "id": "headers.nosniff", "category": "headers",
            "title": "X-Content-Type-Options: nosniff set", "passed": True, "severity": "info",
            "evidence": val, "remediation": "",
        }
    return {
        "id": "headers.nosniff", "category": "headers",
        "title": "Missing X-Content-Type-Options", "passed": False, "severity": "low",
        "evidence": f"value={val!r}" if val else "header not present",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    }


def _check_referrer_policy(headers: httpx.Headers) -> CheckResult:
    val = _get_header(headers, "referrer-policy")
    if not val:
        return {
            "id": "headers.referrer_policy", "category": "headers",
            "title": "Missing Referrer-Policy", "passed": False, "severity": "low",
            "evidence": "header not present",
            "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        }
    # Referrer-Policy may list fallbacks; browsers use the LAST value they
    # understand, so judge the effective (last) token.
    effective = (_tokens(val) or [val])[-1].lower()
    if effective == "unsafe-url":
        return {
            "id": "headers.referrer_policy", "category": "headers",
            "title": "Referrer-Policy set to unsafe-url", "passed": False, "severity": "low",
            "evidence": val,
            "remediation": "Change to a privacy-preserving policy like strict-origin-when-cross-origin.",
        }
    return {
        "id": "headers.referrer_policy", "category": "headers",
        "title": "Referrer-Policy set", "passed": True, "severity": "info",
        "evidence": val, "remediation": "",
    }


def _check_permissions_policy(headers: httpx.Headers) -> CheckResult:
    val = _get_header(headers, "permissions-policy")
    if val:
        return {
            "id": "headers.permissions_policy", "category": "headers",
            "title": "Permissions-Policy set", "passed": True, "severity": "info",
            "evidence": val[:140] + ("..." if len(val) > 140 else ""),
            "remediation": "",
        }
    return {
        "id": "headers.permissions_policy", "category": "headers",
        "title": "Missing Permissions-Policy", "passed": False, "severity": "low",
        "evidence": "header not present",
        "remediation": "Add a Permissions-Policy header to restrict browser features (camera, geolocation, etc.).",
    }


def _fetch_failed(e: BaseException, attempts: int) -> CheckResult:
    suffix = f" (after {attempts} attempts)" if attempts > 1 else ""
    return {
        "id": "headers.fetch", "category": "headers",
        "title": "Could not fetch HTTPS response", "passed": False, "severity": "high",
        "evidence": f"{e.__class__.__name__}: {e}{suffix}",
        "remediation": "Ensure the site responds to HTTPS GET on the root path.",
    }


async def scan_headers(domain: str) -> list[CheckResult]:
    """Fetch https://<domain>/ and evaluate response security headers."""
    url = f"https://{domain}/"
    attempts = 0
    while True:
        attempts += 1
        try:
            fetched = await _fetch_headers(url, _FETCH_TIMEOUT if attempts == 1 else _RETRY_TIMEOUT)
            break
        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            # One retry for transient network failures only (seen in
            # validation: a single ConnectTimeout cost thaigov.go.th 22
            # points). TLS/certificate failures are never retried.
            if attempts == 1 and not _is_tls_failure(e):
                await asyncio.sleep(_RETRY_DELAY)
                continue
            return [_fetch_failed(e, attempts)]
        except httpx.HTTPError as e:
            return [_fetch_failed(e, attempts)]

    h = fetched.headers
    checks = [
        _check_hsts(h),
        _check_csp(h),
        _check_frame_options(h),
        _check_nosniff(h),
        _check_referrer_policy(h),
        _check_permissions_policy(h),
    ]
    # Say which response was judged, so "header missing" on an error page
    # (e.g. a 403 for our User-Agent) is visible in the evidence.
    ctx = fetched.context()
    if ctx:
        for c in checks:
            if not c["passed"]:
                c["evidence"] = f"{c['evidence']} ({ctx})"
    return checks
