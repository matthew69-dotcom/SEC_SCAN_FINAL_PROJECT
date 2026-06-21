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

import re

import httpx

from app.scanners.base import CheckResult


_HSTS_MIN_MAX_AGE = 15_552_000  # 180 days, our policy threshold


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
    if val and val.lower() == "nosniff":
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
    if val.lower() == "unsafe-url":
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


async def scan_headers(domain: str) -> list[CheckResult]:
    """Fetch https://<domain>/ and evaluate response security headers."""
    url = f"https://{domain}/"
    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "MFU-DomainSecurityChecker/0.1 (senior-project)"},
            verify=True,
        ) as client:
            resp = await client.get(url)
    except httpx.HTTPError as e:
        return [{
            "id": "headers.fetch", "category": "headers",
            "title": "Could not fetch HTTPS response", "passed": False, "severity": "high",
            "evidence": f"{e.__class__.__name__}: {e}",
            "remediation": "Ensure the site responds to HTTPS GET on the root path.",
        }]

    h = resp.headers
    return [
        _check_hsts(h),
        _check_csp(h),
        _check_frame_options(h),
        _check_nosniff(h),
        _check_referrer_policy(h),
        _check_permissions_policy(h),
    ]
