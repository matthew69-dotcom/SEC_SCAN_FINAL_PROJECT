"""TLS / HTTPS Scanner.

Checks:
- Certificate is presented at all (port 443 reachable, TLS handshake completes)
- Certificate not expired
- Certificate has >=30 days remaining (renewal buffer)
- Hostname matches the cert (SAN or CN)
- TLS protocol version negotiated is >= 1.2 (no 1.0/1.1)

Notes for Week 2:
- Does NOT enumerate ciphers (would need probing each cipher; deferred to a later
  iteration). For now we trust the negotiated protocol as a strong signal.
- All blocking socket work is offloaded to a thread with asyncio.to_thread so we
  don't stall the event loop.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.scanners.base import CheckResult


def _connect_and_inspect(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Blocking helper: open TLS connection, fetch peer cert + negotiated protocol."""
    ctx = ssl.create_default_context()
    # We want to *observe* the cert even if validation would fail (so we can
    # still report e.g. an expired cert as a finding). The scanner judges, not ssl.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            protocol = ssock.version()
            return {"cert_der": cert_der, "protocol": protocol}


def _hostname_matches(cert: x509.Certificate, hostname: str) -> bool:
    """Wildcard-aware match of hostname against SAN entries (or CN as fallback)."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    candidates: list[str] = list(sans)
    if not candidates:
        # Fall back to CN
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                candidates.append(str(attr.value))

    hostname = hostname.lower()
    for c in candidates:
        c = c.lower()
        if c == hostname:
            return True
        if c.startswith("*."):
            # *.example.com matches foo.example.com but not example.com
            suffix = c[1:]  # ".example.com"
            if hostname.endswith(suffix) and hostname.count(".") == c.count("."):
                return True
    return False


async def scan_tls(domain: str, port: int = 443) -> list[CheckResult]:
    checks: list[CheckResult] = []

    try:
        info = await asyncio.to_thread(_connect_and_inspect, domain, port)
    except (socket.gaierror, OSError, ssl.SSLError, TimeoutError) as e:
        checks.append({
            "id": "tls.handshake", "category": "tls",
            "title": "TLS handshake failed", "passed": False, "severity": "critical",
            "evidence": f"{e.__class__.__name__}: {e}",
            "remediation": "Ensure HTTPS is reachable on port 443 with a valid TLS certificate.",
        })
        return checks

    cert = x509.load_der_x509_certificate(info["cert_der"], default_backend())
    protocol = info["protocol"] or "unknown"

    checks.append({
        "id": "tls.handshake", "category": "tls",
        "title": "TLS handshake succeeded", "passed": True, "severity": "info",
        "evidence": f"Negotiated: {protocol}", "remediation": "",
    })

    # ── Cert expiry ──────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    # cryptography >= 42 deprecated not_valid_after; use *_utc when available
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - now).days

    if days_left < 0:
        checks.append({
            "id": "tls.cert_valid", "category": "tls",
            "title": "Certificate is EXPIRED", "passed": False, "severity": "critical",
            "evidence": f"Expired {abs(days_left)} days ago ({not_after.date().isoformat()})",
            "remediation": "Renew the TLS certificate immediately (e.g. via Let's Encrypt / ACME).",
        })
    else:
        checks.append({
            "id": "tls.cert_valid", "category": "tls",
            "title": "Certificate is valid", "passed": True, "severity": "info",
            "evidence": f"Expires {not_after.date().isoformat()} ({days_left} days left)",
            "remediation": "",
        })
        # ── Renewal buffer ──────────────────────────────
        if days_left >= 30:
            checks.append({
                "id": "tls.cert_renewal_buffer", "category": "tls",
                "title": "Certificate has comfortable renewal buffer", "passed": True, "severity": "info",
                "evidence": f"{days_left} days remaining", "remediation": "",
            })
        else:
            checks.append({
                "id": "tls.cert_renewal_buffer", "category": "tls",
                "title": "Certificate expires soon", "passed": False, "severity": "high",
                "evidence": f"only {days_left} days remaining",
                "remediation": "Renew the certificate now to avoid an outage.",
            })

    # ── Hostname match ───────────────────────────────────────────
    if _hostname_matches(cert, domain):
        checks.append({
            "id": "tls.hostname_match", "category": "tls",
            "title": "Hostname matches certificate", "passed": True, "severity": "info",
            "evidence": f"{domain} is covered by SAN/CN", "remediation": "",
        })
    else:
        checks.append({
            "id": "tls.hostname_match", "category": "tls",
            "title": "Hostname does not match certificate", "passed": False, "severity": "high",
            "evidence": f"{domain} is not in the cert's SAN list",
            "remediation": "Reissue the cert to include the correct hostname(s).",
        })

    # ── Protocol version ─────────────────────────────────────────
    weak = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
    if protocol in weak:
        checks.append({
            "id": "tls.modern_protocol", "category": "tls",
            "title": f"Weak TLS protocol negotiated ({protocol})", "passed": False, "severity": "high",
            "evidence": f"Server accepted {protocol}",
            "remediation": "Disable TLS 1.0/1.1 in your web server config. Require TLS 1.2 or higher.",
        })
    else:
        checks.append({
            "id": "tls.modern_protocol", "category": "tls",
            "title": "Modern TLS protocol in use", "passed": True, "severity": "info",
            "evidence": f"Negotiated {protocol}", "remediation": "",
        })

    return checks
