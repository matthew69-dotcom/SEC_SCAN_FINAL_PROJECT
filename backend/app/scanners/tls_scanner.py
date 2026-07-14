"""TLS / HTTPS Scanner.

Checks:
- Certificate is presented at all (port 443 reachable, TLS handshake completes)
- Certificate not expired
- Certificate has >=30 days remaining (renewal buffer)
- Hostname matches the cert (SAN or CN)
- TLS protocol version negotiated is >= 1.2 (no 1.0/1.1)
- Negotiated cipher suite is strong (AEAD + forward secrecy, no legacy algos)

Notes:
- Cipher judgement is based on the suite negotiated in the single observation
  handshake (the server's preferred suite for a modern client) — we do NOT
  probe every cipher individually, keeping the scan lightweight and passive.
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
            cipher = ssock.cipher()  # (name, protocol, secret_bits) or None
            return {"cert_der": cert_der, "protocol": protocol, "cipher": cipher}


# Substrings that mark a cipher suite as legacy/broken regardless of anything else.
_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5", "ANON")


def _judge_cipher(protocol: str, name: str | None, bits: int | None) -> tuple[bool, str]:
    """Pure rule: is the negotiated cipher suite strong? Returns (passed, reason)."""
    if not name:
        return False, "cipher suite could not be determined"
    upper = name.upper()
    for marker in _WEAK_CIPHER_MARKERS:
        if marker in upper:
            return False, f"legacy algorithm in suite ({marker.rstrip('-')})"
    if bits is not None and bits < 128:
        return False, f"key strength below 128 bits ({bits})"
    if protocol == "TLSv1.3":
        # TLS 1.3 only defines AEAD suites with forward secrecy.
        return True, "TLS 1.3 AEAD suite"
    aead = any(m in upper for m in ("GCM", "CHACHA20", "CCM"))
    if not aead:
        return False, "non-AEAD cipher (e.g. CBC mode)"
    forward_secrecy = upper.startswith(("ECDHE", "DHE", "TLS_ECDHE", "TLS_DHE"))
    if not forward_secrecy:
        return False, "no forward secrecy (static RSA key exchange)"
    return True, "AEAD with forward secrecy"


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

    # ── Cipher strength ──────────────────────────────────────────
    cipher = info.get("cipher") or (None, None, None)
    cipher_name, _, cipher_bits = cipher
    strong, reason = _judge_cipher(protocol, cipher_name, cipher_bits)
    if strong:
        checks.append({
            "id": "tls.strong_ciphers", "category": "tls",
            "title": "Strong cipher suite negotiated", "passed": True, "severity": "info",
            "evidence": f"{cipher_name} ({cipher_bits} bits) — {reason}", "remediation": "",
        })
    else:
        checks.append({
            "id": "tls.strong_ciphers", "category": "tls",
            "title": "Weak cipher suite negotiated", "passed": False, "severity": "medium",
            "evidence": f"{cipher_name or 'unknown'} — {reason}",
            "remediation": "Prefer TLS 1.3, or TLS 1.2 with ECDHE + AES-GCM/ChaCha20 suites; "
                           "disable RC4/3DES/CBC and static-RSA key exchange.",
        })

    return checks
