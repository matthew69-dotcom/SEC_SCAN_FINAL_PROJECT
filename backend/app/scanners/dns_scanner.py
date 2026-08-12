"""DNS Security Scanner.

Checks:
- A record exists (basic sanity)
- MX record exists (so domain can receive email)
- At least 2 NS records (redundancy)
- CAA record present (restricts which CAs can issue certs)
- DNSSEC enabled (signed responses)
- No wildcard A record exposed (catches misconfigurations)

All checks run in parallel via asyncio.
"""
from __future__ import annotations

import asyncio
import secrets

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from app.scanners.base import CheckResult


# Shared resolver pinned to public resolvers.
#
# Why pin: on some networks (campus, ISPs with deep packet inspection, captive
# portals, corporate proxies) dnspython picking up the OS resolver returns
# NoNameservers for TXT/CAA lookups even though the records exist. Pinning to
# Google + Cloudflare gives reproducible results across machines — which is a
# project non-negotiable (deterministic scoring) — and removes the SPF
# false-negative observed in Week 3.
_resolver = dns.asyncresolver.Resolver(configure=False)
_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
_resolver.timeout = 4.0
_resolver.lifetime = 8.0


async def _resolve(name: str, rdtype: str):
    """Wrap resolve() and translate exceptions to a tuple (records, error_msg)."""
    try:
        ans = await _resolver.resolve(name, rdtype)
        return list(ans), None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN (domain does not exist)"
    except dns.resolver.NoAnswer:
        return [], "no records of this type"
    except dns.exception.Timeout:
        return [], "DNS query timed out"
    except dns.exception.DNSException as e:
        return [], f"DNS error: {e.__class__.__name__}"


async def _check_a(domain: str) -> CheckResult:
    records, err = await _resolve(domain, "A")
    if records:
        ips = ", ".join(r.address for r in records)
        return {
            "id": "dns.a_record", "category": "dns",
            "title": "A record present", "passed": True, "severity": "info",
            "evidence": f"Resolves to: {ips}", "remediation": "",
        }
    return {
        "id": "dns.a_record", "category": "dns",
        "title": "Missing A record", "passed": False, "severity": "critical",
        "evidence": err or "no A records",
        "remediation": "Add an A record pointing to your server's IPv4 address.",
    }


async def _check_mx(domain: str) -> CheckResult:
    records, err = await _resolve(domain, "MX")
    if records:
        hosts = ", ".join(str(r.exchange).rstrip(".") for r in records)
        return {
            "id": "dns.mx_record", "category": "dns",
            "title": "MX record present", "passed": True, "severity": "info",
            "evidence": f"Mail servers: {hosts}", "remediation": "",
        }
    return {
        "id": "dns.mx_record", "category": "dns",
        "title": "No MX record", "passed": False, "severity": "low",
        "evidence": err or "no MX records",
        "remediation": "If this domain sends/receives email, add an MX record.",
    }


async def _check_ns(domain: str) -> CheckResult:
    records, err = await _resolve(domain, "NS")
    count = len(records)
    if count >= 2:
        hosts = ", ".join(str(r.target).rstrip(".") for r in records)
        return {
            "id": "dns.ns_redundancy", "category": "dns",
            "title": "Multiple nameservers (redundant)", "passed": True, "severity": "info",
            "evidence": f"{count} nameservers: {hosts}", "remediation": "",
        }
    return {
        "id": "dns.ns_redundancy", "category": "dns",
        "title": "Insufficient nameserver redundancy", "passed": False, "severity": "medium",
        "evidence": err or f"only {count} NS record(s)",
        "remediation": "Configure at least 2 nameservers for failover.",
    }


async def _check_caa(domain: str) -> CheckResult:
    records, err = await _resolve(domain, "CAA")
    if records:
        values = ", ".join(str(r) for r in records)
        return {
            "id": "dns.caa", "category": "dns",
            "title": "CAA record set", "passed": True, "severity": "info",
            "evidence": values, "remediation": "",
        }
    return {
        "id": "dns.caa", "category": "dns",
        "title": "No CAA record", "passed": False, "severity": "medium",
        "evidence": err or "no CAA records",
        "remediation": 'Add a CAA record (e.g. `0 issue "letsencrypt.org"`) to restrict which CAs can issue certs for your domain.',
    }


async def _check_dnssec(domain: str) -> CheckResult:
    # DNSSEC = presence of DS record at the parent OR RRSIG when querying with DO=1
    records, err = await _resolve(domain, "DNSKEY")
    if records:
        return {
            "id": "dns.dnssec", "category": "dns",
            "title": "DNSSEC enabled", "passed": True, "severity": "info",
            "evidence": f"{len(records)} DNSKEY record(s) present", "remediation": "",
        }
    return {
        "id": "dns.dnssec", "category": "dns",
        "title": "DNSSEC not enabled", "passed": False, "severity": "medium",
        "evidence": err or "no DNSKEY records",
        "remediation": "Enable DNSSEC at your DNS provider to cryptographically sign responses.",
    }


async def _check_wildcard(domain: str) -> CheckResult:
    # If a random subdomain resolves, the domain has a wildcard A record exposed.
    random_label = secrets.token_hex(8)
    records, _ = await _resolve(f"{random_label}.{domain}", "A")
    if records:
        return {
            "id": "dns.wildcard_exposed", "category": "dns",
            "title": "Wildcard A record exposed", "passed": False, "severity": "low",
            "evidence": f"{random_label}.{domain} resolves (likely *.{domain})",
            "remediation": "Review your wildcard A record — it may catch typo-squat subdomains.",
        }
    return {
        "id": "dns.wildcard_exposed", "category": "dns",
        "title": "No public wildcard A record", "passed": True, "severity": "info",
        "evidence": f"random subdomain does not resolve", "remediation": "",
    }


async def scan_dns(domain: str) -> list[CheckResult]:
    """Run all DNS checks concurrently and return a flat list of results."""
    results = await asyncio.gather(
        _check_a(domain),
        _check_mx(domain),
        _check_ns(domain),
        _check_caa(domain),
        _check_dnssec(domain),
        _check_wildcard(domain),
        return_exceptions=True,
    )
    # Convert any raised exceptions into a failed-info check
    safe: list[CheckResult] = []
    for r in results:
        if isinstance(r, Exception):
            safe.append({
                "id": "dns.error", "category": "dns",
                "title": "Internal DNS scan error", "passed": False, "severity": "low",
                "evidence": f"{r.__class__.__name__}: {r}", "remediation": "",
            })
        else:
            safe.append(r)
    return safe
