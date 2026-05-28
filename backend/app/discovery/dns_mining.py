"""Passive subdomain discovery by mining DNS records of the apex domain.

Sources queried
---------------
* **NS records** — authoritative nameserver hostnames
* **MX records** — mail exchanger hostnames
* **Common prefixes** — www, mail, ftp, smtp, imap, vpn, api, dev, staging
  (Not a brute-force wordlist — just 8 universally-published names that are
  almost always intentionally advertised in DNS.)

All queries use the pinned public resolvers (8.8.8.8 / 1.1.1.1) for consistency
with the rest of the scanner stack.  This is **fully passive** — only standard
DNS lookups.
"""
from __future__ import annotations

import logging
from typing import Set

import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

_RESOLVER_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
_COMMON_PREFIXES = ["www", "mail", "ftp", "smtp", "imap", "vpn", "api", "dev", "staging"]


def _make_resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.nameservers = _RESOLVER_NAMESERVERS
    r.lifetime = 10.0
    return r


async def mine_dns_subdomains(domain: str) -> Set[str]:
    """Return hostnames found by mining DNS records of *domain*.

    Never raises — returns whatever was discovered before any error.

    Parameters
    ----------
    domain:
        Apex domain, e.g. ``"mfu.ac.th"``

    Returns
    -------
    set[str]
        Lowercased hostnames that belong to *domain*.
    """
    results: Set[str] = set()
    resolver = _make_resolver()

    # --- NS records ---
    try:
        ns_answer = await resolver.resolve(domain, "NS")
        for rdata in ns_answer:
            ns_host = str(rdata.target).rstrip(".").lower()
            if ns_host.endswith(f".{domain}") or ns_host == domain:
                results.add(ns_host)
    except Exception as exc:  # noqa: BLE001
        logger.debug("NS lookup failed for %s: %s", domain, exc)

    # --- MX records ---
    try:
        mx_answer = await resolver.resolve(domain, "MX")
        for rdata in mx_answer:
            mx_host = str(rdata.exchange).rstrip(".").lower()
            if mx_host.endswith(f".{domain}") or mx_host == domain:
                results.add(mx_host)
    except Exception as exc:  # noqa: BLE001
        logger.debug("MX lookup failed for %s: %s", domain, exc)

    # --- Common prefixes (A record probe — passive, not brute-force) ---
    for prefix in _COMMON_PREFIXES:
        candidate = f"{prefix}.{domain}"
        try:
            await resolver.resolve(candidate, "A")
            results.add(candidate)
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            pass  # Non-existent or unreachable — skip silently

    logger.info("DNS mining found %d hostnames for %s", len(results), domain)
    return results
