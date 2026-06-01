"""Orchestrates all passive subdomain sources and returns live, scannable hosts.

Pipeline
--------
1. Gather candidates from crt.sh + DNS mining (run concurrently).
2. Always include the apex domain itself.
3. Strip wildcard entries (``*.foo.com`` → discard; we can't scan ``*``).
4. Deduplicate (case-insensitive).
5. Resolve each candidate to at least one A record (proves it's alive).
6. Return list of ``DiscoveredHost`` objects sorted by hostname.

The caller (routes.py) then scans each host independently.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception

from app.discovery.crtsh import fetch_crtsh_subdomains
from app.discovery.dns_mining import mine_dns_subdomains

logger = logging.getLogger(__name__)

_RESOLVER_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
_WILDCARD_RE = re.compile(r"^\*\.")

# How many A-record resolutions to run in parallel
_RESOLVE_CONCURRENCY = 20


@dataclass
class DiscoveredHost:
    hostname: str
    ip: str  # first resolved A record — informational only


def _make_resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.nameservers = _RESOLVER_NAMESERVERS
    r.lifetime = 8.0
    return r


async def _resolve_a(hostname: str, resolver: dns.asyncresolver.Resolver) -> str | None:
    """Return the first A record IP for *hostname*, or None if unresolvable."""
    try:
        answer = await resolver.resolve(hostname, "A")
        return str(answer[0])
    except Exception:  # noqa: BLE001
        return None


async def enumerate_hosts(domain: str) -> list[DiscoveredHost]:
    """Discover all live hosts inside *domain* using passive techniques.

    Parameters
    ----------
    domain:
        Apex domain, e.g. ``"mfu.ac.th"``

    Returns
    -------
    list[DiscoveredHost]
        Sorted list of resolvable hosts.  Always includes the apex itself
        (if it has an A record).  Never raises.
    """
    # 1. Gather from all sources concurrently
    crtsh_results, dns_results = await asyncio.gather(
        fetch_crtsh_subdomains(domain),
        mine_dns_subdomains(domain),
        return_exceptions=True,
    )

    candidates: set[str] = {domain}  # always include apex

    for result in (crtsh_results, dns_results):
        if isinstance(result, set):
            candidates |= result
        elif isinstance(result, Exception):
            logger.warning("Discovery source error: %s", result)

    # 2. Strip wildcards + normalize
    cleaned: set[str] = set()
    for name in candidates:
        name = name.strip().lower()
        if _WILDCARD_RE.match(name):
            continue  # can't scan *.foo.com
        cleaned.add(name)

    logger.info("Enumerated %d unique candidate hosts for %s", len(cleaned), domain)

    # 3. Resolve each candidate to an A record (liveness check)
    resolver = _make_resolver()
    sem = asyncio.Semaphore(_RESOLVE_CONCURRENCY)

    async def _resolve_with_sem(hostname: str) -> tuple[str, str | None]:
        async with sem:
            ip = await _resolve_a(hostname, resolver)
            return hostname, ip

    resolve_tasks = [_resolve_with_sem(h) for h in cleaned]
    resolved = await asyncio.gather(*resolve_tasks, return_exceptions=True)

    live_hosts: list[DiscoveredHost] = []
    for item in resolved:
        if isinstance(item, Exception):
            continue
        hostname, ip = item
        if ip is not None:
            live_hosts.append(DiscoveredHost(hostname=hostname, ip=ip))

    live_hosts.sort(key=lambda h: h.hostname)
    logger.info(
        "Enumeration complete: %d live hosts out of %d candidates for %s",
        len(live_hosts), len(cleaned), domain,
    )
    return live_hosts
