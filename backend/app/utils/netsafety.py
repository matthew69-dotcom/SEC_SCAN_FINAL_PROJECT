"""Network-safety helpers: never connect to non-public addresses.

A public DNS name can point at a private / loopback / link-local address
(e.g. ``ns1.mfu.ac.th -> 192.168.0.3``). If the scanner then opened TCP/TLS
connections to it, it would be probing the *scanner's own* network instead
of the target — a server-side request forgery (SSRF) risk. Every component
that opens a connection must check with :func:`is_public_ip` first.
"""
from __future__ import annotations

import ipaddress
import logging

import dns.asyncresolver

logger = logging.getLogger(__name__)

_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses.

    Rejects private (RFC 1918), loopback, link-local, CGNAT (100.64/10),
    multicast, reserved, unspecified and malformed values.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return False
    return addr.is_global and not addr.is_multicast


async def resolve_ipv4(hostname: str) -> list[str]:
    """All A records for *hostname* via the pinned public resolvers. Never raises."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = _RESOLVERS
    resolver.lifetime = 6.0
    try:
        ans = await resolver.resolve(hostname, "A")
        return [str(r) for r in ans]
    except Exception:  # noqa: BLE001
        return []


async def non_public_ips(hostname: str, known_ip: str | None = None) -> list[str]:
    """Return the non-public addresses *hostname* resolves to (empty = safe).

    Checks every A record, not just the first, so a name with one public and
    one private record is still treated as unsafe.
    """
    ips = await resolve_ipv4(hostname)
    if known_ip and known_ip not in ips:
        ips.append(known_ip)
    return [ip for ip in ips if not is_public_ip(ip)]


__all__ = ["is_public_ip", "non_public_ips", "resolve_ipv4"]
