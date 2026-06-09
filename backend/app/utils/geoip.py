# backend/app/utils/geoip.py
"""
Geo-IP lookup via ip-api.com (free tier, no API key required).
Rate limit: 45 req/min for HTTP.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as"
TIMEOUT = 5.0


@dataclass
class GeoInfo:
    country: str | None = None
    region: str | None = None
    city: str | None = None
    isp: str | None = None
    org: str | None = None
    asn: str | None = None

    @property
    def location(self) -> str | None:
        parts = [p for p in [self.city, self.region, self.country] if p]
        return ", ".join(parts) if parts else None


async def lookup(ip: str) -> GeoInfo:
    """Return GeoInfo for an IP. Never raises — returns empty GeoInfo on failure."""
    if not ip or ip in ("-", "unknown"):
        return GeoInfo()
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(GEOIP_URL.format(ip=ip))
            data = resp.json()
            if data.get("status") != "success":
                return GeoInfo()
            return GeoInfo(
                country=data.get("country"),
                region=data.get("regionName"),
                city=data.get("city"),
                isp=data.get("isp"),
                org=data.get("org"),
                asn=data.get("as"),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("geoip lookup failed for %s: %s", ip, exc)
        return GeoInfo()


async def lookup_many(ips: list[str]) -> dict[str, GeoInfo]:
    """Lookup multiple IPs concurrently. Returns {ip: GeoInfo}."""
    unique = list(set(ips))
    results = await asyncio.gather(*[lookup(ip) for ip in unique])
    return dict(zip(unique, results))
