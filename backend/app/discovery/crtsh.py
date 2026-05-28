"""Passive subdomain discovery via Certificate Transparency logs (crt.sh).

Strategy
--------
Query  https://crt.sh/?q=%.{domain}&output=json
Parse the `name_value` field — each entry may contain multiple newline-separated
hostnames (SANs).  Wildcard entries (*.foo.com) are kept as-is; callers decide
whether to strip the leading `*.`.

This is entirely **read-only / passive** — no active probing.
"""
from __future__ import annotations

import logging
import re
from typing import Set

import httpx

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
_WILDCARD_RE = re.compile(r"^\*\.")
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


async def fetch_crtsh_subdomains(domain: str) -> Set[str]:
    """Return a set of hostnames discovered via crt.sh for *domain*.

    Never raises — returns an empty set on any network/parse failure so the
    caller can continue with other sources.

    Parameters
    ----------
    domain:
        Apex domain, e.g. ``"mfu.ac.th"``

    Returns
    -------
    set[str]
        Lowercased, deduplicated hostnames.  May include wildcard entries
        like ``"*.mfu.ac.th"``; the enumerator strips those later.
    """
    results: Set[str] = set()
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(CRTSH_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("crt.sh HTTP error for %s: %s", domain, exc)
        return results
    except httpx.RequestError as exc:
        logger.warning("crt.sh request error for %s: %s", domain, exc)
        return results
    except Exception as exc:  # noqa: BLE001
        logger.warning("crt.sh unexpected error for %s: %s", domain, exc)
        return results

    if not isinstance(data, list):
        logger.warning("crt.sh returned non-list for %s", domain)
        return results

    for entry in data:
        name_value: str = entry.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lower()
            if name and _looks_like_hostname(name, domain):
                results.add(name)

    logger.info("crt.sh found %d raw entries for %s", len(results), domain)
    return results


def _looks_like_hostname(name: str, apex: str) -> bool:
    """Return True if *name* belongs to *apex* (or is a wildcard for it)."""
    # Accept both subdomain.apex.com AND *.apex.com
    clean = _WILDCARD_RE.sub("", name)
    return clean == apex or clean.endswith(f".{apex}")
