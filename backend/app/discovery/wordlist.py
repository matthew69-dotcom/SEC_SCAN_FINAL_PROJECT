# backend/app/discovery/wordlist.py
"""
Wordlist-based subdomain brute-force enumeration.
Resolves each candidate against 8.8.8.8 / 1.1.1.1 concurrently.
"""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

# Top ~120 common subdomains
COMMON_SUBDOMAINS: list[str] = [
    "www", "mail", "smtp", "pop", "pop3", "imap", "ftp", "sftp",
    "webmail", "mx", "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "api", "api2", "dev", "dev2", "staging", "stage", "test", "qa",
    "uat", "sandbox", "demo", "preview",
    "admin", "administrator", "panel", "dashboard", "portal", "cpanel",
    "phpmyadmin", "backend", "frontend",
    "blog", "news", "media", "static", "assets", "cdn", "img", "images",
    "files", "docs", "wiki", "kb", "help", "support", "service",
    "app", "apps", "mobile", "m", "wap",
    "store", "shop", "cart", "checkout", "payment",
    "auth", "login", "sso", "oauth", "id", "account", "accounts",
    "vpn", "remote", "ssh", "git", "gitlab", "github", "svn",
    "ci", "cd", "jenkins", "jira", "confluence", "slack",
    "monitoring", "grafana", "prometheus", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "s3", "backup", "archive",
    "status", "health", "ping",
    "smtp1", "smtp2", "relay", "gateway",
    "intranet", "internal", "corp", "office",
    "v1", "v2", "old", "new", "beta",
    "secure", "ssl", "tls",
    "www2", "www3",
]

RESOLVERS = ["8.8.8.8", "1.1.1.1"]
TIMEOUT = 3.0
CONCURRENCY = 50


async def _resolve_candidate(
    hostname: str,
    semaphore: asyncio.Semaphore,
) -> str | None:
    """Return hostname if it resolves, else None."""
    async with semaphore:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = RESOLVERS
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        try:
            await resolver.resolve(hostname, "A")
            return hostname
        except Exception:  # noqa: BLE001
            return None


async def brute_force(domain: str, wordlist: list[str] | None = None) -> set[str]:
    """
    Resolve all wordlist candidates for *domain*.
    Returns set of live hostnames.
    """
    words = wordlist if wordlist is not None else COMMON_SUBDOMAINS
    candidates = [f"{w}.{domain}" for w in words]

    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [_resolve_candidate(h, semaphore) for h in candidates]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    found = {h for h in results if h is not None}
    logger.info(
        "wordlist brute-force: %d/%d candidates resolved for %s",
        len(found), len(candidates), domain,
    )
    return found
