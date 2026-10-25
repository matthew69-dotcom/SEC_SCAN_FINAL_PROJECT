"""Per-client rate limiting for POST /api/scan.

Every scan costs real work on third parties (DNS, TLS and HTTP connections,
crt.sh, ip-api.com, and a paid OpenAI call in Full mode), so an anonymous
user must not be able to start unlimited scans.

Limits are per client IP and per mode (sliding window), plus a global cap on
Full scans running at the same time. Kept in memory: enough for a single
backend process (the deployment target); a multi-process deployment would
need a shared store such as Redis.
"""
from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

WINDOW_SECONDS = 60.0
LIMITS = {"single": 10, "full": 2}   # scans per client per window
MAX_CONCURRENT_FULL = 3              # Full scans running at once, all clients


def _is_proxy(host: str | None) -> bool:
    """Requests from loopback/private addresses come through our own proxy
    (Vite dev server, nginx in Docker). Only then do we trust X-Real-IP."""
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host == "testclient"
    return addr.is_loopback or addr.is_private


def client_ip(request: Request) -> str:
    host = request.client.host if request.client else None
    if _is_proxy(host):
        real = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0]
        if real.strip():
            return real.strip()
    return host or "unknown"


class ScanRateLimiter:
    def __init__(self) -> None:
        self.enabled = True
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.full_running = 0

    def reset(self) -> None:
        self._hits.clear()
        self.full_running = 0

    def check(self, ip: str, mode: str, now: float | None = None) -> None:
        """Raise HTTP 429 if this client is over its limit; else record the hit."""
        if not self.enabled:
            return
        now = time.monotonic() if now is None else now
        limit = LIMITS.get(mode, LIMITS["single"])
        hits = self._hits[(ip, mode)]
        while hits and now - hits[0] >= WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= limit:
            retry = max(1, int(WINDOW_SECONDS - (now - hits[0])) + 1)
            raise HTTPException(
                status_code=429,
                detail=f"Too many {mode} scans: at most {limit} per minute. Try again in {retry} s.",
                headers={"Retry-After": str(retry)},
            )
        if mode == "full" and self.full_running >= MAX_CONCURRENT_FULL:
            raise HTTPException(
                status_code=429,
                detail="The server is busy with other full scans. Try again in a minute.",
                headers={"Retry-After": "30"},
            )
        hits.append(now)


limiter = ScanRateLimiter()
