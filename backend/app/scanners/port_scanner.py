# backend/app/scanners/port_scanner.py
"""
Async TCP port scanner.
Uses asyncio.open_connection() — no raw sockets, no root required.
Never raises: returns empty list on complete failure.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DEFAULT_PORTS: list[int] = [80, 443, 8080, 8443, 8000, 3000]
TIMEOUT = 3.0

_SERVICE_LABELS: dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8000: "HTTP-Dev",
    3000: "HTTP-Dev",
}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str


async def _check_port(host: str, port: int) -> PortResult:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return PortResult(port=port, open=True, service=_SERVICE_LABELS.get(port, str(port)))
    except Exception:  # noqa: BLE001
        return PortResult(port=port, open=False, service=_SERVICE_LABELS.get(port, str(port)))


async def scan_ports(host: str, ports: list[int] | None = None) -> list[PortResult]:
    """
    Scan *ports* on *host* concurrently.
    Returns list of PortResult. Never raises.
    """
    target_ports = ports if ports is not None else DEFAULT_PORTS
    try:
        results = await asyncio.gather(*[_check_port(host, p) for p in target_ports])
        open_ports = [r for r in results if r.open]
        logger.info("port scan %s: open=%s", host, [r.port for r in open_ports])
        return list(results)
    except Exception as exc:  # noqa: BLE001
        logger.warning("port scan failed for %s: %s", host, exc)
        return []


def open_port_numbers(results: list[PortResult]) -> list[int]:
    """Return only the open port numbers."""
    return [r.port for r in results if r.open]
