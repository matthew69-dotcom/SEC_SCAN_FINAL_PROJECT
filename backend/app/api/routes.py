"""HTTP endpoints.

Week 4: Deterministic scoring engine from weights.yaml.
Week 5: Added mode="full" for multi-host scanning.
  - Discovers subdomains via crt.sh (passive CT logs) + DNS mining + wordlist brute-force
  - Scans each host with the 4 scanners, concurrency=5, timeout=20s
  - Aggregates: domain_score = worst-host (most conservative)
Week 6 (backend tasks):
  - Geo-IP lookup per host (ip-api.com)
  - Real port scanning per host (80/443/8080/8443/8000/3000)
  - AI integration point (Role B plugs in ai/analyzer.py)
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    CategoryScore,
    CheckScoreInfo,
    Finding,
    HostResult,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    VersionInfo,
)
from app.db import crud
from app.db.database import get_session
from app.config import settings
from app.discovery.enumerator import enumerate_hosts
from app.scanners.dns_scanner import scan_dns
from app.scanners.email_scanner import scan_email
from app.scanners.header_scanner import scan_headers
from app.scanners.tls_scanner import scan_tls
from app.scanners.port_scanner import scan_ports, open_port_numbers
from app.scoring import score_checks
from app.utils.geoip import lookup_many

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_HOST_CONCURRENCY = 5
HOST_SCAN_TIMEOUT = 20.0

# Full-scan guard rails. crt.sh results grow over time, so without a cap a
# domain that used to yield ~10 hosts can later yield hundreds and the scan
# appears to hang. Every phase is also bounded so one slow third-party
# service (crt.sh / ip-api.com / OpenAI) can't stall the whole request.
MAX_HOSTS = 25
DISCOVERY_TIMEOUT = 45.0
GEOIP_TIMEOUT = 10.0
PORT_SCAN_TIMEOUT = 20.0
PORT_SCAN_CONCURRENCY = 10
AI_TIMEOUT = 30.0


def _prioritize_hosts(hosts: list, apex: str, limit: int) -> list:
    """Keep the apex and www first, then the shallowest/shortest names."""
    def rank(h) -> tuple:
        name = h.hostname
        if name == apex:
            return (0, 0, 0, name)
        if name == f"www.{apex}":
            return (1, 0, 0, name)
        return (2, name.count("."), len(name), name)
    return sorted(hosts, key=rank)[:limit]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _scan_single_host(domain: str) -> tuple[list, dict]:
    dns_res, tls_res, headers_res, email_res = await asyncio.gather(
        scan_dns(domain),
        scan_tls(domain),
        scan_headers(domain),
        scan_email(domain),
        return_exceptions=True,
    )
    all_checks: list[dict] = []
    for res in (dns_res, tls_res, headers_res, email_res):
        if isinstance(res, list):
            all_checks.extend(res)
        elif isinstance(res, Exception):
            all_checks.append({
                "id": "scan.error", "category": "dns",
                "title": "Scanner crashed", "passed": False, "severity": "low",
                "evidence": f"{res.__class__.__name__}: {res}", "remediation": "",
            })
    score_result = score_checks(all_checks)
    return all_checks, score_result


def _build_findings(all_checks: list[dict]) -> list[Finding]:
    return [
        Finding(
            id=c["id"], category=c["category"], title=c["title"],
            severity=c["severity"], passed=c["passed"],
            evidence=c["evidence"], remediation=c["remediation"],
        )
        for c in all_checks
    ]


def _build_breakdown(score_result: dict) -> list[CategoryScore]:
    return [
        CategoryScore(
            name=cat["name"],  # type: ignore[arg-type]
            earned=cat["earned"],
            max=cat["max"],
            checks=[CheckScoreInfo(**row) for row in cat["checks"]],
        )
        for cat in score_result["breakdown"]
    ]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

async def _save_scan(session: AsyncSession, resp: ScanResponse) -> None:
    """Persist a scan result. Never raises — a DB failure must not fail the scan."""
    try:
        await crud.create_scan(
            session,
            scan_id=resp.scan_id,
            domain=resp.domain,
            mode=resp.mode,
            score=resp.score,
            grade=resp.grade,
            findings_count=len(resp.findings),
            result_json=resp.model_dump(),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to persist scan %s: %s", resp.scan_id, exc)


@router.get("/health")
def health():
    return {"status": "ok", "version": settings.app_version}


@router.post("/scan", response_model=ScanResponse)
async def scan(
    req: ScanRequest,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    version = VersionInfo(
        app=settings.app_version,
        model=settings.openai_model,
        rubric=1,
    )

    # ------------------------------------------------------------------
    # mode="single" — scan only the requested domain
    # ------------------------------------------------------------------
    if req.mode == "single":
        all_checks, score_result = await _scan_single_host(req.domain)
        findings = _build_findings(all_checks)
        breakdown = _build_breakdown(score_result)
        failed = sum(1 for c in all_checks if not c["passed"])
        summary = (
            f"DNS + TLS + Headers + Email scan complete for {req.domain}. "
            f"{failed} issue(s) found out of {len(all_checks)} checks. "
            f"Score {score_result['score']}/100 -> grade {score_result['grade']}."
        )
        version.rubric = score_result["rubric_version"]
        resp = ScanResponse(
            scan_id=str(uuid.uuid4()),
            domain=req.domain,
            mode="single",
            score=score_result["score"],
            grade=score_result["grade"],  # type: ignore[arg-type]
            summary=summary,
            findings=findings,
            breakdown=breakdown,
            version=version,
        )
        await _save_scan(session, resp)
        return resp

    # ------------------------------------------------------------------
    # mode="full" — multi-host scan
    # ------------------------------------------------------------------
    logger.info("Starting full scan for %s", req.domain)
    t0 = time.perf_counter()
    try:
        discovered = await asyncio.wait_for(
            enumerate_hosts(req.domain), timeout=DISCOVERY_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("Discovery timed out for %s — scanning apex only", req.domain)
        from app.discovery.enumerator import DiscoveredHost  # noqa: PLC0415
        discovered = [DiscoveredHost(hostname=req.domain, ip="")]
    logger.info(
        "[timing] discovery: %d live hosts for %s in %.1fs",
        len(discovered), req.domain, time.perf_counter() - t0,
    )
    total_discovered = len(discovered)
    if total_discovered > MAX_HOSTS:
        logger.info("Capping hosts %d -> %d", total_discovered, MAX_HOSTS)
        discovered = _prioritize_hosts(discovered, req.domain, MAX_HOSTS)

    sem = asyncio.Semaphore(MAX_HOST_CONCURRENCY)

    async def _scan_host_safe(host_info) -> HostResult | None:
        async with sem:
            try:
                all_checks, score_result = await asyncio.wait_for(
                    _scan_single_host(host_info.hostname),
                    timeout=HOST_SCAN_TIMEOUT,
                )
                return HostResult(
                    host=host_info.hostname,
                    ip=host_info.ip,
                    score=score_result["score"],
                    grade=score_result["grade"],  # type: ignore[arg-type]
                    breakdown=_build_breakdown(score_result),
                    findings=_build_findings(all_checks),
                )
            except TimeoutError:
                logger.warning("Host scan timed out: %s", host_info.hostname)
                return None
            except Exception as exc:  # noqa: BLE001
                logger.warning("Host scan failed: %s — %s", host_info.hostname, exc)
                return None

    t1 = time.perf_counter()
    scan_tasks = [_scan_host_safe(h) for h in discovered]
    results = await asyncio.gather(*scan_tasks)
    logger.info("[timing] host scans: %d hosts in %.1fs", len(discovered), time.perf_counter() - t1)

    host_results: list[HostResult] = [r for r in results if r is not None]
    hosts_failed = len(results) - len(host_results)

    # Geo-IP: lookup all IPs concurrently
    t2 = time.perf_counter()
    ips = [h.ip for h in host_results if h.ip]
    try:
        geo_map = await asyncio.wait_for(lookup_many(ips), timeout=GEOIP_TIMEOUT)
    except TimeoutError:
        logger.warning("Geo-IP lookups timed out — continuing without location")
        geo_map = {}
    for hr in host_results:
        geo = geo_map.get(hr.ip)
        if geo:
            hr.location = geo.location
            hr.isp = geo.isp
            hr.asn = geo.asn

    # Port scan: run concurrently across all hosts
    port_sem = asyncio.Semaphore(PORT_SCAN_CONCURRENCY)

    async def _ports_limited(host: str):
        async with port_sem:
            return await scan_ports(host)

    port_scan_tasks = [_ports_limited(hr.host) for hr in host_results]
    try:
        port_scan_results = await asyncio.wait_for(
            asyncio.gather(*port_scan_tasks, return_exceptions=True),
            timeout=PORT_SCAN_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("Port scans timed out — continuing without open-port data")
        port_scan_results = []
    for hr, port_res in zip(host_results, port_scan_results):
        if isinstance(port_res, list):
            hr.open_ports = open_port_numbers(port_res)
    logger.info("[timing] geo-ip + ports: %.1fs", time.perf_counter() - t2)

    if host_results:
        worst = min(host_results, key=lambda h: h.score)
        domain_score = worst.score
        domain_grade = worst.grade
        avg_score = round(sum(h.score for h in host_results) / len(host_results), 1)
    else:
        domain_score = 0
        domain_grade = "F"  # type: ignore[assignment]
        avg_score = 0.0

    apex_result = next(
        (h for h in host_results if h.host == req.domain),
        host_results[0] if host_results else None,
    )
    if apex_result:
        top_score = apex_result.score
        top_grade = apex_result.grade
        top_findings = apex_result.findings
        top_breakdown = apex_result.breakdown
    else:
        top_score = domain_score
        top_grade = domain_grade  # type: ignore[assignment]
        top_findings = []
        top_breakdown = []

    summary = (
        f"Full domain scan complete for {req.domain}. "
        f"Discovered {total_discovered} host(s)"
        + (f" (scanned the top {MAX_HOSTS})" if total_discovered > MAX_HOSTS else "")
        + f", scanned {len(host_results)}, "
        f"failed {hosts_failed}. "
        f"Domain score (worst host): {domain_score}/100 -> {domain_grade}. "
        f"Average score: {avg_score}/100."
    )

    # AI Risk Analyzer integration point (Role B implements ai/analyzer.py)
    ai_summary = None
    if apex_result:
        try:
            from app.ai.analyzer import analyze_findings  # noqa: PLC0415
            apex_checks = [f.model_dump() for f in apex_result.findings]
            t3 = time.perf_counter()
            ai_summary = await asyncio.wait_for(analyze_findings(apex_checks, {
                "score": top_score,
                "grade": top_grade,
                "domain": req.domain,
                "hosts_scanned": len(host_results),
                "domain_score": domain_score,
                "domain_grade": domain_grade,
            }), timeout=AI_TIMEOUT)
            logger.info("[timing] AI summary: %.1fs", time.perf_counter() - t3)
        except TimeoutError:
            logger.warning("AI analyzer timed out after %.0fs — no AI summary", AI_TIMEOUT)
        except ImportError:
            pass  # ai/analyzer.py not yet implemented — skip silently
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI analyzer failed: %s", exc)

    logger.info("[timing] full scan total: %.1fs", time.perf_counter() - t0)
    version.rubric = 1
    resp = ScanResponse(
        scan_id=str(uuid.uuid4()),
        domain=req.domain,
        mode="full",
        score=top_score,
        grade=top_grade,  # type: ignore[arg-type]
        summary=summary,
        findings=top_findings,
        breakdown=top_breakdown,
        version=version,
        hosts=host_results,
        domain_score=domain_score,
        domain_grade=domain_grade,  # type: ignore[arg-type]
        domain_avg_score=avg_score,
        hosts_scanned=len(host_results),
        hosts_failed=hosts_failed,
        ai_summary=ai_summary,
    )
    await _save_scan(session, resp)
    return resp


# ---------------------------------------------------------------------------
# Scan history (Week 7 — persisted in the database)
# ---------------------------------------------------------------------------

@router.get("/scans", response_model=list[ScanHistoryItem])
async def list_scan_history(
    session: AsyncSession = Depends(get_session),
) -> list[ScanHistoryItem]:
    """Most recent scans (newest first)."""
    records = await crud.list_scans(session)
    return [
        ScanHistoryItem(
            scan_id=r.scan_id,
            domain=r.domain,
            mode=r.mode,  # type: ignore[arg-type]
            score=r.score,
            grade=r.grade,  # type: ignore[arg-type]
            findings_count=r.findings_count,
            created_at=r.created_at,
        )
        for r in records
    ]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_history(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Full stored result for one scan."""
    record = await crud.get_scan(session, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record.result_json


@router.delete("/scans/{scan_id}")
async def delete_scan_history(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Delete one stored scan."""
    deleted = await crud.delete_scan(session, scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}
