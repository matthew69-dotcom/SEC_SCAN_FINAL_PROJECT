"""HTTP endpoints.

Week 4: Replaced the provisional severity-penalty scoring with the deterministic
scoring engine (`app.scoring`). The engine loads its rubric from weights.yaml so
the grade boundaries and per-check weights can be tuned without a code rebuild.
Week 5 will add the AI summary on top of these findings.
"""
from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter

from app.api.schemas import (
    CategoryScore,
    CheckScoreInfo,
    Finding,
    ScanRequest,
    ScanResponse,
    VersionInfo,
)
from app.config import settings
from app.scanners.dns_scanner import scan_dns
from app.scanners.email_scanner import scan_email
from app.scanners.header_scanner import scan_headers
from app.scanners.tls_scanner import scan_tls
from app.scoring import score_checks

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "version": settings.app_version}


@router.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    # Run all four scanners concurrently. return_exceptions so one failure
    # doesn't kill the rest — we'll convert any exception into a failed check.
    dns_res, tls_res, headers_res, email_res = await asyncio.gather(
        scan_dns(req.domain),
        scan_tls(req.domain),
        scan_headers(req.domain),
        scan_email(req.domain),
        return_exceptions=True,
    )

    all_checks = []
    for res in (dns_res, tls_res, headers_res, email_res):
        if isinstance(res, list):
            all_checks.extend(res)
        elif isinstance(res, Exception):
            all_checks.append({
                "id": "scan.error", "category": "dns",
                "title": "Scanner crashed", "passed": False, "severity": "low",
                "evidence": f"{res.__class__.__name__}: {res}", "remediation": "",
            })

    # Deterministic scoring — loaded from app/scoring/weights.yaml.
    score_result = score_checks(all_checks)

    findings = [
        Finding(
            id=c["id"], category=c["category"], title=c["title"],
            severity=c["severity"], passed=c["passed"],
            evidence=c["evidence"], remediation=c["remediation"],
        )
        for c in all_checks
    ]

    breakdown = [
        CategoryScore(
            name=cat["name"],  # type: ignore[arg-type]
            earned=cat["earned"],
            max=cat["max"],
            checks=[CheckScoreInfo(**row) for row in cat["checks"]],
        )
        for cat in score_result["breakdown"]
    ]

    failed = sum(1 for c in all_checks if not c["passed"])
    summary = (
        f"DNS + TLS + Headers + Email scan complete for {req.domain}. "
        f"{failed} issue(s) found out of {len(all_checks)} checks. "
        f"Score {score_result['score']}/100 → grade {score_result['grade']}."
    )

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        domain=req.domain,
        score=score_result["score"],
        grade=score_result["grade"],
        summary=summary,
        findings=findings,
        breakdown=breakdown,
        version=VersionInfo(
            app=settings.app_version,
            model=settings.openai_model,
            rubric=score_result["rubric_version"],
        ),
    )
