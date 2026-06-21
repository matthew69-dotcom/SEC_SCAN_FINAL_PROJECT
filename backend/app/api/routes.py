"""HTTP endpoints.

Week 4: Replaced the provisional severity-penalty scoring with the deterministic
scoring engine (`app.scoring`). The engine loads its rubric from weights.yaml so
the grade boundaries and per-check weights can be tuned without a code rebuild.
Week 5 adds the AI summary on top of these findings.
"""
from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter

from app.ai import explain_scan
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
    # does not kill the rest; we convert exceptions into failed checks.
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
            all_checks.append(
                {
                    "id": "scan.error",
                    "category": "dns",
                    "title": "Scanner crashed",
                    "passed": False,
                    "severity": "low",
                    "evidence": f"{res.__class__.__name__}: {res}",
                    "remediation": "",
                }
            )

    # Deterministic scoring. AI explains results but does not change score/grade.
    score_result = score_checks(all_checks)

    findings = [
        Finding(
            id=c["id"],
            category=c["category"],
            title=c["title"],
            severity=c["severity"],
            passed=c["passed"],
            evidence=c["evidence"],
            remediation=c["remediation"],
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

    ai_explanation = await explain_scan(
        domain=req.domain,
        score=score_result["score"],
        grade=score_result["grade"],
        findings=all_checks,
    )
    summary = ai_explanation.summary

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