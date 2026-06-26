"""AI Risk Analyzer for mode='full' multi-host scan results."""
from __future__ import annotations

from app.ai.service import explain_scan


async def analyze_findings(
    findings: list[dict],
    context: dict,
) -> dict:
    """
    Analyze findings from a full multi-host scan and return a risk summary.

    Args:
        findings: list of Finding dicts from the apex host
        context: dict with keys: score, grade, domain, hosts_scanned,
                 domain_score, domain_grade

    Returns:
        dict with risk_summary, top_issues, positive_findings
    """
    domain = context.get("domain", "unknown")
    score = context.get("score", 0)
    grade = context.get("grade", "F")

    # Re-use the existing explain_scan service (handles OpenAI + fallback)
    ai_result = await explain_scan(
        domain=domain,
        score=score,
        grade=grade,
        findings=findings,  # type: ignore[arg-type]
    )

    # Build top_issues from failed findings
    top_issues = [
        f.explanation
        for f in ai_result.findings
    ]

    # Build positive_findings from passed checks
    positive_findings = [
        f"{f['title']} — passed"
        for f in findings
        if f.get("passed")
    ][:5]  # limit to 5

    return {
        "risk_summary": ai_result.summary,
        "overall_risk": ai_result.overall_risk,
        "top_issues": top_issues,
        "positive_findings": positive_findings,
        "generated_by_ai": ai_result.generated_by_ai,
        "model_used": ai_result.model_used,
        "domain_score": context.get("domain_score"),
        "domain_grade": context.get("domain_grade"),
        "hosts_scanned": context.get("hosts_scanned", 0),
    }