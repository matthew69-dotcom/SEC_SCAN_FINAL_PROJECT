from app.ai.report import render_markdown_report
from app.ai.schemas import AIExplanation, FindingExplanation
from app.scanners.base import CheckResult


def _finding(passed: bool) -> CheckResult:
    return {
        "id": "tls.cert_valid",
        "category": "tls",
        "title": "TLS certificate valid",
        "passed": passed,
        "severity": "high",
        "evidence": "certificate expired yesterday",
        "remediation": "Renew the certificate.",
    }


def test_render_markdown_report_includes_score_and_ai_explanation():
    explanation = AIExplanation(
        summary="The domain has one TLS issue.",
        overall_risk="high",
        findings=[
            FindingExplanation(
                id="tls.cert_valid",
                risk="high",
                explanation="The certificate is expired.",
                next_step="Renew the certificate.",
            )
        ],
        model_used="local-fallback",
    )

    report = render_markdown_report(
        domain="example.com",
        score=72,
        grade="C",
        findings=[_finding(False)],
        ai_explanation=explanation,
    )

    assert "# Security Scan Report: example.com" in report
    assert "Score: 72/100" in report
    assert "Grade: C" in report
    assert "The certificate is expired." in report


def test_render_markdown_report_handles_clean_scan():
    explanation = AIExplanation(
        summary="No major issues found.",
        overall_risk="low",
        findings=[],
        model_used="local-fallback",
    )

    report = render_markdown_report(
        domain="example.com",
        score=100,
        grade="A+",
        findings=[_finding(True)],
        ai_explanation=explanation,
    )

    assert "No failed checks were detected." in report
