import pytest

from app.ai import explain_scan
from app.scanners.base import CheckResult


@pytest.fixture(autouse=True)
def _force_fallback(monkeypatch):
    """These tests verify the LOCAL FALLBACK path. Blank out the API key so
    they behave the same whether or not the developer has a real key in .env."""
    monkeypatch.setattr("app.ai.service.settings.openai_api_key", "")


def _finding(check_id: str, passed: bool, severity: str = "high") -> CheckResult:
    return {
        "id": check_id,
        "category": "tls",
        "title": "TLS certificate valid",
        "passed": passed,
        "severity": severity,  # type: ignore[typeddict-item]
        "evidence": "certificate expired yesterday",
        "remediation": "Renew the certificate.",
    }


async def test_explain_scan_fallback_does_not_change_score_or_grade():
    result = await explain_scan(
        domain="example.com",
        score=72,
        grade="C",
        findings=[_finding("tls.cert_valid", False)],
    )

    assert "72/100" in result.summary
    assert "C" in result.summary
    assert result.generated_by_ai is False
    assert result.model_used == "local-fallback"
    assert result.overall_risk == "high"
    assert result.findings[0].id == "tls.cert_valid"


async def test_explain_scan_fallback_handles_clean_scan():
    result = await explain_scan(
        domain="example.com",
        score=100,
        grade="A+",
        findings=[_finding("tls.cert_valid", True, "info")],
    )

    assert result.overall_risk == "low"
    assert result.findings == []
