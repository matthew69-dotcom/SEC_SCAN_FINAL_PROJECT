"""Markdown report rendering for Role B."""
from __future__ import annotations

from app.ai.schemas import AIExplanation
from app.scanners.base import CheckResult


def render_markdown_report(
    *,
    domain: str,
    score: int,
    grade: str,
    findings: list[CheckResult],
    ai_explanation: AIExplanation,
) -> str:
    """Render a human-readable scan report from scanner and AI output."""
    failed = [finding for finding in findings if not finding["passed"]]
    passed = len(findings) - len(failed)

    lines = [
        f"# Security Scan Report: {domain}",
        "",
        "## Summary",
        f"- Score: {score}/100",
        f"- Grade: {grade}",
        f"- Overall risk: {ai_explanation.overall_risk}",
        f"- Checks passed: {passed}",
        f"- Issues found: {len(failed)}",
        "",
        ai_explanation.summary,
        "",
        "## Findings",
    ]

    if not failed:
        lines.extend(["", "No failed checks were detected."])
        return "\n".join(lines).strip() + "\n"

    explanation_by_id = {item.id: item for item in ai_explanation.findings}
    for finding in failed:
        explanation = explanation_by_id.get(finding["id"])
        lines.extend(
            [
                "",
                f"### {finding['title']}",
                f"- ID: `{finding['id']}`",
                f"- Category: {finding['category']}",
                f"- Severity: {finding['severity']}",
                f"- Evidence: {finding.get('evidence', '')}",
                f"- Recommended fix: {finding.get('remediation', '') or 'Review and document this finding.'}",
            ]
        )
        if explanation is not None:
            lines.extend(
                [
                    f"- AI risk note: {explanation.risk}",
                    f"- AI explanation: {explanation.explanation}",
                    f"- Next step: {explanation.next_step}",
                ]
            )

    return "\n".join(lines).strip() + "\n"
