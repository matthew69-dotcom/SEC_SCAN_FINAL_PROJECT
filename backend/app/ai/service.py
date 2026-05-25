"""AI report generation service."""
from __future__ import annotations

import json
from typing import Any

from app.ai.prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from app.ai.schemas import AIExplanation, FindingExplanation
from app.config import settings
from app.scanners.base import CheckResult

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _risk_from_findings(findings: list[CheckResult]) -> str:
    failed = [f for f in findings if not f["passed"]]
    if any(f["severity"] == "critical" for f in failed):
        return "critical"
    if any(f["severity"] == "high" for f in failed):
        return "high"
    if any(f["severity"] == "medium" for f in failed):
        return "medium"
    return "low"


def _fallback_explanation(domain: str, score: int, grade: str, findings: list[CheckResult]) -> AIExplanation:
    failed = sorted(
        [f for f in findings if not f["passed"]],
        key=lambda f: _SEVERITY_RANK[f["severity"]],
        reverse=True,
    )
    passed_count = len(findings) - len(failed)
    summary = (
        f"{domain} scored {score}/100 ({grade}). "
        f"{passed_count} check(s) passed and {len(failed)} issue(s) need review."
    )

    explanations: list[FindingExplanation] = []
    for finding in failed[:8]:
        remediation = finding.get("remediation") or "Review this control and document the accepted risk or fix."
        explanations.append(
            FindingExplanation(
                id=finding["id"],
                risk=finding["severity"],
                explanation=f"{finding['title']}: {finding.get('evidence', 'No evidence provided.')}",
                next_step=remediation,
            )
        )

    return AIExplanation(
        summary=summary,
        overall_risk=_risk_from_findings(findings),
        findings=explanations,
        model_used="local-fallback",
        generated_by_ai=False,
    )


def _findings_for_prompt(findings: list[CheckResult]) -> str:
    compact: list[dict[str, Any]] = [
        {
            "id": f["id"],
            "category": f["category"],
            "title": f["title"],
            "passed": f["passed"],
            "severity": f["severity"],
            "evidence": f.get("evidence", ""),
            "remediation": f.get("remediation", ""),
        }
        for f in findings
    ]
    return json.dumps(compact, ensure_ascii=False, indent=2)


async def _call_langchain(domain: str, score: int, grade: str, findings: list[CheckResult]) -> AIExplanation | None:
    if not settings.openai_api_key:
        return None

    try:
        from langchain_core.output_parsers import PydanticOutputParser
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_openai import ChatOpenAI
    except ImportError:
        return None

    parser = PydanticOutputParser(pydantic_object=AIExplanation)
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT_TEMPLATE + "\n\n{format_instructions}"),
    ])
    model = ChatOpenAI(model=settings.openai_model, temperature=0, api_key=settings.openai_api_key)
    chain = prompt | model | parser

    result = await chain.ainvoke(
        {
            "domain": domain,
            "score": score,
            "grade": grade,
            "findings_json": _findings_for_prompt(findings),
            "format_instructions": parser.get_format_instructions(),
        }
    )
    result.model_used = settings.openai_model
    result.generated_by_ai = True
    return result


async def explain_scan(domain: str, score: int, grade: str, findings: list[CheckResult]) -> AIExplanation:
    ai_result = await _call_langchain(domain, score, grade, findings)
    if ai_result is not None:
        return ai_result
    return _fallback_explanation(domain, score, grade, findings)