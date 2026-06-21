"""Validation helpers for comparing scanner output with external tools."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ValidationRow(BaseModel):
    """One comparison between our scanner and an external reference tool."""

    domain: str
    check: str
    our_result: str
    external_tool: str
    external_result: str
    matches: bool
    notes: str = ""


class ValidationSummary(BaseModel):
    total: int
    matches: int
    mismatches: int
    accuracy: float = Field(ge=0, le=1)
    false_positives: int
    false_negatives: int


def summarize_validation(rows: list[ValidationRow]) -> ValidationSummary:
    """Calculate accuracy, false positives, and false negatives."""
    total = len(rows)
    matches = sum(1 for row in rows if row.matches)
    mismatches = total - matches
    false_positives = sum(
        1 for row in rows if _looks_failed(row.our_result) and _looks_passed(row.external_result)
    )
    false_negatives = sum(
        1 for row in rows if _looks_passed(row.our_result) and _looks_failed(row.external_result)
    )

    return ValidationSummary(
        total=total,
        matches=matches,
        mismatches=mismatches,
        accuracy=round(matches / total, 3) if total else 0,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


def render_validation_table(rows: list[ValidationRow]) -> str:
    """Render validation rows as a Markdown table for the final report."""
    lines = [
        "| Domain | Check | Our Result | External Tool | External Result | Match? | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        match_text = "yes" if row.matches else "no"
        lines.append(
            f"| {row.domain} | {row.check} | {row.our_result} | {row.external_tool} | "
            f"{row.external_result} | {match_text} | {row.notes} |"
        )
    return "\n".join(lines) + "\n"


def _looks_passed(value: str) -> bool:
    return value.strip().lower() in {"pass", "passed", "ok", "true", "secure", "present", "valid"}


def _looks_failed(value: str) -> bool:
    return value.strip().lower() in {"fail", "failed", "false", "issue", "missing", "invalid", "insecure"}
