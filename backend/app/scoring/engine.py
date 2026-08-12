"""Deterministic scoring engine.

The AI never participates in scoring. Given a flat list of CheckResult dicts
from the scanners, this module:

  1. Loads the rubric from weights.yaml (cached after first call).
  2. For each scoring category, sums the weights of checks whose `passed=True`.
  3. Caps the total at [0, 100] and looks up the grade.
  4. Returns a structured breakdown so the API can show users WHY they got
     the grade.

Design rules followed:
  - Pure function: same inputs → same outputs (reproducibility).
  - No network, no I/O beyond the one YAML load.
  - Checks not listed in the rubric are skipped (info-only sanity checks).
  - Rubric-listed checks that don't arrive earn 0 — making coverage gaps
    visible rather than silently inflating the score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Literal, TypedDict

import yaml

from app.scanners.base import CheckResult

Grade = Literal["A+", "A", "B", "C", "D", "F"]

# weights.yaml lives next to this file.
_DEFAULT_RUBRIC_PATH = Path(__file__).parent / "weights.yaml"


# ───────────────────────────── Rubric (config) ─────────────────────────────


@dataclass(frozen=True)
class CategoryRubric:
    """Per-category section of the rubric."""
    name: str
    weight_total: int
    checks: dict[str, int]  # check_id -> weight


@dataclass(frozen=True)
class Rubric:
    """Loaded weights.yaml in typed form."""
    version: int
    categories: dict[str, CategoryRubric]              # category_name -> rubric
    grade_thresholds: list[tuple[int, Grade]]          # sorted descending by min
    check_to_category: dict[str, str] = field(default_factory=dict)

    def category_of(self, check_id: str) -> str | None:
        return self.check_to_category.get(check_id)

    def weight_of(self, check_id: str) -> int:
        cat = self.category_of(check_id)
        if cat is None:
            return 0
        return self.categories[cat].checks.get(check_id, 0)

    def grade_for(self, score: int) -> Grade:
        for threshold, grade in self.grade_thresholds:
            if score >= threshold:
                return grade
        # grade_thresholds always ends with min=0 → F, but be defensive
        return "F"


def _build_rubric(raw: dict[str, Any]) -> Rubric:
    """Validate the loaded YAML and convert it into a Rubric dataclass."""
    if not isinstance(raw, dict):
        raise ValueError("weights.yaml must be a mapping at the top level")

    version = int(raw.get("version", 1))

    cats_raw = raw.get("categories")
    if not isinstance(cats_raw, dict) or not cats_raw:
        raise ValueError("weights.yaml must define a non-empty 'categories' mapping")

    categories: dict[str, CategoryRubric] = {}
    check_to_category: dict[str, str] = {}
    total_weight = 0

    for cat_name, cat_body in cats_raw.items():
        if not isinstance(cat_body, dict):
            raise ValueError(f"category '{cat_name}' must be a mapping")
        weight_total = int(cat_body.get("weight_total", 0))
        if weight_total < 0:
            raise ValueError(f"category '{cat_name}' weight_total must be >= 0")
        checks_raw = cat_body.get("checks", {}) or {}
        if not isinstance(checks_raw, dict):
            raise ValueError(f"category '{cat_name}' checks must be a mapping")

        # Each check weight must be a non-negative int.
        check_weights: dict[str, int] = {}
        sum_weights = 0
        for cid, w in checks_raw.items():
            w_int = int(w)
            if w_int < 0:
                raise ValueError(f"check '{cid}' weight must be >= 0")
            check_weights[str(cid)] = w_int
            sum_weights += w_int
            if cid in check_to_category:
                raise ValueError(
                    f"check '{cid}' is listed under multiple categories: "
                    f"{check_to_category[cid]} and {cat_name}"
                )
            check_to_category[str(cid)] = str(cat_name)

        if sum_weights > weight_total:
            raise ValueError(
                f"category '{cat_name}': sum of check weights ({sum_weights}) "
                f"exceeds weight_total ({weight_total})"
            )

        categories[str(cat_name)] = CategoryRubric(
            name=str(cat_name),
            weight_total=weight_total,
            checks=check_weights,
        )
        total_weight += weight_total

    if total_weight != 100:
        raise ValueError(
            f"sum of all category weight_total must equal 100, got {total_weight}"
        )

    # Grade thresholds — accept either dict or {min, grade}.
    grades_raw = raw.get("grade_thresholds") or []
    if not isinstance(grades_raw, list) or not grades_raw:
        raise ValueError("weights.yaml must define non-empty 'grade_thresholds' list")

    grades: list[tuple[int, Grade]] = []
    seen_letters: set[str] = set()
    for entry in grades_raw:
        if not isinstance(entry, dict) or "min" not in entry or "grade" not in entry:
            raise ValueError("each grade_thresholds entry must have 'min' and 'grade'")
        m = int(entry["min"])
        g = str(entry["grade"])
        if g not in {"A+", "A", "B", "C", "D", "F"}:
            raise ValueError(f"invalid grade letter: {g}")
        if g in seen_letters:
            raise ValueError(f"grade {g} appears more than once in thresholds")
        seen_letters.add(g)
        grades.append((m, g))  # type: ignore[arg-type]

    # Sort descending by min so first-match-wins works.
    grades.sort(key=lambda x: x[0], reverse=True)

    return Rubric(
        version=version,
        categories=categories,
        grade_thresholds=grades,
        check_to_category=check_to_category,
    )


@lru_cache(maxsize=8)
def load_rubric(path: str | None = None) -> Rubric:
    """Load + validate weights.yaml. Cached per path."""
    p = Path(path) if path else _DEFAULT_RUBRIC_PATH
    with p.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return _build_rubric(raw)


# ───────────────────────────── Score result ────────────────────────────────


class CheckScore(TypedDict):
    """One row in the per-category breakdown."""
    id: str
    weight: int
    earned: int
    passed: bool
    present: bool   # False if the rubric expected this check but no scanner emitted it


class CategoryBreakdown(TypedDict):
    name: str
    earned: int
    max: int
    checks: list[CheckScore]


class ScoreResult(TypedDict):
    score: int            # 0-100
    grade: Grade          # A+ .. F
    breakdown: list[CategoryBreakdown]
    rubric_version: int


# ───────────────────────────── Scoring ─────────────────────────────────────


def score_checks(
    checks: Iterable[CheckResult],
    rubric: Rubric | None = None,
) -> ScoreResult:
    """Aggregate scanner CheckResults into a deterministic score + breakdown.

    Args:
        checks: flat iterable of CheckResult dicts emitted by the scanners.
        rubric: optional Rubric (mainly for tests). Defaults to weights.yaml.

    Returns:
        ScoreResult with score, grade, and per-category breakdown.
    """
    if rubric is None:
        rubric = load_rubric()

    # Index incoming checks by ID. If the same check_id arrives more than once
    # (a scanner glitch), the LAST one wins — but we track that to surface in
    # evidence. For the rubric, "passed if any pass" would be too lenient, so
    # we choose "last-wins" (deterministic, matches what the user sees in findings).
    by_id: dict[str, CheckResult] = {}
    for c in checks:
        by_id[c["id"]] = c

    breakdown: list[CategoryBreakdown] = []
    total_earned = 0

    for cat_name, cat in rubric.categories.items():
        rows: list[CheckScore] = []
        cat_earned = 0
        for check_id, weight in cat.checks.items():
            result = by_id.get(check_id)
            if result is None:
                # Rubric expects this check, but no scanner emitted it.
                rows.append({
                    "id": check_id,
                    "weight": weight,
                    "earned": 0,
                    "passed": False,
                    "present": False,
                })
                continue
            passed = bool(result["passed"])
            earned = weight if passed else 0
            cat_earned += earned
            rows.append({
                "id": check_id,
                "weight": weight,
                "earned": earned,
                "passed": passed,
                "present": True,
            })
        breakdown.append({
            "name": cat_name,
            "earned": cat_earned,
            "max": cat.weight_total,
            "checks": rows,
        })
        total_earned += cat_earned

    score = max(0, min(100, total_earned))
    grade = rubric.grade_for(score)

    return {
        "score": score,
        "grade": grade,
        "breakdown": breakdown,
        "rubric_version": rubric.version,
    }
