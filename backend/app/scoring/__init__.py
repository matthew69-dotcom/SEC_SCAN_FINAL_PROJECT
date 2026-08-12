"""Deterministic scoring engine.

Public API:
    from app.scoring import score_checks, ScoreResult, load_rubric
"""
from app.scoring.engine import (
    ScoreResult,
    CategoryBreakdown,
    CheckScore,
    Rubric,
    load_rubric,
    score_checks,
)

__all__ = [
    "ScoreResult",
    "CategoryBreakdown",
    "CheckScore",
    "Rubric",
    "load_rubric",
    "score_checks",
]
