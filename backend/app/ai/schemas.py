"""Schemas owned by Role B: AI input/output contract."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class FindingExplanation(BaseModel):
    id: str
    risk: str = Field(..., min_length=1)
    explanation: str = Field(..., min_length=1)
    next_step: str = Field(..., min_length=1)


class AIExplanation(BaseModel):
    summary: str = Field(..., min_length=1)
    overall_risk: Literal["low", "medium", "high", "critical"]
    findings: list[FindingExplanation] = Field(default_factory=list)
    model_used: str
    generated_by_ai: bool = False