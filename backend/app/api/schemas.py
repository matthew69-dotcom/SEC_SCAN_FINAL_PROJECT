"""Pydantic models for API I/O — the Inbound Agent layer."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

DOMAIN_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$")
Severity = Literal["critical", "high", "medium", "low", "info"]


class ScanRequest(BaseModel):
    """User-supplied scan input. Validated + sanitized here."""
    domain: str = Field(..., min_length=3, max_length=253)

    @field_validator("domain")
    @classmethod
    def normalize_and_validate(cls, v: str) -> str:
        v = v.strip().lower()
        # strip protocol if user typed https://...
        v = re.sub(r"^https?://", "", v).rstrip("/")
        if not DOMAIN_RE.match(v):
            raise ValueError("Invalid domain format")
        return v


class Finding(BaseModel):
    id: str                          # e.g. "tls.cert_valid"
    category: Literal["tls", "headers", "email", "dns"]
    title: str
    severity: Severity
    passed: bool
    evidence: str = ""
    remediation: str = ""


class VersionInfo(BaseModel):
    app: str
    model: str
    rubric: int = 1  # weights.yaml `version` field


class CheckScoreInfo(BaseModel):
    """One row in a category breakdown — surfaces which rubric checks earned points."""
    id: str
    weight: int
    earned: int
    passed: bool
    present: bool  # False when the rubric expected this check but no scanner emitted it


class CategoryScore(BaseModel):
    """Per-category score (tls/headers/email/dns) with per-check rows."""
    name: Literal["tls", "headers", "email", "dns"]
    earned: int
    max: int
    checks: list[CheckScoreInfo]


class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    score: int = Field(ge=0, le=100)
    grade: Literal["A+", "A", "B", "C", "D", "F"]
    summary: str = ""
    findings: list[Finding] = []
    breakdown: list[CategoryScore] = []
    version: VersionInfo
