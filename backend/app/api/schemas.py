"""Pydantic models for API I/O — the Inbound Agent layer."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

DOMAIN_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$")
Severity = Literal["critical", "high", "medium", "low", "info"]
Grade = Literal["A+", "A", "B", "C", "D", "F"]


class ScanRequest(BaseModel):
    """User-supplied scan input. Validated + sanitized here."""
    domain: str = Field(..., min_length=3, max_length=253)
    mode: Literal["single", "full"] = "single"  # W5: "full" = multi-host scan

    @field_validator("domain")
    @classmethod
    def normalize_and_validate(cls, v: str) -> str:
        v = v.strip().lower()
        v = re.sub(r"^https?://", "", v).rstrip("/")
        if not DOMAIN_RE.match(v):
            raise ValueError("Invalid domain format")
        return v


class Finding(BaseModel):
    id: str
    category: Literal["tls", "headers", "email", "dns"]
    title: str
    severity: Severity
    passed: bool
    evidence: str = ""
    remediation: str = ""


class VersionInfo(BaseModel):
    app: str
    model: str
    rubric: int = 1


class CheckScoreInfo(BaseModel):
    id: str
    weight: int
    earned: int
    passed: bool
    present: bool


class CategoryScore(BaseModel):
    name: Literal["tls", "headers", "email", "dns"]
    earned: int
    max: int
    checks: list[CheckScoreInfo]


# ---------------------------------------------------------------------------
# W5: Multi-host scan models
# ---------------------------------------------------------------------------

class HostResult(BaseModel):
    """Scan result for a single discovered host."""
    host: str
    ip: str
    score: int = Field(ge=0, le=100)
    grade: Grade
    breakdown: list[CategoryScore] = []
    findings: list[Finding] = []


class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    mode: Literal["single", "full"] = "single"

    # --- single-host fields (always populated) ---
    score: int = Field(ge=0, le=100)
    grade: Grade
    summary: str = ""
    findings: list[Finding] = []
    breakdown: list[CategoryScore] = []
    version: VersionInfo

    # --- multi-host fields (populated when mode="full") ---
    hosts: list[HostResult] = []
    domain_score: int | None = None
    domain_grade: Grade | None = None
    domain_avg_score: float | None = None
    hosts_scanned: int = 0
    hosts_failed: int = 0
