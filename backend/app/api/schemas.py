"""Pydantic models for API I/O — the Inbound Agent layer."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# RFC 1123 host name: labels of 1-63 letters/digits/hyphens that do not start
# or end with a hyphen, total <= 253 characters, alphabetic TLD (so bare IP
# addresses are rejected). Internationalised names arrive here as punycode.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
Severity = Literal["critical", "high", "medium", "low", "info"]
Grade = Literal["A+", "A", "B", "C", "D", "F"]


class ScanRequest(BaseModel):
    """User-supplied scan input. Validated + sanitized here."""
    domain: str = Field(..., min_length=3, max_length=253)
    mode: Literal["single", "full"] = "single"  # "full" = multi-host scan

    @field_validator("domain")
    @classmethod
    def normalize_and_validate(cls, v: str) -> str:
        v = v.strip().lower()
        # strip protocol if user typed https://...
        v = re.sub(r"^https?://", "", v).rstrip("/").rstrip(".")
        # Thai / other internationalised names -> punycode (ไทย.com -> xn--...)
        try:
            v = v.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Enter a domain name like example.com") from None
        if not DOMAIN_RE.match(v):
            raise ValueError("Enter a domain name like example.com")
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


# ---------------------------------------------------------------------------
# Multi-host scan models
# ---------------------------------------------------------------------------

class HostResult(BaseModel):
    """Scan result for a single discovered host."""
    host: str
    ip: str
    score: int = Field(ge=0, le=100)
    grade: Grade
    breakdown: list[CategoryScore] = []
    findings: list[Finding] = []
    # Geo-IP
    location: str | None = None
    isp: str | None = None
    asn: str | None = None
    # Port scan
    open_ports: list[int] = []


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
    # AI Risk Analyzer output
    ai_summary: dict | None = None
    # shape: {"risk_summary": str, "top_issues": [str], "positive_findings": [str]}


class ScanHistoryItem(BaseModel):
    """Lightweight row for the history list (GET /api/scans)."""
    scan_id: str
    domain: str
    mode: Literal["single", "full"]
    score: int
    grade: Grade
    findings_count: int
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _assume_utc(cls, v: datetime) -> datetime:
        """Timestamps are stored in UTC, but SQLite drops the timezone, so they
        come back naive and were serialised without "Z" — the browser then
        read them as local time (7 h behind in Thailand). Mark naive values
        as UTC so the JSON always carries an explicit offset."""
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v
