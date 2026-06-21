"""Shared types for all scanners.

Each scanner returns a list of CheckResult. A scanner NEVER raises out — if a
connection fails or DNS times out, it produces a failed check with severity
'high' or 'critical' and explains why in `evidence`.

This keeps the orchestrator (routes.py) dumb: it just collects results.
"""
from __future__ import annotations

from typing import Literal, TypedDict

Category = Literal["dns", "tls", "headers", "email"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class CheckResult(TypedDict):
    id: str           # e.g. "tls.cert_valid"
    category: Category
    title: str
    passed: bool
    severity: Severity
    evidence: str     # human-readable proof (raw data observed)
    remediation: str  # how to fix (empty if passed)
