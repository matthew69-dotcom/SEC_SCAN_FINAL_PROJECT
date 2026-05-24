"""Unit tests for app.scoring.engine.

These are PURE tests — no network, no DNS, no TLS. They build fake
CheckResult lists and verify the engine's arithmetic and grade boundaries.

Run with: pytest backend/tests/test_scoring.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.scanners.base import CheckResult
from app.scoring import load_rubric, score_checks
from app.scoring.engine import _build_rubric


# ───────────────────────── helpers ─────────────────────────


def _check(check_id: str, category: str, passed: bool) -> CheckResult:
    """Construct a minimal CheckResult."""
    return {
        "id": check_id,
        "category": category,  # type: ignore[typeddict-item]
        "title": check_id,
        "passed": passed,
        "severity": "info" if passed else "high",  # type: ignore[typeddict-item]
        "evidence": "test",
        "remediation": "" if passed else "fix it",
    }


def _all_rubric_checks_passing():
    """Produce a CheckResult for every check the production rubric mentions, all passing."""
    rubric = load_rubric()
    out: list[CheckResult] = []
    for cat_name, cat in rubric.categories.items():
        for cid in cat.checks:
            out.append(_check(cid, cat_name, True))
    return out


# ───────────────────────── load_rubric ─────────────────────────


def test_load_rubric_succeeds_on_production_yaml():
    r = load_rubric()
    assert r.version == 1
    assert set(r.categories.keys()) == {"tls", "headers", "email", "dns"}
    assert sum(c.weight_total for c in r.categories.values()) == 100


def test_load_rubric_grade_thresholds_sorted_descending():
    r = load_rubric()
    mins = [m for m, _ in r.grade_thresholds]
    assert mins == sorted(mins, reverse=True)


def test_rubric_rejects_categories_summing_to_wrong_total():
    bad = {
        "version": 1,
        "categories": {
            "tls":     {"weight_total": 50, "checks": {"tls.x": 50}},
            "headers": {"weight_total": 40, "checks": {"headers.y": 40}},
        },
        "grade_thresholds": [{"min": 0, "grade": "F"}],
    }
    with pytest.raises(ValueError, match="equal 100"):
        _build_rubric(bad)


def test_rubric_rejects_check_weight_exceeding_category_total():
    bad = {
        "version": 1,
        "categories": {
            "tls":     {"weight_total": 30, "checks": {"tls.x": 35}},
            "headers": {"weight_total": 25, "checks": {"headers.y": 25}},
            "email":   {"weight_total": 25, "checks": {"email.y": 25}},
            "dns":     {"weight_total": 20, "checks": {"dns.y": 20}},
        },
        "grade_thresholds": [{"min": 0, "grade": "F"}],
    }
    with pytest.raises(ValueError, match="exceeds weight_total"):
        _build_rubric(bad)


def test_rubric_rejects_duplicate_check_across_categories():
    bad = {
        "version": 1,
        "categories": {
            "tls":     {"weight_total": 30, "checks": {"shared.x": 30}},
            "headers": {"weight_total": 25, "checks": {"shared.x": 25}},
            "email":   {"weight_total": 25, "checks": {"email.y": 25}},
            "dns":     {"weight_total": 20, "checks": {"dns.y": 20}},
        },
        "grade_thresholds": [{"min": 0, "grade": "F"}],
    }
    with pytest.raises(ValueError, match="multiple categories"):
        _build_rubric(bad)


# ───────────────────────── score_checks: shape ─────────────────────────


def test_score_no_checks_yields_zero_F():
    result = score_checks([])
    assert result["score"] == 0
    assert result["grade"] == "F"
    assert len(result["breakdown"]) == 4
    # Every check row should be present=False
    for cat in result["breakdown"]:
        assert cat["earned"] == 0
        assert all(not row["present"] for row in cat["checks"])


def test_score_all_passing_yields_full_marks():
    result = score_checks(_all_rubric_checks_passing())
    # The production weights.yaml lists tls.strong_ciphers (weight 6) which
    # the scanner doesn't yet emit, but our test injects it as passing, so
    # we should still hit 100.
    assert result["score"] == 100
    assert result["grade"] == "A+"
    # No "present=False" rows when every rubric check arrives
    for cat in result["breakdown"]:
        assert all(row["present"] for row in cat["checks"])
        assert cat["earned"] == cat["max"]


def test_breakdown_includes_all_four_categories():
    result = score_checks([])
    names = [c["name"] for c in result["breakdown"]]
    assert set(names) == {"tls", "headers", "email", "dns"}


# ───────────────────────── score_checks: arithmetic ─────────────────────────


def test_unlisted_check_ids_are_ignored():
    """dns.a_record is a sanity check, not in the rubric — must NOT affect score."""
    checks = _all_rubric_checks_passing() + [
        _check("dns.a_record", "dns", False),
        _check("dns.mx_record", "dns", False),
        _check("tls.handshake", "tls", False),
    ]
    result = score_checks(checks)
    # Still 100 — non-rubric checks don't penalize.
    assert result["score"] == 100
    assert result["grade"] == "A+"


def test_missing_rubric_check_is_treated_as_not_passed():
    """If the rubric expects a check but no scanner emits it, score must drop."""
    full = _all_rubric_checks_passing()
    # Drop tls.cert_valid (worth 10)
    trimmed = [c for c in full if c["id"] != "tls.cert_valid"]
    result = score_checks(trimmed)
    assert result["score"] == 90
    # And the breakdown row should be present=False
    tls = next(c for c in result["breakdown"] if c["name"] == "tls")
    cert_row = next(r for r in tls["checks"] if r["id"] == "tls.cert_valid")
    assert cert_row["present"] is False
    assert cert_row["earned"] == 0


def test_per_category_breakdown_arithmetic():
    """Build a known partial-pass set and verify each category's earned value."""
    rubric = load_rubric()

    # TLS: pass cert_valid (10) + hostname_match (3) = 13, fail the rest
    tls_checks = [
        _check("tls.cert_valid", "tls", True),
        _check("tls.modern_protocol", "tls", False),
        _check("tls.strong_ciphers", "tls", False),
        _check("tls.cert_renewal_buffer", "tls", False),
        _check("tls.hostname_match", "tls", True),
    ]
    # Headers: pass HSTS (6) + nosniff (3) = 9
    header_checks = [
        _check("headers.hsts", "headers", True),
        _check("headers.csp", "headers", False),
        _check("headers.frame_protection", "headers", False),
        _check("headers.nosniff", "headers", True),
        _check("headers.referrer_policy", "headers", False),
        _check("headers.permissions_policy", "headers", False),
    ]
    # Email: pass SPF (8) + DMARC (7) + DKIM (2) = 17
    email_checks = [
        _check("email.spf_present", "email", True),
        _check("email.spf_hardfail", "email", False),
        _check("email.dmarc_present", "email", True),
        _check("email.dmarc_strict_policy", "email", False),
        _check("email.dkim_detected", "email", True),
    ]
    # DNS: pass NS_redundancy (4) + wildcard_exposed (3) = 7
    dns_checks = [
        _check("dns.dnssec", "dns", False),
        _check("dns.caa", "dns", False),
        _check("dns.ns_redundancy", "dns", True),
        _check("dns.wildcard_exposed", "dns", True),
    ]

    result = score_checks(tls_checks + header_checks + email_checks + dns_checks)

    by_cat = {c["name"]: c for c in result["breakdown"]}
    assert by_cat["tls"]["earned"] == 13
    assert by_cat["tls"]["max"] == rubric.categories["tls"].weight_total
    assert by_cat["headers"]["earned"] == 9
    assert by_cat["email"]["earned"] == 17
    assert by_cat["dns"]["earned"] == 7
    assert result["score"] == 13 + 9 + 17 + 7  # = 46
    assert result["grade"] == "D"


def test_duplicate_check_id_uses_last_arrived():
    """If a check id appears twice, last-wins (deterministic + matches findings ordering)."""
    full = _all_rubric_checks_passing()
    # Override tls.cert_valid to failing AFTER the passing one — should fail final.
    duped = full + [_check("tls.cert_valid", "tls", False)]
    result = score_checks(duped)
    # Lost 10 points (cert_valid weight) => 90.
    assert result["score"] == 90


# ───────────────────────── grade boundaries ─────────────────────────


@pytest.mark.parametrize("score,expected_grade", [
    (100, "A+"),
    (95, "A+"),
    (94, "A"),
    (85, "A"),
    (84, "B"),
    (75, "B"),
    (74, "C"),
    (60, "C"),
    (59, "D"),
    (40, "D"),
    (39, "F"),
    (0, "F"),
])
def test_grade_thresholds(score: int, expected_grade: str):
    """Test every boundary in the rubric: 95+ A+, 85+ A, 75+ B, 60+ C, 40+ D, else F."""
    rubric = load_rubric()
    assert rubric.grade_for(score) == expected_grade


# ───────────────────────── google.com sanity (offline) ─────────────────────────


def test_simulated_google_lands_around_C():
    """Smoke test: build a check list that mimics google.com's known posture and
    verify the new engine lands in the expected C range (~60-70).

    google.com (observed in Week 1-3):
      - TLS: cert valid, modern protocol, hostname OK, renewal buffer OK,
             strong_ciphers NOT IMPLEMENTED (0)  → 10+8+3+3 = 24/30
      - Headers: HSTS yes, nosniff yes, frame yes, others vary; conservatively
                 6+3+4+3 = 16/25 (no CSP, no Permissions-Policy)
      - Email: SPF yes (~all not -all), DMARC yes (reject/quarantine), DKIM yes
                 = 8 + 0 + 7 + 4 + 2 = 21/25
      - DNS:  DNSSEC no, CAA no, NS_redundancy yes, no wildcard yes
                 = 0 + 0 + 4 + 3 = 7/20
    Expected ~= 24 + 16 + 21 + 7 = 68 → grade C.
    """
    checks = [
        # TLS
        _check("tls.cert_valid", "tls", True),
        _check("tls.modern_protocol", "tls", True),
        _check("tls.cert_renewal_buffer", "tls", True),
        _check("tls.hostname_match", "tls", True),
        # tls.strong_ciphers intentionally missing (not implemented yet)
        # Headers
        _check("headers.hsts", "headers", True),
        _check("headers.csp", "headers", False),
        _check("headers.frame_protection", "headers", True),
        _check("headers.nosniff", "headers", True),
        _check("headers.referrer_policy", "headers", True),
        _check("headers.permissions_policy", "headers", False),
        # Email
        _check("email.spf_present", "email", True),
        _check("email.spf_hardfail", "email", False),
        _check("email.dmarc_present", "email", True),
        _check("email.dmarc_strict_policy", "email", True),
        _check("email.dkim_detected", "email", True),
        # DNS
        _check("dns.dnssec", "dns", False),
        _check("dns.caa", "dns", False),
        _check("dns.ns_redundancy", "dns", True),
        _check("dns.wildcard_exposed", "dns", True),
    ]
    result = score_checks(checks)
    # 24 + 19 (HSTS6+frame4+nosniff3+referrer3+permissions0+csp0=16... wait recompute)
    # Headers: HSTS6 + CSP0 + frame4 + nosniff3 + referrer3 + permissions0 = 16
    # Total: 24 + 16 + 21 + 7 = 68
    assert result["score"] == 68
    assert result["grade"] == "C"


# ───────────────────────── custom rubric loading ─────────────────────────


def test_score_checks_accepts_custom_rubric(tmp_path: Path):
    """Validate end-to-end YAML loading with a tiny synthetic rubric."""
    yaml_text = {
        "version": 99,
        "categories": {
            "tls":     {"weight_total": 40, "checks": {"tls.a": 40}},
            "headers": {"weight_total": 30, "checks": {"headers.a": 30}},
            "email":   {"weight_total": 20, "checks": {"email.a": 20}},
            "dns":     {"weight_total": 10, "checks": {"dns.a": 10}},
        },
        "grade_thresholds": [
            {"min": 90, "grade": "A"},
            {"min": 50, "grade": "C"},
            {"min": 0,  "grade": "F"},
        ],
    }
    p = tmp_path / "custom.yaml"
    p.write_text(yaml.safe_dump(yaml_text), encoding="utf-8")

    rubric = load_rubric(str(p))
    result = score_checks([
        _check("tls.a", "tls", True),
        _check("headers.a", "headers", True),
        _check("email.a", "email", False),
        _check("dns.a", "dns", True),
    ], rubric=rubric)
    assert result["score"] == 40 + 30 + 10  # = 80
    assert result["rubric_version"] == 99
    # 80 is not >= 90, but >= 50 → "C"
    assert result["grade"] == "C"
