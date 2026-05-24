"""Email Authentication Scanner.

Checks SPF, DMARC, and DKIM via DNS lookups.

- SPF:   look up TXT at the apex domain, find a record starting with "v=spf1"
- DMARC: look up TXT at "_dmarc.<domain>", find a record starting with "v=DMARC1"
- DKIM:  try a list of common selectors (default, google, selector1, mail, k1).
         Cannot enumerate without knowing the selector, so we settle for "best
         effort detection". A pass here is non-binding; an explicit fail does
         mean the domain hasn't published one under common selectors.

Scoring weights from the rubric (out of 25):
  SPF present (8) + SPF hard-fail -all (4) + DMARC present (7) +
  DMARC policy quarantine/reject (4) + DKIM detected (2) = 25
"""
from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception

from app.scanners.base import CheckResult


# Pinned to public resolvers — see dns_scanner.py for rationale.
# Fixes the Week 3 SPF false-negative ("DNS error: NoNameservers") on networks
# that filter or rewrite TXT queries from the system resolver.
_resolver = dns.asyncresolver.Resolver(configure=False)
_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
_resolver.timeout = 4.0
_resolver.lifetime = 8.0

# Best-effort DKIM selectors. NOT exhaustive — many orgs use custom selectors.
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "k1", "s1"]


async def _txt_records(name: str) -> tuple[list[str], str | None]:
    try:
        ans = await _resolver.resolve(name, "TXT")
        # Each rdata is a sequence of byte strings — join and decode
        records = ["".join(s.decode() for s in r.strings) for r in ans]
        return records, None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "no TXT records"
    except dns.exception.Timeout:
        return [], "DNS timeout"
    except dns.exception.DNSException as e:
        return [], f"DNS error: {e.__class__.__name__}"


async def _check_spf(domain: str) -> list[CheckResult]:
    records, err = await _txt_records(domain)
    spf = next((r for r in records if r.lower().startswith("v=spf1")), None)

    if not spf:
        return [{
            "id": "email.spf_present", "category": "email",
            "title": "No SPF record", "passed": False, "severity": "high",
            "evidence": err or "no v=spf1 TXT record at apex",
            "remediation": "Publish an SPF record, e.g. `v=spf1 include:_spf.google.com -all`",
        }, {
            "id": "email.spf_hardfail", "category": "email",
            "title": "SPF hard-fail not configured", "passed": False, "severity": "medium",
            "evidence": "skipped (no SPF record to evaluate)",
            "remediation": "After publishing SPF, end it with `-all` to hard-fail unauthorized senders.",
        }]

    spf_present: CheckResult = {
        "id": "email.spf_present", "category": "email",
        "title": "SPF record present", "passed": True, "severity": "info",
        "evidence": spf[:160] + ("..." if len(spf) > 160 else ""),
        "remediation": "",
    }

    end = spf.strip().lower().split()[-1]
    if end == "-all":
        spf_hardfail: CheckResult = {
            "id": "email.spf_hardfail", "category": "email",
            "title": "SPF uses hard-fail (-all)", "passed": True, "severity": "info",
            "evidence": f"qualifier: {end}", "remediation": "",
        }
    else:
        spf_hardfail = {
            "id": "email.spf_hardfail", "category": "email",
            "title": f"SPF qualifier is weak ({end})", "passed": False, "severity": "medium",
            "evidence": f"qualifier: {end}",
            "remediation": "Replace the final `~all` or `+all` with `-all` to hard-fail unauthorized senders.",
        }

    return [spf_present, spf_hardfail]


async def _check_dmarc(domain: str) -> list[CheckResult]:
    records, err = await _txt_records(f"_dmarc.{domain}")
    dmarc = next((r for r in records if r.lower().startswith("v=dmarc1")), None)

    if not dmarc:
        return [{
            "id": "email.dmarc_present", "category": "email",
            "title": "No DMARC record", "passed": False, "severity": "high",
            "evidence": err or "no v=DMARC1 TXT at _dmarc subdomain",
            "remediation": "Publish a DMARC record at `_dmarc.<domain>`, e.g. `v=DMARC1; p=quarantine; rua=mailto:admin@yourdomain`",
        }, {
            "id": "email.dmarc_strict_policy", "category": "email",
            "title": "DMARC strict policy not set", "passed": False, "severity": "medium",
            "evidence": "skipped (no DMARC record)",
            "remediation": "After publishing DMARC, set p=quarantine or p=reject (not p=none).",
        }]

    dmarc_present: CheckResult = {
        "id": "email.dmarc_present", "category": "email",
        "title": "DMARC record present", "passed": True, "severity": "info",
        "evidence": dmarc[:160] + ("..." if len(dmarc) > 160 else ""),
        "remediation": "",
    }

    policy = "none"
    for tag in dmarc.split(";"):
        k, _, v = tag.partition("=")
        if k.strip().lower() == "p":
            policy = v.strip().lower()
            break

    if policy in {"quarantine", "reject"}:
        dmarc_policy: CheckResult = {
            "id": "email.dmarc_strict_policy", "category": "email",
            "title": f"DMARC policy is strict ({policy})", "passed": True, "severity": "info",
            "evidence": f"p={policy}", "remediation": "",
        }
    else:
        dmarc_policy = {
            "id": "email.dmarc_strict_policy", "category": "email",
            "title": f"DMARC policy is permissive ({policy})", "passed": False, "severity": "medium",
            "evidence": f"p={policy}",
            "remediation": "Tighten DMARC to `p=quarantine` (then to `p=reject` after monitoring).",
        }

    return [dmarc_present, dmarc_policy]


async def _check_dkim(domain: str) -> CheckResult:
    """Try common selectors. Pass if any returns a TXT containing v=DKIM1 or p=."""
    async def probe(sel: str) -> tuple[str, str | None]:
        records, _ = await _txt_records(f"{sel}._domainkey.{domain}")
        for r in records:
            low = r.lower()
            if "v=dkim1" in low or "p=" in low:
                return sel, r
        return sel, None

    results = await asyncio.gather(*(probe(s) for s in _DKIM_SELECTORS))
    found = [(sel, rec) for sel, rec in results if rec]

    if found:
        sel, rec = found[0]
        return {
            "id": "email.dkim_detected", "category": "email",
            "title": "DKIM key detected", "passed": True, "severity": "info",
            "evidence": f"selector '{sel}' has DKIM TXT record",
            "remediation": "",
        }
    return {
        "id": "email.dkim_detected", "category": "email",
        "title": "DKIM not detected under common selectors", "passed": False, "severity": "low",
        "evidence": f"tried selectors: {', '.join(_DKIM_SELECTORS)}",
        "remediation": "Publish a DKIM key and configure your MTA to sign outgoing mail. The selector depends on your provider.",
    }


async def scan_email(domain: str) -> list[CheckResult]:
    spf, dmarc, dkim = await asyncio.gather(
        _check_spf(domain),
        _check_dmarc(domain),
        _check_dkim(domain),
        return_exceptions=True,
    )

    results: list[CheckResult] = []
    for r in (spf, dmarc, dkim):
        if isinstance(r, Exception):
            results.append({
                "id": "email.error", "category": "email",
                "title": "Internal email scan error", "passed": False, "severity": "low",
                "evidence": f"{r.__class__.__name__}: {r}", "remediation": "",
            })
        elif isinstance(r, list):
            results.extend(r)
        else:
            results.append(r)
    return results
