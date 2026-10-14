"""Validation harness for the Domain Security Checker.

Answers two committee questions with data:

  1. "Is it repeatable?"  -> scan each domain N times, report grade/score
     stability and which checks flip between runs.
  2. "Is it correct?"     -> compare our per-check verdicts with independent
     references:
       * DNS / email facts  -> Google DNS-over-HTTPS (dns.google), automatic.
         A different resolver path and different code from our scanners.
       * TLS                -> Qualys SSL Labs API v4, automatic but OPTIONAL
         (needs a one-time registration with an organisational e-mail).
       * HTTP headers       -> securityheaders.com, MANUAL (their API is
         paid); the CSV has a ref_manual column + link to fill in.

Usage (from the repo root, with the backend running on :8000):

    python validation/validate.py run --runs 3
    # optional, once: python validation/validate.py register --first .. --last .. --email you@lamduan.mfu.ac.th
    python validation/validate.py run --runs 3 --ssllabs-email you@lamduan.mfu.ac.th
    # (optionally fill ref_manual in validation/out/<stamp>/comparison.csv)
    python validation/validate.py report validation/out/<stamp>/comparison.csv

Outputs go to validation/out/<timestamp>/:
    raw_scans.json      every API response (evidence for the report)
    stability.csv       one row per domain
    comparison.csv      one row per (domain, check): ours vs reference
    summary.md          tables ready to paste into the thesis

Only `httpx` is needed (already in backend/requirements.txt).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
DEFAULT_DOMAINS = HERE / "domains.txt"
DEFAULT_API = "http://127.0.0.1:8000/api"
DOH_URL = "https://dns.google/resolve"
SSLLABS_URL = "https://api.ssllabs.com/api/v4/analyze"

# Our check id -> (reference source, short description of what is compared)
DOH_CHECKS = {
    "email.spf_present": "TXT v=spf1 at apex",
    "email.spf_hardfail": "SPF ends with -all",
    "email.dmarc_present": "TXT v=DMARC1 at _dmarc",
    "email.dmarc_strict_policy": "DMARC p=quarantine|reject",
    "dns.caa": "CAA record(s) at apex",
    "dns.ns_redundancy": ">= 2 NS records",
    "dns.dnssec": "resolver AD flag (validated DNSSEC chain)",
}
SSLLABS_CHECKS = {
    "tls.cert_valid": "SSL Labs: no trust issue (grade != T) and cert not expired",
    "tls.hostname_match": "SSL Labs: grade != M (name mismatch)",
    "tls.modern_protocol": "SSL Labs: supports TLS 1.2 or 1.3",
}
HEADER_CHECKS = {
    "headers.hsts": "Strict-Transport-Security",
    "headers.csp": "Content-Security-Policy",
    "headers.frame_protection": "X-Frame-Options / frame-ancestors",
    "headers.nosniff": "X-Content-Type-Options",
    "headers.referrer_policy": "Referrer-Policy",
    "headers.permissions_policy": "Permissions-Policy",
}


# ─────────────────────────────── helpers ────────────────────────────────────

def load_domains(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.append(line)
    return out


def verdicts(findings: list[dict]) -> dict[str, bool]:
    """check id -> passed (last one wins, like the scoring engine)."""
    return {f["id"]: bool(f["passed"]) for f in findings}


def majority(values: list[bool]) -> bool | None:
    if not values:
        return None
    c = Counter(values)
    return c[True] >= c[False]


def fmt(v: bool | None) -> str:
    return "" if v is None else ("pass" if v else "fail")


# ─────────────────────────────── our scanner ────────────────────────────────

def scan(client: httpx.Client, api: str, domain: str, mode: str) -> dict:
    r = client.post(f"{api}/scan", json={"domain": domain, "mode": mode}, timeout=300)
    r.raise_for_status()
    return r.json()


# ─────────────────────────── reference: DNS over HTTPS ──────────────────────

def doh(client: httpx.Client, name: str, rtype: str) -> dict:
    r = client.get(DOH_URL, params={"name": name, "type": rtype, "do": "1"}, timeout=15)
    r.raise_for_status()
    return r.json()


def _txt(answer: list[dict]) -> list[str]:
    out = []
    for a in answer or []:
        if a.get("type") == 16:
            data = a.get("data", "")
            # "part1" "part2" -> part1part2 ; unquoted -> as is
            parts = [p for p in data.split('"') if p.strip()] if '"' in data else [data]
            out.append("".join(parts).strip())
    return out


def doh_reference(client: httpx.Client, domain: str) -> dict[str, bool | None]:
    ref: dict[str, bool | None] = {}
    try:
        txt = _txt(doh(client, domain, "TXT").get("Answer"))
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        ref["email.spf_present"] = spf is not None
        ref["email.spf_hardfail"] = bool(spf) and spf.strip().lower().split()[-1] == "-all"

        dmarc_txt = _txt(doh(client, f"_dmarc.{domain}", "TXT").get("Answer"))
        dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), None)
        ref["email.dmarc_present"] = dmarc is not None
        policy = None
        if dmarc:
            for tag in dmarc.split(";"):
                k, _, v = tag.strip().partition("=")
                if k.strip().lower() == "p":
                    policy = v.strip().lower()
        ref["email.dmarc_strict_policy"] = policy in ("quarantine", "reject")

        caa = doh(client, domain, "CAA").get("Answer") or []
        ref["dns.caa"] = any(a.get("type") == 257 for a in caa)

        ns = doh(client, domain, "NS").get("Answer") or []
        ref["dns.ns_redundancy"] = sum(1 for a in ns if a.get("type") == 2) >= 2

        a_resp = doh(client, domain, "A")
        ref["dns.dnssec"] = bool(a_resp.get("AD"))
    except (httpx.HTTPError, ValueError) as exc:
        print(f"    ! DoH lookup failed for {domain}: {exc}", file=sys.stderr)
    return ref


# ───────────────────────────── reference: SSL Labs ──────────────────────────

def ssllabs_reference(client: httpx.Client, domain: str, email: str,
                      max_wait: int = 600) -> tuple[dict[str, bool | None], str]:
    """Return (check verdicts, ssl labs grade). Uses a <=24h cached report if
    available so we don't hammer Qualys. Results are never published."""
    headers = {"email": email}
    params = {"host": domain, "fromCache": "on", "maxAge": "24", "all": "done", "publish": "off"}
    deadline = time.time() + max_wait
    data: dict = {}
    while time.time() < deadline:
        r = client.get(SSLLABS_URL, params=params, headers=headers, timeout=30)
        if r.status_code == 429:
            time.sleep(30)
            continue
        if r.status_code in (503, 529):
            print("    ! SSL Labs overloaded — skipping", file=sys.stderr)
            return {}, ""
        r.raise_for_status()
        data = r.json()
        if data.get("status") in ("READY", "ERROR"):
            break
        time.sleep(10)
    if data.get("status") != "READY" or not data.get("endpoints"):
        return {}, data.get("statusMessage", "") or ""

    ep = data["endpoints"][0]
    grade = ep.get("grade", "") or ""
    details = ep.get("details") or {}
    protocols = {(p.get("name"), p.get("version")) for p in details.get("protocols", [])}
    modern = any(name == "TLS" and ver in ("1.2", "1.3") for name, ver in protocols)

    now_ms = time.time() * 1000
    leaf = (data.get("certs") or [{}])[0]
    not_expired = leaf.get("notAfter", 0) > now_ms if leaf else None

    ref: dict[str, bool | None] = {
        "tls.cert_valid": (grade != "T") and bool(not_expired) if grade else None,
        "tls.hostname_match": (grade != "M") if grade else None,
        "tls.modern_protocol": modern if protocols else None,
    }
    return ref, grade


# ──────────────────────────────── commands ──────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    domains = load_domains(Path(args.domains))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) / stamp
    out.mkdir(parents=True, exist_ok=True)

    raw: dict[str, list[dict]] = {}
    stability_rows, comparison_rows = [], []

    with httpx.Client() as client:
        try:
            client.get(f"{args.api}/health", timeout=5).raise_for_status()
        except httpx.HTTPError as exc:
            print(f"Backend not reachable at {args.api} ({exc}). Start uvicorn first.")
            return 2

        for i, domain in enumerate(domains, 1):
            print(f"[{i}/{len(domains)}] {domain}")
            runs: list[dict] = []
            for n in range(args.runs):
                t0 = time.perf_counter()
                try:
                    resp = scan(client, args.api, domain, args.mode)
                except httpx.HTTPError as exc:
                    print(f"    run {n + 1}: ERROR {exc}")
                    continue
                resp["_elapsed_s"] = round(time.perf_counter() - t0, 1)
                runs.append(resp)
                print(f"    run {n + 1}: {resp['grade']} {resp['score']} "
                      f"({len(resp['findings'])} findings, {resp['_elapsed_s']}s)")
                if n + 1 < args.runs:
                    time.sleep(args.pause)
            raw[domain] = runs

            # ── stability ──
            grades = [r["grade"] for r in runs]
            scores = [r["score"] for r in runs]
            per_run = [verdicts(r["findings"]) for r in runs]
            all_ids = sorted({k for v in per_run for k in v})
            # A check "flips" if its verdict differs OR it is missing in some
            # runs (e.g. headers.fetch failing replaces the 6 header checks).
            flipping = [cid for cid in all_ids
                        if len({v.get(cid) for v in per_run}) > 1]
            stability_rows.append({
                "domain": domain, "mode": args.mode, "runs_ok": len(runs),
                "grades": " ".join(grades), "scores": " ".join(map(str, scores)),
                "score_range": (max(scores) - min(scores)) if scores else "",
                "stable_grade": len(set(grades)) == 1 if grades else "",
                "flipping_checks": " ".join(flipping),
                "avg_seconds": round(sum(r["_elapsed_s"] for r in runs) / len(runs), 1) if runs else "",
            })

            # ── comparison ──
            ours = {cid: majority([v[cid] for v in per_run if cid in v]) for cid in all_ids}
            ref_doh = doh_reference(client, domain)
            ref_ssl: dict[str, bool | None] = {}
            ssl_grade = ""
            if args.ssllabs_email:
                print("    SSL Labs reference (can take a few minutes)…")
                try:
                    ref_ssl, ssl_grade = ssllabs_reference(client, domain, args.ssllabs_email)
                except httpx.HTTPError as exc:
                    print(f"    ! SSL Labs failed: {exc}", file=sys.stderr)

            def row(cid: str, what: str, source: str, ref: bool | None, link: str,
                    domain: str = domain, ours: dict = ours) -> dict:
                o = ours.get(cid)
                return {
                    "domain": domain, "check": cid, "compares": what,
                    "ours": fmt(o), "ref_auto": fmt(ref), "ref_source": source,
                    "ref_manual": "", "agree": "" if (o is None or ref is None) else (o == ref),
                    "reference_link": link,
                }

            for cid, what in DOH_CHECKS.items():
                comparison_rows.append(row(cid, what, "dns.google DoH", ref_doh.get(cid),
                                           f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}"))
            for cid, what in SSLLABS_CHECKS.items():
                comparison_rows.append(row(
                    cid, what, f"SSL Labs (grade {ssl_grade})" if ssl_grade else "SSL Labs (manual)",
                    ref_ssl.get(cid), f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}&hideResults=on"))
            for cid, what in HEADER_CHECKS.items():
                comparison_rows.append(row(cid, what, "securityheaders.com (manual)", None,
                                           f"https://securityheaders.com/?q={domain}&hide=on&followRedirects=on"))

    (out / "raw_scans.json").write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_csv(out / "stability.csv", stability_rows)
    _write_csv(out / "comparison.csv", comparison_rows)
    summary = build_summary(stability_rows, comparison_rows)
    (out / "summary.md").write_text(summary, encoding="utf-8")
    print("\n" + summary)
    print(f"\nSaved to {out}")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    """One-time SSL Labs API v4 registration (organisational e-mail only)."""
    body = {"firstName": args.first, "lastName": args.last,
            "email": args.email, "organization": args.org}
    r = httpx.post("https://api.ssllabs.com/api/v4/register", json=body, timeout=30)
    print(r.status_code, r.text)
    return 0 if r.is_success else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Re-compute agreement after ref_manual has been filled in."""
    path = Path(args.comparison)
    with path.open(encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        ref = (r.get("ref_manual") or "").strip().lower() or r.get("ref_auto", "")
        r["agree"] = "" if not (r["ours"] and ref) else (r["ours"] == ref)
    stab_path = path.with_name("stability.csv")
    stab = list(csv.DictReader(stab_path.open(encoding="utf-8-sig"))) if stab_path.exists() else []
    summary = build_summary(stab, rows)
    path.with_name("summary.md").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


def build_summary(stability: list[dict], comparison: list[dict]) -> str:
    lines = ["# Validation summary", ""]
    if stability:
        stable = sum(1 for s in stability if str(s["stable_grade"]) == "True")
        lines += [f"## Repeatability — {stable}/{len(stability)} domains got the same grade on every run", "",
                  "| Domain | Grades | Scores | Range | Flipping checks | Avg s |",
                  "| :-- | :-- | :-- | --: | :-- | --: |"]
        for s in stability:
            lines.append(f"| {s['domain']} | {s['grades']} | {s['scores']} | {s['score_range']} "
                         f"| {s['flipping_checks'] or '—'} | {s['avg_seconds']} |")
        lines.append("")

    by_check: dict[str, list[bool]] = {}
    for r in comparison:
        if str(r["agree"]) in ("True", "False"):
            by_check.setdefault(r["check"], []).append(str(r["agree"]) == "True")
    total = [a for v in by_check.values() for a in v]
    if total:
        pct = 100 * sum(total) / len(total)
        lines += [f"## Agreement with reference tools — {sum(total)}/{len(total)} = {pct:.1f}%", "",
                  "| Check | Agree | Compared | % |", "| :-- | --: | --: | --: |"]
        for cid in sorted(by_check):
            v = by_check[cid]
            lines.append(f"| {cid} | {sum(v)} | {len(v)} | {100 * sum(v) / len(v):.0f}% |")
        lines.append("")
        dis = [r for r in comparison if str(r["agree"]) == "False"]
        if dis:
            lines += ["## Disagreements (investigate each one)", "",
                      "| Domain | Check | Ours | Reference | Source |", "| :-- | :-- | :-- | :-- | :-- |"]
            for r in dis:
                ref = (r.get("ref_manual") or "").strip().lower() or r["ref_auto"]
                lines.append(f"| {r['domain']} | {r['check']} | {r['ours']} | {ref} | {r['ref_source']} |")
            lines.append("")
    pending = sum(1 for r in comparison if not str(r["agree"]))
    if pending:
        lines.append(f"_{pending} row(s) have no reference yet — fill `ref_manual` (pass/fail) "
                     "in comparison.csv using `reference_link`, then run the `report` command._")
    return "\n".join(lines) + "\n"


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    # utf-8-sig so Excel opens Thai text / symbols correctly
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="scan domains, fetch references, write CSV + summary")
    r.add_argument("--domains", default=str(DEFAULT_DOMAINS))
    r.add_argument("--runs", type=int, default=3)
    r.add_argument("--mode", choices=["single", "full"], default="single",
                   help="single = apex only (fast, best for per-check accuracy); "
                        "full = multi-host (slow, for stability of the domain grade)")
    r.add_argument("--api", default=DEFAULT_API)
    r.add_argument("--pause", type=float, default=5.0, help="seconds between runs")
    r.add_argument("--ssllabs-email", default="",
                   help="registered SSL Labs API v4 e-mail (organisational); omit to skip")
    r.add_argument("--out", default=str(HERE / "out"))
    r.set_defaults(func=cmd_run)

    reg = sub.add_parser("register", help="one-time SSL Labs API v4 registration")
    reg.add_argument("--first", required=True)
    reg.add_argument("--last", required=True)
    reg.add_argument("--email", required=True, help="organisational e-mail, e.g. @lamduan.mfu.ac.th")
    reg.add_argument("--org", default="Mae Fah Luang University")
    reg.set_defaults(func=cmd_register)

    rep = sub.add_parser("report", help="recompute agreement after filling ref_manual")
    rep.add_argument("comparison", help="path to comparison.csv")
    rep.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
