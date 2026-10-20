"""Copy saved reference verdicts (SSL Labs / securityheaders.com) into a
comparison.csv produced by ``validate.py run``.

The TLS and header references cannot be fetched automatically by validate.py
without an SSL Labs registration (and securityheaders.com's API is paid), so
they were collected once and saved in ``validation/reference/*.csv``
(columns: domain, check, ref, source, evidence). This script fills the
``ref_manual`` column of a comparison.csv from such a file, so the same
reference can be applied to every new validation run.

Usage (repo root):

    python validation/apply_reference.py validation/out/<stamp>/comparison.csv
    python validation/validate.py report validation/out/<stamp>/comparison.csv

Options:
    --reference PATH   reference file (default: newest validation/reference/*.csv)
    --overwrite        also replace ref_manual values that are already filled

Note: the reference is a snapshot. Sites change their headers, so re-collect
the reference if it is much older than the scan you compare it with.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REF_DIR = Path(__file__).resolve().parent / "reference"


def load_reference(path: Path) -> dict[tuple[str, str], str]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return {
            (r["domain"].strip(), r["check"].strip()): r["ref"].strip().lower()
            for r in csv.DictReader(f)
            if r.get("ref", "").strip().lower() in ("pass", "fail")
        }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("comparison", help="validation/out/<stamp>/comparison.csv")
    p.add_argument("--reference", default="", help="reference CSV (default: newest in validation/reference/)")
    p.add_argument("--overwrite", action="store_true", help="replace ref_manual values already filled")
    args = p.parse_args(argv)

    if args.reference:
        ref_path = Path(args.reference)
    else:
        candidates = sorted(REF_DIR.glob("*.csv"))
        if not candidates:
            print(f"No reference files in {REF_DIR}", file=sys.stderr)
            return 1
        ref_path = candidates[-1]
    ref = load_reference(ref_path)

    comp_path = Path(args.comparison)
    with comp_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = list(reader.fieldnames or [])
        rows = list(reader)

    filled = kept = missing = 0
    for r in rows:
        key = (r["domain"], r["check"])
        if not (r["check"].startswith("tls.") or r["check"].startswith("headers.")):
            continue
        if key not in ref:
            missing += 1
            continue
        if r.get("ref_manual", "").strip() and not args.overwrite:
            kept += 1
            continue
        r["ref_manual"] = ref[key]
        filled += 1

    with comp_path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print(f"Reference: {ref_path.name}")
    print(f"ref_manual filled: {filled}, already set (kept): {kept}, no reference: {missing}")
    print(f"Next: python validation/validate.py report {comp_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
