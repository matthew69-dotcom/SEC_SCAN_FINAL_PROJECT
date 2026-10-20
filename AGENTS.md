# AGENTS.md — Guide for AI Agents & Contributors

Read this before touching the repo. See `PROJECT_MAP.md` for the file map and
`docs/ARCHITECTURE.md` for system details.

## What this project is

**AI-Assisted Lightweight Domain Security Checker** — MFU Computer Engineering
senior project (2026). Scans a domain (and its subdomains) and grades security
posture A+–F across DNS, TLS, HTTP headers, and email auth (SPF/DKIM/DMARC).
AI (GPT-4o-mini via LangChain) only writes human-readable summaries.

- Backend: Python 3.12 + FastAPI (async everywhere) — `backend/`
- Frontend: React 19 + Vite 8 + TypeScript (strict) + Tailwind — `frontend/`
- DB: SQLite (dev) / PostgreSQL 16 (prod) via async SQLAlchemy 2.0
- Repo: https://github.com/matthew69-dotcom/SEC_SCAN_FINAL_PROJECT

## Non-negotiable design rules

1. **Non-intrusive / lightweight, no attacks** — observation only, never
   exploit or brute-force auth. Describe it as "non-intrusive" or
   "lightweight", **not "passive"**: it makes normal TLS/HTTP connections, TCP
   connects to 6 ports (full mode) and resolves a ~120-name DNS wordlist.
2. **AI never computes the numeric score.** Scoring is deterministic, driven by
   `backend/app/scoring/weights.yaml`.
3. Every scanner returns `CheckResult` objects and **never raises**.
4. All scanners run in parallel via `asyncio.gather()`.
5. Every API response includes version info (app + model + rubric).
6. A scan must never fail because the DB is down — persistence is wrapped in
   try/except.
7. **Every external phase is time-bounded** (discovery, per-host scans, Geo-IP,
   ports, AI — see constants at the top of `api/routes.py`).
8. **Never connect to non-public IPs** — `utils/netsafety.py`; such hosts are
   reported (`dns.private_ip_exposed`) but not connected to or port-scanned.
9. **Never substitute or invent results** — the apex result is never replaced
   by another host's; show only what was observed and say when something
   could not be measured (`scan.apex_unavailable`, "trust chain not verified").

## Commands

```bash
# Backend (from backend/, inside a Python 3.12 venv)
pip install -r requirements.txt
uvicorn app.main:app --reload        # http://localhost:8000/docs
pytest                               # 142 tests; offline except 4 live tests in test_scanners.py (google.com)
ruff check .

# Frontend (from frontend/)
npm install
npm run dev                          # http://localhost:5173
npx tsc -b --noEmit                  # the meaningful CI check (see gotcha #4)
npm run lint

# Validation (from repo root, backend running) — see validation/README.md
python validation/validate.py run --runs 3
python validation/apply_reference.py validation/out/<stamp>/comparison.csv
python validation/validate.py report validation/out/<stamp>/comparison.csv

# Docker (from repo root) — see docs/DOCKER.md
docker compose up                                     # dev stack
docker compose -f docker-compose.prod.yml up --build  # prod-style stack
```

## Conventions

- **Conventional Commits required:** `feat:`, `fix:`, `refactor:`, `test:`,
  `docs:`, `chore:`, `style:`, `perf:`.
- Branches: `main` (first commit only; merge DEV→main only at release) ←
  `DEV` (integration) ← `feat/*`, `fix/*`, `docs/*` branches cut from DEV.
- Workflow: branch from DEV → `git add <specific files>` (never `-A`) → push →
  PR with **base `DEV`** (GitHub sometimes defaults to `main` — check) →
  review by `6631501118-cmd` → "Create a merge commit" → `git checkout DEV && git pull`.
- Python: ruff, line length 110, target py312. Pydantic v2 models.
- TypeScript: strict, function components only.
- New security check = scanner emits `CheckResult` + entry in `weights.yaml`
  (checks not listed there are info-only and don't affect the score).
- Tests must pass offline — mock all network I/O. `tests/conftest.py` blanks
  `OPENAI_API_KEY` and mocks MX / private-IP lookups for every test.

## Gotchas (learned the hard way)

1. **Git runs on Windows only, and only from one place at a time.** Running git
   from a sandbox/mount simultaneously corrupted the index once (69 files
   deleted; recovered with `git reset --mixed <parent>` + force-push).
2. **Python 3.13 breaks wheel builds on Windows — use 3.12.**
3. **Never commit `.env` or `dev.db`** (gitignored; each dev has their own).
4. **`vite build` fails on Linux when reusing Windows `node_modules`**
   (rolldown native binding is per-OS). Fresh `npm ci` on Linux (e.g. in
   Docker) is fine; `tsc -b --noEmit` is the meaningful correctness check.
5. **Editing large files on the mounted Windows folder from an assistant has
   silently truncated them** (a 1300-line file was cut). Write big files via a
   script/heredoc and **verify line counts after every write**
   (`frontend/src/App.tsx` should be ~1300+ lines).
6. `langchain` must be installed for real AI output; without it (or the key)
   the AI silently falls back to a local template (`generated_by_ai=False`).
7. IP geolocation `location` is approximate — UI marks it "≈". Country and
   ISP/ASN are reliable.
8. No Alembic migrations yet — tables are `create_all`'d on startup. Schema
   changes need a dropped/recreated dev DB.
9. **Line endings:** after `git pull` on Windows, files on disk are CRLF
   (autocrlf). Write CRLF to match; "LF will be replaced by CRLF" is harmless.
10. **Every bug of Oct 2026 was found by scanning real domains**, not by unit
    tests — run the validation harness before any demo/defense.
11. SQLite returns naive datetimes even for `DateTime(timezone=True)`; API
    schemas must mark them UTC (see `ScanHistoryItem.created_at`).

## Environment

`backend/.env` (copy from `.env.example`): `OPENAI_API_KEY` (optional; AI only),
`OPENAI_MODEL`, `DATABASE_URL`, `CORS_ORIGINS`. Quick AI key check:
`python check_ai_live.py` → PASS means `generated_by_ai: True`.

## Current status (October 2026)

Feature-complete for the rubric (TLS 30/30). Oct 2026 hardening, all merged
into `DEV`: full-scan guard rails (#5), email N/A for hosts without MX (#6),
SSRF guard (#7), apex reliability (#8), validation harness (#9), TLS trust
chain + header retry + duplicate headers + History UTC fix (#10), header
evidence with HTTP status/final URL (#11). Validation: 14/14 domains
repeatable, 198/203 = 97.5% agreement with dns.google / SSL Labs /
securityheaders.com (`validation/FINDINGS_2026-10-20.md`).

Open: SSRF guard checks A records only (AAAA not yet — `mfu.ac.th` has AAAA
`::1`); methodology questions for the advisor (web checks N/A on non-web
hosts? apex grade vs worst-host grade in the UI); thesis update; deploy
(Railway + Vercel) only if required.
