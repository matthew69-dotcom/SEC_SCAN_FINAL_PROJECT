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

1. **No active attacks** — observation only, never exploit or brute-force.
2. **AI never computes the numeric score.** Scoring is deterministic, driven by
   `backend/app/scoring/weights.yaml`.
3. Every scanner returns `CheckResult` objects and **never raises**.
4. All scanners run in parallel via `asyncio.gather()`.
5. Every API response includes version info (app + model + rubric).
6. A scan must never fail because the DB is down — persistence is wrapped in
   try/except.

## Commands

```bash
# Backend (from backend/, inside a Python 3.12 venv)
pip install -r requirements.txt
uvicorn app.main:app --reload        # http://localhost:8000/docs
pytest                               # all tests are offline (mocked network)
ruff check .

# Frontend (from frontend/)
npm install
npm run dev                          # http://localhost:5173
npx tsc -b --noEmit                  # the meaningful CI check (see gotcha #4)
npm run lint

# Docker (from repo root) — see docs/DOCKER.md
docker compose up                                     # dev stack
docker compose -f docker-compose.prod.yml up --build  # prod-style stack
```

## Conventions

- **Conventional Commits required:** `feat:`, `fix:`, `refactor:`, `test:`,
  `docs:`, `chore:`, `style:`, `perf:`.
- Branches: `main` (stable) ← `DEV` (integration, PRs land here) ← personal
  branches (`PHEERATHAD`, `PACHARAPOL`, `muanmet`) and `feat/*` branches.
- Python: ruff, line length 110, target py312. Pydantic v2 models.
- TypeScript: strict, function components only.
- New security check = scanner emits `CheckResult` + entry in `weights.yaml`
  (checks not listed there are info-only and don't affect the score).
- Tests must pass offline — mock all network I/O.

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

## Environment

`backend/.env` (copy from `.env.example`): `OPENAI_API_KEY` (optional; AI only),
`OPENAI_MODEL`, `DATABASE_URL`, `CORS_ORIGINS`. Quick AI key check:
`python check_ai_live.py` → PASS means `generated_by_ai: True`.

## Current status (July 2026)

Weeks 1–7 done: scanners, scoring, discovery, AI, FE↔BE integration, DB history.
W8: `tls.strong_ciphers` implemented (2026-07-14) — all rubric checks now
covered, TLS can reach 30/30. Remaining: external validation, deploy
(Railway + Vercel), merge `feat/fe-be-integration` + `feat/scan-history-db`
→ `DEV`.
