# Handoff for New Chat v6 — Domain Security Checker Project

Paste this entire document into a new chat to continue. **v6 — supersedes v5.**
Written after the "documentation + Docker" session (2026-07-09).

---

## 0. WHAT CHANGED SINCE v5 (read this first)

This session added **no feature code** — it added documentation + Docker (all uncommitted, on branch `feat/scan-history-db`):

1. **Docker (dev + prod)** — `backend/Dockerfile` (python:3.12-slim), `frontend/Dockerfile` (node:22 build → nginx with /api reverse proxy) + `frontend/nginx.conf`, `.dockerignore` ×2, `backend/.env.example`, `docker-compose.yml` (dev: hot-reload backend, Vite dev server, Postgres 16, node_modules in a named Linux volume) and `docker-compose.prod.yml` (built images, app at :8080). Guide: `docs/DOCKER.md`.
2. **`frontend/vite.config.ts` modified** (the ONLY existing file changed): /api proxy target now overridable via `VITE_API_PROXY_TARGET` env (defaults to `http://localhost:8000` — local dev unchanged).
3. **New docs:** `PROJECT_MAP.md` (annotated file map), `AGENTS.md` (conventions + all gotchas), `docs/ARCHITECTURE.md` (detailed EN system doc), `docs/DOCKER.md`, `docs/STUDY_GUIDE_TH.md` (Thai committee-prep guide with Q&A).
4. **Corrections discovered by reading actual code** (v5 was wrong/imprecise):
   - Frontend is **React 19 + Vite 8** (v5 said React 18).
   - Scan modes are **`single` / `full`** (not quick/full).
   - Full-mode domain grade = **worst host (min score)**; average shown alongside.
   - AI analyzes **apex-host findings only**; `overall_risk` is **rule-based**, not AI.
   - Port scan is **info-only** (no rubric entry → no score impact). Ports: 80/443/8080/8443/8000/3000, Semaphore(5), 20s/host timeout.
5. **Decision:** user does NOT want to rush W8 deployment — presentation will demo via Docker prod stack locally (plan in STUDY_GUIDE_TH.md §8).

**⚠️ Uncommitted work.** Commit from **Windows only** (git rule!). Suggested commits:
`docs: add project map, agents guide, architecture and study docs` + `feat: add docker dev/prod setup` (includes vite.config.ts change).
Note: `git status` from the sandbox shows phantom "M" on many files — mount artifacts (mode bits), not real changes. Verify on Windows.

---

## 1. PROJECT IDENTITY

- **Title:** AI-Assisted Lightweight Domain Security Checker ระบบตรวจสอบความปลอดภัยของโดเมนแบบเบาด้วยปัญญาประดิษฐ์
- **Type:** Senior project (Computer Engineering), Mae Fah Luang University, 2026. Advisor: Aj. Mahamah Sebakor. Deadline ~end of July 2026.
- **Team:** Role A — Pheerathad Pangputhipong (6631501086) ← ME · Role B — Muanmet Promchan (6631501118) · Role C — Pacharapol Photiyanon (6631501080)
- **Local folder (me):** `D:\MD-hand-for-new-chat\SEC_SCAN_FINAL_PROJECT\SEC_SCAN_FINAL_PROJECT` (⚠️ nested — repo root is one level down)
- **GitHub:** `https://github.com/matthew69-dotcom/SEC_SCAN_FINAL_PROJECT`

## 2. GOAL

Web tool: scan one domain (+ all subdomains), grade security posture A+–F across DNS / TLS / HTTP headers / email auth (SPF/DKIM/DMARC). AI (GPT-4o-mini) only writes human summaries — **never computes the score**; scoring is deterministic (weights.yaml).

## 3. NON-NEGOTIABLES (all satisfied)

1. No active attacks — passive observation only
2. AI never assigns the numeric score
3. Every scanner returns `CheckResult`, never raises
4. All scanners run in parallel (`asyncio.gather`)
5. Every API response includes version info (app + model + rubric)
6. A scan never fails because the DB is down (try/except everywhere DB is touched)

## 4. STACK (corrected)

Python 3.12 + FastAPI (Pydantic v2, async) · **React 19 + Vite 8** + strict TS + Tailwind 3 · SQLite dev / PostgreSQL 16 prod via async SQLAlchemy 2.0 (aiosqlite/asyncpg auto-picked from DATABASE_URL) · LangChain 0.3 + GPT-4o-mini (JSON mode, Full scan only) · dnspython (pin 8.8.8.8/1.1.1.1) · manual ssl/socket + cryptography.x509 · httpx · ip-api.com · pytest (asyncio_mode=auto) · **Docker: compose dev + prod stacks (NEW)**.
⚠️ Python 3.13 breaks wheels on Windows — use 3.12. `vite build` needs per-OS native binding (fine on Windows and in Docker `npm ci`; fails when reusing Windows node_modules on Linux — `tsc -b --noEmit` is the meaningful check).

## 5. GIT STATE

```
main / DEV (integration) / PHEERATHAD / PACHARAPOL / muanmet
feat/fe-be-integration  (PUSHED, PR → DEV)
feat/scan-history-db    (PUSHED, PR → DEV; current branch; has this session's UNCOMMITTED files)
```
Conventional Commits required. **GIT RULE: run git on Windows only, never from two places at once** (index corruption happened once; recovered via `git reset --mixed <parent>` + force-push).

## 6. HOW THE SCAN ACTUALLY WORKS (verified against code)

- `POST /api/scan {domain, mode}`; mode **single**: 4 scanners in parallel → `score_checks()` → persist (try/except). Scanner crash becomes a failed `scan.error` check, never a 500.
- mode **full**: `enumerate_hosts()` (crt.sh + DNS mining + wordlist, strip wildcards, dedup, A-record liveness, resolve concurrency 20) → scan hosts with Semaphore(5) + 20s timeout → Geo-IP all IPs → port scan (6 ports, info-only) → **domain_score = min(host scores)** + avg → AI on apex findings (ImportError/Exception swallowed; fallback template when no key → `generated_by_ai:false`, `model_used:"local-fallback"`, risk level is rule-based).
- History: `GET /api/scans`, `GET/DELETE /api/scans/{id}`; full ScanResponse stored in `ScanRecord.result_json`. Tables `create_all` on lifespan; **no Alembic** (known limitation).
- Scoring engine: pure function, lru_cached rubric, validates weights sum to 100 / no duplicate checks or grades; rubric-listed-but-missing checks earn 0 with `present:false`; duplicate check ids → last-wins.

## 7. RUBRIC (unchanged)

TLS 30 (cert_valid 10, modern_protocol 8, **strong_ciphers 6 = NOT IMPLEMENTED → max 24/30**, renewal_buffer 3, hostname_match 3) · Headers 25 (HSTS 6, CSP 6, frame 4, nosniff 3, referrer 3, permissions 3) · Email 25 (SPF 8, DMARC 7, spf_hardfail 4, dmarc_strict 4, DKIM 2) · DNS 20 (DNSSEC 8, CAA 5, ns_redundancy 4, no_wildcard 3). Grades: 95 A+ / 85 A / 75 B / 60 C / 40 D / else F.

## 8. RUNNING IT

**Windows local:** backend → `py -3.12 -m venv .venv`, activate, `pip install -r requirements.txt`, `uvicorn app.main:app --reload` (dev.db auto-created). frontend → `npm install`, `npm run dev` (:5173). AI needs `backend/.env` with `OPENAI_API_KEY` (test: `python check_ai_live.py`).
**Docker (NEW):** repo root → `docker compose up` (dev, FE :5173 / API :8000, Postgres) or `docker compose -f docker-compose.prod.yml up --build -d` (:8080). Root `.env` can hold `OPENAI_API_KEY`. Full guide `docs/DOCKER.md`. This also solves Pacharapol's broken venv (`[WinError 2]`, unresolved).
Backend tests: **56/56 offline**. Lint: ruff / eslint.

## 9. LESSONS LEARNED (cumulative — critical)

1. Assistant Edit/Write on the mounted Windows folder **silently truncated a 1300-line file** once → write big files via script/heredoc + verify `wc -l` after every write (App.tsx must stay ~1339 lines).
2. Git on Windows only (see §5). Sandbox `git status` shows phantom modifications — ignore, verify on Windows.
3. Never commit `.env` / `dev.db`.
4. langchain must be installed or AI silently falls back.
5. Geo-IP `location` approximate (UI marks "≈"); country/ISP/ASN reliable.
6. Docker dev keeps `node_modules` in a named volume — if vite/rolldown binding errors appear: `docker compose down -v && docker compose up`.

## 10. NEXT TASKS (W8 — deliberately not rushing deploy)

| Task | Owner | Notes |
| :--- | :--- | :--- |
| Commit this session's docs+Docker files (from Windows) | Me (A) | two commits suggested in §0 |
| Merge PRs `feat/fe-be-integration` + `feat/scan-history-db` → DEV | All | review then merge |
| `tls.strong_ciphers` (weight 6, last missing check) | Pheerathad (A) | unlocks TLS 30/30 |
| Validation vs SSL Labs / securityheaders.com / MXToolbox | Muanmet (B) | |
| Committee prep: read `docs/STUDY_GUIDE_TH.md`, pre-scan demo domains into History, rehearse AI-fallback demo | All | demo via Docker prod stack — no cloud deploy needed for presentation |
| Deploy Railway + Vercel | All | LATER — only when team is ready |
| Fix teammate venv (or just use Docker) | Pacharapol (C) | |

## 11. DOCS INDEX

`PROJECT_MAP.md` (file map) · `AGENTS.md` (conventions/gotchas) · `docs/ARCHITECTURE.md` (EN deep doc) · `docs/DOCKER.md` · `docs/STUDY_GUIDE_TH.md` (Thai committee Q&A) · `docs/DATABASE_SUMMARY.md` (W7) · `docs/PROJECT_SUMMARY_AND_TIMELINE.md` · `HANDOFF_FOR_NEW_CHAT_v5.md` (previous).
