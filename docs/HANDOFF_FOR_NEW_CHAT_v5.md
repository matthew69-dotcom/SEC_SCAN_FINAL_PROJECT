# Handoff for New Chat v5 — Domain Security Checker Project

Paste this entire document into a new chat to continue. This is **v5** — supersedes v4. Written after the session that completed the **frontend↔backend integration** and the **Week 7 database**.

---

## 0. WHAT CHANGED SINCE v4 (read this first)

Since v4, the following was completed (mostly Role C's W7 work, done with Role A helping a teammate):

1. **Frontend ↔ backend fully wired** — the UI now shows Geo-IP location, ISP/ASN, open ports, and the structured AI risk summary that the backend already returned. Branch `feat/fe-be-integration` (pushed).
2. **AI confirmed working** — OpenAI key is set up in `backend/.env`; `langchain` packages added to `requirements.txt`. AI runs only in **Full scan** mode.
3. **Week 7 database DONE** — scan-history persistence with async SQLAlchemy (SQLite dev / PostgreSQL prod), history API, and frontend History page now reads from the server. Branch `feat/scan-history-db` (pushed).

**W7 is effectively complete** (Frontend Dashboard + PostgreSQL/DB). Remaining = **W8** (validation, deploy, `tls.strong_ciphers`) + merging PRs into `DEV`.

---

## 1. PROJECT IDENTITY

- **Title:** AI-Assisted Lightweight Domain Security Checker ระบบตรวจสอบความปลอดภัยของโดเมนแบบเบาด้วยปัญญาประดิษฐ์
- **Type:** Senior project (Computer Engineering)
- **School:** Mae Fah Luang University (MFU)
- **Advisor:** Aj. Mahamah Sebakor
- **Year:** 2026
- **Team (3 people):**
  - **Role A — Pheerathad Pangputhipong (6631501086)** ← THIS IS ME
  - Role B — Muanmet Promchan (6631501118)
  - Role C — Pacharapol Photiyanon (6631501080)
- **Deadline:** ~end of July 2026
- **Local working folder (me):** `D:\MD-hand-for-new-chat\SEC_SCAN_FINAL_PROJECT\SEC_SCAN_FINAL_PROJECT` (⚠️ nested — the real repo is one level down)
- **GitHub:** `https://github.com/matthew69-dotcom/SEC_SCAN_FINAL_PROJECT`

> **Note on paths:** the git repo root is the **nested** `SEC_SCAN_FINAL_PROJECT\SEC_SCAN_FINAL_PROJECT`. `backend` and `frontend` live inside that. A teammate (Pacharapol) works on `C:\Users\ASUS\Documents\GitHub\SEC_SCAN_FINAL_PROJECT` (not nested there).

---

## 2. PROJECT GOAL (1-paragraph)

Build a web tool that scans a single domain (and all its subdomains) and grades its security posture A+ to F. Covers DNS, HTTPS/TLS, HTTP security headers, and email auth (SPF/DKIM/DMARC). AI translates findings into human-readable summaries; **AI never computes the numeric score**. Scoring is deterministic and reproducible.

---

## 3. NON-NEGOTIABLES (design rules — all satisfied)

1. ✅ No active attacks — observation only
2. ✅ AI never assigns numeric score — deterministic YAML-driven engine
3. ✅ Every scanner returns `CheckResult` and never raises
4. ✅ All scanners run in parallel via `asyncio.gather()`
5. ✅ Every API response includes version info (app + model + rubric)
6. ✅ **NEW:** A scan must never fail because the DB is down — persistence is wrapped in try/except

---

## 4. STACK

| Layer | Tech | Notes |
| :---- | :---- | :---- |
| Backend | Python 3.12 + FastAPI 0.115+ | Pydantic v2, async everywhere |
| Frontend | React 18 + Vite + TypeScript + Tailwind | strict TS, function components only |
| Database | **SQLite (dev) / PostgreSQL 16 (prod)** | **async SQLAlchemy 2.0 — DONE (W7)** |
| AI | OpenAI GPT-4o-mini via LangChain 0.3+ | JSON-mode; only runs in Full scan |
| DNS | dnspython | pinned to 8.8.8.8 / 1.1.1.1 |
| TLS | ssl + socket + cryptography.x509 | manual handshake |
| HTTP | httpx.AsyncClient | follow_redirects=True |
| Geo-IP | ip-api.com (free) | location approximate; country/ISP/ASN reliable |
| Tests | pytest + pytest-asyncio | asyncio_mode = "auto" |
| Scoring | pyyaml + custom engine | weights.yaml-driven |
| Deploy | Railway (backend) + Vercel (frontend) | **W8 — pending** |

**Python 3.13 caused wheel-build errors on Windows. Stick with 3.12.**
**Frontend uses rolldown-vite; `vite build` needs native binding installed per-OS (fine on Windows, fails in Linux sandbox — not a code error).**

---

## 5. GIT — BRANCHES & STATE

```
main            ← stable
DEV             ← integration branch (PRs land here)
PHEERATHAD      ← my branch (Role A)
PACHARAPOL      ← Role C branch
muanmet         ← Role B branch
feat/fe-be-integration  ← frontend wiring + langchain dep  (PUSHED, PR → DEV)
feat/scan-history-db    ← W7 database                      (PUSHED, PR → DEV)
```

**Conventional Commits required:** `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `style:`, `perf:`

**Open PRs to create/merge into DEV:**
- `feat/fe-be-integration` → DEV
- `feat/scan-history-db` → DEV (based on feat/fe-be-integration)

**⚠️ GIT RULE (learned the hard way):** run git **only on Windows**, never from two places at once. Running git from a sandbox/mount at the same time corrupted the index and once produced a bad commit that deleted 69 files (recovered via `git reset --mixed <parent>` + re-commit + force-push).

---

## 6. WHAT'S BUILT — CURRENT BACKEND TREE

```
backend/
├── requirements.txt          # + langchain*, + sqlalchemy/aiosqlite/asyncpg/greenlet
├── .env                      # OPENAI_API_KEY (gitignored — each dev makes their own)
├── check_ai_live.py          # NEW helper: quick live test of the AI key (untracked)
├── app/
│   ├── main.py               # + lifespan → init_db() on startup
│   ├── config.py             # database_url default = sqlite:///./dev.db
│   ├── api/
│   │   ├── routes.py         # /scan persists to DB; + GET /scans, GET /scans/{id}, DELETE /scans/{id}
│   │   └── schemas.py        # + ScanHistoryItem
│   ├── scanners/             # dns, tls, header, email, port
│   ├── scoring/              # weights.yaml + engine
│   ├── discovery/            # crt.sh + dns_mining + wordlist
│   ├── utils/geoip.py        # ip-api.com
│   ├── ai/                   # analyzer/service/prompts (LangChain + GPT-4o-mini)
│   └── db/                   # NEW W7
│       ├── database.py       # async engine; auto-picks aiosqlite/asyncpg from DATABASE_URL
│       ├── models.py         # ScanRecord (+ result_json JSON column)
│       ├── crud.py           # create / list / get / delete
│       └── __init__.py
└── tests/
    ├── test_main.py, test_scanners.py, test_scoring.py,
    ├── test_discovery.py, test_multi_host.py, test_ai.py,
    └── test_db.py            # NEW — 5 tests

Backend tests: 56/56 passing offline (51 + 5 new DB).
```

**Frontend:** `src/api.ts` (+ listScans/getScan/deleteScan, ScanHistoryItem, geo/port/ai_summary types) and `src/App.tsx` (history page reads server DB; result page shows geo/ports/AI card; location marked "≈ approximate").

---

## 7. DATABASE (W7) — KEY FACTS

- **Model `ScanRecord`:** scan_id (PK), domain, mode, score, grade, findings_count, created_at, `result_json` (full ScanResponse stored as JSON).
- **Endpoints:** `GET /api/scans` (list newest-first), `GET /api/scans/{id}` (full result), `DELETE /api/scans/{id}`. `POST /api/scan` now auto-persists.
- **Dev vs Prod:** one codebase; `DATABASE_URL` picks the driver. `sqlite:///` → aiosqlite; `postgresql://`/`postgres://` → asyncpg (auto-rewritten to `+asyncpg`).
- **Tables auto-created** on startup via `init_db()` (`create_all`) — no Alembic yet (documented limitation).
- **Robustness:** persistence + init wrapped in try/except → scan never fails if DB is down.
- **`dev.db` is gitignored.** Each dev gets their own local DB (history not shared).
- Full write-up: `docs/DATABASE_SUMMARY.md`.

---

## 8. ENVIRONMENT SETUP (Windows)

```cmd
:: repo root is the NESTED folder
cd /d <...>\SEC_SCAN_FINAL_PROJECT\SEC_SCAN_FINAL_PROJECT\backend
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt          :: includes langchain + sqlalchemy now
:: create .env with OPENAI_API_KEY=sk-...  (needed only for AI; scan/DB work without it)
uvicorn app.main:app --reload            :: dev.db auto-created

:: frontend (separate terminal)
cd <...>\SEC_SCAN_FINAL_PROJECT\SEC_SCAN_FINAL_PROJECT\frontend
npm install
npm run dev                              :: http://localhost:5173
```

- AI + Geo-IP + open ports show only in **Full scan** mode (toggle in the UI).
- Quick AI key test (no network scan needed): `python check_ai_live.py` → PASS means `generated_by_ai: True`.

**Teammate venv issue (unresolved as of this handoff):** on `C:\Users\ASUS\Documents\GitHub\...`, `py -3.12 -m venv .venv` fails with `[WinError 2]` even with `--without-pip`. Interpreter is a valid python.org install (`AppData\Local\Programs\Python\Python312`), NOT Store. Next diagnostic step: `py -3.12 -m venv C:\dev\testvenv` — if that works, the problem is the `Documents\GitHub` location (OneDrive sync/AV) → move repo to `C:\dev\...`; if it fails too, repair the Python install (installer → Modify → Repair).

---

## 9. LESSONS LEARNED (new in this session)

1. **Editing large files on a mounted Windows folder from the assistant truncated them** (Edit/Write silently cut a 1300-line file). Fix: edit via a Python script / `cat > file << 'EOF'`, and verify line count after every write.
2. **git index corruption** from running git in two places on the same mount. Only run git on Windows. Recover a bad tree with `git reset --mixed <good-parent>` then re-commit + `git push --force-with-lease`.
3. `.env` and `dev.db` are gitignored — never commit them; each dev creates their own.
4. **langchain is required for AI** — it's now in requirements.txt; without it the AI silently falls back to a local template (`generated_by_ai=False`).
5. Frontend `vite build` fails in Linux (rolldown native binding) but is fine on Windows — not a code bug; `tsc -b --noEmit` is the meaningful check.
6. IP geolocation `location` is approximate (registered network location, and CDN edges skew it); country + ISP/ASN are reliable. UI now marks it "≈".

---

## 10. NEXT IMMEDIATE TASKS (W8)

| Task | Owner | Notes |
| :---- | :---- | :---- |
| Merge PRs `feat/fe-be-integration` + `feat/scan-history-db` → DEV | All | review then merge |
| `tls.strong_ciphers` (weight 6, last missing check) | Pheerathad (A) | max TLS currently 24/30 |
| Validation vs SSL Labs / securityheaders.com / MXToolbox | Muanmet (B) | W8 |
| Deploy: Railway (backend) + Vercel (frontend) | All | set `DATABASE_URL` to Postgres on Railway; set `OPENAI_API_KEY`; set CORS origin to the Vercel URL |
| Fix teammate venv (see §8) | Pacharapol (C) | blocking his local runs |

---

## 11. SCORING RUBRIC (unchanged)

| Category | Weight | Notes |
| :---- | :---- | :---- |
| TLS | 30 | cert_valid 10 + modern_protocol 8 + strong_ciphers 6* + renewal_buffer 3 + hostname_match 3 |
| Headers | 25 | HSTS 6 + CSP 6 + frame 4 + nosniff 3 + referrer 3 + permissions 3 |
| Email | 25 | SPF 8 + DMARC 7 + spf_hardfail 4 + dmarc_strict 4 + DKIM 2 |
| DNS | 20 | DNSSEC 8 + CAA 5 + ns_redundancy 4 + no wildcard 3 |

\*`tls.strong_ciphers` not implemented yet — max TLS = 24/30 (planned W8).
**Grades:** 95+ A+ · 85+ A · 75+ B · 60+ C · 40+ D · else F

---

## 12. DOCS IN `docs/`

| File | Purpose |
| :---- | :---- |
| `HANDOFF_FOR_NEW_CHAT_v5.md` | This file (latest) |
| `HANDOFF_FOR_NEW_CHAT_v4.md` | Previous handoff |
| `PROJECT_SUMMARY_AND_TIMELINE.md` | System overview + week-by-week timeline for presenting |
| `DATABASE_SUMMARY.md` | W7 database deep-dive + advisor Q&A |
| `ScanSystem_Documentation.docx` | Technical doc |
