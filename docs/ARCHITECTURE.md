# Architecture — Domain Security Checker

Detailed system documentation. Companion files: `PROJECT_MAP.md` (file map),
`AGENTS.md` (conventions), `docs/DOCKER.md` (containers),
`docs/DATABASE_SUMMARY.md` (W7 DB deep-dive).

## 1. Overview

A web tool that scans a single domain (plus discovered subdomains) and grades
its security posture **A+ to F**. Coverage: DNS (DNSSEC, CAA, NS redundancy,
wildcard), HTTPS/TLS (cert validity, protocol, hostname match), HTTP security
headers (HSTS, CSP, frame, nosniff, referrer, permissions), and email auth
(SPF, DKIM, DMARC). Full-scan mode adds Geo-IP, open-port observation, and an
AI-written risk summary.

Two hard principles shape the design:

- **Deterministic scoring.** The numeric score comes only from
  `scoring/weights.yaml` applied to boolean check results. The AI writes
  prose; it never grades. Same input → same score, always reproducible.
- **Passive observation.** The system only reads publicly observable state
  (DNS records, TLS handshake, HTTP response headers). No exploitation,
  brute force, or intrusive probing.

## 2. Request flow

```
Browser (React SPA)
   │  POST /api/scan {domain, mode}
   ▼
FastAPI routes.py
   │  1. discovery/ — enumerate subdomains (crt.sh + DNS mining + wordlist)
   │  2. scanners/  — dns, tls, header, email (+ port in Full mode)
   │                  run per host, all in parallel (asyncio.gather)
   │                  each returns CheckResult list, never raises
   │  3. scoring/engine.py — apply weights.yaml → score 0-100 + grade
   │  4. utils/geoip.py    — ip-api.com (Full mode)
   │  5. ai/service.py     — GPT-4o-mini JSON-mode summary (Full mode;
   │                          local template fallback without key/langchain)
   │  6. db/crud.py        — persist ScanRecord (try/except — never blocks scan)
   ▼
ScanResponse (score, grade, findings, geo, ports, ai_summary, version info)
```

Every response carries version info: app version + AI model + rubric version.

## 3. Backend components

### 3.1 API (`app/api/`)

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/health` | Liveness |
| `POST /api/scan` | Run a scan (`mode`: quick/full); auto-persists result |
| `GET /api/scans` | Scan history, newest first (`ScanHistoryItem` list) |
| `GET /api/scans/{id}` | Full stored `ScanResponse` |
| `DELETE /api/scans/{id}` | Remove a history entry |

Schemas are Pydantic v2 (`schemas.py`). Rate limiting via slowapi.

### 3.2 Scanners (`app/scanners/`)

All scanners share the `CheckResult` contract from `base.py`: a named check
(`tls.cert_valid`, `headers.hsts`, …) with `passed`, evidence, and detail.
A scanner catches all its own exceptions — a network failure becomes a failed
check, never a 500. DNS queries pin resolvers to 8.8.8.8 / 1.1.1.1
(dnspython); TLS uses a manual `ssl`/`socket` handshake + `cryptography.x509`;
HTTP uses `httpx.AsyncClient` with `follow_redirects=True`.

### 3.3 Scoring (`app/scoring/`)

`weights.yaml` defines categories → checks → weights (sums to 100) and grade
thresholds (95+ A+, 85+ A, 75+ B, 60+ C, 40+ D, else F):

| Category | Weight | Checks |
| :--- | :--- | :--- |
| TLS | 30 | cert_valid 10, modern_protocol 8, strong_ciphers 6*, renewal_buffer 3, hostname_match 3 |
| Headers | 25 | HSTS 6, CSP 6, frame 4, nosniff 3, referrer 3, permissions 3 |
| Email | 25 | SPF 8, DMARC 7, spf_hardfail 4, dmarc_strict 4, DKIM 2 |
| DNS | 20 | DNSSEC 8, CAA 5, ns_redundancy 4, no_wildcard 3 |

\* `tls.strong_ciphers` reserved, not yet implemented (W8) — TLS max is 24/30.
Checks emitted but not listed are info-only; checks listed but never emitted
score 0 (missing coverage is visible). Tuning the rubric = editing YAML only.

### 3.4 Subdomain discovery (`app/discovery/`)

`enumerator.py` merges three passive sources: certificate-transparency logs
(crt.sh), DNS-record mining, and a common-name wordlist. Each discovered live
host is scanned; results aggregate into the domain grade.

### 3.5 AI layer (`app/ai/`)

LangChain 0.3 + OpenAI GPT-4o-mini in JSON mode. Input: the structured scan
findings. Output: validated structured summary (`schemas.py` +
`validation.py`) — severity narrative, plain-language explanations,
recommendations. Runs **only in Full scan**. If `OPENAI_API_KEY` is missing or
langchain isn't installed, `service.py` falls back to a deterministic local
template and marks `generated_by_ai: false`.

### 3.6 Persistence (`app/db/`) — Week 7

Async SQLAlchemy 2.0. One codebase, two engines: `DATABASE_URL` scheme
auto-selects aiosqlite (`sqlite:///`) or asyncpg
(`postgresql://`/`postgres://`, auto-rewritten to `+asyncpg`). Model
`ScanRecord`: scan_id PK, domain, mode, score, grade, findings_count,
created_at, plus `result_json` holding the entire ScanResponse. Tables are
`create_all`'d in the FastAPI lifespan (`init_db()`); no Alembic yet
(documented limitation). All persistence is wrapped in try/except: **a dead DB
can never fail a scan** (design rule #6).

### 3.7 Config (`app/config.py`)

pydantic-settings; environment variables override `backend/.env`. Keys:
`OPENAI_API_KEY`, `OPENAI_MODEL` (default gpt-4o-mini), `DATABASE_URL`
(default `sqlite:///./dev.db`), `CORS_ORIGINS` (default
`http://localhost:5173`, comma-separated).

## 4. Frontend

React 19 + Vite 8 + strict TypeScript + Tailwind 3, function components only.
`src/api.ts` is the typed client (scan, listScans, getScan, deleteScan and the
response types). `src/App.tsx` (~1300 lines) contains the whole UI: scan form
with quick/full toggle, result page (grade card, per-category findings,
Geo-IP marked "≈ approximate", open ports, AI summary card), and a History
page backed by the server DB. In dev, Vite proxies `/api` to the backend
(target overridable via `VITE_API_PROXY_TARGET` for Docker); in the Docker
prod stack, nginx does the same proxying.

## 5. Testing

`pytest` + `pytest-asyncio` (`asyncio_mode=auto`), 56 tests, all **offline**
(network mocked): API surface, each scanner, scoring engine, discovery,
multi-host aggregation, AI (incl. fallback + validation), DB CRUD. Frontend
correctness check is `tsc -b --noEmit` (see AGENTS.md gotcha about
`vite build` on Linux). Lint: ruff (py) / eslint (ts).

## 6. Deployment (W8 — planned)

Railway hosts the backend + PostgreSQL 16 (`DATABASE_URL` and
`OPENAI_API_KEY` set in Railway; `CORS_ORIGINS` set to the Vercel URL).
Vercel hosts the built frontend. The `docker-compose.prod.yml` stack mirrors
this topology locally. Local dev uses SQLite with zero setup.

## 7. Known limitations

- `tls.strong_ciphers` not implemented (TLS capped at 24/30) — W8.
- No Alembic migrations; schema changes recreate the dev DB.
- Geo-IP `location` is approximate (registered network location; CDN edges
  skew it) — country/ISP/ASN are the reliable fields.
- History DB is per-developer in dev (SQLite, gitignored).
- External validation vs SSL Labs / securityheaders.com / MXToolbox pending (W8).
