# Architecture — Domain Security Checker

Detailed system documentation. Companion files: `PROJECT_MAP.md` (file map),
`AGENTS.md` (conventions), `docs/DOCKER.md` (containers),
`docs/DATABASE_SUMMARY.md` (W7 DB deep-dive).

## 1. Overview

A web tool that scans a single domain (plus discovered subdomains) and grades
its security posture **A+ to F**. Coverage: DNS (DNSSEC, CAA, NS redundancy,
wildcard), HTTPS/TLS (cert validity + trust chain, protocol, hostname match,
cipher), HTTP security
headers (HSTS, CSP, frame, nosniff, referrer, permissions), and email auth
(SPF, DKIM, DMARC). Full-scan mode adds Geo-IP, open-port observation, and an
AI-written risk summary.

Two hard principles shape the design:

- **Deterministic scoring.** The numeric score comes only from
  `scoring/weights.yaml` applied to boolean check results. The AI writes
  prose; it never grades. Same input → same score, always reproducible.
- **Non-intrusive, lightweight observation.** The system only reads what a
  normal client sees (DNS records, TLS handshake, HTTP response headers) plus,
  in full mode, TCP connects to 6 web ports and a ~120-name DNS wordlist. No
  exploitation, auth brute force, or intrusive probing. (Not "passive": it
  does open connections.)
- **Bounded and honest.** Every external phase has a time limit, the scanner
  never connects to non-public IPs, and results are never substituted or
  invented — what could not be measured is reported as such.

## 2. Request flow

```
Browser (React SPA)
   │  POST /api/scan {domain, mode}
   ▼
FastAPI routes.py
   │  1. discovery/ — enumerate subdomains (crt.sh + DNS mining + wordlist)
   │                  45s limit (→ apex only); cap MAX_HOSTS=25 (apex, www,
   │                  then shortest names)
   │  1b. utils/netsafety.py — drop hosts resolving to non-public IPs
   │                  (reported as dns.private_ip_exposed, never connected to)
   │  2. scanners/  — dns, tls, header, email (+ port in Full mode)
   │                  run per host, all in parallel (asyncio.gather)
   │                  5 hosts at a time, 20s/host; apex 40s + 1 retry
   │                  each returns CheckResult list, never raises
   │  3. scoring/engine.py — apply weights.yaml → score 0-100 + grade
   │  4. utils/geoip.py    — ip-api.com (Full mode, 10s); ports 20s, on the
   │                          vetted public IP
   │  5. ai/service.py     — GPT-4o-mini JSON-mode summary (Full mode, apex
   │                          findings only, 30s; local template fallback)
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
| `POST /api/scan` | Run a scan (`mode`: single/full); auto-persists result |
| `GET /api/scans` | Scan history, newest first (`ScanHistoryItem` list) |
| `GET /api/scans/{id}` | Full stored `ScanResponse` |
| `DELETE /api/scans/{id}` | Remove a history entry |

Schemas are Pydantic v2 (`schemas.py`). Input and abuse guards on `POST /api/scan`:

- **Domain syntax** (RFC 1123): labels of 1-63 letters/digits/hyphens, no leading or
  trailing hyphen, total <= 253, alphabetic TLD (bare IPs rejected). `https://`, a
  trailing `/` or `.` and surrounding spaces are stripped; Thai/other IDN names are
  converted to punycode (`ไทย.com` -> `xn--o3cw4h.com`).
- **Domain must exist**: `netsafety.domain_exists()` asks the pinned resolvers; an
  NXDOMAIN answer returns HTTP 422 "does not exist" before any scan or save (gibberish
  such as `ivjowsefhvwieh.com` used to be graded F 3/100 and stored). Timeouts never reject.
- **Rate limit** (`utils/ratelimit.py`, in-memory sliding window): per client IP 10 Single
  and 2 Full scans per minute, and at most 3 Full scans running at once; HTTP 429 with
  `Retry-After`. Behind our own proxy (Vite dev server / nginx) the client IP comes from
  `X-Real-IP`, which is trusted only when the request arrives from a loopback/private address.
  Single-process only — a multi-process deployment would need a shared store (Redis).
`ScanHistoryItem.created_at` is always serialised with a UTC offset (SQLite
returns naive datetimes; without it the browser showed UTC as local time).

### 3.2 Scanners (`app/scanners/`)

All scanners share the `CheckResult` contract from `base.py`: a named check
(`tls.cert_valid`, `headers.hsts`, …) with `passed`, evidence, and detail.
A scanner catches all its own exceptions — a network failure becomes a failed
check, never a 500. DNS queries pin resolvers to 8.8.8.8 / 1.1.1.1
(dnspython).

- **TLS** — two handshakes. (1) Observation handshake with `CERT_NONE` so even
  broken certs can be inspected (`cryptography.x509`): expiry, renewal buffer
  (30 days), hostname vs SAN/CN, negotiated protocol and cipher. (2) Trust
  handshake with `ssl.create_default_context()` (hostname check off — judged
  separately, so a mismatch is not penalised twice). `tls.cert_valid` fails
  if the cert is expired **or** the chain does not verify (self-signed,
  unknown CA, incomplete chain — the OpenSSL reason is in the evidence). If the
  trust handshake itself errors, the check does not invent a failure; the
  evidence says "trust chain not verified".
- **Headers** — `httpx.AsyncClient`, `follow_redirects=True`, streams and reads
  **headers only** (no body). Retried once on `ConnectTimeout`/`ConnectError`
  (second attempt 6s, worst case 17s < 20s host budget), never on TLS/cert
  errors. Repeated headers (joined by httpx as `"nosniff, nosniff"`) are
  split; Referrer-Policy is judged on its effective (last) value. Failing
  checks append the HTTP status and final URL of the judged response.
- **Email** — SPF/DMARC/DKIM graded only on the apex and on hosts with their
  own MX. Other hosts: email category N/A, score rescaled over the remaining
  75 points (`score_checks(..., not_applicable=("email",))`), info finding
  `email.not_applicable`.

### 3.3 Scoring (`app/scoring/`)

`weights.yaml` defines categories → checks → weights (sums to 100) and grade
thresholds (95+ A+, 85+ A, 75+ B, 60+ C, 40+ D, else F):

| Category | Weight | Checks |
| :--- | :--- | :--- |
| TLS | 30 | cert_valid 10, modern_protocol 8, strong_ciphers 6, renewal_buffer 3, hostname_match 3 |
| Headers | 25 | HSTS 6, CSP 6, frame 4, nosniff 3, referrer 3, permissions 3 |
| Email | 25 | SPF 8, DMARC 7, spf_hardfail 4, dmarc_strict 4, DKIM 2 |
| DNS | 20 | DNSSEC 8, CAA 5, ns_redundancy 4, no_wildcard 3 |

Checks emitted but not listed are info-only; checks listed but never emitted
score 0 (missing coverage is visible). Tuning the rubric = editing YAML only.
Info-only IDs in use: `email.not_applicable`, `dns.private_ip_exposed`,
`scan.apex_unavailable`.

### 3.4 Subdomain discovery (`app/discovery/`)

`enumerator.py` merges three sources: certificate-transparency logs (crt.sh,
20s total deadline), DNS-record mining, and a common-name wordlist. Hosts that
resolve are kept; at most `MAX_HOSTS=25` are scanned (apex, www, then the
shallowest/shortest names).

**Aggregation.** Domain score = worst host (average also reported). The
headline card shows the **apex** result; it is never replaced by another
host's. If the apex fails after its retry, the response carries
`scan.apex_unavailable`, a summary note, the domain score as headline, and no
AI summary. The summary lists timed-out hosts.

**SSRF guard** (`utils/netsafety.py`). Every A record of a host must be a
globally routable address (no RFC 1918, loopback, link-local, CGNAT,
multicast). Hosts that fail are reported, not scanned. Port scans target the
vetted IP, not the hostname.

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

`pytest` + `pytest-asyncio` (`asyncio_mode=auto`), **186 test cases** (many
parametrised), offline except 4 live smoke tests in `test_scanners.py` that
hit google.com. Covers API surface, each scanner, scoring engine, discovery,
multi-host aggregation, full-scan limits, email applicability, SSRF guard,
apex reliability, AI (incl. fallback + validation), DB CRUD. The TLS trust
tests run real handshakes against a local TLS server with generated certs.
`tests/conftest.py` keeps the suite hermetic (OpenAI key blanked, MX and
private-IP lookups mocked). Frontend
correctness check is `tsc -b --noEmit` (see AGENTS.md gotcha about
`vite build` on Linux). Lint: ruff (py) / eslint (ts).

## 6. Validation (`validation/`)

`validate.py run` scans 14 domains N times through the live API and writes
`summary.md`, `stability.csv`, `comparison.csv`, `raw_scans.json` to
`validation/out/<stamp>/` (gitignored). Repeatability = same grade every run.
Accuracy = per-check agreement with independent references: dns.google
DNS-over-HTTPS (automatic), SSL Labs and securityheaders.com (saved in
`validation/reference/`, applied with `apply_reference.py`). Latest
(2026-10-20, run 20261020-055742): 14/14 repeatable, 196/203 = 96.6% agreement
(98.0% excluding 3 rows where mahidol.ac.th refuses the scanner); every disagreement
is explained in `validation/FINDINGS_2026-10-20.md`.

## 7. Deployment (planned, only if required)

Railway hosts the backend + PostgreSQL 16 (`DATABASE_URL` and
`OPENAI_API_KEY` set in Railway; `CORS_ORIGINS` set to the Vercel URL).
Vercel hosts the built frontend. The `docker-compose.prod.yml` stack mirrors
this topology locally. Local dev uses SQLite with zero setup.

## 8. Known limitations

- `tls.strong_ciphers` judges only the cipher negotiated in the single
  observation handshake — it does not enumerate every suite the server accepts.
- Trust check uses the OS/Python CA store and does not fetch missing
  intermediates (AIA) like browsers do: a server that omits its intermediate
  fails `tls.cert_valid` (correct for non-browser clients; remediation says so).
- SSRF guard checks A records only, not AAAA (e.g. `mfu.ac.th` publishes AAAA
  `::1`); TLS/headers connect by hostname for SNI, so a DNS-rebinding race
  between check and connect is theoretically possible.
- Full scan caps at 25 hosts; domain score is worst-host.
- Non-web hosts (ns, ftp, …) fail TLS + headers and score very low — whether
  web checks should be N/A for hosts without 80/443 is an open question.
- DKIM only via common selectors.
- No Alembic migrations; schema changes recreate the dev DB.
- Geo-IP `location` is approximate (registered network location; CDN edges
  skew it) — country/ISP/ASN are the reliable fields.
- Some sites serve different headers per client/region (google, youtube):
  results reflect what our scanner was served.
