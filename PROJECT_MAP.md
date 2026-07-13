# Project Map — Domain Security Checker

Annotated map of every folder and important file in the repo.
See `AGENTS.md` for conventions and `docs/ARCHITECTURE.md` for how it all works.

```
SEC_SCAN_FINAL_PROJECT/
│
├── README.md                    # Quick intro + local setup
├── AGENTS.md                    # Guide for AI agents & contributors (conventions, gotchas)
├── PROJECT_MAP.md               # This file
├── ROADMAP.md                   # Week-by-week plan
├── TEAM.md                      # Team members & roles
├── docker-compose.yml           # DEV stack: backend (hot reload) + frontend + Postgres 16
├── docker-compose.prod.yml      # PROD-style stack: built images, nginx frontend on :8080
├── .gitignore                   # .env, dev.db, .venv, node_modules, dist ...
├── .github/
│   └── copilot-instructions.md  # Instructions for GitHub Copilot
│
├── backend/                     # FastAPI backend (Python 3.12)
│   ├── Dockerfile               # python:3.12-slim image, uvicorn on :8000
│   ├── .dockerignore
│   ├── .env                     # OPENAI_API_KEY etc. (gitignored — per-developer)
│   ├── .env.example             # Template for .env
│   ├── requirements.txt         # FastAPI, httpx, dnspython, langchain, sqlalchemy ...
│   ├── pyproject.toml           # pytest (asyncio_mode=auto, pythonpath=.) + ruff config
│   ├── check_ai_live.py         # Helper: live test of the OpenAI key
│   ├── dev.db                   # Local SQLite DB (gitignored, auto-created on startup)
│   │
│   ├── app/
│   │   ├── main.py              # FastAPI entrypoint; lifespan runs init_db(); CORS
│   │   ├── config.py            # Settings from .env (openai key, database_url, cors)
│   │   │
│   │   ├── api/
│   │   │   ├── routes.py        # /api/health, POST /api/scan, GET|DELETE /api/scans[/{id}]
│   │   │   └── schemas.py       # Pydantic models: ScanRequest/Response, ScanHistoryItem ...
│   │   │
│   │   ├── scanners/            # Each returns CheckResult list, never raises, runs in parallel
│   │   │   ├── base.py          # CheckResult + shared scanner scaffolding
│   │   │   ├── dns_scanner.py   # DNSSEC, CAA, NS redundancy, wildcard
│   │   │   ├── tls_scanner.py   # Cert validity, protocol, hostname match (manual handshake)
│   │   │   ├── header_scanner.py# HSTS, CSP, X-Frame-Options, nosniff, referrer, permissions
│   │   │   ├── email_scanner.py # SPF, DKIM, DMARC
│   │   │   └── port_scanner.py  # Open-port observation (Full scan mode)
│   │   │
│   │   ├── scoring/
│   │   │   ├── weights.yaml     # Deterministic rubric — weights + grade thresholds (editable)
│   │   │   └── engine.py        # Applies weights.yaml to CheckResults → score + grade
│   │   │
│   │   ├── discovery/           # Subdomain discovery
│   │   │   ├── enumerator.py    # Orchestrates the three sources below
│   │   │   ├── crtsh.py         # Certificate-transparency logs (crt.sh)
│   │   │   ├── dns_mining.py    # DNS-record mining
│   │   │   └── wordlist.py      # Common-subdomain wordlist probing
│   │   │
│   │   ├── ai/                  # AI risk summaries (LangChain + GPT-4o-mini, JSON mode)
│   │   │   ├── service.py       # Entry point; falls back to local template w/o API key
│   │   │   ├── analyzer.py      # Builds the analysis from scan findings
│   │   │   ├── prompts.py       # Prompt templates
│   │   │   ├── report.py        # Report assembly
│   │   │   ├── schemas.py       # Structured AI output models
│   │   │   ├── validation.py    # Output validation (AI never computes the score)
│   │   │   └── *_writeup.md / validation_*.md  # Role B working notes
│   │   │
│   │   ├── db/                  # Week 7 — scan-history persistence
│   │   │   ├── database.py      # Async engine; auto-picks aiosqlite/asyncpg from DATABASE_URL
│   │   │   ├── models.py        # ScanRecord (scan_id PK, domain, score, grade, result_json)
│   │   │   └── crud.py          # create / list / get / delete
│   │   │
│   │   └── utils/
│   │       └── geoip.py         # ip-api.com lookup (country/ISP/ASN reliable, location ≈)
│   │
│   └── tests/                   # pytest + pytest-asyncio — all offline (mocked network)
│       ├── test_main.py         # API surface
│       ├── test_scanners.py     # Scanner units
│       ├── test_scoring.py      # Rubric engine
│       ├── test_discovery.py    # Subdomain discovery
│       ├── test_multi_host.py   # Multi-host aggregation
│       ├── test_ai.py / test_ai_report.py / test_ai_validation.py
│       └── test_db.py           # DB CRUD + persistence robustness
│
├── frontend/                    # React 19 + Vite 8 + TypeScript + Tailwind 3
│   ├── Dockerfile               # Multi-stage: node build → nginx (proxies /api → backend)
│   ├── nginx.conf               # Prod nginx config (SPA fallback + /api reverse proxy)
│   ├── .dockerignore
│   ├── package.json             # dev / build (tsc -b && vite build) / lint / preview
│   ├── vite.config.ts           # Port 5173; /api proxy (VITE_API_PROXY_TARGET overridable)
│   ├── tailwind.config.js / postcss.config.js
│   ├── tsconfig*.json           # Strict TS
│   ├── eslint.config.js
│   ├── index.html
│   ├── public/                  # favicon.svg, icons.svg
│   └── src/
│       ├── main.tsx             # React entry
│       ├── App.tsx              # Whole UI: scan form, result page, history page (~1300 lines)
│       ├── api.ts               # Typed API client: scan, listScans, getScan, deleteScan
│       └── index.css / app.css  # Tailwind + custom styles
│
└── docs/
    ├── ARCHITECTURE.md          # Detailed system documentation (this session)
    ├── DOCKER.md                # How to run with Docker, dev & prod (this session)
    ├── PROJECT_SUMMARY_AND_TIMELINE.md  # Overview + weekly timeline for presenting
    ├── DATABASE_SUMMARY.md      # W7 database deep-dive + advisor Q&A
    ├── HANDOFF_FOR_NEW_CHAT_v5.md / v4  # Chat-session handoffs
    └── ScanSystem_Documentation.docx    # Technical doc
```

## Key entry points

| Want to… | Start at |
| :--- | :--- |
| Add/change an API endpoint | `backend/app/api/routes.py` + `schemas.py` |
| Add a security check | `backend/app/scanners/*` then register weight in `scoring/weights.yaml` |
| Tune scoring | `backend/app/scoring/weights.yaml` (no code change needed) |
| Change AI behaviour | `backend/app/ai/service.py`, `prompts.py` |
| Change the UI | `frontend/src/App.tsx`, API types in `src/api.ts` |
| DB schema | `backend/app/db/models.py` (no Alembic yet — create_all on startup) |
| Run in Docker | `docker-compose.yml` (dev) / `docker-compose.prod.yml`, see `docs/DOCKER.md` |
