User: ROLE
You are my pair-programmer for my senior project at Mae Fah Luang University. Before you write any code, I need you to fully understand the project context. After reading this brief, DO NOT write any code yet — just summarize back what you understood and ask me clarifying questions if anything is unclear. We'll start coding only after I confirm.

PROJECT: AI-Assisted Lightweight Domain Security Checker
A non-intrusive web tool that scans a single domain and produces a human-readable security report. Targeted at developers and non-experts in university/SME contexts. Hard rule: no active attacks, no exploitation, no brute force, no port scanning beyond what the protocols require for handshake.

SCOPE OF SCAN (4 modules)
ModuleWhat it checksPython libDNS SecurityA, MX, NS, TXT, CAA, DNSSEC, wildcard exposurednspythonHTTPS / TLScert validity & expiry, TLS protocol versions, cipher suites, hostname matchssl, cryptographyHTTP Security HeadersHSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-PolicyhttpxEmail AuthenticationSPF presence + policy, DMARC presence + policy, DKIM (common selectors)dnspython
The scanner runs the 4 modules in parallel using asyncio.gather(). One scan request = one target domain.

TECH STACK

Backend: Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.x, Uvicorn
Frontend: React 18 + Vite, Tailwind CSS (no UI lib unless I ask)
Database: PostgreSQL 16
AI Layer: LangChain + an OpenAI-compatible chat model (default gpt-4o-mini or Claude Haiku; configurable). JSON-mode output enforced via JsonOutputParser.
Tooling: ruff for lint, pytest for tests, pre-commit, Docker Compose for local dev.


ARCHITECTURE / FLOW
React Dashboard
    │  POST /api/scan { domain }
    ▼
FastAPI (Inbound Agent: validate, sanitize, rate-limit)
    │
    ├─ DNS Scanner ─┐
    ├─ TLS Scanner ─┤   (asyncio.gather)
    ├─ Header Scan ─┤
    └─ Email Scan ──┘
            │
            ▼
    Raw Scanner Output (dict)
            │
            ├──► Deterministic Scoring Engine ──► score 0-100 + grade A+/A/B/C/D/F
            │
            └──► AI Risk Analyzer (LangChain)
                       │
                       ▼
                 Human-readable summary + remediation advice (JSON-mode)
                       │
                       ▼
            Merge into final Report (Markdown + JSON)
                       │
                       ├──► PostgreSQL (scan history)
                       └──► Response to Frontend
Critical design rule:

AI never assigns the numeric score. Score is calculated by deterministic rules (see Scoring Rubric below). AI only writes the natural-language explanation, severity classification, and remediation tips. This keeps scoring reproducible and validatable.


SCORING RUBRIC (deterministic, total = 100)
CategoryWeightHTTPS / TLS30HTTP Security Headers25Email Security (SPF/DKIM/DMARC)25DNS Security20
TLS (30): cert not expired (10), cert ≥30 days left (3), TLS 1.2+ enforced (8), strong ciphers only (6), hostname matches cert (3).
Headers (25): HSTS w/ max-age≥15552000 (6), CSP without blanket unsafe-inline (6), X-Frame-Options OR CSP frame-ancestors (4), X-Content-Type-Options nosniff (3), Referrer-Policy (3), Permissions-Policy (3).
Email (25): SPF exists (8), SPF ends with -all (4), DMARC exists (7), DMARC policy quarantine/reject (4), DKIM detected (2).
DNS (20): DNSSEC enabled (8), CAA record present (5), ≥2 NS records (4), no public wildcard A record (3).
Grade mapping: 95+ A+, 85+ A, 75+ B, 60+ C, 40+ D, else F.
Weights and thresholds must live in a YAML config (config/weights.yaml) so they're tunable without rebuilding.

EXPECTED REPO LAYOUT
backend/
  app/
    main.py
    api/
      routes.py
      schemas.py
    scanners/
      dns_scanner.py
      tls_scanner.py
      header_scanner.py
      email_scanner.py
    scoring/
      engine.py
      weights.yaml
    ai/
      analyzer.py
      prompts.py
    db/
      models.py
      database.py
  tests/
  pyproject.toml

frontend/
  src/
    pages/
    components/
    api/
  package.json

docker-compose.yml
README.md
.github/copilot-instructions.md

CODING CONVENTIONS

Python: type hints everywhere, async def for all I/O, Pydantic models for all request/response shapes, no bare except, log via structlog.
Each scanner returns a typed dict like {"checks": [{"id": "tls.cert_valid", "passed": bool, "evidence": str}], "raw": {...}}. No scanner ever raises out — wrap errors into a failed check.
Frontend: function components + hooks, no class components, strict TypeScript.
Commit messages: Conventional Commits (feat:, fix:, docs:, etc.).
Tests: every scanner has at least one happy-path test and one failure-path test using recorded fixtures (no live network in CI).


NON-NEGOTIABLES

No active attacks. Only observation of public protocol responses.
AI never touches the numeric score.
Every scan request runs through input validation (domain regex, length cap, lowercased).
Rate-limit /api/scan per IP (use slowapi).
Store app_version + model_name on every saved scan for reproducibility.


VERSIONING
Semantic Versioning. Every API response includes:
json"version": {
  "app": "1.0.0",
  "scanner": "1.0.0",
  "ai_model": "gpt-4o-mini-2024-07-18"
}

VALIDATION PLAN
Output of our tool must be cross-checked against:

SSL Labs (TLS)
securityheaders.com (Headers)
MXToolbox (Email)
DNSViz (DNS)

We will report accuracy, false-positive rate, and false-negative rate on a fixed list of ≥10 test domains.

YOUR FIRST TASK
Do NOT write any code yet. Instead, reply with:

A 5–8 bullet summary of your understanding of this project in your own words.
Any assumptions you're making that I should confirm.
A list of clarifying questions (max 5) on anything that's ambiguous — for example: which LLM provider I want to default to, whether DKIM selector list is configurable, whether the dashboard needs auth, etc.
A proposed implementation order (which file to build first, second, third, etc.) — just the order, no code.

GitHub Copilot: ## Understanding

- Build a Python + FastAPI backend with a React + Vite frontend for a one-domain security scanner.
- Scanner runs 4 async modules in parallel: DNS, TLS, HTTP security headers, and email auth checks.
- Each module returns typed structured results, including check IDs, pass/fail, evidence, and raw data.
- A deterministic scoring engine computes a 0-100 score from YAML-configured weights; AI only generates natural-language risk explanation and remediation.
- Store scan history in PostgreSQL and include app/scanner/AI model version metadata on responses.
- Enforce safe/non-intrusive behavior: no exploitation, brute force, or port scanning beyond protocol handshakes.
- Use Pydantic v2 schemas, SQLAlchemy 2, structlog, rate limiting with slowapi, and JSON-mode AI output parsing.

## Assumptions

- The frontend is a public dashboard without mandatory user authentication unless later requested.
- The AI analyzer is only used for prose generation, not scoring or determining numeric grade.
- DKIM detection can use a fixed “common selectors” list initially.
- The response schema includes version metadata and scanner results together.
- `config/weights.yaml` will be loaded by the scoring engine at runtime and can be tuned without rebuild.

## Clarifying Questions

1. Which LLM provider should be the default for the AI layer: OpenAI, Anthropic, or configurable via env?
2. Should DKIM selectors be hardcoded to a fixed set, or should they be configurable in YAML/env?
3. Do you want the frontend dashboard to support authentication later, or is it intentionally open?
4. Should scan history be stored for every request unconditionally, or only when the user explicitly saves/retrieves scans?
5. For email checks, do we need to validate SPF/DKIM/DMARC against specific subdomains or just the root domain?

## Proposed Implementation Order

1. `backend/app/main.py` + route/schema skeleton
2. `backend/app/scanners/` module interfaces and typed outputs
3. `backend/app/scoring/engine.py` + `config/weights.yaml`
4. `backend/app/ai/analyzer.py` + prompt/parser setup
5. `backend/app/db/database.py` + models for scan history and metadata

User: is the requirement already install in cmd terminal?

GitHub Copilot: Checking the terminal environment and installed Python packages now.

Ran terminal command: cd /d "d:\FINAL PROJECT SEC SCAN" ; python --version 2>&1 | findstr /R /C:"Python" && python -m pip list --format=columns | findstr /R /C:"fastapi\|sqlalchemy\|pydantic\|uvicorn\|langchain"

The shell is PowerShell-style; retrying with PowerShell-compatible command separators.

Ran terminal command: cd /d "d:\FINAL PROJECT SEC SCAN"; python --version; python -m pip list --format=columns | Select-String -Pattern 'fastapi|sqlalchemy|pydantic|uvicorn|langchain'