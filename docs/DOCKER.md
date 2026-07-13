# Running with Docker

Two compose stacks live at the repo root:

| File | Purpose | URLs |
| :--- | :--- | :--- |
| `docker-compose.yml` | **Dev** — hot reload, Postgres 16 | FE http://localhost:5173 · API http://localhost:8000/docs |
| `docker-compose.prod.yml` | **Prod-style** — built images, nginx | App http://localhost:8080 |

Requirement: Docker Desktop (Windows) or Docker Engine + Compose v2.

## Dev stack

```bash
# from repo root (the NESTED SEC_SCAN_FINAL_PROJECT folder)
docker compose up
```

What you get:

- **db** — Postgres 16 (`secscan`/`secscan`), data persisted in the `pgdata`
  volume, exposed on 5432 for inspection.
- **backend** — built from `backend/Dockerfile` (python:3.12-slim), runs
  uvicorn with `--reload`; `./backend` is bind-mounted so code changes reload
  instantly. Talks to Postgres via `DATABASE_URL` (asyncpg picked
  automatically).
- **frontend** — plain `node:22-alpine` running the Vite dev server with HMR;
  `./frontend` is bind-mounted, but `node_modules` lives in a named Linux
  volume (`frontend_node_modules`) — this is what makes the rolldown native
  binding work and keeps Windows file I/O fast. The Vite `/api` proxy points
  at `http://backend:8000` via `VITE_API_PROXY_TARGET`.

**AI key (optional):** create a `.env` file at the repo root (next to
docker-compose.yml) with `OPENAI_API_KEY=sk-...`, or export it in your shell.
Without it, scans still work; AI summaries use the local template.

Useful:

```bash
docker compose up -d --build       # rebuild backend image after requirements.txt changes
docker compose logs -f backend
docker compose exec backend pytest # run the test suite inside the container
docker compose down                # stop (keeps DB data)
docker compose down -v             # stop and wipe DB + node_modules volumes
```

## Prod-style stack

```bash
docker compose -f docker-compose.prod.yml up --build -d
# open http://localhost:8080
```

- **frontend** is a multi-stage build: `npm ci && npm run build` in node:22,
  then static files served by nginx. nginx also reverse-proxies `/api/*` to
  the backend container — single origin, so CORS never comes into play.
- **backend** runs uvicorn without reload; no source bind-mount.
- Override secrets via env or root `.env`: `POSTGRES_PASSWORD`,
  `OPENAI_API_KEY`.

This mirrors the planned real deployment (Railway backend + Postgres, Vercel
frontend) and is handy for demos on one machine.

## How config flows

Backend settings (`app/config.py`, pydantic-settings) read from environment
variables first, then `backend/.env`:

| Variable | Dev compose value | Notes |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://secscan:secscan@db:5432/secscan` | scheme auto-selects aiosqlite/asyncpg |
| `CORS_ORIGINS` | `http://localhost:5173` | comma-separated |
| `OPENAI_API_KEY` | passed through from host | optional |
| `OPENAI_MODEL` | `gpt-4o-mini` | |

Tables are created automatically on startup (`init_db()`); if the DB is down
the API still serves scans (history disabled) — by design.

## Troubleshooting

- **`vite build` / dev server fails with a rolldown binding error** — you've
  contaminated the Linux volume with Windows `node_modules`. Fix:
  `docker compose down -v && docker compose up`.
- **Backend can't reach Postgres on first boot** — the healthcheck should
  prevent this; if it recurs, `docker compose restart backend`.
- **Port already in use** (5173/8000/5432/8080) — stop the local (non-Docker)
  dev servers first, or change the host-side port in the compose file.
- **Windows + git:** run git commands on Windows only, never from inside the
  container (see AGENTS.md gotcha #1).
