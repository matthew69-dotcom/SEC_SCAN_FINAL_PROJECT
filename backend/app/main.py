"""FastAPI entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import settings
from app.db.database import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup. If the DB is unreachable, log and continue —
    # scanning must still work even if history persistence is unavailable.
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Database init failed (history disabled): %s", exc)
    yield


app = FastAPI(
    title="Domain Security Checker",
    version=settings.app_version,
    description="AI-Assisted Lightweight Domain Security Checker — MFU senior project 2026",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {"status": "running", "version": settings.app_version}
