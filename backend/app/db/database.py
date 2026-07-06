"""Async SQLAlchemy engine + session.

Works with both SQLite (local dev) and PostgreSQL (deploy) — the correct
async driver is selected automatically from the DATABASE_URL scheme:
  sqlite:///./dev.db          -> sqlite+aiosqlite:///./dev.db   (aiosqlite)
  postgresql://user:pw@host/db -> postgresql+asyncpg://...       (asyncpg)
  postgres://...               -> postgresql+asyncpg://...       (Railway legacy)
"""
from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


def _to_async_url(url: str) -> str:
    """Rewrite a sync DB URL to its async-driver equivalent."""
    if url.startswith(("sqlite+aiosqlite", "postgresql+asyncpg")):
        return url
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):  # Railway / Heroku legacy scheme
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


DATABASE_URL = _to_async_url(settings.database_url)

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a session and always closes it."""
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create tables if they don't exist. Called once on app startup."""
    from app.db import models  # noqa: F401  (register models on Base.metadata)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
