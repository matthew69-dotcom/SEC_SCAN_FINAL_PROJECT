"""Unit tests for the scan-history persistence layer (Week 7).

Uses an isolated temp-file SQLite DB per test — does not touch dev.db.
"""
from __future__ import annotations

import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db import crud
from app.db.database import Base

_SAMPLE_JSON = {
    "scan_id": "s1", "domain": "mfu.ac.th", "mode": "single",
    "score": 44, "grade": "D", "summary": "x", "findings": [], "breakdown": [],
    "version": {"app": "0.1.0", "model": "gpt-4o-mini", "rubric": 1},
}


@pytest_asyncio.fixture
async def session(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed(session, scan_id="s1", domain="mfu.ac.th", score=44, grade="D"):
    return await crud.create_scan(
        session, scan_id=scan_id, domain=domain, mode="single",
        score=score, grade=grade, findings_count=3, result_json=_SAMPLE_JSON,
    )


async def test_create_and_get(session):
    await _seed(session)
    record = await crud.get_scan(session, "s1")
    assert record is not None
    assert record.domain == "mfu.ac.th"
    assert record.score == 44
    assert record.result_json["grade"] == "D"


async def test_list_newest_first(session):
    await _seed(session, scan_id="old", score=10)
    await _seed(session, scan_id="new", score=90)
    rows = await crud.list_scans(session)
    assert [r.scan_id for r in rows] == ["new", "old"]


async def test_get_missing_returns_none(session):
    assert await crud.get_scan(session, "does-not-exist") is None


async def test_delete(session):
    await _seed(session)
    assert await crud.delete_scan(session, "s1") is True
    assert await crud.get_scan(session, "s1") is None


async def test_delete_missing_returns_false(session):
    assert await crud.delete_scan(session, "nope") is False
