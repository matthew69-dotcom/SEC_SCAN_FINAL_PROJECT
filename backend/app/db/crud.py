"""Data-access helpers for ScanRecord. Thin, testable, no HTTP concerns."""
from __future__ import annotations

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ScanRecord


async def create_scan(
    session: AsyncSession,
    *,
    scan_id: str,
    domain: str,
    mode: str,
    score: int,
    grade: str,
    findings_count: int,
    result_json: dict,
) -> ScanRecord:
    record = ScanRecord(
        scan_id=scan_id,
        domain=domain,
        mode=mode,
        score=score,
        grade=grade,
        findings_count=findings_count,
        result_json=result_json,
    )
    session.add(record)
    await session.commit()
    return record


async def list_scans(session: AsyncSession, limit: int = 50) -> list[ScanRecord]:
    result = await session.execute(
        select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all())


async def get_scan(session: AsyncSession, scan_id: str) -> ScanRecord | None:
    result = await session.execute(
        select(ScanRecord).where(ScanRecord.scan_id == scan_id)
    )
    return result.scalar_one_or_none()


async def delete_scan(session: AsyncSession, scan_id: str) -> bool:
    result = await session.execute(
        sa_delete(ScanRecord).where(ScanRecord.scan_id == scan_id)
    )
    await session.commit()
    return result.rowcount > 0
