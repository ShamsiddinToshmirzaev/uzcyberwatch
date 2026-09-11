"""Statistika va tahliliy API endpointlari. FT-47, FT-48.

GET /api/v1/stats            — umumiy ko'rsatkichlar (dashboard)
GET /api/v1/stats/timeline   — kunlik ishlar dinamikasi
GET /api/v1/stats/detectors  — detektorlar reytingi
GET /api/v1/stats/ioc        — IoC taqsimoti
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import Case, CaseStatus, Detection, Detector, Indicator

router = APIRouter(prefix="/stats", tags=["stats"])


# ================================================================= /stats

@router.get("")
async def overview(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Umumiy dashboard ko'rsatkichlari. FT-47."""
    # Jami ishlar soni
    total = (await db.execute(select(func.count()).select_from(Case))).scalar() or 0

    # Status bo'yicha taqsimot
    status_rows = (
        await db.execute(
            select(Case.status, func.count().label("cnt"))
            .group_by(Case.status)
        )
    ).all()
    by_status = {str(r.status.value if hasattr(r.status, "value") else r.status): r.cnt
                 for r in status_rows}

    # Region bo'yicha top-10
    region_rows = (
        await db.execute(
            select(Case.region, func.count().label("cnt"))
            .where(Case.region.isnot(None))
            .group_by(Case.region)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    by_region = [{"region": r.region, "count": r.cnt} for r in region_rows]

    # Yuqori xavfli (risk ≥ 70) ishlar
    high_risk = (
        await db.execute(
            select(func.count()).select_from(Case).where(Case.total_risk >= 70)
        )
    ).scalar() or 0

    # O'rtacha xavf darajasi
    avg_risk = (
        await db.execute(select(func.avg(Case.total_risk)).select_from(Case))
    ).scalar()
    avg_risk = round(float(avg_risk), 1) if avg_risk is not None else 0.0

    return {
        "total_cases":   int(total),
        "avg_risk":      avg_risk,
        "high_risk_count": int(high_risk),
        "by_status":     by_status,
        "by_region":     by_region,
    }


# ================================================================= /stats/timeline

@router.get("/timeline")
async def timeline(
    days: int = Query(default=30, ge=1, le=365),
    db:   AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Kunlik ishlar dinamikasi. FT-48.

    Oxirgi `days` kun uchun har kun yaratilgan ishlar soni.
    """
    since = datetime.utcnow() - timedelta(days=days)
    rows = (
        await db.execute(
            select(
                func.date(Case.opened_at).label("day"),
                func.count().label("cnt"),
            )
            .where(Case.opened_at >= since)
            .group_by(func.date(Case.opened_at))
            .order_by(func.date(Case.opened_at))
        )
    ).all()
    return [{"date": str(r.day), "count": r.cnt} for r in rows]


# ================================================================= /stats/detectors

@router.get("/detectors")
async def detectors_stats(
    limit: int = Query(default=10, ge=1, le=50),
    db:    AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Detektorlar reytingi: eng ko'p ishlagan detektorlar. FT-47."""
    rows = (
        await db.execute(
            select(
                Detector.name,
                Detector.kind,
                func.count(Detection.id).label("hit_count"),
            )
            .join(Detection, Detection.detector_id == Detector.id, isouter=True)
            .group_by(Detector.id, Detector.name, Detector.kind)
            .order_by(func.count(Detection.id).desc())
            .limit(limit)
        )
    ).all()
    return [
        {
            "name":      r.name,
            "kind":      str(r.kind.value if hasattr(r.kind, "value") else r.kind),
            "hit_count": r.hit_count,
        }
        for r in rows
    ]


# ================================================================= /stats/ioc

@router.get("/ioc")
async def ioc_stats(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """IoC taqsimoti tur bo'yicha. FT-47."""
    total = (
        await db.execute(select(func.count()).select_from(Indicator))
    ).scalar() or 0

    type_rows = (
        await db.execute(
            select(Indicator.ioc_type, func.count().label("cnt"))
            .group_by(Indicator.ioc_type)
            .order_by(func.count().desc())
        )
    ).all()
    by_type = {
        str(r.ioc_type.value if hasattr(r.ioc_type, "value") else r.ioc_type): r.cnt
        for r in type_rows
    }

    return {"total": int(total), "by_type": by_type}
