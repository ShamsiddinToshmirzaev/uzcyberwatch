"""Ish yuritish endpointlari. FT-38..40.

CRUD operatsiyalari: ro'yxat, yaratish, ko'rish, yangilash.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import CaseCreate, CaseOut, CasePatch
from app.db import get_db
from app.models import Case, CaseStatus

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=list[CaseOut], summary="Ishlar ro'yxati")
async def list_cases(
    status: CaseStatus | None = Query(None, description="Holat filtri"),
    page:   int               = Query(1, ge=1, description="Sahifa raqami"),
    size:   int               = Query(20, ge=1, le=100, description="Sahifa hajmi"),
    db:     AsyncSession      = Depends(get_db),
) -> list[Case]:
    """Barcha ishlarni qaytaradi. FT-38."""
    stmt = select(Case).order_by(Case.opened_at.desc())
    if status:
        stmt = stmt.where(Case.status == status)
    stmt = stmt.offset((page - 1) * size).limit(size)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=CaseOut, status_code=201, summary="Yangi ish yaratish")
async def create_case(
    body: CaseCreate,
    db:   AsyncSession = Depends(get_db),
) -> Case:
    """Yangi kiberjinoyat ishi ochadi. FT-38."""
    case = Case(
        title=body.title,
        region=body.region,
        assignee_id=body.assignee_id,
        status=CaseStatus.new,
    )
    db.add(case)
    await db.flush()
    await db.commit()
    await db.refresh(case)
    return case


@router.get("/{case_id}", response_model=CaseOut, summary="Ish ma'lumotlari")
async def get_case(
    case_id: uuid.UUID,
    db:      AsyncSession = Depends(get_db),
) -> Case:
    """Bir ish ma'lumotlarini qaytaradi. FT-39."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=404, detail="Ish topilmadi")
    return case


@router.patch("/{case_id}", response_model=CaseOut, summary="Ish holatini yangilash")
async def patch_case(
    case_id: uuid.UUID,
    body:    CasePatch,
    db:      AsyncSession = Depends(get_db),
) -> Case:
    """Ish holati yoki tayinlamasini yangilaydi. FT-39."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=404, detail="Ish topilmadi")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(case, field, value)

    await db.commit()
    return case
