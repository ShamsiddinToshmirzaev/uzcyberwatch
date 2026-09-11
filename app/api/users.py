"""Foydalanuvchi boshqaruvi endpointlari. FT-43.

GET  /api/v1/users     — ro'yxat (faqat admin)
POST /api/v1/users     — yangi foydalanuvchi (faqat admin)
GET  /api/v1/users/me  — joriy foydalanuvchi
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import UserCreate, UserOut
from app.auth.deps import get_current_user
from app.auth.password import hash_password
from app.db import get_db
from app.models import User, UserRole

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def me(current: User = Depends(get_current_user)) -> User:
    """Joriy autentifikatsiya qilingan foydalanuvchini qaytaradi. FT-43."""
    return current


@router.get("", response_model=list[UserOut])
async def list_users(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
) -> list[User]:
    """Barcha foydalanuvchilar ro'yxati. Faqat admin. FT-43."""
    _require_admin(current)
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
) -> User:
    """Yangi foydalanuvchi yaratadi. Faqat admin. FT-43.

    HT-03: xom parol saqlanmaydi — faqat bcrypt heshi.
    """
    _require_admin(current)
    existing = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Bu username allaqachon band")
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _require_admin(user: User) -> None:
    if user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Bu amalni bajarish uchun admin huquqi kerak")
