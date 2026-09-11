"""Autentifikatsiya endpointlari. FT-44.

POST /api/v1/auth/login — JWT token olish.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import LoginRequest, TokenOut
from app.auth.jwt import create_access_token
from app.auth.password import verify_password
from app.db import get_db
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenOut:
    """Foydalanuvchi login qiladi va JWT token oladi. FT-44."""
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if (
        user is None
        or not user.is_active
        or not verify_password(body.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login yoki parol noto'g'ri",
        )
    return TokenOut(access_token=create_access_token(user.username))
