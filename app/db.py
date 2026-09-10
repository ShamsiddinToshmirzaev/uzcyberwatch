"""Ma'lumotlar bazasi ulanish va sessiya boshqaruvi.

FT-46: FastAPI ilovasi uchun asinxron PostgreSQL ulanish qatlami.
Sozlamalar .env orqali pydantic-settings dan o'qiladi.
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.models import Base

# ----------------------------------------------------------------- sozlamalar

def _build_dsn() -> str:
    """DATABASE_URL dan DSN olish; asyncpg drayveriga o'zgartirish."""
    url = os.environ.get("DATABASE_URL", "postgresql+asyncpg://ucw:ucw@localhost:5432/uzcyberwatch")
    # psycopg2/psycopg3 prefiksini asyncpg ga almashtirish
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


# ----------------------------------------------------------------- dvigatel

_engine: AsyncEngine | None = None


def get_engine() -> AsyncEngine:
    """Yagona AsyncEngine instanceini qaytaradi (lazy init)."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            _build_dsn(),
            echo=os.environ.get("DB_ECHO", "0") == "1",
            pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
            max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
            pool_pre_ping=True,
        )
    return _engine


# ----------------------------------------------------------------- sessiya zavodi

_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Sessiya zavodini qaytaradi (lazy init)."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


# ----------------------------------------------------------------- FastAPI dependency

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Depends() uchun asinxron sessiya generatori.

    Ishlatilishi::

        @router.get("/cases")
        async def list_cases(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with get_session_factory()() as session:
        yield session


# ----------------------------------------------------------------- DDL yordamchilari (test/dev)

async def create_all() -> None:
    """Barcha jadvallarni yaratadi (faqat test/dev muhit uchun)."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all() -> None:
    """Barcha jadvallarni o'chiradi (faqat test muhit uchun)."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def close_engine() -> None:
    """Ilova to'xtaganda ulanishlarni yopadi."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
