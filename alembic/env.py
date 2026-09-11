"""Alembic muhit sozlamalari. Async SQLAlchemy + asyncpg.

DATABASE_URL muhit o'zgaruvchisidan DSN o'qiladi.
ORM modellari orqali avtomatik migratsiya qo'llab-quvvatlanadi.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.models import Base

# Alembic Config obyekti — alembic.ini dan o'qiladi
config = context.config

# Logging sozlamalari
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ORM metadatasi — avtogenerasiya va taqqoslash uchun
target_metadata = Base.metadata


def get_url() -> str:
    """DATABASE_URL muhit o'zgaruvchisidan DSN qaytaradi."""
    url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://localhost:5432/uzcyberwatch",
    )
    # postgres:// → postgresql+asyncpg://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and "+asyncpg" not in url:
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


# ----------------------------------------------------------------- Offline mode

def run_migrations_offline() -> None:
    """SQL faylga chiqarish (real DB ulanishsiz). `alembic upgrade --sql head`."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=False,
    )
    with context.begin_transaction():
        context.run_migrations()


# ----------------------------------------------------------------- Online mode

def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=False,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Asinxron online migratsiya ishga tushirish."""
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = get_url()
    connectable = async_engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Sinxron wrapper — Alembic CLI tomonidan chaqiriladi."""
    asyncio.run(run_async_migrations())


# ----------------------------------------------------------------- Kirish nuqtasi

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
