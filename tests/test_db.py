"""app/db.py sinovlari — ulanish qatlami (NFT-11).

Haqiqiy PostgreSQL ulanishi shart emas — engine mock qilinadi.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

import app.db as db_module


def _run(coro):
    return asyncio.run(coro)


# ================================================================= _build_dsn

class TestBuildDsn:
    def test_default_contains_asyncpg(self):
        with patch.dict(os.environ, {}, clear=True):
            dsn = db_module._build_dsn()
        assert "asyncpg" in dsn

    def test_postgresql_prefix_converted(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://ucw:pw@db/ucw"}):
            dsn = db_module._build_dsn()
        assert dsn.startswith("postgresql+asyncpg://")
        assert "postgresql+asyncpg+asyncpg" not in dsn

    def test_postgres_prefix_converted(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://ucw:pw@db/ucw"}):
            dsn = db_module._build_dsn()
        assert dsn.startswith("postgresql+asyncpg://")

    def test_asyncpg_prefix_not_doubled(self):
        url = "postgresql+asyncpg://ucw:pw@db/ucw"
        with patch.dict(os.environ, {"DATABASE_URL": url}):
            dsn = db_module._build_dsn()
        assert dsn == url

    def test_custom_host_preserved(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://user:pass@mydb:5433/myschema"}):
            dsn = db_module._build_dsn()
        assert "mydb:5433/myschema" in dsn


# ================================================================= get_engine

class TestGetEngine:
    def setup_method(self):
        db_module._engine = None
        db_module._session_factory = None

    def teardown_method(self):
        db_module._engine = None
        db_module._session_factory = None

    @patch("app.db.create_async_engine")
    def test_creates_engine_on_first_call(self, mock_create):
        mock_create.return_value = MagicMock()
        engine = db_module.get_engine()
        mock_create.assert_called_once()
        assert engine is not None

    @patch("app.db.create_async_engine")
    def test_singleton_second_call_same_object(self, mock_create):
        mock_create.return_value = MagicMock()
        e1 = db_module.get_engine()
        e2 = db_module.get_engine()
        mock_create.assert_called_once()
        assert e1 is e2

    @patch("app.db.create_async_engine")
    def test_echo_from_env(self, mock_create):
        mock_create.return_value = MagicMock()
        with patch.dict(os.environ, {"DB_ECHO": "1"}):
            db_module.get_engine()
        _, kwargs = mock_create.call_args
        assert kwargs.get("echo") is True

    @patch("app.db.create_async_engine")
    def test_pool_size_from_env(self, mock_create):
        mock_create.return_value = MagicMock()
        with patch.dict(os.environ, {"DB_POOL_SIZE": "5"}):
            db_module.get_engine()
        _, kwargs = mock_create.call_args
        assert kwargs.get("pool_size") == 5

    @patch("app.db.create_async_engine")
    def test_pool_pre_ping_enabled(self, mock_create):
        mock_create.return_value = MagicMock()
        db_module.get_engine()
        _, kwargs = mock_create.call_args
        assert kwargs.get("pool_pre_ping") is True


# ================================================================= get_session_factory

class TestGetSessionFactory:
    def setup_method(self):
        db_module._engine = None
        db_module._session_factory = None

    def teardown_method(self):
        db_module._engine = None
        db_module._session_factory = None

    @patch("app.db.async_sessionmaker")
    @patch("app.db.create_async_engine")
    def test_creates_factory_on_first_call(self, mock_engine, mock_factory):
        mock_engine.return_value = MagicMock()
        mock_factory.return_value = MagicMock()
        factory = db_module.get_session_factory()
        mock_factory.assert_called_once()
        assert factory is not None

    @patch("app.db.async_sessionmaker")
    @patch("app.db.create_async_engine")
    def test_singleton_second_call_same_object(self, mock_engine, mock_factory):
        mock_engine.return_value = MagicMock()
        mock_factory.return_value = MagicMock()
        f1 = db_module.get_session_factory()
        f2 = db_module.get_session_factory()
        mock_factory.assert_called_once()
        assert f1 is f2

    @patch("app.db.async_sessionmaker")
    @patch("app.db.create_async_engine")
    def test_expire_on_commit_false(self, mock_engine, mock_factory):
        mock_engine.return_value = MagicMock()
        mock_factory.return_value = MagicMock()
        db_module.get_session_factory()
        _, kwargs = mock_factory.call_args
        assert kwargs.get("expire_on_commit") is False


# ================================================================= close_engine

class TestCloseEngine:
    def setup_method(self):
        db_module._engine = None
        db_module._session_factory = None

    def teardown_method(self):
        db_module._engine = None
        db_module._session_factory = None

    @patch("app.db.create_async_engine")
    def test_close_calls_dispose(self, mock_create):
        mock_engine = AsyncMock()
        mock_create.return_value = mock_engine
        db_module.get_engine()
        _run(db_module.close_engine())
        mock_engine.dispose.assert_called_once()

    @patch("app.db.create_async_engine")
    def test_close_sets_engine_to_none(self, mock_create):
        mock_create.return_value = AsyncMock()
        db_module.get_engine()
        assert db_module._engine is not None
        _run(db_module.close_engine())
        assert db_module._engine is None

    @patch("app.db.create_async_engine")
    def test_close_sets_session_factory_to_none(self, mock_create):
        mock_engine = AsyncMock()
        mock_create.return_value = mock_engine
        db_module.get_engine()
        db_module._session_factory = MagicMock()  # qo'lda o'rnatish
        _run(db_module.close_engine())
        assert db_module._session_factory is None

    def test_close_noop_when_no_engine(self):
        db_module._engine = None
        # Istisno tashqariga chiqmasligi kerak
        _run(db_module.close_engine())
        assert db_module._engine is None

    @patch("app.db.create_async_engine")
    def test_close_then_new_engine_created(self, mock_create):
        mock_create.return_value = AsyncMock()
        db_module.get_engine()
        _run(db_module.close_engine())
        db_module.get_engine()
        assert mock_create.call_count == 2
