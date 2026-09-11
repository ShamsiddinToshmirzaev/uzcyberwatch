"""Alembic migratsiya tuzilmasi sinovlari (TZ: NFT-09, NFT-10).

TDD: fayl tuzilmasi va import aniqligi tekshiriladi.
Real DB ulanishsiz ishlatilishi mumkin bo'lgan testlar.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent

# ================================================================= alembic.ini

class TestAlembicConfig:
    def test_ini_exists(self):
        assert (ROOT / "alembic.ini").exists()

    def test_ini_has_alembic_section(self):
        content = (ROOT / "alembic.ini").read_text()
        assert "[alembic]" in content

    def test_ini_script_location(self):
        content = (ROOT / "alembic.ini").read_text()
        assert "script_location" in content
        assert "alembic" in content

    def test_ini_no_hardcoded_password(self):
        # Parol ini faylda bo'lmasligi shart
        content = (ROOT / "alembic.ini").read_text()
        assert "ucw:ucw" not in content
        assert "password" not in content.lower().replace("%(here)s", "")

    def test_env_py_exists(self):
        assert (ROOT / "alembic" / "env.py").exists()

    def test_versions_dir_exists(self):
        assert (ROOT / "alembic" / "versions").is_dir()


# ================================================================= env.py

class TestEnvPy:
    @pytest.fixture
    def env_src(self):
        return (ROOT / "alembic" / "env.py").read_text()

    def test_imports_base(self, env_src):
        assert "from app.models import Base" in env_src

    def test_target_metadata_set(self, env_src):
        assert "target_metadata" in env_src
        assert "Base.metadata" in env_src

    def test_has_run_migrations_offline(self, env_src):
        assert "run_migrations_offline" in env_src

    def test_has_run_migrations_online(self, env_src):
        assert "run_migrations_online" in env_src or "run_async_migrations" in env_src

    def test_url_from_env(self, env_src):
        # DATABASE_URL muhit o'zgaruvchisidan o'qilishi shart
        assert "DATABASE_URL" in env_src

    def test_no_hardcoded_credentials(self, env_src):
        assert "ucw:ucw@" not in env_src


# ================================================================= Migratsiya fayllari

def _get_migration_files() -> list[Path]:
    vdir = ROOT / "alembic" / "versions"
    return sorted(vdir.glob("*.py"))


class TestMigrationFiles:
    def test_at_least_one_migration(self):
        assert len(_get_migration_files()) >= 1

    def test_at_least_two_migrations(self):
        assert len(_get_migration_files()) >= 2

    def test_initial_migration_exists(self):
        files = [f.name for f in _get_migration_files()]
        assert any("initial" in f or "schema" in f or "0001" in f for f in files)

    def test_seed_migration_exists(self):
        files = [f.name for f in _get_migration_files()]
        assert any("seed" in f or "0002" in f for f in files)

    def test_all_migrations_have_revision(self):
        for f in _get_migration_files():
            src = f.read_text()
            assert "revision" in src, f"{f.name}: revision yo'q"

    def test_all_migrations_have_down_revision(self):
        for f in _get_migration_files():
            src = f.read_text()
            assert "down_revision" in src, f"{f.name}: down_revision yo'q"

    def test_all_migrations_have_upgrade(self):
        for f in _get_migration_files():
            src = f.read_text()
            assert "def upgrade" in src, f"{f.name}: upgrade() yo'q"

    def test_all_migrations_have_downgrade(self):
        for f in _get_migration_files():
            src = f.read_text()
            assert "def downgrade" in src, f"{f.name}: downgrade() yo'q"

    def test_revision_ids_are_unique(self):
        revisions = []
        for f in _get_migration_files():
            src = f.read_text()
            m = re.search(r"revision\s*=\s*['\"]([^'\"]+)['\"]", src)
            if m:
                revisions.append(m.group(1))
        assert len(revisions) == len(set(revisions)), "Takroriy revision ID topildi"

    def test_revision_chain_connected(self):
        """Migratsiyalar zanjiri uzluksiz bo'lishi shart."""
        revisions: dict[str, str | None] = {}
        for f in _get_migration_files():
            src = f.read_text()
            rev_m  = re.search(r"^revision\s*=\s*['\"]([^'\"]+)['\"]", src, re.M)
            down_m = re.search(r"^down_revision\s*=\s*['\"]?([^'\"(\n]+)['\"]?", src, re.M)
            if rev_m:
                down = down_m.group(1).strip().strip("'\"") if down_m else None
                revisions[rev_m.group(1)] = None if down == "None" else down

        # Bosh migratsiyani topish (down_revision=None)
        roots = [r for r, d in revisions.items() if d is None]
        assert len(roots) == 1, f"Aynan 1 ta bosh migratsiya bo'lishi shart, topildi: {roots}"


# ================================================================= Sxema mazmuni

class TestMigrationContent:
    @pytest.fixture
    def initial_src(self):
        files = _get_migration_files()
        for f in files:
            if "initial" in f.name or "schema" in f.name or "0001" in f.name:
                return f.read_text()
        pytest.skip("Boshlang'ich migratsiya topilmadi")

    def test_enum_types_created(self, initial_src):
        for enum in ("case_status", "source_kind", "event_type",
                     "detector_kind", "ioc_type", "user_role"):
            assert enum in initial_src, f"{enum} ENUM yaratilmagan"

    def test_core_tables_created(self, initial_src):
        for table in ("users", "sources", "raw_events", "cases", "detections"):
            assert table in initial_src, f"{table} jadvali yaratilmagan"

    def test_downgrade_drops_tables(self, initial_src):
        assert "drop_table" in initial_src or "DROP TABLE" in initial_src.upper()

    @pytest.fixture
    def seed_src(self):
        files = _get_migration_files()
        for f in files:
            if "seed" in f.name or "0002" in f.name:
                return f.read_text()
        pytest.skip("Seed migratsiya topilmadi")

    def test_seed_has_legal_articles(self, seed_src):
        assert "legal_articles" in seed_src or "278" in seed_src

    def test_seed_has_detectors(self, seed_src):
        assert "detectors" in seed_src
