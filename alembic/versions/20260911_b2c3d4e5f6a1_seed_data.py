"""Boshlang'ich ma'lumotlar: admin foydalanuvchi, JK moddalari, detektorlar. NFT-10.

revision: b2c3d4e5f6a1
down_revision: a1b2c3d4e5f6 (initial_schema dan keyin)

Admin paroli UCW_ADMIN_PASSWORD muhit o'zgaruvchisidan o'qiladi.
O'rnatilmagan bo'lsa standart: Admin@12345 (birinchi kirishda o'zgartiring).
"""
from __future__ import annotations

import os

from alembic import op
import sqlalchemy as sa

from app.auth.password import hash_password

# ----------------------------------------------------------------- Identifikatorlar

revision = "b2c3d4e5f6a1"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


# ================================================================= upgrade

def upgrade() -> None:
    """Admin foydalanuvchi, JK moddalari va detektorlar jadvalga qo'shiladi."""

    # ---- 0. Admin foydalanuvchi (ON CONFLICT — ikkinchi run xavfsiz) --------
    default_password = os.environ.get("UCW_ADMIN_PASSWORD", "Admin@12345")
    password_hash = hash_password(default_password)
    op.execute(
        sa.text(
            "INSERT INTO users "
            "  (id, username, password_hash, role, mfa_enabled, is_active) "
            "VALUES "
            "  (:id, :username, :password_hash, 'admin', false, true) "
            "ON CONFLICT (username) DO NOTHING"
        ).bindparams(
            id="00000000-0000-0000-0000-000000000000",
            username="admin",
            password_hash=password_hash,
        )
    )

    # ---- 1. JK moddalari ----------------------------------------------------
    legal_articles = sa.table(
        "legal_articles",
        sa.column("code", sa.Text),
        sa.column("chapter", sa.Text),
        sa.column("title_uz", sa.Text),
        sa.column("severity", sa.Text),
        sa.column("notes", sa.Text),
    )

    op.bulk_insert(legal_articles, [
        {
            "code": "278",
            "chapter": "Kiberjinoyatlar",
            "title_uz": "Kompyuter axborotiga noqonuniy kirish",
            "severity": "o'rta",
            "notes": "1-3 yil ozodlikdan mahrum qilish",
        },
        {
            "code": "278-1",
            "chapter": "Kiberjinoyatlar",
            "title_uz": "Zararli dasturiy ta'minotni yaratish va tarqatish",
            "severity": "og'ir",
            "notes": "3-7 yil ozodlikdan mahrum qilish",
        },
        {
            "code": "168",
            "chapter": "Firibgarlik",
            "title_uz": "Firibgarlik (internet orqali)",
            "severity": "o'rta",
            "notes": "Kompyuter yoki internet vositasida sodir etilgan firibgarlik",
        },
        {
            "code": "173",
            "chapter": "Firibgarlik",
            "title_uz": "Bank kartasini noqonuniy olish yoki ishlatish",
            "severity": "og'ir",
            "notes": "To'lov karta ma'lumotlarini o'g'irlash yoki fishing",
        },
        {
            "code": "182",
            "chapter": "Huquqiy tartib",
            "title_uz": "Shaxsiy ma'lumotlarni himoya qilish talablarini buzish",
            "severity": "engilroq",
            "notes": "PII ma'lumotlarini ruxsatsiz tarqatish",
        },
    ])

    detectors = sa.table(
        "detectors",
        sa.column("id", sa.Text),
        sa.column("kind", sa.Text),
        sa.column("name", sa.Text),
        sa.column("version", sa.Text),
        sa.column("enabled", sa.Boolean),
        sa.column("params", sa.Text),
    )

    # ---- 2. Standart detektorlar --------------------------------------------
    op.bulk_insert(detectors, [
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "kind": "rule",
            "name": "brands_typosquat",
            "version": "1.0",
            "enabled": True,
            "params": "{}",
        },
        {
            "id": "00000000-0000-0000-0000-000000000002",
            "kind": "rule",
            "name": "text_rules_uz",
            "version": "1.0",
            "enabled": True,
            "params": "{}",
        },
        {
            "id": "00000000-0000-0000-0000-000000000003",
            "kind": "model",
            "name": "url_gbdt",
            "version": "1.0",
            "enabled": True,
            "params": '{"threshold": 0.5}',
        },
        {
            "id": "00000000-0000-0000-0000-000000000004",
            "kind": "heuristic",
            "name": "pii_exposure",
            "version": "1.0",
            "enabled": True,
            "params": "{}",
        },
    ])


# ================================================================= downgrade

def downgrade() -> None:
    """Seed ma'lumotlari o'chiriladi."""
    op.execute(
        "DELETE FROM detectors WHERE id IN ("
        "  '00000000-0000-0000-0000-000000000001',"
        "  '00000000-0000-0000-0000-000000000002',"
        "  '00000000-0000-0000-0000-000000000003',"
        "  '00000000-0000-0000-0000-000000000004'"
        ")"
    )
    op.execute(
        "DELETE FROM legal_articles WHERE code IN ('278', '278-1', '168', '173', '182')"
    )
    op.execute(
        "DELETE FROM users WHERE id = '00000000-0000-0000-0000-000000000000'"
    )
