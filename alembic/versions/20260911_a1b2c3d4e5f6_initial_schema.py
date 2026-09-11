"""Boshlang'ich sxema: ENUM turlar va barcha jadvallar. NFT-09.

revision: a1b2c3d4e5f6
down_revision: None (birinchi migratsiya)
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# ----------------------------------------------------------------- Identifikatorlar

revision = "a1b2c3d4e5f6"
down_revision = None
branch_labels = None
depends_on = None


# ----------------------------------------------------------------- Yordamchi funksiyalar

def _create_enum(name: str, *values: str) -> None:
    """Agar mavjud bo'lmasa ENUM tur yaratadi (idempotent)."""
    vals = ", ".join(f"'{v}'" for v in values)
    op.execute(
        f"DO $$ BEGIN "
        f"  CREATE TYPE {name} AS ENUM ({vals}); "
        f"EXCEPTION WHEN duplicate_object THEN NULL; "
        f"END $$"
    )


def _drop_enum(name: str) -> None:
    """ENUM turni o'chiradi (agar mavjud bo'lsa)."""
    op.execute(f"DROP TYPE IF EXISTS {name} CASCADE")


# ================================================================= upgrade

def upgrade() -> None:
    """Barcha ENUM turlar va jadvallar yaratiladi."""

    # ---- 1. ENUM turlar ------------------------------------------------
    _create_enum("user_role", "analyst", "investigator", "admin", "researcher", "guest")
    _create_enum("source_kind", "ct_log", "complaint", "honeypot", "ti_feed", "manual")
    _create_enum("event_type", "url", "domain", "message", "host_event", "file")
    _create_enum("ioc_type", "domain", "url", "ip", "sha256", "phone", "card_bin", "account", "email")
    _create_enum("detector_kind", "rule", "model", "graph", "heuristic")
    _create_enum("case_status", "new", "triage", "confirmed", "false_positive", "closed")

    # ---- 2. Jadvallar ---------------------------------------------------

    # FT-43,44: foydalanuvchilar
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.Text, nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column(
            "role",
            sa.Enum("analyst", "investigator", "admin", "researcher", "guest",
                    name="user_role", create_type=False),
            nullable=False, server_default="analyst",
        ),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # FT-01..09: manbalar
    op.create_table(
        "sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "kind",
            sa.Enum("ct_log", "complaint", "honeypot", "ti_feed", "manual",
                    name="source_kind", create_type=False),
            nullable=False,
        ),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_run_at", sa.DateTime, nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("error_count", sa.Integer, nullable=False, server_default="0"),
    )

    # FT-10..14: normallashtirilgan hodisalar
    op.create_table(
        "raw_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum("url", "domain", "message", "host_event", "file",
                    name="event_type", create_type=False),
            nullable=False,
        ),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("url", sa.Text, nullable=True),
        sa.Column("domain", sa.Text, nullable=True),
        sa.Column("lang", sa.Text, nullable=True),
        sa.Column("dedup_hash", sa.Text, nullable=False),
        sa.Column("ecs", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("observed_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("ingested_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("dedup_hash", name="uq_raw_events_dedup"),
    )

    # FT-15..20: boyitish
    op.create_table(
        "enrichments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("ip", postgresql.INET, nullable=True),
        sa.Column("asn", sa.Text, nullable=True),
        sa.Column("asn_org", sa.Text, nullable=True),
        sa.Column("geo_country", sa.Text, nullable=True),
        sa.Column("geo_region", sa.Text, nullable=True),
        sa.Column("domain_age_days", sa.Integer, nullable=True),
        sa.Column("registrar", sa.Text, nullable=True),
        sa.Column("cert_issuer", sa.Text, nullable=True),
        sa.Column("screenshot_phash", sa.Text, nullable=True),
        sa.Column("reputation", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("enriched_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # FT-22,26: IoC ko'rsatkichlari
    op.create_table(
        "indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "ioc_type",
            sa.Enum("domain", "url", "ip", "sha256", "phone", "card_bin", "account", "email",
                    name="ioc_type", create_type=False),
            nullable=False,
        ),
        sa.Column("value_hash", sa.Text, nullable=False),
        sa.Column("value_hint", sa.Text, nullable=True),
        sa.Column("first_seen", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("hit_count", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint("ioc_type", "value_hash", name="uq_indicator"),
    )

    # FT-22: Hodisa ↔ IoC ko'p-ko'p
    op.create_table(
        "event_indicators",
        sa.Column("event_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("raw_events.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("indicator_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True),
    )

    # FT-26: Graf qirralari
    op.create_table(
        "indicator_edges",
        sa.Column("src_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("dst_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("weight", sa.Integer, nullable=False, server_default="1"),
        sa.Column("community", sa.Integer, nullable=True),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("src_id <> dst_id", name="chk_no_self_loop"),
    )

    # FT-21..30: detektorlar
    op.create_table(
        "detectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "kind",
            sa.Enum("rule", "model", "graph", "heuristic",
                    name="detector_kind", create_type=False),
            nullable=False,
        ),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("version", sa.Text, nullable=False, server_default="1.0"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("params", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("f1_score", sa.Float, nullable=True),
        sa.Column("precision", sa.Float, nullable=True),
        sa.Column("recall", sa.Float, nullable=True),
        sa.Column("trained_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("name", "version", name="uq_detector"),
    )

    # FT-28: JK moddalari ma'lumotnomasi
    op.create_table(
        "legal_articles",
        sa.Column("code", sa.Text, primary_key=True),
        sa.Column("chapter", sa.Text, nullable=False),
        sa.Column("title_uz", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
    )

    # FT-38,39: Ishlar
    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("assignee_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("article_code", sa.Text,
                  sa.ForeignKey("legal_articles.code", ondelete="SET NULL"), nullable=True),
        sa.Column("article_conf", sa.Float, nullable=True),
        sa.Column(
            "status",
            sa.Enum("new", "triage", "confirmed", "false_positive", "closed",
                    name="case_status", create_type=False),
            nullable=False, server_default="new",
        ),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("region", sa.Text, nullable=True),
        sa.Column("total_risk", sa.Integer, nullable=False, server_default="0"),
        sa.Column("opened_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("closed_at", sa.DateTime, nullable=True),
        sa.CheckConstraint("total_risk BETWEEN 0 AND 100", name="chk_total_risk"),
    )

    # FT-27: Aniqlash natijalari (sabablar majburiy)
    op.create_table(
        "detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("detector_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("detectors.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("case_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("explanation", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("detected_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("event_id", "detector_id", name="uq_detection"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="chk_conf"),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="chk_risk"),
    )

    # FT-40,41: Dalil zanjiri
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_type", sa.Text, nullable=False),
        sa.Column("sha256", sa.Text, nullable=False),
        sa.Column("storage_path", sa.Text, nullable=False),
        sa.Column("collected_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("collected_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("case_id", "sha256", name="uq_evidence_hash"),
    )

    # QM-18,19: Annotatsiya belgilari
    op.create_table(
        "labels",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("class_label", sa.Text, nullable=False),
        sa.Column("annotator_conf", sa.Float, nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("event_id", "user_id", name="uq_label_per_user"),
    )

    # FT-45: Append-only audit jurnali
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("object_ref", sa.Text, nullable=True),
        sa.Column("ip", postgresql.INET, nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )


# ================================================================= downgrade

def downgrade() -> None:
    """Barcha jadvallar va ENUM turlar o'chiriladi."""
    op.drop_table("audit_log")
    op.drop_table("labels")
    op.drop_table("evidence")
    op.drop_table("detections")
    op.drop_table("cases")
    op.drop_table("legal_articles")
    op.drop_table("detectors")
    op.drop_table("indicator_edges")
    op.drop_table("event_indicators")
    op.drop_table("indicators")
    op.drop_table("enrichments")
    op.drop_table("raw_events")
    op.drop_table("sources")
    op.drop_table("users")

    _drop_enum("case_status")
    _drop_enum("detector_kind")
    _drop_enum("ioc_type")
    _drop_enum("event_type")
    _drop_enum("source_kind")
    _drop_enum("user_role")
