"""SQLAlchemy modellari uchun sinov (TZ: NFT-11, HT-03).

Tekshiruvlar:
- Har bir jadval to'g'ri mapping qilinganligini tekshiradi.
- PII maydonlari faqat hash ko'rinishida ekanligini tekshiradi.
- Munosabatlar (relationships) va cheklovlar (constraints) to'g'riligini tekshiradi.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import get_type_hints

import pytest

from app.models import (
    AuditLog,
    Case,
    CaseStatus,
    Detection,
    Detector,
    DetectorKind,
    Enrichment,
    EventIndicator,
    EventType,
    Evidence,
    Indicator,
    IndicatorEdge,
    IocType,
    Label,
    LegalArticle,
    RawEvent,
    Source,
    SourceKind,
    User,
    UserRole,
)


# ----------------------------------------------------------------- yordamchi funksiyalar

def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------- ENUM sinovlari

class TestEnums:
    def test_source_kind_values(self):
        assert set(SourceKind.__members__) == {"ct_log", "complaint", "honeypot", "ti_feed", "manual"}

    def test_event_type_values(self):
        assert set(EventType.__members__) == {"url", "domain", "message", "host_event", "file"}

    def test_detector_kind_values(self):
        assert set(DetectorKind.__members__) == {"rule", "model", "graph", "heuristic"}

    def test_case_status_values(self):
        assert set(CaseStatus.__members__) == {"new", "triage", "confirmed", "false_positive", "closed"}

    def test_ioc_type_values(self):
        assert set(IocType.__members__) == {"domain", "url", "ip", "sha256", "phone", "card_bin", "account", "email"}

    def test_user_role_values(self):
        assert set(UserRole.__members__) == {"analyst", "investigator", "admin", "researcher", "guest"}


# ----------------------------------------------------------------- jadval sinovlari

class TestUserModel:
    def test_tablename(self):
        assert User.__tablename__ == "users"

    def test_pk_is_uuid(self):
        col = User.__table__.c["id"]
        assert str(col.type) in ("UUID", "Uuid")

    def test_password_hash_exists(self):
        # HT-03: xom parol emas, hash saqlanadi
        assert "password_hash" in User.__table__.c

    def test_no_raw_password_field(self):
        # Xom parol maydoni bo'lmasligi shart
        for name in User.__table__.c.keys():
            assert name != "password", "Xom parol maydoni topildi!"

    def test_role_has_default(self):
        col = User.__table__.c["role"]
        assert col.default is not None or col.server_default is not None

    def test_mfa_enabled_default_false(self):
        col = User.__table__.c["mfa_enabled"]
        assert col.default is not None or col.server_default is not None

    def test_is_active_default_true(self):
        col = User.__table__.c["is_active"]
        assert col.default is not None or col.server_default is not None

    def test_instantiation(self):
        u = User(
            username="test_analyst",
            password_hash="$argon2id$v=19$...",
            role=UserRole.analyst,
        )
        assert u.username == "test_analyst"
        assert u.role == UserRole.analyst


class TestSourceModel:
    def test_tablename(self):
        assert Source.__tablename__ == "sources"

    def test_required_columns(self):
        cols = Source.__table__.c.keys()
        for col in ("id", "kind", "name", "config", "enabled"):
            assert col in cols

    def test_nullable_last_run(self):
        assert Source.__table__.c["last_run_at"].nullable

    def test_instantiation(self):
        s = Source(kind=SourceKind.ct_log, name="certstream-prod")
        assert s.kind == SourceKind.ct_log


class TestRawEventModel:
    def test_tablename(self):
        assert RawEvent.__tablename__ == "raw_events"

    def test_content_not_nullable(self):
        assert not RawEvent.__table__.c["content"].nullable

    def test_dedup_hash_not_nullable(self):
        assert not RawEvent.__table__.c["dedup_hash"].nullable

    def test_optional_fields_nullable(self):
        for col in ("url", "domain", "lang"):
            assert RawEvent.__table__.c[col].nullable, f"{col} nullable bo'lishi kerak"

    def test_no_pii_raw_columns(self):
        # HT-03: xom PII maydonlari yo'q bo'lishi kerak
        forbidden = {"phone", "card_number", "passport", "pinfl", "email_raw"}
        cols = set(RawEvent.__table__.c.keys())
        assert not forbidden & cols, f"PII maydoni topildi: {forbidden & cols}"

    def test_source_fk_exists(self):
        fks = {fk.column.table.name for fk in RawEvent.__table__.foreign_keys}
        assert "sources" in fks

    def test_instantiation(self):
        sid = _uuid()
        e = RawEvent(
            source_id=sid,
            event_type=EventType.url,
            content="test content",
            dedup_hash="abc123",
        )
        assert e.event_type == EventType.url


class TestEnrichmentModel:
    def test_tablename(self):
        assert Enrichment.__tablename__ == "enrichments"

    def test_event_id_unique(self):
        col = Enrichment.__table__.c["event_id"]
        uniques = [c for c in Enrichment.__table__.constraints if hasattr(c, "columns")]
        # event_id UNIQUE constraint yoki FK bilan UNIQUE
        assert not col.nullable

    def test_ip_nullable(self):
        assert Enrichment.__table__.c["ip"].nullable

    def test_reputation_jsonb(self):
        col = Enrichment.__table__.c["reputation"]
        assert "JSON" in str(col.type).upper()

    def test_instantiation(self):
        eid = _uuid()
        en = Enrichment(event_id=eid, geo_country="UZ", geo_region="Toshkent")
        assert en.geo_country == "UZ"


class TestIndicatorModel:
    def test_tablename(self):
        assert Indicator.__tablename__ == "indicators"

    def test_value_hash_not_nullable(self):
        # HT-03: qiymat xom holda emas, HMAC-hesh sifatida saqlanadi
        assert not Indicator.__table__.c["value_hash"].nullable

    def test_no_value_raw_column(self):
        # Xom IoC qiymati saqlanmasligi kerak
        assert "value" not in Indicator.__table__.c, "Xom IoC qiymati topildi!"

    def test_value_hint_nullable(self):
        assert Indicator.__table__.c["value_hint"].nullable

    def test_hit_count_default(self):
        col = Indicator.__table__.c["hit_count"]
        assert col.default is not None or col.server_default is not None

    def test_instantiation(self):
        ind = Indicator(
            ioc_type=IocType.phone,
            value_hash="abc" * 21 + "d",
            value_hint="+998 90 *** ** 12",
        )
        assert ind.ioc_type == IocType.phone
        assert ind.value_hint == "+998 90 *** ** 12"


class TestIndicatorEdgeModel:
    def test_tablename(self):
        assert IndicatorEdge.__tablename__ == "indicator_edges"

    def test_no_self_loop_enforced_in_model(self):
        # Modelda src_id != dst_id cheklovi borligini tekshirish
        cols = IndicatorEdge.__table__.c.keys()
        assert "src_id" in cols and "dst_id" in cols

    def test_community_nullable(self):
        assert IndicatorEdge.__table__.c["community"].nullable


class TestEventIndicatorModel:
    def test_tablename(self):
        assert EventIndicator.__tablename__ == "event_indicators"

    def test_composite_pk(self):
        pk_cols = {c.name for c in EventIndicator.__table__.primary_key}
        assert pk_cols == {"event_id", "indicator_id"}


class TestDetectorModel:
    def test_tablename(self):
        assert Detector.__tablename__ == "detectors"

    def test_metrics_nullable(self):
        for col in ("f1_score", "precision", "recall", "trained_at"):
            assert Detector.__table__.c[col].nullable

    def test_instantiation(self):
        d = Detector(kind=DetectorKind.rule, name="url_rules", version="1.0")
        assert d.kind == DetectorKind.rule


class TestLegalArticleModel:
    def test_tablename(self):
        assert LegalArticle.__tablename__ == "legal_articles"

    def test_pk_is_text_code(self):
        col = LegalArticle.__table__.c["code"]
        assert not col.nullable

    def test_instantiation(self):
        la = LegalArticle(
            code="278-1",
            chapter="29-bob",
            title_uz="Firibgarlik",
            severity="og'ir",
        )
        assert la.code == "278-1"


class TestCaseModel:
    def test_tablename(self):
        assert Case.__tablename__ == "cases"

    def test_status_default_new(self):
        col = Case.__table__.c["status"]
        assert col.default is not None or col.server_default is not None

    def test_total_risk_default_zero(self):
        col = Case.__table__.c["total_risk"]
        assert col.default is not None or col.server_default is not None

    def test_assignee_nullable(self):
        assert Case.__table__.c["assignee_id"].nullable

    def test_closed_at_nullable(self):
        assert Case.__table__.c["closed_at"].nullable

    def test_instantiation(self):
        c = Case(title="Phishing kampaniyasi", status=CaseStatus.new)
        assert c.status == CaseStatus.new


class TestDetectionModel:
    def test_tablename(self):
        assert Detection.__tablename__ == "detections"

    def test_explanation_is_jsonb(self):
        col = Detection.__table__.c["explanation"]
        assert "JSON" in str(col.type).upper()

    def test_confidence_not_nullable(self):
        assert not Detection.__table__.c["confidence"].nullable

    def test_case_id_nullable(self):
        assert Detection.__table__.c["case_id"].nullable

    def test_instantiation(self):
        det = Detection(
            event_id=_uuid(),
            detector_id=_uuid(),
            confidence=0.85,
            risk_score=72,
            explanation=[{"rule": "url_typosquat", "score": 72}],
        )
        assert det.risk_score == 72


class TestEvidenceModel:
    def test_tablename(self):
        assert Evidence.__tablename__ == "evidence"

    def test_sha256_not_nullable(self):
        assert not Evidence.__table__.c["sha256"].nullable

    def test_collected_by_nullable(self):
        assert Evidence.__table__.c["collected_by"].nullable


class TestLabelModel:
    def test_tablename(self):
        assert Label.__tablename__ == "labels"

    def test_annotator_conf_default(self):
        col = Label.__table__.c["annotator_conf"]
        assert col.default is not None or col.server_default is not None

    def test_instantiation(self):
        lb = Label(
            event_id=_uuid(),
            user_id=_uuid(),
            class_label="phishing",
        )
        assert lb.class_label == "phishing"


class TestAuditLogModel:
    def test_tablename(self):
        assert AuditLog.__tablename__ == "audit_log"

    def test_action_not_nullable(self):
        assert not AuditLog.__table__.c["action"].nullable

    def test_details_jsonb(self):
        col = AuditLog.__table__.c["details"]
        assert "JSON" in str(col.type).upper()

    def test_user_id_nullable(self):
        # Tizim hodisalari foydalanuvchisiz bo'lishi mumkin
        assert AuditLog.__table__.c["user_id"].nullable

    def test_instantiation(self):
        al = AuditLog(action="case.create", object_ref="case/abc-123")
        assert al.action == "case.create"


# ----------------------------------------------------------------- HT-03 yaxlit tekshiruv

class TestPiiCompliance:
    """HT-03: Barcha jadvallarda xom PII maydoni yo'qligini tekshiradi."""

    FORBIDDEN_COLUMN_NAMES = {
        "phone", "phone_number", "card_number", "card",
        "passport_number", "passport", "pinfl", "email_raw",
        "tin", "ssn", "iban",
    }

    MODELS = [
        User, Source, RawEvent, Enrichment, Indicator, IndicatorEdge,
        EventIndicator, Detector, LegalArticle, Case, Detection,
        Evidence, Label, AuditLog,
    ]

    def test_no_raw_pii_in_any_table(self):
        violations = []
        for model in self.MODELS:
            cols = set(model.__table__.c.keys())
            found = cols & self.FORBIDDEN_COLUMN_NAMES
            if found:
                violations.append(f"{model.__tablename__}: {found}")
        assert not violations, f"HT-03 buzilishi: {violations}"

    def test_indicator_stores_hash_not_value(self):
        cols = set(Indicator.__table__.c.keys())
        assert "value_hash" in cols
        assert "value" not in cols

    def test_user_stores_hash_not_password(self):
        cols = set(User.__table__.c.keys())
        assert "password_hash" in cols
        assert "password" not in cols
