"""SQLAlchemy 2.0 ORM modellari — db/001_schema.sql ga to'liq mos.

FT-43,44 (foydalanuvchilar), FT-01..09 (manbalar), FT-10..14 (hodisalar),
FT-15..20 (boyitish), FT-22,26 (IoC/graf), FT-21..30 (detektorlar),
FT-40,41 (dalil zanjiri), FT-45 (audit).

HT-03: barcha PII maydonlari faqat value_hash / password_hash ko'rinishida.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ----------------------------------------------------------------- ENUM'lar

class SourceKind(str, enum.Enum):
    ct_log    = "ct_log"
    complaint = "complaint"
    honeypot  = "honeypot"
    ti_feed   = "ti_feed"
    manual    = "manual"


class EventType(str, enum.Enum):
    url        = "url"
    domain     = "domain"
    message    = "message"
    host_event = "host_event"
    file       = "file"


class DetectorKind(str, enum.Enum):
    rule      = "rule"
    model     = "model"
    graph     = "graph"
    heuristic = "heuristic"


class CaseStatus(str, enum.Enum):
    new            = "new"
    triage         = "triage"
    confirmed      = "confirmed"
    false_positive = "false_positive"
    closed         = "closed"


class IocType(str, enum.Enum):
    domain   = "domain"
    url      = "url"
    ip       = "ip"
    sha256   = "sha256"
    phone    = "phone"
    card_bin = "card_bin"
    account  = "account"
    email    = "email"


class UserRole(str, enum.Enum):
    analyst      = "analyst"
    investigator = "investigator"
    admin        = "admin"
    researcher   = "researcher"
    guest        = "guest"


# ----------------------------------------------------------------- Asos sinf

class Base(DeclarativeBase):
    pass


# ----------------------------------------------------------------- FT-43,44: foydalanuvchilar

class User(Base):
    """Tizim foydalanuvchisi. FT-43,44."""

    __tablename__ = "users"

    id:            Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username:      Mapped[str]       = mapped_column(Text, nullable=False, unique=True)
    # HT-03: xom parol emas — argon2id/bcrypt heshi
    password_hash: Mapped[str]       = mapped_column(Text, nullable=False)
    role:          Mapped[UserRole]  = mapped_column(
        String(20), nullable=False, default=UserRole.analyst, server_default="analyst"
    )
    mfa_enabled:   Mapped[bool]      = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    is_active:     Mapped[bool]      = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at:    Mapped[datetime]  = mapped_column(nullable=False, server_default=func.now())

    cases:      Mapped[list["Case"]]     = relationship("Case", back_populates="assignee", foreign_keys="Case.assignee_id")
    labels:     Mapped[list["Label"]]    = relationship("Label", back_populates="user")
    evidence:   Mapped[list["Evidence"]] = relationship("Evidence", back_populates="collected_by_user",
                                                        foreign_keys="Evidence.collected_by")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user")


# ----------------------------------------------------------------- FT-01..09: manbalar

class Source(Base):
    """Ma'lumot manbasi (CT log, shikoyat, honeypot, TI feed). FT-01..09."""

    __tablename__ = "sources"

    id:          Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind:        Mapped[SourceKind]      = mapped_column(String(20), nullable=False)
    name:        Mapped[str]             = mapped_column(Text, nullable=False, unique=True)
    config:      Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    enabled:     Mapped[bool]            = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    last_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_error:  Mapped[str | None]      = mapped_column(Text, nullable=True)
    error_count: Mapped[int]             = mapped_column(Integer, nullable=False, default=0, server_default="0")

    raw_events: Mapped[list["RawEvent"]] = relationship("RawEvent", back_populates="source")


# ----------------------------------------------------------------- FT-10..14: normallashtirilgan hodisalar

class RawEvent(Base):
    """Normallashtirilgan xom hodisa. FT-10..14.

    HT-03: content maydoni faqat redact() dan o'tgan matn.
    Xom PII maydoni yo'q — faqat event_indicators orqali Indicator ga bog'lanadi.
    """

    __tablename__ = "raw_events"
    __table_args__ = (
        UniqueConstraint("dedup_hash", name="uq_raw_events_dedup"),
    )

    id:          Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id:   Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False)
    event_type:  Mapped[EventType]       = mapped_column(String(20), nullable=False)
    # FT-13: PII maskalangan holda — pii.redact() ishlatilishi shart
    content:     Mapped[str]             = mapped_column(Text, nullable=False)
    url:         Mapped[str | None]      = mapped_column(Text, nullable=True)
    domain:      Mapped[str | None]      = mapped_column(Text, nullable=True)
    lang:        Mapped[str | None]      = mapped_column(Text, nullable=True)
    dedup_hash:  Mapped[str]             = mapped_column(Text, nullable=False)
    ecs:         Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    observed_at: Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())
    ingested_at: Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())

    source:     Mapped["Source"]                    = relationship("Source", back_populates="raw_events")
    enrichment: Mapped["Enrichment | None"]         = relationship("Enrichment", back_populates="event", uselist=False)
    indicators: Mapped[list["EventIndicator"]]      = relationship("EventIndicator", back_populates="event")
    detections: Mapped[list["Detection"]]           = relationship("Detection", back_populates="event")
    labels:     Mapped[list["Label"]]               = relationship("Label", back_populates="event")


# ----------------------------------------------------------------- FT-15..20: boyitish

class Enrichment(Base):
    """GeoIP, WHOIS, reputatsiya, skrinshot pHash. FT-15..20."""

    __tablename__ = "enrichments"

    id:               Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id:         Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False, unique=True)
    ip:               Mapped[str | None]      = mapped_column(INET, nullable=True)
    asn:              Mapped[str | None]      = mapped_column(Text, nullable=True)
    asn_org:          Mapped[str | None]      = mapped_column(Text, nullable=True)
    geo_country:      Mapped[str | None]      = mapped_column(Text, nullable=True)
    geo_region:       Mapped[str | None]      = mapped_column(Text, nullable=True)
    domain_age_days:  Mapped[int | None]      = mapped_column(Integer, nullable=True)
    registrar:        Mapped[str | None]      = mapped_column(Text, nullable=True)
    cert_issuer:      Mapped[str | None]      = mapped_column(Text, nullable=True)
    screenshot_phash: Mapped[str | None]      = mapped_column(Text, nullable=True)
    reputation:       Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    enriched_at:      Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())

    event: Mapped["RawEvent"] = relationship("RawEvent", back_populates="enrichment")


# ----------------------------------------------------------------- FT-22,26: IoC va graf

class Indicator(Base):
    """Tahdid ko'rsatkichi (IoC). HT-03: xom qiymat emas, HMAC-hesh.

    FT-22 (IoC ro'yxati), FT-26 (graf munosabatlari uchun asos).
    """

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value_hash", name="uq_indicator"),
    )

    id:         Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type:   Mapped[IocType]         = mapped_column(String(20), nullable=False)
    # HT-03: HMAC-SHA256 hesh — pii.pii_hash() ishlatilishi shart
    value_hash: Mapped[str]             = mapped_column(Text, nullable=False)
    value_hint: Mapped[str | None]      = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())
    last_seen:  Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())
    hit_count:  Mapped[int]             = mapped_column(Integer, nullable=False, default=1, server_default="1")

    events:         Mapped[list["EventIndicator"]] = relationship("EventIndicator", back_populates="indicator")
    outgoing_edges: Mapped[list["IndicatorEdge"]]  = relationship("IndicatorEdge", back_populates="src",
                                                                  foreign_keys="IndicatorEdge.src_id")
    incoming_edges: Mapped[list["IndicatorEdge"]]  = relationship("IndicatorEdge", back_populates="dst",
                                                                  foreign_keys="IndicatorEdge.dst_id")


class EventIndicator(Base):
    """Hodisa ↔ IoC ko'p-ko'p aloqasi. FT-22."""

    __tablename__ = "event_indicators"

    event_id:     Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("raw_events.id", ondelete="CASCADE"), primary_key=True)
    indicator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)

    event:     Mapped["RawEvent"]  = relationship("RawEvent", back_populates="indicators")
    indicator: Mapped["Indicator"] = relationship("Indicator", back_populates="events")


class IndicatorEdge(Base):
    """Graf qirrasi: firibgar guruhlarni aniqlash uchun. FT-26."""

    __tablename__ = "indicator_edges"
    __table_args__ = (
        CheckConstraint("src_id <> dst_id", name="chk_no_self_loop"),
    )

    src_id:     Mapped[uuid.UUID]  = mapped_column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)
    dst_id:     Mapped[uuid.UUID]  = mapped_column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)
    weight:     Mapped[int]        = mapped_column(Integer, nullable=False, default=1, server_default="1")
    community:  Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime]   = mapped_column(nullable=False, server_default=func.now())

    src: Mapped["Indicator"] = relationship("Indicator", back_populates="outgoing_edges", foreign_keys=[src_id])
    dst: Mapped["Indicator"] = relationship("Indicator", back_populates="incoming_edges", foreign_keys=[dst_id])


# ----------------------------------------------------------------- FT-21..30: detektorlar

class Detector(Base):
    """Aniqlash dvigateli tavsifi. FT-21..30."""

    __tablename__ = "detectors"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_detector"),
    )

    id:         Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind:       Mapped[DetectorKind]    = mapped_column(String(20), nullable=False)
    name:       Mapped[str]             = mapped_column(Text, nullable=False)
    version:    Mapped[str]             = mapped_column(Text, nullable=False, default="1.0", server_default="1.0")
    enabled:    Mapped[bool]            = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    params:     Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    f1_score:   Mapped[float | None]    = mapped_column(Float, nullable=True)
    precision:  Mapped[float | None]    = mapped_column(Float, nullable=True)
    recall:     Mapped[float | None]    = mapped_column(Float, nullable=True)
    trained_at: Mapped[datetime | None] = mapped_column(nullable=True)

    detections: Mapped[list["Detection"]] = relationship("Detection", back_populates="detector")


# ----------------------------------------------------------------- FT-28: JK moddalari

class LegalArticle(Base):
    """O'zbekiston Jinoyat kodeksi moddasi ma'lumotnomasi. FT-28."""

    __tablename__ = "legal_articles"

    code:     Mapped[str] = mapped_column(Text, primary_key=True)
    chapter:  Mapped[str] = mapped_column(Text, nullable=False)
    title_uz: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    notes:    Mapped[str | None] = mapped_column(Text, nullable=True)

    cases: Mapped[list["Case"]] = relationship("Case", back_populates="legal_article")


# ----------------------------------------------------------------- Ish yuritish

class Case(Base):
    """Kiberjinoyat ishi. FT-38,39."""

    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint("total_risk BETWEEN 0 AND 100", name="chk_total_risk"),
    )

    id:           Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assignee_id:  Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    article_code: Mapped[str | None]      = mapped_column(Text, ForeignKey("legal_articles.code", ondelete="SET NULL"), nullable=True)
    article_conf: Mapped[float | None]    = mapped_column(Float, nullable=True)
    status:       Mapped[CaseStatus]      = mapped_column(String(20), nullable=False, default=CaseStatus.new, server_default="new")
    title:        Mapped[str]             = mapped_column(Text, nullable=False)
    region:       Mapped[str | None]      = mapped_column(Text, nullable=True)
    total_risk:   Mapped[int]             = mapped_column(Integer, nullable=False, default=0, server_default="0")
    opened_at:    Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())
    closed_at:    Mapped[datetime | None] = mapped_column(nullable=True)

    assignee:      Mapped["User | None"]          = relationship("User", back_populates="cases", foreign_keys=[assignee_id])
    legal_article: Mapped["LegalArticle | None"]  = relationship("LegalArticle", back_populates="cases")
    detections:    Mapped[list["Detection"]]      = relationship("Detection", back_populates="case")
    evidence:      Mapped[list["Evidence"]]       = relationship("Evidence", back_populates="case")


class Detection(Base):
    """Aniqlash natijasi. FT-27: explanation (sabablar) majburiy.

    FT-27: har bir aniqlash sababi bo'lishi shart — explanation=[] bo'lmasin.
    """

    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint("event_id", "detector_id", name="uq_detection"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="chk_conf"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="chk_risk"),
    )

    id:          Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id:    Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False)
    detector_id: Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("detectors.id", ondelete="RESTRICT"), nullable=False)
    case_id:     Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    confidence:  Mapped[float]           = mapped_column(Float, nullable=False)
    risk_score:  Mapped[int]             = mapped_column(Integer, nullable=False)
    # FT-27: sabablar ro'yxati — bo'sh bo'lmasligi tavsiya etiladi
    explanation: Mapped[list[Any]]       = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    detected_at: Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())

    event:    Mapped["RawEvent"]    = relationship("RawEvent", back_populates="detections")
    detector: Mapped["Detector"]   = relationship("Detector", back_populates="detections")
    case:     Mapped["Case | None"] = relationship("Case", back_populates="detections")


# ----------------------------------------------------------------- FT-40,41: dalil zanjiri

class Evidence(Base):
    """Raqamli dalil. FT-40,41."""

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("case_id", "sha256", name="uq_evidence_hash"),
    )

    id:            Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id:       Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str]             = mapped_column(Text, nullable=False)
    sha256:        Mapped[str]             = mapped_column(Text, nullable=False)
    storage_path:  Mapped[str]             = mapped_column(Text, nullable=False)
    collected_by:  Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    collected_at:  Mapped[datetime]        = mapped_column(nullable=False, server_default=func.now())

    case:              Mapped["Case"]        = relationship("Case", back_populates="evidence")
    collected_by_user: Mapped["User | None"] = relationship("User", back_populates="evidence", foreign_keys=[collected_by])


# ----------------------------------------------------------------- Dataset belgilash (QM-18,19)

class Label(Base):
    """Annotator belgisi — ML o'qitish uchun. QM-18,19."""

    __tablename__ = "labels"
    __table_args__ = (
        UniqueConstraint("event_id", "user_id", name="uq_label_per_user"),
    )

    id:             Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id:       Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False)
    user_id:        Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    class_label:    Mapped[str]       = mapped_column(Text, nullable=False)
    annotator_conf: Mapped[float]     = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    created_at:     Mapped[datetime]  = mapped_column(nullable=False, server_default=func.now())

    event: Mapped["RawEvent"] = relationship("RawEvent", back_populates="labels")
    user:  Mapped["User"]     = relationship("User", back_populates="labels")


# ----------------------------------------------------------------- FT-45: o'zgartirilmas audit

class AuditLog(Base):
    """Append-only audit jurnali. FT-45.

    DB darajasida UPDATE/DELETE trigger orqali bloklangan.
    """

    __tablename__ = "audit_log"

    id:         Mapped[int]                = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id:    Mapped[uuid.UUID | None]   = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action:     Mapped[str]                = mapped_column(Text, nullable=False)
    object_ref: Mapped[str | None]         = mapped_column(Text, nullable=True)
    ip:         Mapped[str | None]         = mapped_column(INET, nullable=True)
    details:    Mapped[dict[str, Any]]     = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    created_at: Mapped[datetime]           = mapped_column(nullable=False, server_default=func.now())

    user: Mapped["User | None"] = relationship("User", back_populates="audit_logs")
