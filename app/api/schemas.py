"""Pydantic sxemalari — API request/response shablonlari.

FT-46: FastAPI uchun kirish va chiqish ma'lumot modellari.
HT-03: PII faqat hash va hint ko'rinishida — xom qiymat hech qachon javobda bo'lmaydi.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.models import CaseStatus, UserRole


# ================================================================= /analyse

class AnalyseRequest(BaseModel):
    """Tahlil so'rovi. FT-21..27."""

    url:            str | None   = Field(None, description="Tekshirilayotgan URL")
    text:           str | None   = Field(None, description="Tekshirilayotgan matn (o'zbek/rus)")
    domain_age_days: int | None  = Field(None, ge=0, description="Domen yoshi (kun)")
    ml_score:       float | None = Field(None, ge=0.0, le=1.0, description="ML model ehtimolligi")
    has_payload:    bool         = Field(False, description="Zararli fayl mavjudmi")

    @model_validator(mode="after")
    def _require_url_or_text(self) -> "AnalyseRequest":
        if not (self.url or self.text):
            raise ValueError("url yoki text maydonlaridan biri bo'lishi shart")
        if self.url is not None and self.url.strip() == "":
            raise ValueError("url bo'sh bo'lishi mumkin emas")
        if self.text is not None and self.text.strip() == "":
            raise ValueError("text bo'sh bo'lishi mumkin emas")
        return self


class ReasonOut(BaseModel):
    """Aniqlash sababi. FT-27: explainability majburiy."""

    layer:  str
    code:   str
    weight: int
    detail: str


class PiiFoundItem(BaseModel):
    """HT-03: faqat hash va maskalangan hint — xom qiymat yo'q."""

    kind: str
    hash: str
    hint: str


class LegalSuggestionOut(BaseModel):
    """JK moddasi tavsiyasi. HT-05: requires_review doim True."""

    article_code:   str
    confidence:     float
    rationale:      str
    requires_review: bool = True


class AnalyseResponse(BaseModel):
    """Tahlil natijasi. FT-27, HT-03, HT-05."""

    risk_score:    int
    incident_type: str
    confidence:    float
    reasons:       list[ReasonOut]
    legal:         list[LegalSuggestionOut]
    pii_found:     list[PiiFoundItem]
    lang:          str | None


# ================================================================= /cases

class CaseCreate(BaseModel):
    """Yangi ish yaratish. FT-38."""

    title:       str               = Field(..., min_length=3, max_length=500)
    region:      str | None        = None
    assignee_id: uuid.UUID | None  = None


class CasePatch(BaseModel):
    """Ish holatini yangilash. FT-39."""

    status:       CaseStatus | None = None
    assignee_id:  uuid.UUID | None  = None
    article_code: str | None        = None
    article_conf: float | None      = Field(None, ge=0.0, le=1.0)
    region:       str | None        = None
    total_risk:   int | None        = Field(None, ge=0, le=100)


class CaseOut(BaseModel):
    """Ish ma'lumotlari. FT-38,39."""

    id:           uuid.UUID
    title:        str
    status:       CaseStatus
    region:       str | None
    total_risk:   int
    opened_at:    datetime
    closed_at:    datetime | None
    assignee_id:  uuid.UUID | None
    article_code: str | None
    article_conf: float | None

    model_config = {"from_attributes": True}


# ================================================================= /auth

class LoginRequest(BaseModel):
    """Login so'rovi. FT-44."""

    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class TokenOut(BaseModel):
    """JWT token javobi. FT-44."""

    access_token: str
    token_type:   str = "bearer"


# ================================================================= /users

class UserCreate(BaseModel):
    """Yangi foydalanuvchi yaratish. FT-43.

    HT-03: parol faqat hash sifatida saqlanadi.
    """

    username: str      = Field(..., min_length=3, max_length=64)
    password: str      = Field(..., min_length=6)
    role:     UserRole = UserRole.analyst


class UserOut(BaseModel):
    """Foydalanuvchi javobi. HT-03: password_hash yo'q."""

    id:         uuid.UUID
    username:   str
    role:       UserRole
    is_active:  bool
    created_at: datetime

    model_config = {"from_attributes": True}
