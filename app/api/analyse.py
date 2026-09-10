"""Tahlil endpoint. FT-21..28.

Hodisani qabul qilib, aniqlash dvigateli orqali o'tkazadi va
strukturalangan natija qaytaradi. DB ga yozmaydi — faqat tahlil.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.detect import engine
from app.api.schemas import AnalyseRequest, AnalyseResponse, LegalSuggestionOut

router = APIRouter(prefix="/analyse", tags=["analyse"])


@router.post(
    "",
    response_model=AnalyseResponse,
    summary="URL/matn tahlili",
    description=(
        "URL yoki matnni firibgarlik belgilari uchun tekshiradi. "
        "FT-27: sabablar ro'yxati (explainability) majburiy. "
        "HT-03: PII faqat hash+hint ko'rinishida qaytariladi."
    ),
)
async def analyse(req: AnalyseRequest) -> AnalyseResponse:
    """Hodisani gibrid dvigateli orqali tahlil qiladi."""
    verdict = engine.analyse(
        url=req.url,
        text=req.text,
        domain_age_days=req.domain_age_days,
        ml_score=req.ml_score,
        has_payload=req.has_payload,
    )

    # HT-05: legal.requires_review doim True saqlanishi shart
    legal_out = [
        LegalSuggestionOut(
            article_code=s["article_code"],
            confidence=s["confidence"],
            rationale=s["rationale"],
            requires_review=True,
        )
        for s in verdict.legal
    ]

    return AnalyseResponse(
        risk_score=verdict.risk_score,
        incident_type=verdict.incident_type,
        confidence=verdict.confidence,
        reasons=[
            {"layer": r.layer, "code": r.code, "weight": r.weight, "detail": r.detail}
            for r in verdict.reasons
        ],
        legal=legal_out,
        pii_found=verdict.pii_found,
        lang=verdict.lang,
    )
