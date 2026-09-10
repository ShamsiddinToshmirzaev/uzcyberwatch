"""Aniqlangan hodisani Jinoyat kodeksi moddalariga moslashtirish.

TZ: FT-28. Maqsadli ko'rsatkich — QM-08, ≥ 85% to'g'ri moslashtirish.

DIQQAT (HT-05): modul huquqiy qaror qabul qilmaydi, faqat tavsiya beradi.
Yakuniy kvalifikatsiya vakolatli mutaxassis tomonidan tasdiqlanadi.
Moddalar sarlavhalari lex.uz dan tasdiqlanishi shart.
"""
from __future__ import annotations

from dataclasses import dataclass

# (modda kodi, ishonch koeffitsienti, asos)
RULES: dict[str, list[tuple[str, float, str]]] = {
    # fishing resurs: hali zarar yetkazilmagan -> tayyorgarlik
    "phishing_site": [
        ("168", 0.70, "firibgarlik uchun axborot tizimidan foydalanish tayyorgarligi"),
        ("278-1", 0.45, "kompyuter axborotiga kirish uchun rekvizit yig'ish"),
    ],
    # karta mablag'i o'g'irlangan
    "card_theft": [
        ("169", 0.88, "bank plastik kartasi mablag'larini talon-toroj qilish"),
        ("168", 0.60, "aldov yo'li bilan mablag'ni egallash"),
    ],
    # ijtimoiy muhandislik orqali aldov
    "social_engineering": [
        ("168", 0.82, "aldov va ishonchni suiiste'mol qilish"),
    ],
    "malware": [
        ("278-3", 0.85, "zararli dasturlarni tarqatish"),
        ("278-2", 0.50, "tizim ishiga noqonuniy aralashuv"),
    ],
    "unauthorized_access": [
        ("278-1", 0.85, "kompyuter axborotiga qonunga xilof kirish"),
    ],
    "data_leak": [
        ("141", 0.70, "shaxsiy ma'lumotlarni oshkor qilish"),
        ("278-1", 0.55, "ma'lumotlar bazasiga ruxsatsiz kirish"),
    ],
    "extortion": [
        ("165", 0.85, "tovlamachilik"),
    ],
}


@dataclass
class LegalSuggestion:
    article_code: str
    confidence: float
    rationale: str
    requires_review: bool = True


def suggest(incident_type: str, risk_score: int) -> list[LegalSuggestion]:
    """Hodisa turi va risk-ball asosida modda tavsiyalarini qaytaradi."""
    base = RULES.get(incident_type, [])
    if not base:
        return []
    # past risk-ball ishonchni pasaytiradi
    factor = 0.6 + 0.4 * min(risk_score, 100) / 100
    out = [
        LegalSuggestion(code, round(conf * factor, 2), rationale)
        for code, conf, rationale in base
    ]
    return sorted(out, key=lambda s: -s.confidence)


def classify_incident(
    brand_kind: str | None,
    text_rules: list[str],
    has_payload: bool = False,
) -> str:
    """Signallardan hodisa turini aniqlaydi."""
    if has_payload:
        return "malware"
    if "secrecy" in text_rules and "threat" in text_rules:
        return "extortion"
    if brand_kind in ("typosquat", "homoglyph", "subdomain_abuse"):
        return "phishing_site"
    if {"credential_request", "card_request", "card_block"} & set(text_rules):
        return "card_theft"
    if text_rules:
        return "social_engineering"
    return "unknown"
