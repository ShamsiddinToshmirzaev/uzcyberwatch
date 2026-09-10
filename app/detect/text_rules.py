"""O'zbek va rus tilidagi ijtimoiy-muhandislik matnlarini aniqlash qoidalari.

TZ: FT-21, FT-24 (baseline). ML modeli o'qitilgunga qadar tizim shu
qoidalar bilan ishlaydi; keyinchalik qoidalar model uchun zaif belgilar
(weak labels) manbai bo'lib xizmat qiladi.

Matn bu yerga normalize.lang.normalize_text() dan keyin, lotin yozuvida
tushadi.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Har bir naqsh: (nom, regex, og'irlik, izoh)
#
# DIQQAT: o'zbek tili agglyutinativ — "kod-ni", "karta-ngiz", "soat-da".
# Shuning uchun naqshlar so'z oxirida \b ishlatmaydi, faqat boshida.
# Aks holda "SMS kodni" iborasi "sms\s*kod\b" bilan mos kelmaydi.
PATTERNS: list[tuple[str, str, int, str]] = [
    ("urgency",
     r"\b(shoshilinch|zudlik|tezda|hoziroq|\d{1,2}\s*soat|bugun\b|srochno|nemedlenno|urgent)",
     12, "sun'iy shoshilinchlik"),
    ("card_block",
     r"\b(kart\w*\s+(bloklan|to'xtat|yopil|muzlat)|schet\w*\s+zablokir|blokirovk\w*\s+kart)",
     22, "karta bloklanishi haqida qo'rqitish"),
    ("credential_request",
     r"\b(parol\w*|maxfiy\s*kod\w*|sms\s*kod\w*|kod\w*\s+(yubor|kirit|ayt|jo'nat)|cvv|cvc|kod\s+iz\s+sms)",
     30, "maxfiy ma'lumot so'ralmoqda"),
    ("card_request",
     r"\b(kart\w*\s*(raqam|nomer)|nomer\s+kart\w*|kart\w*\s+(yubor|jo'nat|kirit)|rekvizit)",
     22, "karta rekvizitlari so'ralmoqda"),
    ("prize",
     r"\b(yutuq\w*|yutdingiz|sovrin\w*|sovg'a\w*|bonus\w*|aksiy\w*|viigral|podarok|priz\b)",
     18, "yutuq/sovg'a vasvasasi"),
    ("easy_money",
     r"\b(oson\s+pul|kunlik\s+daromad|investitsiy\w*|foyda\s+kafolat|100\s*%?\s*foyda|zarabotok|dohod)",
     18, "oson daromad va'dasi"),
    ("impersonation",
     r"\b(bank\s+xodim\w*|xavfsizlik\s+xizmat\w*|markaziy\s+bank|soliq\s+idora\w*|\biiv\b|politsiy\w*|sluzhb\w*\s+bezopasnosti)",
     20, "rasmiy organ nomidan murojaat"),
    ("threat",
     r"\b(jarim\w*|sudga|jinoyat\s+ish\w*|hibsga|shtraf\w*|ugolovn\w*|blokirue)",
     15, "huquqiy oqibat bilan qo'rqitish"),
    ("link_lure",
     r"(bit\.ly|tinyurl|t\.me/\+|clck\.ru|is\.gd|cutt\.ly|havola\w*\s+(o'ting|bosing|kiring)|ssilk\w*)",
     16, "qisqartirilgan/shubhali havola"),
    ("secrecy",
     r"\b(hech\s+kimga\s+(aytma|ayting)|maxfiy\s+saqla|nikomu\s+ne\s+govori)",
     20, "sir saqlashga undash"),
]

_COMPILED = [(n, re.compile(p, re.I | re.U), w, d) for n, p, w, d in PATTERNS]


@dataclass
class TextHit:
    rule: str
    weight: int
    description: str
    snippet: str


def scan_text(normalized_text: str) -> list[TextHit]:
    hits = []
    for name, rx, weight, desc in _COMPILED:
        m = rx.search(normalized_text)
        if m:
            hits.append(TextHit(name, weight, desc, m.group()[:40]))
    return hits


def text_score(hits: list[TextHit]) -> int:
    """Qoidalar og'irligini 0-100 oralig'iga to'playdi (to'yinish bilan)."""
    if not hits:
        return 0
    total = sum(h.weight for h in hits)
    # ikkinchi va keyingi qoidalar kamayuvchi hissa qo'shadi
    return min(100, int(total * (1 - 0.05 * max(0, len(hits) - 1))))
