"""Shaxsga doir ma'lumotlarni aniqlash, maskalash va heshlash.

TZ: FT-13, HT-02, HT-03.

Tamoyil: xom PII hech qachon bazaga yozilmaydi. Graf tahlili va
deduplikatsiya uchun kalitli HMAC-SHA256 hesh yetarli — bir xil telefon
raqami har doim bir xil heshga tushadi, lekin heshdan raqamni tiklab
bo'lmaydi.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass

_PEPPER = os.environ.get("UCW_PII_PEPPER", "").encode() or b"CHANGE-ME-IN-PRODUCTION"

# O'zbekiston telefon raqami: +998 XX XXX XX XX (turli formatlarda)
RE_PHONE = re.compile(r"(?:\+?998[\s\-()]*)?(?:9[0-9]|33|55|77|88)[\s\-()]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}\b")
# Bank kartasi: 16 raqam (Uzcard 8600/5614, Humo 9860, Visa/MC)
RE_CARD = re.compile(r"\b(?:\d[ \-]?){15,18}\d\b")
# Pasport: AA1234567
RE_PASSPORT = re.compile(r"\b[A-Z]{2}\s?\d{7}\b")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
RE_PINFL = re.compile(r"\b\d{14}\b")


@dataclass
class PiiHit:
    kind: str          # phone | card | passport | email | pinfl
    hash: str
    hint: str          # maskalangan ko'rinish


def pii_hash(kind: str, value: str) -> str:
    norm = re.sub(r"[^A-Za-z0-9]", "", value).upper()
    return hmac.new(_PEPPER, f"{kind}:{norm}".encode(), hashlib.sha256).hexdigest()


def _luhn(digits: str) -> bool:
    s, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def _mask(kind: str, value: str) -> str:
    d = re.sub(r"[^0-9A-Za-z]", "", value)
    if kind == "phone":
        return f"+998 {d[-9:-7]} *** ** {d[-2:]}" if len(d) >= 9 else "***"
    if kind == "card":
        return f"{d[:6]} ****** {d[-4:]}"
    if kind == "email":
        user, _, dom = value.partition("@")
        return f"{user[:2]}***@{dom}"
    if kind == "passport":
        return f"{d[:2]}*****{d[-1:]}"
    return "***"


def scan(text: str) -> list[PiiHit]:
    """Matndagi barcha PII ni topadi."""
    hits: list[PiiHit] = []
    seen: set[str] = set()

    def add(kind: str, raw: str):
        h = pii_hash(kind, raw)
        if h not in seen:
            seen.add(h)
            hits.append(PiiHit(kind, h, _mask(kind, raw)))

    for m in RE_CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 15 <= len(digits) <= 19 and _luhn(digits):
            add("card", m.group())
    for m in RE_PHONE.finditer(text):
        add("phone", m.group())
    for m in RE_PASSPORT.finditer(text):
        add("passport", m.group())
    for m in RE_EMAIL.finditer(text):
        add("email", m.group())
    for m in RE_PINFL.finditer(text):
        add("pinfl", m.group())
    return hits


def redact(text: str) -> str:
    """Matnni bazaga yozishdan oldin PII ni o'rniga token qo'yadi."""
    out = text
    for m in sorted(RE_CARD.finditer(text), key=lambda x: -x.start()):
        digits = re.sub(r"\D", "", m.group())
        if 15 <= len(digits) <= 19 and _luhn(digits):
            out = out[:m.start()] + "[CARD]" + out[m.end():]
    out = RE_PHONE.sub("[PHONE]", out)
    out = RE_PASSPORT.sub("[PASSPORT]", out)
    out = RE_EMAIL.sub("[EMAIL]", out)
    out = RE_PINFL.sub("[PINFL]", out)
    return out
