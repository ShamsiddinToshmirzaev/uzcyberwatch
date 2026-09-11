"""Parol xeshlash va tekshirish. FT-44, HT-03.

HT-03: xom parol hech qachon saqlanmaydi — faqat bcrypt heshi.
"""
from __future__ import annotations

import bcrypt

_ROUNDS = 12


def hash_password(plain: str) -> str:
    """Parolni bcrypt bilan xeshlaydi (72 baytdan uzun parollar qisqartiriladi)."""
    encoded = plain.encode("utf-8")[:72]
    return bcrypt.hashpw(encoded, bcrypt.gensalt(_ROUNDS)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Xom parolni saqlangan xesh bilan taqqoslaydi."""
    encoded = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(encoded, hashed.encode("utf-8"))
