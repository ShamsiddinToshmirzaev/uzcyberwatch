"""JWT token yaratish va tekshirish. FT-44.

Tokenlar HS256 algoritmi bilan imzolanadi.
Muddati: UCW_JWT_EXPIRE_MIN (sukut: 60 daqiqa).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

_SECRET: str = os.environ.get("UCW_JWT_SECRET", "change-me-in-production-32bytes!")
_ALGORITHM: str = "HS256"
_EXPIRE_MINUTES: int = int(os.environ.get("UCW_JWT_EXPIRE_MIN", "60"))


def create_access_token(subject: str) -> str:
    """Foydalanuvchi uchun JWT kirish tokeni yaratadi."""
    exp = datetime.now(timezone.utc) + timedelta(minutes=_EXPIRE_MINUTES)
    return jwt.encode({"sub": subject, "exp": exp}, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> str:
    """Tokenni tekshiradi va sub (username) ni qaytaradi.

    Muddati o'tgan yoki noto'g'ri token uchun JWTError ko'taradi.
    """
    payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    sub: str | None = payload.get("sub")
    if sub is None:
        raise JWTError("sub maydoni yo'q")
    return sub
