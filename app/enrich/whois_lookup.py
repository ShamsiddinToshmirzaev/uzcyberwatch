"""WHOIS/domen yoshi boyitish moduli. FT-16.

Domen → registrar, yaratilgan sana, yoshi (kun).
HT-07: passiv — faqat ommaviy WHOIS serverlari.
"""
from __future__ import annotations

import asyncio
import datetime
from dataclasses import dataclass
from typing import Any

import whois as pywhois


@dataclass
class WhoisResult:
    """WHOIS qidirish natijasi. FT-16."""

    registrar:       str | None = None
    domain_age_days: int | None = None


def _parse_date(val: Any) -> datetime.datetime | None:
    """whois kutubxonasidan kelgan sana qiymatini datetime ga o'giradi."""
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime.datetime):
        return val
    return None


def _sync_lookup(domain: str) -> WhoisResult:
    """Sinxron WHOIS qidirish. asyncio.to_thread orqali chaqiriladi."""
    try:
        w = pywhois.whois(domain)

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        creation_date = _parse_date(w.creation_date)
        domain_age_days = None
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
            delta = datetime.datetime.now(datetime.timezone.utc) - creation_date
            domain_age_days = max(0, delta.days)

        return WhoisResult(registrar=registrar, domain_age_days=domain_age_days)
    except Exception:
        return WhoisResult()


async def lookup(domain: str) -> WhoisResult:
    """Asinxron WHOIS qidirish. FT-16."""
    return await asyncio.to_thread(_sync_lookup, domain)
