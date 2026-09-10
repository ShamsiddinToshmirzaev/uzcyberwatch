"""Boyitish pipeline orkestri. FT-20.

Barcha boyitish qadamlarini parallel bajaradi:
GeoIP + WHOIS + SSL cert + pHash + Reputatsiya.
Har bir qadam mustaqil xatoda ham davom etadi.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Any

from app.enrich import geoip, whois_lookup, cert, screenshot, reputation


@dataclass
class EnrichResult:
    """Boyitish pipeline natijasi. FT-20.

    Enrichment jadvaliga to'g'ridan-to'g'ri mapping qilinadi.
    """

    ip:               str | None       = None
    asn:              str | None       = None
    asn_org:          str | None       = None
    geo_country:      str | None       = None
    geo_region:       str | None       = None
    domain_age_days:  int | None       = None
    registrar:        str | None       = None
    cert_issuer:      str | None       = None
    screenshot_phash: str | None       = None
    reputation:       dict[str, Any]   = field(default_factory=dict)


async def _safe(coro) -> Any:
    """Coroutineni xatoliksiz bajaradi — istisno bo'lsa None qaytaradi."""
    try:
        return await coro
    except Exception:
        return None


async def _none() -> None:
    """No-op placeholder uchun bo'sh coroutine."""
    return None


async def _resolve_ip(hostname: str) -> str | None:
    """Hostname ni IP manzilga aylantiradi."""
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


async def enrich(
    url: str | None    = None,
    domain: str | None = None,
) -> EnrichResult:
    """Barcha boyitish qadamlarini parallel bajaradi. FT-20.

    url yoki domain berilishi shart; ikkalasi ham yo'q bo'lsa — bo'sh natija.
    """
    result = EnrichResult()

    # Domen ajratish
    if not domain and url:
        parsed = urlparse(url if "//" in url else f"http://{url}")
        domain = parsed.hostname or ""
    if not domain:
        return result

    # IP aniqlash
    ip = await _resolve_ip(domain)
    if ip:
        result.ip = ip

    # Parallel boyitish qadamlari
    geo_r, whois_r, cert_r, phash_r, rep_url_r, rep_ip_r = await asyncio.gather(
        _safe(asyncio.to_thread(geoip._sync_lookup, ip)   if ip  else _none()),
        _safe(asyncio.to_thread(whois_lookup._sync_lookup, domain)),
        _safe(asyncio.to_thread(cert._sync_get_cert_issuer, domain)),
        _safe(screenshot.compute_phash(url)                if url else _none()),
        _safe(reputation.lookup_url(url)                   if url else _none()),
        _safe(reputation.lookup_ip(ip)                     if ip  else _none()),
    )

    # GeoIP
    if isinstance(geo_r, geoip.GeoResult):
        result.asn         = geo_r.asn
        result.asn_org     = geo_r.asn_org
        result.geo_country = geo_r.geo_country
        result.geo_region  = geo_r.geo_region

    # WHOIS
    if isinstance(whois_r, whois_lookup.WhoisResult):
        result.registrar       = whois_r.registrar
        result.domain_age_days = whois_r.domain_age_days

    # SSL sertifikat
    if isinstance(cert_r, str):
        result.cert_issuer = cert_r

    # pHash
    if isinstance(phash_r, str):
        result.screenshot_phash = phash_r

    # Reputatsiya
    merged: dict[str, Any] = {}
    for r in (rep_url_r, rep_ip_r):
        if isinstance(r, dict):
            merged.update(r)
    result.reputation = merged

    return result
