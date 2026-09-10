"""Reputatsiya boyitish moduli. FT-19.

URL va IP uchun VirusTotal va AbuseIPDB orqali reputatsiya tekshiruvi.
API kalitlari .env dan — kodda hech qachon hardcode qilinmaydi.
HT-07: faqat passiv so'rovlar (GET) — URL submission yo'q.
"""
from __future__ import annotations

import asyncio
import base64
import os
from typing import Any

import httpx

VT_KEY        = os.environ.get("REPUTATION_VT_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")

_TIMEOUT = httpx.Timeout(10.0)
_VT_BASE  = "https://www.virustotal.com/api/v3"
_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


async def lookup_url(url: str) -> dict[str, Any]:
    """URL reputatsiyasini VirusTotal orqali tekshiradi. FT-19."""
    if not VT_KEY:
        return {}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(
                f"{_VT_BASE}/urls/{url_id}",
                headers={"x-apikey": VT_KEY},
            )
            if r.status_code != 200:
                return {}
            attrs  = r.json().get("data", {}).get("attributes", {})
            stats  = attrs.get("last_analysis_stats", {})
            return {
                "vt_malicious":  stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless":   stats.get("harmless", 0),
                "vt_reputation": attrs.get("reputation", 0),
            }
    except Exception:
        return {}


async def lookup_ip(ip: str) -> dict[str, Any]:
    """IP manzil reputatsiyasini VirusTotal va AbuseIPDB orqali tekshiradi. FT-19."""
    tasks: list = []
    if VT_KEY:
        tasks.append(_vt_ip(ip))
    if ABUSEIPDB_KEY:
        tasks.append(_abuseipdb(ip))
    if not tasks:
        return {}

    results = await asyncio.gather(*tasks, return_exceptions=True)
    merged: dict[str, Any] = {}
    for r in results:
        if isinstance(r, dict):
            merged.update(r)
    return merged


async def _vt_ip(ip: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(
                f"{_VT_BASE}/ip_addresses/{ip}",
                headers={"x-apikey": VT_KEY},
            )
            if r.status_code != 200:
                return {}
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "vt_malicious":  stats.get("malicious", 0),
                "vt_reputation": attrs.get("reputation", 0),
            }
    except Exception:
        return {}


async def _abuseipdb(ip: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(
                f"{_ABUSE_BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )
            if r.status_code != 200:
                return {}
            data = r.json().get("data", {})
            return {
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "abuse_reports": data.get("totalReports", 0),
            }
    except Exception:
        return {}
