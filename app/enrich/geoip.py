"""GeoIP boyitish moduli. FT-15.

IP manzil → mamlakat, viloyat, ASN.
MaxMind GeoLite2 bazasi ishlatiladi; fayl yo'q bo'lsa — bo'sh natija.
HT-07: faqat passiv, lokal DB — tarmoqqa murojaat yo'q.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
from dataclasses import dataclass

import geoip2.database
import geoip2.errors

CITY_DB = os.environ.get("GEOIP_CITY_DB", "/opt/GeoLite2-City.mmdb")
ASN_DB  = os.environ.get("GEOIP_ASN_DB",  "/opt/GeoLite2-ASN.mmdb")


@dataclass
class GeoResult:
    """GeoIP qidirish natijasi. FT-15."""

    ip:          str
    asn:         str | None = None
    asn_org:     str | None = None
    geo_country: str | None = None
    geo_region:  str | None = None


def _is_public(ip: str) -> bool:
    """IP ommaviy tarmoqqa tegishliligini tekshiradi."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_unspecified)
    except ValueError:
        return False


def _sync_lookup(ip: str) -> GeoResult | None:
    """Sinxron GeoIP qidirish. asyncio.to_thread orqali chaqiriladi."""
    if not _is_public(ip):
        return None

    result = GeoResult(ip=ip)

    try:
        with geoip2.database.Reader(CITY_DB) as reader:
            r = reader.city(ip)
            result.geo_country = r.country.iso_code
            result.geo_region  = r.subdivisions.most_specific.name or None
    except (FileNotFoundError, OSError, geoip2.errors.AddressNotFoundError, Exception):
        pass

    try:
        with geoip2.database.Reader(ASN_DB) as reader:
            r = reader.asn(ip)
            num = r.autonomous_system_number
            result.asn     = f"AS{num}" if num else None
            result.asn_org = r.autonomous_system_organization or None
    except (FileNotFoundError, OSError, geoip2.errors.AddressNotFoundError, Exception):
        pass

    return result


async def async_lookup(ip: str) -> GeoResult | None:
    """Asinxron GeoIP qidirish. FT-15."""
    return await asyncio.to_thread(_sync_lookup, ip)
