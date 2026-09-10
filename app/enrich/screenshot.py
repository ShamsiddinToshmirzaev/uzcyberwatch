"""Sahifa rasmi → pHash boyitish moduli. FT-18.

URL sahifasidan og:image yoki birinchi <img> topib, pHash hisoblab qaytaradi.
O'xshash phishing sahifalarni klasterlash uchun ishlatiladi.
HT-07: passiv — faqat GET so'rovlar, aktiv skanerlash yo'q.
"""
from __future__ import annotations

import io
import re
from urllib.parse import urljoin, urlparse

import httpx
import imagehash
from PIL import Image

_TIMEOUT = httpx.Timeout(10.0)
_IMG_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico"})


def _extract_image_url(html: str, base_url: str) -> str | None:
    """HTML dan og:image yoki birinchi <img src> ni ajratib oladi."""
    # og:image — atributlar tartibi ixtiyoriy
    for pattern in (
        r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']',
    ):
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return urljoin(base_url, m.group(1))

    # birinchi <img src>
    m = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        return urljoin(base_url, m.group(1))

    return None


async def _phash_from_response(content: bytes) -> str | None:
    """Bayt qatoridan pHash hisoblaydi."""
    try:
        img = Image.open(io.BytesIO(content))
        return str(imagehash.phash(img))
    except Exception:
        return None


async def compute_phash(url: str) -> str | None:
    """URL sahifasidan rasm topib, pHash hisoblab qaytaradi. FT-18."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        parsed = urlparse(url)
        ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""

        # URL o'zi rasm bo'lsa — to'g'ridan-to'g'ri pHash
        if f".{ext}" in _IMG_EXTS:
            try:
                resp = await client.get(url, headers={"Accept": "image/*"})
                resp.raise_for_status()
                return await _phash_from_response(resp.content)
            except Exception:
                return None

        # HTML sahifadan rasm qidirish
        try:
            resp = await client.get(url, headers={"Accept": "text/html"})
            html = resp.text
        except Exception:
            return None

        img_url = _extract_image_url(html, url)
        if not img_url:
            return None

        try:
            resp = await client.get(img_url, headers={"Accept": "image/*"})
            resp.raise_for_status()
            return await _phash_from_response(resp.content)
        except Exception:
            return None
