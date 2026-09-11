"""Passiv HTTP honeypot kollektori (TZ: FT-03).

Kiruvchi ulanishlarni qayd etadi va aniqlash dvigateliga yuboradi.

HT-03: xom IP manzil bazaga yozilmaydi — faqat HMAC-hesh va masked hint.
HT-07: faqat passiv qabul qiluvchi — aktiv skanerlash, exploit yo'q.

Ishga tushirish:
    python -m app.collectors.honeypot --port 8088 --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Awaitable, Callable

from app.detect import engine

log = logging.getLogger("honeypot")

# IP hash uchun HMAC kalit — .env dan o'qiladi
_HMAC_KEY: bytes = os.environ.get("UCW_PII_KEY", "change-me-pii-key").encode()

# Honeypot uchun qiziqarli yo'llar naqshlari (kuzatuv uchun)
_INTERESTING: list[str] = [
    "/admin", "/wp-login", "/wp-admin", "/phpmyadmin", "/.env",
    "/config", "/shell", "/cmd", "/cgi-bin", "/backup", "/db",
    "/api/v1/admin", "/.git", "/xmlrpc", "/login", "/panel",
    "/manager", "/console", "/actuator", "/solr", "/jenkins",
]


# ----------------------------------------------------------------- IP yordamchilari

def _hash_ip(ip: str) -> str:
    """HT-03: IP HMAC-SHA256 heshi — xom qiymat saqlanmaydi."""
    return hmac.new(_HMAC_KEY, ip.encode(), hashlib.sha256).hexdigest()


def _mask_ip(ip: str) -> str:
    """IP ning faqat birinchi ikki oktetini ko'rsatadi (IPv4 va IPv6)."""
    if ":" in ip:                           # IPv6
        parts = ip.split(":")
        return ":".join(parts[:2]) + ":*:*"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "*"


# ================================================================= Server

class HoneypotServer:
    """Passiv HTTP honeypot. FT-03.

    Kiruvchi HTTP so'rovlarni qayd etadi, risk baholaydi va sink ga yuboradi.
    Hech qanday aktiv hujum yoki javob yuborilmaydi (HT-07).
    """

    def __init__(
        self,
        sink: Callable[[dict], Awaitable[None]],
        port: int = 8088,
        min_risk: int = 20,
    ) -> None:
        self.sink = sink
        self.port = port
        self.min_risk = min_risk
        self.seen: set[str] = set()
        self.stats: dict[str, int] = {
            "connections": 0,
            "interesting": 0,
            "emitted": 0,
            "deduped": 0,
        }

    # ---------------------------------------------------------------- filtr

    def _is_interesting(self, path: str) -> bool:
        """Yo'l qiziqarlimi — kuzatishga arziydi."""
        low = path.lower()
        return any(kw in low for kw in _INTERESTING)

    def _dedup_key(self, ip: str, path: str) -> str:
        return hashlib.sha256(f"{ip}:{path}".encode()).hexdigest()

    # ---------------------------------------------------------------- ishlov berish

    async def handle_request(self, req: dict) -> None:
        """Bitta kiruvchi so'rovni qayd etadi. HT-03, HT-07."""
        self.stats["connections"] += 1

        ip: str = req.get("remote_ip", "0.0.0.0")
        path: str = req.get("path", "/")
        method: str = req.get("method", "GET")

        # Qiziqarli yo'l emas → o'tkazib yuboramiz
        if not self._is_interesting(path):
            return

        self.stats["interesting"] += 1

        # Deduplication
        key = self._dedup_key(ip, path)
        if key in self.seen:
            self.stats["deduped"] += 1
            return
        self.seen.add(key)
        if len(self.seen) > 200_000:
            self.seen.clear()

        # Risk baholash
        url = f"http://honeypot{path}"
        try:
            verdict = engine.analyse(url=url, text=path)
        except Exception:
            log.exception("analyse xatosi: %s", path)
            return

        if verdict.risk_score < self.min_risk:
            return

        # HT-03: xom IP emit qilinmaydi
        event = {
            "ip_hash": _hash_ip(ip),
            "ip_hint": _mask_ip(ip),
            "method": method,
            "path": path,
            "user_agent": req.get("user_agent", ""),
            "risk_score": verdict.risk_score,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict.to_dict(),
        }

        await self.sink(event)
        self.stats["emitted"] += 1

    # ---------------------------------------------------------------- asyncio server

    async def _handle_conn(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
        """Asyncio TCP ulanishini minimal HTTP protokol bilan qabul qiladi."""
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            lines = raw.decode(errors="replace").split("\r\n")
            first = lines[0].split() if lines else []
            method = first[0] if len(first) > 0 else "GET"
            path = first[1] if len(first) > 1 else "/"
            ua = next(
                (l.split(":", 1)[1].strip() for l in lines
                 if l.lower().startswith("user-agent:")), ""
            )
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else "0.0.0.0"

            # Minimal 200 OK javob (honeypot ro'yxatga oladi, ammo ma'lumot bermaydi)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()

            await self.handle_request({
                "method": method, "path": path,
                "remote_ip": ip, "user_agent": ua,
                "headers": {}, "body_size": 0,
            })
        except Exception:
            log.debug("ulanish xatosi", exc_info=True)
        finally:
            writer.close()

    async def run(self) -> None:
        """Honeypot serverini ishga tushiradi."""
        server = await asyncio.start_server(
            self._handle_conn, "0.0.0.0", self.port
        )
        log.info("Honeypot tayyor: port=%d min_risk=%d", self.port, self.min_risk)
        async with server:
            await server.serve_forever()


# -------------------------------------------------------------------- CLI sink

async def _print_sink(event: dict) -> None:
    print(
        f"[{event.get('risk_score', 0):3}] "
        f"{event.get('method','GET'):4} {event.get('path','/')[:50]}"
        f"  ip={event.get('ip_hint','?')} "
        f"  {event.get('observed_at','')[:19]}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="UzCyberWatch passiv honeypot")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--min-risk", type=int, default=20)
    ap.add_argument("--dry-run", action="store_true", help="ekranga chiqaradi")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    srv = HoneypotServer(
        sink=_print_sink,
        port=args.port,
        min_risk=args.min_risk,
    )
    asyncio.run(srv.run())


if __name__ == "__main__":
    main()
