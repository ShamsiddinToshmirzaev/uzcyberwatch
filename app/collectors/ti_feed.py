"""Tahdid ma'lumotlari feed kollektori (TZ: FT-05).

Ochiq manba TI feed'lardan zararli URL va domenlarni yig'adi:
- URLhaus (abuse.ch): faol malware/phishing URL'lar
- OpenPhish: fishing sahifalar ro'yxati
- Feodo Tracker: botnet C2 manzillar

HT-07: faqat passiv o'qish — aktiv skanerlash, exploit yo'q.
Faqat ochiq, ommaviy feed'lar ishlatiladi.

Ishga tushirish:
    python -m app.collectors.ti_feed --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import logging
from datetime import datetime, timezone
from typing import Awaitable, Callable

from app.detect import engine

log = logging.getLogger("ti_feed")


# ----------------------------------------------------------------- Feed parserlari

def _parse_plain_feed(text: str) -> list[str]:
    """Oddiy matn feed: har bir qatorda bir URL (#izoh va bo'sh qatorlar o'tkaziladi)."""
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
    return urls


def _parse_urlhaus_csv(text: str) -> list[str]:
    """URLhaus CSV format: id,dateadded,url,url_status,... — faqat online URL'lar."""
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            reader = csv.reader(io.StringIO(line))
            row = next(reader, None)
            if not row or len(row) < 4:
                continue
            url = row[2].strip()
            status = row[3].strip().lower()
            if status == "online" and url.startswith("http"):
                urls.append(url)
        except Exception:
            continue
    return urls


# ----------------------------------------------------------------- Ochiq feed ro'yxati

FEEDS: list[dict] = [
    {
        "name": "urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "parser": _parse_urlhaus_csv,
        "description": "abuse.ch URLhaus — faol malware/phishing URL'lar (CSV)",
    },
    {
        "name": "openphish",
        "url": "https://openphish.com/feed.txt",
        "parser": _parse_plain_feed,
        "description": "OpenPhish — fishing sahifalar ro'yxati (plain text)",
    },
    {
        "name": "feodotracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "parser": _parse_plain_feed,
        "description": "abuse.ch Feodo Tracker — botnet C2 IP'lar (plain text)",
    },
]


# ================================================================= Kollektori

class TiFeedCollector:
    """TI feed kollektori. FT-05.

    Har `interval` soniyada feedlarni yangilaydi, aniqlash dvigateli
    orqali o'tkazadi va yuqori risklilarni sink ga yuboradi.
    HT-07: faqat passiv o'qish.
    """

    def __init__(
        self,
        sink: Callable[[dict], Awaitable[None]],
        interval: int = 3600,
        min_risk: int = 30,
        feeds: list[dict] | None = None,
    ) -> None:
        self.sink = sink
        self.interval = interval
        self.min_risk = min_risk
        self.feeds = feeds if feeds is not None else FEEDS
        self.seen: set[str] = set()
        self.stats: dict[str, int] = {
            "fetched": 0,
            "emitted": 0,
            "errors": 0,
            "deduped": 0,
        }

    # ---------------------------------------------------------------- dedup

    def _dedup(self, url: str) -> bool:
        """True qaytaradi — yangi URL. False — allaqachon ko'rilgan."""
        h = hashlib.sha256(url.encode()).hexdigest()
        if h in self.seen:
            self.stats["deduped"] += 1
            return False
        self.seen.add(h)
        if len(self.seen) > 500_000:
            self.seen.clear()
        return True

    # ---------------------------------------------------------------- fetch

    async def _fetch_text(self, session, url: str) -> str | None:
        """HTTP GET — xato bo'lsa None qaytaradi."""
        try:
            async with session.get(url, timeout=30) as resp:
                if resp.status == 200:
                    return await resp.text()
                log.warning("feed %s: HTTP %d", url, resp.status)
                return None
        except Exception as exc:
            log.warning("feed xatosi %s: %s", url, exc)
            self.stats["errors"] += 1
            return None

    # ---------------------------------------------------------------- ishlov berish

    async def _process_urls(self, urls: list[str], source_name: str) -> None:
        """URL ro'yxatini aniqlash dvigateli orqali o'tkazadi."""
        for url in urls:
            self.stats["fetched"] += 1

            if not self._dedup(url):
                continue

            try:
                verdict = engine.analyse(url=url, text=url)
            except Exception:
                log.debug("analyse xatosi: %s", url)
                continue

            if verdict.risk_score < self.min_risk:
                continue

            event = {
                "url": url,
                "source_name": source_name,
                "risk_score": verdict.risk_score,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "verdict": verdict.to_dict(),
            }
            await self.sink(event)
            self.stats["emitted"] += 1

    # ---------------------------------------------------------------- bir tsikl

    async def _poll_once(self, session) -> None:
        """Barcha feedlarni bir marta so'raydi."""
        for feed in self.feeds:
            text = await self._fetch_text(session, feed["url"])
            if text is None:
                continue
            urls = feed["parser"](text)
            log.info("feed=%s url_soni=%d", feed["name"], len(urls))
            await self._process_urls(urls, source_name=feed["name"])
        log.info("statistika: %s", self.stats)

    # ---------------------------------------------------------------- asosiy tsikl

    async def run(self) -> None:
        """Doimiy polling tsikli. HT-07: faqat passiv o'qish."""
        import aiohttp
        async with aiohttp.ClientSession(
            headers={"User-Agent": "UzCyberWatch-TI/1.0 (research; passive)"}
        ) as session:
            while True:
                try:
                    await self._poll_once(session)
                except Exception:
                    log.exception("poll xatosi")
                await asyncio.sleep(self.interval)


# -------------------------------------------------------------------- CLI sink

async def _print_sink(event: dict) -> None:
    v = event.get("verdict", {})
    print(
        f"[{event.get('risk_score', 0):3}] "
        f"{event.get('url', '')[:60]}"
        f"  src={event.get('source_name','?')}"
        f"  {v.get('incident_type','')}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="UzCyberWatch TI feed kollektori")
    ap.add_argument("--interval", type=int, default=3600, help="So'rov oralig'i (soniya)")
    ap.add_argument("--min-risk", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true", help="ekranga chiqaradi")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    col = TiFeedCollector(
        sink=_print_sink,
        interval=args.interval,
        min_risk=args.min_risk,
    )
    asyncio.run(col.run())


if __name__ == "__main__":
    main()
