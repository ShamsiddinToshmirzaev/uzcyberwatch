"""Certificate Transparency log kollektori (TZ: FT-01, FT-08, FT-09).

CT loglari yangi ro'yxatdan o'tgan fishing domenlarini eng erta ko'radigan
manba: sertifikat olinishi bilan domen ochiq jurnalga tushadi. MTTD ≤ 5
daqiqa (QM-09) talabi aynan shu manba hisobiga bajariladi.

Ishlash rejimi:
  * `certstream` WebSocket oqimiga ulanadi (real vaqt);
  * har bir sertifikatdagi domenlarni brendlar prefiltri orqali o'tkazadi;
  * mos kelganlarini normalizatsiya navbatiga uzatadi.

Ishga tushirish:
    python -m app.collectors.ct_log --dry-run       # ekranga chiqaradi
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Awaitable, Callable

from app.detect import brands, engine

log = logging.getLogger("ct_log")

CERTSTREAM_URL = "wss://certstream.calidog.io/"


class CtLogCollector:
    def __init__(self, sink: Callable[[dict], Awaitable[None]],
                 min_risk: int = 30, url: str = CERTSTREAM_URL):
        self.sink = sink
        self.min_risk = min_risk
        self.url = url
        self.prefilter = brands.ct_log_prefilter()
        self.seen: set[str] = set()
        self.stats = {"certs": 0, "domains": 0, "prefiltered": 0, "emitted": 0}

    # ---------------------------------------------------------------- filtr
    def _prefilter(self, domain: str) -> bool:
        """Arzon filtr: to'liq tahlildan oldin oqimni ~99% ga qisqartiradi."""
        skel = brands.skeletonize(domain)
        if not skel:
            return False
        if any(k in skel for k in self.prefilter):
            return True
        return bool(brands.lure_hits(domain))

    def _dedup(self, domain: str) -> bool:
        h = hashlib.sha256(domain.encode()).hexdigest()
        if h in self.seen:
            return False
        self.seen.add(h)
        if len(self.seen) > 500_000:          # xotira cheklovi
            self.seen.clear()
        return True

    # ---------------------------------------------------------------- ishlov
    async def handle_cert(self, message: dict) -> None:
        if message.get("message_type") != "certificate_update":
            return
        data = message.get("data", {})
        leaf = data.get("leaf_cert", {})
        domains = leaf.get("all_domains") or []
        seen_at = data.get("seen") or datetime.now(timezone.utc).timestamp()

        self.stats["certs"] += 1
        for raw in domains:
            domain = raw.lstrip("*.").lower().strip()
            self.stats["domains"] += 1
            if not domain or not self._prefilter(domain) or not self._dedup(domain):
                continue
            self.stats["prefiltered"] += 1

            verdict = engine.analyse(url=f"https://{domain}/", domain_age_days=0)
            if verdict.risk_score < self.min_risk:
                continue
            self.stats["emitted"] += 1

            await self.sink({
                "source_kind": "ct_log",
                "event_type": "domain",
                "domain": domain,
                "url": f"https://{domain}/",
                "observed_at": datetime.fromtimestamp(seen_at, timezone.utc).isoformat(),
                "cert_issuer": (leaf.get("issuer") or {}).get("O"),
                "not_before": leaf.get("not_before"),
                "verdict": verdict.to_dict(),
            })

    async def run(self) -> None:
        import websockets                       # talab: websockets>=12

        backoff = 1
        while True:
            try:
                async with websockets.connect(self.url, ping_interval=20) as ws:
                    log.info("certstream ulandi: %s", self.url)
                    backoff = 1
                    async for raw in ws:
                        try:
                            await self.handle_cert(json.loads(raw))
                        except Exception:
                            log.exception("sertifikatga ishlov berishda xato")
            except Exception as exc:            # FT-08: qayta urinish
                log.warning("uzilish: %s — %s soniyadan keyin qayta ulanish", exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)


# -------------------------------------------------------------------- CLI
async def _print_sink(event: dict) -> None:
    v = event["verdict"]
    print(f"[{v['risk_score']:3}] {event['domain']:45} {v['incident_type']}")
    for r in v["reasons"][:2]:
        print(f"        {r['code']:24} +{r['weight']:2}  {r['detail'][:60]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-risk", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true", help="ekranga chiqaradi, bazaga yozmaydi")
    ap.add_argument("--replay", type=str, help="JSONL fayldan o'qish (test uchun)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    collector = CtLogCollector(_print_sink, min_risk=args.min_risk)

    if args.replay:
        async def replay():
            with open(args.replay, encoding="utf-8") as f:
                for line in f:
                    await collector.handle_cert(json.loads(line))
            print(f"\nStatistika: {collector.stats}")
        asyncio.run(replay())
        return

    asyncio.run(collector.run())


if __name__ == "__main__":
    main()
