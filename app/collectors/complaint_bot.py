"""Telegram shikoyat bot kollektori. TZ: FT-04.

Fuqarolar firibgarlik havolalari va xabarlarini botga yuboradi.
Bot ularni aniqlash dvigateli orqali o'tkazib, bazaga yozadi va
foydalanuvchiga qisqacha baholash qaytaradi.

Ishga tushirish:
    TELEGRAM_BOT_TOKEN=<token> python -m app.collectors.complaint_bot

Arxitektura:
    Foydalanuvchi → PTB Application → _handle_message()
        → pii.redact() [HT-03]
        → engine.analyse()
        → sink() [bazaga]
        → reply_text() [foydalanuvchiga]

HT-03: Telegram user_id va xom PII bazaga yozilmaydi; faqat HMAC-hesh.
HT-07: Bot faqat passiv qabul qiluvchi — aktiv skanerlash yo'q.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac as _hmac
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlparse

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from app.detect import engine
from app.detect.engine import Verdict
from app.normalize import pii

log = logging.getLogger("complaint_bot")

# Foydalanuvchi identifikatorini anonimlashtirishda ishlatiladigan "tuz"
_ID_PEPPER = os.environ.get("UCW_PII_PEPPER", "CHANGE-ME").encode()

# URL aniqlovchi regex (faqat protokol bilan yoki taniqli domenlar)
_URL_RE = re.compile(
    r"https?://[^\s,;\"'<>\[\]()]+"
    r"|(?:www\.)[^\s,;\"'<>\[\]()]+"
    r"|(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"(?:uz|ru|com|net|org|info|xyz|site|online|top|tk|ml|ga|cf|gq|click|buzz)[^\s,;\"'<>\[\]()]*",
    re.IGNORECASE,
)

_RATE_WINDOW = 60        # soniya
_RATE_LIMIT  = 5         # xabar / daqiqa
_MAX_TEXT    = 4000       # belgi — Telegram xabar uzunligi chekovi


# ----------------------------------------------------------------- yordamchi funksiyalar

def _extract_url(text: str) -> str | None:
    """Matndan birinchi URL ni ajratib oladi."""
    m = _URL_RE.search(text)
    return m.group() if m else None


def _user_hash(user_id: int) -> str:
    """Telegram user_id ni HMAC-SHA256 bilan anonimlaydi. HT-03."""
    return _hmac.new(_ID_PEPPER, f"tg:{user_id}".encode(), hashlib.sha256).hexdigest()


def _build_event(
    url: str | None,
    redacted_text: str,
    verdict: Verdict,
    user_id: int,
) -> dict:
    """Normallashtirish navbati uchun event dict quradi.

    HT-03: user_id xom holda saqlanmaydi — faqat HMAC-hesh.
    """
    domain: str | None = None
    if url:
        try:
            parsed = urlparse(url if "//" in url else f"http://{url}")
            domain = parsed.hostname or None
        except Exception:
            pass

    return {
        "source_kind": "complaint",
        "event_type":  "url" if url else "message",
        "content":     redacted_text,
        "url":         url,
        "domain":      domain,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "ecs":         {"user_hash": _user_hash(user_id)},
        "verdict":     verdict.to_dict(),
    }


def _format_reply(verdict: Verdict) -> str:
    """Foydalanuvchiga yuboriluvchi baholash xabari (o'zbek tilida)."""
    r = verdict.risk_score
    if r >= 70:
        prefix = f"⚠️ XAVFLI! Risk: {r}/100"
        body   = "Bu havola yoki xabar firibgarlik bo'lishi ehtimoli yuqori."
        advice = "Hech qanday ma'lumot kiritmang va boshqalarga yubormang."
    elif r >= 35:
        prefix = f"🔶 Ehtiyot bo'ling! Risk: {r}/100"
        body   = "Shubhali belgilar aniqlandi."
        advice = "Bu havolani ochmang yoki ma'lumotlaringizni kiritmang."
    else:
        prefix = f"✅ Risk: {r}/100"
        body   = "Jiddiy xavf belgilari aniqlanmadi."
        advice = "Baribir ehtiyot bo'ling va shaxsiy ma'lumotlarni begonalarga bermang."

    return f"{prefix}\n{body}\n{advice}"


# ----------------------------------------------------------------- bot sinfi

class ComplaintBot:
    """Fuqarolar shikoyat boti. FT-04."""

    def __init__(
        self,
        token: str,
        sink:  Callable[[dict], Awaitable[None]],
        min_risk: int = 20,
    ) -> None:
        self.token    = token
        self.sink     = sink
        self.min_risk = min_risk
        self._rate:  dict[int, list[float]] = {}
        self.stats = {
            "received":  0,
            "processed": 0,
            "stored":    0,
            "errors":    0,
        }

    # ---------------------------------------------------------------- rate limiter

    async def _check_rate(self, user_id: int) -> bool:
        """True → xabar qabul qilinadi; False → limit oshgan."""
        now = time.monotonic()
        ts  = [t for t in self._rate.get(user_id, []) if now - t < _RATE_WINDOW]
        if len(ts) >= _RATE_LIMIT:
            self._rate[user_id] = ts
            return False
        ts.append(now)
        self._rate[user_id] = ts
        return True

    # ---------------------------------------------------------------- handler-lar

    async def _handle_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """FT-04: /start buyrug'i — xush kelibsiz xabari."""
        await update.message.reply_text(
            "Salom! Men UzCyberWatch shikoyat botiman.\n\n"
            "Shubhali havola yoki firibgarlik xabarini menga yuboring — "
            "men uni avtomatik tekshirib, xavf darajasini bildirarman.\n\n"
            "Yordam uchun: /yordam\n"
            "Shikoyat qilish: /shikoyat yoki to'g'ridan-to'g'ri yuboring."
        )

    async def _handle_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """FT-04: /yordam buyrug'i."""
        await update.message.reply_text(
            "📋 Foydalanish yo'riqnomasi:\n\n"
            "1. Shubhali havola yoki xabarni to'g'ridan-to'g'ri yuboring.\n"
            "2. Bot xavf darajasini (0–100) va tavsiyani qaytaradi.\n"
            "3. Yuqori xavfli holatlar tekshiruvchilarga yuboriladi.\n\n"
            "⚠️ Eslatma: shaxsiy ma'lumotlaringizni (parol, karta raqami) "
            "hech qachon botga yubormang.\n\n"
            "Buyruqlar:\n"
            "/start — boshlash\n"
            "/shikoyat — shikoyat yuborish\n"
            "/yordam — ushbu yordam xabari"
        )

    async def _handle_shikoyat(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """/shikoyat buyrug'i — foydalanuvchini yo'naltiradi."""
        await update.message.reply_text(
            "Shubhali havola yoki xabarni menga yuboring.\n"
            "Masalan: https://kapitalbnk-uz.com yoki firibgarlik SMS matni."
        )

    async def _handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Asosiy handler: matnni tahlil qilib, natija qaytaradi. FT-04."""
        text    = (update.message.text or "").strip()
        user_id = update.effective_user.id

        if not text:
            return

        # Rate limiter
        if not await self._check_rate(user_id):
            await update.message.reply_text(
                "Iltimos, bir daqiqa kuting. Xabarlar soni cheklangan."
            )
            return

        self.stats["received"] += 1

        # Uzun xabarni qisqartirish
        if len(text) > _MAX_TEXT:
            text = text[:_MAX_TEXT]

        # PII maskalash (HT-03): xom PII bazaga yozilmaydi
        redacted = pii.redact(text)

        # URL qidirish
        url = _extract_url(text)

        # Tahlil
        try:
            verdict = engine.analyse(url=url, text=redacted)
            self.stats["processed"] += 1
        except Exception:
            log.exception("engine.analyse xatosi")
            self.stats["errors"] += 1
            await update.message.reply_text(
                "Kechirasiz, tahlil vaqtida xato yuz berdi. Iltimos qayta urinib ko'ring."
            )
            return

        # Yuqori xavfli hodisalarni saqlab qolish
        if verdict.risk_score >= self.min_risk:
            event = _build_event(url, redacted, verdict, user_id)
            try:
                await self.sink(event)
                self.stats["stored"] += 1
            except Exception:
                log.exception("sink xatosi")

        # Foydalanuvchiga javob
        await update.message.reply_text(_format_reply(verdict))

    # ---------------------------------------------------------------- ilova qurish

    def build_application(self) -> Application:
        """PTB Application obyektini handler-lar bilan qurib qaytaradi."""
        app = Application.builder().token(self.token).build()
        app.add_handler(CommandHandler("start",    self._handle_start))
        app.add_handler(CommandHandler("yordam",   self._handle_help))
        app.add_handler(CommandHandler("help",     self._handle_help))
        app.add_handler(CommandHandler("shikoyat", self._handle_shikoyat))
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message)
        )
        return app

    async def run(self) -> None:
        """Botni polling rejimida ishga tushiradi. FT-04."""
        app = self.build_application()
        log.info("Shikoyat bot ishga tushdi (polling)")
        await app.run_polling(drop_pending_updates=True)


# -------------------------------------------------------------------- CLI

async def _print_sink(event: dict) -> None:
    v = event["verdict"]
    print(
        f"[{v['risk_score']:3}] {event.get('url') or event['event_type']:50} "
        f"{v['incident_type']}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="UzCyberWatch Telegram shikoyat boti")
    ap.add_argument("--min-risk", type=int, default=20, help="Minimal saqlash chegarasi")
    ap.add_argument("--dry-run",  action="store_true", help="Bazaga yozmasdan chiqaradi")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        ap.error("TELEGRAM_BOT_TOKEN muhit o'zgaruvchisi o'rnatilmagan")

    sink = _print_sink if args.dry_run else _print_sink  # prod da DB sink
    bot  = ComplaintBot(token=token, sink=sink, min_risk=args.min_risk)
    asyncio.run(bot.run())


if __name__ == "__main__":
    main()
