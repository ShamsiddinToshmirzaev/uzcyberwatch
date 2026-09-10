"""Telegram shikoyat bot sinovlari (TZ: FT-04, NFT-11).

Barcha PTB va tashqi chaqiruvlar mock qilinadi — haqiqiy bot tokeni shart emas.
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from app.collectors.complaint_bot import (
    ComplaintBot,
    _build_event,
    _extract_url,
    _format_reply,
)
from app.detect.engine import Verdict


# ----------------------------------------------------------------- yordamchi

def _run(coro):
    return asyncio.run(coro)


def _make_verdict(risk: int = 40, incident: str = "phishing_site") -> Verdict:
    from app.detect.engine import Reason
    return Verdict(
        risk_score=risk,
        incident_type=incident,
        confidence=0.70,
        reasons=[Reason("rule", "brand_typosquat", risk, "typosquat aniqlandi")],
        legal=[],
        pii_found=[],
        lang="uz",
    )


def _make_update(text: str = "test", user_id: int = 111) -> MagicMock:
    upd = MagicMock()
    upd.effective_user.id = user_id
    upd.message.text = text
    upd.message.reply_text = AsyncMock()
    upd.message.chat_id = user_id
    return upd


def _ctx() -> MagicMock:
    return MagicMock()


# ================================================================= URL ajratish

class TestExtractUrl:
    def test_https_url_found(self):
        assert _extract_url("Bu havolani tekshiring: https://click-uz.net/login") == "https://click-uz.net/login"

    def test_http_url_found(self):
        assert _extract_url("http://payme-kirish.com xavfli") == "http://payme-kirish.com"

    def test_no_url_returns_none(self):
        assert _extract_url("Oddiy matn, hech qanday havola yo'q") is None

    def test_empty_string_returns_none(self):
        assert _extract_url("") is None

    def test_url_in_middle(self):
        url = _extract_url("Mana link: https://kapitalbnk.uz va boshqa so'zlar")
        assert url == "https://kapitalbnk.uz"

    def test_bare_domain_detected(self):
        url = _extract_url("kapitalbnk.uz saytiga kirmang")
        assert url is not None
        assert "kapitalbnk.uz" in url


# ================================================================= Javob formati

class TestFormatReply:
    def test_high_risk_urgent_message(self):
        v = _make_verdict(risk=80)
        reply = _format_reply(v)
        assert "XAVFLI" in reply or "xavfli" in reply.lower()
        assert "80" in reply

    def test_medium_risk_warning(self):
        v = _make_verdict(risk=45)
        reply = _format_reply(v)
        assert reply
        assert "45" in reply

    def test_low_risk_reassuring(self):
        v = _make_verdict(risk=5)
        reply = _format_reply(v)
        assert reply
        # past xavfda "XAVFLI" bo'lmasligi kerak
        assert "XAVFLI" not in reply

    def test_reply_in_uzbek(self):
        v = _make_verdict(risk=60)
        reply = _format_reply(v)
        # O'zbek tilida bo'lishi (lotin yoki kiril harflar)
        assert any(c.isalpha() for c in reply)

    def test_reply_mentions_risk_score(self):
        v = _make_verdict(risk=72)
        assert "72" in _format_reply(v)


# ================================================================= Event qurish

class TestBuildEvent:
    def test_event_has_required_fields(self):
        v = _make_verdict()
        ev = _build_event(
            url="https://phish.uz",
            redacted_text="Xabar mazmuni",
            verdict=v,
            user_id=999,
        )
        assert ev["source_kind"] == "complaint"
        assert ev["event_type"] in ("url", "message")
        assert "content" in ev
        assert "observed_at" in ev
        assert "verdict" in ev

    def test_url_event_type_when_url_provided(self):
        ev = _build_event("https://phish.uz", "matn", _make_verdict(), 1)
        assert ev["event_type"] == "url"
        assert ev["url"] == "https://phish.uz"

    def test_message_event_type_when_no_url(self):
        ev = _build_event(None, "matn", _make_verdict(), 1)
        assert ev["event_type"] == "message"
        assert ev.get("url") is None

    def test_ht03_user_id_not_in_event_raw(self):
        # HT-03: xom Telegram user_id bazaga yozilmasligi kerak
        ev = _build_event("https://phish.uz", "matn", _make_verdict(), user_id=12345)
        raw_str = str(ev)
        assert "12345" not in raw_str, "Xom Telegram ID topildi (HT-03 buzilishi)"

    def test_user_hash_in_ecs(self):
        ev = _build_event(None, "matn", _make_verdict(), user_id=777)
        assert "user_hash" in ev.get("ecs", {})

    def test_domain_extracted_from_url(self):
        ev = _build_event("https://kapitalbnk.uz/login", "matn", _make_verdict(), 1)
        assert ev.get("domain") == "kapitalbnk.uz"

    def test_content_is_redacted_text(self):
        ev = _build_event(None, "maskalangan matn [PHONE]", _make_verdict(), 1)
        assert ev["content"] == "maskalangan matn [PHONE]"


# ================================================================= Rate limiter

class TestRateLimiter:
    def test_under_limit_allowed(self):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        for _ in range(5):
            assert _run(bot._check_rate(user_id=1)) is True

    def test_over_limit_blocked(self):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        for _ in range(5):
            _run(bot._check_rate(user_id=2))
        assert _run(bot._check_rate(user_id=2)) is False

    def test_different_users_independent(self):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        for _ in range(5):
            _run(bot._check_rate(user_id=10))
        # boshqa user ta'sirlanmasligi kerak
        assert _run(bot._check_rate(user_id=20)) is True

    def test_limit_resets_after_window(self):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        # To'ldiramiz
        for _ in range(5):
            _run(bot._check_rate(user_id=3))
        # Eski timestamplarni eskirtiramiz (monotonic soat bilan)
        bot._rate[3] = [time.monotonic() - 65] * 5
        # Endi yangi xabar o'tishi kerak
        assert _run(bot._check_rate(user_id=3)) is True


# ================================================================= Handler-lar

class TestStartHandler:
    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_start_replies(self, _mock_engine):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        upd = _make_update("/start")
        _run(bot._handle_start(upd, _ctx()))
        upd.message.reply_text.assert_called_once()

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_start_mentions_shikoyat(self, _):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        upd = _make_update()
        _run(bot._handle_start(upd, _ctx()))
        reply_text = upd.message.reply_text.call_args[0][0]
        assert "shikoyat" in reply_text.lower() or "/shikoyat" in reply_text.lower()


class TestHelpHandler:
    def test_help_replies(self):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        upd = _make_update()
        _run(bot._handle_help(upd, _ctx()))
        upd.message.reply_text.assert_called_once()

    def test_help_content_informative(self):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        upd = _make_update()
        _run(bot._handle_help(upd, _ctx()))
        text = upd.message.reply_text.call_args[0][0]
        assert len(text) > 50


class TestMessageHandler:
    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_message_triggers_sink(self, mock_engine):
        mock_engine.return_value = _make_verdict(risk=50)
        sink = AsyncMock()
        bot = ComplaintBot(token="test", sink=sink, min_risk=20)
        upd = _make_update("https://kapitalbnk.uz saytiga kirmang")
        _run(bot._handle_message(upd, _ctx()))
        sink.assert_called_once()

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_below_min_risk_not_stored(self, mock_engine):
        mock_engine.return_value = _make_verdict(risk=5)
        sink = AsyncMock()
        bot = ComplaintBot(token="test", sink=sink, min_risk=30)
        upd = _make_update("https://google.com")
        _run(bot._handle_message(upd, _ctx()))
        sink.assert_not_called()

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_pii_redacted_before_sink(self, mock_engine):
        mock_engine.return_value = _make_verdict(risk=60)
        sink = AsyncMock()
        bot = ComplaintBot(token="test", sink=sink, min_risk=20)
        upd = _make_update("+998901234567 ga pul o'tkazing")
        _run(bot._handle_message(upd, _ctx()))

        call_kwargs = sink.call_args[0][0]
        # HT-03: xom telefon raqami kontentda bo'lmasligi kerak
        assert "+998901234567" not in call_kwargs["content"]
        assert "[PHONE]" in call_kwargs["content"]

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_user_gets_reply(self, mock_engine):
        mock_engine.return_value = _make_verdict(risk=70)
        bot = ComplaintBot(token="test", sink=AsyncMock(), min_risk=20)
        upd = _make_update("https://phish.uz")
        _run(bot._handle_message(upd, _ctx()))
        upd.message.reply_text.assert_called_once()

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_rate_limit_reply(self, mock_engine):
        mock_engine.return_value = _make_verdict(risk=50)
        bot = ComplaintBot(token="test", sink=AsyncMock(), min_risk=20)
        upd = _make_update("https://phish.uz", user_id=42)
        # Limitni to'ldirish
        for _ in range(5):
            _run(bot._handle_message(upd, _ctx()))
        upd.message.reply_text.reset_mock()
        # 6-chi xabar
        _run(bot._handle_message(upd, _ctx()))
        reply = upd.message.reply_text.call_args[0][0]
        assert "kuting" in reply.lower() or "limit" in reply.lower()

    @patch("app.collectors.complaint_bot.engine.analyse", side_effect=Exception("Dvigatel xatosi"))
    def test_engine_error_handled_gracefully(self, _):
        bot = ComplaintBot(token="test", sink=AsyncMock(), min_risk=20)
        upd = _make_update("https://phish.uz")
        # Istisno tashqariga chiqmasligi kerak
        _run(bot._handle_message(upd, _ctx()))
        upd.message.reply_text.assert_called_once()

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_empty_message_ignored(self, mock_engine):
        bot = ComplaintBot(token="test", sink=AsyncMock())
        upd = _make_update("   ")
        _run(bot._handle_message(upd, _ctx()))
        mock_engine.assert_not_called()

    @patch("app.collectors.complaint_bot.engine.analyse")
    def test_stats_updated(self, mock_engine):
        mock_engine.return_value = _make_verdict(risk=60)
        bot = ComplaintBot(token="test", sink=AsyncMock(), min_risk=20)
        upd = _make_update("https://phish.uz")
        _run(bot._handle_message(upd, _ctx()))
        assert bot.stats["received"] == 1
        assert bot.stats["processed"] == 1
        assert bot.stats["stored"] == 1


# ================================================================= Application qurish

class TestBuildApplication:
    def test_application_built_without_error(self):
        bot = ComplaintBot(token="1234567890:AABBCCDD", sink=AsyncMock())
        app = bot.build_application()
        assert app is not None

    def test_handlers_registered(self):
        bot = ComplaintBot(token="1234567890:AABBCCDD", sink=AsyncMock())
        app = bot.build_application()
        # Handler-lar ro'yxatdan o'tganligini tekshirish
        assert len(app.handlers) > 0
